"""
Runtime probes for supervised Orca workers.

The one guard module that touches the outside world: it runs plain `git` inside worker
worktrees (read-only, and never by a shell), reads the `orca` worker list and terminal screens,
delivers nudges through the orca CLI, and stops a worker's own foreground dev server.
`guard watch` builds its ticks and actions from here.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

SETTLED_STATES = frozenset({"succeeded", "failed", "cancelled", "abandoned", "stopped"})
WORKTREE_ID_SEPARATOR = "::"
OUTPUT_TAIL_CHARS = 400
CALL_TIMEOUT_SECONDS = 60
DESCRIPTION_CHARS = 120
_C_UNESCAPES = {"\\": "\\", '"': '"', "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}

# Screen patterns of the agent CLIs, case-insensitive like the PowerShell watchdog they come from.
# A braille spinner glyph followed by the turn timer ("12s", "45m", "1h") means a turn is running.
_SPINNER_RE = re.compile(r"[\u2800-\u28FF]\s+\d+[smh]\b", re.IGNORECASE)
# opencode has no braille timer: its footer shows "esc interrupt" only while a turn runs.
_OPENCODE_BUSY_RE = re.compile(r"esc interrupt", re.IGNORECASE)
# Parts that animate on their own and are no progress: spinner with timers, the opencode bar,
# token counters such as "12.5K (40%)" and bare percentages.
_ANIMATED_RE = re.compile(
    r"[\u2800-\u28FF]\s+\d+[smh](\s+\d+[sm])?|[\u25A0\u2B1D]+|\d+(\.\d+)?K\s*\(\d+%\)|\d+(\.\d+)?\s*%",
    re.IGNORECASE,
)
# The header of the shell command an agent runs: a spinner glyph, then "$ <command>".
_COMMAND_RE = re.compile(r"[\u2800-\u28FF]\s+\$\s*(.{1,120})")
# An omp background job the agent waits on: "<corner><tool>  bg_1 <command><ellipsis> <middle dot> 17m42s"
# (\u2514\u2500 \u27e8bash\u27e9 ... \u00b7), the job's own elapsed time after the last middle dot.
_JOB_RE = re.compile(
    r"^.*?\u2514\u2500\s*\u27e8[^\u27e9]*\u27e9\s+\S+\s+(.*)\u00b7\s*(?:(\d+)h(\d+)m|(\d+)m(\d+)s|(\d+)s)\s*$",
    re.MULTILINE,
)
_DEV_SERVER_RE = re.compile(
    r"ready in \d+\s*ms|Local:\s+http|Nest application successfully started|watching for file changes",
    re.IGNORECASE,
)
# A worker's own dev server: a node process running one of these with its worktree on the command line.
_DEV_PROCESS_RE = re.compile(r"vite|nest start|ts-node|dev-provider-game", re.IGNORECASE)
_WINDOWS_NODE_LIST = (
    "Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" | "
    "Select-Object ProcessId, CommandLine | ConvertTo-Json -Compress"
)


class WorkerRuntimeError(RuntimeError):
    """The orca CLI failed, or answered with something that cannot be parsed."""


@dataclass(frozen=True)
class WorktreeProbe:
    head: str | None
    dirty: bool
    activity_ts: float | None


@dataclass(frozen=True)
class OrcaWorker:
    name: str
    worktree: Path | None
    terminal: str | None
    worker_state: str
    stage_detail: str
    activity: str
    liveness: str
    observed_at: float | None
    settled: bool


@dataclass(frozen=True)
class ScreenState:
    """What one rendered terminal screen says about the agent behind it."""

    busy: bool  # a turn is running (spinner with timer, or the opencode footer)
    stable: str  # the screen without its self-animating parts: changes only on real progress
    command: str | None  # the shell command the agent is running, while busy
    dev_server: bool  # dev-server output owns the screen
    jobs: tuple[tuple[str, float], ...] = ()  # (command, seconds it has run) of each background job shown


def probe_worktree(worktree: Path, *, since: float | None = None) -> WorktreeProbe:
    """
    HEAD, dirtiness and the newest git-visible activity of one worktree. Read-only: git runs
    with `--no-optional-locks` so probing never refreshes the index and never fakes activity.
    HEAD's commit time counts only when it is not older than `since` (when given): a fresh
    worktree on an old base commit must not look like a worker that went quiet long ago.
    """
    rev = _git(worktree, "rev-parse", "HEAD")
    head = (rev.stdout.strip() or None) if rev is not None and rev.returncode == 0 else None

    status = _git(worktree, "status", "--porcelain")
    porcelain = (status.stdout or "") if status is not None and status.returncode == 0 else ""

    stamps: list[float] = []
    commit = _git(worktree, "log", "-1", "--format=%ct")
    if commit is not None and commit.returncode == 0:
        try:
            commit_ts = float(commit.stdout.strip())
        except ValueError:
            commit_ts = None
        if commit_ts is not None and (since is None or commit_ts >= since):
            stamps.append(commit_ts)
    for changed in _porcelain_paths(porcelain):
        stamp = _mtime(worktree / changed)
        if stamp is not None:
            stamps.append(stamp)
    index = _git(worktree, "rev-parse", "--git-path", "index")
    raw_index = index.stdout.strip() if index is not None and index.returncode == 0 else ""
    if raw_index:
        index_path = Path(raw_index)
        stamp = _mtime(index_path if index_path.is_absolute() else worktree / index_path)
        if stamp is not None:
            stamps.append(stamp)
    return WorktreeProbe(head=head, dirty=bool(porcelain.strip()), activity_ts=max(stamps) if stamps else None)


def resolve_orca() -> str | None:
    """The orca CLI to run: `$ORCA_CLI_COMMAND` when set, else `orca` on PATH, else None."""
    return os.environ.get("ORCA_CLI_COMMAND") or shutil.which("orca")


def list_workers(orca: str, run: str, *, names: Sequence[str] | None = None) -> list[OrcaWorker]:
    """
    The workers of one Orca run as `orca orchestration worker-list --run <run> --json` reports
    them. A row without a worktree has no basename to watch, so it is kept only when `names`
    asks for its task id explicitly.
    """
    res = _run([orca, "orchestration", "worker-list", "--run", run, "--json"])
    if res is None or res.returncode != 0:
        detail = _tail(res.stderr) if res is not None else f"could not start {orca}"
        raise WorkerRuntimeError(f"orca orchestration worker-list failed: {detail}")
    rows = _worker_rows(res.stdout or "")

    wanted = set(names) if names is not None else None
    workers: list[OrcaWorker] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        worker = _parse_worker(row)
        if wanted is None:
            if worker.worktree is not None:
                workers.append(worker)
        elif worker.name in wanted:
            workers.append(worker)
    return workers


def send_nudge(orca: str, terminal: str, text: str, *, interrupt: bool = False) -> None:
    """
    Type `text` into a worker terminal and press Enter; any failure raises. `interrupt` sends it
    as an interrupt, since a plain message queues behind the command a busy agent is running.
    """
    argv = [orca, "terminal", "send", "--terminal", terminal, "--text", text, "--enter"]
    if interrupt:
        argv.append("--interrupt")
    res = _run([*argv, "--json"])
    if res is None or res.returncode != 0:
        detail = _tail(res.stderr) if res is not None else f"could not start {orca}"
        raise WorkerRuntimeError(f"orca terminal send to {terminal} failed: {detail}")


def read_screen(orca: str, terminal: str, *, limit: int = 25) -> str | None:
    """The rendered screen of a worker terminal (its last `limit` rows); None when it cannot be read."""
    try:
        res = _run([orca, "terminal", "read", "--terminal", terminal, "--screen", "--limit", str(limit)])
    except WorkerRuntimeError:  # a timed-out read is no screen, not a reason to stop watching
        return None
    if res is None or res.returncode != 0:
        return None
    return res.stdout or ""


def parse_screen(screen: str) -> ScreenState:
    """Decode one screen: busy, the stable text, the running command, dev-server output and background jobs."""
    busy = bool(_SPINNER_RE.search(screen) or _OPENCODE_BUSY_RE.search(screen))
    stable = _ANIMATED_RE.sub("", screen)
    # Matched on the stable text so a percentage or counter printed after it never renames the command.
    match = _COMMAND_RE.search(stable) if busy else None
    command = match.group(1).strip() if match else ""
    return ScreenState(busy=busy, stable=stable, command=command or None, dev_server=bool(_DEV_SERVER_RE.search(screen)),
                       jobs=tuple(_job(found) for found in _JOB_RE.finditer(screen)))


def _job(match: re.Match[str]) -> tuple[str, float]:
    """(command, elapsed seconds) of one background-job line; a cut-off command loses its ellipsis."""
    hours, minutes, minutes_s, seconds, seconds_only = (int(group or 0) for group in match.groups()[1:])
    elapsed = hours * 3600 + (minutes + minutes_s) * 60 + seconds + seconds_only
    return match.group(1).strip().rstrip("\u2026").strip(), float(elapsed)


def stop_dev_servers(worktree: Path) -> list[str]:
    """
    Stop the dev servers a worker runs from its own worktree: node processes whose command line
    names the worktree and runs vite, nest start, ts-node or dev-provider-game. Returns one
    "<pid>: <command line>" description per process stopped; a failed process listing raises.
    """
    stopped: list[str] = []
    for pid, command in _node_processes():
        if pid == os.getpid() or not _DEV_PROCESS_RE.search(command) or not mentions_path(command, worktree):
            continue
        try:
            os.kill(pid, signal.SIGTERM)  # TerminateProcess on Windows
        except OSError:  # already gone, or not ours to stop
            continue
        stopped.append(f"{pid}: {command[:DESCRIPTION_CHARS]}")
    return stopped


def mentions_path(text: str, path: Path) -> bool:
    """
    True when `text` names `path` or something inside it, in either slash style and any case;
    a sibling that only shares the prefix (`wt` and `wt-2`) does not count.
    """
    haystack = text.lower().replace("\\", "/")
    needle = str(path).lower().replace("\\", "/").rstrip("/")
    if not needle:
        return False
    start = haystack.find(needle)
    while start >= 0:
        end = start + len(needle)
        if end == len(haystack) or not (haystack[end].isalnum() or haystack[end] in "-_."):
            return True
        start = haystack.find(needle, start + 1)
    return False


def _node_processes() -> list[tuple[int, str]]:
    """(pid, command line) of every running node process."""
    if sys.platform == "win32":
        res = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_NODE_LIST])
        if res is None or res.returncode != 0:
            detail = _tail(res.stderr) if res is not None else "could not start powershell"
            raise WorkerRuntimeError(f"listing node processes failed: {detail}")
        return _windows_processes(res.stdout or "")
    res = _run(["ps", "-eo", "pid=,comm=,args="])
    if res is None or res.returncode != 0:
        detail = _tail(res.stderr) if res is not None else "could not start ps"
        raise WorkerRuntimeError(f"listing node processes failed: {detail}")
    processes = []
    for line in (res.stdout or "").splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1] == "node":
            processes.append((int(parts[0]), parts[2]))
    return processes


def _windows_processes(stdout: str) -> list[tuple[int, str]]:
    """`ConvertTo-Json` output: nothing, one object, or a list of {ProcessId, CommandLine}."""
    if not stdout.strip():
        return []
    try:
        payload = json.loads(stdout)
    except ValueError as e:
        raise WorkerRuntimeError(f"listing node processes returned unparseable JSON: {_tail(stdout)}") from e
    rows = payload if isinstance(payload, list) else [payload]
    processes = []
    for row in rows:
        row = _mapping(row)
        pid, command = row.get("ProcessId"), row.get("CommandLine")
        if isinstance(pid, int) and not isinstance(pid, bool) and isinstance(command, str):
            processes.append((pid, command))
    return processes


def _worker_rows(stdout: str) -> list[Any]:
    try:
        payload = json.loads(stdout)
    except ValueError as e:
        raise WorkerRuntimeError(f"orca orchestration worker-list returned unparseable JSON: {_tail(stdout)}") from e
    result = _mapping(payload.get("result") if isinstance(payload, dict) else None)
    rows = result.get("workers")
    if not isinstance(rows, list):
        raise WorkerRuntimeError(f"orca orchestration worker-list JSON has no result.workers list: {_tail(stdout)}")
    return rows


def _parse_worker(row: dict[str, Any]) -> OrcaWorker:
    resource = _mapping(row.get("resource"))
    projection = _mapping(row.get("projection"))
    stage = _mapping(projection.get("stage"))
    liveness = _mapping(projection.get("liveness"))
    worker_state = str(row.get("workerState") or "")
    worktree_id = str(resource.get("worktreeId") or "")
    _repo_id, separator, raw_path = worktree_id.partition(WORKTREE_ID_SEPARATOR)
    worktree = Path(raw_path) if separator and raw_path else None
    terminal = row.get("agentTerminalHandle")
    return OrcaWorker(
        name=worktree.name if worktree is not None else str(row.get("taskId") or ""),
        worktree=worktree,
        terminal=str(terminal) if terminal is not None else None,
        worker_state=worker_state,
        stage_detail=str(stage.get("detail") or ""),
        activity=str(stage.get("activity") or ""),
        liveness=str(liveness.get("verdict") or ""),
        observed_at=_observed_at(liveness.get("observedAt")),
        settled=worker_state in SETTLED_STATES,
    )


def _observed_at(value: Any) -> float | None:
    """`projection.liveness.observedAt` is epoch milliseconds; callers work in epoch seconds."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        seconds = float(value) / 1000.0
    except OverflowError:  # an integer too large for a float is not a usable timestamp
        return None
    return seconds if math.isfinite(seconds) else None


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _run(cmd: Sequence[str]) -> subprocess.CompletedProcess[str] | None:
    """
    House call style: argument list, no shell, and a hard timeout so a hung child cannot block
    `guard watch`. None only when the executable cannot be started (or the argv is unusable).
    """
    try:
        return subprocess.run(list(cmd), capture_output=True, text=True, encoding="utf-8",
                              errors="replace", check=False, timeout=CALL_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as e:
        raise WorkerRuntimeError(f"{cmd[0]} timed out after {CALL_TIMEOUT_SECONDS}s") from e
    except (OSError, ValueError):
        return None


def _git(worktree: Path, *args: str) -> subprocess.CompletedProcess[str] | None:
    return _run(["git", "--no-optional-locks", "-C", str(worktree), *args])


def _tail(text: str | None) -> str:
    return (text or "").strip()[-OUTPUT_TAIL_CHARS:]


def _mtime(path: Path) -> float | None:
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def _porcelain_paths(porcelain: str) -> list[str]:
    """
    Changed paths of `git status --porcelain`: `XY PATH`, and `XY OLD -> NEW` only when the
    status marks a rename/copy, so a file literally named `a -> b.txt` keeps its whole name.
    """
    paths = []
    for line in porcelain.splitlines():
        if len(line) < 4:
            continue
        path = line[3:]
        if line[0] in "RC":
            path = path.rsplit(" -> ", 1)[-1]
        paths.append(_unquote(path))
    return paths


def _unquote(path: str) -> str:
    """
    Undo Git's C-style quoting of a porcelain path. Only special characters (quotes, backslashes,
    control and non-ASCII bytes) are quoted; plain spaces are not. Octal escapes are three digits
    (Git's own output), are bytes, and are decoded as UTF-8; a short escape consumes what is there.
    """
    if len(path) < 2 or not path.startswith('"') or not path.endswith('"'):
        return path
    raw = bytearray()
    i = 1
    while i < len(path) - 1:
        char = path[i]
        if char != "\\" or i + 1 >= len(path) - 1:
            raw.extend(char.encode("utf-8"))
            i += 1
            continue
        next_char = path[i + 1]
        if next_char in "01234567":
            digits = next_char
            end = i + 2
            while len(digits) < 3 and end < len(path) - 1 and path[end] in "01234567":
                digits += path[end]
                end += 1
            raw.append(int(digits, 8))
            i = end
        else:
            raw.extend(_C_UNESCAPES.get(next_char, next_char).encode("utf-8"))
            i += 2
    return raw.decode("utf-8", errors="replace")
