"""
Runtime probes for supervised Orca workers.

The one guard module that touches the outside world: it runs plain `git` inside worker
worktrees (read-only, and never by a shell), reads the `orca` worker list, and delivers
nudges through the orca CLI. `guard watch` builds its ticks and actions from here.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

SETTLED_STATES = frozenset({"succeeded", "failed", "abandoned", "stopped"})
WORKTREE_ID_SEPARATOR = "::"
OUTPUT_TAIL_CHARS = 400
CALL_TIMEOUT_SECONDS = 60
_C_UNESCAPES = {"\\": "\\", '"': '"', "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}


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


def probe_worktree(worktree: Path) -> WorktreeProbe:
    """
    HEAD, dirtiness and the newest git-visible activity of one worktree. Read-only: git runs
    with `--no-optional-locks` so probing never refreshes the index and never fakes activity.
    """
    rev = _git(worktree, "rev-parse", "HEAD")
    head = (rev.stdout.strip() or None) if rev is not None and rev.returncode == 0 else None

    status = _git(worktree, "status", "--porcelain")
    porcelain = (status.stdout or "") if status is not None and status.returncode == 0 else ""

    stamps: list[float] = []
    commit = _git(worktree, "log", "-1", "--format=%ct")
    if commit is not None and commit.returncode == 0:
        try:
            stamps.append(float(commit.stdout.strip()))
        except ValueError:
            pass
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


def send_nudge(orca: str, terminal: str, text: str) -> None:
    """Type `text` into a worker terminal and press Enter; any failure raises."""
    res = _run([orca, "terminal", "send", "--terminal", terminal, "--text", text, "--enter", "--json"])
    if res is None or res.returncode != 0:
        detail = _tail(res.stderr) if res is not None else f"could not start {orca}"
        raise WorkerRuntimeError(f"orca terminal send to {terminal} failed: {detail}")


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
