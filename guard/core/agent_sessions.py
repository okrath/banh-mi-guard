"""
Where Camponi's agents keep their session logs, and which subagents those logs name. Read-only.

- omp: `<sessions>/<dir>/<ISO time>_<id>.jsonl`; `<sessions>` is `$PI_CODING_AGENT_DIR/sessions`, else
  `~/.omp/agent/sessions`; `<dir>` comes from the cwd by omp's rule: under the temp root `-tmp-<rel>`,
  under home `-<rel>`, else `--<abs>--` (older omp always), with `/`, `\\` and `:` turned into `-`.
  A subagent writes `<session file without .jsonl>/<Name>.jsonl`, and its own subagents one folder
  down (`<Name>/<Name>.<Sub>.jsonl`). It has ended once a `{"type":"custom","customType":"session_exit"}`
  line is written.
- claude: `<projects>/<cwd with every non-alphanumeric as ->/<session id>.jsonl`; `<projects>` is
  `$CLAUDE_CONFIG_DIR/projects`, else `~/.claude/projects`. One slug can stand for several folders, so
  the `cwd` the log's lines carry decides. Subagents write `<session id>/subagents/agent-*.jsonl`.
  Claude Code writes no exit line: a subagent counts as ended once its last message is an assistant
  turn that stopped with `end_turn` and the log has been quiet for `quiet_sec` (one watch interval).
- codex, opencode and plain shells: no subagents.

Which log belongs to a terminal: the session its args resume, else the most recently written log
created from the terminal's start (less `SESSION_SLACK_SECONDS`) up to the start of the next running
terminal of the same kind in the same folder.
"""

from __future__ import annotations

import functools
import json
import math
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence

from guard.core.worker_runtime import CamponiTerminal

SESSION_SLACK_SECONDS = 5.0
HEAD_BYTES = 256 * 1024
TAIL_BYTES = 64 * 1024
CLAUDE_NAME_MAX = 200  # Claude Code cuts longer folder names (and adds a hash)
# omp names a session `<ISO time with - for : and .>_<id>.jsonl`: 2026-11-02T05-12-52-584Z_<uuid>.jsonl
_OMP_FILE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z_")


@dataclass(frozen=True)
class SubagentLog:
    """One subagent's session log."""

    name: str  # as its top agent knows it: "<Name>", nested "<Name>/<Sub>"
    path: Path
    created: float | None  # epoch seconds the subagent started
    mtime: float  # its last write
    ended: bool


def omp_dir_name(cwd: str, home: str, tmp: str) -> str:
    """omp's session folder name for `cwd`, given the machine's home and temp roots."""
    tmp_rel = _inside(tmp, cwd)
    if tmp_rel is not None:
        return _encode_relative("-tmp", tmp_rel)
    home_rel = _inside(home, cwd)
    if home_rel is not None:
        return _encode_relative("-", home_rel)
    return legacy_dir_name(cwd)


def legacy_dir_name(cwd: str) -> str:
    """Older omp names every session folder by the absolute path."""
    trimmed = re.sub(r"^[/\\]", "", re.sub(r"[/\\]+$", "", cwd))
    return "--" + re.sub(r"[/\\:]", "-", trimmed) + "--"


def claude_dir_name(cwd: str) -> str:
    """Claude Code's project folder name for `cwd`."""
    return re.sub(r"[^a-zA-Z0-9]", "-", re.sub(r"[/\\]+$", "", cwd))


def same_path(a: str, b: str) -> bool:
    """Separators unified, no trailing separator; Windows paths (with a drive) compare without case."""
    return _norm(a) == _norm(b)


def session_log(
    terminal: CamponiTerminal,
    terminals: Sequence[CamponiTerminal],
    *,
    home: str | None = None,
    tmp: str | None = None,
    omp_root: Path | None = None,
    claude_root: Path | None = None,
) -> Path | None:
    """The session log of the agent in `terminal` (`terminals`: every terminal, for the window); None when not found."""
    cwd = terminal.cwd or (str(terminal.worktree) if terminal.worktree else None)
    if not cwd:
        return None
    created: Callable[[Path], float | None]
    if terminal.kind == "omp":
        home = home or str(Path.home())
        root = omp_root or _omp_root()
        folder = _find_dir(root, [omp_dir_name(cwd, home, tmp or tempfile.gettempdir()), legacy_dir_name(cwd)])
        created = _omp_file_created
    elif terminal.kind == "claude":
        name = claude_dir_name(cwd)
        folder = _find_dir(claude_root or _claude_root(), [name], name[:CLAUDE_NAME_MAX] if len(name) > CLAUDE_NAME_MAX else None)
        created = functools.partial(_claude_created, cwd=cwd)
    else:
        return None
    if folder is None:
        return None

    resumed = _resumed(terminal.args)
    if resumed is not None:
        return _resumed_log(folder, resumed, terminal.kind)

    lower = terminal.started_at - SESSION_SLACK_SECONDS if terminal.started_at is not None else -math.inf
    later = [
        other.started_at for other in terminals
        if other.id != terminal.id and other.running and other.kind == terminal.kind and other.started_at is not None
        and terminal.started_at is not None and other.started_at > terminal.started_at
        and same_path(other.cwd or str(other.worktree or ""), cwd)
    ]
    upper = min(later, default=math.inf)
    candidates = []
    for path in folder.glob("*.jsonl"):
        stamp = created(path)
        mtime = _mtime(path)
        if stamp is not None and mtime is not None and lower <= stamp < upper:
            candidates.append((mtime, path))
    return max(candidates)[1] if candidates else None


def subagent_logs(kind: str, session: Path, *, now: float, quiet_sec: float) -> list[SubagentLog]:
    """Every subagent log of one agent session, nested ones included, live or ended."""
    if kind == "omp":
        return _omp_subagents(session.with_suffix(""), "", "")
    if kind == "claude":
        return _claude_subagents(session.with_suffix("") / "subagents", now, quiet_sec)
    return []


def _omp_subagents(folder: Path, parent_stem: str, parent_name: str) -> list[SubagentLog]:
    logs: list[SubagentLog] = []
    for path in sorted(folder.glob("*.jsonl")):
        mtime = _mtime(path)
        if mtime is None:
            continue
        stem = path.stem
        short = stem[len(parent_stem) + 1:] if parent_stem and stem.startswith(parent_stem + ".") else stem
        name = f"{parent_name}/{short}" if parent_name else short
        session = next((row for row in _head_rows(path) if row.get("type") == "session"), {})
        ended = any(row.get("type") == "custom" and row.get("customType") == "session_exit" for row in _tail_rows(path))
        logs.append(SubagentLog(name=name, path=path, created=_iso(session.get("timestamp")), mtime=mtime, ended=ended))
        logs.extend(_omp_subagents(folder / stem, stem, name))
    return logs


def _claude_subagents(folder: Path, now: float, quiet_sec: float) -> list[SubagentLog]:
    logs: list[SubagentLog] = []
    for path in sorted(folder.glob("agent-*.jsonl")):
        mtime = _mtime(path)
        if mtime is None:
            continue
        created = next((_iso(row["timestamp"]) for row in _head_rows(path) if "timestamp" in row), None)
        last = next((row for row in reversed(_tail_rows(path)) if row.get("type") in ("user", "assistant")), {})
        finished = last.get("type") == "assistant" and _mapping(last.get("message")).get("stop_reason") == "end_turn"
        logs.append(SubagentLog(name=path.stem, path=path, created=created, mtime=mtime,
                                ended=finished and now - mtime >= quiet_sec))
    return logs


def _resumed(args: Sequence[str]) -> str | None:
    """The session `--resume=<v>` or `--resume <v>` names (omp: a file or an id; claude: an id)."""
    for index, arg in enumerate(args):
        if arg.startswith("--resume="):
            return arg[len("--resume="):] or None
        if arg == "--resume" and index + 1 < len(args):
            return args[index + 1] or None
    return None


def _resumed_log(folder: Path, resumed: str, kind: str) -> Path | None:
    if resumed.endswith(".jsonl") and Path(resumed).is_file():
        return Path(resumed)
    if kind == "claude":
        path = folder / f"{resumed}.jsonl"
        return path if path.is_file() else None
    wanted = resumed.lower()  # omp takes a session id or a prefix of its file name
    return next((path for path in sorted(folder.glob("*.jsonl")) if wanted in path.name.lower()), None)


def _omp_file_created(path: Path) -> float | None:
    match = _OMP_FILE_RE.match(path.name)
    if match is None:
        return None
    day, hours, minutes, seconds, millis = match.groups()
    return _iso(f"{day}T{hours}:{minutes}:{seconds}.{millis}Z")


def _claude_created(path: Path, cwd: str) -> float | None:
    """The first timestamp of a claude log, None when its lines name another folder or no time yet."""
    created, cwd_seen = None, False
    for row in _head_rows(path):
        if created is None and "timestamp" in row:
            created = _iso(row["timestamp"])
        if isinstance(row.get("cwd"), str):
            if not same_path(row["cwd"], cwd):
                return None
            cwd_seen = True
        if cwd_seen and created is not None:
            break
    return created


def _omp_root() -> Path:
    agent_dir = os.environ.get("PI_CODING_AGENT_DIR")
    return Path(agent_dir) / "sessions" if agent_dir else Path.home() / ".omp" / "agent" / "sessions"


def _claude_root() -> Path:
    config_dir = os.environ.get("CLAUDE_CONFIG_DIR")
    return (Path(config_dir) if config_dir else Path.home() / ".claude") / "projects"


def _find_dir(root: Path, names: Sequence[str], prefix: str | None = None) -> Path | None:
    """The folder under `root` named one of `names` (compared without case), else the first starting with `prefix`."""
    try:
        entries = sorted(entry.name for entry in root.iterdir() if entry.is_dir())
    except OSError:
        return None
    wanted = {name.lower() for name in names}
    hit = next((entry for entry in entries if entry.lower() in wanted), None)
    if hit is None and prefix:
        hit = next((entry for entry in entries if entry.lower().startswith(prefix.lower())), None)
    return root / hit if hit is not None else None


def _head_rows(path: Path) -> Iterator[dict[str, Any]]:
    """The JSON objects of the first `HEAD_BYTES` of a log, in order."""
    try:
        with path.open("rb") as handle:
            chunk = handle.read(HEAD_BYTES)
    except OSError:
        return
    lines = chunk.decode("utf-8", errors="replace").splitlines()
    if len(chunk) == HEAD_BYTES:
        lines = lines[:-1]  # the last line may be cut
    for line in lines:
        row = _json_object(line)
        if row is not None:
            yield row


def _tail_rows(path: Path) -> list[dict[str, Any]]:
    """The JSON objects of the last `TAIL_BYTES` of a log, in order."""
    try:
        with path.open("rb") as handle:
            size = handle.seek(0, os.SEEK_END)
            handle.seek(max(0, size - TAIL_BYTES))
            chunk = handle.read()
    except OSError:
        return []
    lines = chunk.decode("utf-8", errors="replace").splitlines()
    if size > TAIL_BYTES:
        lines = lines[1:]  # the first line may be cut
    return [row for row in map(_json_object, lines) if row is not None]


def _json_object(line: str) -> dict[str, Any] | None:
    try:
        row = json.loads(line)
    except ValueError:
        return None
    return row if isinstance(row, dict) else None


def _iso(value: Any) -> float | None:
    """Epoch seconds of an ISO 8601 time (`Z` or an offset; a bare time is UTC); None when unreadable."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp()


def _mtime(path: Path) -> float | None:
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _inside(root: str, target: str) -> str | None:
    """`target` relative to `root` with `/`, '' when equal, None when outside."""
    r = root.replace("\\", "/").rstrip("/")
    t = target.replace("\\", "/").rstrip("/")
    fold = re.match(r"^[A-Za-z]:", r) is not None
    rr, tt = (r.lower(), t.lower()) if fold else (r, t)
    if tt == rr:
        return ""
    return t[len(r) + 1:] if tt.startswith(rr + "/") else None


def _encode_relative(prefix: str, relative: str) -> str:
    encoded = re.sub(r"[/\\:]", "-", relative)
    if not encoded:
        return prefix
    return f"{prefix}{encoded}" if prefix.endswith("-") else f"{prefix}-{encoded}"


def _norm(path: str) -> str:
    normalized = path.replace("\\", "/").rstrip("/")
    return normalized.lower() if re.match(r"^[A-Za-z]:", normalized) else normalized
