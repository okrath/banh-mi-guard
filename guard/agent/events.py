"""
`guard agent-event <event>`: the one contract every agent adapter calls.

The harness payload is normalised into an AgentEvent, `decide` applies guard's rules and
returns allow / block / notify. Adapters only map fields and format the answer; no gate logic
lives in an adapter. State that exists before `guard pre` (the user's prompt, per-call Bash
fingerprints, files changed before pre) is kept in the Git-excluded .guard/agent-state.json.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from guard.agent.bash import HEAD_KEY, changed_between, content_hash, is_git_commit, is_read_only, worktree_fingerprint
from guard.core.ocr_engine import GitDiffInspector
from guard.core.session import SessionManager, SessionStatus, describe_owner

EVENTS = ("prompt", "before-edit", "after-bash", "stop", "before-commit")
EDIT_TOOLS = {"edit", "write", "multiedit", "notebookedit"}
# Tools known to only read; any other tool that names a file is treated as one that edits it
READ_TOOLS = {"read", "grep", "glob", "ls", "notebookread", "webfetch", "websearch", "todowrite",
              "view", "read_file", "list_directory", "search", "find", "list"}
SHELL_TOOLS = {"bash", "shell", "powershell", "run_shell_command", "terminal"}
STATE_FILE = "agent-state.json"


class AgentEvent(BaseModel):
    event: str
    cwd: str = ""
    prompt: Optional[str] = None
    tool: Optional[str] = None
    file_paths: List[str] = Field(default_factory=list)
    command: Optional[str] = None
    call_id: Optional[str] = None
    loop: bool = False  # the harness says this is a repeated stop (its loop guard)
    # The harness's own session (conversation) id, and the adapter that sent the event: two agent
    # sessions in one working tree are told apart by it. Without an id, events are shared as before
    agent_session: Optional[str] = None
    agent: str = ""


class Decision(BaseModel):
    action: Literal["allow", "block", "notify"] = "allow"
    reason: str = ""


def _get(payload: Any, path: str) -> Any:
    cur = payload
    for part in path.split("."):
        if isinstance(cur, list) and part.isdigit():  # `workspacePaths.0`: an item of a list
            cur = cur[int(part)] if int(part) < len(cur) else None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


# Where common harnesses put each field; an adapter may pass its own mapping
DEFAULT_FIELDS: Dict[str, List[str]] = {
    "cwd": ["cwd", "workspace", "project_dir"],
    "prompt": ["prompt", "user_prompt", "message"],
    "tool": ["tool_name", "tool", "name"],
    "file_paths": ["tool_input.file_path", "tool_input.path", "tool_input.notebook_path", "file_path", "path"],
    "command": ["tool_input.command", "command"],
    "call_id": ["tool_use_id", "call_id", "tool_call_id"],
    "loop": ["stop_hook_active", "loop"],
    "agent_session": ["session_id", "conversation_id", "sessionId", "thread_id"],
}


def _is_loop(value: Any) -> bool:
    """
    The harness already refused a stop once: `true` (stop_hook_active), or a count above zero
    (Cursor's `loop_count`); "false", 0 and a missing field are not.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value > 0
    return str(value).strip().lower() == "true"


def normalise(event: str, payload: Any, fields: Optional[Dict[str, List[str]]] = None) -> AgentEvent:
    fields = {**DEFAULT_FIELDS, **(fields or {})}

    def first(key: str) -> Any:
        for path in fields.get(key, []):
            value = _get(payload, path)
            if value not in (None, ""):
                return value
        return None

    paths = [p for p in (_get(payload, f) for f in fields["file_paths"]) if isinstance(p, str) and p]
    return AgentEvent(
        event=event,
        cwd=str(first("cwd") or ""),
        prompt=first("prompt") if isinstance(first("prompt"), str) else None,
        tool=str(first("tool")) if first("tool") else None,
        file_paths=list(dict.fromkeys(paths)),
        command=first("command") if isinstance(first("command"), str) else None,
        call_id=str(first("call_id")) if first("call_id") else None,
        loop=_is_loop(first("loop")),
        agent_session=str(first("agent_session"))[:200] if first("agent_session") else None,
    )


def _repo(cwd: str) -> Optional[Path]:
    from guard.core.repo_setup import git_root
    return git_root(Path(cwd or ".").resolve())


def _state_path(repo: Path) -> Path:
    return repo / ".guard" / STATE_FILE


def load_state(repo: Path) -> Dict[str, Any]:
    try:
        data = json.loads(_state_path(repo).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(repo: Path, state: Dict[str, Any]) -> None:
    path = _state_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    SessionManager(repo).ensure_gitignore()  # .guard/ stays out of Git
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def update_state(repo: Path, change) -> Any:
    """
    Read, change and write the state under a lock: an agent can run several commands at once, and
    their hook calls must not overwrite each other's fingerprints. Returns what `change` returns.
    """
    lock = _state_path(repo).with_suffix(".lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    for _ in range(200):  # a hook call holds the lock for milliseconds
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except (FileExistsError, PermissionError):  # held (Windows reports a lock being deleted as PermissionError)
            try:
                if time.time() - lock.stat().st_mtime > 30:  # left behind by a killed process
                    lock.unlink(missing_ok=True)
            except OSError:
                pass  # released between the two calls: just try again
            time.sleep(0.02)
    else:
        raise TimeoutError("guard agent state is locked")
    try:
        state = load_state(repo)
        result = change(state)
        save_state(repo, state)
        return result
    finally:
        os.close(fd)
        lock.unlink(missing_ok=True)


SESSION_TTL_S = 86400  # an agent session's state is dropped a day after its last event
CLAIM_TTL_S = 60  # a `guard pre` takes the claim of the agent command that started it, if this recent


def session_state(state: Dict[str, Any], agent_session: Optional[str]) -> Dict[str, Any]:
    """
    The part of the agent state that belongs to one agent session (its prompt, files it changed
    before pre, its Bash fingerprints): `sessions[<id>]`, or the shared top level for an event
    without an id. Sessions not seen for a day are dropped.
    """
    if not agent_session:
        return state
    sessions = state.setdefault("sessions", {})
    now = time.time()
    for stale in [k for k, v in sessions.items() if not isinstance(v, dict) or now - v.get("seen", 0) > SESSION_TTL_S]:
        del sessions[stale]
    own = sessions.setdefault(agent_session, {})
    own["seen"] = now
    return own


def fresh_claim(state: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """
    The agent session that ran `guard pre` within CLAIM_TTL_S: {"agent", "session"}. None when no
    session did, and when two did (two pres started together): which pre is whose is then unknown,
    so neither gets an owner and the shared behaviour applies.
    """
    claims = state.get("claims") if isinstance(state.get("claims"), dict) else {}
    fresh = [(s, c) for s, c in claims.items() if isinstance(c, dict) and time.time() - c.get("at", 0) <= CLAIM_TTL_S]
    if len(fresh) != 1:
        return None
    session, claim = fresh[0]
    return {"agent": str(claim.get("agent") or ""), "session": str(session)}


def _owner(session) -> Optional[Dict[str, str]]:
    owner = getattr(session.pre, "owner", None) if session and session.pre else None
    return owner if isinstance(owner, dict) and owner.get("session") else None


def session_key(ev: AgentEvent) -> Optional[str]:
    """`<agent>:<session id>`: two agents that happen to use the same id are never one session."""
    return f"{ev.agent}:{ev.agent_session}" if ev.agent_session else None


def _from_another_session(ev: AgentEvent, session) -> bool:
    """The event has an id, the guard session has an owner, and they are not the same agent session."""
    owner = _owner(session)
    return bool(ev.agent_session and owner and owner["session"] != session_key(ev))


def _held_reason(session) -> str:
    owner, pre = _owner(session), session.pre
    task = " ".join(pre.prompt.split())[:80]
    return (f"this working tree is held by another agent's guard session ({describe_owner(owner)}, task "
            f"\"{task}\", since {pre.timestamp[:16].replace('T', ' ')} UTC)")


# `guard pre` as the command itself: at the start or after a shell separator, optionally behind
# variable assignments or a path; never as an argument (`grep guard pre docs/`)
GUARD_PRE = re.compile(r"(?:^|[;&|(\n])\s*(?:\w+=\S*\s+)*(?:\S*[/\\])?guard(?:\.exe)?\s+pre(?:\s|$)")


def is_guard_command(cmd: str) -> bool:
    """True when every executed pipeline/sequence segment in cmd is a guard command."""
    if not cmd or not cmd.strip():
        return False
    # Reject command substitutions and redirections targeting .guard
    if "$(" in cmd or "`" in cmd or re.search(r">\s*\S*\.guard", cmd, re.IGNORECASE):
        return False
    try:
        lexer = shlex.shlex(cmd, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = False
        tokens = list(lexer)
    except (ValueError, OSError):
        return False
    if not tokens:
        return False

    subcommands: List[List[str]] = []
    current: List[str] = []
    for t in tokens:
        if t in (";", "&&", "||", "|", "&"):
            if current:
                subcommands.append(current)
                current = []
        else:
            current.append(t)
    if current:
        subcommands.append(current)

    for sub in subcommands:
        if not sub:
            continue
        idx = 0
        while idx < len(sub) and "=" in sub[idx] and not sub[idx].startswith(("-", "/")):
            idx += 1
        if idx >= len(sub):
            return False
        first = sub[idx].replace("\\", "/")
        if first.lower().endswith(".exe"):
            first = first[:-4]
        prog = first.split("/")[-1].lower()
        if prog == "guard":
            continue
        elif prog in ("python", "python3", "py"):
            if idx + 2 < len(sub) and sub[idx + 1] == "-m" and sub[idx + 2] == "guard":
                continue
            return False
        else:
            return False
    return True


def _claim(state: Dict[str, Any], agent_session: str, agent: str) -> None:
    """Record that this agent session starts a `guard pre`; claims older than CLAIM_TTL_S go."""
    claims = state.get("claims") if isinstance(state.get("claims"), dict) else {}
    now = time.time()
    claims = {s: c for s, c in claims.items() if isinstance(c, dict) and now - c.get("at", 0) <= CLAIM_TTL_S}
    claims[agent_session] = {"agent": agent, "at": now}
    state["claims"] = claims


def _relative(repo: Path, file_path: str) -> Optional[str]:
    """Repository-relative path, or None for files outside the repository."""
    p = Path(file_path)
    p = (p if p.is_absolute() else repo / p).resolve()
    try:
        return p.relative_to(repo.resolve()).as_posix()
    except ValueError:
        return None


def _active_pre(session) -> bool:
    return bool(session and session.pre and session.status in (
        SessionStatus.AWAITING_POST, SessionStatus.NEEDS_FIX, SessionStatus.NEEDS_USER))


def _staged_differs(repo: Path) -> List[str]:
    """
    Staged files whose staged content is not the working-tree file (what was approved): the index
    blob id against `git hash-object`, which applies Git's own filters (line endings) to the file.
    """
    import subprocess
    git = ["git", "-C", str(repo)]
    res = subprocess.run(git + ["diff", "--cached", "--name-only", "-z"], capture_output=True)
    out = []
    for rel in (p.decode("utf-8", "replace") for p in res.stdout.split(b"\0") if p):
        staged = subprocess.run(git + ["rev-parse", "-q", "--verify", f":{rel}"], capture_output=True, text=True).stdout.strip()
        on_disk = subprocess.run(git + ["hash-object", "--", rel], capture_output=True, text=True).stdout.strip() \
            if (repo / rel).is_file() else ""
        if staged != on_disk:  # also a staged deletion of a file that still exists, and the reverse
            out.append(rel)
    return out


def _uncovered(repo: Path, session, staged: bool = False) -> List[str]:
    """
    Changed files not covered by the session's approval (all of them without an approval). With
    staged=True the staged content is checked too: `git add` then editing again commits the old text.
    """
    approved = SessionManager.verified_approval(session)
    out = [f for f in GitDiffInspector(repo).get_working_files() if approved.get(f) != content_hash(repo / f)]
    if staged:
        out += [f for f in _staged_differs(repo) if f not in out]
    return out


def _task_edits(repo: Path, session) -> List[str]:
    """Changed files that differ from what pre recorded (pre-existing, untouched changes are not the task's)."""
    baseline = session.pre.baseline_dirty if session and session.pre else {}
    return [f for f in GitDiffInspector(repo).get_working_files() if baseline.get(f) != content_hash(repo / f)]


PRE_HINT = ('run `guard pre "<the user\'s request>" --scope <files you will change>` first '
            "(add --allow-dirty when unrelated changes must stay)")


def decide(ev: AgentEvent) -> Decision:
    repo = _repo(ev.cwd)
    if repo is None:
        return Decision()  # guard protects Git repositories only
    session = SessionManager(repo).load_local_session()
    tool = (ev.tool or "").lower()
    other = _from_another_session(ev, session)  # judged on its own work, not the owner's

    if ev.event == "prompt":
        if ev.prompt:
            update_state(repo, lambda s: session_state(s, session_key(ev)).update(
                user_prompt=ev.prompt, prompt_at=datetime.now(timezone.utc).isoformat()))
        if _active_pre(session):
            return Decision()
        return Decision(action="notify", reason=f"Guard: before editing files, {PRE_HINT}.")

    if ev.event == "before-commit" or (ev.event == "before-edit" and ev.command is not None
                                       and is_git_commit(ev.command, repo)):
        if other:
            return Decision(action="block", reason=(
                f"Guard: {_held_reason(session)}; its approval is not yours to commit. Use `git worktree add` "
                "for parallel work, or wait until it is committed."))
        return _commit_decision(repo, session)  # a harness hook dedicated to commits: always gated

    if ev.event == "before-edit":
        if tool in READ_TOOLS:
            return Decision()
        shell = tool in SHELL_TOOLS or (ev.command is not None and not ev.file_paths)
        unclassified = bool(tool) and tool not in EDIT_TOOLS and not shell and not ev.file_paths
        if shell and ev.command and ev.agent_session and GUARD_PRE.search(ev.command):
            # the guard pre this command starts belongs to this agent session (its owner)
            update_state(repo, lambda s: _claim(s, session_key(ev), ev.agent))
        if (shell and ev.command and not is_read_only(ev.command)) or unclassified:
            # An unknown command, or a tool guard cannot classify that names no file: it runs, and
            # what it changed is measured afterwards (the after-tool event)
            fingerprint = worktree_fingerprint(repo)
            session_json = repo / ".guard" / "session.json"
            fingerprint[".guard/session.json"] = content_hash(session_json) if session_json.is_file() else ""
            if ev.command:
                fingerprint["__command__"] = ev.command
            update_state(repo, lambda s: session_state(s, session_key(ev)).setdefault("bash", {}).__setitem__(
                ev.call_id or "last", fingerprint))
            return Decision()
        if shell:
            return Decision()  # read-only command
        return _edit_decision(repo, session, ev, other)

    if ev.event == "after-bash":
        return _after_bash(repo, session, ev, other)

    if ev.event == "stop":
        return _stop_decision(repo, session, ev, other)

    return Decision()


def _ignored_by_the_user(repo: Path, paths: List[str]) -> set:
    """
    Paths the user chose to always ignore (`guard untracked <path> --ignore`, e.g. an agent's plans/):
    never part of the repository, so an edit there is not guarded. Only that choice counts: a file
    .gitignore hides (.env, build output) stays guarded. An unreadable registry ignores nothing.
    """
    from guard.core.untracked import RegistryError, covers, load_decisions
    try:
        ignored = [d for d, choice in load_decisions(repo).items() if choice == "ignore"]
    except (RegistryError, OSError, ValueError):
        return set()
    return {p for p in paths if any(covers(d, p) for d in ignored)}


def _is_guard_path(path_str: str) -> bool:
    norm = path_str.replace("\\", "/").strip("/").lower()
    if not (norm == ".guard" or norm.startswith(".guard/")):
        return False
    if norm == ".guard/notes.txt":
        return False
    return True


def _edit_decision(repo: Path, session, ev: AgentEvent, other: bool = False) -> Decision:
    all_targets = [r for r in (_relative(repo, p) for p in ev.file_paths) if r]
    if any(_is_guard_path(r) for r in all_targets):
        return Decision(action="block", reason="Guard: guard's state is written only by guard commands.")
    targets = [t for t in all_targets if not (t.replace("\\", "/").strip("/").lower() == ".guard"
                                              or t.replace("\\", "/").strip("/").lower().startswith(".guard/"))]
    targets = [t for t in targets if t not in _ignored_by_the_user(repo, targets)]
    if not targets:
        return Decision()
    if other and _active_pre(session):
        return Decision(action="block", reason=(
            f"Guard: {_held_reason(session)}. Use `git worktree add` for parallel work, or wait until it is committed."))
    if not _active_pre(session):
        why = "the last guard session was approved; this is new work" if session and session.status == SessionStatus.COMPLETED \
            else "there is no guard session for this task"
        return Decision(action="block", reason=f"Guard: {why}. Before editing {', '.join(targets)}, {PRE_HINT}.")
    scope = session.pre.expected_files
    if not scope:  # with the hook, edits need a declared scope: otherwise nothing bounds the task
        return Decision(action="block", reason=(
            f"Guard: this guard session declares no scope. Restart it with the files the task changes: "
            f"`guard pre --force \"<task>\" --scope {' --scope '.join(targets)}`."
        ))
    outside = [t for t in targets if not GitDiffInspector(repo)._is_expected(t, scope)]
    if outside:
        return Decision(action="block", reason=(
            f"Guard: {', '.join(outside)} is outside the declared scope. If the task needs it, restart with "
            f"`guard pre --force \"<task>\" --scope {' --scope '.join(outside)}` (reported as SCOPE-004), otherwise leave it."
        ))
    return Decision()


def _record_changes(repo: Path, ev: AgentEvent, key: str, changed: List[str]) -> None:
    """Add `changed` to this agent session's list `key` (the shared top level without an id)."""
    def add(state):
        own = session_state(state, session_key(ev))
        own[key] = sorted(set(own.get(key) or []) | set(changed))
    update_state(repo, add)


def _after_bash(repo: Path, session, ev: AgentEvent, other: bool = False) -> Decision:
    before = update_state(repo, lambda s: (session_state(s, session_key(ev)).get("bash") or {}).pop(ev.call_id or "last", None))
    if before is None:
        return Decision()  # read-only command, or no fingerprint was taken
    session_json = repo / ".guard" / "session.json"
    after_session_hash = content_hash(session_json) if session_json.is_file() else ""
    before_session_hash = before.pop(".guard/session.json", None)
    cmd = ev.command or before.pop("__command__", "")
    session_changed = before_session_hash is not None and before_session_hash != after_session_hash
    if session_changed and not is_guard_command(cmd):
        return Decision(
            action="notify",
            reason="Guard: that command changed .guard/session.json; guard's state is written only by guard commands.",
        )
    after = worktree_fingerprint(repo)
    committed = before.get(HEAD_KEY) != after.get(HEAD_KEY) and bool(before.get(HEAD_KEY))
    changed = [c for c in changed_between(before, after) if not c.startswith(".guard/") and c != HEAD_KEY and not c.startswith("__")]
    if committed and (other or _commit_decision(repo, session).action == "block"):  # a commit got past the check
        return Decision(action="notify", reason=(
            f"Guard: that command made a commit ({after.get(HEAD_KEY, '')[:12]}) without an approved guard review. "
            "Tell the user; run `guard post` on the work and get it approved before anything is pushed."
        ))
    if not changed:
        return Decision()
    if other and _active_pre(session):
        # what the owner's agent changed meanwhile stays the owner's; the rest is this session's own work
        scope = session.pre.expected_files
        own = [c for c in changed if not (scope and GitDiffInspector(repo)._is_expected(c, scope))]
        if not own:
            return Decision()
        _record_changes(repo, ev, "own_changes", own)
        return Decision(action="notify", reason=(
            f"Guard: that command changed {', '.join(own)} while {_held_reason(session)}. Undo it, or do this "
            "work in a separate `git worktree add`."))
    if not _active_pre(session):
        _record_changes(repo, ev, "pre_edit_changes", changed)
        return Decision(action="notify", reason=(
            f"Guard: that command changed {', '.join(changed)} before any guard session. Stop editing and {PRE_HINT}; "
            "these files are reported as changed before pre."
        ))
    scope = session.pre.expected_files
    outside = [c for c in changed if scope and not GitDiffInspector(repo)._is_expected(c, scope)]
    if outside:
        return Decision(action="notify", reason=(
            f"Guard: that command changed {', '.join(outside)}, outside the declared scope. Undo it if it was not "
            "intended, or declare it with `guard pre --force ... --scope` (reported as SCOPE-004)."
        ))
    return Decision()


POST_MARKER = "post-running.json"


def _pid_alive(pid: int) -> bool:
    # Reject non-positive or non-integer PIDs to prevent POSIX waitpid reaping / signal broadcast
    if not isinstance(pid, int) or pid <= 0:
        return False
    if os.name == "nt":  # os.kill(pid, 0) would terminate the process on Windows
        import ctypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        kernel32.CloseHandle(handle)
        return bool(ok) and code.value == 259  # STILL_ACTIVE
    try:
        # Reap our finished child so zombie processes are not treated as alive on POSIX
        if os.waitpid(pid, os.WNOHANG)[0] != 0:
            return False
    except ChildProcessError:
        pass
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class post_running:
    """`.guard/post-running.json` with this process id while guard post works; removed when it ends."""

    def __init__(self, repo: Path):
        self.path = repo / ".guard" / POST_MARKER

    def __enter__(self):
        from guard.core.git_exclude import write_bytes_atomic
        try:
            # atomic, and never through a symlink someone placed at the marker's path
            write_bytes_atomic(self.path, json.dumps({"pid": os.getpid(), "since": datetime.now(timezone.utc).isoformat()}).encode("utf-8"))
        except OSError:
            pass  # only a courtesy for waiting agents: never a reason for post to fail
        return self

    def __exit__(self, *exc):
        try:
            # only this post's own marker: a second post running meanwhile keeps its marker
            if json.loads(self.path.read_text(encoding="utf-8")).get("pid") == os.getpid() and not self.path.is_symlink():
                self.path.unlink()
        except (OSError, ValueError, AttributeError):
            pass


def _post_in_progress(repo: Path) -> bool:
    import stat
    path = repo / ".guard" / POST_MARKER
    try:
        # Only a small regular file is read (never a symlink, FIFO or device that could hang the hook)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            return False
        with open(path, "rb") as f:
            pid = int(json.loads(f.read(4096).decode("utf-8"))["pid"])
    except (OSError, ValueError, KeyError, TypeError):
        return False
    return pid != os.getpid() and _pid_alive(pid)  # a marker left by a killed post does not count


POST_WAIT_S = 540  # under the harness's 600 s hook limit


def _wait_for_post(repo: Path) -> bool:
    """
    Wait while a guard post runs (its marker names a live process), then let the caller decide on
    the session as it is then. A marker proves nothing (anyone can write one), so it only buys time:
    it never allows a stop by itself. True when a post was running.
    """
    deadline, waited = time.monotonic() + POST_WAIT_S, False
    while _post_in_progress(repo) and time.monotonic() < deadline:
        waited = True
        time.sleep(max(0.0, min(2.0, deadline - time.monotonic())))  # never past the limit
    return waited


def _stop_decision(repo: Path, session, ev: AgentEvent, other: bool = False) -> Decision:
    if ev.loop:
        return Decision()  # the harness already blocked once; never trap the agent
    if other:
        # Another agent's session holds the tree: never wait for its post, never answer for its edits.
        # Only what this session itself changed (a command that got past before-edit) stops it
        working = set(GitDiffInspector(repo).get_working_files())
        mine = session_state(load_state(repo), session_key(ev))
        own = [f for f in sorted(set(mine.get("own_changes") or []) | set(mine.get("pre_edit_changes") or []))
               if f in working]
        if own:
            return Decision(action="block", reason=(
                f"Guard: you changed {', '.join(own)} while {_held_reason(session)}. Undo it, or move the work "
                "to a separate `git worktree add`, then tell the user."))
        return Decision()
    if _wait_for_post(repo):  # the agent waits for a running guard post: decide on its result, once
        if _post_in_progress(repo):
            # Still running when the hook must answer (a full review takes longer than a hook may wait):
            # keep the agent from stopping, but never send it to start a second post
            return Decision(action="block", reason=(
                f"Guard: a guard post is still running (more than {POST_WAIT_S // 60} min so far). Do not start "
                "another one: wait until it finishes, then read .guard/POST_TASK_REPORT.md and act on it."))
        decision = _stop_on_session(repo, SessionManager(repo).load_local_session(), session_key(ev))
        if decision.action == "allow":
            return Decision(action="notify", reason="Guard: the guard post you waited for has finished; read its report and act on it.")
        return decision
    return _stop_on_session(repo, session, session_key(ev))


def _stop_on_session(repo: Path, session, agent_session: Optional[str] = None) -> Decision:
    if session and session.status == SessionStatus.NEEDS_USER:
        return Decision()  # stopping is right: the user decides (guard accept) before anything else
    if _active_pre(session):
        if _task_edits(repo, session) or session.status == SessionStatus.NEEDS_FIX:
            return Decision(action="block", reason="Guard: the task has edits without an approved guard post. Run `guard post` and fix what its report lists.")
        return Decision()
    if session and session.status == SessionStatus.COMPLETED:
        uncovered = _uncovered(repo, session)
        if uncovered:
            return Decision(action="block", reason=f"Guard: {', '.join(uncovered)} changed after the last approval. Run `guard post` again.")
        if not SessionManager.is_approval_verified(session):
            return Decision(action="block", reason="Guard: this approval is missing a valid signature. Run `guard post` again.")
        return Decision()
    pre_edit = session_state(load_state(repo), agent_session).get("pre_edit_changes") or []
    if pre_edit:
        return Decision(action="block", reason=(
            f"Guard: {', '.join(pre_edit)} changed without a guard session. Tell the user, or {PRE_HINT} and then run `guard post`."
        ))
    return Decision()


def _commit_decision(repo: Path, session) -> Decision:
    if session and session.status == SessionStatus.NEEDS_USER:
        return Decision(action="block", reason=(
            "Guard: this task used its review rounds and waits for the user. Stop and ask them: they run "
            "`guard accept` in their own terminal (accept the remaining findings, or allow more rounds)."))
    if not session or session.status != SessionStatus.COMPLETED or not session.post:
        return Decision(action="block", reason="Guard: commit only approved work. Run `guard post` until it approves, then commit.")
    if not SessionManager.is_approval_verified(session):
        return Decision(action="block", reason="Guard: this approval is missing a valid signature. Run `guard post` again before committing.")
    uncovered = _uncovered(repo, session, staged=True)
    if uncovered:
        return Decision(action="block", reason=f"Guard: {', '.join(uncovered)} changed after the last approval. Run `guard post` again before committing.")
    # The approval is enough: the Alibaba OCR review is optional (`guard post --full`), and the user is
    # asked about it before the commit (the report's Commit line), not forced by the gate
    return Decision()
