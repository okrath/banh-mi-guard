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

from guard.agent.bash import (
    HEAD_KEY,
    changed_between,
    content_hash,
    is_git_commit,
    is_read_only,
    strict_target,
    worktree_fingerprint,
)
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


# The dialect strict_target parses a tool's command in; any other tool's command is parsed as unknown
SHELL_DIALECTS = {"bash": "bash", "powershell": "powershell"}


def _shell_quote(word: str, tool: str) -> str:
    """`word` quoted for the tool's shell, only when it needs it (PowerShell doubles a single quote)."""
    quoted = shlex.quote(word)
    if quoted == word or SHELL_DIALECTS.get(tool) != "powershell":
        return quoted
    return "'" + word.replace("'", "''") + "'"


def _same_repo(a: Path, b: Path) -> bool:
    return os.path.normcase(str(a.resolve())) == os.path.normcase(str(b.resolve()))


def _commit_repo(ev: AgentEvent, tool: str, cwd_repo: Path) -> Path:
    """
    The repository a commit command clearly runs in (`git -C <wt> commit`, `Set-Location <wt>; git commit`),
    or the cwd repository whenever that is not certain: the git pre-commit hook backstops the rest.
    """
    return _repo_of(_strict_commit_target(ev, tool), cwd_repo)


def _repo_of(target: Optional[str], cwd_repo: Path) -> Path:
    """The repository of a strict commit target, or the cwd repository when there is none."""
    from guard.core.repo_setup import repo_for_path
    return (repo_for_path(target) if target else None) or cwd_repo


def _strict_commit_target(ev: AgentEvent, tool: str) -> Optional[str]:
    """The directory a commit command certainly runs in, or None when the command does not say for certain."""
    if not ev.command:
        return None
    return strict_target(ev.command, str(Path(ev.cwd or ".").resolve()), shell=SHELL_DIALECTS.get(tool))


def _command_repos(ev: AgentEvent, tool: str, cwd_repo: Path, commit_repo: Optional[Path] = None) -> List[Path]:
    """
    The cwd repository, then every other repository the command names a directory of (`cd <wt> && ...`).
    Only measured and claimed, never trusted to allow anything: naming one too many costs time only.
    `commit_repo` is the commit's repository when the caller has already read it.
    """
    from guard.core.repo_setup import repo_for_path
    out = [cwd_repo, commit_repo or _commit_repo(ev, tool, cwd_repo)]
    cwd = Path(ev.cwd or ".").resolve()
    for tok in _tokenize(ev.command or "")[:64]:
        word = tok.strip("\"'")
        # never a UNC or device path (an unreachable host stalls the call), an option, a variable or a bare drive
        if not word or word.startswith(("\\\\", "//", "-")) or "$" in word or word.endswith(":"):
            continue
        p = Path(word) if Path(word).is_absolute() else cwd / word
        try:
            if p.is_dir():
                out.append(repo_for_path(p) or cwd_repo)
        except OSError:
            continue
    unique: List[Path] = []
    for r in out:
        if not any(_same_repo(r, u) for u in unique):
            unique.append(r)
    return unique


def _touched(cwd_repo: Path, ev: AgentEvent) -> List[Path]:
    """Other repositories this agent session worked in (recorded in the cwd repository's state) that still exist."""
    raw = session_state(load_state(cwd_repo), session_key(ev)).get("repos") or []
    return [Path(r) for r in raw if isinstance(r, str) and Path(r).is_dir() and not _same_repo(Path(r), cwd_repo)]


def _touch(cwd_repo: Path, ev: AgentEvent, repos: List[Path]) -> None:
    others = [str(r) for r in repos if not _same_repo(r, cwd_repo)]
    if others:
        def add(state):
            own = session_state(state, session_key(ev))
            own["repos"] = sorted(set(own.get("repos") or []) | set(others))
        update_state(cwd_repo, add)


def _in_repo(decision: Decision, repo: Path, cwd_repo: Path) -> Decision:
    """A decision about another repository than the cwd's names the repository it checked."""
    if decision.reason.startswith("Guard:") and not _same_repo(repo, cwd_repo):
        decision.reason = f"Guard ({repo}):{decision.reason[len('Guard:'):]}"
    return decision


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
    raw_claims = state.get("claims")
    claims: dict = raw_claims if isinstance(raw_claims, dict) else {}
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
    return (f"this working tree is held by another agent's guard session ({describe_owner(owner or {})}, task "
            f"\"{task}\", since {pre.timestamp[:16].replace('T', ' ')} UTC)")


# Executable patterns for guard: guard, guard.exe, python[3[.x]] -m guard, py [-3[.x]] -m guard
GUARD_EXEC_RE = (
    r"(?:(?:\"[^\"]*[/\\]guard(?:\.exe)?\"|'[^']*[/\\]guard(?:\.exe)?'|(?:\S*[/\\])?guard(?:\.exe)?)|"
    r"(?:\"[^\"]*[/\\](?:python(?:3(?:\.\d+)?)?|py)(?:\.exe)?\"|'[^']*[/\\](?:python(?:3(?:\.\d+)?)?|py)(?:\.exe)?'|(?:\S*[/\\])?(?:python(?:3(?:\.\d+)?)?|py)(?:\.exe)?)"
    r"(?:\s+-(?:[3\w.]+|\"[^\"]*\"|'[^']*'))*\s+-m\s+guard(?:\.exe)?)"
)

# `guard pre` as the command itself: at the start or after a shell separator, optionally behind
# variable assignments or a path; never as an argument (`grep guard pre docs/`)
GUARD_PRE = re.compile(
    rf"(?:^|[;&|(\n])\s*(?:\w+=\S*\s+)*{GUARD_EXEC_RE}\s+pre(?:\s|$)",
    re.IGNORECASE,
)

GUARD_SEG_RE = re.compile(
    rf"^[ \t]*(?:\w+=\S*[ \t]+)*{GUARD_EXEC_RE}(?:[ \t]+(.*))?$",
    re.IGNORECASE,
)


GUARD_SUSPECT_WRITE_RE = re.compile(
    r"(?:>>?|&>|\d+>>?)\s*\S*\.guard|\btee\s+(?:-\S+\s+)*\S*\.guard",
    re.IGNORECASE,
)

PYTHON_LAUNCHER_RE = re.compile(r"^(?:python(?:\d+(?:\.\d+)*)?|py)$", re.IGNORECASE)
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
SEPARATORS = {";", "&&", "||", "|", "&", "\n"}


def _tokenize(cmd_or_seg: str) -> List[str]:
    cleaned = re.sub(r"\d*>&[0-2]|\d*>>?&\d+", " ", cmd_or_seg)
    try:
        lex = shlex.shlex(cleaned, posix=False, punctuation_chars=";&|\n><")
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except (ValueError, OSError):
        return []


def _prog_name(tok: str) -> str:
    cleaned = tok.strip("\"'")
    name = cleaned.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def _is_run_subcommand(tokens: List[str]) -> bool:
    """Find the subcommand token (skipping flags and option arguments) and check if it is 'run'."""
    i = 0
    while i < len(tokens):
        tok = tokens[i].strip("\"'")
        if tok == "--":
            break
        if tok in ("--repo", "-r", "-a", "--agent"):
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        return tok.lower() == "run"
    return False


def is_single_segment_guard(seg: str) -> bool:
    tokens = _tokenize(seg)
    while tokens and ASSIGN_RE.match(tokens[0]):
        tokens.pop(0)
    if not tokens:
        return False

    prog = _prog_name(tokens[0])
    if prog == "guard":
        return not _is_run_subcommand(tokens[1:])

    if PYTHON_LAUNCHER_RE.match(prog):
        sub_tokens = tokens[1:]
        for idx, tok in enumerate(sub_tokens):
            if tok == "-m" and idx + 1 < len(sub_tokens):
                target = _prog_name(sub_tokens[idx + 1])
                if target == "guard":
                    return not _is_run_subcommand(sub_tokens[idx + 2:])
                break
            if not tok.startswith("-"):
                break
    return False


def _split_unquoted_segments(cmd: str) -> List[str]:
    tokens = _tokenize(cmd)
    if not tokens:
        return []
    segments: List[str] = []
    curr: List[str] = []
    for tok in tokens:
        if tok in SEPARATORS:
            if curr:
                segments.append(" ".join(curr))
                curr = []
        else:
            curr.append(tok)
    if curr:
        segments.append(" ".join(curr))
    return segments


def _is_benign_segment(seg: str) -> bool:
    if is_read_only(seg):
        return True
    tokens = _tokenize(seg)
    if not tokens:
        return False
    if any(t in (">", ">>", "<", "<<", ">|", "&>", "&>>", ">&") or t.startswith(">") or t.startswith("<") for t in tokens):
        return False
    words = [t for t in tokens if not ASSIGN_RE.match(t)]
    if words and _prog_name(words[0]) in ("cd", "pushd", "popd"):
        return True
    return False


def is_guard_command(cmd: str) -> bool:
    """True when cmd contains a guard command, counting compound commands for their guard part; guard run is excluded."""
    if not cmd or not cmd.strip():
        return False
    if "$(" in cmd or "`" in cmd or GUARD_SUSPECT_WRITE_RE.search(cmd):
        return False
    segments = _split_unquoted_segments(cmd)
    if not segments:
        return False
    has_guard = False
    for seg in segments:
        if is_single_segment_guard(seg):
            has_guard = True
        elif _is_benign_segment(seg):
            continue
        else:
            return False
    return has_guard


def _claim(state: Dict[str, Any], agent_session: str, agent: str) -> None:
    """Record that this agent session starts a `guard pre`; claims older than CLAIM_TTL_S go."""
    raw_claims = state.get("claims")
    claims_dict: dict = raw_claims if isinstance(raw_claims, dict) else {}
    now = time.time()
    claims = {s: c for s, c in claims_dict.items() if isinstance(c, dict) and now - c.get("at", 0) <= CLAIM_TTL_S}
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
        staged = subprocess.run(git + ["rev-parse", "-q", "--verify", f":{rel}"], capture_output=True, text=True,
                                encoding="utf-8", errors="replace").stdout.strip()
        on_disk = subprocess.run(git + ["hash-object", "--", rel], capture_output=True, text=True,
                                 encoding="utf-8", errors="replace").stdout.strip() \
            if (repo / rel).is_file() else ""
        if staged != on_disk:  # also a staged deletion of a file that still exists, and the reverse
            out.append(rel)
    return out


def _uncovered(repo: Path, session, staged: bool = False) -> List[str]:
    """
    Changed files not covered by the session's approval (all of them without an approval). With
    staged=True the staged content is checked too: `git add` then editing again commits the old text.
    """
    approved = SessionManager(repo).verified_approval(session)
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
    """
    Each check runs against the repository the event acts in: a commit's target (`git -C <wt> commit`),
    each edited file's repository, and for shell commands, stop and the prompt notice, the cwd repository
    plus the other repositories this agent session worked in.
    """
    repo = _repo(ev.cwd)
    if repo is None:
        return Decision()  # guard protects Git repositories only
    session = SessionManager(repo).load_local_session()
    tool = (ev.tool or "").lower()
    other = _from_another_session(ev, session)  # judged on its own work, not the owner's

    def load(r: Path):
        """The repository's guard session, and whether this event comes from another agent session than its owner."""
        s = session if _same_repo(r, repo) else SessionManager(r).load_local_session()
        return s, _from_another_session(ev, s)

    if ev.event == "prompt":
        if ev.prompt:
            update_state(repo, lambda s: session_state(s, session_key(ev)).update(
                user_prompt=ev.prompt, prompt_at=datetime.now(timezone.utc).isoformat()))
        if any(_active_pre(s) for s in [session] + [load(r)[0] for r in _touched(repo, ev)]):
            return Decision()
        return Decision(action="notify", reason=f"Guard: before editing files, {PRE_HINT}.")

    if ev.event == "before-commit" or (ev.event == "before-edit" and ev.command is not None
                                       and is_git_commit(ev.command, repo)):
        strict = _strict_commit_target(ev, tool)  # read once: the repository and the message below both need it
        target = _repo_of(strict, repo)
        _touch(repo, ev, [target])
        t_session, t_other = load(target)
        if t_other:
            return _in_repo(Decision(action="block", reason=(
                f"Guard: {_held_reason(t_session)}; its approval is not yours to commit. Use `git worktree add` "
                "for parallel work, or wait until it is committed.")), target, repo)
        decision = _commit_decision(target, t_session)  # a harness hook dedicated to commits: always gated
        named = [r for r in _command_repos(ev, tool, repo, target) if not _same_repo(r, target)]
        if decision.action == "block" and _same_repo(target, repo) and named and not strict:
            # The target could not be read for certain, so the cwd repository was checked: its verdict
            # would send the agent to approve the wrong repository. Forward slashes: bash never reads a
            # backslash path as certain, so the suggested command would be refused again
            names = ", ".join(r.as_posix() for r in named)
            commands = " or ".join(f"`git -C {_shell_quote(r.as_posix(), tool)} commit -F <message file>`" for r in named)
            return Decision(action="block", reason=(
                f"Guard: cannot tell which repository this commit runs in; it names {names}. Commit in the one "
                f"you mean with one plain command, nothing chained after it: {commands}."))
        return _in_repo(decision, target, repo)

    if ev.event == "before-edit":
        if tool in READ_TOOLS:
            return Decision()
        shell = tool in SHELL_TOOLS or (ev.command is not None and not ev.file_paths)
        unclassified = bool(tool) and tool not in EDIT_TOOLS and not shell and not ev.file_paths
        if shell and ev.command and ev.agent_session and GUARD_PRE.search(ev.command):
            # the guard pre this command starts belongs to this agent session (its owner), in whichever
            # repository it runs; the user's prompt goes with the claim, for that pre to record
            s_key = session_key(ev) or ""
            own = session_state(load_state(repo), s_key)
            prompt = {k: own[k] for k in ("user_prompt", "prompt_at") if own.get(k)}
            for r in _command_repos(ev, tool, repo):
                def claim(state, r=r):
                    _claim(state, s_key, ev.agent)
                    if not _same_repo(r, repo):
                        session_state(state, s_key).update(prompt)
                update_state(r, claim)
        if (shell and ev.command and not is_read_only(ev.command)) or unclassified:
            # An unknown command, or a tool guard cannot classify that names no file: it runs, and
            # what it changed is measured afterwards (the after-tool event), in the cwd repository and in every
            # other repository it names that guard already works in (a `.guard` folder: nothing new is written elsewhere)
            named = _command_repos(ev, tool, repo)[1:] if shell and ev.command else []
            repos = [repo] + [r for r in named if (r / ".guard").is_dir()]
            for r in repos:
                fingerprint = worktree_fingerprint(r)
                session_json = r / ".guard" / "session.json"
                fingerprint[".guard/session.json"] = content_hash(session_json) if session_json.is_file() else ""
                if ev.command:
                    fingerprint["__command__"] = ev.command
                update_state(r, lambda s, f=fingerprint: session_state(s, session_key(ev)).setdefault("bash", {}).__setitem__(
                    ev.call_id or "last", f))
            others = [str(r) for r in repos[1:]]
            if others:
                _touch(repo, ev, repos)
                update_state(repo, lambda s: session_state(s, session_key(ev)).setdefault("bash_repos", {}).__setitem__(
                    ev.call_id or "last", others))
            return Decision()
        if shell:
            return Decision()  # read-only command
        from guard.core.repo_setup import group_by_repo
        groups = group_by_repo(ev.file_paths, base=Path(ev.cwd or ".").resolve())
        _touch(repo, ev, [r for r in groups if r is not None])
        for r, paths in groups.items():
            if r is None:
                continue  # outside every repository: not guarded, as before
            r_session, r_other = load(r)
            decision = _edit_decision(r, r_session, ev.model_copy(update={"file_paths": paths}), r_other)
            if decision.action == "block":
                return _in_repo(decision, r, repo)
        return Decision()

    if ev.event == "after-bash":
        extra = update_state(repo, lambda s: (session_state(s, session_key(ev)).get("bash_repos") or {}).pop(
            ev.call_id or "last", None)) or []
        decisions = [_after_bash(repo, session, ev, other)]
        for r in (Path(x) for x in extra if isinstance(x, str) and Path(x).is_dir()):
            r_session, r_other = load(r)
            decisions.append(_in_repo(_after_bash(r, r_session, ev, r_other), r, repo))
        reasons = [d.reason for d in decisions if d.action != "allow"]
        return Decision(action="notify", reason=" ".join(reasons)) if reasons else Decision()

    if ev.event == "stop":
        deadline = time.monotonic() + POST_WAIT_S  # one wait for every repository, under the harness's hook limit
        decisions = [_stop_decision(repo, session, ev, other, deadline)]
        for r in _touched(repo, ev):
            r_session, r_other = load(r)
            decisions.append(_in_repo(_stop_decision(r, r_session, ev, r_other, deadline), r, repo))
        return next((d for d in decisions if d.action == "block"),
                    next((d for d in decisions if d.action != "allow"), Decision()))

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
    return True


def _edit_decision(repo: Path, session, ev: AgentEvent, other: bool = False) -> Decision:
    all_targets = [r for r in (_relative(repo, p) for p in ev.file_paths) if r]
    if any(_is_guard_path(r) for r in all_targets):
        return Decision(action="block", reason="Guard: guard's state is written only by guard commands.")
    targets = [t for t in all_targets if t not in _ignored_by_the_user(repo, all_targets)]
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
    saved_cmd = before.pop("__command__", None)
    cmd = ev.command or saved_cmd or ""
    session_changed = before_session_hash is not None and before_session_hash != after_session_hash
    session_notice = ""
    if session_changed and not is_guard_command(cmd):
        session_notice = "Guard: that command changed .guard/session.json; guard's state is written only by guard commands."
    after = worktree_fingerprint(repo)
    committed = before.get(HEAD_KEY) != after.get(HEAD_KEY) and bool(before.get(HEAD_KEY))
    changed = [c for c in changed_between(before, after) if not c.startswith(".guard/") and c != HEAD_KEY]

    normal_reasons: List[str] = []
    if committed and (other or _commit_decision(repo, session).action == "block"):  # a commit got past the check
        normal_reasons.append(
            f"Guard: that command made a commit ({after.get(HEAD_KEY, '')[:12]}) without an approved guard review. "
            "Tell the user; run `guard post` on the work and get it approved before anything is pushed."
        )
    elif changed:
        if other and _active_pre(session):
            # what the owner's agent changed meanwhile stays the owner's; the rest is this session's own work
            scope = session.pre.expected_files
            own = [c for c in changed if not (scope and GitDiffInspector(repo)._is_expected(c, scope))]
            if own:
                _record_changes(repo, ev, "own_changes", own)
                normal_reasons.append(
                    f"Guard: that command changed {', '.join(own)} while {_held_reason(session)}. Undo it, or do this "
                    "work in a separate `git worktree add`."
                )
        elif not _active_pre(session):
            _record_changes(repo, ev, "pre_edit_changes", changed)
            normal_reasons.append(
                f"Guard: that command changed {', '.join(changed)} before any guard session. Stop editing and {PRE_HINT}; "
                "these files are reported as changed before pre."
            )
        else:
            scope = session.pre.expected_files
            outside = [c for c in changed if scope and not GitDiffInspector(repo)._is_expected(c, scope)]
            if outside:
                normal_reasons.append(
                    f"Guard: that command changed {', '.join(outside)}, outside the declared scope. Undo it if it was not "
                    "intended, or declare it with `guard pre --force ... --scope` (reported as SCOPE-004)."
                )

    all_reasons = []
    if session_notice:
        all_reasons.append(session_notice)
    all_reasons.extend(normal_reasons)
    if all_reasons:
        return Decision(action="notify", reason=" ".join(all_reasons))
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


def _wait_for_post(repo: Path, deadline: Optional[float] = None) -> bool:
    """
    Wait while a guard post runs (its marker names a live process), then let the caller decide on
    the session as it is then. A marker proves nothing (anyone can write one), so it only buys time:
    it never allows a stop by itself. True when a post was running. `deadline` (monotonic) is shared
    when several repositories are checked in one hook call.
    """
    deadline, waited = deadline if deadline is not None else time.monotonic() + POST_WAIT_S, False
    while _post_in_progress(repo) and time.monotonic() < deadline:
        waited = True
        time.sleep(max(0.0, min(2.0, deadline - time.monotonic())))  # never past the limit
    return waited


def _stop_decision(repo: Path, session, ev: AgentEvent, other: bool = False,
                   deadline: Optional[float] = None) -> Decision:
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
    if _wait_for_post(repo, deadline):  # the agent waits for a running guard post: decide on its result, once
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
        if _task_edits(repo, session) and not SessionManager(repo).is_approval_verified(session):
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
    if not SessionManager(repo).is_approval_verified(session):
        return Decision(action="block", reason="Guard: this approval is missing a valid signature. Run `guard post` again before committing.")
    uncovered = _uncovered(repo, session, staged=True)
    if uncovered:
        return Decision(action="block", reason=f"Guard: {', '.join(uncovered)} changed after the last approval. Run `guard post` again before committing.")
    # The approval is enough: the Alibaba OCR review is optional (`guard post --full`), and the user is
    # asked about it before the commit (the report's Commit line), not forced by the gate
    return Decision()
