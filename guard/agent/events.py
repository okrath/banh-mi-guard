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
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from guard.agent.bash import HEAD_KEY, changed_between, content_hash, is_git_commit, is_read_only, worktree_fingerprint
from guard.core.ocr_engine import GitDiffInspector
from guard.core.session import SessionManager, SessionStatus

EVENTS = ("prompt", "before-edit", "after-bash", "stop", "before-commit")
EDIT_TOOLS = {"edit", "write", "multiedit", "notebookedit"}
# Tools known to only read; any other tool that names a file is treated as one that edits it
READ_TOOLS = {"read", "grep", "glob", "ls", "notebookread", "webfetch", "websearch", "todowrite",
              "view", "read_file", "list_directory", "search", "find"}
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


class Decision(BaseModel):
    action: Literal["allow", "block", "notify"] = "allow"
    reason: str = ""


def _get(payload: Any, path: str) -> Any:
    cur = payload
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
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
}


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
        loop=first("loop") is True or str(first("loop")).strip().lower() == "true",  # "false" is not true
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
    approved = session.post.approved_fingerprints if session and session.post else {}
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

    if ev.event == "prompt":
        if ev.prompt:
            update_state(repo, lambda s: s.update(user_prompt=ev.prompt, prompt_at=datetime.now(timezone.utc).isoformat()))
        if _active_pre(session):
            return Decision()
        return Decision(action="notify", reason=f"Guard: before editing files, {PRE_HINT}.")

    if ev.event == "before-commit":  # a harness hook dedicated to commits: always gated
        return _commit_decision(repo, session)
    if ev.event == "before-edit" and ev.command is not None and is_git_commit(ev.command, repo):
        return _commit_decision(repo, session)

    if ev.event == "before-edit":
        if tool in READ_TOOLS:
            return Decision()
        shell = tool in SHELL_TOOLS or (ev.command is not None and not ev.file_paths)
        unclassified = bool(tool) and tool not in EDIT_TOOLS and not shell and not ev.file_paths
        if (shell and ev.command and not is_read_only(ev.command)) or unclassified:
            # An unknown command, or a tool guard cannot classify that names no file: it runs, and
            # what it changed is measured afterwards (the after-tool event)
            fingerprint = worktree_fingerprint(repo)
            update_state(repo, lambda s: s.setdefault("bash", {}).__setitem__(ev.call_id or "last", fingerprint))
            return Decision()
        if shell:
            return Decision()  # read-only command
        return _edit_decision(repo, session, ev)

    if ev.event == "after-bash":
        return _after_bash(repo, session, ev)

    if ev.event == "stop":
        return _stop_decision(repo, session, ev)

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


def _edit_decision(repo: Path, session, ev: AgentEvent) -> Decision:
    targets = [r for r in (_relative(repo, p) for p in ev.file_paths) if r and not r.startswith(".guard/")]
    targets = [t for t in targets if t not in _ignored_by_the_user(repo, targets)]
    if not targets:
        return Decision()
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


def _after_bash(repo: Path, session, ev: AgentEvent) -> Decision:
    before = update_state(repo, lambda s: (s.get("bash") or {}).pop(ev.call_id or "last", None))
    if before is None:
        return Decision()  # read-only command, or no fingerprint was taken
    after = worktree_fingerprint(repo)
    committed = before.get(HEAD_KEY) != after.get(HEAD_KEY) and bool(before.get(HEAD_KEY))
    changed = [c for c in changed_between(before, after) if not c.startswith(".guard/") and c != HEAD_KEY]
    if committed and _commit_decision(repo, session).action == "block":  # a commit got past the before-commit check
        return Decision(action="notify", reason=(
            f"Guard: that command made a commit ({after.get(HEAD_KEY, '')[:12]}) without an approved guard review. "
            "Tell the user; run `guard post --full` on the work before anything is pushed."
        ))
    if not changed:
        return Decision()
    if not _active_pre(session):
        update_state(repo, lambda s: s.__setitem__("pre_edit_changes", sorted(set(s.get("pre_edit_changes") or []) | set(changed))))
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


def _stop_decision(repo: Path, session, ev: AgentEvent) -> Decision:
    if ev.loop:
        return Decision()  # the harness already blocked once; never trap the agent
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
        return Decision()
    pre_edit = load_state(repo).get("pre_edit_changes") or []
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
    uncovered = _uncovered(repo, session, staged=True)
    if uncovered:
        return Decision(action="block", reason=f"Guard: {', '.join(uncovered)} changed after the last approval. Run `guard post` again before committing.")
    if not session.post.ocr_complete:
        return Decision(action="block", reason=(
            "Guard: the approval has no completed Alibaba OCR review "
            f"({session.post.ocr_status or 'not run'}). Run `guard post --full` before committing."
        ))
    return Decision()
