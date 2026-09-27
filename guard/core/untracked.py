"""
Untracked paths in the user's repository (agent folders such as plans/, scratch files): the user
decides once per path whether it is part of the repository ("include") or never looked at again
("ignore": a line in the repository's info/exclude, local to this machine, no repository file
changes). Decisions live next to that exclude file, in the repository's common Git directory
(info/guard-untracked.json), so every linked worktree sees the same rule and the same decision;
they can be changed at any time.

This module is the registry and the decisions; info/exclude I/O and its lock are in git_exclude,
names and the exclude block in untracked_names.
"""

from __future__ import annotations

import json
import os
import subprocess
import unicodedata
from pathlib import Path
from typing import Dict, List, Literal

from guard.core.git_exclude import ExcludeLock
from guard.core.git_exclude import exclude_file as _exclude_file
from guard.core.git_exclude import inside_git_dir as _inside_git_dir
from guard.core.git_exclude import open_no_follow as _open_no_follow  # noqa: F401  (kept importable here)
from guard.core.git_exclude import write_bytes_atomic as _write_bytes_atomic
from guard.core.untracked_names import (  # noqa: F401  (public names of this module)
    MARK, exclude_lines as _exclude_lines, is_guard_dir as _is_guard_dir, normalise, printable, shown, suggest,
)

DECISIONS_FILE = "guard-untracked.json"
Choice = Literal["include", "ignore"]


def _decisions_path(repo: Path) -> Path:
    exclude = _exclude_file(repo)
    if exclude is None:
        raise ValueError(f"{repo} is not a Git repository")
    return exclude.parent / DECISIONS_FILE


class RegistryError(ValueError):
    """The decision registry exists but cannot be read: never treated as empty, never overwritten."""


def load_decisions(repo: Path) -> Dict[str, str]:
    """
    The recorded decisions; {} only when there is no registry yet. A registry that exists but is
    unreadable or malformed, or whose path cannot be resolved (a symlink loop), raises RegistryError,
    so a later decision cannot silently replace it.
    """
    try:
        path = _decisions_path(repo)
        _inside_git_dir(repo, path)
        if path.is_symlink() and not path.exists():  # a dangling (or looping) link is not "no registry"
            raise OSError(f"{path} is a symlink to a missing file")
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}  # none yet: guard's blocks still count
        blocks = set(_ignored_by_guard(repo))
    except RegistryError:
        raise
    except (OSError, ValueError, RuntimeError) as e:
        raise RegistryError(f"the untracked-path registry cannot be read ({e}); repair it, or delete it to start over") from e
    if not isinstance(data, dict) or not all(isinstance(k, str) and v in ("include", "ignore") for k, v in data.items()):
        raise RegistryError(f"{path} is not a map of path -> include|ignore; repair it, or delete it to start over")
    # The exclude block is the effect and the registry only records it: an "ignore" without guard's
    # block (removed by hand, or an undo that could not finish) no longer hides anything, so it is
    # dropped and the path is asked about again; a block without a record counts as "ignore".
    decisions = {k: v for k, v in data.items() if v != "ignore" or k in blocks}
    for entry in blocks:
        decisions[entry] = "ignore"
    return decisions


def _ignored_by_guard(repo: Path) -> List[str]:
    """Entries of the complete guard blocks in info/exclude (mark naming the entry, then its lines)."""
    exclude = _exclude_file(repo)
    if exclude is None or not exclude.is_file():
        return []
    lines = [line.rstrip(b"\r\n") for line in exclude.read_bytes().splitlines()]
    prefix = (MARK + ": ").encode("utf-8")
    out = []
    for i, line in enumerate(lines):
        if line.startswith(prefix):
            entry = line[len(prefix):].decode("utf-8", "surrogateescape")
            ours = [s.encode("utf-8", "surrogateescape") for s in _exclude_lines(entry)]
            if lines[i:i + len(ours)] == ours:
                out.append(entry)
    return out


def _save(repo: Path, decisions: Dict[str, str]) -> None:
    _write_bytes_atomic(_decisions_path(repo), json.dumps(dict(sorted(decisions.items())), indent=2).encode("utf-8"))


def untracked_entries(repo: Path) -> List[str]:
    """
    Untracked, not ignored paths as Git lists them: a new folder once (`plans/`), a new file or
    symlink by name. Raises RuntimeError when Git cannot list them: the check must not pass silently.
    """
    try:
        res = subprocess.run(
            ["git", "-C", str(repo), "-c", "core.quotepath=false", "ls-files", "--others", "--exclude-standard", "--directory", "-z"],
            capture_output=True,
        )
    except OSError as e:  # git could not even be started
        raise RuntimeError(f"could not run git: {e}") from e
    if res.returncode != 0:
        raise RuntimeError(f"git ls-files failed: {(res.stderr or b'').decode('utf-8', 'replace').strip()[:200]}")
    # surrogateescape keeps bytes that are not UTF-8 recognisable (they become lone surrogates),
    # while a real U+FFFD in a name stays a valid character
    entries = (p.decode("utf-8", "surrogateescape") for p in res.stdout.split(b"\0") if p)
    return [e for e in entries if not _is_guard_dir(e)]


def covers(decision: str, entry: str) -> bool:
    """A decision about `plans/` covers everything in it; a file decision covers only that file."""
    return entry == decision or (decision.endswith("/") and entry.startswith(decision))


def undecided(repo: Path, skip_task_files: bool = True) -> List[str]:
    """
    Untracked entries without a decision in effect. Git lists only paths it does not ignore, so an
    "ignore" never settles a listed entry: its rule is not in effect (a file and a folder of the same
    name, a negation of the user's), and the path is asked about again. Files a guard session's task
    created after its pre are the task's work, not something to ask about.
    """
    from guard.core.session import SessionManager, SessionStatus
    included = [d for d, choice in load_decisions(repo).items() if choice == "include"]
    session = SessionManager(repo).load_local_session()
    running = skip_task_files and session and session.pre and \
        session.status in (SessionStatus.AWAITING_POST, SessionStatus.NEEDS_FIX)
    baseline = set(session.pre.baseline_dirty) if running else None  # a finished task's baseline says nothing

    def created_by_task(entry: str) -> bool:
        return baseline is not None and not any(
            b == entry or (entry.endswith("/") and b.startswith(entry)) for b in baseline)

    return [e for e in untracked_entries(repo)
            if not any(covers(d, e) for d in included) and not created_by_task(e)]


def decide(repo: Path, path: str, choice: Choice) -> str:
    """
    Record and apply the user's choice; returns a one-line summary. The info/exclude change is
    applied first and the decision recorded second; if recording fails, info/exclude is put back, so
    nothing changes. A run killed between the two steps stays consistent, because guard's own block
    in info/exclude counts as the decision. Only guard's own lines are touched; the file's other bytes
    stay as they were.
    """
    entry = normalise(path)
    rename = "rename it first (git status shows it; e.g. `mv` / `ren`), then decide"
    if any(unicodedata.category(ch) == "Cc" or ch in "\u2028\u2029" for ch in entry):
        raise ValueError(f"{printable(entry)} contains control characters: {rename}")
    target = repo / entry.rstrip("/")
    if entry and not entry.endswith("/"):
        if os.path.lexists(target):
            is_folder = target.is_dir() and not target.is_symlink()  # a symlink is listed as a file
        else:
            is_folder = entry + "/" in load_decisions(repo)  # gone from disk: what was recorded
        if is_folder:
            entry += "/"  # a folder is written as Git lists it (plans/)
    if not entry or _is_guard_dir(entry):
        raise ValueError(f"{printable(repr(path))} is not a path guard decides about")
    exclude = _exclude_file(repo)
    if exclude is None:
        raise ValueError(f"{repo} is not a Git repository")
    try:
        exclude.parent.mkdir(parents=True, exist_ok=True)
        _inside_git_dir(repo, exclude)
        with ExcludeLock(repo):
            return _decide_locked(repo, entry, choice, exclude)
    except OSError as e:
        raise ValueError(f"could not apply the decision ({e}); nothing changed, run the command again") from e


def _decide_locked(repo: Path, entry: str, choice: Choice, exclude: Path) -> str:
    raw = exclude.read_bytes() if exclude.exists() else b""
    newline = b"\r\n" if b"\r\n" in raw else b"\n"
    lines = raw.splitlines(keepends=True)
    # surrogateescape writes a non-UTF-8 name back as the exact bytes Git listed
    ours = [s.encode("utf-8", "surrogateescape") for s in _exclude_lines(entry)]
    bare = [line.rstrip(b"\r\n") for line in lines]
    ours_at = [i for i in range(len(lines) - len(ours) + 1) if bare[i:i + len(ours)] == ours]

    decisions = load_decisions(repo)
    # guard's own exclude pair counts as a decision: a lost registry must not strand an ignored path
    try:
        listed = entry in decisions or bool(ours_at) or entry in untracked_entries(repo)
    except RuntimeError as e:
        raise ValueError(f"cannot list untracked paths: {e}") from e
    if not listed:
        raise ValueError(f"{printable(repr(entry))} is not an untracked path Git lists here (see `guard untracked`)")
    new_exclude = None
    if choice == "ignore" and not ours_at:
        tail = b"" if not raw or raw.endswith((b"\n", b"\r")) else newline
        new_exclude = raw + tail + b"".join(line + newline for line in ours)
    elif choice == "include" and ours_at:
        drop = {i for at in ours_at for i in range(at, at + len(ours))}
        new_exclude = b"".join(line for i, line in enumerate(lines) if i not in drop)
    # Apply first, record second: a decision is only saved once it is in effect, and a failed save
    # puts info/exclude back, so pre never treats a path as decided when the choice did not apply
    if new_exclude is not None:
        _write_bytes_atomic(exclude, new_exclude)
    try:
        _save(repo, {**decisions, entry: choice})
    except OSError as saved:
        if new_exclude is None:
            raise
        try:
            _write_bytes_atomic(exclude, raw)
        except OSError as undone:
            # info/exclude now differs from the record; say so instead of "nothing changed". The
            # next read reconciles from guard's blocks, and repeating the command finishes it.
            raise ValueError(
                f"info/exclude was changed but the decision could not be recorded ({saved}) or undone "
                f"({undone}); run the same command again to finish it"
            ) from undone
        raise
    if choice == "ignore":
        return f"{shown(entry)}: always ignored (local info/exclude; guard never looks at it)"
    return f"{shown(entry)}: always included (a normal part of the repository)"


ASK_USER = (
    "Ask the user once for each: is it part of the repository, or should guard always ignore it? Then run "
    "`guard untracked <path> --include` or `guard untracked <path> --ignore` (local to this machine, changeable later)."
)
