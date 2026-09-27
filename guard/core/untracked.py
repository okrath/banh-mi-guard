"""
Untracked paths in the user's repository (agent folders such as plans/, scratch files): the user
decides once per path whether it is part of the repository ("include") or never looked at again
("ignore": a line in the repository's info/exclude, local to this machine, no repository file
changes). Decisions live next to that exclude file, in the repository's common Git directory
(info/guard-untracked.json), so every linked worktree sees the same rule and the same decision;
they can be changed at any time.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import unicodedata
from pathlib import Path
from typing import Dict, List, Literal, Optional

DECISIONS_FILE = "guard-untracked.json"
MARK = "# guard: ignored (guard untracked --include removes it)"  # prefix; the entry follows
Choice = Literal["include", "ignore"]


def _decisions_path(repo: Path) -> Path:
    exclude = _exclude_file(repo)
    if exclude is None:
        raise ValueError(f"{repo} is not a Git repository")
    return exclude.parent / DECISIONS_FILE


def _inside_git_dir(repo: Path, path: Path) -> None:
    """Refuse a path that resolves outside the common Git directory (a symlinked info/ or file)."""
    common = _exclude_file(repo).parent.parent.resolve()
    try:
        path.resolve().relative_to(common)
    except ValueError:
        raise OSError(f"{path} resolves outside {common}; guard does not follow it")


class RegistryError(ValueError):
    """The decision registry exists but cannot be read: never treated as empty, never overwritten."""


def load_decisions(repo: Path) -> Dict[str, str]:
    """
    The recorded decisions; {} only when there is no registry yet. A registry that exists but is
    unreadable or malformed raises RegistryError, so a later decision cannot silently replace it.
    """
    try:
        path = _decisions_path(repo)
        _inside_git_dir(repo, path)
        if path.is_symlink() and not path.exists():  # 4. a dangling link is not "no registry"
            raise OSError(f"{path} is a symlink to a missing file")
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}  # none yet: guard's blocks still count
    except RegistryError:
        raise
    except (OSError, ValueError) as e:
        raise RegistryError(f"the untracked-path registry cannot be read ({e}); repair it, or delete it to start over") from e
    if not isinstance(data, dict) or not all(isinstance(k, str) and v in ("include", "ignore") for k, v in data.items()):
        raise RegistryError(f"{path} is not a map of path -> include|ignore; repair it, or delete it to start over")
    # The exclude block is the effect and the registry only records it: an "ignore" without guard's
    # block (removed by hand, or an undo that could not finish) no longer hides anything, so it is
    # dropped and the path is asked about again; a block without a record counts as "ignore".
    blocks = set(_ignored_by_guard(repo))
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


SAFE_NAME = re.compile(r"^[A-Za-z0-9._/ @+,=-]+$")


def suggest(entry: str) -> str:
    """
    The two commands for the entry, safe to copy into a shell: a name made only of safe characters
    is single-quoted (./-prefixed when it starts with a dash); any other name gets a placeholder,
    since no single quoting is safe in every shell.
    """
    if SAFE_NAME.fullmatch(entry):
        name = "'" + (("./" + entry) if entry.startswith("-") else entry) + "'"
    else:
        name = "<the path above>"
    return f"guard untracked {name} --include   or   guard untracked {name} --ignore"


FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _open_no_follow(path: Path) -> int:
    """
    Open (creating) a file descriptor without following a symlink or other reparse point. POSIX:
    O_NOFOLLOW. Windows has no O_NOFOLLOW: CreateFileW with FILE_FLAG_OPEN_REPARSE_POINT opens the
    link itself, never its target, and a reparse point that was opened is refused.
    """
    if os.name != "nt":
        return os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    import ctypes
    import msvcrt
    from ctypes import wintypes
    create = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create.restype = wintypes.HANDLE
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    generic_rw, share_rw, open_always = 0xC0000000, 0x1 | 0x2, 4
    flags = 0x80 | 0x00200000  # FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
    handle = create(str(path), generic_rw, share_rw, None, open_always, flags, None)
    if handle in (None, wintypes.HANDLE(-1).value):
        raise ctypes.WinError(ctypes.get_last_error())
    fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
    if getattr(os.fstat(fd), "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
        os.close(fd)
        raise OSError(f"{path} is a symlink or junction; guard does not follow it")
    return fd


class _Locked:
    """
    Serialises decide(): the exclude file and the registry are read, changed and written as one
    step. An OS lock on a lock file (msvcrt / fcntl): the OS releases it when the process ends, so
    there is no stale lock to clean up and no race in cleaning one.
    """

    def __init__(self, repo: Path):
        self.repo = repo
        self.path = _decisions_path(repo).with_suffix(".lock")

    def __enter__(self):
        _inside_git_dir(self.repo, self.path)
        fd = _open_no_follow(self.path)
        opened, on_disk = os.fstat(fd), os.lstat(self.path)
        if os.path.islink(self.path) or (opened.st_ino, opened.st_dev) != (on_disk.st_ino, on_disk.st_dev):
            os.close(fd)
            raise OSError(f"{self.path} is a symlink or was replaced while opening; guard does not follow it")
        self.f = os.fdopen(fd, "r+b")
        if os.name == "nt":
            import msvcrt
            import time
            for _ in range(1500):  # msvcrt only offers a non-blocking try; wait up to ~30 s
                try:
                    self.f.seek(0)
                    msvcrt.locking(self.f.fileno(), msvcrt.LK_NBLCK, 1)
                    return self
                except OSError:
                    time.sleep(0.02)
            self.f.close()
            raise OSError("another guard untracked command is running; try again")
        import fcntl
        fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        try:
            if os.name == "nt":
                import msvcrt
                self.f.seek(0)
                msvcrt.locking(self.f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
        finally:
            self.f.close()


def _save(repo: Path, decisions: Dict[str, str]) -> None:
    _write_bytes_atomic(_decisions_path(repo), json.dumps(dict(sorted(decisions.items())), indent=2).encode("utf-8"))


def normalise(path: str) -> str:
    """`plans`, `./plans/`, `plans\\` (Windows) -> `plans/` for a folder; files keep their name."""
    # A backslash is a separator only on Windows; elsewhere it is a valid character of a name.
    # Spaces are valid too: nothing is trimmed
    p = path.replace("\\", "/") if os.sep == "\\" else path
    while p.startswith("./"):
        p = p[2:]
    return p


def _is_guard_dir(entry: str) -> bool:
    return entry == ".guard" or entry == ".guard/" or entry.startswith(".guard/")


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


def shown(entry: str) -> str:
    """
    The entry for a Rich terminal: control characters and undecodable bytes are escaped, and so
    is Rich markup (a file named `[red]x` must print as that name, not change the output).
    """
    from rich.markup import escape
    return escape(printable(entry))


def printable(entry: str) -> str:
    """The entry as plain text: control characters and undecodable bytes escaped (no markup handling)."""
    if all(ch.isprintable() and not 0xDC80 <= ord(ch) <= 0xDCFF for ch in entry):
        return entry
    return entry.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace").encode("unicode_escape").decode("ascii")


def undecided(repo: Path, skip_task_files: bool = True) -> List[str]:
    """
    Untracked entries the user has not decided about (ignored ones are no longer listed by Git).
    Files a guard session's task created after its pre are the task's work, not something to ask about.
    """
    from guard.core.session import SessionManager, SessionStatus
    decisions = load_decisions(repo)
    session = SessionManager(repo).load_local_session()
    running = skip_task_files and session and session.pre and \
        session.status in (SessionStatus.AWAITING_POST, SessionStatus.NEEDS_FIX)
    baseline = set(session.pre.baseline_dirty) if running else None  # a finished task's baseline says nothing

    def decided(entry: str) -> bool:
        return any(entry == d or (d.endswith("/") and entry.startswith(d)) for d in decisions)

    def created_by_task(entry: str) -> bool:
        return baseline is not None and not any(
            b == entry or (entry.endswith("/") and b.startswith(entry)) for b in baseline)

    return [e for e in untracked_entries(repo) if not decided(e) and not created_by_task(e)]


def _exclude_file(repo: Path) -> Optional[Path]:
    try:
        res = subprocess.run(["git", "-C", str(repo), "rev-parse", "--git-common-dir"], capture_output=True, text=True)
    except OSError:
        return None
    common = (res.stdout or "").strip()
    if res.returncode != 0 or not common:
        return None
    git_dir = Path(common) if Path(common).is_absolute() else repo / common
    return git_dir / "info" / "exclude"


def _pattern(entry: str) -> str:
    """The entry as a literal gitignore pattern anchored at the repository root."""
    escaped = "".join("\\" + ch if ch in "*?[]\\!#" else ch for ch in entry)
    if escaped.endswith(" "):
        escaped = escaped[:-1] + "\\ "  # a trailing space is significant only when escaped
    return "/" + escaped


def _exclude_lines(entry: str) -> List[str]:
    """
    guard's block: a mark naming the entry, then its pattern; all lines must match for guard to
    remove them. A file rule is followed by "!/name/" so a folder that later takes the same name is
    not ignored with it (it is a different thing and is asked about again).
    """
    lines = [f"{MARK}: {entry}", _pattern(entry)]
    if not entry.endswith("/"):
        lines.append("!" + _pattern(entry) + "/")
    return lines


def _write_bytes_atomic(path: Path, data: bytes) -> None:
    """Replace `path` through a uniquely named temporary file next to it; a symlinked destination is refused."""
    if path.is_symlink():
        raise OSError(f"{path} is a symlink; guard does not write through it")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="." + path.name + ".", suffix=".guard-tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


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
        with _Locked(repo):
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
