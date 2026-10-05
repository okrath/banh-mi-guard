"""
The repository's info/exclude (local to this machine, in the common Git directory so linked
worktrees share it) and the one lock every guard writer of it takes: guard untracked, the .guard/
exclude, hook installation and workspace setup never lose each other's lines.
"""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Iterable, List, Optional

LOCK_FILE = "guard-exclude.lock"
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def exclude_file(repo: Path) -> Optional[Path]:
    try:
        res = subprocess.run(["git", "-C", str(repo), "rev-parse", "--git-common-dir"], capture_output=True, text=True)
    except OSError:
        return None
    common = (res.stdout or "").strip()
    if res.returncode != 0 or not common:
        return None
    git_dir = Path(common) if Path(common).is_absolute() else repo / common
    return git_dir / "info" / "exclude"


def inside_git_dir(repo: Path, path: Path) -> None:
    """
    Refuse a path that resolves outside the common Git directory (a symlinked info/ or file). A path
    that cannot be resolved at all (a symlink loop) is refused the same way: OSError, never a crash.
    """
    exclude = exclude_file(repo)
    if exclude is None:
        raise OSError(f"{repo} is not a Git repository")
    try:
        common = exclude.parent.parent.resolve()
        path.resolve().relative_to(common)
    except ValueError as e:
        raise OSError(f"{path} resolves outside {common}; guard does not follow it") from e
    except RuntimeError as e:  # a symlink loop, before Python 3.13
        raise OSError(f"{path} cannot be resolved ({e}); guard does not follow it") from e


def open_no_follow(path: Path) -> int:
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


class ExcludeLock:
    """
    Serialises every read-change-write of info/exclude (and of the untracked-path registry next to
    it). An OS lock on a lock file (msvcrt / fcntl): the OS releases it when the process ends, so
    there is no stale lock to clean up and no race in cleaning one.
    """

    def __init__(self, repo: Path):
        self.repo = repo
        exclude = exclude_file(repo)
        if exclude is None:
            raise OSError(f"{repo} is not a Git repository")
        self.path = exclude.parent / LOCK_FILE

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        inside_git_dir(self.repo, self.path)
        fd = open_no_follow(self.path)
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
            raise OSError("another guard command is changing info/exclude; try again")
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


def write_bytes_atomic(path: Path, data: bytes) -> None:
    """Replace `path` through a uniquely named temporary file next to it; a symlinked destination is refused."""
    if path.is_symlink():
        raise OSError(f"{path} is a symlink; guard does not write through it")
    path.parent.mkdir(parents=True, exist_ok=True)
    # mkstemp creates 0600: keep the replaced file's mode (a group-shared Git directory stays shared)
    mode = stat.S_IMODE(os.stat(path).st_mode) if path.exists() else 0o644
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="." + path.name + ".", suffix=".guard-tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _edit(repo: Path, change: Callable[[bytes, bytes], Optional[bytes]]) -> bool:
    """
    Apply `change(current bytes, newline) -> new bytes or None` to info/exclude under the lock.
    True when it wrote; False outside Git or when nothing needed to change.
    """
    exclude = exclude_file(repo)
    if exclude is None:
        return False
    exclude.parent.mkdir(parents=True, exist_ok=True)
    inside_git_dir(repo, exclude)
    with ExcludeLock(repo):
        raw = exclude.read_bytes() if exclude.exists() else b""
        new = change(raw, b"\r\n" if b"\r\n" in raw else b"\n")
        if new is None:
            return False
        write_bytes_atomic(exclude, new)
        return True


def _stripped(raw: bytes) -> List[str]:
    return [line.decode("utf-8", "surrogateescape").strip() for line in raw.splitlines()]


def ensure_excluded(repo: Path, pattern: str, comment: Optional[str] = None, same: Iterable[str] = ()) -> bool:
    """
    Append `pattern` (after an optional comment line) unless it, or an equivalent pattern in `same`,
    is already a line; the file's other bytes stay as they were. True when it was added.
    """
    def change(raw: bytes, newline: bytes) -> Optional[bytes]:
        if {pattern, *same} & set(_stripped(raw)):
            return None
        tail = b"" if not raw or raw.endswith((b"\n", b"\r")) else newline
        block = ([comment] if comment else []) + [pattern]
        return raw + tail + b"".join(s.encode("utf-8", "surrogateescape") + newline for s in block)
    return _edit(repo, change)


def remove_excluded(repo: Path, lines_to_drop: Iterable[str]) -> bool:
    """Remove every line equal (whitespace aside) to one in `lines_to_drop`. True when one went."""
    drop = set(lines_to_drop)

    def change(raw: bytes, newline: bytes) -> Optional[bytes]:
        lines = raw.splitlines(keepends=True)
        keep = [line for line in lines if line.decode("utf-8", "surrogateescape").strip() not in drop]
        return None if len(keep) == len(lines) else b"".join(keep)
    return _edit(repo, change)


def reword_excluded_comments(repo: Path, old: str, new: str) -> bool:
    """Replace `old` with `new` in comment lines (`# ...`); the patterns stay. True when one changed."""
    def change(raw: bytes, newline: bytes) -> Optional[bytes]:
        lines = raw.splitlines(keepends=True)
        out = [line.replace(old.encode("utf-8"), new.encode("utf-8"))
               if line.lstrip().startswith(b"#") else line for line in lines]
        return None if out == lines else b"".join(out)
    return _edit(repo, change)
