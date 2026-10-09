"""
The build command `guard post` runs: the one set for the repository with `guard config build`, else the
one guard detects from its files.

The set command lives in the common Git directory (`.git/guard-build.json`): every worktree of the
repository reads it, and nothing in the working tree changes. It runs as an argument list, never
through a shell, so it holds one command without `&&`, pipes or redirections.
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
from pathlib import Path
from typing import List, Optional

from guard.core.git_exclude import exclude_file, inside_git_dir

STORE = "guard-build.json"
SHELL_OPERATOR_CHARS = "();<>|&"  # an unquoted word of only these is shell syntax: `&&`, `|`, `>`, `;`, `&`
NO_TESTS_EXIT = 5  # pytest: no tests collected; python -m unittest (3.12+): NO TESTS RAN
BUILD_HINT = 'Set the command for this repository with `guard config build "<command>"`.'


def _store(repo: Path) -> Optional[Path]:
    exclude = exclude_file(repo)
    return exclude.parent.parent / STORE if exclude else None


def configured_build_command(repo: Path) -> Optional[str]:
    """The command set with `guard config build` for this repository, if any."""
    path = _store(repo)
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path and path.is_file() else {}
    except (OSError, ValueError):
        return None
    command = data.get("command") if isinstance(data, dict) else None
    return command.strip() if isinstance(command, str) and command.strip() else None


def command_problem(command: str) -> Optional[str]:
    """Why `command` cannot run as one argument list, or None when it can (quoted operators are plain arguments)."""
    if "\n" in command or "\r" in command:
        return "it holds more than one line"
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        words = list(lexer)
    except ValueError as e:
        return f"it cannot be split into arguments ({e})"
    if not words:
        return "it is empty"
    op = next((w for w in words if w and set(w) <= set(SHELL_OPERATOR_CHARS)), None)
    if op:
        return f"`{op}` needs a shell"
    if re.match(r"[A-Za-z_]\w*=", words[0]):
        return f"`{words[0]}` sets a variable, which needs a shell"
    return None


def set_build_command(repo: Path, command: Optional[str]) -> Path:
    """Store `command` for the repository (None removes it); returns the file. OSError outside a Git repository."""
    path = _store(repo)
    if path is None:
        raise OSError(f"{repo} is not a Git repository")
    inside_git_dir(repo, path)
    if command is None:
        path.unlink(missing_ok=True)
    else:
        path.write_text(json.dumps({"command": command}, indent=2) + "\n", encoding="utf-8")
    return path


def build_command(repo: Path) -> tuple[Optional[str], bool]:
    """(the command post runs, whether it was set with `guard config build`); (None, False) when there is none."""
    from guard.domains.detector import detect_build_command
    configured = configured_build_command(repo)
    return (configured, True) if configured else (detect_build_command(repo), False)


def build_argv(command: str) -> List[str]:
    """
    `command` as an argument list (POSIX quoting on every OS: write paths with forward slashes), its program
    resolved on PATH (`pnpm` finds `pnpm.cmd` on Windows).
    """
    argv = shlex.split(command)
    if argv:
        argv[0] = shutil.which(argv[0]) or argv[0]
    return argv


def collected_no_tests(command: str, exit_code: int) -> bool:
    """True when a pytest or unittest run ended because it found no tests (exit 5), which is not a failure."""
    if exit_code != NO_TESTS_EXIT:
        return False
    try:
        words = shlex.split(command)
    except ValueError:
        return False
    if words and Path(words[0]).stem.lower() == "pytest":
        return True
    return (len(words) >= 3 and Path(words[0]).stem.lower().startswith(("python", "py"))
            and words[1] == "-m" and words[2] in ("pytest", "unittest"))
