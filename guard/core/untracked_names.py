"""
Names of untracked paths: how the user writes them, how guard shows them (terminal and plain text,
never markup or control characters), the commands it suggests, and the literal info/exclude block
guard writes for an ignored path.
"""

from __future__ import annotations

import os
import re
from typing import List

MARK = "# guard: ignored (guard untracked --include removes it)"  # prefix; the entry follows
SAFE_NAME = re.compile(r"^[A-Za-z0-9._/ @+,=-]+$")


def normalise(path: str) -> str:
    """`plans`, `./plans/`, `plans\\` (Windows) -> `plans/` for a folder; files keep their name."""
    # A backslash is a separator only on Windows; elsewhere it is a valid character of a name.
    # Spaces are valid too: nothing is trimmed
    p = path.replace("\\", "/") if os.sep == "\\" else path
    while p.startswith("./"):
        p = p[2:]
    return p


def is_guard_dir(entry: str) -> bool:
    """guard's own `.guard/` directory and what is in it; a file named `.guard` or `.guardian/` is the user's."""
    return entry.startswith(".guard/")


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


def pattern(entry: str) -> str:
    """The entry as a literal gitignore pattern anchored at the repository root."""
    escaped = "".join("\\" + ch if ch in "*?[]\\!#" else ch for ch in entry)
    if escaped.endswith(" "):
        escaped = escaped[:-1] + "\\ "  # a trailing space is significant only when escaped
    return "/" + escaped


def exclude_lines(entry: str) -> List[str]:
    """
    guard's block: a mark naming the entry, then its pattern; all lines must match for guard to
    remove them. A file rule is followed by "!/name/" so a folder that later takes the same name is
    not ignored with it (it is a different thing and is asked about again).
    """
    lines = [f"{MARK}: {entry}", pattern(entry)]
    if not entry.endswith("/"):
        lines.append("!" + pattern(entry) + "/")
    return lines
