"""Reading `git diff` output: file headers, hunk headers, per-file chunks and a hunk-aware line walk.

Every module that reads a unified diff goes through here, so a path with spaces, a quoted path or a
removed `-- comment` line inside a hunk reads the same everywhere. What a caller does with the lines
(counting, scanning, line caps) stays with the caller.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Iterator

GIT_HEADER = "diff --git "
HUNK_RE = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@")
_ESCAPE = re.compile(rb'\\[0-7]{1,3}|\\[\\ntrbf"]')
_ESCAPES = {b"\\\\": b"\\", b'\\"': b'"', b"\\n": b"\n", b"\\t": b"\t", b"\\r": b"\r", b"\\b": b"\b", b"\\f": b"\f"}


def decode_git_path(path: str) -> str:
    """Decode a C-style quoted git path with octal escapes (`"caf\\303\\251"` -> `café`); others pass through."""
    p = path.strip()
    if len(p) < 2 or not (p.startswith('"') and p.endswith('"')):
        return p

    def _unescape(m: re.Match) -> bytes:
        seq = m.group(0)
        return bytes([int(seq[1:], 8) & 0xFF]) if seq[1:2].isdigit() else _ESCAPES[seq]

    return _ESCAPE.sub(_unescape, p[1:-1].encode("utf-8")).decode("utf-8", errors="replace")


def _strip_prefix(path: str) -> str:
    return path[2:] if path.startswith(("a/", "b/")) else path


def _quoted_token(text: str) -> tuple[str, str] | None:
    """Split a leading `"..."` token (backslash escapes respected) from the rest of `text`."""
    i = 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == '"':
            return text[:i + 1], text[i + 1:]
        i += 1
    return None


def parse_git_header(line: str) -> tuple[str, str] | None:
    """`diff --git a/old b/new` -> (old, new) without the a/ b/ prefixes, quoted paths decoded.

    An unquoted path may itself hold ` b/`: the split that gives two equal paths wins, else the last ` b/`.
    A rename's exact paths are on its `---`/`+++` lines, which `walk_diff` prefers.
    """
    if not line.startswith(GIT_HEADER):
        return None
    rest = line[len(GIT_HEADER):].rstrip("\r")
    if rest.startswith('"'):
        token = _quoted_token(rest)
        if token is None:
            return None
        old, new = token[0], token[1].strip()
    elif rest.endswith('"') and ' "' in rest:
        old, new = rest[:rest.rfind(' "')], rest[rest.rfind(' "') + 1:]
    else:
        half = (len(rest) - 1) // 2
        if len(rest) % 2 == 1 and rest[half] == " " and _strip_prefix(rest[:half]) == _strip_prefix(rest[half + 1:]):
            old, new = rest[:half], rest[half + 1:]
        elif " b/" in rest:
            cut = rest.rfind(" b/")
            old, new = rest[:cut], rest[cut + 1:]
        else:
            return None
    return _strip_prefix(decode_git_path(old)), _strip_prefix(decode_git_path(new))


def parse_file_header(line: str) -> str | None:
    """`--- a/x` or `+++ b/x` -> `x`, `/dev/null` -> ``, anything else -> None."""
    if not line.startswith(("--- ", "+++ ")):
        return None
    path = line[4:].rstrip("\r")
    if not path.startswith('"') and "\t" in path:  # a timestamp after a tab (non-git diffs)
        path = path.split("\t", 1)[0]
    path = decode_git_path(path)
    return "" if path == "/dev/null" else _strip_prefix(path)


def parse_hunk_header(line: str) -> tuple[int, int, int, int] | None:
    """`@@ -a,b +c,d @@` -> (a, b, c, d); a count left out is 1."""
    m = HUNK_RE.match(line)
    if not m:
        return None
    old_start, old_count, new_start, new_count = m.groups()
    return int(old_start), int(old_count or 1), int(new_start), int(new_count or 1)


def split_file_chunks(raw_diff: str) -> tuple[str, list[str]]:
    """(text before the first file, one chunk per file starting with `diff --git `), the text kept intact."""
    pieces = re.split(r"(?m)^(?=diff --git )", raw_diff)
    head = pieces[0] if pieces and not pieces[0].startswith(GIT_HEADER) else ""
    return head, [p for p in pieces if p.startswith(GIT_HEADER)]


def chunk_paths(chunk: str) -> tuple[str, str]:
    """(old, new) paths of one file chunk; the `---`/`+++` lines win over the `diff --git` line."""
    old = new = ""
    for d in walk_diff(chunk):
        if d.kind == "hunk":
            break
        old, new = d.old_path, d.path
    return old, new


@dataclass
class DiffLine:
    """One line of a diff with what it means.

    kind: `file` (a `diff --git` line), `header` (`---`/`+++` file header), `meta` (index, mode, rename,
    `Binary files`, text outside any file), `hunk` (`@@` header), `+`, `-`, ` ` (context) or `\\`
    (`\\ No newline at end of file`).
    """

    kind: str
    raw: str  # the line, without a trailing carriage return
    path: str  # the file's current path: the new path, or the old one for a deleted file
    old_path: str
    deleted: bool  # the file is deleted
    added: bool  # the file is new
    old_no: int = 0  # `-` and context: the line's number in the old file; `hunk`: the old start
    new_no: int = 0  # `+` and context: the line's number in the new file; `hunk`: the new start

    @property
    def text(self) -> str:
        """The line's content without its `+`/`-`/` ` marker (content kinds only)."""
        return self.raw[1:]


def walk_diff(diff: str | Iterable[str]) -> Iterator[DiffLine]:
    """Classify each line of a unified diff, tracking the current file and hunk.

    A hunk lasts as long as its `@@` counts say, so a removed `-- comment` or an added `++x` inside it is
    content, never a file header. A line that keeps the hunk's `+`/`-`/` ` form after the counts run out
    is still content (hand-written diffs miscount); an empty line inside a hunk is an empty context line.
    A `diff --git` line always starts a new file, even inside a hunk cut short. A `+`/`-` line outside any
    hunk that is not a file header is content too (a fragment without `@@`), numbered 0.
    """
    lines: Iterable[str] = diff
    if isinstance(diff, str):
        # split on \n only (not form feed or other separators); the final newline starts no empty line
        lines = diff[:-1].split("\n") if diff.endswith("\n") else diff.split("\n") if diff else []
    path = old_path = ""
    deleted = added = False
    old_left = new_left = 0
    in_hunk = False
    old_no = new_no = 0
    for raw in lines:
        line = raw[:-1] if raw.endswith("\r") else raw
        if line.startswith(GIT_HEADER):
            parsed = parse_git_header(line)
            old_path, path = parsed if parsed else ("", "")
            deleted = added = in_hunk = False
            yield DiffLine("file", line, path, old_path, deleted, added)
            continue
        if in_hunk:
            counted = old_left > 0 or new_left > 0
            kind = " " if not line and counted else line[:1]
            if kind == "\\":
                yield DiffLine("\\", line, path, old_path, deleted, added, old_no, new_no)
                continue
            if kind in ("+", "-", " ") and (counted or not line.startswith(("--- ", "+++ "))):
                d = DiffLine(kind, line or " ", path, old_path, deleted, added, old_no, new_no)
                if kind != "+":
                    old_no += 1
                    old_left -= 1
                if kind != "-":
                    new_no += 1
                    new_left -= 1
                yield d
                continue
            in_hunk = False
        hunk = parse_hunk_header(line)
        if hunk:
            old_no, old_left, new_no, new_left = hunk
            in_hunk = True
            yield DiffLine("hunk", line, path, old_path, deleted, added, old_no, new_no)
            continue
        header = parse_file_header(line)
        if header is not None:
            if line.startswith("--- "):
                old_path = header
                added = added or header == ""
            elif header:
                path = header
            else:
                deleted = True
                path = old_path or path
            yield DiffLine("header", line, path, old_path, deleted, added)
            continue
        if line[:1] in ("+", "-"):
            # Git puts no other +/- line outside a hunk: a bare fragment of a diff (no `@@`) still reads as content
            yield DiffLine(line[0], line, path, old_path, deleted, added)
            continue
        if line.startswith("deleted file mode"):
            deleted = True
        elif line.startswith("new file mode"):
            added = True
        yield DiffLine("meta", line, path, old_path, deleted, added)
