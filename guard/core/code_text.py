"""
Reading code text and file types, no rule knowledge.
"""

from __future__ import annotations

import re
from typing import Optional


PY = (".py",)

JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte")

CODE = PY + JS + (".go", ".rb", ".php", ".java", ".kt", ".cs", ".rs", ".swift", ".dart")

YAML = (".yaml", ".yml")

CSS = (".css", ".scss", ".sass", ".less")

MARKUP = (".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte")

def _is_test_path(path: str) -> bool:
    """A test file: in a tests/, test/ or __tests__/ folder, or named test_*, *_test.*, *.test.* or *.spec.*."""
    parts = path.split("/")
    name = parts[-1]
    return any(p in ("tests", "test", "__tests__") for p in parts[:-1]) or name.startswith("test_") or \
        bool(re.search(r"(?:_test|\.test|\.spec)\.[a-z0-9]+$", name))

def _scan(code: str, start: int = 0):
    """(index, character, in_string) for each character from `start`, following ' " ` strings and escapes."""
    quote, escaped = "", False
    for k in range(start, len(code)):
        ch = code[k]
        if quote:
            yield k, ch, True
            if ch == quote and not escaped:
                quote = ""
            escaped = ch == "\\" and not escaped
        elif ch in "'\"`":
            quote = ch
            yield k, ch, True
        else:
            yield k, ch, False

def _call_arguments(code: str, open_paren: int) -> str:
    """The text between a call's parenthesis at `open_paren` and the one that closes it (strings skipped)."""
    depth = 0
    for k, ch, in_string in _scan(code, open_paren):
        if in_string:
            continue
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0:
            return code[open_paren + 1:k]
    return code[open_paren + 1:]

def _comment_start(code: str, hash_comments: bool, spans: Optional[list] = None, blocks: tuple = ()) -> int:
    """
    Where the line's comment begins, outside any string (`#` or `//` by language, or a block comment
    not closed on the line); -1 for none. A block comment closed on the line (`/* note */ run(x)`) is not the
    end of the code: the scan goes on after it, and its (start, end) goes into `spans` when given.
    """
    closed_until = 0
    for k, ch, in_string in _scan(code):
        if in_string or k < closed_until:
            continue
        for opening, closing in blocks:
            if code.startswith(opening, k):
                end = code.find(closing, k + len(opening))
                if end < 0:
                    return k
                closed_until = end + len(closing)
                if spans is not None:
                    spans.append((k, closed_until))
        if k < closed_until:
            continue
        if (hash_comments and ch == "#") or (not hash_comments and code.startswith("//", k)):
            return k
    return -1

def _hash_comments(path_lower: str) -> bool:
    """`#` starts a comment in Python, YAML, shell and Dockerfiles; elsewhere `//` does (in Python `//` divides)."""
    return path_lower.endswith(PY + YAML + (".sh", ".rb", ".toml")) or _is_dockerfile(path_lower)

def _block_comments(path_lower: str) -> tuple:
    """Block comment pairs (opening, closing) allowed in the file type."""
    if _hash_comments(path_lower):
        return ()
    if path_lower.endswith((".html", ".htm", ".xml", ".svg")):
        return (("<!--", "-->"),)
    if path_lower.endswith((".jsx", ".tsx", ".vue", ".svelte")):
        return (("/*", "*/"), ("<!--", "-->"))
    if path_lower.endswith(CODE) or path_lower.endswith(CSS):
        return (("/*", "*/"),)
    return ()

def _carry_comment(open_comments: dict, path_lower: str, code: str) -> Optional[str]:
    """
    The line without the part inside a block comment an earlier line left open (None when all of it
    is), noting in `open_comments` whether this line leaves one open for the next.
    """
    blocks = _block_comments(path_lower)
    closing = open_comments.pop(path_lower, None)
    if closing:
        end = code.find(closing)
        if end < 0:
            open_comments[path_lower] = closing
            return None
        code = code[end + len(closing):]
    cut = _comment_start(code, _hash_comments(path_lower), blocks=blocks)
    for opening, closer in blocks:
        if cut >= 0 and code.startswith(opening, cut):
            open_comments[path_lower] = closer
    return code

def _tag_end(tag: str) -> int:
    """Where a tag closes: its first `>` outside `{...}` and quotes that is not part of `=>`; -1 when it goes on."""
    depth, quote = 0, ""
    for k, ch in enumerate(tag):
        if quote:
            if ch == quote and tag[k - 1:k] != "\\":
                quote = ""
            continue
        if depth <= 0 and ch in "'\"":
            quote = ch
            continue
        depth += (ch == "{") - (ch == "}")
        if ch == ">" and depth <= 0 and tag[k - 1:k] != "=":
            return k
    return -1

def _mask_strings(code: str) -> str:
    """The line with the inside of every string blanked, except `${...}` in template strings: what remains is code."""
    chars, quote, depth, inner, escaped = list(code), "", 0, "", False
    for k, ch, in_string in _scan(code):
        if not in_string:
            quote, depth, inner, escaped = "", 0, "", False
            continue
        if not quote:
            quote = ch
        if quote == "`" and code.startswith("${", k) and not depth:
            depth = 1
            continue
        if depth:
            if inner:
                if ch == inner and not escaped:
                    inner = ""
                else:
                    chars[k] = " "
                escaped = ch == "\\" and not escaped
            elif ch in "'\"":
                inner, escaped = ch, False
            elif ch == "{" and code[k - 1] != "$":
                depth += 1
            elif ch == "}":
                depth -= 1
            continue
        if ch not in "'\"`":
            chars[k] = " "
    return "".join(chars)

def _is_docs_path(path: str) -> bool:
    """A documentation page or example: in a docs/ or doc/ folder."""
    return any(p in ("docs", "doc") for p in path.split("/")[:-1])

def _is_dockerfile(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")
