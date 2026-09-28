"""
Shell commands an agent runs: which ones are read-only, and which files a command changed.

A command is read-only only when every segment (split on ;, &&, ||, |, &) is a known reader and
nothing is redirected into a file. Anything else is not guessed at: it runs, and the working
tree is compared before and after (git status + content hashes) to see what it really changed.
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
from pathlib import Path
from typing import Dict, List, Optional

from guard.core.ocr_engine import GitDiffInspector

SEPARATORS = {";", "&&", "||", "|", "&", "\n"}
WRITES = {">", ">>", ">|", "&>", "&>>", ">&"}
READERS = {
    "ls", "dir", "cat", "type", "head", "tail", "wc", "grep", "egrep", "fgrep", "rg", "pwd", "echo",
    "which", "where", "tree", "stat", "file", "du", "df", "less", "more", "diff", "cmp", "basename",
    "dirname", "realpath", "readlink", "date", "whoami", "printenv", "true",
}
GIT_READERS = {"status", "diff", "log", "show", "blame", "rev-parse", "ls-files", "grep", "describe", "shortlog", "cat-file"}
FIND_WRITES = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"}
# Options that make an otherwise reading program write or change something
WRITE_OPTIONS = {"git": ("--output", "-o"), "tree": ("-o",), "date": ("-s", "--set"), "file": ("-C", "--compile")}
# guard subcommands that only read the repository (post runs the project's build, which may write)
GUARD_READERS = {"pre", "reset", "doctor", "status", "--help", "-h", "--version", "untracked"}
# Programs that run another command given as their arguments
WRAPPERS = {"env", "sudo", "nohup", "time", "nice", "xargs", "command", "exec", "timeout", "stdbuf"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "powershell", "pwsh"}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


# `<<` (not `<<<`), optional `-`, then a quoted delimiter (any text, e.g. 'END HERE') or a word
HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)\s*(?:'([^'\n]*)'|\"([^\"\n]*)\"|([^\s;&|<>()'\"]+))")


def _scan(line: str):
    """
    (code, open quote) for one line, as the shell reads it: a `#` starts a comment only outside
    quotes and at a word start (`a#b` is a word); the code is the line up to such a comment.
    """
    quote, prev = "", " "
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                prev = "x"
                continue
            if ch == quote:
                quote = ""
        elif ch == "\\":
            i += 2
            prev = "x"
            continue
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and prev in " \t;&|()":
            return line[:i], ""
        prev = ch
        i += 1
    return line, quote


def _is_operator(prefix: str) -> bool:
    """
    `<<` after this text is a shell operator, not text: the text before it is not in a comment and
    not inside quotes. When in doubt it is not a here-document, so no line is dropped (a real command
    after a `# <<EOF` comment or an `echo "<<EOF"` stays visible to the checks).
    """
    code, quote = _scan(prefix)
    escaped = (len(prefix) - len(prefix.rstrip("\\"))) % 2 == 1  # `\<<EOF` is a `<` and a redirect
    return code == prefix and not quote and not escaped


def strip_heredocs(command: str) -> str:
    """
    The command without here-document bodies: a message such as `git commit -F - <<'EOF'` followed by
    "guard's change" is text for the program, not shell syntax, and must not break the tokenizer.
    """
    lines, out, i = command.split("\n"), [], 0
    while i < len(lines):
        line = lines[i]
        found = [m for m in HEREDOC.finditer(line) if _is_operator(line[:m.start()])]
        out.append(HEREDOC.sub("", line) if found else line)
        i += 1
        for m in found:  # each here-document's body follows in order, up to its delimiter line
            delim, dash = next(g for g in m.groups()[1:] if g is not None), m.group(1) == "-"
            while i < len(lines) and (lines[i].lstrip("\t") if dash else lines[i]) != delim:
                i += 1
            i += 1  # the delimiter line itself
    return "\n".join(out)


def _tokens(command: str) -> Optional[List[str]]:
    # Heredoc bodies and comments are not commands; a line break separates commands like `;`
    # (a quoted string spanning lines then fails to parse, and the callers fail closed)
    lines = strip_heredocs(command.replace("\\\n", "")).split("\n")
    command = " ;\n".join(_scan(line)[0] for line in lines)
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:  # unbalanced quotes: not something to reason about
        return None


def _segments(tokens: List[str]) -> List[List[str]]:
    out, current = [], []
    for tok in tokens:
        if tok in SEPARATORS:
            if current:
                out.append(current)
            current = []
        else:
            current.append(tok)
    if current:
        out.append(current)
    return out


def _words(segment: List[str]) -> List[str]:
    """The segment without leading VAR=value assignments."""
    i = 0
    while i < len(segment) and ASSIGNMENT.match(segment[i]):
        i += 1
    return segment[i:]


def _git_subcommand(words: List[str]) -> Optional[str]:
    """`git -C dir -c k=v commit ...` -> "commit"."""
    i = 1
    while i < len(words):
        w = words[i]
        if w in ("-C", "-c", "--git-dir", "--work-tree", "--namespace"):
            i += 2
            continue
        if w.startswith("-"):
            i += 1
            continue
        return w
    return None


def _program(words: List[str]) -> str:
    name = words[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name[:-4] if name.endswith((".exe", ".cmd", ".bat")) else name


def _writes_by_option(prog: str, words: List[str]) -> bool:
    opts = WRITE_OPTIONS.get(prog, ())
    return any(w == o or w.startswith(o + "=") or (o.startswith("--") and w.startswith(o)) for w in words[1:] for o in opts)


def _segment_reads_only(words: List[str]) -> bool:
    if not words:
        return True
    prog = _program(words)
    if _writes_by_option(prog, words):
        return False
    if prog == "git":
        sub = _git_subcommand(words)
        if sub == "branch":  # listing only
            return all(w.startswith("-") and w in ("-a", "-r", "-v", "-vv", "--list", "--show-current") for w in words[2:])
        return sub in GIT_READERS
    if prog == "find":
        return not any(w in FIND_WRITES for w in words[1:])
    if prog == "guard":
        sub = next((w for w in words[1:] if not w.startswith("-") or w in GUARD_READERS), None)
        return sub in GUARD_READERS or (sub == "invariants" and "check" in words) or (sub == "config" and len(words) == 2)
    return prog in READERS


def is_read_only(command: str) -> bool:
    if "$(" in command or "`" in command or "<(" in command or ">(" in command:
        return False  # command substitution runs something we did not look at
    if "<<" in command:
        return False  # a here-document: measured, not guessed (a misread body could hide a command)
    tokens = _tokens(command)
    if tokens is None or any(t in WRITES or t.startswith((">", "&>")) for t in tokens):
        return False
    if any(_program(_words(s)) == "tee" for s in _segments(tokens) if _words(s)):
        return False
    return all(_segment_reads_only(_words(s)) for s in _segments(tokens))


def _unwrap(words: List[str]) -> List[str]:
    """`env A=1 sudo nohup git commit` -> `git commit`: the command a wrapper runs."""
    while words and _program(words) in WRAPPERS:
        # Wrapper options take arguments of their own (sudo -u me, timeout 30): rather than knowing
        # each one, jump to the first word that is git or a shell
        rest = words[1:]
        start = next((i for i, w in enumerate(rest) if _program([w]) in {"git"} | SHELLS | WRAPPERS), None)
        if start is None:
            return []
        words = rest[start:]
    return words


def _git_alias(repo: Optional[Path], name: str) -> str:
    if repo is None:
        return ""
    import subprocess
    res = subprocess.run(["git", "-C", str(repo), "config", "--get", f"alias.{name}"], capture_output=True, text=True)
    return (res.stdout or "").strip()


# `git`, its global options (-C <dir>, -c <k=v>, --flag[=value]), then the `commit` subcommand
COMMIT_SHAPE = re.compile(
    r"(?:^|[;&|(`])\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*"  # at a command position (VAR=x prefixes allowed)
    r"git(?:\s+(?:-[Cc]\s+\S+|-\S+))*\s+commit(?:\s|$)"
)


def _looks_like_commit(command: str) -> bool:
    """
    A commit found without trusting the tokenizer: every line as the shell sees it (continuations
    joined, comments removed), heredoc bodies included. Stripping a heredoc wrongly can then never
    hide a commit; the cost is a rare false alarm for a message line that starts with `git commit`.
    """
    for line in command.replace("\\\n", " ").split("\n"):
        if COMMIT_SHAPE.search(_scan(line)[0]):
            return True
    return False


def is_git_commit(command: str, repo: Optional[Path] = None, _depth: int = 0) -> bool:
    """
    Whether the command makes a Git commit, looking through wrappers (env, sudo, xargs, ...),
    shells given a command string (sh -c "..."), and git aliases (git ci -> commit).
    """
    if _depth > 3:
        return False
    if _looks_like_commit(command):
        return True
    tokens = _tokens(command)
    if tokens is None:
        # Cannot be parsed (an open quote): any line naming git and then commit counts, whatever wraps
        # it (sudo, --git-dir <dir>, …), so a quote in a message never lets a commit past the gate
        return any(re.search(r"\bgit\b.*\bcommit\b", _scan(line)[0]) for line in command.replace("\\\n", " ").split("\n"))
    for seg in _segments(tokens):
        words = _unwrap(_words(seg))
        if not words:
            continue
        prog = _program(words)
        if prog in SHELLS:
            def runs_string(w: str) -> bool:  # -c, combined short flags such as -lc, cmd /c, -Command
                low = w.lower()
                return low in ("/c", "-command") or (low.startswith("-") and not low.startswith("--") and "c" in low[1:])
            inner = next((words[i + 1] for i, w in enumerate(words[:-1]) if runs_string(w)), None)
            if inner and is_git_commit(inner, repo, _depth + 1):
                return True
            continue
        if prog != "git":
            continue
        sub = _git_subcommand(words)
        if sub == "commit":
            return True
        alias = _git_alias(repo, sub) if sub else ""
        if alias:
            expanded = alias[1:] if alias.startswith("!") else "git " + alias
            if is_git_commit(expanded, repo, _depth + 1):
                return True
    return False


def content_hash(path: Path) -> str:
    if path.is_symlink():  # the link itself is the content: retargeting it is a change
        return "link:" + os.readlink(path)
    if not path.is_file():
        return "<deleted>"
    digest = hashlib.sha1()  # streamed: large files are never read into memory at once
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


HEAD_KEY = "<HEAD>"


def worktree_fingerprint(repo: Path) -> Dict[str, str]:
    """
    Changed, staged and untracked files (git status) with their content hash; ignored files are not
    in it. HEAD is recorded too, so a commit the command made is seen afterwards.
    """
    out = {p: content_hash(repo / p) for p in GitDiffInspector(repo).get_working_files()}
    out[HEAD_KEY] = GitDiffInspector(repo).get_head() or ""
    return out


def changed_between(before: Dict[str, str], after: Dict[str, str]) -> List[str]:
    return sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))
