"""
Impact range: what a task is expected to touch, and what it actually touched.

At pre, every symbol defined in the scoped files (Python def/class, JS/TS exports, functions and
classes, CSS classes, string keys) is listed with the files that reference it (tracked, or untracked
and not ignored, so a task's new tests count), the tests
among them and the invariants whose check globs match the file. At post, the symbols the task diff
added, changed or removed are compared with that range: a changed symbol referenced from a file
the range did not list, and a changed symbol no test references, are reported (MEDIUM, never
blocking) and handed to the LLM reviewer as verified evidence. Work is bounded by caps, and every
cap that cut something is named in the report.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from guard.core.ocr_engine import GitDiffInspector, RuleViolation, glob_to_regex
from guard.core.removal_check import CODE_EXTS, REMOVED_CSS_CLASS, REMOVED_EXPORT, REMOVED_KEY, STYLE_EXTS

MAX_FILES = 40
MAX_SYMBOLS_PER_FILE = 60
MAX_REFS_PER_SYMBOL = 15
MAX_REPORTED = 20  # IMPACT-OUTSIDE findings per post

PY_DEF = re.compile(r"""^\s*(?:async\s+)?(def|class)\s+([A-Za-z_]\w*)""")
JS_DEF = re.compile(r"""^\s*(?:async\s+)?(function\*?|class)\s+([A-Za-z_$][\w$]*)""")
# A function bound to a name: `const draw = () => …`, `let f = async function …`, `var g = (a: T): R => …`
JS_FN_VAR = re.compile(
    r"""^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s+)?"""
    r"""(?:function\b|(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::[^=]+)?=>)"""
)
TEST_PATH = re.compile(r"""(^|/)(tests?|__tests__|spec)/|(^|/)test_[^/]*$|_test\.[^/.]+$|\.(test|spec)\.[^/]+$""")
HUNK = re.compile(r"""^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@""")


class ImpactSymbol(BaseModel):
    file: str
    name: str
    kind: str
    line: int
    references: List[str] = Field(default_factory=list)  # other tracked files that reference it
    tests: List[str] = Field(default_factory=list)  # the test files among all references
    capped: bool = False  # more referencing files than MAX_REFS_PER_SYMBOL: references is incomplete


class ImpactRange(BaseModel):
    symbols: List[ImpactSymbol] = Field(default_factory=list)
    invariants: Dict[str, List[str]] = Field(default_factory=dict)  # file -> ids whose check globs match it
    capped_files: List[str] = Field(default_factory=list)  # files with more than MAX_SYMBOLS_PER_FILE symbols
    notes: List[str] = Field(default_factory=list)  # what a cap cut


def is_test(path: str) -> bool:
    return bool(TEST_PATH.search(path))


def definitions(path: str, text: str) -> List[Tuple[int, str, str]]:
    """(line, name, kind) of every symbol defined in `text`, in file order."""
    out: List[Tuple[int, str, str]] = []
    style, code, py = path.endswith(STYLE_EXTS), path.endswith(CODE_EXTS), path.endswith(".py")
    for n, line in enumerate(text.splitlines(), 1):
        if style:
            selector = line.split("{", 1)[0]
            if "{" in line or selector.rstrip().endswith(","):
                out.extend((n, name, "css-class") for name in REMOVED_CSS_CLASS.findall(selector))
            continue
        if not code:
            continue
        # The removal check's patterns match removed diff lines, so a source line is read as one
        m = REMOVED_KEY.match("-" + line)
        if m:
            out.append((n, m.group(1), "string-key"))
            continue
        found = None
        if py:
            m = PY_DEF.match(line)
            found = m and m.groups()
        elif REMOVED_EXPORT.match("-" + line):
            found = ("export", REMOVED_EXPORT.match("-" + line).group(1))
        else:
            m = JS_DEF.match(line)
            found = (m and m.groups()) or (JS_FN_VAR.match(line) and ("function", JS_FN_VAR.match(line).group(1)))
        if found:
            kind, name = found
            if not (name.startswith("__") and name.endswith("__")):
                out.append((n, name, kind.rstrip("*")))
    return out


def _repo_files(repo: Path) -> List[str]:
    """Tracked files and untracked ones Git does not ignore (a task's new files are untracked until committed)."""
    res = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    return [n for n in (res.stdout or "").split("\0") if n]


def references(repo: Path, names: Iterable[str]) -> Dict[str, Set[str]]:
    """name -> files (tracked, or untracked and not ignored) that contain it as a whole word, in one git grep."""
    names = sorted(set(names))
    found: Dict[str, Set[str]] = {n: set() for n in names}
    if not names:
        return found  # an empty pattern list would match every line
    res = subprocess.run(
        ["git", "-C", str(repo), "grep", "--untracked", "-I", "-w", "-F", "-o", "-z", "-f", "-"],
        input="\n".join(names) + "\n", capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    for line in (res.stdout or "").splitlines():
        path, _, match = line.partition("\0")
        if match in found:
            found[match].add(path)
    return found


def _invariants_for(path: str, invariants: List[dict]) -> List[str]:
    return sorted({
        str(inv.get("id")) for inv in invariants
        for c in inv.get("checks") or []
        if c.get("files") and glob_to_regex(str(c["files"])).match(path)
    })


def expected_impact(repo: Path, scope: List[str], invariants: List[dict]) -> ImpactRange:
    """The expected impact range of the scoped files, as the repository is before the task."""
    inspector = GitDiffInspector(repo)
    files = sorted(
        {f for f in _repo_files(repo) if inspector._is_expected(f, scope)}
        | {s for s in scope if (repo / s).is_file()}
    )
    impact = ImpactRange()
    if len(files) > MAX_FILES:
        impact.notes.append(f"{len(files)} scoped files: symbols listed for the first {MAX_FILES} only")
        files = files[:MAX_FILES]

    per_file: Dict[str, List[Tuple[int, str, str]]] = {}
    for f in files:
        try:
            text = (repo / f).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        seen: Dict[str, Tuple[int, str, str]] = {}
        for d in definitions(f, text):
            seen.setdefault(d[1], d)
        symbols = list(seen.values())
        if len(symbols) > MAX_SYMBOLS_PER_FILE:
            impact.capped_files.append(f)
            impact.notes.append(f"`{f}` defines {len(symbols)} symbols: the first {MAX_SYMBOLS_PER_FILE} are listed")
            symbols = symbols[:MAX_SYMBOLS_PER_FILE]
        per_file[f] = symbols
        ids = _invariants_for(f, invariants)
        if ids:
            impact.invariants[f] = ids

    refs = references(repo, (name for symbols in per_file.values() for _, name, _ in symbols))
    capped = 0
    for f, symbols in per_file.items():
        for line, name, kind in symbols:
            others = sorted(refs.get(name, set()) - {f})
            sym = ImpactSymbol(
                file=f, name=name, kind=kind, line=line,
                references=others[:MAX_REFS_PER_SYMBOL], tests=[p for p in others if is_test(p)][:MAX_REFS_PER_SYMBOL],
                capped=len(others) > MAX_REFS_PER_SYMBOL,
            )
            capped += sym.capped
            impact.symbols.append(sym)
    if capped:
        impact.notes.append(f"{capped} symbol(s) are referenced from more than {MAX_REFS_PER_SYMBOL} files: "
                            f"the first {MAX_REFS_PER_SYMBOL} are listed")
    return impact


def _decorator(path: str, line: str) -> bool:
    return path.endswith(".py") and line.lstrip().startswith("@")


def _diff_changes(raw_diff: str) -> Dict[str, Tuple[Set[int], List[str]]]:
    """path -> (lines of the current file the diff touched, removed lines) per file of a unified diff."""
    changes: Dict[str, Tuple[Set[int], List[str]]] = {}
    old = current = ""
    new_line = 0
    in_removed_def = False
    for line in raw_diff.splitlines():
        if line.startswith("diff --git "):
            old = current = ""
            in_removed_def = False
            continue
        if line.startswith("--- "):
            old = line[6:] if line.startswith("--- a/") else ""
            continue
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else old  # a deleted file keeps its old path
            changes.setdefault(current, (set(), []))
            continue
        m = HUNK.match(line)
        if m:
            new_line = int(m.group(1))
            in_removed_def = False  # a removed definition's body never continues into another hunk
            continue
        if not current or not line or line[0] not in "+- ":
            continue
        touched, removed = changes[current]
        blank = not line[1:].strip()  # blank lines between definitions belong to no symbol's change
        if line[0] == "+":
            if not blank:
                touched.add(new_line)
            new_line += 1
        elif line[0] == "-":
            # Removed code belongs to the symbol of the line before it, unless it follows a removed
            # definition: then it is that symbol's body, gone with it
            in_removed_def = in_removed_def or bool(definitions(current, line[1:]))
            if _decorator(current, line[1:]):
                touched.add(new_line)  # a removed decorator belongs to the definition below it
            elif not blank and not in_removed_def:
                touched.add(max(new_line - 1, 1))
            removed.append(line[1:])
        else:
            new_line += 1
        if line[0] != "-":
            in_removed_def = False
    return changes


def changed_symbols(repo: Path, raw_diff: str) -> Tuple[List[Tuple[str, str, str, bool]], List[str]]:
    """
    (file, name, kind, removed) for the symbols the diff added, changed or removed, bounded by the
    same caps as pre, and a note for every cap that cut something.
    """
    out: List[Tuple[str, str, str, bool]] = []
    notes: List[str] = []
    changes = sorted(_diff_changes(raw_diff).items())
    if len(changes) > MAX_FILES:
        notes.append(f"{len(changes)} changed files: symbols checked in the first {MAX_FILES} only")
        changes = changes[:MAX_FILES]
    for path, (touched, removed_lines) in changes:
        target = repo / path
        text = target.read_text(encoding="utf-8", errors="ignore") if target.is_file() else ""
        defs = definitions(path, text)
        lines = text.splitlines()
        starts = []  # a symbol's span starts at the decorators right above its definition
        for line, _, _ in defs:
            while line > 1 and _decorator(path, lines[line - 2]):
                line -= 1
            starts.append(line)
        names: Dict[str, str] = {}
        for i, (_, name, kind) in enumerate(defs):
            end = starts[i + 1] if i + 1 < len(defs) else float("inf")
            if any(starts[i] <= t < end for t in touched):
                names.setdefault(name, kind)
        # A touched line above the first definition belongs to no symbol
        still = {name for _, name, _ in defs}
        gone = {name: kind for _, name, kind in definitions(path, "\n".join(removed_lines)) if name not in still}
        found = [(path, n, k, False) for n, k in names.items()] + [(path, n, k, True) for n, k in gone.items()]
        if len(found) > MAX_SYMBOLS_PER_FILE:
            notes.append(f"`{path}` has {len(found)} changed symbols: the first {MAX_SYMBOLS_PER_FILE} are checked")
            found = found[:MAX_SYMBOLS_PER_FILE]
        out.extend(found)
    return out, notes


def check_impact(
    repo: Path, raw_diff: str, expected: Optional[ImpactRange], scope: List[str],
) -> Tuple[List[RuleViolation], str]:
    changed, notes = changed_symbols(repo, raw_diff)
    if not changed:  # still say what a cap left unchecked
        return [], (f"Impact range check: no symbol added, changed or removed in the checked files ({'; '.join(notes)})."
                    if notes else "")
    refs = references(repo, (name for _, name, _, _ in changed))
    inspector = GitDiffInspector(repo)

    # The outside check needs the range pre listed; a session started before it existed has none
    check_outside = expected is not None and bool(scope)
    known: Dict[Tuple[str, str], ImpactSymbol] = {}
    listed: Set[str] = set()
    if check_outside:
        known = {(s.file, s.name): s for s in expected.symbols}
        listed = {p for s in expected.symbols for p in s.references + s.tests}
    elif expected is None:
        notes.append("the session has no expected impact range (started before it existed): outside-range check skipped")
    else:
        notes.append("no scope declared: outside-range check skipped")

    violations: List[RuleViolation] = []
    outside_names: List[str] = []
    skipped: List[str] = []
    untested: Dict[str, List[str]] = {}
    for path, name, kind, removed in changed:
        others = sorted(refs.get(name, set()) - {path})
        if check_outside:
            sym = known.get((path, name))
            if (sym and sym.capped) or (sym is None and path in expected.capped_files):
                skipped.append(f"`{name}`")  # pre could not list its whole range
            else:
                outside = [p for p in others if p not in listed and not inspector._is_expected(p, scope)]
                if outside:
                    outside_names.append(f"`{name}` ({', '.join(outside[:5])}{' …' if len(outside) > 5 else ''})")
                    if len(outside_names) <= MAX_REPORTED:
                        violations.append(RuleViolation(
                            rule_id="IMPACT-OUTSIDE",
                            severity="MEDIUM",
                            file_path=path,
                            message=(f"{'Removed' if removed else 'Changed'} {kind} `{name}` is referenced from "
                                     f"file(s) outside the expected impact range: {', '.join(outside[:10])}"
                                     f"{' …' if len(outside) > 10 else ''}."),
                        ))
        if not removed and not is_test(path) and not any(is_test(p) for p in others):
            untested.setdefault(path, []).append(name)

    for path, names in list(untested.items())[:MAX_REPORTED]:
        violations.append(RuleViolation(
            rule_id="IMPACT-UNTESTED",
            severity="MEDIUM",
            file_path=path,
            message=f"Changed symbol(s) no test file references: {_capped([f'`{n}`' for n in names])}.",
        ))
    if len(outside_names) > MAX_REPORTED:
        notes.append(f"{len(outside_names)} symbols are referenced outside the range: the first {MAX_REPORTED} are reported")
    if len(untested) > MAX_REPORTED:
        notes.append(f"{len(untested)} files have untested changed symbols: the first {MAX_REPORTED} are reported")
    if skipped:
        notes.append(f"outside-range check skipped where pre's listing was capped: {_capped(skipped)}")

    summary = (
        f"Impact range check (deterministic, files Git does not ignore):{len(changed)} symbol(s) added, changed or removed "
        f"in {len({p for p, _, _, _ in changed})} file(s); referenced outside the expected impact range: "
        f"{_capped(outside_names) or 'none'}; changed without a test reference: "
        f"{_capped([f'`{n}`' for names in untested.values() for n in names]) or 'none'}"
        + (f" ({'; '.join(notes)})" if notes else "") + "."
    )
    return violations, summary


def _capped(items: List[str]) -> str:
    """The first MAX_REPORTED items, and how many more there are: report and LLM evidence stay bounded."""
    more = len(items) - MAX_REPORTED
    return ", ".join(items[:MAX_REPORTED]) + (f" … and {more} more" if more > 0 else "")
