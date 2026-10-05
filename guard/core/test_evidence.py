r"""
Test-quality evidence extraction from unified diffs.

Provides language-agnostic facts (never verdicts) to review gates about test
modifications, weakened assertions, skipped tests, global state mutations, and
tests lacking assertions.

Table of Pattern Sets
=====================

1. Test File Identification
| Ecosystem / Tool | Path / File Pattern | Examples |
|---|---|---|
| Universal directories (case-insensitive) | `test/`, `tests/`, `__tests__/`, `spec/`, `specs/` | `tests/foo.py`, `src/__tests__/app.ts` |
| Python / Go / Rust (prefix/infix) | `*_test.*`, `test_*.*` | `server_test.go`, `test_main.py` |
| JS / TS / Ruby (infix/suffix) | `*.test.*`, `*.spec.*`, `*_spec.rb` | `button.test.tsx`, `user_spec.rb` |
| Java / Kotlin / Swift / C# (case-sensitive) | `*Test.java|kt|cs|swift`, `*Tests.*` | `UserTest.java`, `AuthTests.cs` |

2. Assertion Patterns
| Framework / Ecosystem | Assertion Syntax | Patterns Covered |
|---|---|---|
| Python `unittest` / `pytest` / keyword | `assert <expr>`, `self.assert*`, `pytest.raises`, `pytest.warns` | `assert`, `self.assert*`, `pytest.raises` |
| JS / TS (`jest`, `chai`, `vitest`) | `expect(...)`, `.toBe(...)`, `toThrow(...)`, `.should` | `expect(`, `toThrow(`, `.should` |
| Go `testing` / `testify` | `t.Error`, `t.Fatal`, `t.Fail`, `require.Equal` | `t.Error*`, `t.Fatal*`, `require.*` |
| Java / Kotlin (`junit`, `testng`, `kotest`) | `Assert.*`, `assertEquals`, `assertThrows`, `ok(...)`, `shouldBe` | `Assert.*`, `assert*`, `ok(`, `shouldBe` |
| C# (`xUnit`, `NUnit`, `FluentAssertions`) | `Assert.*`, `.Should()` | `Assert.*`, `.Should()` |
| Swift `XCTest` | `XCTAssert`, `XCTAssertEqual`, etc. | `XCTAssert*` |
| Rust | `assert!`, `assert_eq!`, `assert_ne!`, `#[should_panic]` | `assert!*`, `#[should_panic]` |
| Behavior / BDD | `verify(...)`, `check(...)`, `require(...)` | `verify(`, `check(`, `require(` |

3. Disabled / Skipped Test Markers
| Ecosystem / Tool | Marker Syntax | Patterns Covered |
|---|---|---|
| Pytest / Python | `@pytest.mark.skip`, `@pytest.mark.skipif`, `pytest.skip`, `xfail` | `skip`, `skipif`, `xfail` |
| JS / TS (`jest`, `mocha`) | `xit(...)`, `xdescribe(...)`, `it.skip(...)`, `.todo(...)` | `xit`, `xdescribe`, `.skip(`, `.todo(` |
| Java / Kotlin (`junit`, `@Disabled @Test`) | `@Disabled`, `@Ignore`, `@Disabled @Test` | `@Disabled`, `@Ignore` |
| Go | `t.Skip(...)`, `t.Skipf(...)`, `t.SkipNow()` | `t.Skip*` |
| Rust | `todo!()`, `#[ignore]` | `todo!`, `#[ignore]` |
| Ruby / RSpec / minitest | `skip(...)`, `pending(...)`, `xit(...)` | `skip`, `pending`, `xit` |
| C# (`xUnit`, `NUnit`) | `[Fact(Skip = ...)]`, `[Ignore]` | `[Fact(Skip=`, `[Ignore]` |
| PHPUnit | `markTestSkipped(...)` | `markTestSkipped` |
| Swift / XCTest | `XCTSkip(...)`, `XCTSkipIf(...)`, `XCTSkipUnless(...)` | `XCTSkip*` |
| Dart / Flutter | `skip: true`, `skip: "reason"` | `skip:` |

4. Global State Mutation Added
| Target | Language / Mechanism | Covered Syntax |
|---|---|---|
| Python sys.path | `sys.path.insert`, `sys.path.append` | `sys.path.(insert|append)` |
| Python package path | `__path__` insertion / assignment | `__path__` method call or assignment |
| Environment variables | `os.environ[...] =`, `os.environ.pop/setdefault/update` | `os.environ`, `process.env`, `setenv`, `putenv` |
| Python / Node / Ruby chdir | `os.chdir(...)`, `process.chdir(...)`, `Dir.chdir(...)` | `os.chdir`, `process.chdir`, `Dir.chdir` |
| Go / Ruby / Java / Rust env | `os.Setenv`, `ENV[...] =`, `System.setProperty`, `set_var` | `os.Setenv`, `ENV[]=`, `System.setProperty`, `set_var` |

Known Heuristic Limits (Left to LLM Review)
===========================================
- Embedded test function signatures inside docstrings or multiline strings may split a test block.
- Assertions inside loops that execute zero times cannot be verified statically.
- Dynamic test assertions constructed through metaprogramming or reflection.
- Unrestored module-level monkeypatching without clear framework teardowns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from guard.core.code_text import _mask_strings
from guard.core.rulebook import OCRRulebookRunner
from guard.core.rules import LINE_RULES, _Sec008Matcher

# Bounded limit constants
MAX_SCANNED_LINES = 20_000
MAX_LINE_CHARS = 2_000
MAX_QUOTE_CHARS = 160
MAX_EVIDENCE_LINES = 12
MAX_PATH_CHARS = 80

# Import declarations that mention 'assert' or 'require' but are not assertions
_IMPORT_LINE_RE = re.compile(
    r"^\s*(?:import\s|from\s+\S+\s+import\b|using\s|package\s|#include\b|(?:const|let|var)\s+\S+\s*=\s*require\s*\()"
)

# Full line comment prefixes across languages (Rust #[...] attributes and C/C++ operators excluded)
_COMMENT_LINE_RE = re.compile(
    r"^\s*(?:#(?!\[|!\[)|//|/\*|\*(?:\s|$)|--(?:\s|$)|<!--|;|%|'(?:\s|$)|rem\b)",
    re.IGNORECASE,
)

# Assertion patterns (statement or call required; assignments like assertion_count = 0 excluded)
_ASSERTION_PATTERNS = [
    re.compile(r"(?:^|;\s*)\s*assert(?:\s+|\s*\()"),
    re.compile(r"\b(?:self\.)?assert(?:[A-Z][a-zA-Z0-9_]*|_[a-zA-Z0-9_]+)\s*\("),
    re.compile(r"\bassert(?:_eq|_ne)?!\s*[\(\[]"),
    re.compile(r"\b(?:Assert|Assertions|StringAssert|CollectionAssert)\.[a-zA-Z0-9_]+\s*\("),
    re.compile(r"\bXCTAssert[a-zA-Z0-9_]*\s*\("),
    re.compile(r"\bexpect\s*\("),
    re.compile(r"\btoThrow(?:Error)?\s*\("),
    re.compile(
        r"(?:\.should\b|\bshould\s*\(|\bshould\s+(?:be|equal|have|match|raise|not)\b|\.should_[a-zA-Z0-9_]+|\bshould(?:Be|NotBe|Equal)\b|\.Should\s*\()"
    ),
    re.compile(r"(?:\brequire\.[a-zA-Z0-9_]+|\b(?:verify|check)\s*\()"),
    re.compile(r"\brequire\s*\((?!['\"][a-zA-Z0-9_\-\.\/]+['\"]\s*\))"),
    re.compile(r"\bt\.(?:Error|Fatal|Fail)(?:f|Now)?\s*\("),
    re.compile(r"\bok\s*\("),
    re.compile(r"#!?\[should_panic"),
    re.compile(r"\bpytest\.(?:raises|warns)\b"),
]

# Skip / disabled test markers
_SKIP_PATTERNS = [
    re.compile(r"\bpytest\.mark\.(?:skip|skipif|xfail)\b"),
    re.compile(r"\bpytest\.(?:skip|xfail)\s*\("),
    re.compile(r"\b(?:xit|xdescribe)\b"),
    re.compile(r"\b(?:test|it|describe|context|suite)\.(?:skip|todo)\s*\("),
    re.compile(r"^\s*@(?:Disabled|Ignore)\b|@Test\s+@Disabled\b|@Disabled\s+@Test\b"),
    re.compile(r"\[(?:Fact|Theory)\s*\([^\]]*Skip\s*="),
    re.compile(r"\[Ignore(?:Attribute)?(?:\([^\]]*\))?\]"),
    re.compile(r"\bt\.Skip(?:f|Now)?\s*\("),
    re.compile(r"#!?\[ignore(?:\s*=\s*['\"][^'\"]*['\"]|\([^\]]*\))?\]"),
    re.compile(r"\btodo!\s*\(?"),
    re.compile(r"(?<!def\s)(?<!\.)\b(?:skip|pending)\b(?:\s*\(|\s+['\"])"),
    re.compile(r"\bmarkTestSkipped\s*\("),
    re.compile(r"\bXCTSkip(?:If|Unless)?\s*\("),
    re.compile(r"\bskip\s*:\s*(?:true\b|['\"])"),
]

# Global state mutation patterns: assignments require =(?!=) and ignore reads/comparisons
_GLOBAL_MUTATION_PATTERNS = [
    re.compile(r"\bsys\.path\.(?:insert|append)\s*\("),
    re.compile(r"\b__path__\.(?:insert|append|extend)\s*\("),
    re.compile(r"\b__path__\s*(?:\[[^\]]+\])?\s*=(?!=)"),
    re.compile(r"\bos\.environ\s*\[[^\]]+\]\s*=(?!=)"),
    re.compile(r"\bos\.environ\.(?:pop|setdefault|update)\s*\("),
    re.compile(r"\bprocess\.env(?:\.[a-zA-Z0-9_]+|\[[^\]]+\])\s*=(?!=)"),
    re.compile(r"(?:\bos\.putenv|(?<![\w.])putenv|(?<![\w.])setenv)\s*\("),
    re.compile(r"\bDir\.chdir\b"),
    re.compile(r"\b(?:os|process)\.chdir\s*\("),
    re.compile(r"\bENV\s*\[[^\]]+\]\s*=(?!=)"),
    re.compile(r"\bos\.Setenv\s*\("),
    re.compile(r"\bSystem\.setProperty\s*\("),
    re.compile(r"\b(?:std::env::set_var|env::set_var|set_var)\s*\("),
]


def _extract_sec008_rule_patterns() -> list[re.Pattern]:
    """Reuse SEC-008 credential patterns directly from rules.LINE_RULES."""
    extracted: list[re.Pattern] = []
    for rule_id, _sev, _files, matcher, _msg in LINE_RULES:
        if rule_id == "SEC-008":
            if isinstance(matcher, _Sec008Matcher):
                extracted.append(matcher._pattern)
            elif hasattr(matcher, "search"):
                extracted.append(matcher)
    return extracted


# Reused secret patterns: shared rulebook regex, SEC-008 rules, linear token prefixes and assignments
_TOKEN_PREFIX_RE = re.compile(
    r"""(?i)\b(?:sk_live_[a-zA-Z0-9_\-]{8,100}|ghp_[a-zA-Z0-9]{20,100}|AKIA[0-9A-Z]{16}|Bearer\s+[a-zA-Z0-9_\-\.]{20,200})\b"""
)

_SECRET_ASSIGN_OR_COMPARE_RE = re.compile(
    r"""(?i)(?:os\.environ\s*\[\s*["']|process\.env\.(?:[a-zA-Z0-9_]{1,60}\.)?|process\.env\s*\[\s*["']|\b)(?:api[_-]?key|secret|token|password|auth[_-]?token|private[_-]?key|jwt)[a-zA-Z0-9_]{0,40}["']?\s*\]?\s*(?:[:=]|={2,3})\s*["'][^"'\r\n]{6,200}["']"""
)

_REUSED_SECRET_PATTERNS: list[re.Pattern] = [
    OCRRulebookRunner.SECRET_REGEX,
    *_extract_sec008_rule_patterns(),
    _TOKEN_PREFIX_RE,
    _SECRET_ASSIGN_OR_COMPARE_RE,
]

# Test function starters
_TEST_START_PATTERNS = [
    (re.compile(r"^\s*(?:async\s+def|def)\s+(test_[a-zA-Z0-9_]+)"), lambda m, _next: m.group(1)),
    (
        re.compile(r"^\s*(?:it|test)\s*(?:\(\s*|\s+)['\"`]([^'\"`]{1,60})['\"`]"),
        lambda m, _next: f'{m.group(0).split()[0].split("(")[0].strip()}("{m.group(1)}")',
    ),
    (re.compile(r"^\s*(it|test)\s*\("), lambda m, _next: m.group(1)),
    (re.compile(r"^\s*func\s+(Test[a-zA-Z0-9_]*)"), lambda m, _next: m.group(1)),
    (re.compile(r"^\s*func\s+(test[A-Z][a-zA-Z0-9_]*)"), lambda m, _next: m.group(1)),
    (re.compile(r"^\s*#\[(?:tokio::test|test)\]"), lambda _m, _next: _m.group(0).strip()),
    (re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(test_[a-zA-Z0-9_]+)"), lambda m, _next: m.group(1)),
    (re.compile(r"^\s*@Test\b"), lambda _m, next_l: _extract_method_name(next_l) or "@Test"),
    (re.compile(r"^\s*\[(?:Fact|Theory|Test)(?:\([^\]]*\))?\]"), lambda m, next_l: _extract_method_name(next_l) or m.group(0).strip()),
    (re.compile(r"^\s*(?:public\s+)?function\s+(test[A-Z0-9_][a-zA-Z0-9_]*)"), lambda m, _next: m.group(1)),
]


def _extract_method_name(next_line: str) -> str | None:
    """Extract a method name from the line immediately following a test annotation."""
    if not next_line:
        return None
    m = re.search(r"\b(?:void|fun|Task|async\s+Task)\s+([a-zA-Z0-9_]+)\s*\(", next_line)
    if m:
        return m.group(1)
    m2 = re.search(r"\bdef\s+([a-zA-Z0-9_]+)\s*\(", next_line)
    if m2:
        return m2.group(1)
    m3 = re.search(r"\bfn\s+([a-zA-Z0-9_]+)\s*\(", next_line)
    if m3:
        return m3.group(1)
    return None


def shorten_path(path: str, max_chars: int = MAX_PATH_CHARS) -> str:
    """Shorten long file paths for bounded evidence reporting."""
    norm = path.replace("\\", "/").strip()
    if len(norm) <= max_chars:
        return norm
    parts = norm.split("/")
    if len(parts) <= 2:
        return norm[: max_chars - 3] + "..."
    head, tail = parts[0], parts[-1]
    if len(head) + len(tail) + 5 <= max_chars:
        return f"{head}/.../{tail}"
    return f".../{tail}"[-max_chars:]


def decode_git_path(path: str) -> str:
    """Decode git C-style quoted paths with octal escapes (e.g. \\303\\251 -> UTF-8)."""
    p = path.strip()
    if p.startswith('"') and p.endswith('"') and len(p) >= 2:
        inner = p[1:-1]
        try:
            def _replace_escape(m: re.Match) -> bytes:
                seq = m.group(0).decode("latin1")
                if len(seq) > 1 and seq[1] in "01234567":
                    return bytes([int(seq[1:], 8)])
                escapes: dict[str, bytes] = {
                    "\\\\": b"\\",
                    '\\"': b'"',
                    "\\n": b"\n",
                    "\\t": b"\t",
                    "\\r": b"\r",
                    "\\b": b"\b",
                    "\\f": b"\f",
                }
                val = escapes.get(seq)
                if val is not None:
                    return val
                return seq.encode("latin1")

            raw_bytes = re.sub(rb'\\[0-7]{1,3}|\\[\\ntrbf"]', _replace_escape, inner.encode("latin1"))
            return raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            return inner
    return p


def is_test_path(path: str) -> bool:
    """
    True if path matches known test directory or file patterns across ecosystems.
    Directory names are case-insensitive; *Test suffix patterns are case-sensitive.
    """
    norm = path.replace("\\", "/").strip()
    parts = [p for p in norm.split("/") if p]
    if not parts:
        return False
    # Case-insensitive directory matching
    for d in parts[:-1]:
        if d.lower() in ("test", "tests", "__tests__", "spec", "specs"):
            return True
    filename = parts[-1]
    # Infix / prefix (case-insensitive)
    if re.search(r"^(?:test_.+|.+_test)\.[a-zA-Z0-9_]+$", filename, re.IGNORECASE):
        return True
    if re.search(r"^.+\.(?:test|spec)\.[a-zA-Z0-9_]+$", filename, re.IGNORECASE):
        return True
    if re.search(r"^.+_spec\.rb$", filename, re.IGNORECASE):
        return True
    # Suffix patterns (case-sensitive: requires capital Test/Tests after non-empty name)
    if re.search(r"^[a-zA-Z0-9_]+Test\.(?:java|kt|cs|swift)$", filename):
        return True
    if re.search(r"^[a-zA-Z0-9_]+Tests\.[a-zA-Z0-9_]+$", filename):
        return True
    return False


def is_secret_line(line: str) -> bool:
    """True if line matches credential or secret assignment patterns."""
    line_cut = line[:MAX_LINE_CHARS]
    return any(p.search(line_cut) for p in _REUSED_SECRET_PATTERNS)


def format_quoted_line(file_path: str, line_num: int | None, line_content: str) -> str:
    """
    Format a quoted line safely:
    - Never quotes lines matching secret assignments or exceeding MAX_QUOTE_CHARS.
    - Names file and line instead of quoting.
    """
    clean = line_content.strip()
    sp = shorten_path(file_path)
    loc = f"{sp}:{line_num}" if line_num is not None else sp
    if is_secret_line(clean):
        return f"[line omitted: potential secret at {loc}]"
    if len(clean) > MAX_QUOTE_CHARS:
        return f"[line omitted: exceeds {MAX_QUOTE_CHARS} characters at {loc}]"
    return clean


def strip_trailing_comment(line: str) -> str:
    """Strip trailing # (except Rust #[...]) or // comments outside of string literals."""
    masked = _mask_strings(line)
    m = re.search(r"(?:#(?!\[|!\[)|//)", masked)
    if m:
        return line[: m.start()].rstrip()
    return line.rstrip()


def is_assertion_line(line: str) -> bool:
    """True if line matches assertion-like patterns and is not a comment or import."""
    line_cut = line[:MAX_LINE_CHARS]
    if _COMMENT_LINE_RE.match(line_cut):
        return False
    if _IMPORT_LINE_RE.match(line_cut):
        return False
    stripped = strip_trailing_comment(line_cut)
    code_only = _mask_strings(stripped)
    return any(p.search(code_only) for p in _ASSERTION_PATTERNS)


@dataclass
class _DiffHunk:
    added_lines: list[tuple[int, str]] = field(default_factory=list)
    removed_lines: list[tuple[int, str]] = field(default_factory=list)


@dataclass
class _ParsedFileDiff:
    path: str
    is_deleted: bool = False
    total_insertions: int = 0
    total_deletions: int = 0
    hunks: list[_DiffHunk] = field(default_factory=list)


def _parse_unified_diff(raw_diff: str) -> tuple[list[_ParsedFileDiff], bool]:
    """Parse raw unified diff into file diffs and hunks, up to MAX_SCANNED_LINES."""
    # Split only on \n and strip trailing \r (avoids splitting on form feed \x0c or line separators)
    lines = [line.rstrip("\r") for line in raw_diff.split("\n")]
    exceeded = len(lines) > MAX_SCANNED_LINES
    if exceeded:
        lines = lines[:MAX_SCANNED_LINES]

    files: list[_ParsedFileDiff] = []
    current_file: _ParsedFileDiff | None = None
    current_hunk: _DiffHunk | None = None
    old_line_num = 0
    new_line_num = 0

    hunk_header_re = re.compile(r"^@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@")
    diff_git_re = re.compile(r'^diff --git (?:\"a/(.+?)\"|a/(\S+?)) (?:\"b/(.+?)\"|b/(\S+?))$')

    for raw_line in lines:
        line = raw_line[:MAX_LINE_CHARS]

        if line.startswith("diff --git"):
            m = diff_git_re.match(line)
            current_hunk = None
            if m:
                new_raw = m.group(3) or m.group(4) or ""
                old_raw = m.group(1) or m.group(2) or ""
                path_raw = new_raw if new_raw != "/dev/null" else old_raw
                path = decode_git_path('"' + path_raw + '"' if "\\" in path_raw else path_raw)
                current_file = _ParsedFileDiff(path=path)
                files.append(current_file)
            else:
                current_file = None
            continue

        if current_file is None:
            if line.startswith("--- a/") or line.startswith('--- "a/'):
                p_raw = line[4:].strip()
                current_file = _ParsedFileDiff(path=decode_git_path(p_raw)[2:])
                files.append(current_file)
                continue
            if line == "--- /dev/null":
                current_file = _ParsedFileDiff(path="")
                files.append(current_file)
                continue
            if line.startswith("+++ b/") or line.startswith('+++ "b/'):
                p_raw = line[4:].strip()
                current_file = _ParsedFileDiff(path=decode_git_path(p_raw)[2:])
                files.append(current_file)
                continue
            continue

        if line.startswith("deleted file mode"):
            current_file.is_deleted = True
            continue
        if line.startswith("new file mode"):
            continue

        # File headers outside hunks
        if current_hunk is None:
            if line.startswith("--- a/") or line == "--- /dev/null" or line.startswith('--- "a/'):
                continue
            if line.startswith("+++ b/") or line == "+++ /dev/null" or line.startswith('+++ "b/'):
                if line == "+++ /dev/null":
                    current_file.is_deleted = True
                else:
                    p_raw = line[4:].strip()
                    current_file.path = decode_git_path(p_raw)[2:]
                continue

        m_hunk = hunk_header_re.match(line)
        if m_hunk:
            old_line_num = int(m_hunk.group(1))
            new_line_num = int(m_hunk.group(2))
            current_hunk = _DiffHunk()
            current_file.hunks.append(current_hunk)
            continue

        if current_hunk is None:
            continue

        if line.startswith("\\"):
            # Git metadata marker (e.g. \ No newline at end of file) - skip without shifting lines
            continue
        if line.startswith("+"):
            content = line[1:]
            current_hunk.added_lines.append((new_line_num, content))
            current_file.total_insertions += 1
            new_line_num += 1
        elif line.startswith("-"):
            content = line[1:]
            current_hunk.removed_lines.append((old_line_num, content))
            current_file.total_deletions += 1
            old_line_num += 1
        else:
            # Context line
            new_line_num += 1
            old_line_num += 1

    return files, exceeded


def _check_hunk_tests(file_path: str, added_lines: list[tuple[int, str]]) -> list[tuple[str, int, str]]:
    """Check added lines in a hunk for test functions without assertions (Rule 4)."""
    reports: list[tuple[str, int, str]] = []
    test_starts: list[tuple[int, int, str]] = []

    for idx, (lnum, line) in enumerate(added_lines):
        line_cut = line[:MAX_LINE_CHARS]
        next_line = added_lines[idx + 1][1][:MAX_LINE_CHARS] if idx + 1 < len(added_lines) else ""
        for pat, name_fn in _TEST_START_PATTERNS:
            m = pat.match(line_cut)
            if m:
                test_name = name_fn(m, next_line)
                test_starts.append((idx, lnum, test_name))
                break

    for i, (start_idx, lnum, test_name) in enumerate(test_starts):
        end_idx = test_starts[i + 1][0] if i + 1 < len(test_starts) else len(added_lines)
        block = added_lines[start_idx:end_idx]
        if len(block) < 2:
            continue
        has_assert = any(is_assertion_line(text) for _, text in block)
        if not has_assert:
            reports.append((file_path, lnum, test_name))

    return reports


def test_evidence_lines(raw_diff: str) -> list[str]:
    """
    Extract factual test-quality evidence lines from a unified diff.

    Returns up to 12 facts about test files. Returns [] if no test files exist in the diff
    and the diff was not truncated.
    """
    if not raw_diff or not raw_diff.strip():
        return []

    parsed_files, exceeded_diff_lines = _parse_unified_diff(raw_diff)
    test_files = [f for f in parsed_files if is_test_path(f.path)]

    if not test_files:
        if exceeded_diff_lines:
            return [f"diff exceeds {MAX_SCANNED_LINES:,} lines; scanned first {MAX_SCANNED_LINES:,} lines only"]
        return []

    # Collect raw candidate actions before expensive formatting/quoting
    candidates: list[tuple] = []

    if exceeded_diff_lines:
        candidates.append(("notice", f"diff exceeds {MAX_SCANNED_LINES:,} lines; scanned first {MAX_SCANNED_LINES:,} lines only"))

    for file_stat in test_files:
        fp = file_stat.path

        # Rule 5: A test file whose diff only deletes lines, and a deleted test file
        if file_stat.is_deleted:
            candidates.append(("rule5", f"{shorten_path(fp)}: test file deleted"))
        elif file_stat.total_deletions > 0 and file_stat.total_insertions == 0:
            candidates.append(("rule5", f"{shorten_path(fp)}: test file diff only deletes lines"))

        all_added: list[tuple[int, str]] = []
        all_removed: list[tuple[int, str]] = []
        for hunk in file_stat.hunks:
            all_added.extend(hunk.added_lines)
            all_removed.extend(hunk.removed_lines)

        # Rule 1: Assertions removed or reduced
        removed_assertions = [
            (lnum, text) for lnum, text in all_removed if is_assertion_line(text)
        ]
        added_assertions = [
            (lnum, text) for lnum, text in all_added if is_assertion_line(text)
        ]

        if len(removed_assertions) > len(added_assertions):
            candidates.append(("rule1", fp, removed_assertions, added_assertions))

        # Rule 2: Disabled or skipped added
        skip_matches = [
            (lnum, text)
            for lnum, text in all_added
            if any(p.search(text[:MAX_LINE_CHARS]) for p in _SKIP_PATTERNS)
        ]
        if skip_matches:
            candidates.append(("rule2", fp, skip_matches))

        # Rule 3: Global state mutation added
        for lnum, text in all_added:
            text_cut = text[:MAX_LINE_CHARS]
            if any(p.search(text_cut) for p in _GLOBAL_MUTATION_PATTERNS):
                candidates.append(("rule3", fp, lnum, text))

        # Rule 4: New test without assertion lines (heuristic)
        for hunk in file_stat.hunks:
            for item in _check_hunk_tests(fp, hunk.added_lines):
                candidates.append(("rule4", *item))

    # Apply 12-line cap BEFORE formatting candidates
    total_candidates = len(candidates)
    if total_candidates > MAX_EVIDENCE_LINES:
        to_format = candidates[: MAX_EVIDENCE_LINES - 1]
        overflow = total_candidates - (MAX_EVIDENCE_LINES - 1)
    else:
        to_format = candidates
        overflow = 0

    evidence: list[str] = []
    for item in to_format:
        kind = item[0]
        if kind in ("notice", "rule5"):
            evidence.append(item[1])
        elif kind == "rule1":
            _k, fp, rem, add = item
            samples = [format_quoted_line(fp, lnum, text) for lnum, text in rem[:3]]
            sample_str = ", ".join(f"'{s}'" for s in samples)
            sp = shorten_path(fp)
            evidence.append(
                f"{sp}: {len(rem)} assertion line(s) removed, {len(add)} added (removed: {sample_str})"
            )
        elif kind == "rule2":
            _k, fp, skips = item
            samples = [f"line {lnum}: '{format_quoted_line(fp, lnum, text)}'" for lnum, text in skips[:3]]
            sp = shorten_path(fp)
            evidence.append(f"{sp}: disabled or skipped test marker(s) added: {', '.join(samples)}")
        elif kind == "rule3":
            _k, fp, lnum, text = item
            clean_quote = format_quoted_line(fp, lnum, text)
            sp = shorten_path(fp)
            evidence.append(f"{sp}:{lnum}: added global state mutation: {clean_quote}")
        elif kind == "rule4":
            _k, fp, lnum, test_name = item
            sp = shorten_path(fp)
            evidence.append(f"{sp}:{lnum} {test_name} adds no assertion-like line (heuristic)")

    if overflow > 0:
        evidence.append(f"... and {overflow} more")

    return evidence


# Tell pytest not to collect this module or function as tests
__test__ = False
test_evidence_lines.__test__ = False  # type: ignore[attr-defined]
