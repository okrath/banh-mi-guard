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
| Universal directories | `test/`, `tests/`, `__tests__/`, `spec/`, `specs/` | `tests/foo.py`, `src/__tests__/app.ts` |
| Python / Go / Rust | `*_test.*`, `test_*.*` | `server_test.go`, `test_main.py` |
| JS / TS / Ruby | `*.test.*`, `*.spec.*`, `*_spec.rb` | `button.test.tsx`, `user_spec.rb` |
| Java / Kotlin / Swift / C# | `*Test.java|kt|cs|swift`, `*Tests.*` | `UserTest.java`, `AuthTests.cs` |

2. Assertion Patterns
| Framework / Ecosystem | Assertion Syntax | Patterns Covered |
|---|---|---|
| Python `unittest` / `pytest` / keyword | `assert`, `self.assert*`, `pytest.raises`, `pytest.warns` | `assert`, `assert*`, `pytest.raises` |
| JS / TS (`jest`, `chai`, `vitest`) | `expect(...)`, `.toBe(...)`, `toThrow(...)`, `.should` | `expect(`, `toThrow(`, `.should` |
| Go `testing` / `testify` | `t.Error`, `t.Fatal`, `t.Fail`, `require.Equal` | `t.Error*`, `t.Fatal*`, `require.*` |
| Java / Kotlin (`junit`, `testng`) | `Assert.*`, `assertEquals`, `assertThrows`, `ok(...)` | `Assert.*`, `assert*`, `ok(` |
| Swift `XCTest` | `XCTAssert`, `XCTAssertEqual`, etc. | `XCTAssert*` |
| Rust | `assert!`, `assert_eq!`, `assert_ne!`, `#[should_panic]` | `assert!*`, `#[should_panic]` |
| Behavior / BDD | `verify(...)`, `check(...)`, `require(...)` | `verify(`, `check(`, `require(` |

3. Disabled / Skipped Test Markers
| Ecosystem / Tool | Marker Syntax | Patterns Covered |
|---|---|---|
| Pytest / Python | `@pytest.mark.skip`, `pytest.skip`, `xfail` | `pytest.mark.skip`, `pytest.skip`, `xfail` |
| JS / TS (`jest`, `mocha`) | `xit(...)`, `xdescribe(...)`, `it.skip(...)`, `.todo(...)`| `xit`, `xdescribe`, `.skip(`, `.todo(` |
| Java / Kotlin (`junit`) | `@Disabled`, `@Ignore` | `@Disabled`, `@Ignore` |
| Go | `t.Skip(...)`, `t.Skipf(...)`, `t.SkipNow()` | `t.Skip*` |
| Rust | `todo!()` | `todo!` |
| Ruby / RSpec / minitest | `skip(...)`, `pending(...)` | `skip(`, `pending(` |

4. Global State Mutation Added
| Target | Language / Mechanism | Covered Syntax |
|---|---|---|
| Python sys.path | `sys.path.insert`, `sys.path.append` | `sys.path.(insert|append)` |
| Python package path | `__path__` modification | `__path__` |
| Environment variables | `os.environ[...] =`, `os.environ.pop`, `process.env.X =` | `os.environ`, `process.env`, `setenv(`, `putenv(` |
| Working directory | `os.chdir(...)`, `Dir.chdir(...)` | `os.chdir`, `Dir.chdir` |

5. Intentionally Left to LLM (Not in Heuristic Scope)
- Monkeypatch-free module attribute assignment (too language-specific).
- Complex semantic assertion loops and empty collection assertions.
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

# File path pattern matching test files across ecosystems
_TEST_PATH_RE = re.compile(
    r"""(?x)
    (?:^|/)
    (?:
        (?:test|tests|__tests__|spec|specs)/.*            # directory name
        | (?:[^/]*_test|test_[^/]*)\.[a-zA-Z0-9_]+$       # *_test.*, test_*.*
        | [^/]*\.(?:test|spec)\.[a-zA-Z0-9_]+$           # *.test.*, *.spec.*
        | [^/]*Test\.(?:java|kt|cs|swift)$               # *Test.java|kt|cs|swift
        | [^/]*Tests\.[a-zA-Z0-9_]+$                     # *Tests.*
        | [^/]*_spec\.rb$                                # *_spec.rb
    )
    """,
    re.IGNORECASE,
)

# Import declarations that mention 'assert' or 'require' but are not assertions
_IMPORT_LINE_RE = re.compile(
    r"^\s*(?:import\s|from\s+\S+\s+import\b|using\s|package\s|#include\b|(?:const|let|var)\s+\S+\s*=\s*require\s*\()"
)

# Assertion-like patterns
_ASSERTION_PATTERNS = [
    re.compile(r"\bassert[a-zA-Z0-9_]*\b", re.IGNORECASE),
    re.compile(r"\b(?:Assert|Assertions|StringAssert|CollectionAssert)\.[a-zA-Z0-9_]+"),
    re.compile(r"\bXCTAssert[a-zA-Z0-9_]*"),
    re.compile(r"\bexpect\s*\("),
    re.compile(r"\btoThrow(?:Error)?\s*\("),
    re.compile(r"(?:\.should\b|\bshould\s*\(|\bshould\s+(?:be|equal|have|match|raise|not)\b|\.should_[a-zA-Z0-9_]+)"),
    re.compile(r"(?:\brequire\.[a-zA-Z0-9_]+|\b(?:verify|check)\s*\()"),
    re.compile(r"\brequire\s*\((?!['\"][a-zA-Z0-9_\-\.\/]+['\"]\s*\))"),
    re.compile(r"\bt\.(?:Error|Fatal|Fail)(?:f|Now)?\b"),
    re.compile(r"\bok\s*\("),
    re.compile(r"#!?\[should_panic"),
    re.compile(r"\bpytest\.(?:raises|warns)\b"),
]

# Skip / disabled test markers
_SKIP_PATTERNS = [
    re.compile(r"\bpytest\.mark\.(?:skip|xfail)\b"),
    re.compile(r"\bpytest\.(?:skip|xfail)\s*\("),
    re.compile(r"\b(?:xit|xdescribe)\s*\("),
    re.compile(r"\.(?:skip|todo)\s*\("),
    re.compile(r"^\s*@(?:Disabled|Ignore)\b"),
    re.compile(r"\bt\.Skip(?:f|Now)?\s*\("),
    re.compile(r"\btodo!\s*\(?"),
    re.compile(r"(?<!def\s)\b(?:skip|pending)\s*\("),
]

# Global state mutation patterns
_GLOBAL_MUTATION_PATTERNS = [
    re.compile(r"\bsys\.path\.(?:insert|append)\s*\("),
    re.compile(r"\b__path__\b"),
    re.compile(r"\bos\.environ\s*\[[^\]]+\]\s*="),
    re.compile(r"\bos\.environ\.(?:pop|setdefault|update)\s*\("),
    re.compile(r"\bprocess\.env(?:\.[a-zA-Z0-9_]+|\[[^\]]+\])\s*="),
    re.compile(r"(?<!\.)\b(?:setenv|putenv)\s*\("),
    re.compile(r"\bDir\.chdir\b"),
    re.compile(r"\bos\.chdir\s*\("),
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


# Secret assignment patterns: reuse primary rulebook regex + SEC-008 rules from rules.py
_REUSED_SECRET_PATTERNS: list[re.Pattern] = [
    OCRRulebookRunner.SECRET_REGEX,
    *_extract_sec008_rule_patterns(),
    re.compile(
        r"""(?i)(?:os\.environ\s*\[|process\.env(?:\.|\[))\s*["']?[^"'\r\n\]]*(?:token|secret|password|api[_-]?key|auth|jwt)[^"'\r\n\]]*["']?\s*\]?\s*=\s*["'][^"'\r\n]+["']"""
    ),
]

# Test function starters
_TEST_START_PATTERNS = [
    # Python def test_...
    (re.compile(r"^\s*def\s+(test_[a-zA-Z0-9_]+)"), lambda m, _next_line: m.group(1)),
    # JS/TS/Ruby it(...) or test(...)
    (
        re.compile(r"^\s*(?:it|test)\s*(?:\(\s*|\s+)['\"`]([^'\"`]{1,60})['\"`]"),
        lambda m, _next_line: f'{m.group(0).split("(")[0].strip()}("{m.group(1)}")',
    ),
    (re.compile(r"^\s*(it|test)\s*\("), lambda m, _next_line: m.group(1)),
    # Go func TestXxx
    (re.compile(r"^\s*func\s+(Test[a-zA-Z0-9_]*)"), lambda m, _next_line: m.group(1)),
    # Rust fn test_xxx
    (re.compile(r"^\s*(?:pub\s+)?fn\s+(test_[a-zA-Z0-9_]+)"), lambda m, _next_line: m.group(1)),
    # Rust #[test]
    (re.compile(r"^\s*#\[test\]"), lambda _m, next_line: _extract_method_name(next_line) or "#[test]"),
    # Java @Test
    (re.compile(r"^\s*@Test\b"), lambda _m, next_line: _extract_method_name(next_line) or "@Test"),
    # C# [Fact], [Theory], [Test]
    (
        re.compile(r"^\s*\[(?:Fact|Theory|Test)\]"),
        lambda m, next_line: _extract_method_name(next_line) or m.group(0).strip(),
    ),
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


def is_test_path(path: str) -> bool:
    """True if path matches known test directory or file patterns across ecosystems."""
    norm = path.replace("\\", "/").strip()
    return bool(_TEST_PATH_RE.search(norm))


def is_secret_line(line: str) -> bool:
    """True if line matches credential or secret assignment patterns."""
    line_cut = line[:MAX_LINE_CHARS]
    return any(p.search(line_cut) for p in _REUSED_SECRET_PATTERNS)


def format_quoted_line(file_path: str, line_num: int | None, line_content: str) -> str:
    """
    Format a quoted line safely:
    - Never quotes lines matching secret assignments (names file and line instead).
    - Truncates lines longer than MAX_QUOTE_CHARS (160 characters).
    """
    clean = line_content.strip()
    if is_secret_line(clean):
        loc = f"{file_path}:{line_num}" if line_num is not None else file_path
        return f"[line omitted: potential secret at {loc}]"
    if len(clean) > MAX_QUOTE_CHARS:
        return clean[: MAX_QUOTE_CHARS - 3] + "..."
    return clean


def is_assertion_line(line: str) -> bool:
    """True if line matches assertion-like patterns and is not an import."""
    line_cut = line[:MAX_LINE_CHARS]
    if _IMPORT_LINE_RE.match(line_cut):
        return False
    code_only = _mask_strings(line_cut)
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
    lines = raw_diff.splitlines()
    exceeded = len(lines) > MAX_SCANNED_LINES
    if exceeded:
        lines = lines[:MAX_SCANNED_LINES]

    files: list[_ParsedFileDiff] = []
    current_file: _ParsedFileDiff | None = None
    current_hunk: _DiffHunk | None = None
    old_line_num = 0
    new_line_num = 0

    hunk_header_re = re.compile(r"^@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@")
    diff_git_re = re.compile(r"^diff --git a/(.*) b/(.*)")

    for raw_line in lines:
        line = raw_line[:MAX_LINE_CHARS]

        if line.startswith("diff --git"):
            m = diff_git_re.match(line)
            current_hunk = None
            if m:
                path = m.group(2) if m.group(2) != "/dev/null" else m.group(1)
                current_file = _ParsedFileDiff(path=path)
                files.append(current_file)
            else:
                current_file = None
            continue

        if current_file is None:
            if line.startswith("--- a/"):
                current_file = _ParsedFileDiff(path=line[6:].strip())
                files.append(current_file)
                continue
            if line == "--- /dev/null":
                current_file = _ParsedFileDiff(path="")
                files.append(current_file)
                continue
            if line.startswith("+++ b/"):
                current_file = _ParsedFileDiff(path=line[6:].strip())
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
            if line.startswith("--- a/") or line == "--- /dev/null":
                continue
            if line.startswith("+++ b/") or line == "+++ /dev/null":
                if line == "+++ /dev/null":
                    current_file.is_deleted = True
                elif line.startswith("+++ b/"):
                    current_file.path = line[6:].strip()
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


def _check_hunk_tests(file_path: str, added_lines: list[tuple[int, str]]) -> list[str]:
    """Check added lines in a hunk for test functions without assertions (Rule 4)."""
    reports: list[str] = []
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
            reports.append(f"{file_path}:{lnum} {test_name} adds no assertion-like line (heuristic)")

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

    evidence: list[str] = []

    if exceeded_diff_lines:
        evidence.append(f"diff exceeds {MAX_SCANNED_LINES:,} lines; scanned first {MAX_SCANNED_LINES:,} lines only")

    for file_stat in test_files:
        fp = file_stat.path

        # Rule 5: A test file whose diff only deletes lines, and a deleted test file
        if file_stat.is_deleted:
            evidence.append(f"{fp}: test file deleted")
        elif file_stat.total_deletions > 0 and file_stat.total_insertions == 0:
            evidence.append(f"{fp}: test file diff only deletes lines")

        # Collect all added and removed lines across hunks
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
            sample_lines = [
                format_quoted_line(fp, lnum, text)
                for lnum, text in removed_assertions[:3]
            ]
            sample_str = ", ".join(f"'{s}'" for s in sample_lines)
            evidence.append(
                f"{fp}: {len(removed_assertions)} assertion line(s) removed, "
                f"{len(added_assertions)} added (removed: {sample_str})"
            )

        # Rule 2: Disabled or skipped added
        skip_matches = [
            (lnum, text)
            for lnum, text in all_added
            if any(p.search(text[:MAX_LINE_CHARS]) for p in _SKIP_PATTERNS)
        ]
        if skip_matches:
            samples = [
                f"line {lnum}: '{format_quoted_line(fp, lnum, text)}'"
                for lnum, text in skip_matches[:3]
            ]
            evidence.append(f"{fp}: disabled or skipped test marker(s) added: {', '.join(samples)}")

        # Rule 3: Global state mutation added
        for lnum, text in all_added:
            text_cut = text[:MAX_LINE_CHARS]
            if any(p.search(text_cut) for p in _GLOBAL_MUTATION_PATTERNS):
                clean_quote = format_quoted_line(fp, lnum, text)
                evidence.append(f"{fp}:{lnum}: added global state mutation: {clean_quote}")

        # Rule 4: New test without assertion lines (heuristic)
        for hunk in file_stat.hunks:
            hunk_reports = _check_hunk_tests(fp, hunk.added_lines)
            evidence.extend(hunk_reports)

    # Cap output at MAX_EVIDENCE_LINES (12 lines)
    if len(evidence) > MAX_EVIDENCE_LINES:
        remaining = len(evidence) - (MAX_EVIDENCE_LINES - 1)
        evidence = evidence[: MAX_EVIDENCE_LINES - 1] + [f"... and {remaining} more"]

    return evidence


# Tell pytest not to collect this module or function as tests
__test__ = False
test_evidence_lines.__test__ = False  # type: ignore[attr-defined]
