r"""
Test-quality evidence extraction from unified diffs.

Provides language-agnostic facts (never verdicts) to review gates about test
modifications, weakened assertions, skipped tests, global state mutations, and
tests lacking assertions.

Table of Pattern Sets
=====================
| Category | Primary Patterns / Frameworks | Reporting Trigger |
|---|---|---|
| Assertion reduction | `assert`, `expect(`, `should`, `require`, `verify`, `check`, `XCTAssert`, `t.Error/Fatal`, `assertEquals`, `ok(`, `#[should_panic]`, `pytest.raises`, `assertThrows`, `toThrow` | Removed count > Added count |
| Skipped / disabled tests | `pytest.mark.skip/xfail`, `unittest.skip`, `xit`, `xdescribe`, `@Disabled`, `@Ignore`, `#[ignore]`, `t.Skip`, `todo!`, `skip "reason"`, `pending`, `markTestSkipped`, `XCTSkip` | Any added skip marker |
| Global mutation | `sys.path.(insert|append)`, `__path__`, `os.environ[...] =`, `os.environ.pop/setdefault/update`, `process.env.X =`, `setenv`, `putenv`, `Dir.chdir`, `os.chdir`, `ENV[...] =`, `os.Setenv`, `System.setProperty`, `set_var` | Any added mutation line |
| Assertion-free tests | `def test_`, `it(`, `test(`, `func Test`, `test*()`, `#[test]`, `fn test_`, `@Test`, `[Fact/Test]`, `function test*` | Added test with >= 2 lines and 0 assertions |
| Deletions-only diff | Test file entirely deleted or containing only deleted lines (`-`) | Diff has deletions > 0 and insertions == 0 |

Ecosystem Support
=================
- Python: pytest, unittest, assert statements
- JavaScript / TypeScript: Jest, Vitest, Mocha, Jasmine, Chai
- Java: JUnit 4, JUnit 5, TestNG, AssertJ
- Kotlin: kotlin.test, Kotest
- Go: testing package, testify/assert, testify/require
- Ruby: RSpec, Minitest
- Rust: cargo test, built-in #[test] and #[should_panic]
- C# / .NET: xUnit, NUnit, MSTest, FluentAssertions
- PHP: PHPUnit, Pest
- Swift: XCTest, Swift Testing (#expect, #assert)

Known Non-Goals / Left to LLM Review
====================================
- Embedded test function signatures inside multiline docstrings (Python triple-quotes, Ruby =begin/=end, C# #if false, PHP #).
- Wrapping existing unchanged assertions in `+/*` and `+*/` comment markers without editing the assertion lines themselves (context lines in diff are not counted as removed).
- Assertions inside loops that execute zero times cannot be verified statically.
- Dynamic test assertions constructed through metaprogramming or reflection.
- RSpec block assertions (`expect { ... }.to change(...)`).
- Minitest / Ruby `must_*` and `refute_*` expectation syntax.
- Jest / Vitest `xtest` and `test.fixme`.
- TestNG `@Test(enabled = false)`.
- Scala / ScalaTest (`*Spec.scala`, `WordSpec`, `FunSpec`).
- Non-assignment mutations (`+=`, `||=`, `del os.environ[...]`, `delete process.env.X`).
- Unrestored module-level monkeypatching without clear framework teardowns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from guard.core.code_text import (
    _block_comments,
    _carry_comment,
    _comment_start,
    _hash_comments,
    _mask_strings,
)
from guard.core.rulebook import OCRRulebookRunner
from guard.core.rules import LINE_RULES

# Bounded limit constants
MAX_SCANNED_LINES = 20_000
MAX_LINE_CHARS = 2_000
MAX_QUOTE_CHARS = 160
MAX_EVIDENCE_LINES = 12
MAX_PATH_CHARS = 80
MAX_PER_CHAR_SCAN_CHARS = 400_000


class _ScanBudget:
    """Diff-wide character budget for expensive per-character scanners."""

    def __init__(self, limit: int = MAX_PER_CHAR_SCAN_CHARS) -> None:
        self.remaining: int = limit
        self.exhausted: bool = False

    def spend(self, count: int) -> bool:
        """Attempt to spend `count` characters from the scan budget."""
        if self.remaining <= 0:
            self.exhausted = True
            return False
        self.remaining -= count
        if self.remaining <= 0:
            self.exhausted = True
        return True


# Fast regex for string literal masking (25x faster than character loop for standard strings)
_STRING_LITERAL_RE = re.compile(r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')')


def _mask_code_strings(code: str, budget: _ScanBudget | None = None) -> str:
    """Mask string contents in code lines, using fast regex for standard strings."""
    if budget and not budget.spend(len(code)):
        return code
    if '"' not in code and "'" not in code and "`" not in code:
        return code
    if "`" in code:
        return _mask_strings(code)
    return _STRING_LITERAL_RE.sub(
        lambda m: m.group(0)[0] + " " * (len(m.group(0)) - 2) + m.group(0)[-1]
        if len(m.group(0)) >= 2
        else m.group(0),
        code,
    )


# Fast keyword prefilters to skip expensive string masking / regexes on plain lines
_FAST_ASSERT_KEYS = (
    "assert",
    "Assert",
    "Assertions",
    "expect",
    "should",
    "Should",
    "require",
    "verify",
    "check",
    "XCT",
    "t.Error",
    "t.Fatal",
    "t.Fail",
    "ok(",
    "should_panic",
    "pytest",
    "Throw",
    "assertEquals",
    "assertThrows",
)

_FAST_SKIP_KEYS = (
    "skip",
    "Skip",
    "xit",
    "xdescribe",
    "Disabled",
    "Ignore",
    "ignore",
    "todo",
    "pending",
    "markTestSkipped",
    "XCTSkip",
)

_FAST_MUTATION_KEYS = (
    "sys.path",
    "__path__",
    "environ",
    "process.env",
    "process.chdir",
    "setenv",
    "putenv",
    "os.chdir",
    "Dir.chdir",
    "ENV[",
    "Setenv",
    "setProperty",
    "set_var",
)

# Import declarations that mention 'assert' or 'require' but are not assertions
_IMPORT_LINE_RE = re.compile(
    r"^\s*(?:import\s|from\s+\S+\s+import\b|using\s|package\s|#include\b|(?:const|let|var)\s+\S+\s*=\s*require\s*\()"
)


def _has_should_pattern(s: str) -> bool:
    """Fast substring check to verify if 'should' occurs in an assertion-like context."""
    if ".should" in s or ".Should" in s or "should(" in s or "should_" in s:
        return True
    if "shouldBe" in s or "shouldNotBe" in s or "shouldEqual" in s or "Should()" in s:
        return True
    if any(f"should {w}" in s for w in ("be", "equal", "have", "match", "raise", "not", "exist", "include")):
        return True
    return False


# Grouped targeted assertion patterns mapped to fast keywords
_ASSERT_PATTERNS_MAP = [
    (
        ("assert", "Assert", "Assertions"),
        [
            re.compile(r"(?:^|;\s*)\s*(?:#)?assert(?:\s+|\s*\()"),
            re.compile(r"\b(?:self\.)?assert(?:[A-Z][a-zA-Z0-9_]*|_[a-zA-Z0-9_]+)(?:\s*\(|\s+[^\=\<\>\!\+\-\*\/\%\&\|\^\~])"),
            re.compile(r"\bassert(?:_eq|_ne)?!\s*[\(\[]"),
            re.compile(r"\b(?:assert|Assert|Assertions|StringAssert|CollectionAssert)\.[a-zA-Z0-9_]+\s*\("),
            re.compile(r"\bassertEquals\s*\("),
            re.compile(r"\bassertThrows\s*\("),
        ],
    ),
    (
        ("expect", "#expect"),
        [
            re.compile(r"\bexpect\s*\("),
            re.compile(r"(?:^|;\s*)\s*#expect\s*\("),
        ],
    ),
    (
        ("#assert",),
        [
            re.compile(r"(?:^|;\s*)\s*#assert\s*\("),
        ],
    ),
    (
        ("should", "Should"),
        [
            re.compile(
                r"(?:\.should\b|\bshould\s*\(|\bshould\s+(?:be|equal|have|match|raise|not)\b|\.should_[a-zA-Z0-9_]+|\bshould(?:Be|NotBe|Equal)\b|\.Should\s*\()"
            ),
        ],
    ),
    (
        ("require",),
        [
            re.compile(r"(?:\brequire\.[a-zA-Z0-9_]+|\b(?:verify|check)\s*\()"),
            re.compile(r"\brequire\s*\((?!['\"][a-zA-Z0-9_\-\.\/]+['\"]\s*\))"),
        ],
    ),
    (
        ("verify", "check"),
        [
            re.compile(r"(?:\brequire\.[a-zA-Z0-9_]+|\b(?:verify|check)\s*\()"),
        ],
    ),
    (
        ("XCT",),
        [
            re.compile(r"\bXCTAssert[a-zA-Z0-9_]*\s*\("),
        ],
    ),
    (
        ("t.Error", "t.Fatal", "t.Fail"),
        [
            re.compile(r"\bt\.(?:Error|Fatal|Fail)(?:f|Now)?\s*\("),
        ],
    ),
    (
        ("ok(",),
        [
            re.compile(r"\bok\s*\("),
        ],
    ),
    (
        ("should_panic",),
        [
            re.compile(r"#!?\[should_panic"),
        ],
    ),
    (
        ("pytest",),
        [
            re.compile(r"\bpytest\.(?:raises|warns)\b"),
        ],
    ),
    (
        ("Throw",),
        [
            re.compile(r"\btoThrow(?:Error)?\s*\("),
        ],
    ),
]

# Targeted skip / disabled test patterns mapped to fast keywords
_SKIP_MAP = [
    (("pytest.mark", "skip", "Skip", "xfail"), [
        re.compile(r"\bpytest\.mark\.(?:skip|skipif|xfail)\b"),
        re.compile(r"\bpytest\.(?:skip|xfail)\s*\("),
    ]),
    (("unittest.skip", "skipTest"), [
        re.compile(r"\b(?:unittest\.skip(?:If|Unless)?|self\.skipTest)\b"),
    ]),
    (("xit", "xdescribe"), [
        re.compile(r"\b(?:xit|xdescribe)\b"),
    ]),
    ((".skip", ".todo"), [
        re.compile(r"\b(?:test|it|describe|context|suite)\.(?:skip|todo)\s*\("),
    ]),
    (("Disabled", "@Disabled"), [
        re.compile(r"^\s*@(?:Disabled|Ignore)\b|@Test\s+@Disabled\b|@Disabled\s+@Test\b"),
    ]),
    (("Fact", "Theory"), [
        re.compile(r"\[(?:Fact|Theory)\s*\([^\]]*Skip\s*="),
    ]),
    (("Ignore", "ignore"), [
        re.compile(r"\[[^\]]*\bIgnore\b(?:\s*\([^)]*\))?[^\]]*\]"),
        re.compile(r"#!?\[ignore(?:\s*=\s*['\"][^'\"]*['\"]|\([^\]]*\))?\]"),
    ]),
    (("t.Skip", "Skip"), [
        re.compile(r"\bt\.Skip(?:f|Now)?\s*\("),
    ]),
    (("todo!",), [
        re.compile(r"\btodo!\s*\(?"),
    ]),
    (("pending", "skip"), [
        re.compile(r"^\s*(?:skip|pending)\b(?:\s*\(|\s+['\"]|\s*$)"),
    ]),
    (("markTestSkipped",), [
        re.compile(r"\bmarkTestSkipped\s*\("),
    ]),
    (("XCTSkip",), [
        re.compile(r"\bXCTSkip(?:If|Unless)?\s*\("),
    ]),
    (("skip:",), [
        re.compile(r"(?<!\{)\bskip\s*:\s*(?:true\b|['\"])"),
    ]),
]
_SKIP_PATTERNS = [p for _, pats in _SKIP_MAP for p in pats]

# Targeted global state mutation patterns mapped to fast keywords
_MUTATION_MAP = [
    (("sys.path",), [re.compile(r"\bsys\.path\.(?:insert|append)\s*\(")]),
    (("__path__",), [
        re.compile(r"\b__path__\.(?:insert|append|extend)\s*\("),
        re.compile(r"\b__path__\s*(?:\[[^\]]+\])?\s*=(?!=)"),
    ]),
    (("environ",), [
        re.compile(r"\bos\.environ\s*\[[^\]]+\]\s*=(?!=)"),
        re.compile(r"\bos\.environ\.(?:pop|setdefault|update)\s*\("),
    ]),
    (("process.env",), [re.compile(r"\bprocess\.env(?:\.[a-zA-Z0-9_]+|\[[^\]]+\])\s*=(?!=)")]),
    (("setenv", "putenv"), [re.compile(r"(?:\bos\.putenv|(?<![\w.])putenv|(?<![\w.])setenv)\s*\(")]),
    (("os.chdir", "process.chdir"), [re.compile(r"\b(?:os|process)\.chdir\s*\(")]),
    (("Dir.chdir",), [re.compile(r"\bDir\.chdir\b")]),
    (("ENV[",), [re.compile(r"\bENV\s*\[[^\]]+\]\s*=(?!=)")]),
    (("Setenv",), [re.compile(r"\bos\.Setenv\s*\(")]),
    (("setProperty",), [re.compile(r"\bSystem\.setProperty\s*\(")]),
    (("set_var",), [re.compile(r"\b(?:std::env::set_var|env::set_var|set_var)\s*\(")]),
]
_GLOBAL_MUTATION_PATTERNS = [p for _, pats in _MUTATION_MAP for p in pats]

# Secret-like words: password, passwd, token, secret, api_key, apikey, auth, jwt, private_key, credential
_SECRET_WORDS_RE = re.compile(
    r"""(?i)\b[a-zA-Z0-9_]*(?:password|passwd|token|secret|api_key|apikey|api-key|auth|jwt|private_key|credential)[a-zA-Z0-9_]*\b"""
)

# Linear, strictly bounded token prefix patterns (no unbounded wildcards, O(N) execution)
_TOKEN_PREFIX_PATTERNS = [
    OCRRulebookRunner.SECRET_REGEX,
    re.compile(r"""(?i)\b(?:sk_live_|sk_test_|sk-proj-|ghp_|github_pat_|glpat-|xoxb-|xoxp-|AKIA)[a-zA-Z0-9_\-]{8,100}\b"""),
    re.compile(r"""(?i)\bAIza[0-9A-Za-z-_]{20,100}\b"""),
    re.compile(r"""(?i)\bBearer\s{1,4}\S+"""),
    re.compile(r"""-----BEGIN (?:[A-Z ]{1,20} )?PRIVATE KEY-----"""),
    re.compile(r"""\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"""),
    re.compile(r"""[a-zA-Z][a-zA-Z0-9+.-]{1,10}://[^:\s/]{0,100}:[^@\s/]{1,100}@[^/\s]{1,100}"""),
]

# Test function starters
_TEST_START_PATTERNS = [
    (re.compile(r"^\s*(?:async\s+def|def)\s+(test_[a-zA-Z0-9_]+)"), lambda m, _next: m.group(1)),
    (
        re.compile(r"""^\s*(?:it|test)\s*(?:\(\s*|\s+)(?:'([^'\r\n]{1,80})'|"([^"\r\n]{1,80})"|`([^`\r\n]{1,80})`)"""),
        lambda m, _next: f'{m.group(0).split()[0].split("(")[0].strip()}("{m.group(1) or m.group(2) or m.group(3)}")',
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


def _extract_secret_patterns() -> list[re.Pattern]:
    """Test hook for secret pattern access from LINE_RULES and bounded token patterns."""
    patterns: list[re.Pattern] = []
    for rule in LINE_RULES:
        if rule[0] == "SEC-008":
            pat = getattr(rule[3], "_pattern", rule[3])
            if hasattr(pat, "search"):
                patterns.append(pat)
    return patterns or _TOKEN_PREFIX_PATTERNS


# Backward compatibility alias for earlier callers
_extract_sec008_rule_patterns = _extract_secret_patterns


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
    """Shorten long file paths for bounded evidence reporting, preserving directory and test prefixes."""
    norm = path.replace("\\", "/").strip()
    if len(norm) <= max_chars:
        return norm
    parts = norm.split("/")
    if len(parts) == 1:
        filename = parts[0]
        ext_idx = filename.rfind(".")
        ext = filename[ext_idx:] if ext_idx > 0 else ""
        stem = filename[:ext_idx] if ext_idx > 0 else filename
        avail = max_chars - len(ext) - 3
        return f"{stem[:avail]}...{ext}"

    dir_part = parts[0]
    filename = parts[-1]
    prefix = f"{dir_part}/.../"

    # If filename fits with prefix, keep the whole filename
    if len(prefix) + len(filename) <= max_chars:
        return f"{prefix}{filename}"

    ext_idx = filename.rfind(".")
    ext = filename[ext_idx:] if ext_idx > 0 else ""
    stem = filename[:ext_idx] if ext_idx > 0 else filename

    avail_stem = max_chars - len(prefix) - len(ext) - 3
    if avail_stem > 6:
        return f"{prefix}{stem[:avail_stem]}...{ext}"
    return f"{dir_part}/.../{filename[:max_chars - len(dir_part) - 8]}...{ext}"


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
    # Suffix patterns (case-sensitive: requires capital Test/Tests, allows punctuation in stems)
    if re.search(r"^.+Test\.(?:java|kt|cs|swift)$", filename):
        return True
    if re.search(r"^.+Tests\.[a-zA-Z0-9_]+$", filename):
        return True
    return False


def is_secret_line(line: str) -> bool:
    """True if line matches credential, token prefix, or secret-like name with a string literal."""
    if len(line) > MAX_LINE_CHARS:
        return False
    line_cut = line[:MAX_LINE_CHARS]
    # Any line that mentions a secret-like name with a string literal on the same line
    if ('"' in line_cut or "'" in line_cut or "`" in line_cut) and _SECRET_WORDS_RE.search(line_cut):
        return True
    return any(p.search(line_cut) for p in _TOKEN_PREFIX_PATTERNS)


def format_quoted_line(file_path: str, line_num: int | None, line_content: str) -> str:
    """
    Format a quoted line safely:
    - Never quotes lines matching secret assignments or comparisons
    - Names file and line instead of quoting when secret is present or line is > 160 chars
    """
    clean = shorten_path(file_path)
    sp = clean
    loc = f"{sp}:{line_num}" if line_num is not None else sp
    if is_secret_line(clean):
        return f"[line omitted: potential secret at {loc}]"
    if is_secret_line(line_content):
        return f"[line omitted: potential secret at {loc}]"
    if len(clean) > MAX_QUOTE_CHARS:
        return f"[line omitted: exceeds {MAX_QUOTE_CHARS} characters at {loc}]"
    if len(line_content) > MAX_QUOTE_CHARS:
        return f"[line omitted: exceeds {MAX_QUOTE_CHARS} characters at {loc}]"
    return line_content.strip()


def is_comment_line(line: str, path_lower: str) -> bool:
    """True if line is a full-line comment in the file's language."""
    stripped = line.strip()
    if not stripped:
        return False
    is_hash = _hash_comments(path_lower) if path_lower else False
    if is_hash:
        return stripped.startswith("#")
    # For non-hash languages (JS, TS, Java, Swift, Go, C#, C++, Rust, Kotlin)
    if stripped.startswith("//"):
        return True
    while stripped.startswith("/*"):
        close_idx = stripped.find("*/", 2)
        if close_idx == -1:
            return True
        stripped = stripped[close_idx + 2:].strip()
    if not stripped or stripped.startswith("//"):
        return True
    if stripped.startswith("*") and not stripped.startswith("*="):
        return True
    if path_lower.endswith((".html", ".htm", ".xml", ".svg")) and stripped.startswith("<!--"):
        return True
    if path_lower.endswith((".sql", ".lua")) and stripped.startswith("--"):
        return True
    return False


def strip_trailing_comment(line: str, path_lower: str = "", budget: _ScanBudget | None = None) -> str:
    """Strip trailing comment outside of string literals using the file language's comment rules."""
    if budget and not budget.spend(len(line)):
        return line.rstrip()

    is_hash = _hash_comments(path_lower) if path_lower else True
    blocks = _block_comments(path_lower) if path_lower else ()

    might_have_comment = False
    if is_hash and "#" in line:
        might_have_comment = True
    elif blocks and ("/" in line or "=" in line):
        might_have_comment = True
    elif not is_hash and ("/" in line or ("#" in line and path_lower.endswith(".php"))):
        might_have_comment = True
    elif path_lower.endswith((".sql", ".lua")) and "--" in line:
        might_have_comment = True
    elif path_lower.endswith((".html", ".htm", ".xml", ".svg")) and "<!--" in line:
        might_have_comment = True

    if not might_have_comment:
        return line.rstrip()

    spans: list[tuple[int, int]] = []
    cut = _comment_start(line, is_hash, spans=spans, blocks=blocks)
    chars = list(line)
    # Blank out closed block comments on the line (e.g. /* note */)
    for start, end in spans:
        for idx in range(start, min(end, len(chars))):
            chars[idx] = " "
    line_clean = "".join(chars)
    if cut >= 0:
        return line_clean[:cut].rstrip()
    return line_clean.rstrip()


def is_assertion_line(line: str, path: str = "", budget: _ScanBudget | None = None) -> bool:
    """True if line matches assertion-like patterns and is not a comment or import."""
    # Lines over 2,000 characters are treated as non-assertion text without scanning
    if len(line) > MAX_LINE_CHARS:
        return False

    line_cut = line[:MAX_LINE_CHARS]

    # Fast substring check before expensive string masking and regex matching
    if not any(k in line_cut for k in _FAST_ASSERT_KEYS):
        return False

    # Parens check: almost all assertions require '(' unless statement/macro forms
    if ("(" not in line_cut) and ("assert" not in line_cut) and ("should" not in line_cut) and ("Should" not in line_cut) and ("should_panic" not in line_cut):
        return False

    path_lower = path.replace("\\", "/").lower()
    if is_comment_line(line_cut, path_lower):
        return False
    if _IMPORT_LINE_RE.match(line_cut):
        return False

    # Targeted raw pattern check: only run patterns for the keyword that matched
    matched_pat = None
    for keys, pats in _ASSERT_PATTERNS_MAP:
        if any(k in line_cut for k in keys):
            if "should" in keys or "Should" in keys:
                if not _has_should_pattern(line_cut):
                    continue
            for p in pats:
                if p.search(line_cut):
                    matched_pat = p
                    break
            if matched_pat:
                break
    if not matched_pat:
        return False

    if budget and budget.exhausted:
        return True

    stripped = strip_trailing_comment(line_cut, path_lower, budget=budget)
    if not matched_pat.search(stripped):
        return False

    # Check if the matched assertion was inside a string literal
    first_quote = min((stripped.find(q) for q in ('"', "'", "`") if stripped.find(q) != -1), default=-1)
    if first_quote == -1:
        return True
    m = matched_pat.search(stripped)
    if m and m.start() < first_quote:
        return True

    # Otherwise, mask strings to verify assertion is outside string literals
    code_only = _mask_code_strings(stripped, budget=budget)
    return bool(matched_pat.search(code_only))


@dataclass
class _DiffHunk:
    added_lines: list[tuple[int, str, bool, bool, bool]] = field(default_factory=list)  # (lnum, text, is_assert, is_comment, was_cut)
    removed_lines: list[tuple[int, str, bool, bool, bool]] = field(default_factory=list)


@dataclass
class _ParsedFileDiff:
    path: str
    is_deleted: bool = False
    total_insertions: int = 0
    total_deletions: int = 0
    hunks: list[_DiffHunk] = field(default_factory=list)


def _parse_unified_diff(raw_diff: str, budget: _ScanBudget | None = None) -> tuple[list[_ParsedFileDiff], bool]:
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
    open_comments_old: dict[str, str] = {}
    open_comments_new: dict[str, str] = {}

    hunk_header_re = re.compile(r"^@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@")
    diff_git_re = re.compile(r'^diff --git (?:\"a/(.+?)\"|a/(\S+?)) (?:\"b/(.+?)\"|b/(\S+?))$')

    for raw_line in lines:
        was_cut = len(raw_line) > MAX_LINE_CHARS
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

        fp = current_file.path
        is_tp = is_test_path(fp)
        fp_lower = fp.replace("\\", "/").lower()

        if line.startswith("+"):
            content = line[1:]
            if is_tp:
                if was_cut:
                    is_assert = False
                    is_comment = False
                else:
                    needs_carry = open_comments_new.get(fp_lower) or ("/*" in content) or ("<!--" in content) or (fp_lower.endswith(".rb") and ("=begin" in content or "=end" in content))
                    if needs_carry:
                        if budget and not budget.spend(len(content)):
                            carried = content
                        else:
                            carried = _carry_comment(open_comments_new, fp_lower, content)
                    else:
                        carried = content
                    is_comment = (carried is None) or is_comment_line(carried, fp_lower)
                    is_assert = (carried is not None) and is_assertion_line(carried, fp, budget=budget)
            else:
                is_assert = False
                is_comment = False
            current_hunk.added_lines.append((new_line_num, content, is_assert, is_comment, was_cut))
            current_file.total_insertions += 1
            new_line_num += 1
        elif line.startswith("-"):
            content = line[1:]
            if is_tp:
                if was_cut:
                    is_assert = False
                    is_comment = False
                else:
                    needs_carry = open_comments_old.get(fp_lower) or ("/*" in content) or ("<!--" in content) or (fp_lower.endswith(".rb") and ("=begin" in content or "=end" in content))
                    if needs_carry:
                        if budget and not budget.spend(len(content)):
                            carried = content
                        else:
                            carried = _carry_comment(open_comments_old, fp_lower, content)
                    else:
                        carried = content
                    is_comment = (carried is None) or is_comment_line(carried, fp_lower)
                    is_assert = (carried is not None) and is_assertion_line(carried, fp, budget=budget)
            else:
                is_assert = False
                is_comment = False
            current_hunk.removed_lines.append((old_line_num, content, is_assert, is_comment, was_cut))
            current_file.total_deletions += 1
            old_line_num += 1
        else:
            # Context line: updates both old and new side comment state if applicable
            if is_tp:
                ctx_code = line[1:] if line.startswith(" ") else line
                needs_carry = open_comments_old.get(fp_lower) or open_comments_new.get(fp_lower) or ("/*" in line) or ("<!--" in line) or (fp_lower.endswith(".rb") and ("=begin" in line or "=end" in line))
                if needs_carry:
                    if budget and not budget.spend(len(ctx_code)):
                        pass
                    else:
                        if open_comments_old.get(fp_lower) or ("/*" in line) or ("<!--" in line) or (fp_lower.endswith(".rb") and ("=begin" in line or "=end" in line)):
                            _carry_comment(open_comments_old, fp_lower, ctx_code)
                        if open_comments_new.get(fp_lower) or ("/*" in line) or ("<!--" in line) or (fp_lower.endswith(".rb") and ("=begin" in line or "=end" in line)):
                            _carry_comment(open_comments_new, fp_lower, ctx_code)
            new_line_num += 1
            old_line_num += 1

    return files, exceeded


def _check_hunk_tests(file_path: str, added_lines: list[tuple[int, str, bool, bool, bool]]) -> list[tuple[str, int, str]]:
    """Check added lines in a hunk for test functions without assertions (Rule 4)."""
    reports: list[tuple[str, int, str]] = []
    test_starts: list[tuple[int, int, str]] = []

    for idx, (lnum, line, _is_a, is_c, was_cut) in enumerate(added_lines):
        if is_c or was_cut:
            continue
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
        # Reuse cached assertion evaluation from diff parsing
        has_assert = any(is_a for _, _, is_a, _, _ in block)
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

    budget = _ScanBudget(MAX_PER_CHAR_SCAN_CHARS)
    parsed_files, exceeded_diff_lines = _parse_unified_diff(raw_diff, budget=budget)
    test_files = [f for f in parsed_files if is_test_path(f.path)]

    if not test_files:
        res = []
        if exceeded_diff_lines:
            res.append(f"diff exceeds {MAX_SCANNED_LINES:,} lines; scanned first {MAX_SCANNED_LINES:,} lines only")
        if budget.exhausted:
            res.append("diff scan budget reached; scan reduced")
        return res

    # Collect raw candidate actions before expensive formatting/quoting
    candidates: list[tuple] = []

    for file_stat in test_files:
        fp = file_stat.path
        fp_lower = fp.replace("\\", "/").lower()

        # Rule 5: A test file whose diff only deletes lines, and a deleted test file
        if file_stat.is_deleted:
            candidates.append(("rule5", f"{shorten_path(fp)}: test file deleted"))
        elif file_stat.total_deletions > 0 and file_stat.total_insertions == 0:
            candidates.append(("rule5", f"{shorten_path(fp)}: test file diff only deletes lines"))

        all_added: list[tuple[int, str, bool, bool, bool]] = []
        all_removed: list[tuple[int, str, bool, bool, bool]] = []
        for hunk in file_stat.hunks:
            all_added.extend(hunk.added_lines)
            all_removed.extend(hunk.removed_lines)

        # Rule 1: Assertions removed or reduced (uses cached assertion evaluations)
        removed_assertions = [
            (lnum, text) for lnum, text, is_a, _, _ in all_removed if is_a
        ]
        added_assertions = [
            (lnum, text) for lnum, text, is_a, _, _ in all_added if is_a
        ]

        if len(removed_assertions) > len(added_assertions):
            candidates.append(("rule1", fp, removed_assertions, added_assertions))

        # Rule 2: Disabled or skipped added (recheck only the matching pattern after masking)
        skip_matches = []
        for lnum, text, _is_a, _is_c, was_cut in all_added:
            if was_cut:
                continue
            if not any(k in text for k in _FAST_SKIP_KEYS):
                continue
            matching_skips = []
            for keys, pats in _SKIP_MAP:
                if any(k in text for k in keys):
                    for p in pats:
                        if p.search(text[:MAX_LINE_CHARS]):
                            matching_skips.append(p)
            if not matching_skips:
                continue
            if budget.exhausted:
                skip_matches.append((lnum, text))
                continue
            if is_comment_line(text, fp_lower):
                continue
            stripped = strip_trailing_comment(text, fp_lower, budget=budget)
            code_only = _mask_code_strings(stripped, budget=budget)
            if any(p.search(code_only) for p in matching_skips):
                skip_matches.append((lnum, text))
        if skip_matches:
            candidates.append(("rule2", fp, skip_matches))

        # Rule 3: Global state mutation added (recheck only the matching pattern after masking)
        for lnum, text, _is_a, _is_c, was_cut in all_added:
            if was_cut:
                continue
            if not any(k in text for k in _FAST_MUTATION_KEYS):
                continue
            matching_mutations = []
            for keys, pats in _MUTATION_MAP:
                if any(k in text for k in keys):
                    for p in pats:
                        if p.search(text[:MAX_LINE_CHARS]):
                            matching_mutations.append(p)
            if not matching_mutations:
                continue
            if budget.exhausted:
                candidates.append(("rule3", fp, lnum, text))
                continue
            if is_comment_line(text, fp_lower):
                continue
            stripped = strip_trailing_comment(text, fp_lower, budget=budget)
            code_only = _mask_code_strings(stripped, budget=budget)
            if any(p.search(code_only) for p in matching_mutations):
                candidates.append(("rule3", fp, lnum, text))
        # Rule 4: New test without assertion lines (heuristic)
        for hunk in file_stat.hunks:
            for item in _check_hunk_tests(fp, hunk.added_lines):
                candidates.append(("rule4", *item))
    if budget.exhausted:
        candidates.insert(0, ("notice", "diff scan budget reached; scan reduced"))
    if exceeded_diff_lines:
        candidates.insert(0, ("notice", f"diff exceeds {MAX_SCANNED_LINES:,} lines; scanned first {MAX_SCANNED_LINES:,} lines only"))

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
            clean_test_name = format_quoted_line(fp, lnum, test_name)
            sp = shorten_path(fp)
            evidence.append(f"{sp}:{lnum} {clean_test_name} adds no assertion-like line (heuristic)")

    if overflow > 0:
        evidence.append(f"... and {overflow} more")

    return evidence


# Tell pytest not to collect this module or function as tests
__test__ = False
test_evidence_lines.__test__ = False  # type: ignore[attr-defined]
