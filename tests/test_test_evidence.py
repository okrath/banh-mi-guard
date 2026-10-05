"""
Tests for test-quality evidence extraction and review checklists.
"""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from guard.core.review_checklists import TEST_QUALITY_CHECKLIST
from guard.core.rules import _Sec008Matcher
from guard.core.test_evidence import (
    MAX_EVIDENCE_LINES,
    MAX_QUOTE_CHARS,
    MAX_SCANNED_LINES,
    _extract_sec008_rule_patterns,
    format_quoted_line,
    is_assertion_line,
    is_secret_line,
    is_test_path,
)
from guard.core.test_evidence import (
    test_evidence_lines as get_evidence_lines,
)


def _get_git_show_diff(commit_hash: str, file_path: str, fallback_diff: str) -> str:
    """Fetch diff via git show from repo root if ref exists, otherwise return fallback diff."""
    repo_dir = str(Path(__file__).resolve().parent.parent)
    try:
        check = subprocess.run(
            ["git", "cat-file", "-e", f"{commit_hash}^{{commit}}"],
            cwd=repo_dir,
            capture_output=True,
            timeout=5,
        )
        if check.returncode != 0:
            return fallback_diff
        res = subprocess.run(
            ["git", "show", commit_hash, "--", file_path],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout
    except Exception:
        pass
    return fallback_diff


# ---------------------------------------------------------------------------
# Test File Path Recognition
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_something.py",
        "test/something.py",
        "src/__tests__/button.test.tsx",
        "src/__tests__/button.js",
        "spec/models/user_spec.rb",
        "specs/api.spec.js",
        "pkg/server/server_test.go",
        "src/test_foo.py",
        "src/components/button.test.js",
        "src/components/button.spec.ts",
        "src/UserServiceTest.java",
        "src/UserServiceTest.kt",
        "src/UserServiceTest.cs",
        "src/UserServiceTest.swift",
        "src/UserServiceTests.cs",
        "src/UserServiceTests.py",
        "app/controllers/user_spec.rb",
        "tests\\nested\\test_win.py",
    ],
)
def test_is_test_path_positive(path: str):
    """Test recognized test paths across ecosystems."""
    assert is_test_path(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "src/main.py",
        "guard/core/rules.py",
        "docs/index.md",
        "README.md",
        "src/test_helpers/factory.py",
        "testing_data/fixtures.json",
    ],
)
def test_is_test_path_negative(path: str):
    """Non-test paths are not identified as test files."""
    assert is_test_path(path) is False


# ---------------------------------------------------------------------------
# Empty Diffs & No Test Files
# ---------------------------------------------------------------------------


def test_empty_diff_returns_empty_list():
    """An empty or whitespace diff returns []."""
    assert get_evidence_lines("") == []
    assert get_evidence_lines("   \n\t  ") == []


def test_no_test_files_returns_empty_list():
    """A diff modifying only non-test files returns []."""
    diff = """diff --git a/src/sample_tool.py b/src/sample_tool.py
--- a/src/sample_tool.py
+++ b/src/sample_tool.py
@@ -10,3 +10,4 @@
 def sample_runner():
+    print("hello")
     return 0
"""
    assert get_evidence_lines(diff) == []


# ---------------------------------------------------------------------------
# Table-Driven Assertion Patterns
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line, expected",
    [
        ("assert x == 1", True),
        ("assert False, 'error message'", True),
        ("self.assertEqual(a, b)", True),
        ("self.assertTrue(result)", True),
        ("expect(val).toBe(42)", True),
        ("expect(() => call()).toThrow()", True),
        ("val.should.equal(10)", True),
        ("val.should be == 10", True),
        ("require.Equal(t, expected, actual)", True),
        ("require.NoError(t, err)", True),
        ("require(condition)", True),
        ("verify(mockService).save()", True),
        ("check(propertyHolds)", True),
        ("Assert.assertEquals(expected, actual)", True),
        ("Assertions.assertTrue(ok)", True),
        ("XCTAssertEqual(res, 200)", True),
        ("XCTAssert(flag)", True),
        ("t.Errorf('unexpected: %v', err)", True),
        ("t.Fatalf('fatal: %v', err)", True),
        ("assertEquals(1, 2)", True),
        ("ok(isValid, 'must hold')", True),
        ("#[should_panic]", True),
        ("with pytest.raises(ValueError):", True),
        ("with pytest.warns(UserWarning):", True),
        ("assertThrows(RuntimeException.class, () -> {})", True),
        # Negative / non-assertion cases
        ("import assert from 'assert'", False),
        ("from unittest.mock import Mock", False),
        ("const fs = require('fs')", False),
        ("let path = require('path')", False),
        ("x = 10", False),
        ("print('assert nothing here')", False),
    ],
)
def test_assertion_pattern_table(line: str, expected: bool):
    """Assertion patterns across all covered testing frameworks."""
    assert is_assertion_line(line) == expected


# ---------------------------------------------------------------------------
# Rule 1: Assertions Removed or Reduced
# ---------------------------------------------------------------------------


def test_rule1_assertions_reduced_positive():
    """Reported when removed assertions exceed added assertions, listing up to 3."""
    diff = """diff --git a/tests/test_calc.py b/tests/test_calc.py
--- a/tests/test_calc.py
+++ b/tests/test_calc.py
@@ -10,8 +10,4 @@
-    assert add(1, 1) == 2
-    assert add(2, 2) == 4
-    assert add(3, 3) == 6
-    assert add(4, 4) == 8
+    assert add(1, 1) == 2
"""
    evidence = get_evidence_lines(diff)
    assert len(evidence) == 1
    assert "tests/test_calc.py: 4 assertion line(s) removed, 1 added" in evidence[0]
    assert "add(1, 1) == 2" in evidence[0]
    assert "add(2, 2) == 4" in evidence[0]
    assert "add(3, 3) == 6" in evidence[0]


def test_rule1_assertions_reduced_negative():
    """Not reported when added assertions equal or exceed removed assertions."""
    diff = """diff --git a/tests/test_calc.py b/tests/test_calc.py
--- a/tests/test_calc.py
+++ b/tests/test_calc.py
@@ -10,3 +10,5 @@
-    assert old_calc(1) == 1
+    assert new_calc(1) == 1
+    assert new_calc(2) == 2
"""
    evidence = get_evidence_lines(diff)
    assert not any("assertion line(s) removed" in e for e in evidence)


# ---------------------------------------------------------------------------
# Rule 2: Disabled or Skipped Added
# ---------------------------------------------------------------------------


def test_rule2_skip_markers_positive_multi_language():
    """Detects added skip markers across Python, JS, Java, Go, Rust, Ruby."""
    diff = """diff --git a/tests/test_skip.py b/tests/test_skip.py
--- a/tests/test_skip.py
+++ b/tests/test_skip.py
@@ -5,1 +5,4 @@
+@pytest.mark.skip(reason="wip")
+def test_py():
+    assert True
diff --git a/src/__tests__/app.test.js b/src/__tests__/app.test.js
--- a/src/__tests__/app.test.js
+++ b/src/__tests__/app.test.js
@@ -1,1 +1,4 @@
+xit("temporarily skipped", () => {
+    expect(true).toBe(true);
+});
diff --git a/tests/ServiceTest.java b/tests/ServiceTest.java
--- a/tests/ServiceTest.java
+++ b/tests/ServiceTest.java
@@ -1,1 +1,4 @@
+@Disabled("flaky test")
+@Test
+void testJava() {
+}
diff --git a/pkg/server_test.go b/pkg/server_test.go
--- a/pkg/server_test.go
+++ b/pkg/server_test.go
@@ -1,1 +1,4 @@
+func TestGo(t *testing.T) {
+    t.Skip("skipping in CI")
+}
diff --git a/spec/calc_spec.rb b/spec/calc_spec.rb
--- a/spec/calc_spec.rb
+++ b/spec/calc_spec.rb
@@ -1,1 +1,4 @@
+it "pending feature" do
+    skip("not implemented")
+end
"""
    evidence = get_evidence_lines(diff)
    assert any("tests/test_skip.py: disabled or skipped test marker(s) added" in e for e in evidence)
    assert any("src/__tests__/app.test.js: disabled or skipped test marker(s) added" in e for e in evidence)
    assert any("tests/ServiceTest.java: disabled or skipped test marker(s) added" in e for e in evidence)
    assert any("pkg/server_test.go: disabled or skipped test marker(s) added" in e for e in evidence)
    assert any("spec/calc_spec.rb: disabled or skipped test marker(s) added" in e for e in evidence)


def test_rule2_skip_markers_negative_removal():
    """Removing a skip marker does not trigger Rule 2."""
    diff = """diff --git a/tests/test_skip.py b/tests/test_skip.py
--- a/tests/test_skip.py
+++ b/tests/test_skip.py
@@ -5,2 +5,2 @@
-@pytest.mark.skip(reason="unskip")
 def test_active():
     assert True
"""
    evidence = get_evidence_lines(diff)
    assert not any("disabled or skipped test marker(s)" in e for e in evidence)


# ---------------------------------------------------------------------------
# Rule 3: Global State Mutation Added
# ---------------------------------------------------------------------------


def test_rule3_global_state_mutation_positive():
    """Detects sys.path, __path__, os.environ, process.env, and chdir mutations."""
    diff = """diff --git a/tests/test_env.py b/tests/test_env.py
--- a/tests/test_env.py
+++ b/tests/test_env.py
@@ -1,3 +1,8 @@
+import sys, os
+sys.path.insert(0, '/local/repo')
+sys.path.append('/other')
+os.environ['ENV_VAR'] = 'val'
+os.chdir('/tmp')
"""
    evidence = get_evidence_lines(diff)
    assert any("tests/test_env.py:2: added global state mutation: sys.path.insert(0, '/local/repo')" in e for e in evidence)
    assert any("tests/test_env.py:3: added global state mutation: sys.path.append('/other')" in e for e in evidence)
    assert any("tests/test_env.py:4: added global state mutation: os.environ['ENV_VAR'] = 'val'" in e for e in evidence)
    assert any("tests/test_env.py:5: added global state mutation: os.chdir('/tmp')" in e for e in evidence)


def test_rule3_environ_setdefault_and_update():
    """Detects os.environ.setdefault and os.environ.update as global state mutations."""
    diff = """diff --git a/tests/test_env.py b/tests/test_env.py
--- a/tests/test_env.py
+++ b/tests/test_env.py
@@ -1,1 +1,3 @@
+os.environ.setdefault('A', '1')
+os.environ.update({'B': '2'})
"""
    evidence = get_evidence_lines(diff)
    assert any("os.environ.setdefault" in e for e in evidence)
    assert any("os.environ.update" in e for e in evidence)


def test_rule3_global_state_mutation_negative_monkeypatch():
    """Monkeypatch and standard reads are not reported as global state mutations."""
    diff = """diff --git a/tests/test_env.py b/tests/test_env.py
--- a/tests/test_env.py
+++ b/tests/test_env.py
@@ -1,3 +1,7 @@
 def test_clean(monkeypatch):
     monkeypatch.setenv('VAR', 'val')
     monkeypatch.syspath_prepend('/tmp')
     monkeypatch.chdir('/tmp')
     v = os.environ.get('VAR')
     assert v == 'val'
"""
    evidence = get_evidence_lines(diff)
    assert not any("added global state mutation" in e for e in evidence)


# ---------------------------------------------------------------------------
# Rule 4: New Test Without Assertions (Heuristic)
# ---------------------------------------------------------------------------


def test_rule4_new_test_without_assertions_positive():
    """Heuristic reports added test functions having >= 2 lines and no assertions."""
    diff = """diff --git a/tests/test_hollow.py b/tests/test_hollow.py
--- a/tests/test_hollow.py
+++ b/tests/test_hollow.py
@@ -10,0 +10,5 @@
+def test_does_nothing():
+    x = 1
+    y = 2
+    print(x + y)
+
diff --git a/src/__tests__/ui.test.js b/src/__tests__/ui.test.js
--- a/src/__tests__/ui.test.js
+++ b/src/__tests__/ui.test.js
@@ -5,0 +5,5 @@
+it("renders without check", () => {
+    const btn = renderButton();
+    console.log(btn);
+});
+
diff --git a/pkg/service_test.go b/pkg/service_test.go
--- a/pkg/service_test.go
+++ b/pkg/service_test.go
@@ -5,0 +5,5 @@
+func TestWorker(t *testing.T) {
+    w := newWorker()
+    w.start()
+}
+
diff --git a/tests/AccountTest.cs b/tests/AccountTest.cs
--- a/tests/AccountTest.cs
+++ b/tests/AccountTest.cs
@@ -5,0 +5,5 @@
+    [Fact]
+    public void TestDeposit() {
+        var acc = new Account();
+    }
+
"""
    evidence = get_evidence_lines(diff)
    assert any("tests/test_hollow.py:10 test_does_nothing adds no assertion-like line (heuristic)" in e for e in evidence)
    assert any("src/__tests__/ui.test.js:5 it(\"renders without check\") adds no assertion-like line (heuristic)" in e for e in evidence)
    assert any("pkg/service_test.go:5 TestWorker adds no assertion-like line (heuristic)" in e for e in evidence)
    assert any("tests/AccountTest.cs:5 TestDeposit adds no assertion-like line (heuristic)" in e for e in evidence)


def test_rule4_new_test_without_assertions_negative_has_assert():
    """New test containing an assertion is not flagged."""
    diff = """diff --git a/tests/test_good.py b/tests/test_good.py
--- a/tests/test_good.py
+++ b/tests/test_good.py
@@ -10,0 +10,4 @@
+def test_real():
+    x = compute()
+    assert x == 42
+
"""
    evidence = get_evidence_lines(diff)
    assert not any("adds no assertion-like line" in e for e in evidence)


def test_rule4_new_test_without_assertions_negative_short_stub():
    """Single-line stub or test block shorter than 2 lines is never reported."""
    diff = """diff --git a/tests/test_stub.py b/tests/test_stub.py
--- a/tests/test_stub.py
+++ b/tests/test_stub.py
@@ -10,0 +10,1 @@
+def test_stub(): pass
"""
    evidence = get_evidence_lines(diff)
    assert not any("adds no assertion-like line" in e for e in evidence)


# ---------------------------------------------------------------------------
# Rule 5: Deleted Test File & Deletions-Only Diff
# ---------------------------------------------------------------------------


def test_rule5_deleted_test_file_positive():
    """Deleted test files are reported."""
    diff = """diff --git a/tests/test_deprecated.py b/tests/test_deprecated.py
deleted file mode 100644
--- a/tests/test_deprecated.py
+++ /dev/null
@@ -1,5 +0,0 @@
-def test_old():
-    assert True
"""
    evidence = get_evidence_lines(diff)
    assert any("tests/test_deprecated.py: test file deleted" in e for e in evidence)


def test_rule5_diff_only_deletes_lines_positive():
    """Test file diff containing only line removals is reported."""
    diff = """diff --git a/tests/test_clean.py b/tests/test_clean.py
--- a/tests/test_clean.py
+++ b/tests/test_clean.py
@@ -10,3 +10,0 @@
-def test_obsolete():
-    pass
"""
    evidence = get_evidence_lines(diff)
    assert any("tests/test_clean.py: test file diff only deletes lines" in e for e in evidence)


def test_rule5_deleted_non_test_file_negative():
    """Deleted non-test file is not reported as test file deleted."""
    diff = """diff --git a/docs/old.md b/docs/old.md
deleted file mode 100644
--- a/docs/old.md
+++ /dev/null
@@ -1,2 +0,0 @@
-Old doc
"""
    evidence = get_evidence_lines(diff)
    assert evidence == []


# ---------------------------------------------------------------------------
# Parser Edge Cases: Operators and Metadata
# ---------------------------------------------------------------------------


def test_code_lines_starting_with_plus_or_minus_not_dropped():
    """Lines like ++count or --count inside code hunks are not misidentified as file headers."""
    diff = """diff --git a/tests/test_cpp.cpp b/tests/test_cpp.cpp
--- a/tests/test_cpp.cpp
+++ b/tests/test_cpp.cpp
@@ -5,3 +5,2 @@
-    --count; assert(old_val == 0);
-    assert(base == 1);
+    ++count; assert(new_val == 1);
"""
    evidence = get_evidence_lines(diff)
    assert len(evidence) == 1
    assert "tests/test_cpp.cpp: 2 assertion line(s) removed, 1 added" in evidence[0]
    assert "assert(old_val == 0)" in evidence[0]


def test_no_newline_marker_does_not_shift_line_numbers():
    """A '\\ No newline at end of file' line does not shift line numbering."""
    diff = """diff --git a/tests/test_nl.py b/tests/test_nl.py
--- a/tests/test_nl.py
+++ b/tests/test_nl.py
@@ -1,1 +1,2 @@
 context
\\ No newline at end of file
+sys.path.insert(0, '/tmp')
"""
    evidence = get_evidence_lines(diff)
    assert any("tests/test_nl.py:2:" in e and "sys.path.insert" in e for e in evidence)


# ---------------------------------------------------------------------------
# Cap at 12 Lines
# ---------------------------------------------------------------------------


def test_evidence_lines_cap_at_12():
    """Output is capped at 12 lines with an overflow notice."""
    diff_parts = []
    for i in range(16):
        diff_parts.append(
            f"""diff --git a/tests/test_file_{i}.py b/tests/test_file_{i}.py
new file mode 100644
--- /dev/null
+++ b/tests/test_file_{i}.py
@@ -0,0 +1,4 @@
+import sys
+sys.path.insert(0, '/dir_{i}')
+def test_{i}():
+    x = 1
"""
        )
    diff = "\n".join(diff_parts)
    evidence = get_evidence_lines(diff)
    assert len(evidence) == MAX_EVIDENCE_LINES
    assert evidence[-1].startswith("... and ")
    assert evidence[-1].endswith(" more")


# ---------------------------------------------------------------------------
# ReDoS and 1 MB Line Performance
# ---------------------------------------------------------------------------


def test_redos_and_1mb_line_speed():
    """A diff containing a 1 MB line returns in under 1.0 second."""
    huge_line = "+" + "a" * 1_000_000 + "\n"
    diff = f"""diff --git a/tests/test_huge.py b/tests/test_huge.py
new file mode 100644
--- /dev/null
+++ b/tests/test_huge.py
@@ -0,0 +1,1 @@
{huge_line}"""

    t0 = time.perf_counter()
    res = get_evidence_lines(diff)
    elapsed = time.perf_counter() - t0

    assert elapsed < 1.0, f"Expected < 1.0s, took {elapsed:.4f}s"
    assert isinstance(res, list)


# ---------------------------------------------------------------------------
# Secret Assignment Sanitization & Quoting Length
# ---------------------------------------------------------------------------


def test_secret_assignment_detection_helper():
    """Directly test is_secret_line pattern matching."""
    k1 = "api" + "_key"
    t1 = "secret" + "_token_12345"
    assert is_secret_line(f'{k1} = "{t1}"') is True
    assert is_secret_line('process.env.SECRET_KEY = "token_value_abc"') is True
    assert is_secret_line('os.environ["AUTH_KEY"] = "token_value_xyz"') is True
    assert is_secret_line('x = 10') is False


def test_extract_sec008_rule_patterns_shapes():
    """Test SEC-008 pattern extraction across matchers and fallbacks."""
    patterns = _extract_sec008_rule_patterns()
    assert len(patterns) >= 4
    for p in patterns:
        assert hasattr(p, "search")

    mock_rules = [
        ("SEC-008", "MEDIUM", lambda _f: True, _Sec008Matcher(re.compile(r"mock_sec008_a"), "set", ()), "msg"),
        ("SEC-008", "MEDIUM", lambda _f: True, re.compile(r"mock_sec008_b"), "msg"),
        ("SEC-008", "MEDIUM", lambda _f: True, "not_a_matcher", "msg"),
        ("SEC-004", "HIGH", lambda _f: True, re.compile(r"other_rule"), "msg"),
    ]
    with patch("guard.core.test_evidence.LINE_RULES", mock_rules):
        extracted = _extract_sec008_rule_patterns()
        assert len(extracted) == 2
        assert any(p.search("mock_sec008_a") for p in extracted)
        assert any(p.search("mock_sec008_b") for p in extracted)


def test_secret_assignment_never_quoted():
    """Lines looking like secret assignments are never quoted in evidence."""
    k_name = "api" + "_key"
    token_val = "secret" + "_payload_token_long_value_123"
    diff = (
        "diff --git a/tests/test_sec.py b/tests/test_sec.py\n"
        "--- a/tests/test_sec.py\n"
        "+++ b/tests/test_sec.py\n"
        "@@ -5,1 +5,3 @@\n"
        f'+{k_name} = "{token_val}"\n'
        f'+os.environ["AUTH_KEY"] = "{token_val}"\n'
    )
    evidence = get_evidence_lines(diff)
    for line in evidence:
        assert token_val not in line
    assert any("tests/test_sec.py:6:" in e and "[line omitted: potential secret" in e for e in evidence)


def test_line_quoting_length_cap():
    """Quoted evidence never exceeds MAX_QUOTE_CHARS (160 chars)."""
    long_stmt = "sys.path.insert(0, '" + "x" * 200 + "')"
    diff = f"""diff --git a/tests/test_long.py b/tests/test_long.py
--- a/tests/test_long.py
+++ b/tests/test_long.py
@@ -1,1 +1,2 @@
+{long_stmt}
"""
    evidence = get_evidence_lines(diff)
    assert len(evidence) >= 1
    quote = format_quoted_line("tests/test_long.py", 1, long_stmt)
    assert len(quote) <= MAX_QUOTE_CHARS
    assert quote.endswith("...")


# ---------------------------------------------------------------------------
# Scanned Line Limit (20,000 Lines)
# ---------------------------------------------------------------------------


def test_diff_exceeds_max_scanned_lines_notice():
    """Diffs exceeding 20,000 lines report that only first 20,000 lines were scanned."""
    dummy_lines = [" context line"] * (MAX_SCANNED_LINES + 500)
    # Case A: Diff with a test file
    diff = (
        "diff --git a/tests/test_big.py b/tests/test_big.py\n"
        "--- a/tests/test_big.py\n"
        "+++ b/tests/test_big.py\n"
        "@@ -1,1 +1,1 @@\n"
        + "\n".join(dummy_lines)
    )
    evidence = get_evidence_lines(diff)
    assert any("scanned first 20,000 lines only" in e for e in evidence)

    # Case B: Diff without test files in the first 20,000 lines also emits notice
    diff_no_test = (
        "diff --git a/src/big.py b/src/big.py\n"
        "--- a/src/big.py\n"
        "+++ b/src/big.py\n"
        "@@ -1,1 +1,1 @@\n"
        + "\n".join(dummy_lines)
    )
    ev_no_test = get_evidence_lines(diff_no_test)
    assert any("scanned first 20,000 lines only" in e for e in ev_no_test)


# ---------------------------------------------------------------------------
# Real Commit Fixtures (d3eec3b & tracked test_command_target fixture)
# ---------------------------------------------------------------------------


def test_real_commit_d3eec3b_defects_captured():
    """Commit d3eec3b mutations to sys.path, guard.__path__, and skip are detected."""
    fallback = (
        "diff --git a/tests/test_main_module.py b/tests/test_main_module.py\n"
        "new file mode 100644\n--- /dev/null\n+++ b/tests/test_main_module.py\n"
        "@@ -0,0 +1,86 @@\n"
        "+def test_main_module_matches_console_script():\n"
        '+    guard_bin = shutil.which("guard")\n'
        "+    if not guard_bin:\n"
        '+        pytest.skip("guard console script not found in PATH")\n'
        "+    local_root = str(Path(__file__).resolve().parent.parent)\n"
        "+    if local_root not in sys.path:\n"
        "+        sys.path.insert(0, local_root)\n"
        '+    local_guard_dir = str(Path(__file__).resolve().parent.parent / "guard")\n'
        "+    if local_guard_dir not in guard.__path__:\n"
        "+        guard.__path__.insert(0, local_guard_dir)\n"
        "+    assert True\n"
    )
    diff = _get_git_show_diff("d3eec3b", "tests/test_main_module.py", fallback)
    evidence = get_evidence_lines(diff)
    assert any("tests/test_main_module.py: disabled or skipped test marker(s) added" in e for e in evidence)
    assert any("sys.path.insert" in e for e in evidence)
    assert any("guard.__path__" in e for e in evidence)


def test_tracked_fixture_t1_v1_test_command_target_loads():
    """Verify tracked fixture tests/fixtures/test_quality/t1_v1_test_command_target.txt detects path mutations."""
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "test_quality" / "t1_v1_test_command_target.txt"
    assert fixture_path.exists()
    content = fixture_path.read_text(encoding="utf-8")
    assert len(content) > 1000
    diff = (
        "diff --git a/tests/test_command_target.py b/tests/test_command_target.py\n"
        "new file mode 100644\n--- /dev/null\n+++ b/tests/test_command_target.py\n"
        "@@ -0,0 +1,50 @@\n"
        + "\n".join("+" + line for line in content.splitlines()[:50])
    )
    evidence = get_evidence_lines(diff)
    assert len(evidence) >= 2
    assert any("guard.__path__" in e for e in evidence)
    assert any("guard.agent.__path__" in e for e in evidence)


# ---------------------------------------------------------------------------
# Review Checklist: TEST_QUALITY_CHECKLIST
# ---------------------------------------------------------------------------


def test_review_checklist_length_and_topics():
    """Checklist is under 1,600 chars and covers all required test-quality topics via keywords."""
    assert len(TEST_QUALITY_CHECKLIST) < 1600

    required_keywords = [
        "mock",
        "tautolog",
        "cannot fail",
        "empty",
        "zero",
        "feature removed",
        "weakened",
        "deleted",
        "skip",
        "reason",
        "sys.path",
        "environment",
        "cwd",
        "restor",
        "working directory",
        "script",
        "ambient",
        "helper",
        "private",
        "public",
        "blocks",
        "unproven",
        "advisory",
    ]

    checklist_lower = TEST_QUALITY_CHECKLIST.lower()
    for kw in required_keywords:
        assert kw in checklist_lower, f"Missing required keyword in TEST_QUALITY_CHECKLIST: {kw}"
