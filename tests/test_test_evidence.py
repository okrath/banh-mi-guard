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
    MAX_PATH_CHARS,
    MAX_SCANNED_LINES,
    _extract_sec008_rule_patterns,
    _extract_secret_patterns,
    decode_git_path,
    is_assertion_line,
    is_secret_line,
    is_test_path,
    shorten_path,
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
        "Test/something.py",
        "TESTS/something.py",
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
        "src/user-profileTest.java",
        "src/my.fileTests.cs",
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
        "src/Latest.java",
        "src/Contest.kt",
        "src/contests.py",
        "src/attests.js",
        "src/fastest.cs",
        "src/protest.swift",
    ],
)
def test_is_test_path_negative(path: str):
    """Non-test paths and lookalike suffix words are rejected."""
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
# Comment Filtering & Assertion Refinement
# ---------------------------------------------------------------------------


def test_commented_out_assertion_reported_as_removed():
    """Commenting out an assertion counts as removed and is reported."""
    diff_hash = """diff --git a/tests/test_c.py b/tests/test_c.py
--- a/tests/test_c.py
+++ b/tests/test_c.py
@@ -1,2 +1,2 @@
-assert total == 3
+# assert total == 3
"""
    ev_hash = get_evidence_lines(diff_hash)
    assert len(ev_hash) == 1
    assert "tests/test_c.py: 1 assertion line(s) removed, 0 added" in ev_hash[0]

    diff_slash = """diff --git a/src/__tests__/c.test.ts b/src/__tests__/c.test.ts
--- a/src/__tests__/c.test.ts
+++ b/src/__tests__/c.test.ts
@@ -1,2 +1,2 @@
-expect(total).toBe(3)
+// expect(total).toBe(3)
"""
    ev_slash = get_evidence_lines(diff_slash)
    assert len(ev_slash) == 1
    assert "src/__tests__/c.test.ts: 1 assertion line(s) removed, 0 added" in ev_slash[0]

    diff_block = """diff --git a/tests/test_b.py b/tests/test_b.py
--- a/tests/test_b.py
+++ b/tests/test_b.py
@@ -1,2 +1,2 @@
-assert total == 3
+/* assert total == 3 */
"""
    ev_block = get_evidence_lines(diff_block)
    assert len(ev_block) == 1
    assert "tests/test_b.py: 1 assertion line(s) removed, 0 added" in ev_block[0]


def test_assignment_containing_assert_not_an_assertion():
    """Assignments like assertion_count = 0 or has_assert = True are not counted."""
    assert is_assertion_line("assertion_count = 0", "test.py") is False
    assert is_assertion_line("has_assert = True", "test.py") is False
    assert is_assertion_line("assert_flag = False", "test.py") is False
    assert is_assertion_line("assert total == 3", "test.py") is True
    assert is_assertion_line("assert x > 0  # comment", "test.py") is True


def test_language_aware_comment_syntax():
    """Comment markers respect the file language (# in python/ruby, // in js/ts/swift)."""
    # Swift Testing macros with # are assertions, not comments
    assert is_assertion_line("#expect(x == 1)", "test.swift") is True
    assert is_assertion_line("#assert(x)", "test.swift") is True

    # JS private fields with # are not comments
    assert is_assertion_line("assert(this.#x == 1);", "test.js") is True

    # Python floor division // is not a comment
    assert is_assertion_line("x = a // 2; assert x", "test.py") is True


def test_inline_block_comment_with_assertion():
    """A line starting with closed /* note */ followed by an assertion is counted as an assertion."""
    diff_inline = """diff --git a/tests/test_inline.ts b/tests/test_inline.ts
--- a/tests/test_inline.ts
+++ b/tests/test_inline.ts
@@ -10,2 +10,1 @@
-expect(old).toBe(1);
-expect(older).toBe(2);
+/* note */ expect(x).toBe(1);
"""
    ev = get_evidence_lines(diff_inline)
    assert len(ev) == 1
    assert "2 assertion line(s) removed, 1 added" in ev[0]


def test_block_comment_separate_old_and_new_state_repro1():
    """Un-commenting a test (-/* ... -*/) does not treat following added lines as commented."""
    diff_r1 = """diff --git a/tests/test_u1.ts b/tests/test_u1.ts
--- a/tests/test_u1.ts
+++ b/tests/test_u1.ts
@@ -10,3 +10,4 @@
-/*
+it("uncommented test", () => {
+    expect(true).toBe(true);
+});
-*/
"""
    ev = get_evidence_lines(diff_r1)
    assert not any("adds no assertion-like line" in e for e in ev)


def test_block_comment_separate_old_and_new_state_repro2():
    """Replacement hunk with -/* old and +// new does not treat added lines as block-commented."""
    diff_r2 = """diff --git a/tests/test_u2.ts b/tests/test_u2.ts
--- a/tests/test_u2.ts
+++ b/tests/test_u2.ts
@@ -10,4 +10,4 @@
-/* old
+// new
+it("active test", () => {
+    expect(true).toBe(true);
+});
 */
"""
    ev = get_evidence_lines(diff_r2)
    assert not any("adds no assertion-like line" in e for e in ev)


# ---------------------------------------------------------------------------
# Line Splitting (no split on form feeds \x0c)
# ---------------------------------------------------------------------------


def test_line_splitting_preserves_form_feed():
    """Embedded form feeds \\x0c do not create phantom diff lines."""
    diff_ff = """diff --git a/tests/test_ff.py b/tests/test_ff.py
--- a/tests/test_ff.py
+++ b/tests/test_ff.py
@@ -1,2 +1,2 @@
-assert x == 1
+x = 1\x0c+assert True
"""
    ev_ff = get_evidence_lines(diff_ff)
    assert len(ev_ff) == 1
    assert "tests/test_ff.py: 1 assertion line(s) removed, 0 added" in ev_ff[0]


# ---------------------------------------------------------------------------
# Table-Driven Assertion Patterns
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line, path, expected",
    [
        ("assert x == 1", "test.py", True),
        ("assert False, 'error message'", "test.py", True),
        ("self.assertEqual(a, b)", "test.py", True),
        ("self.assertTrue(result)", "test.py", True),
        ("assert_equal 1, x", "test_minitest.rb", True),
        ("assert.Equal(t, 1, x)", "server_test.go", True),
        ("assert.equal(x, 1);", "test.js", True),
        ("assert.strictEqual(x, 1);", "test.js", True),
        ("#expect(x == 1)", "test.swift", True),
        ("#assert(x)", "test.swift", True),
        ("expect(val).toBe(42)", "test.ts", True),
        ("expect(() => call()).toThrow()", "test.ts", True),
        ("val.should.equal(10)", "test.rb", True),
        ("val.should be == 10", "test.rb", True),
        ("result.shouldBe(42)", "test.kt", True),
        ("result shouldBe 42", "test.kt", True),
        ("result.Should().Be(42)", "Test.cs", True),
        ("require.Equal(t, expected, actual)", "server_test.go", True),
        ("require.NoError(t, err)", "server_test.go", True),
        ("require(condition)", "test.js", True),
        ("verify(mockService).save()", "Test.java", True),
        ("check(propertyHolds)", "test.py", True),
        ("Assert.assertEquals(expected, actual)", "Test.java", True),
        ("Assertions.assertTrue(ok)", "Test.java", True),
        ("XCTAssertEqual(res, 200)", "Test.swift", True),
        ("XCTAssert(flag)", "Test.swift", True),
        ("t.Errorf('unexpected: %v', err)", "test.go", True),
        ("t.Fatalf('fatal: %v', err)", "test.go", True),
        ("assertEquals(1, 2)", "Test.java", True),
        ("ok(isValid, 'must hold')", "test.js", True),
        ("#[should_panic]", "test.rs", True),
        ("with pytest.raises(ValueError):", "test.py", True),
        ("with pytest.warns(UserWarning):", "test.py", True),
        ("assertThrows(RuntimeException.class, () -> {})", "Test.java", True),
        # Negative / non-assertion cases
        ("import assert from 'assert'", "test.js", False),
        ("from unittest.mock import Mock", "test.py", False),
        ("const fs = require('fs')", "test.js", False),
        ("let path = require('path')", "test.js", False),
        ("x = 10", "test.py", False),
        ("print('assert nothing here')", "test.py", False),
        ("# assert total == 3", "test.py", False),
        ("// assert total == 3", "test.js", False),
        ("/* assert total == 3 */", "test.js", False),
        ("assertion_count = 0", "test.py", False),
    ],
)
def test_assertion_pattern_table(line: str, path: str, expected: bool):
    """Assertion patterns across all covered testing frameworks."""
    assert is_assertion_line(line, path) == expected


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
# Rule 2: Disabled or Skipped Added (Multi-language coverage)
# ---------------------------------------------------------------------------


def test_rule2_skip_markers_positive_part1():
    """Detects added skip markers across Python, JS, Java, Go, Ruby."""
    diff = """diff --git a/tests/test_skip.py b/tests/test_skip.py
--- a/tests/test_skip.py
+++ b/tests/test_skip.py
@@ -5,1 +5,6 @@
+@pytest.mark.skip(reason="wip")
+@pytest.mark.skipif(condition, reason="skipif")
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
@@ -1,1 +1,6 @@
+@Disabled("flaky test")
+@Test @Disabled
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
@@ -1,1 +1,5 @@
+it "pending feature" do
+    skip "not implemented"
+    pending "reason"
+end
"""
    evidence = get_evidence_lines(diff)
    assert any("tests/test_skip.py: disabled or skipped test marker(s) added" in e for e in evidence)
    assert any("src/__tests__/app.test.js: disabled or skipped test marker(s) added" in e for e in evidence)
    assert any("tests/ServiceTest.java: disabled or skipped test marker(s) added" in e for e in evidence)
    assert any("pkg/server_test.go: disabled or skipped test marker(s) added" in e for e in evidence)
    assert any("spec/calc_spec.rb: disabled or skipped test marker(s) added" in e for e in evidence)


def test_rule2_skip_markers_positive_part2():
    """Detects added skip markers across C#, PHPUnit, Swift, Dart."""
    diff = """diff --git a/tests/TestCs.cs b/tests/TestCs.cs
--- a/tests/TestCs.cs
+++ b/tests/TestCs.cs
@@ -1,1 +1,4 @@
+[Fact(Skip = "broken")]
+[Test, Ignore("flaky")]
+public void TestMethod() {}
diff --git a/tests/TestPhp.php b/tests/TestPhp.php
--- a/tests/TestPhp.php
+++ b/tests/TestPhp.php
@@ -1,1 +1,4 @@
+$this->markTestSkipped("not configured");
diff --git a/tests/TestSwift.swift b/tests/TestSwift.swift
--- a/tests/TestSwift.swift
+++ b/tests/TestSwift.swift
@@ -1,1 +1,4 @@
+XCTSkip("not ready")
diff --git a/test/test_dart.dart b/test/test_dart.dart
--- a/test/test_dart.dart
+++ b/test/test_dart.dart
@@ -1,1 +1,4 @@
+test('dart test', () {}, skip: true);
"""
    evidence = get_evidence_lines(diff)
    assert any("tests/TestCs.cs: disabled or skipped test marker(s) added" in e for e in evidence)
    assert any("tests/TestPhp.php: disabled or skipped test marker(s) added" in e for e in evidence)
    assert any("tests/TestSwift.swift: disabled or skipped test marker(s) added" in e for e in evidence)
    assert any("test/test_dart.dart: disabled or skipped test marker(s) added" in e for e in evidence)


def test_rule2_skip_markers_negative_iterator_and_removal():
    """Stream.skip, LINQ query.Skip and option dicts are not flagged as skip markers."""
    diff = """diff --git a/tests/test_skip.py b/tests/test_skip.py
--- a/tests/test_skip.py
+++ b/tests/test_skip.py
@@ -5,5 +5,5 @@
-@pytest.mark.skip(reason="unskip")
+stream.skip(5)
+query.Skip(10)
+options = {skip: true}
+# skip: true
 def test_active():
     assert True
"""
    evidence = get_evidence_lines(diff)
    assert not any("disabled or skipped test marker(s)" in e for e in evidence)


def test_rule2_skips_in_comments_and_strings_ignored():
    """Skip words inside comments and string literals are not flagged as skip markers."""
    diff_skip_clean = """diff --git a/tests/test_skip_clean.py b/tests/test_skip_clean.py
--- a/tests/test_skip_clean.py
+++ b/tests/test_skip_clean.py
@@ -1,1 +1,4 @@
+x = 1  # skip
+return skip
+s = 'it.skip(x)'
"""
    ev = get_evidence_lines(diff_skip_clean)
    assert not any("disabled or skipped test marker(s)" in e for e in ev)


# ---------------------------------------------------------------------------
# Rule 3: Global State Mutation Added (Multi-language coverage & comparisons)
# ---------------------------------------------------------------------------


def test_rule3_global_state_mutation_positive_part1():
    """Detects sys.path, __path__, os.environ, and putenv mutations."""
    diff = """diff --git a/tests/test_env1.py b/tests/test_env1.py
--- a/tests/test_env1.py
+++ b/tests/test_env1.py
@@ -1,1 +1,9 @@
+import sys, os
+sys.path.insert(0, '/local/repo')
+sys.path.append('/other')
+guard.__path__.insert(0, '/local/guard')
+guard.__path__ = ['/local/guard']
+os.environ['ENV_VAR'] = 'val'
+os.environ.setdefault('A', '1')
+os.environ.update({'B': '2'})
+os.putenv('A', 'B')
"""
    evidence = get_evidence_lines(diff)
    assert any("sys.path.insert" in e for e in evidence)
    assert any("sys.path.append" in e for e in evidence)
    assert any("guard.__path__.insert" in e for e in evidence)
    assert any("guard.__path__ =" in e for e in evidence)
    assert any("os.environ['ENV_VAR'] = 'val'" in e for e in evidence)
    assert any("os.environ.setdefault" in e for e in evidence)
    assert any("os.environ.update" in e for e in evidence)
    assert any("os.putenv" in e for e in evidence)


def test_rule3_global_state_mutation_positive_part2():
    """Detects setenv, process.env, chdir, ENV[]=, Setenv, setProperty, set_var."""
    diff = """diff --git a/tests/test_env2.py b/tests/test_env2.py
--- a/tests/test_env2.py
+++ b/tests/test_env2.py
@@ -1,1 +1,9 @@
+setenv('C', 'D', 1)
+process.env.NODE_ENV = 'test'
+process.chdir('/tmp')
+os.chdir('/tmp')
+Dir.chdir('/tmp')
+ENV['RUBY_KEY'] = 'val'
+os.Setenv("GO_KEY", "val")
+System.setProperty("java.key", "val")
+env::set_var("RUST_KEY", "val")
"""
    evidence = get_evidence_lines(diff)
    assert any("setenv" in e for e in evidence)
    assert any("process.env.NODE_ENV" in e for e in evidence)
    assert any("process.chdir" in e for e in evidence)
    assert any("os.chdir" in e for e in evidence)
    assert any("Dir.chdir" in e for e in evidence)
    assert any("ENV['RUBY_KEY']" in e for e in evidence)
    assert any("os.Setenv" in e for e in evidence)
    assert any("System.setProperty" in e for e in evidence)
    assert any("env::set_var" in e for e in evidence)


def test_rule3_comparisons_and_reads_not_mutations():
    """Comparisons (==, ===) and reads (in __path__) are not mutations."""
    diff = """diff --git a/tests/test_env.py b/tests/test_env.py
--- a/tests/test_env.py
+++ b/tests/test_env.py
@@ -1,3 +1,10 @@
+if os.environ['CI'] == 'true':
+    pass
+if process.env.CI === 'true':
+    pass
+if local_guard_dir not in guard.__path__:
+    pass
+if ENV['VAR'] == 'val':
+    pass
+s = "os.environ['A'] = 'b'"
+# os.environ['A'] = 'b'
+monkeypatch.setenv('VAR', 'val')
"""
    evidence = get_evidence_lines(diff)
    assert not any("added global state mutation" in e for e in evidence)


# ---------------------------------------------------------------------------
# Rule 4: New Test Without Assertions (Multi-language coverage)
# ---------------------------------------------------------------------------


def test_rule4_new_test_without_assertions_positive_multi_language():
    """Heuristic reports added test functions having >= 2 lines and no assertions."""
    diff = """diff --git a/tests/test_hollow.py b/tests/test_hollow.py
--- a/tests/test_hollow.py
+++ b/tests/test_hollow.py
@@ -10,0 +10,9 @@
+def test_does_nothing():
+    x = 1
+    y = 2
+    print(x + y)
+
+async def test_async_empty():
+    step1()
+    step2()
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
diff --git a/spec/ui_spec.rb b/spec/ui_spec.rb
--- a/spec/ui_spec.rb
+++ b/spec/ui_spec.rb
@@ -5,0 +5,5 @@
+it "runs ruby test" do
+    val = calculate()
+    puts val
+end
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
diff --git a/tests/AppTests.swift b/tests/AppTests.swift
--- a/tests/AppTests.swift
+++ b/tests/AppTests.swift
@@ -5,0 +5,5 @@
+func testLoginScreen() {
+    let screen = LoginScreen()
+    screen.load()
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
diff --git a/tests/UserTest.php b/tests/UserTest.php
--- a/tests/UserTest.php
+++ b/tests/UserTest.php
@@ -5,0 +5,5 @@
+public function testCreateUser() {
+    $u = new User();
+}
+
"""
    evidence = get_evidence_lines(diff)
    assert any("tests/test_hollow.py:10 test_does_nothing adds no assertion-like line" in e for e in evidence)
    assert any("tests/test_hollow.py:15 test_async_empty adds no assertion-like line" in e for e in evidence)
    assert any("src/__tests__/ui.test.js:5 it(\"renders without check\") adds no assertion-like line" in e for e in evidence)
    assert any("spec/ui_spec.rb:5 it(\"runs ruby test\") adds no assertion-like line" in e for e in evidence)
    assert any("pkg/service_test.go:5 TestWorker adds no assertion-like line" in e for e in evidence)
    assert any("tests/AppTests.swift:5 testLoginScreen adds no assertion-like line" in e for e in evidence)
    assert any("tests/AccountTest.cs:5 TestDeposit adds no assertion-like line" in e for e in evidence)
    assert any("tests/UserTest.php:5 testCreateUser adds no assertion-like line" in e for e in evidence)


def test_rule4_test_name_with_apostrophe_cleanly_formatted():
    """Test descriptions with apostrophes like it(\"doesn't crash\") are not truncated."""
    diff = """diff --git a/src/__tests__/apostrophe.test.js b/src/__tests__/apostrophe.test.js
--- a/src/__tests__/apostrophe.test.js
+++ b/src/__tests__/apostrophe.test.js
@@ -1,0 +1,4 @@
+it("doesn't crash on load", () => {
+    const a = 1;
+    console.log(a);
+});
"""
    evidence = get_evidence_lines(diff)
    assert len(evidence) == 1
    assert 'it("doesn\'t crash on load")' in evidence[0]


def test_rule4_test_name_with_secret_or_long_name_sanitized():
    """Rule 4 test names with secrets or exceeding 160 chars are redacted."""
    tok = "Bearer " + "gh" + "p_" + "1234567890" * 3
    diff = f"""diff --git a/tests/SecretNameTest.cs b/tests/SecretNameTest.cs
--- a/tests/SecretNameTest.cs
+++ b/tests/SecretNameTest.cs
@@ -1,0 +1,3 @@
+[Fact(Display = "{tok}")]
+    var x = 1;
+    var y = 2;
"""
    evidence = get_evidence_lines(diff)
    assert len(evidence) == 1
    assert ("gh" + "p_") not in evidence[0]
    assert "[line omitted: potential secret" in evidence[0]


def test_rule4_new_test_without_assertions_negatives():
    """Test with assertions or single line stub is not flagged."""
    diff = """diff --git a/tests/test_good.py b/tests/test_good.py
--- a/tests/test_good.py
+++ b/tests/test_good.py
@@ -10,0 +10,5 @@
+def test_real():
+    x = compute()
+    assert x == 42
+def test_stub(): pass
"""
    evidence = get_evidence_lines(diff)
    assert not any("adds no assertion-like line" in e for e in evidence)


# ---------------------------------------------------------------------------
# Rule 5: Deleted Test File & Deletions-Only Diff
# ---------------------------------------------------------------------------


def test_rule5_deleted_test_file_positive():
    """Deleted test files and deletions-only diffs are reported."""
    diff = """diff --git a/tests/test_deprecated.py b/tests/test_deprecated.py
deleted file mode 100644
--- a/tests/test_deprecated.py
+++ /dev/null
@@ -1,5 +0,0 @@
-def test_old():
-    assert True
diff --git a/tests/test_clean.py b/tests/test_clean.py
--- a/tests/test_clean.py
+++ b/tests/test_clean.py
@@ -10,3 +10,0 @@
-def test_obsolete():
-    pass
"""
    evidence = get_evidence_lines(diff)
    assert any("tests/test_deprecated.py: test file deleted" in e for e in evidence)
    assert any("tests/test_clean.py: test file diff only deletes lines" in e for e in evidence)


# ---------------------------------------------------------------------------
# Quoted Non-ASCII Paths in Git Diffs
# ---------------------------------------------------------------------------


def test_git_quoted_non_ascii_paths_decoded():
    """Git octal-escaped paths (e.g. \\303\\251 -> é) are decoded and recognized."""
    raw = '"a/tests/t\\303\\251st.py"'
    decoded = decode_git_path(raw)
    assert decoded == "a/tests/tést.py"

    diff = """diff --git "a/tests/t\\303\\251st.py" "b/tests/t\\303\\251st.py"
new file mode 100644
--- /dev/null
+++ "b/tests/t\\303\\251st.py"
@@ -0,0 +1,4 @@
+import sys
+sys.path.insert(0, '/tmp')
+def test_ok():
+    assert True
"""
    evidence = get_evidence_lines(diff)
    assert len(evidence) >= 1
    assert any("tests/tést.py" in e and "sys.path.insert" in e for e in evidence)


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
# Performance & ReDoS Tests
# ---------------------------------------------------------------------------


def test_performance_secret_lookalike_input_speed():
    """400 lines of secret-lookalike input must process in well under 1.0 second."""
    chunk = "+sys.path.insert(0,'x'); process.env." + ("token" * 380)
    diff_400 = (
        "diff --git a/tests/test_perf.py b/tests/test_perf.py\n"
        "--- a/tests/test_perf.py\n"
        "+++ b/tests/test_perf.py\n"
        "@@ -1,1 +1,400 @@\n"
        + "\n".join([chunk] * 400)
    )
    t0 = time.perf_counter()
    ev = get_evidence_lines(diff_400)
    elapsed = time.perf_counter() - t0
    # Measured at ~0.005s on local machine; ceiling bounded at 1.0s
    assert elapsed < 1.0, f"Expected < 1.0s, took {elapsed:.4f}s"
    assert len(ev) == MAX_EVIDENCE_LINES


# Hot input chunks for 20,000-line benchmarks (~1,900 chars each)
_CHUNK_A = "sys.path.insert(0, x); process.env.A = b; "
_LINE_A = "s = '" + (_CHUNK_A * (1890 // len(_CHUNK_A))) + "'"

_CHUNK_B = "/* a */ expect(1) '/*' "
_LINE_B = _CHUNK_B * (1900 // len(_CHUNK_B))

_CHUNK_C = "`expect(1)` should check "
_LINE_C = _CHUNK_C * (1900 // len(_CHUNK_C))

_CHUNK_D = "assert(1) expect(1) "
_LINE_D = "assert x='" + (_CHUNK_D * (1880 // len(_CHUNK_D))) + "'"

_CHUNK_E = "The developer should check this implementation carefully. "
_LINE_E = _CHUNK_E * (1900 // len(_CHUNK_E))

_CHUNK_F = "@pytest.mark.skip(reason='x'); it.skip('y'); "
_LINE_F = _CHUNK_F * (1900 // len(_CHUNK_F))


@pytest.mark.parametrize(
    "name, line, fname, mode",
    [
        ("a_in_string_mutation", _LINE_A, "test_perf.py", "added"),
        ("a_in_string_mutation", _LINE_A, "test_perf.py", "removed"),
        ("a_in_string_mutation", _LINE_A, "test_perf.py", "mixed"),
        ("b_comment_dense_js", _LINE_B, "test_perf.js", "added"),
        ("b_comment_dense_js", _LINE_B, "test_perf.js", "removed"),
        ("b_comment_dense_js", _LINE_B, "test_perf.js", "mixed"),
        ("c_backtick_js", _LINE_C, "test_perf.js", "added"),
        ("c_backtick_js", _LINE_C, "test_perf.js", "removed"),
        ("c_backtick_js", _LINE_C, "test_perf.js", "mixed"),
        ("d_keywords_inside_quote", _LINE_D, "test_perf.py", "added"),
        ("d_keywords_inside_quote", _LINE_D, "test_perf.py", "removed"),
        ("d_keywords_inside_quote", _LINE_D, "test_perf.py", "mixed"),
        ("e_prose_should_check", _LINE_E, "test_perf.py", "added"),
        ("e_prose_should_check", _LINE_E, "test_perf.py", "removed"),
        ("e_prose_should_check", _LINE_E, "test_perf.py", "mixed"),
        ("f_dense_skip_markers", _LINE_F, "test_perf.py", "added"),
        ("f_dense_skip_markers", _LINE_F, "test_perf.py", "removed"),
        ("f_dense_skip_markers", _LINE_F, "test_perf.py", "mixed"),
    ],
)
def test_performance_hot_inputs_speed(name: str, line: str, fname: str, mode: str):
    """
    Every hot input of 20,000 lines x ~1,900 chars finishes well under the 6.0s ceiling.
    CI runners are slower and noisier than a laptop (macOS took 3.27s for the prose input);
    the regressions this guards against took 9-28s, so 6.0s leaves room for CI noise and still
    catches them.

    Measured local wall-clock times:
    - a_in_string_mutation: added ~0.49s, removed ~0.22s, mixed ~0.36s
    - b_comment_dense_js: added ~0.48s, removed ~0.31s, mixed ~0.40s
    - c_backtick_js: added ~0.41s, removed ~0.25s, mixed ~0.33s
    - d_keywords_inside_quote: added ~0.37s, removed ~0.14s, mixed ~0.25s
    - e_prose_should_check: added ~1.12s, removed ~0.96s, mixed ~1.03s
    - f_dense_skip_markers: added ~1.86s, removed ~0.96s, mixed ~1.45s
    """
    if mode == "added":
        diff_lines = ["+" + line] * 20000
    elif mode == "removed":
        diff_lines = ["-" + line] * 20000
    else:
        diff_lines = [("+" + line if i % 2 == 0 else "-" + line) for i in range(20000)]
    diff = (
        f"diff --git a/tests/{fname} b/tests/{fname}\n"
        f"--- a/tests/{fname}\n"
        f"+++ b/tests/{fname}\n"
        "@@ -1,10000 +1,10000 @@\n"
        + "\n".join(diff_lines)
    )
    t0 = time.perf_counter()
    ev = get_evidence_lines(diff)
    elapsed = time.perf_counter() - t0

    assert elapsed < 6.0, f"{name} ({mode}) expected < 6.0s, took {elapsed:.4f}s"
    assert elapsed > 0.0
    assert isinstance(ev, list)

    # For cases with comment/string density on added lines, verify slow path reached & budget consumed
    if mode == "added" and name in ("a_in_string_mutation", "b_comment_dense_js", "c_backtick_js", "d_keywords_inside_quote", "f_dense_skip_markers"):
        assert any("diff scan budget reached; scan reduced" in line for line in ev)


def test_performance_prose_non_test_file_skip_speed():
    """20,000 prose lines in a non-test file skip scanning in under 1.0s."""
    diff_nontest = (
        "diff --git a/src/main.py b/src/main.py\n"
        "--- a/src/main.py\n"
        "+++ b/src/main.py\n"
        "@@ -1,1 +1,20000 @@\n"
        + ("+" + _LINE_E + "\n") * 20000
    )
    t0 = time.perf_counter()
    res_nontest = get_evidence_lines(diff_nontest)
    elapsed_nontest = time.perf_counter() - t0
    # Measured at ~0.08s on local machine; ceiling bounded at 1.0s
    assert elapsed_nontest < 1.0, f"Expected < 1.0s, took {elapsed_nontest:.4f}s"
    assert not any("assertion" in e or "mutation" in e or "skipped" in e for e in res_nontest)


def test_diff_scan_budget_exhaustion_emits_notice():
    """Diffs exceeding the character scan budget emit an informational reduction notice."""
    chunk = "/* comment */ expect(x).toBe(1); "
    long_line = "+" + (chunk * (1900 // len(chunk))) + "\n"
    # 300 lines of 1,900 chars = 570,000 chars (exceeds 400,000 char budget)
    diff = (
        "diff --git a/tests/test_budget.ts b/tests/test_budget.ts\n"
        "--- a/tests/test_budget.ts\n"
        "+++ b/tests/test_budget.ts\n"
        "@@ -1,1 +1,300 @@\n"
        + (long_line * 300)
    )
    ev = get_evidence_lines(diff)
    assert any("diff scan budget reached; scan reduced" in e for e in ev)


def test_lines_exceeding_2000_chars_skipped_for_rules_2_and_3():
    """Lines exceeding 2,000 characters do not produce false skip or mutation reports."""
    # Line longer than 2,000 chars with sys.path inside a string that continues (Rule 3)
    chunk = "sys.path.insert(0, '/tmp'); "
    long_line = "+" + 's = "' + (chunk * 100) + '"\n'
    assert len(long_line) > 2000
    diff = f"""diff --git a/tests/test_long.py b/tests/test_long.py
--- a/tests/test_long.py
+++ b/tests/test_long.py
@@ -1,1 +1,2 @@
{long_line}"""
    ev = get_evidence_lines(diff)
    # Must NOT report global state mutation because line > 2,000 chars is skipped
    assert not any("added global state mutation" in e for e in ev)

    # Line longer than 2,000 chars with skip marker inside a string that continues (Rule 2)
    chunk_skip = "it.skip('flaky test'); "
    long_skip_line = "+" + 's = "' + (chunk_skip * 100) + '"\n'
    assert len(long_skip_line) > 2000
    diff_skip = f"""diff --git a/tests/test_long_skip.py b/tests/test_long_skip.py
--- a/tests/test_long_skip.py
+++ b/tests/test_long_skip.py
@@ -1,1 +1,2 @@
{long_skip_line}"""
    ev_skip = get_evidence_lines(diff_skip)
    # Must NOT report disabled/skipped test marker because line > 2,000 chars is skipped
    assert not any("disabled or skipped test marker(s) added" in e for e in ev_skip)

def test_consecutive_closed_block_comments_with_assertion():
    """A line starting with multiple closed block comments followed by an assertion is an assertion line."""
    line = "/* a */ /* b */ expect(1).toBe(1);"
    assert is_assertion_line(line, "test.ts") is True
    diff = """diff --git a/tests/test_consec.ts b/tests/test_consec.ts
--- a/tests/test_consec.ts
+++ b/tests/test_consec.ts
@@ -1,2 +1,1 @@
-expect(old).toBe(1);
-expect(older).toBe(2);
+/* a */ /* b */ expect(1).toBe(1);
"""
    ev = get_evidence_lines(diff)
    assert len(ev) == 1
    assert "2 assertion line(s) removed, 1 added" in ev[0]


def test_rule4_test_inside_added_block_comment_not_reported():
    """A test function entirely enclosed within added block comments does not trigger rule 4."""
    diff = """diff --git a/tests/test_commented.js b/tests/test_commented.js
--- a/tests/test_commented.js
+++ b/tests/test_commented.js
@@ -1,0 +1,5 @@
+/*
+it('commented out test', () => {
+  expect(1).toBe(1);
+});
+*/
"""
    ev = get_evidence_lines(diff)
    assert not any("adds no assertion-like line" in e for e in ev)


def test_rule2_rust_ignore_markers():
    """Rust #[ignore] and #[ignore = 'slow'] are detected as skip markers."""
    diff = """diff --git a/tests/test_rust.rs b/tests/test_rust.rs
--- a/tests/test_rust.rs
+++ b/tests/test_rust.rs
@@ -1,1 +1,7 @@
+#[test]
+#[ignore]
+fn test_a() { assert!(true); }
+#[test]
+#[ignore = "slow"]
+fn test_b() { assert!(true); }
"""
    ev = get_evidence_lines(diff)
    assert any("disabled or skipped test marker(s) added" in e and "#[ignore]" in e and '#[ignore = "slow"]' in e for e in ev)


def test_redos_and_1mb_regex_hot_line_speed():
    """A diff containing a 1 MB line with regex-hot content returns in under 1.0 second."""
    k_env = "API" + "_KEY"
    v_env = "sk_live" + "_1234567890"
    hot_pattern = f"assert x == 1; process.env.{k_env} = '{v_env}'; sys.path.insert(0, '/tmp'); "
    huge_line = "+" + (hot_pattern * (1_000_000 // len(hot_pattern) + 1))[:1_000_000] + "\n"
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
# Secret Redaction & Line/Path Length Bounds
# ---------------------------------------------------------------------------


def test_secret_assignment_and_comparison_never_quoted():
    """Secret tokens, assignments and comparisons are never quoted in evidence lines."""
    k_name = "api" + "_key"
    token_val = "sk_live" + "_998877665544332211aabbcc"
    diff = (
        "diff --git a/tests/test_sec.py b/tests/test_sec.py\n"
        "--- a/tests/test_sec.py\n"
        "+++ b/tests/test_sec.py\n"
        "@@ -5,1 +5,4 @@\n"
        f'+{k_name} = "{token_val}"\n'
        f'+os.environ["AUTH_KEY"] = "{token_val}"\n'
        f'+assert {k_name} == "{token_val}"\n'
    )
    evidence = get_evidence_lines(diff)
    for line in evidence:
        assert token_val not in line
    assert any("tests/test_sec.py:6:" in e and "[line omitted: potential secret" in e for e in evidence)


def test_secret_pattern_breadth():
    """Variable names like DB_PASSWORD and token prefixes are detected as secrets."""
    k_db = "DB" + "_PASSWORD"
    v_db = "my" + "_db_pass_123"
    assert is_secret_line(f'{k_db} = "{v_db}"') is True

    k_aws = "AWS" + "_SECRET_ACCESS_KEY"
    v_aws = "wJalr" + "XUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert is_secret_line(f'{k_aws} = "{v_aws}"') is True

    k_gh = "GITHUB" + "_TOKEN"
    gh_val = "gh" + "p_" + "1234567890" * 3
    assert is_secret_line(f'{k_gh} = "{gh_val}"') is True

    bearer = "Bea" + "rer " + "short_token_val"
    assert is_secret_line(f'auth = "{bearer}"') is True

    slack = "xo" + "xb-" + "1234567890-abcdef"
    assert is_secret_line(f'slack_token = "{slack}"') is True

    jwt = "ey" + "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0"
    assert is_secret_line(f'jwt_token = "{jwt}"') is True

    redis_url = "redis" + "://:" + "super_secret" + "_pw" + "@" + "localhost:6379"
    assert is_secret_line(f'database_url = "{redis_url}"') is True

    # Leaks from review round 4
    k_tok = "API" + "_TOKEN"
    k_sec = "secret" + "_key"
    k_pass = "user" + "_password"
    assert is_secret_line(f"os.environ.setdefault('{k_tok}', 'val')") is True
    assert is_secret_line(f"os.putenv('{k_db}', 'val')") is True
    assert is_secret_line(f"ENV['{k_tok}'] = 'val'") is True
    assert is_secret_line(f'os.Setenv("{k_gh}", "val")') is True
    assert is_secret_line('System.setProperty("db.password", "val")') is True
    assert is_secret_line(f'set_var("{k_tok}", "val")') is True
    assert is_secret_line(f'expect({k_tok.lower()}).toBe("val")') is True
    assert is_secret_line('assertEquals("val", user.getPassword())') is True
    assert is_secret_line('assert.Equal(t, "val", cfg.Token)') is True
    assert is_secret_line("assert cfg['api_key'] == 'val'") is True
    assert is_secret_line(f'assert {k_sec} == b"val"') is True
    assert is_secret_line(f'it("{k_pass}=val", () => {{') is True
    aiza_val = "AI" + "zaSyD-" + "x" * 36
    assert is_secret_line(f'key = "{aiza_val}"') is True
    proj_val = "sk-" + "proj-1234567890abcdef"
    assert is_secret_line(f'proj = "{proj_val}"') is True
    xoxp_val = "xo" + "xp-1234567890-abcdef"
    assert is_secret_line(f'user_token = "{xoxp_val}"') is True
    stripe_val = "sk_" + "test_1234567890abcdef"
    assert is_secret_line(f'stripe = "{stripe_val}"') is True
    gl_val = "gl" + "pat-12345678901234567890"
    assert is_secret_line(f'gl = "{gl_val}"') is True
    pat_val = "github_" + "pat_1234567890"
    assert is_secret_line(f'pat = "{pat_val}"') is True


def test_line_quoting_length_cap_and_path_bounding():
    """Quoted evidence over MAX_QUOTE_CHARS is omitted and paths are shortened."""
    long_stmt = "sys.path.insert(0, '" + "x" * 200 + "')"
    deep_path = "tests/" + "nested/" * 25 + "test_long.py"
    diff = f"""diff --git a/{deep_path} b/{deep_path}
--- a/{deep_path}
+++ b/{deep_path}
@@ -1,1 +1,2 @@
+{long_stmt}
"""
    evidence = get_evidence_lines(diff)
    assert len(evidence) >= 1
    # Check that line over 160 chars is NOT quoted
    assert "[line omitted: exceeds 160 characters" in evidence[0]
    # Check that long path is bounded and keeps directory prefix
    short = shorten_path(deep_path, MAX_PATH_CHARS)
    assert len(short) <= MAX_PATH_CHARS
    assert short.startswith("tests/")
    assert "test_long.py" in short


# ---------------------------------------------------------------------------
# Scanned Line Limit (20,000 Lines)
# ---------------------------------------------------------------------------


def test_diff_exceeds_max_scanned_lines_notice():
    """Diffs exceeding 20,000 lines report notice, even if no test files in the first 20k."""
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
    lines = content.splitlines()
    assert len(lines) >= 280

    # Feed the WHOLE fixture as an added test file diff
    diff = (
        "diff --git a/tests/test_command_target.py b/tests/test_command_target.py\n"
        "new file mode 100644\n--- /dev/null\n+++ b/tests/test_command_target.py\n"
        f"@@ -0,0 +1,{len(lines)} @@\n"
        + "\n".join("+" + line for line in lines)
    )
    evidence = get_evidence_lines(diff)
    assert len(evidence) >= 2
    assert any("guard.__path__" in e for e in evidence)
    assert any("guard.agent.__path__" in e for e in evidence)
    # Note: test_deeply_nested_shells_limit has its assert inside a loop (which may run zero times),
    # which cannot be flagged by heuristic rule 4 and is addressed by TEST_QUALITY_CHECKLIST.


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


def test_extract_secret_patterns_shapes():
    """Test secret pattern extraction across matchers, fallbacks, and alias."""
    patterns = _extract_secret_patterns()
    assert len(patterns) >= 1
    for p in patterns:
        assert hasattr(p, "search")
    # Verify backward-compatibility alias
    assert _extract_sec008_rule_patterns is _extract_secret_patterns
    mock_rules = [
        ("SEC-008", "MEDIUM", lambda _f: True, _Sec008Matcher(re.compile(r"mock_sec008_a"), "set", ()), "msg"),
        ("SEC-008", "MEDIUM", lambda _f: True, re.compile(r"mock_sec008_b"), "msg"),
        ("SEC-008", "MEDIUM", lambda _f: True, "not_a_matcher", "msg"),
        ("SEC-004", "HIGH", lambda _f: True, re.compile(r"other_rule"), "msg"),
    ]
    with patch("guard.core.test_evidence.LINE_RULES", mock_rules):
        extracted = _extract_secret_patterns()
        assert len(extracted) >= 1
