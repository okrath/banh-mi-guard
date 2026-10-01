"""
Unit tests for OCR Engine and Git Diff Inspector across Quality Pillars.
"""

from pathlib import Path

from guard.core.ocr_engine import (
    GitDiffInspector,
    OCRRulebookRunner,
)

SAMPLE_DIFF = """diff --git a/src/Checkout.tsx b/src/Checkout.tsx
new file mode 100644
--- /dev/null
+++ b/src/Checkout.tsx
@@ -0,0 +1,5 @@
+import React from "react";
+export const Checkout = () => {
+  const apiKey = "sk_live_998877665544332211";
+  return <div>Checkout</div>;
+};
diff --git a/src/api/order.ts b/src/api/order.ts
--- a/src/api/order.ts
+++ b/src/api/order.ts
@@ -10,3 +10,2 @@
- const query = "SELECT * FROM orders WHERE id = 1";
+ const query = "SELECT * FROM orders WHERE id = " + orderId;
"""


def test_parse_diff_stats():
    inspector = GitDiffInspector(Path("."))
    summary = inspector.parse_diff(SAMPLE_DIFF, expected_files=["src/Checkout.tsx"])

    assert len(summary.files) == 2
    assert summary.total_insertions == 6
    assert summary.total_deletions == 1
    # src/api/order.ts was not in expected_files -> out of scope!
    assert "src/api/order.ts" in summary.out_of_scope_files
    assert "src/Checkout.tsx" not in summary.out_of_scope_files


def test_rulebook_secret_detection():
    runner = OCRRulebookRunner()
    violations = runner.scan_diff(SAMPLE_DIFF)

    secret_violation = next((v for v in violations if v.rule_id == "SEC-001"), None)
    assert secret_violation is not None
    assert secret_violation.severity == "CRITICAL"
    assert "src/Checkout.tsx" in secret_violation.file_path


def test_rulebook_sqli_detection():
    runner = OCRRulebookRunner()
    violations = runner.scan_diff(SAMPLE_DIFF)

    sqli_violation = next((v for v in violations if v.rule_id == "SEC-002"), None)
    assert sqli_violation is not None
    assert sqli_violation.severity == "CRITICAL"
    assert "orderId" in sqli_violation.snippet


def test_rulebook_xss_detection():
    diff = """diff --git a/src/Post.tsx b/src/Post.tsx
--- a/src/Post.tsx
+++ b/src/Post.tsx
@@ -10,2 +10,3 @@
+ return <div dangerouslySetInnerHTML={{ __html: userBio }} />;
"""
    runner = OCRRulebookRunner()
    violations = runner.scan_diff(diff)
    xss_violation = next((v for v in violations if v.rule_id == "SEC-003"), None)
    assert xss_violation is not None
    assert xss_violation.severity == "HIGH"


def test_clean_diff_no_violations():
    diff = """diff --git a/src/App.tsx b/src/App.tsx
--- a/src/App.tsx
+++ b/src/App.tsx
@@ -5,2 +5,2 @@
- const title = "Old Title";
+ const title = "New Title";
"""
    runner = OCRRulebookRunner()
    violations = runner.scan_diff(diff)
    assert len(violations) == 0
