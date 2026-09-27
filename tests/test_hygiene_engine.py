"""
Unit tests for Hygiene & Dead Code Engine.
"""

from pathlib import Path
from guard.core.hygiene_engine import HygieneEngine
from guard.core.ocr_engine import DiffSummary, FileDiffStat


def test_is_junk_filename():
    engine = HygieneEngine()
    assert engine.is_junk_filename("src/temp_auth.py") is True
    assert engine.is_junk_filename("components/Modal.backup.tsx") is True
    assert engine.is_junk_filename("test_scratchpad.py") is True
    assert engine.is_junk_filename("build/output.tmp") is True
    assert engine.is_junk_filename("src/copy_of_header.ts") is True

    assert engine.is_junk_filename("src/components/Header.tsx") is False
    assert engine.is_junk_filename("guard/core/invariant_eval.py") is False


def test_is_entrypoint_or_whitelisted():
    engine = HygieneEngine()
    assert engine.is_entrypoint_or_whitelisted("README.md") is True
    assert engine.is_entrypoint_or_whitelisted("pyproject.toml") is True
    assert engine.is_entrypoint_or_whitelisted("src/main.ts") is True
    assert engine.is_entrypoint_or_whitelisted("src/index.tsx") is True
    assert engine.is_entrypoint_or_whitelisted("tests/test_core.py") is True
    assert engine.is_entrypoint_or_whitelisted("docs/index.html") is True

    assert engine.is_entrypoint_or_whitelisted("src/components/DeadWidget.tsx") is False
    assert engine.is_entrypoint_or_whitelisted("services/unused_helper.py") is False


def test_check_orphan_file_in_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    # File A is imported by main.py
    (repo / "main.py").write_text("from active_module import do_work\n", encoding="utf-8")
    (repo / "active_module.py").write_text("def do_work(): pass\n", encoding="utf-8")

    # File B is completely orphaned (not imported anywhere)
    (repo / "orphan_service.py").write_text("def abandoned(): pass\n", encoding="utf-8")

    engine = HygieneEngine(repo_path=repo)

    # Active module is not orphan
    assert engine.check_orphan_file("active_module.py") is None

    # Orphan service is flagged
    viol = engine.check_orphan_file("orphan_service.py")
    assert viol is not None
    assert viol.rule_id == "DEAD-001"
    assert "Orphan file" in viol.message


def test_scan_commented_code_detection():
    engine = HygieneEngine()

    # 1. Normal prose comments -> No violation
    prose = [
        "// This function handles the checkout process",
        "// We validate the token and then submit order",
        "// Returns true if checkout succeeded",
    ]
    assert len(engine.scan_commented_code_lines(prose, "Checkout.tsx")) == 0

    # 2. Commented-out code block (3 lines) -> Violation
    commented_code = [
        "// const oldTax = calculateTax(amount);",
        "// const total = amount + oldTax;",
        "// return submitOrder(total);",
    ]
    violations = engine.scan_commented_code_lines(commented_code, "Checkout.tsx")
    assert len(violations) == 1
    assert violations[0].rule_id == "DEAD-002"
    assert "Commented-out code block (3 lines)" in violations[0].message


def test_scan_python_unused_symbols():
    engine = HygieneEngine()

    code = """
def public_api():
    return _active_helper()

def _active_helper():
    return "active"

def _dead_helper(x, y):
    # This helper is defined but never called
    return x * y + 42
"""
    violations = engine.scan_python_unused_symbols(code, "services/calc.py")
    assert len(violations) == 1
    assert violations[0].rule_id == "DEAD-003"
    assert "_dead_helper" in violations[0].message

def test_scan_python_unused_imports():
    engine = HygieneEngine()

    code = """
import os
import math
from sys import argv, exit

def run():
    print(os.getcwd())
    print(argv)
"""
    violations = engine.scan_python_unused_symbols(code, "services/cli.py")
    unused_symbols = [v.message for v in violations if "Unused imported symbol" in v.message]
    assert any("math" in msg for msg in unused_symbols)
    assert any("exit" in msg for msg in unused_symbols)
    assert not any("os" in msg for msg in unused_symbols)
    assert not any("argv" in msg for msg in unused_symbols)

def test_scan_diff_level(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("print('hello')\n", encoding="utf-8")

    engine = HygieneEngine(repo_path=repo)

    raw_diff = """
diff --git a/temp_draft.py b/temp_draft.py
new file mode 100644
--- /dev/null
+++ b/temp_draft.py
@@ -0,0 +1,5 @@
+# const a = 1;
+# const b = 2;
+# return a + b;
+print("draft")
"""
    diff_summary = DiffSummary(
        total_files=1,
        files=[FileDiffStat(path="temp_draft.py", status="added", insertions=5, deletions=0)],
        raw_diff=raw_diff,
    )

    violations = engine.scan_diff_level(raw_diff, diff_summary)
    assert any(v.rule_id == "DEAD-001" for v in violations)
    assert any(v.rule_id == "DEAD-002" for v in violations)


def test_scan_focus_level(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    dead_file = repo / "dead.py"
    dead_file.write_text("""
# def legacy_process():
#     const = 1;
#     return const;

def _unused_subroutine():
    return 100
""", encoding="utf-8")

    engine = HygieneEngine(repo_path=repo)
    violations = engine.scan_focus_level(["dead.py"])

    # Expect orphan check (DEAD-001), commented code (DEAD-002), and unused subroutine (DEAD-003)
    rule_ids = {v.rule_id for v in violations}
    assert "DEAD-001" in rule_ids
    assert "DEAD-002" in rule_ids
    assert "DEAD-003" in rule_ids


def test_documentation_is_never_an_orphan(tmp_path):
    from guard.core.hygiene_engine import HygieneEngine
    engine = HygieneEngine(tmp_path)
    for doc in ("plans/2026-x/phase-01.md", "docs/guide.rst", "NOTES.txt", "handbook/docs/a.mdx"):
        assert engine.check_orphan_file(doc) is None, doc
