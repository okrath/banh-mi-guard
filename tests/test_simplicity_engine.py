"""
Unit tests for Simplicity & Engineering Frugality Engine (KISS & YAGNI).
"""

from guard.core.ocr_engine import DiffSummary, FileDiffStat
from guard.core.simplicity_engine import SimplicityEngine


def test_calculate_net_loc_bonus():
    engine = SimplicityEngine()

    # Net negative LOC (deleted 100 lines, added 20 -> net: -80)
    diff_negative = DiffSummary(
        total_insertions=20,
        total_deletions=100,
        files=[],
    )
    res = engine.calculate_net_loc(diff_negative)
    assert res["is_net_negative"] is True
    assert res["net_loc"] == -80
    assert "Debt Reduction Bonus" in res["bonus_label"]

    # Neutral or standard expansion
    diff_positive = DiffSummary(
        total_insertions=40,
        total_deletions=10,
        files=[],
    )
    res_pos = engine.calculate_net_loc(diff_positive)
    assert res_pos["is_net_negative"] is False
    assert res_pos["net_loc"] == 30


def test_scan_dependency_bloat_npm():
    engine = SimplicityEngine()

    raw_diff = """
diff --git a/package.json b/package.json
index 123..456 100644
--- a/package.json
+++ b/package.json
@@ -10,2 +10,4 @@
+    "is-odd": "^3.0.1",
+    "uuid": "^9.0.0",
     "react": "^18.2.0"
"""
    violations = engine.scan_dependency_bloat(raw_diff)
    assert len(violations) == 2
    rule_ids = [v.rule_id for v in violations]
    assert all(r == "LAZY-001" for r in rule_ids)
    assert any("is-odd" in v.message for v in violations)
    assert any("uuid" in v.message for v in violations)


def test_scan_dependency_bloat_python():
    engine = SimplicityEngine()

    raw_diff = """
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,1 +1,3 @@
+pathlib2>=2.3.0
+mock>=4.0.0
 requests>=2.31.0
"""
    violations = engine.scan_dependency_bloat(raw_diff)
    assert len(violations) == 2
    assert any("pathlib2" in v.message for v in violations)
    assert any("mock" in v.message for v in violations)



def test_scan_diff_and_focus_levels(tmp_path):
    repo = tmp_path / "frugal_repo"
    repo.mkdir()

    calc_file = repo / "calc.py"
    calc_file.write_text("""
def calculate_subtotal(order):
    return compute_total(order)
""", encoding="utf-8")

    engine = SimplicityEngine(repo_path=repo)

    # Diff-level check
    diff = """
diff --git a/package.json b/package.json
+++ b/package.json
@@ -5,0 +5,1 @@
+    "rimraf": "^5.0.0"
"""
    diff_summary = DiffSummary(total_files=1, files=[FileDiffStat(path="package.json", status="modified", insertions=1, deletions=0)])
    diff_viols = engine.scan_diff_level(diff, diff_summary)
    assert len(diff_viols) == 1
    assert diff_viols[0].rule_id == "LAZY-001"

    # Focus-level check
    focus_viols = engine.scan_focus_level(["calc.py"])
    assert len(focus_viols) == 0
