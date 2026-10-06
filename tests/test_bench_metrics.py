"""
Tests for benchmark metrics, runner, comparison, and CLI.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from bench.__main__ import main
from bench.metrics import case_outcome, compare, match_defects, summarise, to_markdown
from bench.runner import (
    ReviewResult,
    default_review_fn,
    estimate_case_worst_calls,
    load_cases_from_path,
    make_dry_run_review_fn,
    run_case,
    run_corpus,
)

# ============================================================================
# Group 1: match_defects tests
# ============================================================================


def test_match_defects_suffix_and_keyword():
    defects = [
        {
            "id": "c03",
            "file": "guard/core/diff_inspector.py",
            "keywords": ["# [ERROR:", "diff error"],
            "severity": "high",
        }
    ]

    # Matching finding: exact file, keyword present, blocking
    findings = [
        {
            "id": "f1",
            "location": "guard/core/diff_inspector.py:42",
            "description": "Found # [ERROR: marker in parser",
            "blocking": True,
            "severity": "high",
        }
    ]
    matched = match_defects(findings, defects)
    assert matched["caught"] == ["c03"]
    assert matched["caught_blocking"] == ["c03"]
    assert matched["missed"] == []
    assert matched["extra_blocking"] == []

    # Suffix match: finding location is just filename or relative path
    findings_suffix = [
        {
            "id": "f2",
            "location": "diff_inspector.py:10",
            "description": "Unexpected diff error here",
            "blocking": True,
            "severity": "high",
        }
    ]
    matched_suffix = match_defects(findings_suffix, defects)
    assert matched_suffix["caught"] == ["c03"]

    # Windows-style backslashes in location
    findings_win = [
        {
            "id": "f3",
            "location": "guard\\core\\diff_inspector.py:5",
            "description": "Found diff error in hunk",
            "blocking": False,
            "severity": "medium",
        }
    ]
    matched_win = match_defects(findings_win, defects)
    assert matched_win["caught"] == ["c03"]
    assert matched_win["caught_advisory"] == ["c03"]
    assert matched_win["caught_blocking"] == []


def test_match_defects_file_only_not_enough():
    """Matching the file without any keyword must NOT catch the defect."""
    defects = [
        {
            "id": "c03",
            "file": "guard/core/diff_inspector.py",
            "keywords": ["# [ERROR:", "diff error"],
        }
    ]
    findings = [
        {
            "id": "f1",
            "location": "guard/core/diff_inspector.py:12",
            "description": "Unrelated syntax issue or indentation flaw",
            "blocking": True,
            "severity": "high",
        }
    ]
    matched = match_defects(findings, defects)
    assert matched["caught"] == []
    assert matched["missed"] == ["c03"]
    # The blocking finding that matched no defect is extra_blocking
    assert matched["extra_blocking"] == ["f1"]


def test_match_defects_keyword_only_wrong_file_not_enough():
    """Matching keywords on the wrong file must NOT catch the defect."""
    defects = [
        {
            "id": "c03",
            "file": "guard/core/diff_inspector.py",
            "keywords": ["diff error"],
        }
    ]
    findings = [
        {
            "id": "f1",
            "location": "guard/core/other_module.py:55",
            "description": "Found diff error in string",
            "blocking": True,
            "severity": "high",
        }
    ]
    matched = match_defects(findings, defects)
    assert matched["caught"] == []
    assert matched["missed"] == ["c03"]
    assert matched["extra_blocking"] == ["f1"]


def test_match_defects_advisory_finding_not_extra_blocking():
    """An advisory finding that matches nothing does not count as extra_blocking."""
    defects = [
        {"id": "c01", "file": "src/app.py", "keywords": ["token leak"]}
    ]
    findings = [
        {
            "id": "adv1",
            "location": "src/other.py:10",
            "description": "Consider adding comments",
            "blocking": False,
            "severity": "low",
        }
    ]
    matched = match_defects(findings, defects)
    assert matched["caught"] == []
    assert matched["missed"] == ["c01"]
    assert matched["extra_blocking"] == []


# ============================================================================
# Group 2: case_outcome tests
# ============================================================================


def test_case_outcome_defect_case():
    case = {
        "id": "c01",
        "label": "defect",
        "defects": [
            {"id": "d1", "file": "src/a.py", "keywords": ["kw1"]},
            {"id": "d2", "file": "src/b.py", "keywords": ["kw2"]},
        ],
    }
    findings = [
        {
            "id": "f1",
            "location": "src/a.py:1",
            "description": "kw1 issue",
            "blocking": True,
            "severity": "high",
        }
    ]
    out = case_outcome(case, verdict="REVISE", findings=findings, calls=2, seconds=1.5)
    assert out["case_id"] == "c01"
    assert out["label"] == "defect"
    assert out["verdict"] == "REVISE"
    assert out["caught_blocking"] == [("c01", "d1")]
    assert out["caught"] == [("c01", "d1")]
    assert out["missed"] == [("c01", "d2")]
    assert out["defects_total"] == 2
    assert out["false_block"] is False
    assert out["calls"] == 2
    assert out["no_llm"] is False


def test_case_outcome_clean_case_clean():
    case = {"id": "n01", "label": "clean", "defects": []}
    out = case_outcome(case, verdict="APPROVED", findings=[], calls=1, seconds=0.5)
    assert out["case_id"] == "n01"
    assert out["label"] == "clean"
    assert out["verdict"] == "APPROVED"
    assert out["false_block"] is False
    assert out["caught"] == []
    assert out["defects_total"] == 0
    assert out["advisory_count"] == 0


def test_case_outcome_clean_case_false_block():
    case = {"id": "n02", "label": "clean", "defects": []}
    # REVISE verdict on clean case -> false block
    out1 = case_outcome(case, verdict="REVISE", findings=[])
    assert out1["false_block"] is True

    # APPROVED verdict but with a blocking finding -> false block
    findings = [
        {
            "id": "fb1",
            "location": "src/clean.py:10",
            "description": "Hallucinated issue",
            "blocking": True,
        }
    ]
    out2 = case_outcome(case, verdict="APPROVED", findings=findings)
    assert out2["false_block"] is True
    assert "fb1" in out2["extra_blocking"]


def test_case_outcome_no_llm():
    case = {"id": "c05", "label": "defect", "defects": [{"id": "d5", "file": "a.py", "keywords": ["k"]}]}
    out = case_outcome(case, verdict="no-llm", findings=[], llm_error="Timeout connecting to model")
    assert out["no_llm"] is True
    assert out["llm_error"] == "Timeout connecting to model"


# ============================================================================
# Group 3: summarise tests
# ============================================================================


def test_summarise_handmade_set():
    # 2 defect cases:
    # c1: 2 defects, catches 1 blocking, 1 advisory
    # c2: 1 defect, catches 1 blocking
    # 2 clean cases:
    # n1: clean pass
    # n2: false block
    outcomes = [
        {
            "case_id": "c1",
            "label": "defect",
            "verdict": "REVISE",
            "defects_total": 2,
            "caught_blocking": ["d1"],
            "caught_advisory": ["d2"],
            "caught": ["d1", "d2"],
            "missed": [],
            "false_block": False,
            "calls": 2,
            "chars_sent": 200,
            "seconds": 1.0,
            "blocking_finding_ids": ["f1"],
        },
        {
            "case_id": "c2",
            "label": "defect",
            "verdict": "REVISE",
            "defects_total": 1,
            "caught_blocking": ["d3"],
            "caught_advisory": [],
            "caught": ["d3"],
            "missed": [],
            "false_block": False,
            "calls": 1,
            "chars_sent": 150,
            "seconds": 0.8,
            "blocking_finding_ids": ["f2"],
        },
        {
            "case_id": "n1",
            "label": "clean",
            "verdict": "APPROVED",
            "defects_total": 0,
            "caught_blocking": [],
            "caught": [],
            "missed": [],
            "false_block": False,
            "calls": 1,
            "chars_sent": 100,
            "seconds": 0.5,
            "blocking_finding_ids": [],
        },
        {
            "case_id": "n2",
            "label": "clean",
            "verdict": "REVISE",
            "defects_total": 0,
            "caught_blocking": [],
            "caught": [],
            "missed": [],
            "false_block": True,
            "calls": 1,
            "chars_sent": 100,
            "seconds": 0.6,
            "blocking_finding_ids": ["f_fb"],
        },
    ]

    s = summarise(outcomes)
    assert s["defects_total"] == 3
    assert s["caught_blocking"] == 2
    assert s["caught_any"] == 3
    assert pytest.approx(s["recall_blocking"], 0.001) == 2 / 3
    assert pytest.approx(s["recall_any"], 0.001) == 1.0
    assert s["clean_total"] == 2
    assert s["false_blocks"] == 1
    assert s["calls"] == 5
    assert s["chars_sent"] == 550
    assert pytest.approx(s["seconds"], 0.01) == 2.9
    assert s["no_llm_count"] == 0
    assert s["skipped_count"] == 0
    assert len(s["per_case_rows"]) == 4


def test_summarise_stability_repeats():
    # Case c1 run 3 times: runs 1 and 2 agree, run 3 differs
    outcomes = [
        {
            "case_id": "c1",
            "label": "defect",
            "verdict": "REVISE",
            "caught": ["d1"],
            "blocking_finding_ids": ["f1"],
            "defects_total": 1,
            "caught_blocking": ["d1"],
            "missed": [],
            "calls": 1,
            "chars_sent": 10,
            "seconds": 0.1,
        },
        {
            "case_id": "c1",
            "label": "defect",
            "verdict": "REVISE",
            "caught": ["d1"],
            "blocking_finding_ids": ["f1"],
            "defects_total": 1,
            "caught_blocking": ["d1"],
            "missed": [],
            "calls": 1,
            "chars_sent": 10,
            "seconds": 0.1,
        },
        {
            "case_id": "c1",
            "label": "defect",
            "verdict": "APPROVED",
            "caught": [],
            "blocking_finding_ids": [],
            "defects_total": 1,
            "caught_blocking": [],
            "missed": ["d1"],
            "calls": 1,
            "chars_sent": 10,
            "seconds": 0.1,
        },
    ]
    s = summarise(outcomes)
    row = s["per_case_rows"][0]
    assert pytest.approx(row["stability"], 0.01) == 2 / 3
    assert pytest.approx(s["stability"], 0.01) == 2 / 3


def test_summarise_no_llm_and_skipped_exclusion():
    outcomes = [
        # Normal defect case
        {
            "case_id": "c1",
            "label": "defect",
            "verdict": "REVISE",
            "defects_total": 1,
            "caught_blocking": ["d1"],
            "caught": ["d1"],
            "missed": [],
            "calls": 1,
            "chars_sent": 50,
            "seconds": 0.5,
            "no_llm": False,
        },
        # Defect case with no-llm (should be excluded from recall calculations)
        {
            "case_id": "c2",
            "label": "defect",
            "verdict": "no-llm",
            "defects_total": 2,
            "caught_blocking": [],
            "caught": [],
            "missed": ["d2", "d3"],
            "calls": 0,
            "chars_sent": 0,
            "seconds": 0.0,
            "no_llm": True,
        },
        # Clean case skipped for budget (should be excluded from clean_total and false_block)
        {
            "case_id": "n1",
            "label": "clean",
            "verdict": "skipped (budget)",
            "defects_total": 0,
            "caught_blocking": [],
            "caught": [],
            "missed": [],
            "calls": 0,
            "chars_sent": 0,
            "seconds": 0.0,
            "skipped": True,
        },
    ]
    s = summarise(outcomes)
    assert s["no_llm_count"] == 1
    assert s["skipped_count"] == 1
    # defects_total should ONLY count c1 (1 defect), not c2
    assert s["defects_total"] == 1
    assert s["caught_blocking"] == 1
    assert s["recall_blocking"] == 1.0
    # clean_total should be 0 because n1 was skipped
    assert s["clean_total"] == 0


# ============================================================================
# Group 4: compare tests (decision rule clauses)
# ============================================================================


def test_compare_clause_a_gained_defects():
    # Baseline caught c01, variant caught c01 and c02 (gained 1 defect)
    base = {"caught_blocking": [("c01", "c01")], "false_blocks": 0, "calls": 10}
    var = {"caught_blocking": [("c01", "c01"), ("c02", "c02")], "false_blocks": 0, "calls": 12}
    res = compare(base, var)
    assert res["gained"] == [("c02", "c02")]
    assert res["lost"] == []
    assert res["new_false_blocks"] == []
    assert res["adopt"] is True


def test_compare_clause_a_removed_false_block():
    # Baseline had a false block on n01; variant removed it
    base = {"caught_blocking": [("c01", "c01")], "false_block_cases": ["n01"], "calls": 10}
    var = {"caught_blocking": [("c01", "c01")], "false_block_cases": [], "calls": 10}
    res = compare(base, var)
    assert res["gained"] == []
    assert res["lost"] == []
    assert res["new_false_blocks"] == []
    assert res["adopt"] is True


def test_compare_clause_a_fail_no_gain():
    # Variant caught the exact same defect, removed no false blocks
    base = {"caught_blocking": [("c01", "c01")], "false_blocks": 0, "calls": 10}
    var = {"caught_blocking": [("c01", "c01")], "false_blocks": 0, "calls": 10}
    res = compare(base, var)
    assert res["adopt"] is False


def test_compare_clause_b_lost_defect():
    # Baseline caught c01 and c02; variant gained c03 but lost c01
    base = {"caught_blocking": [("c01", "c01"), ("c02", "c02")], "false_blocks": 0, "calls": 10}
    var = {"caught_blocking": [("c02", "c02"), ("c03", "c03")], "false_blocks": 0, "calls": 15}
    res = compare(base, var)
    assert res["gained"] == [("c03", "c03")]
    assert res["lost"] == [("c01", "c01")]
    assert res["adopt"] is False


def test_compare_clause_c_new_false_block():
    # Variant gained c02, but raised a new false block on n02
    base = {"caught_blocking": [("c01", "c01")], "false_block_cases": [], "calls": 10}
    var = {"caught_blocking": [("c01", "c01"), ("c02", "c02")], "false_block_cases": ["n02"], "calls": 12}
    res = compare(base, var)
    assert res["gained"] == [("c02", "c02")]
    assert res["new_false_blocks"] == ["n02"]
    assert res["adopt"] is False


def test_compare_clause_d_call_ratio_over_2():
    # Calls ratio is 25 / 10 = 2.5x > 2.0x
    base = {"caught_blocking": ["c01"], "false_blocks": 0, "calls": 10, "recall_blocking": 0.5}
    var = {"caught_blocking": ["c01", "c02"], "false_blocks": 0, "calls": 25, "recall_blocking": 1.0}

    # Under standard default-on rule, call_ratio > 2 blocks adoption
    res_std = compare(base, var, opt_in_by_design=False)
    assert res_std["call_ratio"] == 2.5
    assert res_std["adopt"] is False

    # Under opt-in-by-design (the panel), adopt is ALWAYS False and recommendation is reported
    res_opt = compare(base, var, opt_in_by_design=True)
    assert res_opt["call_ratio"] == 2.5
    assert res_opt["adopt"] is False
    assert "keep as opt-in" in res_opt["recommendation"]
    assert "recall_gained_per_extra_call" in res_opt
    assert pytest.approx(res_opt["recall_gained_per_extra_call"], 0.001) == 0.5 / 15


def test_compare_returns_plain_lists():
    base = {"caught_blocking": ["c01"], "calls": 10}
    var = {"caught_blocking": ["c01", "c02"], "calls": 10}
    res = compare(base, var)
    assert type(res["gained"]) is list
    assert type(res["lost"]) is list
    assert type(res["new_false_blocks"]) is list
# ============================================================================
# Group 5: run_corpus tests
# ============================================================================


def test_estimate_case_worst_calls():
    # Small diff: 1 part, 1 reviewer -> 2 calls
    assert estimate_case_worst_calls("diff --git a/x b/x", repeats=1) == 2
    # Small diff with 3 repeats -> 6 calls
    assert estimate_case_worst_calls("diff", repeats=3) == 6
    diff_2files = (
        "diff --git a/f1.py b/f1.py\n--- a/f1.py\n+++ b/f1.py\n@@ -1,1 +1,1 @@\n" + ("+x\n" * 15000) +
        "diff --git a/f2.py b/f2.py\n--- a/f2.py\n+++ b/f2.py\n@@ -1,1 +1,1 @@\n" + ("+x\n" * 15000)
    )
    assert estimate_case_worst_calls(diff_2files, repeats=1) == 4
    # With validate_findings=True -> +5 calls
    assert estimate_case_worst_calls("diff", variant={"validate_findings": True}, repeats=1) == 7


def test_run_corpus_budget_stops_exactly():
    """Verify max_calls budget stops before exceeding it and marks remaining skipped."""
    cases = [
        {"id": "case1", "label": "defect", "diff": "diff 1", "defects": [{"id": "d1", "file": "a.py", "keywords": ["kw"]}]},
        {"id": "case2", "label": "defect", "diff": "diff 2", "defects": [{"id": "d2", "file": "b.py", "keywords": ["kw"]}]},
        {"id": "case3", "label": "defect", "diff": "diff 3", "defects": [{"id": "d3", "file": "c.py", "keywords": ["kw"]}]},
    ]

    calls_made = 0

    def mock_review(case: dict, variant: Any = None) -> ReviewResult:
        nonlocal calls_made
        calls_made += 1
        return ReviewResult(verdict="APPROVED", findings=[], calls=1, chars_sent=50, seconds=0.01)

    # Worst-case for each case is 2 calls (1 part * 2 * 1 reviewer).
    # Budget = 3:
    # Before case 1: remaining = 3 >= 2 -> runs (calls_made=1, remaining=2).
    # Before case 2: remaining = 2 >= 2 -> runs (calls_made=2, remaining=1).
    # Before case 3: remaining = 1 < 2 -> SKIPPED!
    summary = run_corpus(cases, mock_review, repeats=1, max_calls=3)
    assert calls_made == 2
    assert summary["budget_remaining"] == 1
    assert summary["skipped_count"] == 1
    # Check that case 3 row was recorded as skipped
    c3_row = [r for r in summary["per_case_rows"] if r["case_id"] == "case3"][0]
    assert c3_row["skipped"] is True
    assert c3_row["verdict"] == "skipped (budget)"


def test_run_corpus_label_filter():
    cases = [
        {"id": "c01", "label": "defect", "diff": "d1", "defects": []},
        {"id": "n01", "label": "clean", "diff": "d2", "defects": []},
        {"id": "c02", "label": "defect", "diff": "d3", "defects": []},
    ]
    dry_fn = make_dry_run_review_fn()

    summary_defect = run_corpus(cases, dry_fn, repeats=1, max_calls=100, label_filter="defect")
    assert len(summary_defect["per_case_rows"]) == 2
    assert all(r["label"] == "defect" for r in summary_defect["per_case_rows"])

    summary_clean = run_corpus(cases, dry_fn, repeats=1, max_calls=100, label_filter="clean")
    assert len(summary_clean["per_case_rows"]) == 1
    assert summary_clean["per_case_rows"][0]["case_id"] == "n01"


def test_run_case_repeats():
    case = {"id": "c01", "label": "defect", "diff": "x", "defects": []}
    dry_fn = make_dry_run_review_fn()
    outcomes = run_case(case, dry_fn, repeats=3)
    assert len(outcomes) == 3
    assert all(o["case_id"] == "c01" for o in outcomes)


# ============================================================================
# Group 6: CLI smoke tests
# ============================================================================


def test_cli_smoke_run_dry_run(tmp_path: Path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    c1 = {
        "id": "c01",
        "label": "defect",
        "diff": "diff --git a/a.py b/a.py\n+bad_code\n",
        "defects": [{"id": "c01", "file": "a.py", "keywords": ["error"], "severity": "high"}],
    }
    n1 = {
        "id": "n01",
        "label": "clean",
        "diff": "diff --git a/clean.py b/clean.py\n+good_code\n",
        "defects": [],
    }
    (cases_dir / "c01.json").write_text(json.dumps(c1), encoding="utf-8")
    (cases_dir / "n01.json").write_text(json.dumps(n1), encoding="utf-8")

    out_file = tmp_path / "result.json"
    rc = main(["run", "--cases", str(cases_dir), "--dry-run", "--out", str(out_file)])
    assert rc == 0
    assert out_file.exists()

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "recall_blocking" in data
    assert data["clean_total"] == 1
    assert data["defects_total"] == 1

    # Security check: verify no diff text or finding descriptions in result JSON
    raw_text = out_file.read_text(encoding="utf-8")
    assert "diff --git" not in raw_text
    assert "bad_code" not in raw_text


def test_cli_smoke_compare_and_report(tmp_path: Path, capsys: pytest.CaptureFixture):
    base_file = tmp_path / "baseline.json"
    var_file = tmp_path / "variant.json"
    cmp_out = tmp_path / "compare.json"

    base_data = {
        "caught_blocking": ["c01"],
        "false_blocks": 0,
        "clean_total": 5,
        "calls": 10,
        "recall_blocking": 0.5,
    }
    var_data = {
        "caught_blocking": ["c01", "c02"],
        "false_blocks": 0,
        "clean_total": 5,
        "calls": 12,
        "recall_blocking": 1.0,
    }
    base_file.write_text(json.dumps(base_data), encoding="utf-8")
    var_file.write_text(json.dumps(var_data), encoding="utf-8")

    rc_cmp = main(["compare", str(base_file), str(var_file), "--out", str(cmp_out)])
    assert rc_cmp == 0
    assert cmp_out.exists()
    cmp_res = json.loads(cmp_out.read_text(encoding="utf-8"))
    assert cmp_res["adopt"] is True
    assert cmp_res["gained"] == [["case", "c02"]]

    rc_rep = main(["report", str(var_file)])
    assert rc_rep == 0
    captured = capsys.readouterr()
    assert "Benchmark Results" in captured.out


def test_to_markdown_formatting():
    summary = {
        "recall_blocking": 0.85,
        "recall_any": 0.90,
        "defects_total": 20,
        "caught_blocking": 17,
        "caught_any": 18,
        "false_blocks": 0,
        "clean_total": 5,
        "no_llm_count": 0,
        "skipped_count": 0,
        "stability": 1.0,
        "calls": 42,
        "chars_sent": 125000,
        "seconds": 15.2,
        "per_case_rows": [
            {
                "case_id": "c01",
                "label": "defect",
                "verdict": "REVISE",
                "defects": 1,
                "caught_blocking": ["c01"],
                "missed": [],
                "false_block": False,
                "calls": 2,
                "stability": 1.0,
            }
        ],
    }
    md = to_markdown(summary)
    assert "# Benchmark Results" in md
    assert "85.0%" in md
    assert "42" in md
    assert "| c01 | defect |" in md


# ============================================================================
# Group 7: Harness error check
# ============================================================================


def test_default_review_fn_harness_error(monkeypatch: pytest.MonkeyPatch):
    """When LLM review runs successfully (not heuristic, no llm_error) but calls == 0, fail loudly."""
    monkeypatch.setattr("guard.core.config.load_config", lambda *args, **kwargs: MagicMock())
    fake_verdict = MagicMock()
    fake_verdict.review_mode = "llm"
    fake_verdict.llm_error = None
    fake_verdict.verdict = "APPROVED"
    fake_verdict.findings = []
    fake_verdict.llm_calls = None
    fake_verdict.llm_chars = None

    fake_reviewer = MagicMock()
    fake_reviewer.review.return_value = fake_verdict

    monkeypatch.setattr("guard.core.llm_reviewer.LLMReviewerEngine", lambda **kwargs: fake_reviewer)
    # Patch call_llm so it is never called inside reviewer.review
    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", lambda *args, **kwargs: "")

    case = {"id": "test_c", "diff": "test", "prompt": "test"}
    with pytest.raises(RuntimeError, match="Harness error"):
        default_review_fn(case)


def test_bench_gitignore(tmp_path: Path):
    """Verify bench/.gitignore has exact lines and ignores cases/archive/ and results/."""
    import subprocess

    gitignore_path = Path(__file__).resolve().parent.parent / "bench" / ".gitignore"
    assert gitignore_path.exists()
    content = gitignore_path.read_text(encoding="utf-8")
    assert content == "cases/archive/\nresults/\n"
    # Verify with git check-ignore in a temporary repo
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    bench_dir = tmp_path / "bench"
    bench_dir.mkdir()
    (bench_dir / ".gitignore").write_text(content, encoding="utf-8")

    res1 = subprocess.run(
        ["git", "check-ignore", "bench/cases/archive/x.json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert res1.returncode == 0
    assert "bench/cases/archive/x.json" in res1.stdout

    res2 = subprocess.run(
        ["git", "check-ignore", "bench/results/x.json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert res2.returncode == 0
    assert "bench/results/x.json" in res2.stdout
def test_parse_variant_args():
    from bench.__main__ import parse_variant_args

    args = [
        "reviewers=3",
        "validate_findings=true",
        "auto_sync=false",
        "score=2.5",
        "threat_frame=auto",
    ]
    parsed = parse_variant_args(args)
    assert parsed["reviewers"] == 3
    assert parsed["validate_findings"] is True
    assert parsed["auto_sync"] is False
    assert parsed["score"] == 2.5
    assert parsed["threat_frame"] == "auto"


def test_load_cases_from_path(tmp_path: Path):
    from bench.runner import load_cases_from_path

    # Directory with multiple files
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    (cases_dir / "c1.json").write_text(json.dumps({"id": "c1", "label": "clean"}), encoding="utf-8")
    (cases_dir / "c2.json").write_text(json.dumps({"id": "c2", "label": "defect"}), encoding="utf-8")
    (cases_dir / "not_json.txt").write_text("random text", encoding="utf-8")

    cases = load_cases_from_path(cases_dir)
    assert len(cases) == 2
    assert {c["id"] for c in cases} == {"c1", "c2"}

    # Single JSON file containing a list of cases
    list_file = tmp_path / "cases_list.json"
    list_file.write_text(json.dumps([{"id": "c3"}, {"id": "c4"}]), encoding="utf-8")
    list_cases = load_cases_from_path(list_file)
    assert len(list_cases) == 2
    assert [c["id"] for c in list_cases] == ["c3", "c4"]

    # Non-existent path returns empty list
    assert load_cases_from_path(tmp_path / "nonexistent") == []


def test_internal_metrics_helpers():
    from bench.metrics import (
        _extract_caught_defects,
        _extract_false_block_cases,
        _get_finding_id,
        _normalize_path,
        _path_suffix_match,
    )

    # Path normalization & suffix match
    assert _normalize_path("path\\to\\file.py") == "path/to/file.py"
    assert _path_suffix_match("", "foo.py") is False
    assert _path_suffix_match("foo.py", "") is False
    assert _path_suffix_match("src/a.py", "src/a.py") is True
    assert _path_suffix_match("src/a.py", "a.py") is True
    assert _path_suffix_match("other/a.py", "src/a.py") is False

    # Finding id generation
    assert _get_finding_id({"id": "explicit_id"}) == "explicit_id"
    generated_id = _get_finding_id({"location": "foo.py:1", "description": "desc", "kind": "correctness"})
    assert isinstance(generated_id, str) and len(generated_id) > 0

    # Extract caught defects and false block cases from rows
    summary = {
        "per_case_rows": [
            {"case_id": "c1", "caught_blocking": ["d1"], "false_block": False},
            {"case_id": "n1", "caught_blocking": [], "false_block": True},
        ]
    }
    assert _extract_caught_defects(summary) == {("c1", "d1")}
    assert _extract_false_block_cases(summary) == {"n1"}


def test_internal_runner_helpers():
    from bench.runner import _call_review_fn

    # Review fn returning a ReviewResult directly
    def fn_result(case: dict) -> ReviewResult:
        return ReviewResult(verdict="APPROVED")

    assert _call_review_fn(fn_result, {"id": "1"}, None).verdict == "APPROVED"

    # Review fn returning a dict
    def fn_dict(case: dict, variant: dict | None = None) -> dict:
        return {"verdict": "REVISE", "calls": 2}

    res_dict = _call_review_fn(fn_dict, {"id": "2"}, {"opt": 1})
    assert res_dict.verdict == "REVISE"
    assert res_dict.calls == 2

    # Review fn returning invalid type raises TypeError
    def fn_invalid(case: dict) -> int:
        return 42

    with pytest.raises(TypeError, match="unexpected type"):
        _call_review_fn(fn_invalid, {"id": "3"}, None)
def test_summarise_per_case_missed_defects():
    """Verify per-case rows correctly retain missed defects."""
    outcomes = [
        {
            "case_id": "c1",
            "label": "defect",
            "verdict": "REVISE",
            "caught_blocking": [("c1", "d1")],
            "caught": [("c1", "d1")],
            "missed": [("c1", "d2")],
            "defects_total": 2,
            "calls": 1,
            "chars_sent": 50,
            "seconds": 0.1,
            "blocking_finding_ids": ["f1"],
        }
    ]
    s = summarise(outcomes)
    row = s["per_case_rows"][0]
    assert row["missed"] == [("c1", "d2")]
    assert row["caught_blocking"] == [("c1", "d1")]


def test_compare_with_empty_caught_blocking_lists():
    """Ensure compare handles empty lists without raising TypeError."""
    base = {"caught_blocking": [], "false_blocks": 0, "calls": 5}
    var = {"caught_blocking": [], "false_blocks": 0, "calls": 5}
    res = compare(base, var)
    assert res["adopt"] is False
    assert res["gained"] == []
    assert res["lost"] == []


def test_compare_critical_lost_defect_across_cases():
    """Critical 1: Baseline catching c03 only in c03 and variant catching only in m02 must not adopt."""
    base = {
        "per_case_rows": [
            {
                "case_id": "c03",
                "label": "defect",
                "verdict": "REVISE",
                "caught_blocking": [("c03", "c03")],
                "no_llm": False,
                "skipped": False,
            },
            {
                "case_id": "m02",
                "label": "defect",
                "verdict": "APPROVED",
                "caught_blocking": [],
                "no_llm": False,
                "skipped": False,
            },
        ],
        "calls": 10,
    }
    var = {
        "per_case_rows": [
            {
                "case_id": "c03",
                "label": "defect",
                "verdict": "APPROVED",
                "caught_blocking": [],
                "no_llm": False,
                "skipped": False,
            },
            {
                "case_id": "m02",
                "label": "defect",
                "verdict": "REVISE",
                "caught_blocking": [("m02", "c03")],
                "no_llm": False,
                "skipped": False,
            },
        ],
        "calls": 10,
    }
    res = compare(base, var)
    assert ("c03", "c03") in res["lost"]
    assert ("m02", "c03") in res["gained"]
    assert res["adopt"] is False


def test_budget_overshoot_3x41k():
    """Critical 2: 3 files of ~41k chars estimate 6 calls, and max_calls=4 stops without exceeding 4."""
    content_41k = ("+x" * 20500) + "\n"
    diff_3x41k = (
        "diff --git a/f1.py b/f1.py\n--- a/f1.py\n+++ b/f1.py\n@@ -1,1 +1,1 @@\n" + content_41k +
        "diff --git a/f2.py b/f2.py\n--- a/f2.py\n+++ b/f2.py\n@@ -1,1 +1,1 @@\n" + content_41k +
        "diff --git a/f3.py b/f3.py\n--- a/f3.py\n+++ b/f3.py\n@@ -1,1 +1,1 @@\n" + content_41k
    )
    est = estimate_case_worst_calls(diff_3x41k, variant={"reviewers": 1}, repeats=1)
    assert est == 6

    case = {"id": "c_large", "label": "defect", "diff": diff_3x41k, "defects": []}
    calls_made = 0

    def counting_mock(c, variant=None, **kwargs):
        nonlocal calls_made
        b = kwargs.get("budget_remaining") or (variant or {}).get("_budget_remaining")
        if b is not None and calls_made >= b:
            from bench.runner import BudgetExceeded

            raise BudgetExceeded("Budget exceeded")
        calls_made += 1
        return ReviewResult(verdict="APPROVED", calls=1)

    s1 = run_corpus([case], counting_mock, max_calls=4)
    assert s1["skipped_count"] == 1
    assert s1["calls"] == 0

    from bench.runner import BudgetExceeded

    calls_made = 0
    with pytest.raises(BudgetExceeded):
        for _ in range(10):
            counting_mock(case, budget_remaining=4)
    assert calls_made == 4

    # Mid-case BudgetExceeded captures calls already made in summary totals and budget_remaining
    def mid_review_mock(c, variant=None, **kwargs):
        from bench.runner import BudgetExceeded

        raise BudgetExceeded("Blown mid-case", calls=4, chars_sent=400)

    case_small = {"id": "c_small", "label": "defect", "diff": "diff", "defects": []}
    s2 = run_corpus([case_small], mid_review_mock, max_calls=10)
    assert s2["skipped_count"] == 1
    assert s2["calls"] == 4
    assert s2["chars_sent"] == 400
    assert s2["budget_remaining"] == 6

    # Later repeat raises BudgetExceeded: earlier repeat's calls are preserved
    rep_counter = 0

    def multi_rep_mock(c, variant=None, **kwargs):
        nonlocal rep_counter
        curr = rep_counter
        rep_counter += 1
        if curr == 0:
            return ReviewResult(verdict="APPROVED", calls=2, chars_sent=200)
        from bench.runner import BudgetExceeded

        raise BudgetExceeded("Exceeded on repeat 1", calls=1, chars_sent=100)

    s3 = run_corpus([case_small], multi_rep_mock, repeats=3, max_calls=10)
    assert s3["calls"] == 3  # 2 from repeat 0 + 1 from repeat 1
    assert s3["chars_sent"] == 300
    assert s3["budget_remaining"] == 7  # 10 - 3
def test_compare_exclusions():
    """High 3: no-llm, unlabelled, and skipped cases must not leak into compare."""
    # 1) no-llm defect case does not count as gained
    base = {
        "per_case_rows": [
            {"case_id": "c1", "label": "defect", "verdict": "no-llm", "no_llm": True, "caught_blocking": []}
        ],
        "calls": 0,
    }
    var = {
        "per_case_rows": [
            {"case_id": "c1", "label": "defect", "verdict": "REVISE", "no_llm": False, "caught_blocking": [("c1", "d1")]}
        ],
        "calls": 2,
    }
    res = compare(base, var)
    assert res["gained"] == []

    # 2) unlabelled case marked REVISE does not count as false block
    base2 = {
        "per_case_rows": [
            {"case_id": "u1", "label": "unlabelled", "verdict": "APPROVED", "false_block": False}
        ],
        "calls": 1,
    }
    var2 = {
        "per_case_rows": [
            {"case_id": "u1", "label": "unlabelled", "verdict": "REVISE", "false_block": True}
        ],
        "calls": 1,
    }
    res2 = compare(base2, var2)
    assert res2["new_false_blocks"] == []

    # 3) baseline case skipped for budget does not turn variant catch into gained
    base3 = {
        "per_case_rows": [
            {"case_id": "c2", "label": "defect", "verdict": "skipped (budget)", "skipped": True, "caught_blocking": []}
        ],
        "calls": 0,
    }
    var3 = {
        "per_case_rows": [
            {"case_id": "c2", "label": "defect", "verdict": "REVISE", "skipped": False, "caught_blocking": [("c2", "d2")]}
        ],
        "calls": 2,
    }
    res3 = compare(base3, var3)
    assert res3["gained"] == []


def test_cli_max_calls_required_for_real_runs(tmp_path: Path):
    """High 4: --max-calls is required when not in dry-run mode."""
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    (cases_dir / "c1.json").write_text(json.dumps({"id": "c1", "label": "clean"}), encoding="utf-8")
    rc = main(["run", "--cases", str(cases_dir)])
    assert rc == 2


def test_verdict_enum_value_and_clean_false_block():
    """Medium 5: Verdict enum value stored as string and clean REVISE is false block."""
    from guard.core.llm_reviewer import ReviewVerdict

    case = {"id": "n01", "label": "clean", "defects": []}
    out = case_outcome(case, verdict=ReviewVerdict.REVISE, findings=[])
    assert out["verdict"] == "REVISE"
    assert out["false_block"] is True


def test_variant_validation():
    """Medium 6: Validate reviewers in 1..5."""
    from bench.runner import validate_variant

    with pytest.raises(ValueError, match="reviewers"):
        validate_variant({"reviewers": 0})
    with pytest.raises(ValueError, match="reviewers"):
        validate_variant({"reviewers": 6})
    with pytest.raises(ValueError, match="reviewers"):
        validate_variant({"reviewers": -1})
    with pytest.raises(ValueError, match="reviewers"):
        validate_variant({"reviewers": 1.5})
    with pytest.raises(ValueError, match="reviewers"):
        validate_variant({"reviewers": True})
    with pytest.raises(ValueError, match="reviewers"):
        validate_variant({"reviewers": "1.5"})
    from decimal import Decimal

    with pytest.raises(ValueError, match="reviewers"):
        validate_variant({"reviewers": Decimal("1.5")})
    assert validate_variant({"reviewers": 3})["reviewers"] == 3


def test_cli_missing_files_usage_error(tmp_path: Path):
    """Low 8: Missing files in compare/report exit with code 2."""
    rc1 = main(["compare", str(tmp_path / "no_base.json"), str(tmp_path / "no_var.json")])
    assert rc1 == 2
    rc2 = main(["report", str(tmp_path / "no_res.json")])
    assert rc2 == 2


def test_location_matching_rules():
    """Low 9: Location matching with basename ambiguity, directory suffix, and Windows paths."""
    # Bare events.py with 1 file in diff matches
    defects = [{"id": "d1", "file": "sub/events.py", "keywords": ["leak"]}]
    findings = [{"location": "events.py:10", "description": "leak found", "blocking": True}]
    res1 = match_defects(findings, defects, case_files={"sub/events.py"})
    assert res1["caught"] == ["d1"]

    # Bare events.py with 2 files in diff does NOT match (ambiguous)
    res2 = match_defects(findings, defects, case_files={"sub/events.py", "other/events.py"})
    assert res2["caught"] == []

    # Directory part: must equal or be suffix on / boundary
    findings_dir = [{"location": "sub/events.py:10", "description": "leak found", "blocking": True}]
    res3 = match_defects(findings_dir, defects, case_files={"sub/events.py", "other/events.py"})
    assert res3["caught"] == ["d1"]

    findings_wrong_dir = [{"location": "wrong/events.py:10", "description": "leak found", "blocking": True}]
    res4 = match_defects(findings_wrong_dir, defects, case_files={"sub/events.py", "other/events.py"})
    assert res4["caught"] == []

    # Windows drive path C:\repo\x.py:3 must parse as file C:\repo\x.py
    defects_win = [{"id": "d2", "file": "repo/x.py", "keywords": ["leak"]}]
    findings_win = [{"location": "C:\\repo\\x.py:3", "description": "leak found", "blocking": True}]
    res5 = match_defects(findings_win, defects_win, case_files={"repo/x.py"})
    assert res5["caught"] == ["d2"]


def test_corrupt_case_file_marked_invalid(tmp_path: Path):
    """Low 10: Corrupt case file appears as invalid in result."""
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    (cases_dir / "good.json").write_text(json.dumps({"id": "good", "label": "clean"}), encoding="utf-8")
    (cases_dir / "bad.json").write_text("{corrupt json content...", encoding="utf-8")
    cases = load_cases_from_path(cases_dir)
    assert any(c.get("label") == "invalid" and c.get("id") == "bad" for c in cases)
    s = run_corpus(cases, make_dry_run_review_fn(), repeats=1, max_calls=10)
    assert s["invalid_count"] == 1
    assert any(r.get("label") == "invalid" and r.get("case_id") == "bad" for r in s["per_case_rows"])


def test_real_reviewer_call_llm_path(monkeypatch: pytest.MonkeyPatch):
    """Low 12: Exercise real reviewer's call path with scripted fake at guard.core.llm_reviewer.call_llm."""
    import guard.core.llm_reviewer as reviewer_mod
    from guard.core.config import GuardConfig, LLMConfig, LLMProtocol

    dummy_key = "".join(["m", "o", "c", "k"])
    cfg = GuardConfig(
        llm=LLMConfig(
            protocol=LLMProtocol.OPENAI,
            base_url="https://api.mock.test/v1",
            api_key=dummy_key,
            model="mock-model",
        )
    )
    monkeypatch.setattr("guard.core.config.load_config", lambda *args, **kwargs: cfg)

    call_llm_invoked = False

    def fake_call_llm(*args, **kwargs):
        nonlocal call_llm_invoked
        call_llm_invoked = True
        return "SCORE: 9.0\nVERDICT: APPROVED\nSUMMARY: Passed\nFINDINGS:\nnone\n"

    monkeypatch.setattr(reviewer_mod, "call_llm", fake_call_llm)

    case = {
        "id": "c_real",
        "prompt": "Test prompt",
        "domain": "backend",
        "diff": "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n-old\n+new\n",
    }
    res = default_review_fn(case)
    assert call_llm_invoked is True
    assert res.verdict == "APPROVED"
    assert res.calls == 1
