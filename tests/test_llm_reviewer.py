"""
Unit tests for LLM Reviewer Engine (Final Safety Gate).
"""

import threading

import pytest

from guard.core.invariant_eval import DomainType, InvariantCheck, InvariantResult
from guard.core.llm_reviewer import LLMReviewerEngine, ReviewVerdict
from guard.core.ocr_engine import DiffSummary, FileDiffStat, RuleViolation
from guard.core.session import BuildCheckResult


@pytest.fixture
def reviewer():
    return LLMReviewerEngine(config=None)


def test_reviewer_approve_clean_task(reviewer):
    build_check = BuildCheckResult(
        command="npm run build",
        passed=True,
        exit_code=0,
        output="Build succeeded in 2.1s",
        duration_s=2.1,
    )
    diff = DiffSummary(
        files=[FileDiffStat(path="src/App.tsx", status="modified", insertions=10, deletions=2)],
        total_insertions=10,
        total_deletions=2,
        out_of_scope_files=[],
    )
    inv_res = InvariantResult(
        all_passed=True,
        checks=[InvariantCheck(id="FE-INV-01", description="Keep loading state", passed=True, confidence=0.95)],
        ui_regression_risk=False,
        latency_ms=1.0,
    )

    verdict = reviewer.review(
        prompt="Update heading style in App.tsx",
        domain=DomainType.FRONTEND,
        diff_summary=diff,
        build_check=build_check,
        violations=[],
        invariant_result=inv_res,
        use_llm=False,
    )

    assert verdict.verdict == ReviewVerdict.APPROVED
    assert verdict.score >= 9.0
    assert len(verdict.remediation_steps) == 0


def test_reviewer_reject_on_build_failure(reviewer):
    build_check = BuildCheckResult(
        command="npm run build",
        passed=False,
        exit_code=1,
        output="TS2304: Cannot find name 'unknownVariable'",
        duration_s=1.5,
    )
    verdict = reviewer.review(
        prompt="Add feature",
        domain=DomainType.FRONTEND,
        build_check=build_check,
        use_llm=False,
    )

    assert verdict.verdict == ReviewVerdict.REVISE
    assert verdict.score < 7.5
    assert any("TS2304" in step for step in verdict.remediation_steps)


def test_reviewer_reject_on_critical_secret_and_scope_breach(reviewer):
    diff = DiffSummary(
        files=[FileDiffStat(path="src/Secret.ts", status="modified")],
        out_of_scope_files=["src/Secret.ts"],
    )
    violations = [
        RuleViolation(
            rule_id="SEC-001",
            severity="CRITICAL",
            file_path="src/Secret.ts",
            message="Hardcoded API key detected",
        )
    ]
    verdict = reviewer.review(
        prompt="Update login",
        domain=DomainType.BACKEND,
        diff_summary=diff,
        violations=violations,
        use_llm=False,
    )

    assert verdict.verdict == ReviewVerdict.REVISE
    assert verdict.score <= 5.0
    assert any("SEC-001" in step for step in verdict.remediation_steps)


def test_reviewer_llm_response_parsing(reviewer):
    raw_llm = """
SCORE: 9.2
VERDICT: APPROVED
SUMMARY: Source code is architecturally sound and clean of memory leaks.
FINDINGS: None
TECHNICAL:
* No orphaned listeners
* Build verification passed
ERGONOMICS:
* Responsive UI layout preserved
REMEDIATION:
None
    """
    parsed = reviewer._parse_llm_response(raw_llm)
    assert parsed is not None
    assert parsed.score == 9.2
    assert parsed.verdict == ReviewVerdict.APPROVED
    assert len(parsed.technical_audit) == 2
    assert len(parsed.remediation_steps) == 0
def test_reviewer_reject_on_dead_code_focus(reviewer):
    diff = DiffSummary(
        files=[FileDiffStat(path="temp_draft.py", status="added", insertions=10, deletions=0)],
        raw_diff="diff --git a/temp_draft.py ...",
    )
    violations = [
        RuleViolation(
            rule_id="DEAD-001",
            severity="HIGH",
            file_path="temp_draft.py",
            message="Temporary draft file detected.",
        )
    ]
    # In normal mode without dead-code focus, score is penalized slightly
    normal_verdict = reviewer.review(
        prompt="Add feature",
        domain=DomainType.BACKEND,
        diff_summary=diff,
        violations=violations,
        use_llm=False,
        focus="all",
    )
    assert normal_verdict.score >= 7.5

    # In dead-code focus mode, DEAD-001 is a hard blocker
    focus_verdict = reviewer.review(
        prompt="Add feature",
        domain=DomainType.BACKEND,
        diff_summary=diff,
        violations=violations,
        use_llm=False,
        focus="dead-code",
    )
    assert focus_verdict.verdict == ReviewVerdict.REVISE
    assert focus_verdict.focus_area == "dead-code"
    assert any("DEAD-001" in step for step in focus_verdict.remediation_steps)
def test_reviewer_simplicity_focus_and_net_loc(reviewer):
    # 1. Net negative LOC is reported but never scored (deleting code is not evidence of quality)
    diff_reduced = DiffSummary(
        total_insertions=5,
        total_deletions=50,
        files=[FileDiffStat(path="src/legacy.py", status="modified", insertions=5, deletions=50)],
        raw_diff="diff --git a/src/legacy.py ...",
    )
    verdict_clean = reviewer.review(
        prompt="Delete deprecated code",
        domain=DomainType.BACKEND,
        diff_summary=diff_reduced,
        use_llm=False,
        focus="all",
    )
    assert verdict_clean.verdict == ReviewVerdict.APPROVED
    assert any("Net -45 LOC (informational, not scored)" in note for note in verdict_clean.technical_audit)
    assert verdict_clean.score == 10.0
    assert verdict_clean.review_mode == "heuristic"

    # 2. In simplicity focus mode, LAZY-001 is a hard blocker
    violations = [
        RuleViolation(
            rule_id="LAZY-001",
            severity="HIGH",
            file_path="package.json",
            message="Added redundant dependency is-odd",
        )
    ]
    focus_verdict = reviewer.review(
        prompt="Add helper",
        domain=DomainType.BACKEND,
        diff_summary=diff_reduced,
        violations=violations,
        use_llm=False,
        focus="simplicity",
    )
    assert focus_verdict.verdict == ReviewVerdict.REVISE
    assert focus_verdict.focus_area == "simplicity"
    assert any("LAZY-001" in step for step in focus_verdict.remediation_steps)


def _llm_config():
    from guard.core.config import GuardConfig, LLMConfig
    return GuardConfig(llm=LLMConfig(base_url="http://127.0.0.1:9/v1", api_key="k", model="m"))


def test_unparseable_llm_answer_is_retried_once():
    from unittest.mock import patch

    answers = iter(["I think this looks fine overall.", "SCORE: 8.5\nSUMMARY: ok\nFINDINGS: None"])
    with patch("guard.core.llm_reviewer.call_llm", side_effect=lambda **kw: next(answers)) as llm:
        verdict = LLMReviewerEngine(config=_llm_config()).review(prompt="p", domain=DomainType.BACKEND)
    assert llm.call_count == 2 and verdict.review_mode == "llm_deep" and verdict.score == 8.5
    assert llm.call_args.kwargs["cfg"].timeout is None  # a review waits for the answer, however long


def test_refusal_is_reported_as_such():
    from unittest.mock import patch

    refusal = "Sorry, I can't help you with this request at the moment."
    with patch("guard.core.llm_reviewer.call_llm", return_value=refusal):
        verdict = LLMReviewerEngine(config=_llm_config()).review(prompt="p", domain=DomainType.BACKEND)
    assert verdict.review_mode == "heuristic"
    assert "part 1/1 answer was not a review" in verdict.llm_error and "Sorry" in verdict.llm_error


def test_deleted_files_are_sent_as_a_one_line_note():
    diff = ("diff --git a/old.py b/old.py\ndeleted file mode 100644\n--- a/old.py\n+++ /dev/null\n@@ -1,3 +0,0 @@\n-a\n-b\n-c\n"
            "diff --git a/kept.py b/kept.py\n--- a/kept.py\n+++ b/kept.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n")
    batch = LLMReviewerEngine()._prepare_diff_batches(DiffSummary(raw_diff=diff))[0]
    assert "[file deleted: 3 lines removed; content omitted]" in batch
    assert "-a\n" not in batch and "+x = 2" in batch


@pytest.mark.parametrize("severity, expected", [
    ("HIGH", ReviewVerdict.REVISE),
    ("CRITICAL", ReviewVerdict.REVISE),
    ("MEDIUM", ReviewVerdict.APPROVED),
])
def test_ocr_high_or_critical_finding_blocks(reviewer, severity, expected):
    finding = RuleViolation(rule_id="OCR-BUG", severity=severity, file_path="src/App.tsx", message="race")
    diff = DiffSummary(files=[FileDiffStat(path="src/App.tsx", status="modified", insertions=1)], total_insertions=1)
    verdict = reviewer.review(prompt="Fix src/App.tsx", domain=DomainType.FRONTEND, diff_summary=diff,
                              build_check=None, violations=[finding], invariant_result=None, use_llm=False)
    assert verdict.verdict == expected


def test_diff_text_inside_a_changed_line_does_not_start_a_new_file():
    raw = (
        "diff --git a/tests/test_x.py b/tests/test_x.py\n--- a/tests/test_x.py\n+++ b/tests/test_x.py\n"
        "@@ -1 +1,2 @@\n+SAMPLE = \"\"\"diff --git a/src/Fake.tsx b/src/Fake.tsx\n+diff --git a/src/Other.ts b/src/Other.ts\n"
    )
    batches = LLMReviewerEngine(config=None)._prepare_diff_batches(DiffSummary(raw_diff=raw))
    assert len(batches) == 1 and batches[0] == raw  # one file, its fixture lines left as content


def test_every_piece_of_an_oversized_file_names_the_file(monkeypatch):
    import guard.core.llm_reviewer as reviewer_module
    monkeypatch.setattr(reviewer_module, "REVIEW_BATCH_CHARS", 200)
    raw = "diff --git a/big.py b/big.py\n@@ -0,0 +1,40 @@\n" + "".join(f"+line_{i} = {i}\n" for i in range(40))
    batches = LLMReviewerEngine(config=None)._prepare_diff_batches(DiffSummary(raw_diff=raw))
    assert len(batches) > 1 and all(b.startswith("diff --git a/big.py b/big.py") for b in batches)
    assert all(len(b) <= 200 for b in batches)  # the continuation header counts toward the limit
    prefix = "diff --git a/big.py b/big.py\n[continued: next part of this file's diff]\n"
    assert batches[0] + "".join(b[len(prefix):] for b in batches[1:]) == raw  # nothing lost or repeated


def test_contracts_included_in_llm_prompt():
    from unittest.mock import patch

    from guard.core.session import DomainContract

    contracts = [
        DomainContract(category="API_ENDPOINT", name="GET /api/v1/items", description="Returns all items"),
        DomainContract(category="UI_STATE", name="loading_spinner", description="Visible while fetching items"),
    ]
    captured = {}

    def fake_call(**kwargs):
        captured["kwargs"] = kwargs
        return "SCORE: 8.5\nSUMMARY: ok\nFINDINGS: None"

    with patch("guard.core.llm_reviewer.call_llm", side_effect=fake_call):
        verdict = LLMReviewerEngine(config=_llm_config()).review(
            prompt="Refactor items view",
            domain=DomainType.BACKEND,
            contracts=contracts,
        )

    assert verdict.review_mode == "llm_deep"
    call_kw = captured["kwargs"]
    prompt = call_kw["prompt"]
    full_prompt = prompt + "\n" + call_kw.get("system_prompt", "")

    for c in contracts:
        assert c.category in prompt
        assert c.name in prompt
        assert c.description in prompt
        assert f"- [{c.category}] {c.name}: {c.description}" in prompt

    assert "preserved, changed or removed" in full_prompt


@pytest.mark.parametrize("contracts", [None, []])
def test_contracts_none_or_empty_says_none_recorded(contracts):
    from unittest.mock import patch

    captured = {}

    def fake_call(**kwargs):
        captured["prompt"] = kwargs["prompt"]
        return "SCORE: 8.5\nSUMMARY: ok\nFINDINGS: None"

    with patch("guard.core.llm_reviewer.call_llm", side_effect=fake_call):
        verdict = LLMReviewerEngine(config=_llm_config()).review(
            prompt="Update items",
            domain=DomainType.BACKEND,
            contracts=contracts,
        )

    assert verdict.review_mode == "llm_deep"
    assert "Baseline contracts recorded at guard pre (what callers rely on):" in captured["prompt"]
    assert "- none recorded" in captured["prompt"]
@pytest.mark.parametrize("focus", ["all", "security"])
def test_review_prompt_contains_checklist(focus):
    from unittest.mock import patch

    captured = {}

    def fake_call(**kwargs):
        captured["system_prompt"] = kwargs.get("system_prompt", "")
        captured["prompt"] = kwargs.get("prompt", "")
        return "SCORE: 8.5\nSUMMARY: ok\nFINDINGS: None"

    with patch("guard.core.llm_reviewer.call_llm", side_effect=fake_call):
        LLMReviewerEngine(config=_llm_config()).review(
            prompt="Refactor code",
            domain=DomainType.BACKEND,
            focus=focus,
        )

    full_text = captured["system_prompt"] + "\n" + captured["prompt"]
    assert "Leaks:" in full_text
    assert "Null dereference:" in full_text
    assert "Blocking calls" in full_text
    assert "dead-code" in full_text
    assert "over-engineering" in full_text


def _helper_engine():
    engine = LLMReviewerEngine(config=None)
    engine._task_text = "Refactor the review stage"  # set by _evaluate_with_llm before the panel runs
    return engine


def _panel_text(finding_line=None):
    body = f"- {finding_line}\n" if finding_line else "None\n"
    return f"SCORE: 9.0\nSUMMARY: ok\nFINDINGS:\n{body}"


def test_security_sensitive_diff_activates_threat_frame_in_header():
    from guard.core.llm_reviewer import THREAT_FRAME_INSTRUCTIONS
    from guard.core.review_options import ReviewOptions

    raw = "diff --git a/src/auth/login.py b/src/auth/login.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"
    _, header, threat_active = _helper_engine()._build_review_context(
        "Change login", "backend", "model", "all", ReviewOptions(threat_frame="auto"),
        DiffSummary(raw_diff=raw), None, [], None, None, None, None, None,
    )
    assert threat_active is True
    assert "Security-sensitive surface detected" in header
    assert THREAT_FRAME_INSTRUCTIONS in header


def test_reviewer_panel_below_budget_runs_no_reviewer_and_says_so():
    from guard.core.review_options import ReviewOptions

    calls = []
    # Worst case is 2 reviewers * 2 calls * 1 part = 4, but only 3 calls remain
    verdict, note = _helper_engine()._run_reviewer_panel(
        ReviewOptions(reviewers=2, max_llm_calls=3), ["part"], "header", "system", "all", False,
        lambda s, p: calls.append(p) or "", 0,
    )
    assert verdict is None
    assert note == "Reviewer panel unavailable (budget exceeded); one reviewer ran."
    assert calls == []


def test_reviewer_panel_with_no_usable_lens_falls_back_with_a_note():
    from guard.core.review_options import ReviewOptions

    verdict, note = _helper_engine()._run_reviewer_panel(
        ReviewOptions(reviewers=2), ["part"], "header", "system", "all", False,
        lambda s, p: "unparseable answer without a findings section", 0,
    )
    assert verdict is None
    assert note == "Reviewer panel unavailable (insufficient usable lenses); one reviewer ran."


def test_reviewer_panel_blocking_finding_gives_revise_verdict():
    from guard.core.review_options import ReviewOptions

    line = "high | correctness | src/app.py:7 | - | Off-by-one in the loop bound"
    part = "diff --git a/src/app.py b/src/app.py\n@@ -0,0 +1,10 @@\n" + "+line\n" * 10
    verdict, note = _helper_engine()._run_reviewer_panel(
        ReviewOptions(reviewers=2), [part], "header", "system", "all", False,
        lambda s, p: _panel_text(line), 0,
    )
    assert note is None
    assert verdict.verdict == ReviewVerdict.REVISE and verdict.score == 6.0
    assert verdict.reviewer_model == "Panel (2 lenses)" and verdict.review_mode == "llm_deep"
    assert any("src/app.py:7" in step for step in verdict.remediation_steps)


@pytest.mark.parametrize("still_blocking, expected", [(False, ReviewVerdict.APPROVED), (True, ReviewVerdict.REVISE)])
def test_validation_verdict_follows_the_findings_that_still_block(still_blocking, expected):
    from guard.core.findings import Finding
    from guard.core.llm_reviewer import LLMReviewVerdict

    original = Finding(id="f1", severity="high", kind="correctness", location="a.py:1",
                       description="Bug", blocking=True)
    merged = LLMReviewVerdict(verdict=ReviewVerdict.REVISE, score=6.0, summary="s",
                              remediation_steps=["stale step"])
    LLMReviewerEngine._apply_validation_verdict(merged, [original.model_copy(update={"blocking": still_blocking})])
    assert merged.verdict == expected
    if still_blocking:
        assert merged.remediation_steps == ["[f1] a.py:1: Bug"]
    else:
        assert merged.score == 8.0 and merged.remediation_steps == []


def test_finding_rejected_by_validation_is_demoted_and_logged(monkeypatch):
    from guard.core.findings import Finding
    from guard.core.llm_reviewer import LLMReviewVerdict
    from guard.core.review_options import ReviewOptions

    finding = Finding(id="f1", severity="high", kind="correctness", location="a.py:1",
                      description="Bug", blocking=True)
    merged = LLMReviewVerdict(verdict=ReviewVerdict.REVISE, score=6.0, summary="s", findings=[finding])
    demoted = finding.model_copy(update={"blocking": False})
    validation = type("V", (), {"finding_id": "f1", "verdict": "refuted", "evidence_verified": True,
                                "reason": "r"})()
    monkeypatch.setattr("guard.core.llm_reviewer.validate_findings", lambda **kw: ([demoted], [validation]))
    records, note = _helper_engine()._validate_blocking_findings(
        merged, "diff", "task", ReviewOptions(validate_findings=True), True, 1,
        lambda s, p: "", threading.Lock(), threading.Event(),
    )
    assert note is None
    assert records == [{"finding_id": "f1", "verdict": "refuted", "evidence_verified": True, "reason": "r"}]
    assert merged.verdict == ReviewVerdict.APPROVED and merged.findings == [demoted]


def test_validation_skipped_over_budget_leaves_findings_untouched(monkeypatch):
    from guard.core.findings import Finding
    from guard.core.llm_reviewer import LLMReviewVerdict
    from guard.core.review_options import ReviewOptions

    finding = Finding(id="f1", severity="high", kind="correctness", location="a.py:1",
                      description="Bug", blocking=True)
    merged = LLMReviewVerdict(verdict=ReviewVerdict.REVISE, score=6.0, summary="s", findings=[finding])
    called = []
    monkeypatch.setattr("guard.core.llm_reviewer.validate_findings", lambda **kw: called.append(kw))
    records, note = _helper_engine()._validate_blocking_findings(
        merged, "diff", "task", ReviewOptions(validate_findings=True, max_llm_calls=3), True, 3,
        lambda s, p: "", threading.Lock(), threading.Event(),
    )
    assert records == [] and note == "Finding validation skipped (budget exceeded)."
    assert called == [] and merged.findings == [finding]


def test_coverage_notes_are_empty_when_off_and_partition_gaps_then_notes_when_on():
    from guard.core.diff_partition import DiffPartition
    from guard.core.llm_reviewer import LLMReviewVerdict
    from guard.core.review_coverage import build_coverage_notes
    from guard.core.review_options import ReviewOptions

    partition = DiffPartition(parts=["a"], skipped_files=["big.bin"], omitted_deleted=[], cut_parts=0,
                              files_per_part=[["a"]])
    merged = LLMReviewVerdict(verdict=ReviewVerdict.APPROVED, score=8.5, summary="s")

    LLMReviewerEngine._set_coverage_notes(merged, ReviewOptions(coverage_notes=False), partition, [], ["x"])
    assert merged.coverage_notes == []

    LLMReviewerEngine._set_coverage_notes(merged, ReviewOptions(coverage_notes=True), partition, [], ["panel note"])
    gaps = build_coverage_notes(partition, [])
    assert gaps and merged.coverage_notes == gaps + ["panel note"]
