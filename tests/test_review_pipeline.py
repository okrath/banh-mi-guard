"""
Tests for LLM review pipeline integration (Task I1).
Validates diff partitioning, header additions, findings parser hardening,
threat frame, ensemble panel, finding validation, budget caps, and coverage notes.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys

import pytest

from guard.core.config import GuardConfig, LLMConfig
from guard.core.diff_partition import REVIEW_BATCH_CHARS, REVIEW_MAX_BATCHES
from guard.core.findings import parse_findings
from guard.core.llm_reviewer import LLMReviewerEngine, ReviewVerdict
from guard.core.ocr_engine import DiffSummary
from guard.core.review_options import ReviewOptions

# ---------------------------------------------------------------------------
# Helper: Load old LLMReviewerEngine from pinned commit 7f67d12
# ---------------------------------------------------------------------------


def _load_old_reviewer_from_pinned(monkeypatch: pytest.MonkeyPatch):
    """Load LLMReviewerEngine from the pinned commit 7f67d12."""
    check = subprocess.run(
        ["git", "cat-file", "-e", "7f67d12"],
        capture_output=True,
    )
    if check.returncode != 0:
        pytest.skip("commit 7f67d12 not found in git")

    out = subprocess.check_output(
        ["git", "show", "7f67d12:guard/core/llm_reviewer.py"],
        text=True,
    )
    spec = importlib.util.spec_from_loader("old_llm_reviewer_pinned", loader=None)
    if spec is None:
        pytest.skip("failed to create module spec for old reviewer")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "old_llm_reviewer_pinned", mod)
    exec(out, mod.__dict__)
    mod.LLMReviewVerdict.model_rebuild()
    return mod


def _make_config() -> GuardConfig:
    cfg = GuardConfig()
    cfg.llm = LLMConfig(api_key="k", model="mock-model", base_url="https://mock.llm")
    return cfg


# ---------------------------------------------------------------------------
# 1. Import Direction & Constants
# ---------------------------------------------------------------------------


def test_import_direction_and_constants():
    """Import direction is llm_reviewer -> diff_partition only; both import in fresh interpreters."""
    cmd1 = [sys.executable, "-c", "import guard.core.diff_partition; print('ok')"]
    res1 = subprocess.run(cmd1, capture_output=True, text=True)
    assert res1.returncode == 0
    assert "ok" in res1.stdout

    cmd2 = [sys.executable, "-c", "import guard.core.llm_reviewer; print('ok')"]
    res2 = subprocess.run(cmd2, capture_output=True, text=True)
    assert res2.returncode == 0
    assert "ok" in res2.stdout

    assert REVIEW_BATCH_CHARS == 80000
    assert REVIEW_MAX_BATCHES == 6


# ---------------------------------------------------------------------------
# 2. Equality with pinned commit (7f67d12) for defaults
# ---------------------------------------------------------------------------


def test_equality_with_pinned_commit_on_single_part_diff(monkeypatch: pytest.MonkeyPatch):
    """With defaults, prompts, findings, verdict, and score are identical to commit 7f67d12."""
    old_mod = _load_old_reviewer_from_pinned(monkeypatch)
    old_engine = old_mod.LLMReviewerEngine(config=_make_config())
    new_engine = LLMReviewerEngine(config=_make_config())

    diff_text = (
        "diff --git a/src/math.py b/src/math.py\n"
        "--- a/src/math.py\n"
        "+++ b/src/math.py\n"
        "@@ -1,3 +1,3 @@\n"
        "-def add(a, b): return 0\n"
        "+def add(a, b): return a + b\n"
    )
    diff_summary = DiffSummary(raw_diff=diff_text)
    task_prompt = "Fix addition logic"

    mock_llm_response = (
        "SCORE: 9.5\n"
        "SUMMARY: Clean fix for addition logic.\n"
        "FINDINGS:\n"
        "None\n"
        "TECHNICAL:\n"
        "- Math implementation is correct\n"
        "ERGONOMICS:\n"
        "- Clean signature\n"
    )

    old_prompts: list[dict[str, str]] = []

    def mock_old_call_llm(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, kwargs
        old_prompts.append({"prompt": prompt, "system_prompt": system_prompt})
        return mock_llm_response

    new_prompts: list[dict[str, str]] = []

    def mock_new_call_llm(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, kwargs
        new_prompts.append({"prompt": prompt, "system_prompt": system_prompt})
        return mock_llm_response

    monkeypatch.setattr(old_mod, "call_llm", mock_old_call_llm)
    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", mock_new_call_llm)

    old_verdict = old_engine.review(prompt=task_prompt, domain="backend", diff_summary=diff_summary)
    new_verdict = new_engine.review(prompt=task_prompt, domain="backend", diff_summary=diff_summary, options=None)

    assert len(old_prompts) == 1
    assert len(new_prompts) == 1
    assert new_prompts[0]["system_prompt"] == old_prompts[0]["system_prompt"]
    assert new_prompts[0]["prompt"] == old_prompts[0]["prompt"]

    assert new_verdict.verdict == old_verdict.verdict
    assert new_verdict.score == old_verdict.score
    assert new_verdict.summary == old_verdict.summary
    assert new_verdict.findings == old_verdict.findings
    assert new_verdict.technical_audit == old_verdict.technical_audit
    assert new_verdict.llm_calls == 1
    assert new_verdict.llm_chars > 0


def test_equality_with_pinned_commit_on_multipart_diff(monkeypatch: pytest.MonkeyPatch):
    """Multi-part diff with default options sends identical prompts per part as 7f67d12."""
    old_mod = _load_old_reviewer_from_pinned(monkeypatch)
    old_engine = old_mod.LLMReviewerEngine(config=_make_config())
    new_engine = LLMReviewerEngine(config=_make_config())

    chunk1 = "diff --git a/src/a.py b/src/a.py\n@@ -0,0 +1,100 @@\n" + ("+x = 1\n" * 50000)
    chunk2 = "diff --git a/src/b.py b/src/b.py\n@@ -0,0 +1,100 @@\n" + ("+y = 2\n" * 50000)
    diff_text = chunk1 + chunk2
    diff_summary = DiffSummary(raw_diff=diff_text)
    task_prompt = "Refactor modules a and b"

    mock_llm_response = (
        "SCORE: 8.5\n"
        "SUMMARY: Part reviewed successfully.\n"
        "FINDINGS:\n"
        "None\n"
        "TECHNICAL:\n"
        "- Well-isolated parts\n"
    )

    old_prompts: list[dict[str, str]] = []
    new_prompts: list[dict[str, str]] = []

    def mock_old_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, kwargs
        old_prompts.append({"prompt": prompt, "system_prompt": system_prompt})
        return mock_llm_response

    def mock_new_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, kwargs
        new_prompts.append({"prompt": prompt, "system_prompt": system_prompt})
        return mock_llm_response

    monkeypatch.setattr(old_mod, "call_llm", mock_old_call)
    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", mock_new_call)

    old_verdict = old_engine.review(prompt=task_prompt, domain="backend", diff_summary=diff_summary)
    new_verdict = new_engine.review(prompt=task_prompt, domain="backend", diff_summary=diff_summary, options=ReviewOptions())

    assert len(old_prompts) == len(new_prompts) > 1
    for i in range(2):
        assert new_prompts[i]["system_prompt"] == old_prompts[i]["system_prompt"]
        assert new_prompts[i]["prompt"] == old_prompts[i]["prompt"]

    assert new_verdict.verdict == old_verdict.verdict
    assert new_verdict.score == old_verdict.score
    assert len(new_verdict.findings) == len(old_verdict.findings)


# ---------------------------------------------------------------------------
# 3. Header Additions: part_manifest, test_evidence, test_checklist, threat_frame
# ---------------------------------------------------------------------------


def test_part_manifest_option(monkeypatch: pytest.MonkeyPatch):
    """Manifest is present only when options.part_manifest=True AND diff has multiple parts."""
    engine = LLMReviewerEngine(config=_make_config())

    chunk1 = "diff --git a/src/a.py b/src/a.py\n@@ -0,0 +1,10 @@\n" + ("+x = 1\n" * 50000)
    chunk2 = "diff --git a/src/b.py b/src/b.py\n@@ -0,0 +1,10 @@\n" + ("+y = 2\n" * 50000)
    multipart_diff = chunk1 + chunk2

    prompts_captured: list[str] = []

    def mock_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, system_prompt, kwargs
        prompts_captured.append(prompt)
        return "SCORE: 9.0\nSUMMARY: ok\nFINDINGS:\nNone\n"

    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", mock_call)

    # 1. Multi-part with part_manifest=False
    prompts_captured.clear()
    engine.review(
        prompt="Multi-part", domain="backend", diff_summary=DiffSummary(raw_diff=multipart_diff),
        options=ReviewOptions(part_manifest=False),
    )
    assert not any("Other parts of this same diff" in p for p in prompts_captured)

    # 2. Multi-part with part_manifest=True
    prompts_captured.clear()
    engine.review(
        prompt="Multi-part", domain="backend", diff_summary=DiffSummary(raw_diff=multipart_diff),
        options=ReviewOptions(part_manifest=True),
    )
    assert any("Other parts of this same diff" in p for p in prompts_captured)

    # 3. Single-part with part_manifest=True -> manifest must NOT appear
    prompts_captured.clear()
    single_diff = "diff --git a/src/a.py b/src/a.py\n@@ -1 +1 @@\n-a\n+b\n"
    engine.review(
        prompt="Single-part", domain="backend", diff_summary=DiffSummary(raw_diff=single_diff),
        options=ReviewOptions(part_manifest=True),
    )
    assert not any("Other parts of this same diff" in p for p in prompts_captured)


def test_test_evidence_option(monkeypatch: pytest.MonkeyPatch):
    """test_evidence_lines appended to evidence list only when options.test_evidence=True."""
    engine = LLMReviewerEngine(config=_make_config())
    test_diff = (
        "diff --git a/tests/test_foo.py b/tests/test_foo.py\n"
        "--- a/tests/test_foo.py\n"
        "+++ b/tests/test_foo.py\n"
        "@@ -1,2 +1,3 @@\n"
        " def test_existing():\n"
        "+    sys.path.insert(0, '/tmp')\n"
        "     pass\n"
    )
    prompts_captured: list[str] = []

    def mock_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, system_prompt, kwargs
        prompts_captured.append(prompt)
        return "SCORE: 9.0\nSUMMARY: ok\nFINDINGS:\nNone\n"

    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", mock_call)

    # Off by default
    prompts_captured.clear()
    engine.review(
        prompt="Test change", domain="backend", diff_summary=DiffSummary(raw_diff=test_diff),
        options=ReviewOptions(test_evidence=False),
    )
    assert not any("added global state mutation" in p for p in prompts_captured)

    # On
    prompts_captured.clear()
    engine.review(
        prompt="Test change", domain="backend", diff_summary=DiffSummary(raw_diff=test_diff),
        options=ReviewOptions(test_evidence=True),
    )
    assert any("added global state mutation" in p for p in prompts_captured)


def test_test_checklist_option(monkeypatch: pytest.MonkeyPatch):
    """TEST_QUALITY_CHECKLIST appended to system prompt only when options.test_checklist=True."""
    engine = LLMReviewerEngine(config=_make_config())
    diff = "diff --git a/a.py b/a.py\n@@ -1 +1 @@\n-x\n+y\n"
    system_prompts: list[str] = []

    def mock_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, prompt, kwargs
        system_prompts.append(system_prompt)
        return "SCORE: 9.0\nSUMMARY: ok\nFINDINGS:\nNone\n"

    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", mock_call)

    # Off
    system_prompts.clear()
    engine.review(
        prompt="Checklist test", domain="backend", diff_summary=DiffSummary(raw_diff=diff),
        options=ReviewOptions(test_checklist=False),
    )
    assert not any("TEST QUALITY CHECKLIST:" in sp for sp in system_prompts)

    # On
    system_prompts.clear()
    engine.review(
        prompt="Checklist test", domain="backend", diff_summary=DiffSummary(raw_diff=diff),
        options=ReviewOptions(test_checklist=True),
    )
    assert any("TEST QUALITY CHECKLIST:" in sp for sp in system_prompts)


def test_threat_frame_option(monkeypatch: pytest.MonkeyPatch):
    """Threat frame appears in prompt only when options.threat_frame='auto' and diff is sensitive."""
    engine = LLMReviewerEngine(config=_make_config())

    sensitive_diff = (
        "diff --git a/guard/auth.py b/guard/auth.py\n"
        "--- a/guard/auth.py\n"
        "+++ b/guard/auth.py\n"
        "@@ -1 +1 @@\n"
        "+import subprocess\n"
    )
    benign_diff = (
        "diff --git a/README.md b/README.md\n"
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1 +1 @@\n"
        "+# Hello\n"
    )

    prompts_captured: list[str] = []

    def mock_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, system_prompt, kwargs
        prompts_captured.append(prompt)
        return "SCORE: 9.0\nSUMMARY: ok\nFINDINGS:\nNone\n"

    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", mock_call)

    # 1. Sensitive diff but threat_frame="off"
    prompts_captured.clear()
    engine.review(
        prompt="Auth fix", domain="backend", diff_summary=DiffSummary(raw_diff=sensitive_diff),
        options=ReviewOptions(threat_frame="off"),
    )
    assert not any("SECURITY REVIEW FRAME:" in p for p in prompts_captured)
    assert not any("Security-sensitive surface detected:" in p for p in prompts_captured)

    # 2. Sensitive diff with threat_frame="auto"
    prompts_captured.clear()
    engine.review(
        prompt="Auth fix", domain="backend", diff_summary=DiffSummary(raw_diff=sensitive_diff),
        options=ReviewOptions(threat_frame="auto"),
    )
    assert any("SECURITY REVIEW FRAME:" in p for p in prompts_captured)
    assert any("Security-sensitive surface detected:" in p for p in prompts_captured)

    # 3. Benign diff with threat_frame="auto" (not sensitive)
    prompts_captured.clear()
    engine.review(
        prompt="Docs update", domain="backend", diff_summary=DiffSummary(raw_diff=benign_diff),
        options=ReviewOptions(threat_frame="auto"),
    )
    assert not any("SECURITY REVIEW FRAME:" in p for p in prompts_captured)
    assert not any("Security-sensitive surface detected:" in p for p in prompts_captured)


# ---------------------------------------------------------------------------
# 4. Answer Parsing: Threat sections tolerance & anchoring
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "layout",
    [
        "after_findings",
        "before_findings",
        "between_summary_and_findings",
        "markdown_wrapped",
    ],
)
def test_threat_sections_parsing_all_layouts(layout: str):
    """parse_findings and _parse_llm_response parse findings identically in all threat section layouts."""
    finding_line = "high | security | src/auth.py:42 | - | Token leakage vulnerability"
    threat_text = (
        "THREATMODEL:\n"
        "- Assets: token store\n"
        "- Entry points: /auth/login\n"
        "UNREVIEWED:\n"
        "- database connection timeout\n"
    )

    if layout == "after_findings":
        text = f"SCORE: 5.0\nSUMMARY: Security audit\nFINDINGS:\n- {finding_line}\nTECHNICAL:\n- Token checked\n{threat_text}"
    elif layout == "before_findings":
        text = f"SCORE: 5.0\nSUMMARY: Security audit\n{threat_text}\nFINDINGS:\n- {finding_line}\nTECHNICAL:\n- Token checked\n"
    elif layout == "between_summary_and_findings":
        text = f"SCORE: 5.0\nSUMMARY: Security audit\n{threat_text}\nFINDINGS:\n- {finding_line}\n"
    elif layout == "markdown_wrapped":
        text = (
            f"SCORE: 5.0\nSUMMARY: Security audit\nFINDINGS:\n- {finding_line}\n\n"
            "**THREATMODEL:**\n- Assets: token store\n**UNREVIEWED:**\n- database connection timeout\n"
        )
    else:
        raise ValueError(layout)

    findings = parse_findings(text, "Task prompt")
    assert findings is not None
    assert len(findings) == 1
    assert findings[0].location == "src/auth.py:42"

    engine = LLMReviewerEngine()
    verdict = engine._parse_llm_response(text)
    assert verdict is not None
    assert verdict.verdict == ReviewVerdict.REVISE
    assert len(verdict.findings) == 1
    assert any("Threat model:" in t for t in verdict.technical_audit)


def test_findings_parser_anchoring_and_ambiguity():
    """FINDINGS block is anchored; inline FINDINGS in threat model does not hijack; duplicate header returns None."""
    # 1. Inline FINDINGS: None inside a THREATMODEL bullet does not hijack
    text_with_inline = (
        "SCORE: 9.0\n"
        "SUMMARY: Clean audit\n"
        "FINDINGS:\n"
        "- high | security | src/key.py:10 | - | Insecure key exchange\n"
        "THREATMODEL:\n"
        "- Note on audit: FINDINGS: None found on boundary\n"
        "UNREVIEWED:\n"
        "- session timeout\n"
    )
    f1 = parse_findings(text_with_inline, "")
    assert f1 is not None
    assert len(f1) == 1
    assert f1[0].location == "src/key.py:10"

    # 2. Second header line starting with FINDINGS: is ambiguous -> fails closed (None)
    text_ambiguous = (
        "SCORE: 9.0\n"
        "SUMMARY: Clean audit\n"
        "FINDINGS:\n"
        "- high | security | src/key.py:10 | - | First bug\n"
        "FINDINGS:\n"
        "- low | style | src/key.py:20 | - | Second bug\n"
    )
    f2 = parse_findings(text_ambiguous, "")
    assert f2 is None


# ---------------------------------------------------------------------------
# 5. Ensemble Panel (Opt-In)
# ---------------------------------------------------------------------------


def test_ensemble_panel_union_of_lenses(monkeypatch: pytest.MonkeyPatch):
    """Ensemble merges distinct findings from multiple lenses into union."""
    engine = LLMReviewerEngine(config=_make_config())
    diff = "diff --git a/src/app.py b/src/app.py\n@@ -10,3 +10,3 @@\n-x = 1\n+x = 2\n"

    # Lens 1 (correctness) finds Bug A, Lens 2 (requirements) finds Bug B
    call_count = 0

    def mock_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, prompt, kwargs
        nonlocal call_count
        call_count += 1
        if "Requirements" in system_prompt:
            return (
                "SCORE: 6.0\nSUMMARY: reqs issue\nFINDINGS:\n"
                "- high | requirement | src/app.py:10 | 'must support y' | Missing y requirement\n"
            )
        return (
            "SCORE: 5.0\nSUMMARY: correctness issue\nFINDINGS:\n"
            "- high | correctness | src/app.py:10 | - | Null pointer exception\n"
        )

    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", mock_call)

    verdict = engine.review(
        prompt="Fix app.py, must support y",
        domain="backend",
        diff_summary=DiffSummary(raw_diff=diff),
        options=ReviewOptions(reviewers=2),
    )

    assert verdict.verdict == ReviewVerdict.REVISE
    # Both lenses ran and contributed findings
    assert len(verdict.findings) == 2
    kinds = {f.kind for f in verdict.findings}
    assert "correctness" in kinds
    assert "requirement" in kinds
    assert verdict.llm_calls == 2


def test_ensemble_panel_budget_exceeded_skips_with_coverage_note(monkeypatch: pytest.MonkeyPatch):
    """When panel worst-case exceeds max_llm_calls, panel skips and single reviewer runs."""
    engine = LLMReviewerEngine(config=_make_config())
    diff = "diff --git a/src/app.py b/src/app.py\n@@ -1 +1 @@\n-a\n+b\n"

    single_ran = False

    def mock_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, prompt, system_prompt, kwargs
        nonlocal single_ran
        single_ran = True
        return "SCORE: 9.0\nSUMMARY: single reviewer ok\nFINDINGS:\nNone\n"

    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", mock_call)

    # 3 reviewers * 1 part * 2 worst case = 6 calls needed. Budget is 2.
    verdict = engine.review(
        prompt="App fix",
        domain="backend",
        diff_summary=DiffSummary(raw_diff=diff),
        options=ReviewOptions(reviewers=3, max_llm_calls=2),
    )

    assert single_ran is True
    assert verdict.verdict == ReviewVerdict.APPROVED
    assert any("Reviewer panel unavailable (budget exceeded); one reviewer ran." in note for note in verdict.coverage_notes)


def test_ensemble_panel_none_fallback_with_coverage_note(monkeypatch: pytest.MonkeyPatch):
    """When run_ensemble returns None (e.g. timeout or unparseable), fall back to single reviewer."""
    engine = LLMReviewerEngine(config=_make_config())
    diff = "diff --git a/src/app.py b/src/app.py\n@@ -1 +1 @@\n-a\n+b\n"

    # Make run_ensemble return None
    monkeypatch.setattr("guard.core.llm_reviewer.run_ensemble", lambda **kwargs: None)

    def mock_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, prompt, system_prompt, kwargs
        return "SCORE: 9.0\nSUMMARY: single reviewer fallback\nFINDINGS:\nNone\n"

    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", mock_call)

    verdict = engine.review(
        prompt="App fix",
        domain="backend",
        diff_summary=DiffSummary(raw_diff=diff),
        options=ReviewOptions(reviewers=2),
    )

    assert verdict.verdict == ReviewVerdict.APPROVED
    assert any("Reviewer panel unavailable" in note for note in verdict.coverage_notes)
    assert any("one reviewer ran." in note for note in verdict.coverage_notes)


# ---------------------------------------------------------------------------
# 6. Finding Validation (Opt-In)
# ---------------------------------------------------------------------------


def test_validation_docs_move_scenario_flips_revise_to_approved(monkeypatch: pytest.MonkeyPatch):
    """Docs-move scenario: README removal refuted by cross-part docs addition, flipping REVISE to APPROVED."""
    engine = LLMReviewerEngine(config=_make_config())

    chunk1 = "diff --git a/README.md b/README.md\n@@ -10,5 +10,0 @@\n-CLI Reference documentation\n-Use --help for details\n"
    chunk2 = "diff --git a/docs/cli.md b/docs/cli.md\n@@ -0,0 +1,5 @@\n+CLI Reference documentation\n+Use --help for details\n"
    diff_text = chunk1 + chunk2
    diff_summary = DiffSummary(raw_diff=diff_text)

    # Monkeypatch REVIEW_BATCH_CHARS to force 2 parts
    monkeypatch.setattr("guard.core.llm_reviewer.REVIEW_BATCH_CHARS", len(chunk1) + 10)

    # Review calls: Part 1 raises blocking correctness finding. Part 2 passes.
    # Validation call: refutes Part 1 finding with verbatim evidence line from Part 2.
    def mock_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, kwargs
        # Validation call uses VALIDATION_SYSTEM_PROMPT
        if "code review validator" in system_prompt.lower():
            return (
                "VERDICT: refuted\n"
                "EVIDENCE: CLI Reference documentation\n"
                "REASON: The CLI documentation was moved to docs/cli.md\n"
            )
        if "README.md" in prompt:
            return (
                "SCORE: 4.0\nSUMMARY: Documentation removed\nFINDINGS:\n"
                "- high | correctness | README.md:10 | - | CLI Reference was deleted\n"
            )
        return "SCORE: 9.0\nSUMMARY: Part 2 ok\nFINDINGS:\nNone\n"

    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", mock_call)

    verdict = engine.review(
        prompt="Move CLI docs to docs/cli.md",
        domain="backend",
        diff_summary=diff_summary,
        options=ReviewOptions(validate_findings=True),
    )

    # The finding was demoted because the quote is verified in docs/cli.md
    assert verdict.verdict == ReviewVerdict.APPROVED
    assert len(verdict.validation_log) == 1
    log_entry = verdict.validation_log[0]
    assert log_entry["verdict"] == "refuted"
    assert log_entry["evidence_verified"] is True
    assert "[contested:" in verdict.findings[0].description


def test_validation_fabricated_quote_leaves_revise(monkeypatch: pytest.MonkeyPatch):
    """Fabricated evidence quote fails verification and leaves verdict as REVISE."""
    engine = LLMReviewerEngine(config=_make_config())

    chunk1 = "diff --git a/README.md b/README.md\n@@ -10,3 +10,0 @@\n-Real removal\n"
    chunk2 = "diff --git a/docs/cli.md b/docs/cli.md\n@@ -0,0 +1,3 @@\n+Some other content\n"
    diff_summary = DiffSummary(raw_diff=chunk1 + chunk2)

    monkeypatch.setattr("guard.core.llm_reviewer.REVIEW_BATCH_CHARS", len(chunk1) + 10)

    def mock_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, kwargs
        if "code review validator" in system_prompt.lower():
            return (
                "VERDICT: refuted\n"
                "EVIDENCE: This quote does not exist in any file in the diff\n"
                "REASON: Disproven\n"
            )
        if "README.md" in prompt:
            return (
                "SCORE: 4.0\nSUMMARY: Real removal\nFINDINGS:\n"
                "- high | correctness | README.md:10 | - | Real removal\n"
            )
        return "SCORE: 9.0\nSUMMARY: Part 2 ok\nFINDINGS:\nNone\n"

    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", mock_call)

    verdict = engine.review(
        prompt="Task", domain="backend", diff_summary=diff_summary,
        options=ReviewOptions(validate_findings=True),
    )

    assert verdict.verdict == ReviewVerdict.REVISE
    assert len(verdict.validation_log) == 1
    assert verdict.validation_log[0]["evidence_verified"] is False
    assert verdict.findings[0].blocking is True


def test_validation_raising_call_leaves_revise(monkeypatch: pytest.MonkeyPatch):
    """A raising call in validation fails safe: verdict and findings remain unchanged."""
    engine = LLMReviewerEngine(config=_make_config())

    chunk1 = "diff --git a/README.md b/README.md\n@@ -10,3 +10,0 @@\n-Real removal\n"
    chunk2 = "diff --git a/docs/cli.md b/docs/cli.md\n@@ -0,0 +1,3 @@\n+Some other content\n"
    diff_summary = DiffSummary(raw_diff=chunk1 + chunk2)

    monkeypatch.setattr("guard.core.llm_reviewer.REVIEW_BATCH_CHARS", len(chunk1) + 10)

    def mock_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, kwargs
        if "code review validator" in system_prompt.lower():
            raise RuntimeError("API network failure during validation")
        if "README.md" in prompt:
            return (
                "SCORE: 4.0\nSUMMARY: Bug\nFINDINGS:\n"
                "- high | correctness | README.md:10 | - | Bug description\n"
            )
        return "SCORE: 9.0\nSUMMARY: ok\nFINDINGS:\nNone\n"

    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", mock_call)

    verdict = engine.review(
        prompt="Task", domain="backend", diff_summary=diff_summary,
        options=ReviewOptions(validate_findings=True),
    )

    assert verdict.verdict == ReviewVerdict.REVISE
    assert verdict.findings[0].blocking is True


def test_validation_single_part_diff_makes_no_validation_call(monkeypatch: pytest.MonkeyPatch):
    """Single-part diff makes no validation calls even when options.validate_findings=True."""
    engine = LLMReviewerEngine(config=_make_config())
    diff = "diff --git a/src/a.py b/src/a.py\n@@ -1 +1 @@\n-x\n+y\n"

    val_calls = 0

    def mock_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, prompt, kwargs
        nonlocal val_calls
        if "code review validator" in system_prompt.lower():
            val_calls += 1
            return "VERDICT: refuted\nEVIDENCE: y\nREASON: ok\n"
        return (
            "SCORE: 4.0\nSUMMARY: Bug\nFINDINGS:\n"
            "- high | correctness | src/a.py:1 | - | Single part bug\n"
        )

    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", mock_call)

    verdict = engine.review(
        prompt="Task", domain="backend", diff_summary=DiffSummary(raw_diff=diff),
        options=ReviewOptions(validate_findings=True),
    )

    assert val_calls == 0
    assert verdict.verdict == ReviewVerdict.REVISE
    assert len(verdict.validation_log) == 0


# ---------------------------------------------------------------------------
# 7. Budget Caps & Exact Counters
# ---------------------------------------------------------------------------


def test_call_budget_and_exact_counters(monkeypatch: pytest.MonkeyPatch):
    """llm_calls and llm_chars accurately track all calls and retry attempts."""
    engine = LLMReviewerEngine(config=_make_config())
    diff = "diff --git a/src/a.py b/src/a.py\n@@ -1 +1 @@\n-x\n+y\n"

    call_count = 0
    total_chars = 0

    def mock_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, kwargs
        nonlocal call_count, total_chars
        call_count += 1
        total_chars += len(prompt) + len(system_prompt or "")
        if call_count == 1:
            # First attempt returns unparseable answer to trigger retry
            return "I am an unformatted response."
        return "SCORE: 8.0\nSUMMARY: Retried review\nFINDINGS:\nNone\n"

    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", mock_call)

    verdict = engine.review(
        prompt="Task", domain="backend", diff_summary=DiffSummary(raw_diff=diff),
        options=ReviewOptions(),
    )

    assert verdict.verdict == ReviewVerdict.APPROVED
    assert call_count == 2
    assert verdict.llm_calls == 2
    assert verdict.llm_chars == total_chars


# ---------------------------------------------------------------------------
# 8. Contested Ledger Entry Rendering
# ---------------------------------------------------------------------------


def test_contested_ledger_entry_rendering():
    """Ledger entry containing [contested: is rendered as contested with instruction to re-check."""
    normal_entry = {
        "id": "11111111",
        "round": 1,
        "status": "open",
        "severity": "high",
        "kind": "correctness",
        "location": "src/a.py:10",
        "description": "Unchecked error return",
    }
    contested_entry = {
        "id": "22222222",
        "round": 1,
        "status": "open",
        "severity": "high",
        "kind": "correctness",
        "location": "README.md:1",
        "description": 'Content removed [contested: validation refuted this finding - evidence: "+CLI doc"]',
    }

    header = LLMReviewerEngine._build_review_header(
        prompt="Task",
        domain_str="backend",
        focus="all",
        diff_summary=None,
        build_check=None,
        violations=[],
        invariant_result=None,
        contracts=[],
        evidence=[],
        ledger=[normal_entry, contested_entry],
        known_rules=[],
    )

    # Normal entry has standard status
    assert "- [11111111] round 1, open: high correctness src/a.py:10: Unchecked error return" in header

    # Contested entry has contested status
    expected_contested = (
        "- [22222222] round 1, contested (a validation step disputed it; re-check it against the current diff): "
        'high correctness README.md:1: Content removed [contested: validation refuted this finding - evidence: "+CLI doc"]'
    )
    assert expected_contested in header
    assert "does NOT apply to contested entries" in header

# ---------------------------------------------------------------------------
# 9. Full Multi-Stage Deterministic Run
# ---------------------------------------------------------------------------


def test_full_multistage_deterministic_run(monkeypatch: pytest.MonkeyPatch):
    """Full run with panel (2 reviewers), validation, threat frame, test checklist, and evidence."""
    engine = LLMReviewerEngine(config=_make_config())

    chunk1 = (
        "diff --git a/guard/auth.py b/guard/auth.py\n"
        "@@ -10,5 +10,0 @@\n"
        "-def verify_token(): pass\n"
    )
    chunk2 = (
        "diff --git a/tests/test_auth.py b/tests/test_auth.py\n"
        "@@ -0,0 +1,5 @@\n"
        "+def verify_token(): pass\n"
    )
    chunk3 = (
        "diff --git a/assets/logo.png b/assets/logo.png\n"
        "new file mode 100644\n"
        "Binary files /dev/null and b/assets/logo.png differ\n"
    )
    multipart_diff = chunk1 + chunk2 + chunk3
    diff_summary = DiffSummary(raw_diff=multipart_diff)
    monkeypatch.setattr("guard.core.llm_reviewer.REVIEW_BATCH_CHARS", len(chunk1) + 10)

    options = ReviewOptions(
        reviewers=2,
        validate_findings=True,
        threat_frame="auto",
        test_checklist=True,
        test_evidence=True,
        part_manifest=True,
        max_llm_calls=12,
    )

    def mock_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        _ = cfg, prompt, kwargs
        if "code review validator" in system_prompt.lower():
            return (
                "VERDICT: refuted\n"
                "EVIDENCE: def verify_token(): pass\n"
                "REASON: Moved to tests\n"
            )
        if "Requirements" in system_prompt:
            return (
                "SCORE: 7.0\nSUMMARY: reqs review\nFINDINGS:\n"
                "- high | correctness | guard/auth.py:10 | - | verify_token removed\n"
                "THREATMODEL:\n- Assets: token\nUNREVIEWED:\n- cache\n"
            )
        return (
            "SCORE: 8.0\nSUMMARY: correctness review\nFINDINGS:\nNone\n"
            "THREATMODEL:\n- Assets: token\nUNREVIEWED:\n- cache\n"
        )

    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", mock_call)

    verdict = engine.review(
        prompt="Update auth token",
        domain="backend",
        diff_summary=diff_summary,
        options=options,
    )

    assert verdict.verdict == ReviewVerdict.APPROVED
    assert len(verdict.validation_log) == 1
    assert verdict.validation_log[0]["verdict"] == "refuted"
    assert verdict.llm_calls > 0
    assert verdict.llm_chars > 0
    assert len(verdict.coverage_notes) > 0


@pytest.mark.parametrize("interloper", ["  NOTE: see below", "Summary: two issues", "  **Score:** 4"])
def test_a_header_like_line_inside_findings_never_drops_the_findings_after_it(interloper):
    text = (
        "SCORE: 8\nSUMMARY: ok\nFINDINGS:\n- low | style | a.py:1 | - | nit\n"
        f"{interloper}\n- high | security | b.py:2 | - | sql injection\nTECHNICAL:\n- x\n"
    )
    assert parse_findings(text, "task") is None  # unreadable: never an approval missing the high finding


def test_a_section_after_findings_without_finding_lines_still_ends_the_block():
    text = "FINDINGS:\n- high | security | b.py:2 | - | sql injection\n  Threatmodel:\n  - attacker controls b\n"
    parsed = parse_findings(text, "task")
    assert parsed is not None and [f.severity for f in parsed] == ["high"]
