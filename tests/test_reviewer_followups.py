"""Follow-ups of the reviewer integration: validation stage safety, per-review counters, parsers, panel budget."""

from __future__ import annotations

import threading

import pytest

from guard.core.config import GuardConfig, LLMConfig
from guard.core.findings import parse_findings
from guard.core.llm_reviewer import LLMReviewerEngine, ReviewVerdict
from guard.core.ocr_engine import DiffSummary
from guard.core.review_options import ReviewOptions

CHUNK1 = "diff --git a/README.md b/README.md\n@@ -10,3 +10,0 @@\n-Real removal\n"
CHUNK2 = "diff --git a/docs/cli.md b/docs/cli.md\n@@ -0,0 +1,3 @@\n+Some other content\n"
BLOCKING = "SCORE: 4.0\nSUMMARY: Bug\nFINDINGS:\n- high | correctness | README.md:10 | - | Bug description\n"
CLEAN = "SCORE: 9.0\nSUMMARY: ok\nFINDINGS:\nNone\n"


def _engine() -> LLMReviewerEngine:
    cfg = GuardConfig()
    cfg.llm = LLMConfig(api_key="k", model="mock-model", base_url="https://mock.llm")
    return LLMReviewerEngine(config=cfg)


def _two_parts(monkeypatch: pytest.MonkeyPatch) -> DiffSummary:
    monkeypatch.setattr("guard.core.llm_reviewer.REVIEW_BATCH_CHARS", len(CHUNK1) + 10)
    return DiffSummary(raw_diff=CHUNK1 + CHUNK2)


def _review_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
    _ = cfg, system_prompt, kwargs
    return BLOCKING if "README.md" in prompt else CLEAN


def test_validation_crash_leaves_findings_and_adds_a_coverage_note(monkeypatch: pytest.MonkeyPatch):
    diff = _two_parts(monkeypatch)
    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", _review_call)

    def boom(**kwargs: object):
        raise ValueError("validator exploded")

    monkeypatch.setattr("guard.core.llm_reviewer.validate_findings", boom)
    verdict = _engine().review(
        prompt="Task", domain="backend", diff_summary=diff, options=ReviewOptions(validate_findings=True),
    )
    assert verdict.verdict == ReviewVerdict.REVISE
    assert verdict.findings[0].blocking is True
    assert any("Finding validation failed (ValueError)" in n for n in verdict.coverage_notes)


def test_a_timed_out_validation_stage_makes_no_further_model_calls(monkeypatch: pytest.MonkeyPatch):
    diff = _two_parts(monkeypatch)
    model_calls: list[str] = []

    def mock_call(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        model_calls.append(system_prompt)
        return _review_call(cfg, prompt, system_prompt, **kwargs)

    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", mock_call)
    release, finished = threading.Event(), threading.Event()
    late: list[object] = []

    def slow_validate(**kwargs: object):
        release.wait(10)
        try:
            kwargs["call"]("validator", "late prompt")  # type: ignore[operator]
            late.append("called")
        except Exception as e:
            late.append(e)
        finished.set()
        return kwargs["findings"], []

    monkeypatch.setattr("guard.core.llm_reviewer.validate_findings", slow_validate)
    options = ReviewOptions.model_construct(validate_findings=True, stage_timeout_s=0.2)
    verdict = _engine().review(prompt="Task", domain="backend", diff_summary=diff, options=options)
    calls_at_verdict = len(model_calls)
    release.set()
    assert finished.wait(10)

    assert verdict.verdict == ReviewVerdict.REVISE
    assert any("timed out" in n for n in verdict.coverage_notes)
    assert late and isinstance(late[0], RuntimeError)
    assert len(model_calls) == calls_at_verdict == verdict.llm_calls


def test_error_path_reports_this_reviews_counts_not_the_previous_ones(monkeypatch: pytest.MonkeyPatch):
    engine = _engine()
    diff = _two_parts(monkeypatch)
    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", _review_call)
    first = engine.review(prompt="Task", domain="backend", diff_summary=diff)
    assert first.llm_calls == 2

    def failing(cfg: object, prompt: str, system_prompt: str, **kwargs: object) -> str:
        raise RuntimeError("network down")

    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", failing)
    second = engine.review(prompt="Task", domain="backend", diff_summary=diff)
    assert second.llm_error
    assert second.llm_calls < 2


def test_no_llm_review_after_a_counted_one_reports_zero_calls(monkeypatch: pytest.MonkeyPatch):
    engine = _engine()
    diff = _two_parts(monkeypatch)
    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", _review_call)
    assert engine.review(prompt="Task", domain="backend", diff_summary=diff).llm_calls == 2
    engine.config.llm = None  # type: ignore[union-attr]
    again = engine.review(prompt="Task", domain="backend", diff_summary=diff)
    assert again.llm_error and again.llm_calls == 0


def test_indented_word_colon_inside_a_bullet_list_does_not_end_the_section():
    engine = _engine()
    text = (
        "TECHNICAL:\n- builds a query\n  SQL: select 1\n- second point\n"
        "ERGONOMICS:\n- fine\n  NOTE: indented\nREMEDIATION:\nNone\n"
    )
    assert engine._extract_bullet_items(text, "TECHNICAL") == ["builds a query", "SQL: select 1", "second point"]
    assert engine._extract_bullet_items(text, "ERGONOMICS") == ["fine", "NOTE: indented"]


@pytest.mark.parametrize("header", ["  **ERGONOMICS:**", "## ERGONOMICS:", "**ERGONOMICS**:", "ERGONOMICS:"])
def test_real_section_headers_still_end_a_section(header: str):
    text = f"TECHNICAL:\n- point one\n{header}\n- other\n"
    assert _engine()._extract_bullet_items(text, "TECHNICAL") == ["point one"]


@pytest.mark.parametrize("header", ["**FINDINGS:**", "## FINDINGS:", "**FINDINGS**:", "### FINDINGS:", "FINDINGS:"])
def test_markdown_wrapped_findings_header_parses(header: str):
    text = f"SCORE: 4\n{header}\n- high | correctness | a.py:1 | - | Broken\nSUMMARY: x\n"
    found = parse_findings(text, "task")
    assert found is not None and len(found) == 1 and found[0].blocking


def test_markdown_findings_header_counts_toward_the_ambiguity_rule():
    line = "- high | correctness | a.py:1 | - | Broken\n"
    assert parse_findings(f"FINDINGS:\nNone\n**FINDINGS:**\n{line}", "task") is None
    assert parse_findings(f"## FINDINGS:\n{line}FINDINGS:\n{line}", "task") is None


def test_a_finding_shaped_line_after_a_cut_block_still_returns_none():
    text = "**FINDINGS:**\n- high | correctness | a.py:1 | - | One\nNOTE: x\n- high | correctness | b.py:2 | - | Two\n"
    assert parse_findings(text, "task") is None
