"""
Benchmark runner: case execution, corpus evaluation, and LLM reviewer invocation.
"""

from __future__ import annotations

import importlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional
from unittest.mock import patch

from bench.metrics import case_outcome, summarise


class BudgetExceeded(Exception):
    """Raised when an LLM call would exceed the remaining budget."""

    def __init__(self, message: str, calls: int = 0, chars_sent: int = 0) -> None:
        super().__init__(message)
        self.calls = calls
        self.chars_sent = chars_sent


@dataclass
class ReviewResult:
    """Result of reviewing one case."""

    verdict: str
    findings: list[dict] = field(default_factory=list)
    calls: int = 0
    chars_sent: int = 0
    seconds: float = 0.0
    llm_error: Optional[str] = None


def estimate_case_worst_calls(diff: str, variant: Optional[dict] = None, repeats: int = 1) -> int:
    """
    Worst-case LLM call bound for one case using the real partitioner:
    guard.core.diff_partition.partition_diff(diff).parts (including trailing sentinel),
    times 2 for retries, times reviewers (1..5), plus 5 when validation is on.
    """
    from guard.core.diff_partition import partition_diff

    partition = partition_diff(diff or "")
    num_parts = max(1, len(partition.parts))
    reviewers = 1
    validate_on = False
    if isinstance(variant, dict):
        rev = variant.get("reviewers")
        if rev is not None and not isinstance(rev, bool):
            try:
                r_int = int(rev)
                reviewers = max(1, min(5, r_int))
            except (ValueError, TypeError):
                reviewers = 1
        validate_on = bool(variant.get("validate_findings", False))

    calls_per_run = 2 * num_parts * reviewers + (5 if validate_on else 0)
    return calls_per_run * max(1, repeats)


def validate_variant(variant: Optional[dict]) -> dict:
    """Validate and normalize variant parameters (e.g. reviewers in 1..5)."""
    if not variant:
        return {}
    if "reviewers" in variant:
        rev = variant["reviewers"]
        if isinstance(rev, bool):
            raise ValueError(f"reviewers must be an integer, got boolean {rev}")
        if isinstance(rev, int):
            r_int = rev
        elif isinstance(rev, str) and rev.strip().lstrip("-").isdigit():
            r_int = int(rev.strip())
        else:
            raise ValueError(f"reviewers must be an integer in 1..5, got {type(rev).__name__} ({rev})")

        if not (1 <= r_int <= 5):
            raise ValueError(f"reviewers must be between 1 and 5, got {rev}")
        variant["reviewers"] = r_int
    return variant


def default_review_fn(
    case: dict,
    variant: Optional[dict] = None,
    *,
    budget_remaining: Optional[int] = None,
) -> ReviewResult:
    """
    Default review function: calls LLMReviewerEngine.review as guard post does.
    Counts calls by wrapping guard.core.llm_reviewer.call_llm.
    Fails loudly if the LLM ran but calls == 0.
    Raises BudgetExceeded if an additional call would exceed remaining budget.
    """
    import guard.core.llm_reviewer as llm_reviewer_mod
    from guard.core.config import load_config
    from guard.core.diff_inspector import GitDiffInspector
    from guard.core.llm_reviewer import LLMReviewerEngine

    cfg = load_config()
    reviewer = LLMReviewerEngine(config=cfg)

    raw_diff = str(case.get("diff", ""))
    prompt = str(case.get("prompt", "Benchmark case review"))
    domain = str(case.get("domain", "backend"))

    inspector = GitDiffInspector(Path("."))
    diff_summary = inspector.parse_diff(raw_diff)

    calls = 0
    chars_sent = 0
    real_call_llm = llm_reviewer_mod.call_llm

    call_budget = budget_remaining
    if call_budget is None and isinstance(variant, dict):
        call_budget = variant.get("_budget_remaining")

    def counting_call_llm(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls, chars_sent
        if call_budget is not None and calls >= call_budget:
            raise BudgetExceeded(
                f"LLM call budget exceeded ({call_budget} calls allowed)",
                calls=calls,
                chars_sent=chars_sent,
            )
        calls += 1
        p_text = ""
        s_text = ""
        if len(args) >= 2 and isinstance(args[1], str):
            p_text = args[1]
        elif "prompt" in kwargs and isinstance(kwargs["prompt"], str):
            p_text = kwargs["prompt"]

        if len(args) >= 3 and isinstance(args[2], str):
            s_text = args[2]
        elif "system_prompt" in kwargs and isinstance(kwargs["system_prompt"], str):
            s_text = kwargs["system_prompt"]
        elif "system" in kwargs and isinstance(kwargs["system"], str):
            s_text = kwargs["system"]

        chars_sent += len(p_text) + len(s_text)
        return real_call_llm(*args, **kwargs)

    extra_kwargs: dict[str, Any] = {}
    import inspect

    sig = inspect.signature(reviewer.review)
    if "options" in sig.parameters and variant:
        try:
            review_options_mod = importlib.import_module("guard.core.review_options")
            review_options_cls = getattr(review_options_mod, "ReviewOptions", None)
            if review_options_cls is not None:
                # Strip internal helper keys like _budget_remaining
                clean_variant = {k: v for k, v in variant.items() if not k.startswith("_")}
                extra_kwargs["options"] = review_options_cls(**clean_variant)
        except Exception as e:
            raise ValueError(f"Failed to apply variant configuration {variant}: {e}") from e

    t0 = time.perf_counter()
    try:
        with patch.object(llm_reviewer_mod, "call_llm", side_effect=counting_call_llm):
            verdict = reviewer.review(
                prompt=prompt,
                domain=domain,
                diff_summary=diff_summary,
                build_check=None,
                violations=[],
                invariant_result=None,
                use_llm=True,
                **extra_kwargs,
            )
        v_err = getattr(verdict, "llm_error", None)
        if v_err and "BudgetExceeded" in str(v_err):
            raise BudgetExceeded(str(v_err))
    except BudgetExceeded:
        raise
    duration = time.perf_counter() - t0

    v_calls = getattr(verdict, "llm_calls", None)
    if v_calls is not None:
        calls = int(v_calls)
    v_chars = getattr(verdict, "llm_chars", None)
    if v_chars is not None:
        chars_sent = int(v_chars)

    is_heuristic = getattr(verdict, "review_mode", "") == "heuristic"
    llm_err = getattr(verdict, "llm_error", None)

    # Fail loudly if LLM ran but 0 calls were counted (harness error)
    if not llm_err and not is_heuristic and calls == 0:
        raise RuntimeError("Harness error: LLM review ran but call count is 0. Check call_llm wrapping.")

    raw_verdict = getattr(verdict, "verdict", "APPROVED")
    raw_val = getattr(raw_verdict, "value", None)
    verdict_str = "no-llm" if (llm_err or is_heuristic) else (str(raw_val) if raw_val is not None else str(raw_verdict))

    findings_dicts: List[dict] = []
    for f in getattr(verdict, "findings", []) or []:
        if hasattr(f, "model_dump"):
            fd = f.model_dump()
        elif hasattr(f, "dict"):
            fd = f.dict()
        elif isinstance(f, dict):
            fd = dict(f)
        else:
            fd = {}
        if "blocking" not in fd:
            fd["blocking"] = bool(getattr(f, "blocking", False))
        findings_dicts.append(fd)
    return ReviewResult(
        verdict=verdict_str,
        findings=findings_dicts,
        calls=calls,
        chars_sent=chars_sent,
        seconds=duration,
        llm_error=llm_err,
    )


def make_dry_run_review_fn() -> Any:
    """Scripted review function for dry-runs and unit tests."""

    def dry_run_review_fn(case: dict, variant: Optional[dict] = None) -> ReviewResult:
        _ = variant
        label = case.get("label", "unlabelled")
        defects = case.get("defects", [])
        if label == "defect" and defects:
            findings = []
            for d in defects:
                kw = d.get("keywords", ["error"])[0] if d.get("keywords") else "error"
                findings.append(
                    {
                        "id": f"find_{d.get('id', '1')}",
                        "location": f"{d.get('file', 'unknown')}:10",
                        "description": f"Found issue matching keyword {kw}",
                        "blocking": True,
                        "severity": d.get("severity", "high"),
                        "kind": d.get("kind", "correctness"),
                    }
                )
            return ReviewResult(
                verdict="REVISE",
                findings=findings,
                calls=1,
                chars_sent=100,
                seconds=0.005,
            )
        return ReviewResult(
            verdict="APPROVED",
            findings=[],
            calls=1,
            chars_sent=50,
            seconds=0.005,
        )

    return dry_run_review_fn


def _call_review_fn(
    review_fn: Any,
    case: dict,
    variant: Optional[dict],
    *,
    budget_remaining: Optional[int] = None,
) -> ReviewResult:
    import inspect

    sig = inspect.signature(review_fn)
    params = list(sig.parameters.values())
    has_var_keyword = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)
    has_variant_param = "variant" in sig.parameters
    has_budget_param = "budget_remaining" in sig.parameters
    can_take_variant = has_var_keyword or has_variant_param or len(params) >= 2

    effective_variant = variant
    if budget_remaining is not None and isinstance(variant, dict):
        effective_variant = {**variant, "_budget_remaining": budget_remaining}
    elif budget_remaining is not None and variant is None:
        effective_variant = {"_budget_remaining": budget_remaining}

    kwargs: dict[str, Any] = {}
    if has_budget_param:
        kwargs["budget_remaining"] = budget_remaining

    if can_take_variant:
        if has_variant_param or has_var_keyword:
            res = review_fn(case, variant=effective_variant, **kwargs)
        else:
            res = review_fn(case, effective_variant, **kwargs)
    else:
        res = review_fn(case, **kwargs)

    if isinstance(res, ReviewResult):
        return res
    if isinstance(res, dict):
        return ReviewResult(
            verdict=str(res.get("verdict", "APPROVED")),
            findings=list(res.get("findings", [])),
            calls=int(res.get("calls", 0)),
            chars_sent=int(res.get("chars_sent", 0)),
            seconds=float(res.get("seconds", 0.0)),
            llm_error=res.get("llm_error"),
        )
    raise TypeError(f"review_fn returned unexpected type: {type(res)}")


def run_case(
    case: dict,
    review_fn: Any,
    *,
    repeats: int = 1,
    variant: Optional[dict] = None,
) -> list[dict]:
    """Run one case for `repeats` times; return one outcome dict per repeat."""
    outcomes: list[dict] = []
    for _ in range(repeats):
        res = _call_review_fn(review_fn, case, variant)
        outcome = case_outcome(
            case,
            verdict=res.verdict,
            findings=res.findings,
            calls=res.calls,
            chars_sent=res.chars_sent,
            seconds=res.seconds,
            llm_error=res.llm_error,
        )
        outcomes.append(outcome)
    return outcomes


def run_corpus(
    cases: list[dict],
    review_fn: Any,
    *,
    repeats: int = 1,
    max_calls: int = 1000,
    label_filter: Optional[str] = None,
    variant: Optional[dict] = None,
) -> dict:
    """
    Run an entire corpus of cases within a hard LLM call budget.

    Checks worst-case call bound before each case; skips remaining cases if budget would be exceeded.
    Stops immediately if BudgetExceeded is raised.
    """
    if repeats < 1:
        raise ValueError(f"repeats must be at least 1, got {repeats}")
    if variant:
        validate_variant(variant)

    filtered_cases = cases
    if label_filter and label_filter.lower() != "all":
        filtered_cases = [c for c in cases if c.get("label", "").lower() == label_filter.lower()]

    remaining_budget = max_calls
    all_outcomes: list[dict] = []

    for i, case in enumerate(filtered_cases):
        if case.get("label") == "invalid":
            for _ in range(repeats):
                out = case_outcome(
                    case,
                    verdict="invalid",
                    findings=[],
                    calls=0,
                    chars_sent=0,
                    seconds=0.0,
                )
                out["invalid"] = True
                out["error"] = case.get("error", "Corrupt case file")
                all_outcomes.append(out)
            continue

        worst_case = estimate_case_worst_calls(case.get("diff", ""), variant=variant, repeats=repeats)

        if remaining_budget < worst_case:
            # Hard budget cap: skip this case and all remaining cases
            for skipped_case in filtered_cases[i:]:
                for _ in range(repeats):
                    out = case_outcome(
                        skipped_case,
                        verdict="skipped (budget)",
                        findings=[],
                        calls=0,
                        chars_sent=0,
                        seconds=0.0,
                    )
                    out["skipped"] = True
                    out["skip_reason"] = "budget"
                    all_outcomes.append(out)
            break

        # Run repeats for this case with budget guard
        budget_blown = False
        calls_before_exc = 0
        chars_before_exc = 0
        case_outcomes: list[dict] = []

        for rep_idx in range(repeats):
            try:
                res = _call_review_fn(review_fn, case, variant, budget_remaining=remaining_budget)
                calls_used = res.calls
                remaining_budget -= calls_used
                out = case_outcome(
                    case,
                    verdict=res.verdict,
                    findings=res.findings,
                    calls=calls_used,
                    chars_sent=res.chars_sent,
                    seconds=res.seconds,
                    llm_error=res.llm_error,
                )
                case_outcomes.append(out)
            except BudgetExceeded as exc:
                budget_blown = True
                calls_before_exc = getattr(exc, "calls", 0)
                chars_before_exc = getattr(exc, "chars_sent", 0)
                remaining_budget -= calls_before_exc
                # Attribute partial calls made during this blown repeat
                out = case_outcome(
                    case,
                    verdict="skipped (budget)",
                    findings=[],
                    calls=calls_before_exc,
                    chars_sent=chars_before_exc,
                    seconds=0.0,
                )
                out["skipped"] = True
                out["skip_reason"] = "budget"
                case_outcomes.append(out)

                # Attribute 0 calls to any remaining unrun repeats of this case
                for _ in range(rep_idx + 1, repeats):
                    unrun_out = case_outcome(
                        case,
                        verdict="skipped (budget)",
                        findings=[],
                        calls=0,
                        chars_sent=0,
                        seconds=0.0,
                    )
                    unrun_out["skipped"] = True
                    unrun_out["skip_reason"] = "budget"
                    case_outcomes.append(unrun_out)
                break

        all_outcomes.extend(case_outcomes)

        if budget_blown:
            # Skip all remaining cases as well
            for skipped_case in filtered_cases[i + 1 :]:
                for _ in range(repeats):
                    out = case_outcome(
                        skipped_case,
                        verdict="skipped (budget)",
                        findings=[],
                        calls=0,
                        chars_sent=0,
                        seconds=0.0,
                    )
                    out["skipped"] = True
                    out["skip_reason"] = "budget"
                    all_outcomes.append(out)
            break

    summary = summarise(all_outcomes)
    summary["budget_max_calls"] = max_calls
    summary["budget_remaining"] = max(0, remaining_budget)
    summary["repeats"] = repeats
    summary["label_filter"] = label_filter or "all"
    if variant is not None:
        summary["variant"] = variant
    return summary


def load_cases_from_path(cases_path: Path | str) -> list[dict]:
    """Load case dicts directly from a directory or JSON file using plain json."""
    import sys

    p = Path(cases_path)
    if not p.exists():
        sys.stderr.write(f"Warning: cases path not found: {cases_path}\n")
        return []
    if p.is_file():
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return [d for d in data if isinstance(d, dict)]
                if isinstance(data, dict):
                    return [data]
                return []
        except Exception as e:
            sys.stderr.write(f"Warning: failed to parse case file {p}: {e}\n")
            return [{"id": p.stem, "label": "invalid", "error": str(e), "file": str(p), "diff": ""}]

    cases: list[dict] = []
    for f in sorted(p.glob("*.json")):
        try:
            with open(f, "r", encoding="utf-8") as fp:
                data = json.load(fp)
                if isinstance(data, dict) and "id" in data:
                    cases.append(data)
                elif isinstance(data, list):
                    cases.extend(d for d in data if isinstance(d, dict) and "id" in d)
        except Exception as e:
            sys.stderr.write(f"Warning: failed to parse case file {f}: {e}\n")
            cases.append({"id": f.stem, "label": "invalid", "error": str(e), "file": str(f), "diff": ""})
            continue
    return cases
