"""
Benchmark runner and metrics for dual-gate quality evaluation.
"""

from __future__ import annotations

from bench.metrics import (
    ItemList,
    case_outcome,
    compare,
    match_defects,
    summarise,
    to_markdown,
)
from bench.runner import (
    ReviewResult,
    default_review_fn,
    estimate_case_worst_calls,
    load_cases_from_path,
    make_dry_run_review_fn,
    run_case,
    run_corpus,
)

__all__ = [
    "ItemList",
    "match_defects",
    "case_outcome",
    "summarise",
    "compare",
    "to_markdown",
    "ReviewResult",
    "estimate_case_worst_calls",
    "default_review_fn",
    "make_dry_run_review_fn",
    "run_case",
    "run_corpus",
    "load_cases_from_path",
]
