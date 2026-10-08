"""
Named benchmark variants: each one is a set of ReviewOptions overrides.

The runner builds ``ReviewOptions(**overrides)`` from the dict and passes it to the real
``LLMReviewerEngine.review``, so a variant measures exactly what ``guard post`` would do with those options.

Usage (all runner flags are passed through; the budget flag is still required for real runs):

    python -m bench.variants list
    python -m bench.variants run panel3 --max-calls 40 --repeats 1 --out bench/results/panel3.json
"""

from __future__ import annotations

import sys
from typing import Any, List, Optional

from bench.__main__ import main as bench_main

# Panel and validation stages are capped by ``max_llm_calls`` inside the reviewer (default 12), which is
# below the worst case of a multi-part diff reviewed by five lenses. The benchmark's own ``--max-calls``
# stays the hard cap, so the in-reviewer cap is raised for the variants that need it.
_STAGE_CAP = 40

# Every option that changes a prompt or adds LLM calls is spelled out so a variant never depends on defaults.
_BASE: dict[str, Any] = {
    "part_manifest": False,
    "test_evidence": False,
    "test_checklist": False,
    "threat_frame": "off",
    "validate_findings": False,
    "reviewers": 1,
}

VARIANTS: dict[str, dict[str, Any]] = {
    "baseline": dict(_BASE),
    "tests": {**_BASE, "test_checklist": True},
    "threat": {**_BASE, "threat_frame": "auto"},
    "validate": {**_BASE, "validate_findings": True, "max_llm_calls": _STAGE_CAP},
    "panel3": {**_BASE, "reviewers": 3, "max_llm_calls": _STAGE_CAP},
    "panel5": {**_BASE, "reviewers": 5, "max_llm_calls": _STAGE_CAP},
    "all": {
        **_BASE,
        "part_manifest": True,
        "test_evidence": True,
        "test_checklist": True,
        "threat_frame": "auto",
        "validate_findings": True,
        "reviewers": 3,
        "max_llm_calls": _STAGE_CAP,
    },
}


def variant_overrides(name: str) -> dict[str, Any]:
    """Return a copy of the overrides for ``name``; unknown names raise ``ValueError`` listing the valid ones."""
    try:
        return dict(VARIANTS[name])
    except KeyError:
        raise ValueError(f"unknown variant '{name}'; choose one of: {', '.join(VARIANTS)}") from None


def variant_args(name: str) -> List[str]:
    """Translate a named variant into the runner's repeatable ``--variant key=value`` arguments."""
    args: List[str] = []
    for key, value in variant_overrides(name).items():
        text = str(value).lower() if isinstance(value, bool) else str(value)
        args += ["--variant", f"{key}={text}"]
    return args


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["list"]:
        for name, overrides in VARIANTS.items():
            sys.stdout.write(f"{name}: {overrides}\n")
        return 0
    if len(argv) < 2 or argv[0] != "run":
        sys.stderr.write("usage: python -m bench.variants list | run NAME [bench run flags]\n")
        return 2
    try:
        extra = variant_args(argv[1])
    except ValueError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 2
    return bench_main(["run", *argv[2:], *extra])


if __name__ == "__main__":
    sys.exit(main())
