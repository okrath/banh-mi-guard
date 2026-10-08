"""Tests for the named benchmark variants (no model calls)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bench.__main__ import parse_variant_args
from bench.runner import validate_variant
from bench.variants import VARIANTS, main, variant_args, variant_overrides
from guard.core.review_options import ReviewOptions


def test_expected_variant_names() -> None:
    assert list(VARIANTS) == ["baseline", "tests", "threat", "validate", "panel3", "panel5", "all"]


@pytest.mark.parametrize("name", list(VARIANTS))
def test_every_variant_builds_review_options(name: str) -> None:
    opts = ReviewOptions(**variant_overrides(name))
    assert opts.reviewers >= 1


def test_variants_switch_exactly_the_documented_options() -> None:
    base = ReviewOptions(**variant_overrides("baseline"))
    assert (base.test_checklist, base.threat_frame, base.validate_findings, base.reviewers) == (
        False,
        "off",
        False,
        1,
    )
    assert base.part_manifest is False and base.test_evidence is False
    assert ReviewOptions(**variant_overrides("tests")).test_checklist is True
    assert ReviewOptions(**variant_overrides("threat")).threat_frame == "auto"
    assert ReviewOptions(**variant_overrides("validate")).validate_findings is True
    assert ReviewOptions(**variant_overrides("panel3")).reviewers == 3
    assert ReviewOptions(**variant_overrides("panel5")).reviewers == 5
    everything = ReviewOptions(**variant_overrides("all"))
    assert everything.reviewers == 3 and everything.validate_findings and everything.test_checklist
    assert everything.threat_frame == "auto" and everything.part_manifest and everything.test_evidence


def test_overrides_are_copies() -> None:
    variant_overrides("baseline")["reviewers"] = 5
    assert VARIANTS["baseline"]["reviewers"] == 1


def test_unknown_variant_lists_valid_names() -> None:
    with pytest.raises(ValueError, match="panel3"):
        variant_overrides("nope")


@pytest.mark.parametrize("name", list(VARIANTS))
def test_cli_args_round_trip_through_the_runner_parser(name: str) -> None:
    args = variant_args(name)
    pairs = [a for a in args if a != "--variant"]
    parsed = validate_variant(parse_variant_args(pairs))
    assert parsed == VARIANTS[name]
    assert bool(parsed)  # a non-empty dict makes the runner pass options to the reviewer


def test_main_runs_a_variant_through_the_bench_cli(tmp_path: Path) -> None:
    case = {
        "id": "x1",
        "label": "defect",
        "prompt": "p",
        "diff": "diff --git a/a.py b/a.py\n+x = 1\n",
        "defects": [{"id": "d1", "file": "a.py", "keywords": ["x"]}],
    }
    cases = tmp_path / "cases"
    cases.mkdir()
    (cases / "x1.json").write_text(json.dumps(case), encoding="utf-8")
    out = tmp_path / "out.json"
    code = main(["run", "panel3", "--dry-run", "--cases", str(cases), "--out", str(out)])
    assert code == 0
    assert json.loads(out.read_text(encoding="utf-8"))["variant"]["reviewers"] == 3


def test_main_rejects_unknown_name_and_bad_usage() -> None:
    assert main(["run", "nope"]) == 2
    assert main([]) == 2
