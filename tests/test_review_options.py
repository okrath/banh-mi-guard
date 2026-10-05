"""
Unit tests for guard.core.review_options.

Validates:
- Defaults of ReviewOptions
- Layered resolution: defaults < global_cfg["review"] < cli
- CLI overrides global_cfg and defaults
- CLI None values do not override config or defaults
- Flat global_cfg without 'review' dict is not read as review options
- Unknown keys in config and CLI are ignored with no error
- Ignored keys reporting for review config typos and non-object review
- Strict validation of invalid values with informative error messages naming all invalid fields
- Attribute assignment validation and with_overrides revalidation
- Boolean spellings (true/false/1/0/yes/no, case-insensitive)
- Isolation from environment variables (GUARD_REVIEW_* and unprefixed names)
- Cost hint arithmetic (retries, reviewers, validation stage)
- Effective sources reporting
- Leaf module property: zero imports from guard, no relative imports
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from guard.core.review_options import (
    ReviewOptions,
    effective_sources,
    ignored_keys,
    load_review_options,
)


def test_default_review_options() -> None:
    opts = ReviewOptions()
    assert opts.coverage_notes is True
    assert opts.part_manifest is False
    assert opts.test_evidence is False
    assert opts.test_checklist is False
    assert opts.threat_frame == "off"
    assert opts.validate_findings is False
    assert opts.reviewers == 1
    assert opts.max_llm_calls == 12
    assert opts.stage_timeout_s == 900

    loaded = load_review_options()
    assert loaded == opts

    sources = effective_sources()
    assert len(sources) == 9
    for field, source in sources.items():
        assert source == "default", f"Field {field} should be 'default', got {source}"


def test_fields_from_global_config_review_key() -> None:
    global_cfg = {
        "review": {
            "reviewers": 2,
            "threat_frame": "auto",
            "test_evidence": True,
            "max_llm_calls": 24,
            "stage_timeout_s": 600,
        }
    }
    opts = load_review_options(global_cfg=global_cfg)
    assert opts.reviewers == 2
    assert opts.threat_frame == "auto"
    assert opts.test_evidence is True
    assert opts.max_llm_calls == 24
    assert opts.stage_timeout_s == 600
    # Unspecified fields keep defaults
    assert opts.coverage_notes is True
    assert opts.part_manifest is False

    sources = effective_sources(global_cfg=global_cfg)
    assert sources["reviewers"] == "config"
    assert sources["threat_frame"] == "config"
    assert sources["test_evidence"] == "config"
    assert sources["max_llm_calls"] == "config"
    assert sources["stage_timeout_s"] == "config"
    assert sources["coverage_notes"] == "default"
    assert sources["part_manifest"] == "default"


def test_flat_global_config_is_not_read_as_review_options() -> None:
    # Top-level keys without 'review' dict must NOT be treated as review options
    global_cfg = {
        "reviewers": 4,
        "part_manifest": True,
        "validate_findings": True,
    }
    opts = load_review_options(global_cfg=global_cfg)
    assert opts.reviewers == 1  # Default kept
    assert opts.part_manifest is False  # Default kept
    assert opts.validate_findings is False  # Default kept
    assert opts.coverage_notes is True

    sources = effective_sources(global_cfg=global_cfg)
    assert sources["reviewers"] == "default"
    assert sources["part_manifest"] == "default"
    assert sources["validate_findings"] == "default"

    # Non-dict 'review' key also yields defaults
    global_cfg_invalid_review = {"review": "not a dict", "reviewers": 4}
    opts_invalid = load_review_options(global_cfg=global_cfg_invalid_review)
    assert opts_invalid.reviewers == 1


def test_fields_from_cli() -> None:
    cli: dict[str, Any] = {
        "reviewers": 4,
        "validate_findings": True,
        "stage_timeout_s": 1200,
        "coverage_notes": False,
    }
    opts = load_review_options(cli=cli)
    assert opts.reviewers == 4
    assert opts.validate_findings is True
    assert opts.stage_timeout_s == 1200
    assert opts.coverage_notes is False
    assert opts.threat_frame == "off"

    sources = effective_sources(cli=cli)
    assert sources["reviewers"] == "cli"
    assert sources["validate_findings"] == "cli"
    assert sources["stage_timeout_s"] == "cli"
    assert sources["coverage_notes"] == "cli"
    assert sources["threat_frame"] == "default"


def test_priority_order_cli_overrides_config_overrides_defaults() -> None:
    global_cfg = {
        "review": {
            "reviewers": 2,
            "threat_frame": "auto",
            "max_llm_calls": 20,
            "coverage_notes": True,
        }
    }
    cli = {
        "reviewers": 5,
        "threat_frame": "off",
        "coverage_notes": False,
    }
    opts = load_review_options(global_cfg=global_cfg, cli=cli)
    assert opts.reviewers == 5  # CLI wins
    assert opts.threat_frame == "off"  # CLI wins
    assert opts.coverage_notes is False  # CLI wins
    assert opts.max_llm_calls == 20  # Config wins over default
    assert opts.part_manifest is False  # Default

    sources = effective_sources(global_cfg=global_cfg, cli=cli)
    assert sources["reviewers"] == "cli"
    assert sources["threat_frame"] == "cli"
    assert sources["coverage_notes"] == "cli"
    assert sources["max_llm_calls"] == "config"
    assert sources["part_manifest"] == "default"


def test_cli_none_values_do_not_override_config_or_defaults() -> None:
    global_cfg = {
        "review": {
            "reviewers": 3,
            "threat_frame": "auto",
            "coverage_notes": False,
        }
    }
    cli = {
        "reviewers": None,
        "threat_frame": None,
        "coverage_notes": None,
        "part_manifest": None,
    }
    opts = load_review_options(global_cfg=global_cfg, cli=cli)
    assert opts.reviewers == 3  # Config kept
    assert opts.threat_frame == "auto"  # Config kept
    assert opts.coverage_notes is False  # Config kept
    assert opts.part_manifest is False  # Default kept

    sources = effective_sources(global_cfg=global_cfg, cli=cli)
    assert sources["reviewers"] == "config"
    assert sources["threat_frame"] == "config"
    assert sources["coverage_notes"] == "config"
    assert sources["part_manifest"] == "default"


def test_every_field_individually_from_cli() -> None:
    all_cli: dict[str, Any] = {
        "coverage_notes": False,
        "part_manifest": True,
        "test_evidence": True,
        "test_checklist": True,
        "threat_frame": "auto",
        "validate_findings": True,
        "reviewers": 5,
        "max_llm_calls": 36,
        "stage_timeout_s": 1800,
    }
    opts = load_review_options(cli=all_cli)
    assert opts.coverage_notes is False
    assert opts.part_manifest is True
    assert opts.test_evidence is True
    assert opts.test_checklist is True
    assert opts.threat_frame == "auto"
    assert opts.validate_findings is True
    assert opts.reviewers == 5
    assert opts.max_llm_calls == 36
    assert opts.stage_timeout_s == 1800

    sources = effective_sources(cli=all_cli)
    for field in all_cli:
        assert sources[field] == "cli", f"Field {field} should be 'cli'"


def test_every_field_individually_from_config() -> None:
    all_cfg = {
        "review": {
            "coverage_notes": False,
            "part_manifest": True,
            "test_evidence": True,
            "test_checklist": True,
            "threat_frame": "auto",
            "validate_findings": True,
            "reviewers": 3,
            "max_llm_calls": 18,
            "stage_timeout_s": 600,
        }
    }
    opts = load_review_options(global_cfg=all_cfg)
    assert opts.coverage_notes is False
    assert opts.part_manifest is True
    assert opts.test_evidence is True
    assert opts.test_checklist is True
    assert opts.threat_frame == "auto"
    assert opts.validate_findings is True
    assert opts.reviewers == 3
    assert opts.max_llm_calls == 18
    assert opts.stage_timeout_s == 600

    sources = effective_sources(global_cfg=all_cfg)
    for field in all_cfg["review"]:
        assert sources[field] == "config", f"Field {field} should be 'config'"


def test_environment_variables_are_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    # Prefixed environment variables
    monkeypatch.setenv("GUARD_REVIEW_REVIEWERS", "3")
    monkeypatch.setenv("GUARD_REVIEW_THREAT_FRAME", "auto")
    monkeypatch.setenv("GUARD_REVIEW_VALIDATE_FINDINGS", "true")
    monkeypatch.setenv("GUARD_REVIEW_COVERAGE_NOTES", "false")
    monkeypatch.setenv("GUARD_REVIEW_MAX_LLM_CALLS", "99")
    monkeypatch.setenv("GUARD_REVIEW_STAGE_TIMEOUT_S", "5000")

    # Unprefixed environment variables
    monkeypatch.setenv("REVIEWERS", "3")
    monkeypatch.setenv("VALIDATE_FINDINGS", "1")
    monkeypatch.setenv("THREAT_FRAME", "auto")
    monkeypatch.setenv("COVERAGE_NOTES", "0")
    monkeypatch.setenv("MAX_LLM_CALLS", "50")
    monkeypatch.setenv("STAGE_TIMEOUT_S", "3000")

    opts = load_review_options()
    assert opts.reviewers == 1
    assert opts.threat_frame == "off"
    assert opts.validate_findings is False
    assert opts.coverage_notes is True
    assert opts.max_llm_calls == 12
    assert opts.stage_timeout_s == 900

    sources = effective_sources()
    for source in sources.values():
        assert source == "default"


@pytest.mark.parametrize(
    "raw,expected",
    [
        (True, True),
        (False, False),
        (1, True),
        (0, False),
        ("true", True),
        ("True", True),
        ("TRUE", True),
        ("false", False),
        ("False", False),
        ("FALSE", False),
        ("yes", True),
        ("Yes", True),
        ("YES", True),
        ("no", False),
        ("No", False),
        ("NO", False),
        ("1", True),
        ("0", False),
    ],
)
def test_bool_spellings(raw: Any, expected: bool) -> None:
    for field in [
        "coverage_notes",
        "part_manifest",
        "test_evidence",
        "test_checklist",
        "validate_findings",
    ]:
        opts = ReviewOptions(**{field: raw})
        assert getattr(opts, field) is expected

        loaded = load_review_options(cli={field: raw})
        assert getattr(loaded, field) is expected


@pytest.mark.parametrize("invalid_bool", ["y", "n", "t", "f", "banana", "maybe", 2, -1, [1], {"a": 1}])
def test_invalid_boolean_spellings_rejected(invalid_bool: Any) -> None:
    for field in ["coverage_notes", "part_manifest", "validate_findings"]:
        with pytest.raises(ValueError) as excinfo:
            ReviewOptions(**{field: invalid_bool})
        msg = str(excinfo.value)
        assert field in msg
        assert "boolean (true/false/1/0/yes/no)" in msg


@pytest.mark.parametrize("invalid_val", [0, 6, 9, -1, "abc", "0", "9", True, False, 2.5])
def test_invalid_reviewers_raises_value_error(invalid_val: Any) -> None:
    with pytest.raises(ValueError) as excinfo:
        ReviewOptions(reviewers=invalid_val)
    msg = str(excinfo.value)
    assert "reviewers" in msg
    assert "between 1 and 5" in msg

    with pytest.raises(ValueError) as excinfo_load:
        load_review_options(cli={"reviewers": invalid_val})
    assert "reviewers" in str(excinfo_load.value)

    with pytest.raises(ValueError) as excinfo_sources:
        effective_sources(global_cfg={"review": {"reviewers": invalid_val}})
    assert "reviewers" in str(excinfo_sources.value)


@pytest.mark.parametrize("invalid_val", ["on", "disabled", "enabled", "none", 123, True, ""])
def test_invalid_threat_frame_raises_value_error(invalid_val: Any) -> None:
    with pytest.raises(ValueError) as excinfo:
        ReviewOptions(threat_frame=invalid_val)  # type: ignore[arg-type]
    msg = str(excinfo.value)
    assert "threat_frame" in msg
    assert "('off', 'auto')" in msg

    with pytest.raises(ValueError) as excinfo_load:
        load_review_options(cli={"threat_frame": invalid_val})
    assert "threat_frame" in str(excinfo_load.value)


@pytest.mark.parametrize("invalid_val", [0, -1, -10, "zero", "0", False, True])
def test_invalid_max_llm_calls_raises_value_error(invalid_val: Any) -> None:
    with pytest.raises(ValueError) as excinfo:
        ReviewOptions(max_llm_calls=invalid_val)
    msg = str(excinfo.value)
    assert "max_llm_calls" in msg
    assert ">= 1" in msg


@pytest.mark.parametrize("invalid_val", [29, 0, -1, "twenty", "29", False, True])
def test_invalid_stage_timeout_s_raises_value_error(invalid_val: Any) -> None:
    with pytest.raises(ValueError) as excinfo:
        ReviewOptions(stage_timeout_s=invalid_val)
    msg = str(excinfo.value)
    assert "stage_timeout_s" in msg
    assert ">= 30" in msg


def test_validation_lists_all_invalid_fields() -> None:
    with pytest.raises(ValueError) as excinfo:
        ReviewOptions(reviewers=0, threat_frame="invalid")  # type: ignore[arg-type]
    msg = str(excinfo.value)
    assert "reviewers" in msg
    assert "threat_frame" in msg

    with pytest.raises(ValueError) as excinfo_multi:
        load_review_options(
            cli={
                "reviewers": 9,
                "threat_frame": "bad",
                "max_llm_calls": 0,
                "stage_timeout_s": 10,
            }
        )
    multi_msg = str(excinfo_multi.value)
    assert "reviewers" in multi_msg
    assert "threat_frame" in multi_msg
    assert "max_llm_calls" in multi_msg
    assert "stage_timeout_s" in multi_msg


def test_validate_assignment() -> None:
    opts = ReviewOptions()

    with pytest.raises(ValueError) as excinfo_rev:
        opts.reviewers = 0
    assert "reviewers" in str(excinfo_rev.value)

    with pytest.raises(ValueError) as excinfo_tf:
        opts.threat_frame = "invalid"  # type: ignore[assignment]
    assert "threat_frame" in str(excinfo_tf.value)

    with pytest.raises(ValueError) as excinfo_calls:
        opts.max_llm_calls = 0
    assert "max_llm_calls" in str(excinfo_calls.value)

    with pytest.raises(ValueError) as excinfo_timeout:
        opts.stage_timeout_s = 10
    assert "stage_timeout_s" in str(excinfo_timeout.value)

    # Valid assignments succeed
    opts.reviewers = 3
    assert opts.reviewers == 3

    opts.threat_frame = "auto"
    assert opts.threat_frame == "auto"


def test_with_overrides() -> None:
    opts = ReviewOptions()
    opts2 = opts.with_overrides(reviewers=4, threat_frame="auto", validate_findings=True)
    assert opts2.reviewers == 4
    assert opts2.threat_frame == "auto"
    assert opts2.validate_findings is True
    assert opts2.coverage_notes is True  # Preserved from opts
    assert opts.reviewers == 1  # Original not mutated

    # Invalid overrides revalidate and list all invalid fields
    with pytest.raises(ValueError) as excinfo:
        opts.with_overrides(reviewers=0, threat_frame="bad")
    msg = str(excinfo.value)
    assert "reviewers" in msg
    assert "threat_frame" in msg


def test_unknown_keys_ignored_in_loading() -> None:
    opts = ReviewOptions(unknown_key="ignored", future_feature=123)  # type: ignore[call-arg]
    assert not hasattr(opts, "unknown_key")
    assert not hasattr(opts, "future_feature")

    loaded_cfg = load_review_options(
        global_cfg={"future_key": "val", "review": {"extra": 1, "reviewers": 2}}
    )
    assert loaded_cfg.reviewers == 2
    assert not hasattr(loaded_cfg, "extra")

    loaded_cli = load_review_options(cli={"cli_unknown": True, "threat_frame": "auto"})
    assert loaded_cli.threat_frame == "auto"
    assert not hasattr(loaded_cli, "cli_unknown")

    sources = effective_sources(global_cfg={"review": {"extra": 1}}, cli={"cli_unknown": 2})
    assert "extra" not in sources
    assert "cli_unknown" not in sources
    assert len(sources) == 9


def test_ignored_keys_reporting() -> None:
    # Clean input
    assert ignored_keys() == []
    assert ignored_keys(global_cfg={"review": {"reviewers": 2}}) == []
    assert ignored_keys(global_cfg={"llm": {"model": "gpt-4o"}}) == []

    # Typo in review object
    res_cfg = ignored_keys(global_cfg={"review": {"validate_finding": True, "reviewers": 2}})
    assert res_cfg == ["review.validate_finding"]

    # Unknown key in cli
    res_cli = ignored_keys(cli={"unknown_flag": 1, "reviewers": 3})
    assert res_cli == ["unknown_flag"]

    # Both config typo and CLI unknown
    res_both = ignored_keys(global_cfg={"review": {"typo": 1}}, cli={"cli_typo": 2})
    assert res_both == ["review.typo", "cli_typo"]

    # Structural warning when review is present but not a dict
    assert ignored_keys(global_cfg={"review": "not an object"}) == ["review (not an object)"]
    assert ignored_keys(global_cfg={"review": None}) == ["review (not an object)"]
    assert ignored_keys(global_cfg={"review": [1, 2]}) == ["review (not an object)"]
    assert ignored_keys(global_cfg={"review": 123}) == ["review (not an object)"]


@pytest.mark.parametrize(
    "reviewers,validate_findings,parts,expected_cost",
    [
        (1, False, 0, 0),
        (1, True, 0, 5),
        (1, False, 1, 2),
        (1, True, 1, 7),
        (1, False, 3, 6),
        (1, True, 3, 11),
        (2, False, 2, 8),
        (2, True, 2, 13),
        (3, False, 4, 24),
        (3, True, 4, 29),
        (5, False, 5, 50),
        (5, True, 5, 55),
    ],
)
def test_cost_hint_calculations(
    reviewers: int,
    validate_findings: bool,
    parts: int,
    expected_cost: int,
) -> None:
    opts = ReviewOptions(reviewers=reviewers, validate_findings=validate_findings)
    assert opts.cost_hint(parts) == expected_cost


@pytest.mark.parametrize("invalid_parts", [-1, -5, "3", 1.5, True, False, None])
def test_cost_hint_invalid_parts(invalid_parts: Any) -> None:
    opts = ReviewOptions()
    with pytest.raises(ValueError):
        opts.cost_hint(invalid_parts)


def test_string_numbers_parsed_correctly() -> None:
    opts = load_review_options(
        cli={
            "reviewers": "3",
            "max_llm_calls": "20",
            "stage_timeout_s": "1200",
        }
    )
    assert opts.reviewers == 3
    assert opts.max_llm_calls == 20
    assert opts.stage_timeout_s == 1200


def test_invalid_container_types_raise_value_error() -> None:
    with pytest.raises(ValueError, match="global_cfg must be a dict or None"):
        load_review_options(global_cfg="not a dict")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="cli must be a dict or None"):
        load_review_options(cli=123)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="global_cfg must be a dict or None"):
        ignored_keys(global_cfg="not a dict")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="cli must be a dict or None"):
        ignored_keys(cli=123)  # type: ignore[arg-type]


def test_leaf_module_has_zero_guard_imports_and_no_relative_imports() -> None:
    target_file = Path(__file__).resolve().parent.parent / "guard" / "core" / "review_options.py"
    assert target_file.is_file(), f"Target file does not exist: {target_file}"

    tree = ast.parse(target_file.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                assert not name.name.startswith("guard"), (
                    f"Illegal guard import in leaf module: {name.name}"
                )
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, (
                f"Illegal relative import in leaf module: level={node.level} module={node.module}"
            )
            if node.module:
                assert not node.module.startswith("guard"), (
                    f"Illegal guard import in leaf module: from {node.module}"
                )
