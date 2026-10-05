"""
Review Options configuration and resolution for Banh-Mi-Guard.

Leaf module in the dependency graph: imports nothing from guard.
Supports layered resolution: defaults < global_cfg["review"] < CLI flags.
Environment variables are intentionally ignored to prevent prompt/stage tampering.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

_BOOLEAN_FIELDS = {
    "coverage_notes",
    "part_manifest",
    "test_evidence",
    "test_checklist",
    "validate_findings",
}

_ALLOWED_THREAT_FRAMES = ("off", "auto")

_KNOWN_FIELDS = (
    "coverage_notes",
    "part_manifest",
    "test_evidence",
    "test_checklist",
    "threat_frame",
    "validate_findings",
    "reviewers",
    "max_llm_calls",
    "stage_timeout_s",
)


def _parse_bool(field: str, val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        if val in (0, 1):
            return bool(val)
        raise ValueError(
            f"Invalid value for '{field}': expected boolean (true/false/1/0/yes/no), got {val!r}"
        )
    if isinstance(val, str):
        normalized = val.strip().lower()
        if normalized in ("true", "1", "yes", "y", "t"):
            return True
        if normalized in ("false", "0", "no", "n", "f"):
            return False
        raise ValueError(
            f"Invalid value for '{field}': expected boolean (true/false/1/0/yes/no), got {val!r}"
        )
    raise ValueError(
        f"Invalid value for '{field}': expected boolean (true/false/1/0/yes/no), got {val!r}"
    )


def _parse_int(field: str, val: Any, min_val: int, max_val: int | None = None) -> int:
    range_str = (
        f"integer between {min_val} and {max_val}"
        if max_val is not None
        else f"integer >= {min_val}"
    )

    if isinstance(val, bool) or val is None:
        raise ValueError(
            f"Invalid value for '{field}': expected {range_str}, got {val!r}"
        )

    if isinstance(val, int):
        int_val = val
    elif isinstance(val, str):
        s = val.strip()
        try:
            int_val = int(s)
        except ValueError:
            raise ValueError(
                f"Invalid value for '{field}': expected {range_str}, got {val!r}"
            ) from None
    else:
        raise ValueError(
            f"Invalid value for '{field}': expected {range_str}, got {val!r}"
        )

    if int_val < min_val or (max_val is not None and int_val > max_val):
        raise ValueError(
            f"Invalid value for '{field}': expected {range_str}, got {val!r}"
        )
    return int_val


def _parse_threat_frame(field: str, val: Any) -> Literal["off", "auto"]:
    if isinstance(val, str):
        normalized = val.strip().lower()
        if normalized in _ALLOWED_THREAT_FRAMES:
            return normalized  # type: ignore[return-value]
    raise ValueError(
        f"Invalid value for '{field}': expected one of {_ALLOWED_THREAT_FRAMES}, got {val!r}"
    )


def _normalize_field(field: str, val: Any) -> Any:
    if field in _BOOLEAN_FIELDS:
        return _parse_bool(field, val)
    if field == "threat_frame":
        return _parse_threat_frame(field, val)
    if field == "reviewers":
        return _parse_int(field, val, min_val=1, max_val=5)
    if field == "max_llm_calls":
        return _parse_int(field, val, min_val=1)
    if field == "stage_timeout_s":
        return _parse_int(field, val, min_val=30)
    return val


class ReviewOptions(BaseModel):
    model_config = ConfigDict(extra="ignore")

    coverage_notes: bool = True
    part_manifest: bool = False
    test_evidence: bool = False
    test_checklist: bool = False
    threat_frame: Literal["off", "auto"] = "off"
    validate_findings: bool = False
    reviewers: int = Field(default=1, ge=1, le=5)
    max_llm_calls: int = Field(default=12, ge=1)
    stage_timeout_s: int = Field(default=900, ge=30)

    def __init__(self, **data: Any) -> None:
        try:
            super().__init__(**data)
        except ValidationError as e:
            first_err = e.errors()[0] if e.errors() else None
            msg = first_err.get("msg") if first_err else str(e)
            if msg and msg.startswith("Value error, "):
                msg = msg[len("Value error, ") :]
            raise ValueError(msg) from None

    @model_validator(mode="before")
    @classmethod
    def _validate_and_normalize(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        normalized: dict[str, Any] = {}
        for k, v in data.items():
            if k in _KNOWN_FIELDS:
                normalized[k] = _normalize_field(k, v)
            else:
                normalized[k] = v
        return normalized

    def cost_hint(self, parts: int) -> int:
        """
        Worst-case number of LLM calls for a diff with that many review parts.
        One reviewer costs up to 2 * parts calls (retries included).
        Worst case is 2 * parts * reviewers, plus 5 when validate_findings is on.
        """
        if isinstance(parts, bool) or not isinstance(parts, int):
            raise ValueError("parts must be an integer")
        if parts < 0:
            raise ValueError("parts must be a non-negative integer")
        base = 2 * parts * self.reviewers
        if self.validate_findings:
            base += 5
        return base


def _extract_dict(data: Any, name: str) -> dict[str, Any]:
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{name} must be a dict or None, got {type(data).__name__}")
    return data


def _extract_config_dict(global_cfg: Any) -> dict[str, Any]:
    cfg = _extract_dict(global_cfg, "global_cfg")
    if "review" in cfg and isinstance(cfg["review"], dict):
        return cfg["review"]
    return cfg


def load_review_options(
    global_cfg: dict | None = None,
    cli: dict | None = None,
) -> ReviewOptions:
    """
    Resolve review options from defaults, global_cfg ('review' object), and cli flags.
    Priority order: defaults < global_cfg < cli.
    Unknown keys are ignored with no error.
    Invalid values raise ValueError naming the field and allowed values.
    Environment variables are deliberately NOT inspected.
    """
    cfg_data = _extract_config_dict(global_cfg)
    cli_data = _extract_dict(cli, "cli")

    merged: dict[str, Any] = {}
    for field in _KNOWN_FIELDS:
        if field in cli_data and cli_data[field] is not None:
            merged[field] = cli_data[field]
        elif field in cfg_data and cfg_data[field] is not None:
            merged[field] = cfg_data[field]

    return ReviewOptions(**merged)


def effective_sources(
    global_cfg: dict | None = None,
    cli: dict | None = None,
) -> dict[str, Literal["default", "config", "cli"]]:
    """
    Return a dictionary mapping each ReviewOptions field to its resolution source:
    'default', 'config', or 'cli'.
    Validates values via load_review_options first (raising ValueError on invalid input).
    """
    load_review_options(global_cfg=global_cfg, cli=cli)

    cfg_data = _extract_config_dict(global_cfg)
    cli_data = _extract_dict(cli, "cli")

    sources: dict[str, Literal["default", "config", "cli"]] = {}
    for field in _KNOWN_FIELDS:
        if field in cli_data and cli_data[field] is not None:
            sources[field] = "cli"
        elif field in cfg_data and cfg_data[field] is not None:
            sources[field] = "config"
        else:
            sources[field] = "default"
    return sources
