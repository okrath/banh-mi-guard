"""
Deterministic evaluation of invariants locked at pre-task.

- Invariants with `checks` (project-defined) run regex checks on the current files.
- Generic template invariants only get diff keyword heuristics; when no heuristic applies they
  are UNVERIFIED instead of being reported as maintained.
"""

from __future__ import annotations

import re
import time
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, model_validator


class DomainType(str, Enum):
    FRONTEND = "frontend"
    BACKEND = "backend"
    INFRA = "infra"
    MOBILE = "mobile"
    FULLSTACK = "fullstack"


# Removed lines that indicate a keyboard handler: key events or Escape key comparisons
KEY_HANDLER_REGEX = re.compile(r"""\bkey(?:down|up|press)\b|\bonKey(?:Down|Up)\b|['"`]Esc(?:ape)?['"`]|\bkeyCode\s*={2,3}\s*27\b""")


class InvariantCheck(BaseModel):
    id: str
    description: str
    passed: bool  # False only on a detected violation; see `status` for unverified checks
    confidence: float
    notes: str = ""
    status: str = ""  # "passed" | "failed" | "unverified" | "baseline_failed" | "retired"

    @model_validator(mode="after")
    def _default_status(self):
        # Sessions written before `status` existed: derive it from `passed`
        if not self.status:
            self.status = "passed" if self.passed else "failed"
        return self


class InvariantResult(BaseModel):
    all_passed: bool
    checks: List[InvariantCheck]
    ui_regression_risk: bool
    latency_ms: float
    engine_mode: str = "deterministic_rules"
    unverified_count: int = 0


# A keyword match on a template invariant: a lead for the LLM gate, not a verdict
HINT = "Keyword hint, not a check (judge it from the diff): "


def _removed_lines(git_diff: str) -> List[str]:
    """Lines the diff removes from files that still exist: a deleted file's lines are not a removed handler or state."""
    out: List[str] = []
    deleted = False
    for line in git_diff.splitlines():
        if line.startswith("diff --git "):
            deleted = False
        elif line.startswith("deleted file mode") or line.startswith("+++ /dev/null"):
            deleted = True
        elif line.startswith("-") and not line.startswith("---") and not deleted:
            out.append(line[1:].strip())
    return out


def evaluate_invariants(
    invariants: List[Dict[str, object]],
    git_diff: str,
    files_changed: List[str],
    repo_path: Optional[Path] = None,
) -> InvariantResult:
    """
    Evaluate invariants locked in pre-task.
    - Invariants with `checks` (project-defined) run deterministic regex checks on current files.
    - Generic template invariants only get diff keyword heuristics; when no heuristic applies
      they are reported as UNVERIFIED instead of being silently marked as maintained. A keyword match is
      not a check either (it reads one language's syntax and guesses): it is reported as UNVERIFIED with
      a hint the LLM gate judges from the diff, never as a failed invariant that blocks the gate by itself.
    """
    from guard.core.project_invariants import STATUS_FAILED, STATUS_PASSED, STATUS_UNVERIFIED, evaluate_checks

    start = time.perf_counter()
    checks: List[InvariantCheck] = []
    removed_lines = _removed_lines(git_diff)
    added_lines = [line[1:] for line in git_diff.splitlines() if line.startswith("+") and not line.startswith("+++")]

    for inv in invariants:
        inv_id = str(inv.get("id", "INV-UNKNOWN"))
        desc = str(inv.get("description", ""))
        desc_lower = desc.lower()
        inv_checks = inv.get("checks") or []

        confidence = 1.0
        if inv_checks and repo_path is not None:
            status, note = evaluate_checks(repo_path, inv_checks)  # type: ignore[arg-type]
        else:
            confidence = 0.5  # keyword heuristic over the diff, not a real check
            status, note = STATUS_UNVERIFIED, "No automated check applies (manual verification required)"
            if "escape" in desc_lower:
                status, note = STATUS_PASSED, "No keyboard/escape handler removed in diff"
                # Key-handling signals only; identifiers such as escapeHtml / escapedText are not handlers
                if any(KEY_HANDLER_REGEX.search(line) for line in removed_lines):
                    status, note = STATUS_UNVERIFIED, HINT + "the diff removes a keyboard/escape handler"
            elif "disabled" in desc_lower:
                status, note = STATUS_PASSED, "No disabled state removed in diff"
                if any("disabled" in line.lower() for line in removed_lines):
                    status, note = STATUS_UNVERIFIED, HINT + "the diff removes a disabled state"
            elif "timeout" in desc_lower:
                status, note = STATUS_PASSED, "No timeout construct added in diff"
                if any("timeout" in line.lower() for line in added_lines):
                    status, note = STATUS_UNVERIFIED, HINT + "the diff adds a timeout construct"
            elif "secret" in desc_lower:
                status, note = STATUS_PASSED, "No hardcoded secret added in diff"
                if any(re.search(r"\b(api_key|secret|password)\s*[:=]\s*['\"].+['\"]", line.lower()) for line in added_lines):
                    status, note = STATUS_UNVERIFIED, HINT + "the diff adds what looks like a hardcoded secret"

        checks.append(InvariantCheck(
            id=inv_id,
            description=desc,
            passed=status != STATUS_FAILED,
            confidence=0.0 if status == STATUS_UNVERIFIED else confidence,
            notes=note,
            status=status,
        ))

    failed = [c for c in checks if c.status == STATUS_FAILED]
    ui_regression_risk = bool(failed) and any(
        any(k in f.lower() for k in [".tsx", ".jsx", ".vue", ".html", ".css", ".swift", ".dart"])
        for f in files_changed
    )

    latency = (time.perf_counter() - start) * 1000
    return InvariantResult(
        all_passed=not failed,
        checks=checks,
        ui_regression_risk=ui_regression_risk,
        latency_ms=latency,
        engine_mode="deterministic_rules",
        unverified_count=sum(1 for c in checks if c.status == STATUS_UNVERIFIED),
    )
