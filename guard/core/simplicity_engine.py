"""
Simplicity & Engineering Frugality Engine — The "Productive Laziness" (KISS & YAGNI) Pillar.
Inspired by Larry Wall's virtue of Laziness and Dietrich Gebert's Ponytail philosophy:
"The best code is the code you never wrote."

Detects:
- LAZY-001 (Dependency Bloat): Unnecessary new dependencies added to package.json / pyproject.toml / requirements.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from guard.core.ocr_engine import DiffSummary, FileDiffStat, RuleViolation


# Known redundant npm packages easily replaced by native modern JS/TS runtime APIs
REDUNDANT_NPM_PACKAGES = {
    "is-odd": "Replace with `n % 2 !== 0`",
    "is-even": "Replace with `n % 2 === 0`",
    "left-pad": "Replace with native `str.padStart()`",
    "uuid": "Replace with native `crypto.randomUUID()`",
    "mkdirp": "Replace with native `fs.mkdirSync(path, { recursive: true })`",
    "rimraf": "Replace with native `fs.rmSync(path, { recursive: true, force: true })`",
    "node-fetch": "Replace with native global `fetch()`",
    "cross-fetch": "Replace with native global `fetch()`",
    "query-string": "Replace with native `new URLSearchParams()`",
    "lodash.get": "Replace with native optional chaining `obj?.prop?.sub`",
    "lodash.has": "Replace with `prop in obj` or `Object.hasOwn(obj, prop)`",
    "chalk": "Use standard ANSI terminal escape sequences or modern lightweight styling",
}

# Known redundant Python packages replaced by standard library
REDUNDANT_PY_PACKAGES = {
    "pathlib2": "Replace with native standard library `pathlib`",
    "mock": "Replace with native standard library `unittest.mock`",
    "simplejson": "Replace with native standard library `json`",
    "pytz": "Replace with native standard library `zoneinfo` (Python 3.9+)",
    "six": "Remove obsolete Python 2/3 compatibility layer",
}


class SimplicityEngine:
    """
    Simplicity & Engineering Frugality (Productive Laziness) Gatekeeper.
    """

    def __init__(self, repo_path: Optional[Path] = None):
        self.repo_path = Path(repo_path or Path.cwd()).resolve()

    def calculate_net_loc(self, diff_summary: Optional[DiffSummary]) -> Dict[str, Any]:
        """
        Calculate Net Lines of Code (LOC) change.
        Rewarding net negative code (deleting more code than adding).
        """
        if not diff_summary:
            return {"net_loc": 0, "is_net_negative": False, "bonus_label": "Neutral"}

        insertions = diff_summary.total_insertions
        deletions = diff_summary.total_deletions
        net = insertions - deletions

        is_net_negative = (net < 0 and deletions >= 10)
        bonus_label = "Neutral"
        if is_net_negative:
            bonus_label = f"⭐ Code Debt Reduction Bonus (Net: {net:+d} LOC)"
        elif net > 500:
            bonus_label = f"⚠️ High Blast Radius (+{net} LOC)"

        return {
            "insertions": insertions,
            "deletions": deletions,
            "net_loc": net,
            "is_net_negative": is_net_negative,
            "bonus_label": bonus_label,
        }

    def scan_dependency_bloat(self, raw_diff: str) -> List[RuleViolation]:
        """
        LAZY-001: Scan diff in manifest files (package.json, pyproject.toml, requirements.txt)
        to catch unnecessary new dependencies when native or stdlib suffices.
        """
        violations: List[RuleViolation] = []
        current_file = ""

        for line in raw_diff.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()
                continue

            if not (line.startswith("+") and not line.startswith("+++")):
                continue

            added_content = line[1:].strip().lower()
            cf_lower = current_file.replace("\\", "/").lower()

            # Check package.json additions
            if cf_lower.endswith("package.json"):
                for pkg, rec in REDUNDANT_NPM_PACKAGES.items():
                    if f'"{pkg}"' in added_content or f"'{pkg}'" in added_content:
                        violations.append(RuleViolation(
                            rule_id="LAZY-001",
                            severity="HIGH",
                            file_path=current_file,
                            message=f"Dependency Bloat: Added redundant npm package `{pkg}`. {rec}.",
                            snippet=line[1:].strip()[:80],
                        ))

            # Check pyproject.toml / requirements.txt additions
            elif cf_lower.endswith("pyproject.toml") or "requirements" in cf_lower:
                for pkg, rec in REDUNDANT_PY_PACKAGES.items():
                    if re.search(rf"""(?i)\b{re.escape(pkg)}\b""", added_content):
                        violations.append(RuleViolation(
                            rule_id="LAZY-001",
                            severity="HIGH",
                            file_path=current_file,
                            message=f"Dependency Bloat: Added redundant Python package `{pkg}`. {rec}.",
                            snippet=line[1:].strip()[:80],
                        ))

        return violations

    def scan_diff_level(self, raw_diff: Optional[str], diff_summary: Optional[DiffSummary]) -> List[RuleViolation]:
        """
        Level 1: Fast commit-level check (Diff-level, <50ms).
        Detects dependency bloat in added diff lines.
        """
        diff_text = raw_diff or ""
        return self.scan_dependency_bloat(diff_text)

    def scan_focus_level(self, touched_files: List[str]) -> List[RuleViolation]:
        """
        Level 2: Deep focus check (Full-file scope) for `--focus simplicity` / `--focus yagni`.
        Returns deterministic simplicity violations if any.
        """
        return []
