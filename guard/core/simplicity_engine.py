"""
Simplicity & Engineering Frugality Engine — The "Productive Laziness" (KISS & YAGNI) Pillar.
Inspired by Larry Wall's virtue of Laziness and Dietrich Gebert's Ponytail philosophy:
"The best code is the code you never wrote."

Detects:
- LAZY-001 (Dependency Bloat): Unnecessary new dependencies added to package.json / pyproject.toml / requirements /
  go.mod / Cargo.toml / pom.xml / build.gradle(.kts) / composer.json / *.csproj.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from guard.core.ocr_engine import DiffSummary, RuleViolation
from guard.core.unified_diff import walk_diff

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

# Packages of other ecosystems that the standard library replaces; only uncontroversial ones, where the
# package itself points to the replacement. Gemfile, pubspec.yaml and Package.swift list none yet
REDUNDANT_GO_PACKAGES = {
    "github.com/pkg/errors": "Replace with the standard library `errors` and `fmt.Errorf` with `%w` (Go 1.13+)",
}

REDUNDANT_CARGO_PACKAGES = {
    "lazy_static": "Replace with the standard library `std::sync::LazyLock` (Rust 1.80+)",
    "once_cell": "Replace with the standard library `std::sync::OnceLock` / `LazyLock` (Rust 1.70+ / 1.80+)",
}

REDUNDANT_JVM_PACKAGES = {
    "joda-time": "Replace with the standard library `java.time` (Java 8+), as Joda-Time itself advises",
}

REDUNDANT_COMPOSER_PACKAGES = {
    "paragonie/random_compat": "Replace with the built-in `random_bytes()` / `random_int()` (PHP 7+)",
}

REDUNDANT_NUGET_PACKAGES = {
    "System.ValueTuple": "Remove: value tuples are built into .NET Core / .NET 5+ and .NET Framework 4.7+",
}

# (manifest test, ecosystem label, packages, quoted): the first manifest that matches the file is checked;
# a quoted manifest (JSON) names a package only in quotes, so prose in "description" does not count
MANIFESTS = (
    (lambda f: f.endswith("package.json"), "npm", REDUNDANT_NPM_PACKAGES, True),
    (lambda f: f.endswith("pyproject.toml") or "requirements" in f, "Python", REDUNDANT_PY_PACKAGES, False),
    (lambda f: f.endswith("go.mod"), "Go", REDUNDANT_GO_PACKAGES, False),
    (lambda f: f.endswith("cargo.toml"), "Cargo", REDUNDANT_CARGO_PACKAGES, False),
    (lambda f: f.endswith(("pom.xml", "build.gradle", "build.gradle.kts")), "Java/Kotlin", REDUNDANT_JVM_PACKAGES, False),
    (lambda f: f.endswith("composer.json"), "PHP", REDUNDANT_COMPOSER_PACKAGES, True),
    (lambda f: f.endswith(".csproj"), ".NET", REDUNDANT_NUGET_PACKAGES, False),
    (lambda f: f.endswith(("gemfile", "pubspec.yaml", "package.swift")), "", {}, False),
)


def _names_package(content: str, pkg: str, quoted: bool) -> bool:
    """`pkg` as a whole package name: `argparse` is not `argparse-manpage`, `mock` is not `pytest-mock`."""
    # `(?<=dependencies\.)`: Cargo's table form `[dependencies.once_cell]`
    name = rf"[\"']{re.escape(pkg)}[\"']" if quoted \
        else rf"(?:(?<=dependencies\.)|(?<![\w.\-/@])){re.escape(pkg)}(?![\w.\-/])"
    return re.search(name, content, re.IGNORECASE) is not None


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
        LAZY-001: Scan diff in manifest files (package.json, pyproject.toml, requirements*, go.mod, Cargo.toml,
        pom.xml, build.gradle(.kts), composer.json, *.csproj, Gemfile, pubspec.yaml, Package.swift)
        to catch unnecessary new dependencies when native or stdlib suffices.
        """
        violations: List[RuleViolation] = []
        for d in walk_diff(raw_diff):
            if d.kind != "+":
                continue

            current_file = d.path
            added_content = d.text.strip()
            cf_lower = current_file.replace("\\", "/").lower()
            manifest = next((m[1:] for m in MANIFESTS if m[0](cf_lower)), None)
            if not manifest or (cf_lower.endswith("go.mod") and added_content.endswith("// indirect")):
                continue  # an `// indirect` module is a dependency of a dependency, not the author's choice
            label, packages, quoted = manifest
            for pkg, rec in packages.items():
                if _names_package(added_content, pkg, quoted):
                    violations.append(RuleViolation(
                        rule_id="LAZY-001",
                        severity="HIGH",
                        file_path=current_file,
                        message=f"Dependency Bloat: Added redundant {label} package `{pkg}`. {rec}.",
                        snippet=added_content[:80],
                    ))

        return violations

    def scan_diff_level(self, raw_diff: Optional[str], diff_summary: Optional[DiffSummary]) -> List[RuleViolation]:
        """
        Level 1: Fast commit-level check (Diff-level, <50ms).
        Detects dependency bloat in added diff lines.
        """
        diff_text = raw_diff or ""
        return self.scan_dependency_bloat(diff_text)
