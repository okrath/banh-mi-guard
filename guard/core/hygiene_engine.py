"""
Hygiene & Dead Code Engine — Pillar for Clean, Maintainable AI-Assisted Codebases.
Detects:
1. Orphan & Draft Files (DEAD-001): Added files not referenced or matching draft/scratchpad patterns.

Supports two tiers of analysis:
- Commit-level (Diff-level): Sub-50ms check on newly created files.
- Focus-level (Full-file): Check on touched files when `--focus dead-code`.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Optional

from guard.core.code_text import CODE
from guard.core.ocr_engine import DiffSummary, RuleViolation

SEARCH_EXTENSIONS = CODE + (
    ".json", ".yaml", ".yml", ".toml", ".xml",
    ".gradle", ".kts", ".csproj", ".html", ".vue", ".svelte", ".erb",
)


# File patterns that are legitimate entry points or configs and should not be flagged as orphan
DOC_SUFFIXES = (".md", ".mdx", ".rst", ".txt", ".adoc")
DEFAULT_ENTRYPOINT_PATTERNS = [
    # Top-level & documentation
    r"^README(\..+)?$",
    r"^LICENSE(\..+)?$",
    r"^CHANGELOG(\..+)?$",
    r"^\.gitignore$",
    r"^\.env(\..+)?$",
    r"^guard\.invariants\.json$",  # Read by guard itself, never imported by project code
    r"^pyproject\.toml$",
    r"^setup\.(py|cfg)$",
    r"^package(\-lock)?\.json$",
    r"^tsconfig(\..+)?\.json$",
    r"^vite\.config\.[jt]s$",
    r"^next\.config\.[jt]s$",
    r"^webpack\.config\.[jt]s$",
    r"^docker-compose.*\.ya?ml$",
    r"^Dockerfile.*$",
    r"^Makefile$",
    r"^Cargo\.(toml|lock)$",
    r"^go\.(mod|sum)$",
    r"^\.github/.*",
    r"^docs/.*",
    # Framework application entry points
    r"(^|/)main\.(py|go|rs|ts|js)$",
    r"(^|/)app\.(py|ts|js|jsx|tsx)$",
    r"(^|/)index\.(html|ts|js|jsx|tsx)$",
    r"(^|/)__init__\.py$",
    r"(^|/)__main__\.py$",
    r"(^|/)cli\.(py|ts|js)$",
    r"(^|/)wsgi\.py$",
    r"(^|/)asgi\.py$",
    r"(^|/)manage\.py$",
    # Web routes & pages
    r"(^|/)pages/.*",
    r"(^|/)app/.*",
    r"(^|/)routes/.*",
    # Test suites & fixtures
    r"(^|/)tests?/.*",
    r"(^|/)test_.*\.py$",
    r"(^|/).*_test\.(py|go|rs|ts|js)$",
    r"(^|/).*\.(test|spec)\.(ts|js|jsx|tsx)$",
    r"(^|/)conftest\.py$",
]

# Obvious draft, scratchpad, or temporary backup file patterns
JUNK_FILE_REGEX = re.compile(
    r"""(?i)(^|/)(temp_|_temp|test_scratch|scratchpad|.*\.backup\.|.*\.bak$|.*\.tmp$|.*\.swp$|copy_of_)"""
)


class HygieneEngine:
    """
    Code & Asset Hygiene Gatekeeper for catching dead code and orphan files.
    """

    def __init__(self, repo_path: Optional[Path] = None):
        self.repo_path = Path(repo_path or Path.cwd()).resolve()

    def is_entrypoint_or_whitelisted(self, file_path: str) -> bool:
        norm = file_path.replace("\\", "/").strip("/")
        # Documentation is read, not imported: it is never an orphan
        if norm.lower().endswith(DOC_SUFFIXES) or norm.lower().startswith("docs/") or "/docs/" in norm.lower():
            return True
        for pat in DEFAULT_ENTRYPOINT_PATTERNS:
            if re.search(pat, norm, re.IGNORECASE):
                return True
        return False

    def is_junk_filename(self, file_path: str) -> bool:
        norm = file_path.replace("\\", "/").strip("/")
        return bool(JUNK_FILE_REGEX.search(norm))

    def is_file_referenced_in_repo(self, target_file: str, max_files: int = 500) -> bool:
        """
        Check if the file stem or relative path is imported or referenced across the repo.
        """
        p = Path(target_file)
        stem = p.stem
        # If stem is too generic (like "utils" or "helpers"), use path parts
        target_token = stem
        if stem in ("index", "utils", "helper", "common", "mod", "lib"):
            parts = p.parts
            target_token = parts[-2] if len(parts) >= 2 else stem

        if not target_token or len(target_token) < 3:
            return True  # Avoid false positives for very short names

        scanned = 0
        norm_target = target_file.replace("\\", "/").lower()

        for root, dirs, files in os.walk(str(self.repo_path)):
            # Skip VCS and vendor dirs
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "venv", "__pycache__", ".guard", "dist", "build")]
            for f in files:
                scanned += 1
                if scanned > max_files:
                    return True  # Timeout/budget safety: assume referenced if repo is huge

                fpath = Path(root) / f
                rel_fpath = str(fpath.relative_to(self.repo_path)).replace("\\", "/").lower()
                if rel_fpath == norm_target:
                    continue  # Don't check the file itself

                # Only search code and config files
                if not any(f.endswith(ext) for ext in SEARCH_EXTENSIONS):
                    continue

                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    if target_token in content or stem in content:
                        return True
                    # Go imports a package by its directory: a Go file is used when a Go import path ends in it
                    if norm_target.endswith(".go") and f.endswith(".go") and p.parent.name \
                            and f'/{p.parent.name}"' in content:
                        return True
                except (OSError, UnicodeDecodeError):
                    continue
        return False

    def check_orphan_file(self, file_path: str) -> Optional[RuleViolation]:
        """
        Verify if a newly created file is junk or an unreferenced orphan.
        """
        if self.is_junk_filename(file_path):
            return RuleViolation(
                rule_id="DEAD-001",
                severity="HIGH",
                file_path=file_path,
                line_number=None,
                message="Temporary or scratchpad draft file detected. Delete before commit.",
                snippet=f"File: {file_path}",
            )

        if self.is_entrypoint_or_whitelisted(file_path):
            return None

        # Check if imported/referenced in repository
        if not self.is_file_referenced_in_repo(file_path):
            return RuleViolation(
                rule_id="DEAD-001",
                severity="MEDIUM",
                file_path=file_path,
                line_number=None,
                message="Orphan file: Newly added file is never imported or referenced in codebase.",
                snippet=f"File: {file_path}",
            )

        return None

    def scan_diff_level(self, raw_diff: Optional[str], diff_summary: Optional[DiffSummary]) -> List[RuleViolation]:
        """
        Level 1: Fast commit-level check (Diff-level).
        Operates on newly added files for orphan / scratchpad status.
        """
        violations: List[RuleViolation] = []
        if diff_summary:
            for f in diff_summary.files:
                if f.status == "added":
                    viol = self.check_orphan_file(f.path)
                    if viol:
                        violations.append(viol)
        return violations

    def scan_focus_level(self, touched_files: List[str]) -> List[RuleViolation]:
        """
        Level 2: Focus check for `--focus dead-code`.
        Scans touched files for orphan or draft status.
        """
        violations: List[RuleViolation] = []
        for rel_path in touched_files:
            abs_path = self.repo_path / rel_path
            if not abs_path.is_file():
                continue
            orphan_viol = self.check_orphan_file(rel_path)
            if orphan_viol:
                violations.append(orphan_viol)
        return violations
