"""
Hygiene & Dead Code Engine — Pillar for Clean, Maintainable AI-Assisted Codebases.
Detects:
1. Orphan & Draft Files (DEAD-001): Added files not referenced or matching draft/scratchpad patterns.
2. Commented-out Code (DEAD-002): Stale blocks of commented source code instead of clean deletions.
3. Unused Local Symbols & Imports (DEAD-003): Unreferenced private helpers or unused imported symbols.

Supports two tiers of analysis:
- Commit-level (Diff-level): Sub-50ms check on added lines & newly created files.
- Focus-level (Full-file): Deep-scan across entire file contents and AST when `--focus dead-code`.
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path
from typing import List, Optional, Set

from guard.core.ocr_engine import DiffSummary, FileDiffStat, RuleViolation


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

# Code markers indicating commented-out source code rather than prose comments
CODE_MARKERS = [
    # JS / TS
    "const ", "let ", "var ", "function ", "return ", "import ", "export ",
    "if (", "} else {", ");", "=>", "class ", "await ", "async ",
    # Python
    "def ", "class ", "import ", "from ", "return ", "self.", "elif ",
    "except ", "print(", "raise ",
]


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
                if not any(f.endswith(ext) for ext in (".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".toml", ".html")):
                    continue

                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    if target_token in content or stem in content:
                        return True
                except Exception:
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

    def scan_commented_code_lines(self, lines: List[str], file_path: str, start_line: int = 1) -> List[RuleViolation]:
        """
        Detect consecutive commented-out code blocks (3+ lines containing code syntax).
        """
        violations: List[RuleViolation] = []
        current_block: List[str] = []
        block_start = 0

        for idx, raw_line in enumerate(lines):
            line = raw_line.strip()
            is_comment = False
            comment_content = ""

            if line.startswith("//") or line.startswith("#"):
                is_comment = True
                comment_content = line.lstrip("/# ").strip()
            elif line.startswith("/*") and line.endswith("*/"):
                is_comment = True
                comment_content = line[2:-2].strip()

            has_code_marker = False
            if is_comment and comment_content:
                has_code_marker = any(marker in comment_content for marker in CODE_MARKERS) or (
                    comment_content.endswith(";") or comment_content.endswith("{")
                )

            if is_comment and has_code_marker:
                if not current_block:
                    block_start = start_line + idx
                current_block.append(line)
            else:
                if len(current_block) >= 3:
                    violations.append(RuleViolation(
                        rule_id="DEAD-002",
                        severity="MEDIUM",
                        file_path=file_path,
                        line_number=block_start,
                        message=f"Commented-out code block ({len(current_block)} lines). Prefer clean Git deletion instead of leaving zombie code.",
                        snippet=current_block[0][:80],
                    ))
                current_block = []

        if len(current_block) >= 3:
            violations.append(RuleViolation(
                rule_id="DEAD-002",
                severity="MEDIUM",
                file_path=file_path,
                line_number=block_start,
                message=f"Commented-out code block ({len(current_block)} lines). Prefer clean Git deletion instead of leaving zombie code.",
                snippet=current_block[0][:80],
            ))

        return violations

    def scan_python_unused_symbols(self, code_str: str, file_path: str) -> List[RuleViolation]:
        """
        Use Python AST to find unused private functions or unused imported symbols.
        """
        violations: List[RuleViolation] = []
        try:
            tree = ast.parse(code_str)
        except Exception:
            return violations

        # 1. Private helper functions `_foo`
        defined_private_funcs: dict[str, int] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("_") and not node.name.startswith("__"):
                    defined_private_funcs[node.name] = node.lineno

        # Count references in AST
        name_counts: dict[str, int] = {name: 0 for name in defined_private_funcs}
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in name_counts:
                name_counts[node.id] += 1
            elif isinstance(node, ast.Attribute) and node.attr in name_counts:
                name_counts[node.attr] += 1

        for name, count in name_counts.items():
            # count == 0 means no references exist
            if count == 0:
                violations.append(RuleViolation(
                    rule_id="DEAD-003",
                    severity="MEDIUM",
                    file_path=file_path,
                    line_number=defined_private_funcs[name],
                    message=f"Unused private helper function `{name}` defined but never called in file.",
                    snippet=f"def {name}(...)",
                ))

        # 2. Unused imports (skip __init__.py and files with __all__)
        is_init = file_path.replace("\\", "/").endswith("__init__.py")
        if not is_init:
            imported_symbols: dict[str, int] = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        symbol = alias.asname or alias.name
                        if "." not in symbol:
                            imported_symbols[symbol] = node.lineno
                elif isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        if alias.name != "*":
                            symbol = alias.asname or alias.name
                            imported_symbols[symbol] = node.lineno

            import_counts: dict[str, int] = {name: 0 for name in imported_symbols}
            has_all = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    if node.id == "__all__":
                        has_all = True
                    if node.id in import_counts:
                        import_counts[node.id] += 1

            if not has_all:
                for sym, count in import_counts.items():
                    if count == 0:
                        violations.append(RuleViolation(
                            rule_id="DEAD-003",
                            severity="LOW",
                            file_path=file_path,
                            line_number=imported_symbols[sym],
                            message=f"Unused imported symbol `{sym}`.",
                            snippet=f"import ... {sym}",
                        ))

        return violations

    def scan_diff_level(self, raw_diff: Optional[str], diff_summary: Optional[DiffSummary]) -> List[RuleViolation]:
        """
        Level 1: Fast commit-level check (Diff-level).
        Operates only on newly added files and added lines (`+`).
        """
        violations: List[RuleViolation] = []
        diff_text = raw_diff or ""

        # Check newly added files for orphan / scratchpad status
        if diff_summary:
            for f in diff_summary.files:
                if f.status == "added":
                    viol = self.check_orphan_file(f.path)
                    if viol:
                        violations.append(viol)

        # Check added lines for commented-out code (excluding test and doc files)
        current_file = ""
        current_added_lines: List[str] = []
        line_num = 0
        block_start_line = 0

        def _flush_added_lines(lines_to_flush: List[str], target_f: str, start_l: int):
            if not target_f or not lines_to_flush:
                return
            tf_lower = target_f.replace("\\", "/").lower()
            is_doc = any(tf_lower.endswith(ext) for ext in (".md", ".markdown", ".txt", ".rst"))
            is_test = "tests/" in tf_lower or "test_" in tf_lower or "/test/" in tf_lower
            if not is_doc and not is_test:
                violations.extend(self.scan_commented_code_lines(lines_to_flush, target_f, start_line=start_l))

        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                if current_file and current_added_lines:
                    _flush_added_lines(current_added_lines, current_file, block_start_line)
                    current_added_lines = []
                current_file = line[6:].strip()
                line_num = 0
                continue

            if line.startswith("@@"):
                match = re.search(r"\+(\d+)", line)
                if match:
                    line_num = int(match.group(1)) - 1
                continue

            if line.startswith("+") and not line.startswith("+++"):
                line_num += 1
                if not current_added_lines:
                    block_start_line = line_num
                current_added_lines.append(line[1:])
            else:
                if current_file and current_added_lines:
                    _flush_added_lines(current_added_lines, current_file, block_start_line)
                    current_added_lines = []

        if current_file and current_added_lines:
            _flush_added_lines(current_added_lines, current_file, block_start_line)

        return violations

    def scan_focus_level(self, touched_files: List[str]) -> List[RuleViolation]:
        """
        Level 2: Deep focus check (Full-file scope) for `--focus dead-code`.
        Scans entire files for orphan files, full commented blocks, and AST unused helpers.
        """
        violations: List[RuleViolation] = []

        for rel_path in touched_files:
            abs_path = self.repo_path / rel_path
            if not abs_path.is_file():
                continue

            # Check orphan status
            orphan_viol = self.check_orphan_file(rel_path)
            if orphan_viol:
                violations.append(orphan_viol)

            try:
                content = abs_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            rp_lower = rel_path.replace("\\", "/").lower()
            is_doc = any(rp_lower.endswith(ext) for ext in (".md", ".markdown", ".txt", ".rst"))
            is_test = "tests/" in rp_lower or "test_" in rp_lower or "/test/" in rp_lower

            if not is_doc and not is_test:
                # 1. Full commented-out code check across whole file
                file_lines = content.splitlines()
                violations.extend(self.scan_commented_code_lines(file_lines, rel_path, start_line=1))

                # 2. Unused AST helper functions for Python
                if rel_path.endswith(".py"):
                    violations.extend(self.scan_python_unused_symbols(content, rel_path))

        return violations
