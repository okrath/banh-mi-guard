"""
Pre-Analysis for Banh-Mi-Guard: Domain and Baseline Contracts via LLM.

Executes a single combined LLM call at `guard pre` to determine:
- task domain
- repo domain
- reasoning
- contracts that callers rely on (API endpoints, UI states, schemas, etc.)

With caching in `.guard/pre-analysis-cache.json` and graceful fallback to
`score_repo_domain` when the LLM is not configured or fails.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Tuple

import httpx

from guard.core.config import GuardConfig
from guard.core.invariant_eval import DomainType
from guard.core.llm_client import LLMClientError, call_llm
from guard.core.session import DomainContract
from guard.domains.detector import (
    SKIP_DIRS,
    _node_manifest_signals,
    _package_manifests,
    score_repo_domain,
)

PRE_ANALYSIS_CACHE = "pre-analysis-cache.json"
MAX_TOTAL_FILE_CHARS = 40_000
MAX_PER_FILE_CHARS = 8_000
MAX_TREE_LINES = 300
MAX_MANIFEST_LINES = 60
MAX_MANIFEST_LINE_CHARS = 400
MAX_MANIFEST_DEPS = 60
MAX_PROMPT_CHARS = 4_000
MAX_SCOPE_ENTRIES = 200
MAX_FILE_NOTES = 20

VALID_DOMAINS = {
    "frontend": DomainType.FRONTEND,
    "backend": DomainType.BACKEND,
    "fullstack": DomainType.FULLSTACK,
    "infra": DomainType.INFRA,
    "mobile": DomainType.MOBILE,
}

OTHER_MANIFEST_NAMES = [
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Gemfile",
    "composer.json",
    "pubspec.yaml",
    "Package.swift",
]


@dataclass
class PreAnalysis:
    task_domain: DomainType
    repo_domain: DomainType
    domain_source: str
    reason: str
    contracts: List[DomainContract]
    contracts_source: str


def _repo_tree_to_depth_2(repo: Path) -> List[str]:
    """Top-level repository tree to depth 2 with SKIP_DIRS applied."""
    lines: List[str] = []
    try:
        entries = sorted(repo.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    except OSError:
        return lines
    for e in entries:
        if e.name in SKIP_DIRS or e.name.startswith("."):
            continue
        if e.is_dir():
            lines.append(f"{e.name}/")
            try:
                sub_entries = sorted(e.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
                for sub in sub_entries:
                    if sub.name in SKIP_DIRS or sub.name.startswith("."):
                        continue
                    if sub.is_dir():
                        lines.append(f"  {sub.name}/")
                    else:
                        lines.append(f"  {sub.name}")
            except OSError:
                pass
        else:
            lines.append(e.name)
    return lines


def _manifest_signals(repo: Path) -> Tuple[List[str], List[str]]:
    """Manifest file names with dependency names. Returns (lines, notes)."""
    lines: List[str] = []
    notes: List[str] = []
    node_deps, _ = _node_manifest_signals(repo)
    node_files = _package_manifests(repo)
    if node_files:
        paths = [str(p.relative_to(repo)).replace("\\", "/") for p in node_files]
        sorted_deps = sorted(node_deps)
        if len(sorted_deps) > MAX_MANIFEST_DEPS:
            more = len(sorted_deps) - MAX_MANIFEST_DEPS
            dep_str = ", ".join(sorted_deps[:MAX_MANIFEST_DEPS]) + f", ... and {more} more"
            notes.append(f"dependencies cut to {MAX_MANIFEST_DEPS} of {len(sorted_deps)} names")
        elif sorted_deps:
            dep_str = ", ".join(sorted_deps)
        else:
            dep_str = "none"
        lines.append(f"package.json files ({', '.join(paths)}): dependencies: {dep_str}")

    found_other: List[str] = []
    for m in OTHER_MANIFEST_NAMES:
        if (repo / m).is_file():
            found_other.append(m)
    try:
        for entry in repo.iterdir():
            if entry.is_dir() and entry.name not in SKIP_DIRS and not entry.name.startswith("."):
                for m in OTHER_MANIFEST_NAMES:
                    if (entry / m).is_file():
                        found_other.append(f"{entry.name}/{m}")
    except OSError:
        pass
    if found_other:
        lines.append(f"Other manifest files: {', '.join(sorted(found_other))}")

    bounded_lines: List[str] = []
    for line in lines:
        if len(line) > MAX_MANIFEST_LINE_CHARS:
            orig_len = len(line)
            line = line[:MAX_MANIFEST_LINE_CHARS - 3] + "..."
            notes.append(f"manifest line cut to {MAX_MANIFEST_LINE_CHARS} of {orig_len} characters")
        bounded_lines.append(line)

    return bounded_lines, notes


def _format_impact(impact: Any) -> str:
    if not impact:
        return "Not available"
    lines: List[str] = []
    symbols = getattr(impact, "symbols", []) or []
    for s in symbols[:20]:
        caller_str = f", called by: {', '.join(s.references[:5])}" if getattr(s, "references", None) else ""
        lines.append(f"- {s.name} ({s.kind}) in {s.file}:{s.line}{caller_str}")
    if len(symbols) > 20:
        lines.append(f"... and {len(symbols) - 20} more symbols")
    return "\n".join(lines) if lines else "None detected"


def _scoped_files(repo: Path, scope: List[str]) -> Tuple[List[str], set]:
    """
    The files `--scope` names (files, directories or globs, as `expected_impact` reads them), and the set of
    those Git lists: tracked, or untracked and not ignored. Only listed files are ever read; a literal entry
    Git does not list (an ignored `.env`, a path outside the repository) is returned only to explain the skip.
    """
    from guard.core.diff_inspector import GitDiffInspector
    from guard.core.impact import _repo_files

    inspector = GitDiffInspector(repo)
    named = {e.replace("\\", "/").lstrip("./") for e in scope}
    # _is_expected always admits guard's own files and .gitignore (a task may touch them); they are not
    # the task's code, so they are sent only when the scope names them, and .guard/ never
    listed = {f for f in _repo_files(repo) if inspector._is_expected(f, scope)
              and not f.startswith(".guard/") and (f != ".gitignore" or f in named)}
    literal = [s for s in scope if not any(ch in s for ch in "*?[") and not (repo / s).is_dir()]
    return sorted(listed | set(literal)), listed


def _read_scoped_files(repo: Path, scope: List[str]) -> Tuple[str, List[str]]:
    """
    Read scoped files capped at MAX_TOTAL_FILE_CHARS total and MAX_PER_FILE_CHARS per file.
    Returns (formatted text, notes on cuts).
    """
    sections: List[str] = []
    notes: List[str] = []
    total_chars = 0

    resolved_repo = repo.resolve()

    candidates, listed = _scoped_files(repo, scope)
    for rel_path in candidates:
        if total_chars >= MAX_TOTAL_FILE_CHARS:
            notes.append(f"{rel_path} omitted: overall {MAX_TOTAL_FILE_CHARS} character budget reached")
            continue

        p_raw = Path(rel_path)
        if p_raw.is_absolute() or rel_path.startswith(("/", "\\")):
            notes.append(f"{rel_path} skipped: absolute path")
            continue

        p = repo / rel_path

        is_sym = False
        try:
            is_sym = p.is_symlink()
        except OSError:
            pass

        try:
            resolved_p = p.resolve()
            is_outside = not resolved_p.is_relative_to(resolved_repo)
        except (ValueError, OSError, AttributeError):
            is_outside = True

        if is_sym:
            if is_outside:
                notes.append(f"{rel_path} skipped: symlink pointing outside repository")
            else:
                notes.append(f"{rel_path} skipped: symlink")
            continue

        if is_outside:
            notes.append(f"{rel_path} skipped: outside repository")
            continue

        if not p.is_file():
            continue
        if rel_path.replace("\\", "/") not in listed:
            notes.append(f"{rel_path} skipped: ignored by Git or not in the repository")
            continue

        try:
            with open(p, "rb") as f_bin:
                first_chunk = f_bin.read(4096)
            if b"\x00" in first_chunk:
                notes.append(f"{rel_path} skipped: binary")
                continue
        except OSError:
            continue

        remaining_budget = MAX_TOTAL_FILE_CHARS - total_chars
        allowed = min(MAX_PER_FILE_CHARS, remaining_budget)
        try:
            file_size = p.stat().st_size
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(allowed + 1)
        except OSError:
            continue

        if len(content) > allowed:
            content = content[:allowed]
            notes.append(f"{rel_path} cut to {allowed} of {file_size} bytes")

        total_chars += len(content)
        sections.append(f"--- File: {rel_path} ---\n{content}\n")

    if len(notes) > MAX_FILE_NOTES:
        more = len(notes) - MAX_FILE_NOTES
        notes = notes[:MAX_FILE_NOTES] + [f"... and {more} more files skipped or cut"]

    return "\n".join(sections), notes


def build_pre_analysis_prompt(
    repo: Path,
    prompt: str,
    scope: List[str],
    impact: Any,
) -> Tuple[str, List[str]]:
    """Build user prompt for pre-analysis. Returns (prompt_text, cut_notes)."""
    notes: List[str] = []

    tree_lines = _repo_tree_to_depth_2(repo)
    if len(tree_lines) > MAX_TREE_LINES:
        more = len(tree_lines) - MAX_TREE_LINES
        notes.append(f"tree cut to {MAX_TREE_LINES} of {len(tree_lines)} lines")
        tree_lines = tree_lines[:MAX_TREE_LINES] + [f"... {more} more entries"]

    manifest_lines, manifest_notes = _manifest_signals(repo)
    notes.extend(manifest_notes)
    if len(manifest_lines) > MAX_MANIFEST_LINES:
        notes.append(f"manifests cut to {MAX_MANIFEST_LINES} of {len(manifest_lines)} lines")
        manifest_lines = manifest_lines[:MAX_MANIFEST_LINES]

    effective_scope = list(scope)
    if len(effective_scope) > MAX_SCOPE_ENTRIES:
        notes.append(f"scope list cut to {MAX_SCOPE_ENTRIES} of {len(effective_scope)} entries")
        effective_scope = effective_scope[:MAX_SCOPE_ENTRIES]
    scope_lines = [f"- {s} (ext: {Path(s).suffix or 'none'})" for s in effective_scope] or ["- none declared"]

    effective_prompt = prompt
    if len(effective_prompt) > MAX_PROMPT_CHARS:
        orig_len = len(effective_prompt)
        notes.append(f"task text cut to {MAX_PROMPT_CHARS} of {orig_len} characters")
        effective_prompt = effective_prompt[:MAX_PROMPT_CHARS]

    file_contents, file_notes = _read_scoped_files(repo, effective_scope)
    notes.extend(file_notes)
    impact_text = _format_impact(impact)

    user_prompt = f"""Repository Snapshot:
Tree (depth 2):
{chr(10).join(tree_lines) if tree_lines else "Empty"}

Manifests:
{chr(10).join(manifest_lines) if manifest_lines else "None"}

Declared Scope:
{chr(10).join(scope_lines)}

Task Request:
{effective_prompt}

Expected Impact Range (symbols and callers):
{impact_text}

Scoped Files Content (capped at at most {MAX_TOTAL_FILE_CHARS} chars in total, {MAX_PER_FILE_CHARS} per file):
{file_contents if file_contents else "(No scoped files content)"}
"""
    return user_prompt, notes

SYSTEM_PROMPT = """You are Banh-Mi-Guard Pre-Analysis Gate.
Analyze the repository snapshot, declared scope, task request, expected impact range, and scoped files content.
Determine:
1. TASK_DOMAIN: The technical domain of THIS TASK (frontend|backend|fullstack|infra|mobile).
2. REPO_DOMAIN: The technical domain of the overall repository (frontend|backend|fullstack|infra|mobile).
3. REASON: Exactly one line explaining why.
4. CONTRACTS: Contracts what callers rely on (public functions, CLI commands with callers, endpoints and response shapes, schemas, UI states).

Output format must be EXACTLY:
TASK_DOMAIN: frontend|backend|fullstack|infra|mobile
REPO_DOMAIN: frontend|backend|fullstack|infra|mobile
REASON: <one line>
CONTRACTS:
- CATEGORY | name | file:symbol | description

If there are no contracts, output:
CONTRACTS:
- none
"""


def _own_guard_dir(guard_dir: Path) -> bool:
    """`.guard` is a real folder directly inside its repository, not a symlink or junction leading elsewhere."""
    try:
        if guard_dir.is_symlink():
            return False
        if not guard_dir.exists():
            return True  # created below, inside the repository
        return guard_dir.resolve().parent == guard_dir.parent.resolve()
    except OSError:
        return False


def _load_cache(guard_dir: Path, key: str) -> Optional[str]:
    cache_file = guard_dir / PRE_ANALYSIS_CACHE
    if not _own_guard_dir(guard_dir):
        return None
    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("key") == key:
            return data.get("raw_response")
    except (OSError, ValueError):
        pass
    return None


def _save_cache(guard_dir: Path, key: str, raw_response: str) -> None:
    cache_file = guard_dir / PRE_ANALYSIS_CACHE
    if not _own_guard_dir(guard_dir):
        return  # a .guard that leads outside the repository is never written through
    try:
        guard_dir.mkdir(parents=True, exist_ok=True)
        # a fresh, exclusively created temp file: a path the repository planted (a symlink) is never written
        fd, tmp = tempfile.mkstemp(dir=guard_dir, prefix=".pre-analysis-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"key": key, "raw_response": raw_response}, f)
            os.replace(tmp, cache_file)  # replaces a link at cache_file itself, never its target
        except OSError:
            Path(tmp).unlink(missing_ok=True)
            raise
    except OSError:
        pass


def _parse_llm_response(text: str) -> Tuple[Optional[DomainType], Optional[DomainType], Optional[str], List[DomainContract], int, bool]:
    task_domain: Optional[DomainType] = None
    repo_domain: Optional[DomainType] = None
    reason: Optional[str] = None
    contracts: List[DomainContract] = []
    malformed_count = 0
    in_contracts = False
    has_contracts_section = False
    contract_lines_count = 0
    none_count = 0

    task_domain_count = 0
    repo_domain_count = 0
    reason_count = 0
    contracts_count = 0

    headers = ("TASK_DOMAIN:", "REPO_DOMAIN:", "REASON:", "CONTRACTS:")

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        upper = line.upper()
        if not in_contracts:
            if upper.startswith("TASK_DOMAIN:"):
                task_domain_count += 1
                if task_domain_count > 1:
                    malformed_count += 1
                val = line.split(":", 1)[1].strip().lower()
                task_domain = VALID_DOMAINS.get(val)
                if task_domain is None:
                    malformed_count += 1
            elif upper.startswith("REPO_DOMAIN:"):
                repo_domain_count += 1
                if repo_domain_count > 1:
                    malformed_count += 1
                val = line.split(":", 1)[1].strip().lower()
                repo_domain = VALID_DOMAINS.get(val)
                if repo_domain is None:
                    malformed_count += 1
            elif upper.startswith("REASON:"):
                reason_count += 1
                if reason_count > 1:
                    malformed_count += 1
                r_val = line.split(":", 1)[1].strip()
                if r_val:
                    reason = r_val
                else:
                    malformed_count += 1
            elif upper.startswith("CONTRACTS:"):
                contracts_count += 1
                if upper != "CONTRACTS:":
                    malformed_count += 1  # text after the header: not the format asked for
                in_contracts = True
                has_contracts_section = True
                if task_domain_count != 1 or repo_domain_count != 1 or reason_count != 1:
                    malformed_count += 1
            else:
                malformed_count += 1
        else:
            check_line = line[1:].strip() if line.startswith("-") else line
            check_upper = check_line.upper()
            if any(check_upper.startswith(h) for h in headers):
                malformed_count += 1
                continue
            contract_lines_count += 1
            if not line.startswith("-"):
                malformed_count += 1
                continue
            item = line[1:].strip()
            if item.lower() == "none":
                none_count += 1
                continue
            parts = [p.strip() for p in item.split("|", 3)]
            if len(parts) == 4 and all(parts):
                cat, name, file_sym, desc = parts
                full_desc = f"[{file_sym}] {desc}"
                contracts.append(DomainContract(
                    category=cat,
                    name=name,
                    description=full_desc,
                ))
            else:
                malformed_count += 1

    if (
        not has_contracts_section
        or task_domain_count != 1
        or repo_domain_count != 1
        or reason_count != 1
        or contracts_count != 1
    ):
        malformed_count += 1

    if in_contracts and contract_lines_count == 0:
        malformed_count += 1
    if none_count > 0 and contract_lines_count != 1:
        malformed_count += 1

    return task_domain, repo_domain, reason, contracts, malformed_count, has_contracts_section


def _heuristic_fallback(repo: Path, reason: str) -> PreAnalysis:
    heuristic_dom, _, _ = score_repo_domain(repo)
    return PreAnalysis(
        task_domain=heuristic_dom,
        repo_domain=heuristic_dom,
        domain_source=f"heuristic: {reason}",
        reason=reason,
        contracts=[],
        contracts_source=f"not extracted ({reason})",
    )


def _pre_analysis_cache_key(
    system_prompt: str,
    user_prompt: str,
    config: GuardConfig,
) -> str:
    protocol = str(getattr(config.llm.protocol, "value", config.llm.protocol) or "")
    model = str(config.llm.model or "")
    cli_agent = str(config.llm.cli_agent or "")
    hasher = hashlib.sha256()
    hasher.update(system_prompt.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(user_prompt.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(protocol.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(model.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(cli_agent.encode("utf-8"))
    return hasher.hexdigest()


def analyze_task(
    repo: Path,
    prompt: str,
    scope: List[str],
    impact: Any,
    config: GuardConfig,
) -> PreAnalysis:
    """Analyze domain and baseline contracts using LLM with heuristic fallback and caching."""
    if not getattr(config.llm, "ready", False):
        return _heuristic_fallback(repo, "LLM not configured")

    user_prompt, notes = build_pre_analysis_prompt(repo, prompt, scope, impact)
    cache_key = _pre_analysis_cache_key(SYSTEM_PROMPT, user_prompt, config)
    guard_dir = repo / ".guard"

    raw_response = _load_cache(guard_dir, cache_key)
    from_cache = raw_response is not None
    if raw_response is None:
        try:
            raw_response = call_llm(
                config.llm,
                prompt=user_prompt,
                system_prompt=SYSTEM_PROMPT,
                temperature=0.0,
            )
        except (LLMClientError, httpx.HTTPError, OSError, subprocess.SubprocessError) as e:
            err_msg = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
            return _heuristic_fallback(repo, err_msg)

    try:
        task_domain, repo_domain, reason, contracts, malformed_count, has_contracts_section = _parse_llm_response(raw_response)
        if (
            task_domain is None
            or repo_domain is None
            or not reason
            or not has_contracts_section
            or malformed_count > 0
        ):
            return _heuristic_fallback(repo, "unparsable answer")
    except (ValueError, TypeError, AttributeError, IndexError, KeyError):
        return _heuristic_fallback(repo, "unparsable answer")

    if not from_cache:
        _save_cache(guard_dir, cache_key, raw_response)

    contracts_source = f"LLM (input capped: {'; '.join(notes)})" if notes else "LLM"

    return PreAnalysis(
        task_domain=task_domain,
        repo_domain=repo_domain,
        domain_source="LLM",
        reason=reason,
        contracts=contracts,
        contracts_source=contracts_source,
    )
