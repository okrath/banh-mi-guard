"""
Unit tests for error-handling audit and error paths.
Verifies that failures on gate paths surface as failed checks, findings, or recorded error reasons,
and never silently pass.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from guard.core.config import GuardConfig, load_config
from guard.core.diff_inspector import DiffSummary, GitDiffInspector
from guard.core.llm_client import LLMClientError
from guard.core.llm_reviewer import LLMReviewerEngine
from guard.core.removal_check import check_removed_symbols
from guard.domains.pre_analysis import analyze_task


SAMPLE_REMOVAL_DIFF = """diff --git a/src/app.ts b/src/app.ts
--- a/src/app.ts
+++ b/src/app.ts
@@ -10,2 +10,1 @@
-export function calculateTax(rate: number): number {
-    return rate * 0.1;
-}
+export function calculateTotal(): number {
"""


def test_removal_check_git_ls_files_error_surfaces_violation(tmp_path):
    """Rule 1: If git ls-files fails during removal check, failure surfaces as a HIGH DEAD-REF violation."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 128
        mock_proc.stdout = ""
        mock_proc.stderr = "fatal: not a git repository"
        mock_run.return_value = mock_proc

        violations, summary = check_removed_symbols(repo, SAMPLE_REMOVAL_DIFF)

    assert len(violations) >= 1
    assert any(v.rule_id == "DEAD-REF" for v in violations)
    assert any(v.severity == "HIGH" for v in violations)
    assert "Removal check could not verify removed symbols" in violations[0].message
    assert "failed" in summary.lower()


def test_removal_check_file_read_error_surfaces_violation(tmp_path):
    """Rule 1: If an individual file cannot be read, failure surfaces as a HIGH DEAD-REF violation and error note in summary."""
    repo = tmp_path / "repo"
    repo.mkdir()
    code_file = repo / "src" / "index.ts"
    code_file.parent.mkdir(parents=True)
    code_file.write_text("import { calculateTax } from './app';\n", encoding="utf-8")

    with patch("guard.core.removal_check._repo_files", return_value=[code_file]):
        with patch.object(Path, "read_text", side_effect=OSError("Permission denied")):
            violations, summary = check_removed_symbols(repo, SAMPLE_REMOVAL_DIFF)

    assert len(violations) >= 1
    assert any(v.rule_id == "DEAD-REF" for v in violations)
    assert any("could not read" in v.message for v in violations)
    assert "unreadable files: 1" in summary


def test_removal_check_empty_diff_returns_clean(tmp_path):
    """A diff with no removed symbols returns clean with no violations."""
    clean_diff = """diff --git a/a.ts b/a.ts
--- a/a.ts
+++ b/a.ts
@@ -1,1 +1,2 @@
+export const x = 1;
"""
    violations, summary = check_removed_symbols(tmp_path, clean_diff)
    assert violations == []
    assert summary == ""


def test_llm_reviewer_error_surfaces_heuristic_and_recorded_reason():
    """Rule 1 & Rule 4 (GATE-01): LLM reviewer error falls back to heuristic with llm_error recorded."""
    cfg = GuardConfig()
    cfg.llm.base_url = "http://localhost:8000"
    cfg.llm.api_key = "test-key"
    cfg.llm.model = "test-model"
    engine = LLMReviewerEngine(config=cfg)

    diff_summary = DiffSummary(
        total_files=1,
        total_insertions=1,
        total_deletions=0,
        raw_diff="diff --git a/a.py b/a.py\n+x = 1\n",
        files=[],
    )

    with patch("guard.core.llm_reviewer.call_llm", side_effect=LLMClientError("Connection timed out")):
        verdict = engine.review(
            prompt="Refactor error handling",
            domain="BACKEND",
            diff_summary=diff_summary,
            build_check=None,
        )

    assert verdict.review_mode == "heuristic"
    assert "LLMClientError" in verdict.llm_error
    assert "LLM review did NOT run" in verdict.summary


def test_llm_reviewer_unparseable_response_records_error():
    """Rule 1 & Rule 4: LLM response with corrupt structure falls back to heuristic with error recorded."""
    cfg = GuardConfig()
    cfg.llm.base_url = "http://localhost:8000"
    cfg.llm.api_key = "test-key"
    cfg.llm.model = "test-model"
    engine = LLMReviewerEngine(config=cfg)

    diff_summary = DiffSummary(
        total_files=1,
        total_insertions=1,
        total_deletions=0,
        raw_diff="diff --git a/a.py b/a.py\n+x = 1\n",
        files=[],
    )

    with patch("guard.core.llm_reviewer.call_llm", return_value="Random non-conformant output without SCORE"):
        verdict = engine.review(
            prompt="Refactor error handling",
            domain="BACKEND",
            diff_summary=diff_summary,
            build_check=None,
        )

    assert verdict.review_mode == "heuristic"
    assert verdict.llm_error != ""
    assert "LLM review did NOT run" in verdict.summary


def test_diff_inspector_records_error_on_subprocess_failure(tmp_path):
    """Rule 1: Subprocess errors during diff inspection are recorded in last_error, never silently swallowed."""
    (tmp_path / ".git").mkdir()
    inspector = GitDiffInspector(tmp_path)
    with patch("subprocess.run", side_effect=subprocess.SubprocessError("git execution failed")):
        diff = inspector.get_diff()
        assert "ERROR: git diff error" in diff
        assert inspector.last_error is not None
        assert "git execution failed" in inspector.last_error

        head = inspector.get_head()
        assert head is None
        assert "get_head error" in inspector.last_error

        sha = inspector.create_baseline_snapshot()
        assert sha is None
        assert "create_baseline_snapshot error" in inspector.last_error


def test_diff_inspector_unreadable_untracked_file_surfaces_error_marker(tmp_path):
    """Rule 1: Untracked file that cannot be read is surfaced in synthetic diff with error marker and last_error recorded."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    untracked_file = repo / "secret_draft.txt"
    untracked_file.write_text("draft content", encoding="utf-8")

    inspector = GitDiffInspector(repo)
    with patch.object(inspector, "get_untracked_files", return_value=["secret_draft.txt"]):
        with patch.object(Path, "read_text", side_effect=OSError("Permission denied")):
            diff = inspector.get_diff()

    assert "ERROR: unreadable untracked file" in diff
    assert "secret_draft.txt" in diff
    assert inspector.last_error is not None
    assert "could not be read" in inspector.last_error


def test_pre_analysis_cli_agent_oserror_falls_back(tmp_path):
    """Rule 1: If call_llm raises OSError (e.g. CLI agent missing/broken), pre-analysis falls back to heuristic with error recorded."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()

    cfg = GuardConfig()
    cfg.llm.base_url = "http://localhost:8000"
    cfg.llm.api_key = "test-key"

    with patch("guard.domains.pre_analysis.call_llm", side_effect=OSError("CLI agent binary failed")):
        result = analyze_task(repo, "Task prompt", [], None, cfg)

    assert result.domain_source.startswith("heuristic: OSError")
    assert "OSError" in result.contracts_source


def test_load_config_corrupt_file_warns_and_falls_back(tmp_path):
    """Corrupt local config file warns and falls back to global/defaults."""
    guard_dir = tmp_path / ".guard"
    guard_dir.mkdir(parents=True)
    cfg_file = guard_dir / "config.json"
    cfg_file.write_text("{broken json", encoding="utf-8")

    printed_warnings = []
    with patch("guard.core.config.console.print", side_effect=printed_warnings.append):
        cfg = load_config(tmp_path)

    assert isinstance(cfg, GuardConfig)
    assert any("Could not read local config" in str(msg) for msg in printed_warnings)


def test_diff_inspector_parse_diff_surfaces_git_error(tmp_path):
    """Rule 1: If git diff has an error, parse_diff marks is_clean=False and preserves error."""
    inspector = GitDiffInspector(tmp_path)
    error_diff = "# [ERROR: git diff error: execution failed]\n"
    summary = inspector.parse_diff(error_diff)

    assert summary.is_clean is False
    assert summary.error is not None
    assert "execution failed" in summary.error


def test_llm_reviewer_heuristic_penalizes_diff_error():
    """Rule 1: Heuristic evaluator applies Check 0 penalty and alert when DiffSummary has an error."""
    engine = LLMReviewerEngine()
    diff_summary = DiffSummary(
        total_files=0,
        total_insertions=0,
        total_deletions=0,
        raw_diff="# [ERROR: git diff error: failed]\n",
        is_clean=False,
        error="git diff error: failed",
        files=[],
    )

    verdict = engine._evaluate_heuristics(
        build_check=None,
        diff_summary=diff_summary,
        violations=[],
        invariant_result=None,
    )

    assert verdict.score <= 5.0
    assert any("Diff Inspection Error" in note for note in verdict.technical_audit)
    assert any("Resolve Git error" in step for step in verdict.remediation_steps)
