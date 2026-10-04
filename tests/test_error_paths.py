"""
Unit tests for error-handling audit and error paths.
Verifies that failures on gate paths surface as failed checks, findings, or recorded error reasons,
and never silently pass.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from guard.core.config import GuardConfig, LLMConfig, LLMProtocol, load_config, sync_to_alibaba_ocr
from guard.core.diff_inspector import DiffSummary, GitDiffInspector
from guard.core.llm_client import LLMClientError, call_llm, ping_llm
from guard.core.llm_reviewer import LLMReviewerEngine, ReviewVerdict
from guard.core.removal_check import check_removed_symbols
from guard.domains.pre_analysis import analyze_task
from guard.hooks.runner import run_sandwich_task


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
    """Rule 1: If git ls-files fails during removal check, failure surfaces as a HIGH DEAD-REF-UNVERIFIED violation."""
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
    assert any(v.rule_id == "DEAD-REF-UNVERIFIED" for v in violations)
    assert any(v.severity == "HIGH" for v in violations)
    assert "could not verify removed-symbol references" in violations[0].message
    assert "could not verify removed-symbol references" in summary

def test_removal_check_file_read_error_surfaces_violation(tmp_path):
    """Rule 1: If an individual file cannot be read, failure surfaces as a HIGH DEAD-REF-UNREADABLE violation and error note in summary."""
    repo = tmp_path / "repo"
    repo.mkdir()
    code_file = repo / "src" / "index.ts"
    code_file.parent.mkdir(parents=True)
    code_file.write_text("import { calculateTax } from './app';\n", encoding="utf-8")

    with patch("guard.core.removal_check._repo_files", return_value=[code_file]):
        with patch.object(Path, "read_text", side_effect=OSError("Permission denied")):
            violations, summary = check_removed_symbols(repo, SAMPLE_REMOVAL_DIFF)

    assert len(violations) >= 1
    assert any(v.rule_id == "DEAD-REF-UNREADABLE" for v in violations)
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


def test_diff_inspector_base_ref_failure_surfaces_revise_verdict(tmp_path):
    """Base_ref diff failure records error, surfaces in DiffSummary, and yields REVISE verdict."""
    (tmp_path / ".git").mkdir()
    inspector = GitDiffInspector(tmp_path)
    with patch("subprocess.run") as mock_subproc:
        proc = MagicMock()
        proc.returncode = 128
        proc.stdout = ""
        proc.stderr = "fatal: bad revision 'origin/main'"
        mock_subproc.return_value = proc

        raw_diff = inspector.get_diff(base_ref="origin/main")
        assert "ERROR: git diff failed" in raw_diff
        assert inspector.last_error is not None
        assert "bad revision" in inspector.last_error

        summary = inspector.parse_diff(raw_diff)
        assert summary.error is not None
        assert "bad revision" in summary.error
        assert summary.is_clean is False

        # Pass through gate scoring and assert the verdict, not only the score
        engine = LLMReviewerEngine()
        verdict = engine._evaluate_heuristics(
            build_check=None,
            diff_summary=summary,
            violations=[],
            invariant_result=None,
        )
        assert verdict.verdict == ReviewVerdict.REVISE
        assert verdict.score <= 5.0
        assert any("Diff Inspection Error" in note for note in verdict.technical_audit)


def test_diff_inspector_unreadable_untracked_with_nonempty_tracked_diff(tmp_path):
    """Unreadable untracked file error surfaces in DiffSummary even when tracked diff is non-empty."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    untracked_file = repo / "notes.txt"
    untracked_file.write_text("secret", encoding="utf-8")

    inspector = GitDiffInspector(repo)
    tracked_diff = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,2 @@\n+x = 1\n"

    def _fake_diff_run(cmd, *args, **kwargs):
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = tracked_diff
        proc.stderr = ""
        return proc

    with patch("subprocess.run", side_effect=_fake_diff_run):
        with patch.object(inspector, "get_untracked_files", return_value=["notes.txt"]):
            with patch.object(Path, "read_text", side_effect=OSError("Permission denied")):
                raw_diff = inspector.get_diff()

    assert "diff --git a/app.py b/app.py" in raw_diff
    assert "ERROR: unreadable untracked file" in raw_diff

    summary = inspector.parse_diff(raw_diff)
    assert summary.error is not None
    assert "Permission denied" in summary.error
    assert summary.is_clean is False
    assert any(f.path == "app.py" for f in summary.files)


def test_diff_inspector_git_status_failure_with_nonempty_tracked_diff(tmp_path):
    """Failed git status error surfaces in DiffSummary even when tracked diff is non-empty."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()

    inspector = GitDiffInspector(repo)
    tracked_diff = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,2 @@\n+x = 1\n"

    def _fake_status_run(cmd, *args, **kwargs):
        proc = MagicMock()
        if "diff" in cmd:
            proc.returncode = 0
            proc.stdout = tracked_diff
            proc.stderr = ""
        elif "status" in cmd:
            proc.returncode = 128
            proc.stdout = ""
            proc.stderr = "fatal: error reading status"
        else:
            proc.returncode = 0
            proc.stdout = ""
            proc.stderr = ""
        return proc

    with patch("subprocess.run", side_effect=_fake_status_run):
        raw_diff = inspector.get_diff()
        assert inspector.last_error is not None
        assert "git status failed" in inspector.last_error

        summary = inspector.parse_diff(raw_diff)
        assert summary.error is not None
        assert "git status failed" in summary.error
        assert summary.is_clean is False


def test_diff_inspector_update_ref_failure_is_reported(tmp_path):
    """Failed git update-ref during baseline snapshot is recorded and returns None."""
    (tmp_path / ".git").mkdir()
    inspector = GitDiffInspector(tmp_path)

    def _fake_updateref_run(cmd, *args, **kwargs):
        proc = MagicMock()
        if "stash" in cmd:
            proc.returncode = 0
            proc.stdout = "abc1234\n"
            proc.stderr = ""
        elif "update-ref" in cmd:
            proc.returncode = 1
            proc.stdout = ""
            proc.stderr = "fatal: update-ref failed"
        else:
            proc.returncode = 0
            proc.stdout = ""
            proc.stderr = ""
        return proc

    with patch("subprocess.run", side_effect=_fake_updateref_run):
        sha = inspector.create_baseline_snapshot()
        assert sha is None
        assert inspector.last_error is not None
        assert "git update-ref failed" in inspector.last_error


def test_ping_llm_invalid_url_returns_false_no_exception():
    """ping_llm with an invalid URL returns (False, msg) without raising an unhandled exception."""
    cfg = LLMConfig(
        provider="custom",
        protocol=LLMProtocol.OPENAI,
        base_url="http://localhost:abc/v1",
        model="gpt-4o",
    )
    ok, msg, latency = ping_llm(cfg)
    assert ok is False
    assert isinstance(msg, str)
    assert len(msg) > 0


def test_call_llm_cli_unexpected_exception_wraps_in_llm_client_error(tmp_path):
    """cli_llm.call raising unexpected exception raises LLMClientError; guard pre falls back with reason."""
    cfg = LLMConfig(
        provider="cli",
        protocol=LLMProtocol.CLI,
        cli_agent="claude",
        model="claude-3-5-sonnet",
    )
    with patch("guard.core.cli_llm.call", side_effect=TypeError("unexpected type in CLI call")):
        with pytest.raises(LLMClientError) as exc_info:
            call_llm(cfg, "prompt")
        assert "TypeError" in str(exc_info.value)

        # Pre-task analysis falls back to heuristic with reason
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        result = analyze_task(repo, "Task prompt", [], None, GuardConfig(llm=cfg))
        assert result.domain_source.startswith("heuristic: LLMClientError")
        assert "TypeError" in result.contracts_source


def test_hook_runner_catches_value_error(tmp_path):
    """run_sandwich_task catches ValueError (e.g. embedded null byte in argument)."""
    with patch("guard.task_flow.execute_pre_task", return_value=True):
        with patch("subprocess.run", side_effect=ValueError("embedded null byte")):
            code = run_sandwich_task("prompt", ["bad\0cmd"], repo_path=tmp_path)
            assert code == 1


def test_config_ocr_sync_catches_value_error():
    """sync_to_alibaba_ocr catches ValueError (e.g. embedded null byte in setting)."""
    cfg = LLMConfig(provider="custom", protocol=LLMProtocol.OPENAI, model="test", base_url="http://localhost:8000")
    with patch("subprocess.run", side_effect=ValueError("embedded null byte")):
        with patch("guard.core.config.shutil.which", return_value="/bin/ocr"):
            ok, msg = sync_to_alibaba_ocr(cfg)
            assert ok is False
            assert "Error executing OCR CLI" in msg
            assert "ValueError" in msg or "embedded null byte" in msg
