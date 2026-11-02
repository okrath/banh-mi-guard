"""Tests for the `guard worker-verify` command (tests/test_commands_worker_verify.py)."""

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import guard.cli
from guard.core import worker_verify as engine

app = guard.cli.app


def git(repo: Path, *args: str) -> str:
    res = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8",
                         errors="replace", check=True)
    return (res.stdout or "").strip()


def make_repo(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True, capture_output=True)
    return path


def committed_repo(path: Path) -> Path:
    """A repo with one tracked file committed; returns the commit sha."""
    repo = make_repo(path)
    (repo / "a.py").write_text("VALUE = 1\n", encoding="utf-8")
    git(repo, "add", "a.py")
    git(repo, "commit", "-m", "init")
    return repo


# --- guard worker-verify ------------------------------------------------------


def test_worker_verify_passes_a_clean_repo_within_ownership(tmp_path):
    repo = committed_repo(tmp_path / "clean")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "a.py").write_text("VALUE = 2\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py"])

    assert result.exit_code == 0
    assert "RESULT: PASS" in result.output


def test_worker_verify_fails_an_out_of_scope_edit(tmp_path):
    repo = committed_repo(tmp_path / "outside")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "b.py").write_text("STOLEN = True\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py"])

    assert result.exit_code == 1
    assert "FAIL  [scope-outside-ownership]" in result.output
    assert "RESULT: FAIL (1)" in result.output


def test_worker_verify_own_splits_a_comma_separated_value(tmp_path):
    repo = committed_repo(tmp_path / "comma")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
    (repo / "b.py").write_text("B = 1\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py, b.py"]
    )

    assert result.exit_code == 0
    assert "RESULT: PASS" in result.output


def test_worker_verify_role_test_rejects_tracked_edits(tmp_path):
    repo = committed_repo(tmp_path / "testrole")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "a.py").write_text("VALUE = 2\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--role", "test", "--own", "**"]
    )

    assert result.exit_code == 1
    assert "test-worker-tracked-edits" in result.output


def test_worker_verify_json_matches_to_dict(tmp_path):
    repo = committed_repo(tmp_path / "json")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "b.py").write_text("STOLEN = True\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py", "--json"]
    )

    assert result.exit_code == 1
    assert json.loads(result.output) == engine.verify_worker(repo, base=base, own=["a.py"]).to_dict()


def test_worker_verify_quick_skips_the_check_commands(tmp_path):
    repo = committed_repo(tmp_path / "quick")
    base = git(repo, "rev-parse", "HEAD")
    failing = 'python -c "import sys; sys.exit(1)"'

    result = CliRunner().invoke(
        app,
        ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py", "--quick", "--check", failing],
    )

    assert result.exit_code == 0
    assert "RESULT: PASS" in result.output


def test_worker_verify_failing_check_fails_the_audit(tmp_path):
    repo = committed_repo(tmp_path / "check")
    base = git(repo, "rev-parse", "HEAD")

    result = CliRunner().invoke(
        app,
        ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py",
         "--check", 'python -c "import sys; sys.exit(1)"'],
    )

    assert result.exit_code == 1
    assert "FAIL  [check-failed]" in result.output
    assert "RESULT: FAIL (1)" in result.output


def test_worker_verify_prints_warnings_before_failures(tmp_path):
    repo = committed_repo(tmp_path / "warn")
    tests_dir = repo / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_x.py").write_text("def test_x():\n    assert 1 == 1\n    assert 2 == 2\n", encoding="utf-8")
    git(repo, "add", "tests/test_x.py")
    git(repo, "commit", "-m", "tests")
    base = git(repo, "rev-parse", "HEAD")
    (tests_dir / "test_x.py").write_text("def test_x():\n    pass\n", encoding="utf-8")
    (repo / "src").mkdir()
    (repo / "src" / "other.py").write_text("X = 1\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "tests/**"]
    )

    assert result.exit_code == 1
    output = result.output
    assert "WARN  [fewer-assertions]" in output
    assert "FAIL  [scope-outside-ownership]" in output
    assert output.index("WARN ") < output.index("FAIL ")
    assert "RESULT: FAIL (1)" in output


def test_worker_verify_reports_a_pass_with_warnings(tmp_path):
    repo = committed_repo(tmp_path / "warnonly")
    tests_dir = repo / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_y.py").write_text("def test_y():\n    assert 1 == 1\n    assert 2 == 2\n", encoding="utf-8")
    git(repo, "add", "tests/test_y.py")
    git(repo, "commit", "-m", "tests")
    base = git(repo, "rev-parse", "HEAD")
    (tests_dir / "test_y.py").write_text("def test_y():\n    assert 1 == 1\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "tests/**"]
    )

    assert result.exit_code == 0
    assert "RESULT: PASS with 1 warning(s)" in result.output


def test_worker_verify_accepts_epoch_since(tmp_path):
    repo = committed_repo(tmp_path / "since")
    base = git(repo, "rev-parse", "HEAD")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py", "--since", "1"]
    )

    assert result.exit_code == 0
    assert "RESULT: PASS" in result.output


@pytest.mark.parametrize(
    "extra",
    [
        ["--since", "not-a-time"],
        ["--since", "2026-13-99T99:99:99"],
        ["--role", "reviewer"],
    ],
)
def test_worker_verify_invalid_option_values_are_usage_errors(tmp_path, extra):
    repo = committed_repo(tmp_path / ("bad" + extra[-1].replace(":", "").replace("-", "")))
    base = git(repo, "rev-parse", "HEAD")

    result = CliRunner().invoke(app, ["worker-verify", "--worktree", str(repo), "--base", base, *extra])

    assert result.exit_code == 2


def test_worker_verify_missing_worktree_is_a_usage_error(tmp_path):
    result = CliRunner().invoke(app, ["worker-verify", "--worktree", str(tmp_path / "missing"), "--base", "HEAD"])

    assert result.exit_code == 2


def test_worker_verify_unresolvable_base_is_a_usage_error(tmp_path):
    repo = committed_repo(tmp_path / "badbase")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", "no-such-ref^{commit}"]
    )

    assert result.exit_code == 2
    assert "does not resolve" in result.output


def test_worker_verify_report_relative_to_the_worktree(tmp_path):
    repo = committed_repo(tmp_path / "report")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "report.md").write_text("All tests pass.\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py", "--own", "report.md",
              "--report", "report.md", "--quick"]
    )

    assert result.exit_code == 0  # --quick skips the report check: the file is not read

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py", "--own", "report.md",
              "--report", "report.md"]
    )

    assert result.exit_code == 0
    assert "WARN  [report-unchecked-claim]" in result.output


def test_worker_verify_accepts_an_iso_8601_since(tmp_path):
    repo = committed_repo(tmp_path / "iso-since")
    base = git(repo, "rev-parse", "HEAD")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py",
              "--since", "2020-01-01T00:00:00"]
    )

    assert result.exit_code == 0
    assert "RESULT: PASS" in result.output


def test_worker_verify_evidence_path_is_relative_to_the_worktree(tmp_path):
    repo = committed_repo(tmp_path / "evidence")
    base = git(repo, "rev-parse", "HEAD")
    evidence = repo / "evidence-artifacts"
    evidence.mkdir()
    (evidence / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * 9000)

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--evidence", "evidence-artifacts"]
    )

    assert result.exit_code == 0
    assert "evidence-empty" not in result.output

    missing = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--evidence", "no-such-dir"]
    )

    assert missing.exit_code == 0
    assert "WARN  [evidence-empty]" in missing.output


def test_help_lists_worker_verify_and_no_watch():
    output = CliRunner().invoke(app, ["--help"]).output

    assert "worker-verify" in output
    assert "watch" not in output
