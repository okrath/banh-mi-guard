"""Unit and functional tests for `python -m guard` entry point and score arithmetic."""

import os
import runpy
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from guard import __version__
from guard.core.llm_reviewer import LLMReviewerEngine
from guard.core.ocr_engine import RuleViolation
from guard.core.repo_setup import refresh_after_upgrade

REPO_ROOT = Path(__file__).resolve().parent.parent
# Guard prints emoji/box-drawing text; force the child to write UTF-8 so it matches the decode below.
CHILD_ENV = {**os.environ, "PYTHONIOENCODING": "utf-8"}


def _run_guard(cmd):
    return subprocess.run(
        cmd, cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", env=CHILD_ENV
    )


def test_main_module_version():
    """`python -m guard --version` prints the version and exits 0."""
    refresh_after_upgrade()
    result = _run_guard(
        [sys.executable, "-m", "guard", "--version"]
    )
    assert result.returncode == 0
    assert f"guard version {__version__}" in result.stdout


def test_main_module_matches_console_script():
    """`python -m guard --version` prints the same as the console script entry point."""
    # Ensure GUARD_HOME is already refreshed so neither invocation prints first-visit health check
    refresh_after_upgrade()

    module_res = _run_guard(
        [sys.executable, "-m", "guard", "--version"]
    )
    script_res = _run_guard(
        [sys.executable, "-c", "import sys; from guard.cli import main; sys.exit(main())", "--version"]
    )

    assert module_res.returncode == script_res.returncode
    assert module_res.stdout.strip() == script_res.stdout.strip()


def test_main_module_exit_code_pass_through():
    """Non-zero exit codes (such as unknown command or invalid options) pass through."""
    result = _run_guard(
        [sys.executable, "-m", "guard", "nonexistent-subcommand-12345"]
    )
    assert result.returncode != 0

    # Also test valid command exits with 0
    help_res = _run_guard(
        [sys.executable, "-m", "guard", "--help"]
    )
    assert help_res.returncode == 0


def test_main_module_execution_invokes_cli_main():
    """Importing/running guard.__main__ executes guard.cli.main and calls sys.exit."""
    main_py = REPO_ROOT / "guard" / "__main__.py"
    with patch("guard.cli.main") as mock_main:
        mock_main.return_value = 0
        with pytest.raises(SystemExit) as exc_info:
            runpy.run_path(str(main_py), run_name="__main__")
        assert exc_info.value.code == 0
        mock_main.assert_called_once()


def test_heuristic_penalty_order_float_precision():
    """Penalty order preserves floating-point precision bit-identically."""
    engine = LLMReviewerEngine()
    violations = [
        RuleViolation(rule_id="DEAD-001", severity="LOW", file_path="foo.py", message="unused"),
        RuleViolation(rule_id="LAZY-001", severity="LOW", file_path="foo.py", message="overkill"),
    ]
    verdict = engine._evaluate_heuristics(
        build_check=None,
        diff_summary=None,
        violations=violations,
        invariant_result=None,
        focus="lazy",
    )
    # Subtracting penalties sequentially (10.0 - 0.8 - 2.5) yields 6.699999999999999,
    # whereas summing penalties first (10.0 - (0.8 + 2.5)) would yield 6.7.
    assert verdict.score == 6.699999999999999
