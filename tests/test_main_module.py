"""
Unit and functional tests for `python -m guard` entry point.
"""

import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from guard import __version__
from guard.core.repo_setup import refresh_after_upgrade


def test_main_module_version():
    """`python -m guard --version` prints the version and exits 0."""
    refresh_after_upgrade()
    result = subprocess.run(
        [sys.executable, "-m", "guard", "--version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert f"guard version {__version__}" in result.stdout


def test_main_module_matches_console_script():
    """`python -m guard --version` prints the same as `guard --version`."""
    guard_bin = shutil.which("guard")
    if not guard_bin:
        pytest.skip("guard console script not found in PATH")

    # Ensure GUARD_HOME is already refreshed so neither invocation prints first-visit health check
    refresh_after_upgrade()

    module_res = subprocess.run(
        [sys.executable, "-m", "guard", "--version"],
        capture_output=True,
        text=True,
    )
    script_res = subprocess.run(
        [guard_bin, "--version"],
        capture_output=True,
        text=True,
    )

    assert module_res.returncode == script_res.returncode
    assert module_res.stdout.strip() == script_res.stdout.strip()


def test_main_module_exit_code_pass_through():
    """Non-zero exit codes (such as unknown command or invalid options) pass through."""
    result = subprocess.run(
        [sys.executable, "-m", "guard", "nonexistent-subcommand-12345"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0

    # Also test valid command exits with 0
    help_res = subprocess.run(
        [sys.executable, "-m", "guard", "--help"],
        capture_output=True,
        text=True,
    )
    assert help_res.returncode == 0


def test_main_module_execution_invokes_cli_main():
    """Importing/running guard.__main__ executes guard.cli.main."""
    import runpy

    import guard

    local_root = str(Path(__file__).resolve().parent.parent)
    if local_root not in sys.path:
        sys.path.insert(0, local_root)
    local_guard_dir = str(Path(__file__).resolve().parent.parent / "guard")
    if local_guard_dir not in guard.__path__:
        guard.__path__.insert(0, local_guard_dir)

    with patch("guard.cli.main") as mock_main:
        runpy.run_module("guard", run_name="__main__")
        mock_main.assert_called_once()
