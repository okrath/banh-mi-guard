"""
Setup check shown by `guard doctor`, after `guard update self` and on the first run of a new
version: every gap an older installation can have, with the command that fixes it.
"""

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from guard.cli import app
from guard.core.repo_setup import DIRECTIVE_END, DIRECTIVE_START, install_global
from guard.core.setup_health import setup_health


@pytest.fixture
def fake_machine(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "gitconfig"))
    return home


def make_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    return path


def by_item(rows):
    return {(r["item"], r["level"]): r for r in rows}


def test_old_install_reports_what_is_missing_and_how_to_fix(fake_machine, tmp_path):
    repo = make_repo(tmp_path / "app")
    rows = by_item(setup_health(repo))
    assert rows[("Git hooks", "missing")]["fix"].startswith("guard install")
    assert rows[("Agent directives", "missing")]["fix"].startswith("guard install")
    assert rows[("Invariants", "warn")]["fix"].startswith("guard invariants init")


def test_complete_install_reports_ok(fake_machine, tmp_path):
    from guard.core.config import LLMConfig, _remember_ocr_sync, load_global_config, save_config
    repo = make_repo(tmp_path / "app")
    install_global(repo)  # also sets the repository up (invariants file)
    cfg = load_global_config()  # a complete install has an LLM, given to OCR
    cfg.llm = LLMConfig(base_url="http://llm.local/v1", api_key="k", model="m")
    cfg.ocr.always = False  # and the user chose when OCR runs
    save_config(cfg)
    _remember_ocr_sync(cfg.llm)
    with patch("guard.core.setup_health.shutil.which", return_value="ocr"):
        levels = {r["item"]: r["level"] for r in setup_health(repo)}
    assert levels["Git hooks"] == "ok"
    assert levels["Agent directives"] == "ok"
    assert "missing" not in levels.values()


def test_unmarked_directives_are_a_warning_with_instructions(fake_machine, tmp_path):
    repo = make_repo(tmp_path / "app")
    (repo / "CLAUDE.md").write_text("# BANH-MI-GUARD protocol pasted by hand\n", encoding="utf-8")
    rows = [r for r in setup_health(repo) if r["item"] == "Agent directives"]
    assert rows and all(r["level"] == "warn" for r in rows)
    assert "START/END markers" in rows[0]["fix"]


def test_hooks_kept_in_the_repository_are_reported_with_the_line_to_add(fake_machine, tmp_path):
    repo = make_repo(tmp_path / "app")
    install_global(tmp_path)
    subprocess.run(["git", "config", "core.hooksPath", ".husky"], cwd=repo, check=True)
    (repo / ".husky").mkdir()
    hook = repo / ".husky" / "pre-commit"
    hook.write_text("#!/bin/sh\nnpm test\n", encoding="utf-8")

    row = by_item(setup_health(repo))[("Repository hook", "missing")]
    assert "guard does not edit repository files" in row["detail"]
    assert "guard post --hook" in row["fix"] and str(hook) in row["fix"]

    # Neither setup nor refresh edits a hook that lives in the repository tree
    from guard.core.repo_setup import ensure_repo_setup
    ensure_repo_setup(repo)
    assert CliRunner().invoke(app, ["hook", "refresh", "--repo", str(repo)]).exit_code == 0
    assert hook.read_text(encoding="utf-8") == "#!/bin/sh\nnpm test\n"

    # Once the user adds the recommended line, the check is satisfied
    from guard.core.repo_setup import MANUAL_HOOK_LINE
    assert MANUAL_HOOK_LINE in row["fix"]
    hook.write_text(f"#!/bin/sh\nnpm test\n{MANUAL_HOOK_LINE}\n", encoding="utf-8")
    assert ("Repository hook", "missing") not in by_item(setup_health(repo))


def test_first_command_after_upgrade_prints_the_check_once(fake_machine, tmp_path, monkeypatch, capsys):
    """An old `guard update self` cannot refresh; the new version's first command must speak up."""
    import sys
    from guard import cli

    repo = make_repo(tmp_path / "app")
    monkeypatch.chdir(repo)
    monkeypatch.setattr(sys, "argv", ["guard", "--version"])
    for _ in range(2):
        try:
            cli.main()
        except SystemExit:
            pass
    out = capsys.readouterr().out
    assert out.count("setup check") == 1  # once per version, not on every command
    assert "guard install" in out


def test_doctor_shows_the_setup_table(fake_machine, tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "app")
    monkeypatch.chdir(repo)
    result = CliRunner().invoke(app, ["doctor", "--no-updates"])
    assert result.exit_code == 0
    assert "Installation & Repository Setup" in result.output
    assert "MISSING" in result.output and "guard install" in result.output


def test_commit_mode_is_asked_until_chosen(fake_machine, tmp_path):
    repo = make_repo(tmp_path / "app")
    rows = by_item(setup_health(repo))
    assert rows[("Commit messages", "warn")]["fix"] == "guard config commit auto   (or: guard config commit ask)"

    result = CliRunner().invoke(app, ["config", "commit", "ask"])
    assert result.exit_code == 0
    rows = by_item(setup_health(repo))
    assert "mode `ask`" in rows[("Commit messages", "ok")]["detail"]
    assert CliRunner().invoke(app, ["config", "commit", "sometimes"]).exit_code == 1


def test_missing_ocr_is_reported_with_the_install_command(fake_machine, tmp_path):
    repo = make_repo(tmp_path / "app")
    with patch("guard.core.setup_health.shutil.which", return_value=None):
        rows = by_item(setup_health(repo))
    assert rows[("Alibaba OCR", "warn")]["fix"].startswith("npm install -g @alibaba-group/open-code-review")


def test_install_shows_what_is_left_to_choose(fake_machine, tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "app")
    monkeypatch.chdir(repo)
    from guard.cli import console
    monkeypatch.setattr(console, "width", 250)  # keep table cells on one line
    result = CliRunner().invoke(app, ["install"])
    assert result.exit_code == 0
    assert "Commit messages" in result.output and "guard config commit auto" in result.output

    # Once chosen, install no longer asks (only what is left to choose is listed); doctor still shows it
    assert CliRunner().invoke(app, ["config", "commit", "auto"]).exit_code == 0
    assert "Commit messages" not in CliRunner().invoke(app, ["install"]).output
    doctor = CliRunner().invoke(app, ["doctor", "--no-updates"])
    assert "Commit messages" in doctor.output and "mode `auto`" in doctor.output
