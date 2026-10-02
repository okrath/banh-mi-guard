"""
Unit tests for Hook Installer and Templates.
"""

import pytest
from typer.testing import CliRunner

from guard.cli import app
from guard.hooks.installer import HookInstaller

runner = CliRunner()


@pytest.fixture
def mock_git_repo(tmp_path):
    import subprocess
    repo = tmp_path / "target_repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)  # info/exclude lives where Git says
    (repo / ".git" / "hooks").mkdir(exist_ok=True)
    return repo


def test_hook_status_initial(mock_git_repo):
    installer = HookInstaller(mock_git_repo)
    status = installer.get_status()
    assert status["is_git_repo"] is True
    assert status["pre_commit_installed"] is False
    assert status["prepare_commit_msg_installed"] is False
    assert status["claude_md_active"] is False
    assert status["agent_md_active"] is False
    assert status["mode"] == "none"


def test_hook_install_and_backup(mock_git_repo):
    # Pre-existing custom hook
    custom_pre_commit = mock_git_repo / ".git" / "hooks" / "pre-commit"
    custom_pre_commit.write_text("#!/bin/sh\necho 'my custom hook'\n", encoding="utf-8")

    installer = HookInstaller(mock_git_repo)
    success, messages = installer.install(mode="all")
    assert success is True

    # Check that custom hook was backed up
    backup_file = mock_git_repo / ".git" / "hooks" / "pre-commit.guard.bak"
    assert backup_file.exists()
    assert "my custom hook" in backup_file.read_text(encoding="utf-8")

    # Check new hook is Guard hook
    assert "BANH-MI-GUARD" in custom_pre_commit.read_text(encoding="utf-8")

    # Status check
    status = installer.get_status()
    assert status["pre_commit_installed"] is True
    assert status["prepare_commit_msg_installed"] is True
    assert status["agent_wrapper_installed"] is True
    assert status["claude_md_active"] is True
    assert status["agent_md_active"] is True
    assert status["mode"] == "all"

    # Check CLAUDE.md and AGENT.md exist
    assert (mock_git_repo / "CLAUDE.md").exists()
    assert (mock_git_repo / "AGENT.md").exists()


def test_hook_uninstall_and_restore(mock_git_repo):
    # Custom hook
    pre_commit = mock_git_repo / ".git" / "hooks" / "pre-commit"
    pre_commit.write_text("#!/bin/sh\necho 'original hook'\n", encoding="utf-8")

    installer = HookInstaller(mock_git_repo)
    installer.install(mode="all")

    # Uninstall
    uninstalled, msgs = installer.uninstall()
    assert uninstalled is True

    # Check original hook was restored
    assert pre_commit.exists()
    assert "original hook" in pre_commit.read_text(encoding="utf-8")
    assert not (mock_git_repo / ".git" / "hooks" / "pre-commit.guard.bak").exists()

    # Guard-generated CLAUDE.md and AGENT.md should be cleaned up
    assert not (mock_git_repo / "CLAUDE.md").exists()
    assert not (mock_git_repo / "AGENT.md").exists()


def test_hook_install_stealth_mode(mock_git_repo):
    installer = HookInstaller(mock_git_repo)
    success, messages = installer.install(mode="git")
    assert success is True

    # Hooks installed
    pre_commit = mock_git_repo / ".git" / "hooks" / "pre-commit"
    prep_msg = mock_git_repo / ".git" / "hooks" / "prepare-commit-msg"
    assert pre_commit.exists()
    assert "BANH-MI-GUARD" in pre_commit.read_text(encoding="utf-8")
    assert prep_msg.exists()

    # Zero workspace footprint: NO CLAUDE.md, NO AGENT.md, NO guard-exec
    assert not (mock_git_repo / "CLAUDE.md").exists()
    assert not (mock_git_repo / "AGENT.md").exists()
    assert not (mock_git_repo / ".guard" / "bin" / "guard-exec").exists()

    # Local .git/info/exclude must have .guard/
    exclude = mock_git_repo / ".git" / "info" / "exclude"
    assert exclude.exists()
    assert ".guard/" in exclude.read_text(encoding="utf-8")

    status = installer.get_status()
    assert status["mode"] == "git"
    assert status["pre_commit_installed"] is True
    assert status["claude_md_active"] is False
    assert status["agent_md_active"] is False
    assert status["git_exclude_active"] is True


def test_hook_install_agent_only_mode(mock_git_repo):
    installer = HookInstaller(mock_git_repo)
    success, messages = installer.install(mode="agent")
    assert success is True

    # Directives exist
    assert (mock_git_repo / "CLAUDE.md").exists()
    assert (mock_git_repo / "AGENT.md").exists()
    assert (mock_git_repo / ".guard" / "bin" / "guard-exec").exists()

    # Git hooks NOT installed
    assert not (mock_git_repo / ".git" / "hooks" / "pre-commit").exists()
    assert not (mock_git_repo / ".git" / "hooks" / "prepare-commit-msg").exists()

    status = installer.get_status()
    assert status["mode"] == "agent"
    assert status["pre_commit_installed"] is False
    assert status["claude_md_active"] is True
    assert status["agent_md_active"] is True


def test_hook_selective_uninstall(mock_git_repo):
    installer = HookInstaller(mock_git_repo)
    installer.install(mode="all")
    status = installer.get_status()
    assert status["mode"] == "all"

    # Uninstall git only
    installer.uninstall(mode="git")
    status = installer.get_status()
    assert status["mode"] == "agent"
    assert not (mock_git_repo / ".git" / "hooks" / "pre-commit").exists()
    assert (mock_git_repo / "CLAUDE.md").exists()

    # Reinstall all, then uninstall agent only
    installer.install(mode="all")
    installer.uninstall(mode="agent")
    status = installer.get_status()
    assert status["mode"] == "git"
    assert (mock_git_repo / ".git" / "hooks" / "pre-commit").exists()
    assert not (mock_git_repo / "CLAUDE.md").exists()


def test_cli_hook_install_stealth(mock_git_repo):
    result = runner.invoke(app, ["hook", "install", "--repo", str(mock_git_repo), "--stealth"])
    assert result.exit_code == 0
    assert "Ghost/Stealth Mode" in result.stdout
    assert (mock_git_repo / ".git" / "hooks" / "pre-commit").exists()
    assert not (mock_git_repo / "CLAUDE.md").exists()


def test_cli_hook_install_agent(mock_git_repo):
    result = runner.invoke(app, ["hook", "install", "--repo", str(mock_git_repo), "--mode", "agent"])
    assert result.exit_code == 0
    assert "Agent Directives Mode" in result.stdout
    assert (mock_git_repo / "CLAUDE.md").exists()
    assert not (mock_git_repo / ".git" / "hooks" / "pre-commit").exists()


def test_cli_hook_status(mock_git_repo):
    runner.invoke(app, ["hook", "install", "--repo", str(mock_git_repo), "--stealth"])
    result = runner.invoke(app, ["hook", "status", "--repo", str(mock_git_repo)])
    assert result.exit_code == 0
    assert "Stealth Mode" in result.stdout


def test_hook_invalid_mode_raises(mock_git_repo):
    installer = HookInstaller(mock_git_repo)
    with pytest.raises(ValueError):
        installer.install(mode="invalid_mode")
    with pytest.raises(ValueError):
        installer.uninstall(mode="invalid_mode")


def test_hook_uninstall_cleans_git_exclude(mock_git_repo):
    installer = HookInstaller(mock_git_repo)
    installer.install(mode="git")
    exclude = mock_git_repo / ".git" / "info" / "exclude"
    assert exclude.exists()
    assert ".guard/" in exclude.read_text(encoding="utf-8")

    installer.uninstall(mode="git")
    assert ".guard/" not in exclude.read_text(encoding="utf-8")


def test_find_child_git_repos(tmp_path):
    workspace = tmp_path / "my_workspace"
    workspace.mkdir()

    repo1 = workspace / "services" / "backend"
    repo1.mkdir(parents=True)
    (repo1 / ".git").mkdir()

    repo2 = workspace / "apps" / "frontend"
    repo2.mkdir(parents=True)
    (repo2 / ".git").mkdir()

    # Ignored directory with a fake .git
    ignored = workspace / "node_modules" / "some_pkg"
    ignored.mkdir(parents=True)
    (ignored / ".git").mkdir()

    installer = HookInstaller(workspace)
    assert not installer.is_git_repo()

    discovered = installer.find_child_git_repos()
    discovered_names = [r.name for r in discovered]
    assert "backend" in discovered_names
    assert "frontend" in discovered_names
    assert "some_pkg" not in discovered_names


def test_safe_append_preserves_user_directives(mock_git_repo):
    claude_md = mock_git_repo / "CLAUDE.md"
    user_rules = "# My Custom Company Guidelines\n- Always write docstrings\n- Run linter before pushing\n"
    claude_md.write_text(user_rules, encoding="utf-8")

    installer = HookInstaller(mock_git_repo)
    installer.install(mode="agent")

    # Verify original content is STILL present
    updated_content = claude_md.read_text(encoding="utf-8")
    assert "# My Custom Company Guidelines" in updated_content
    assert "Always write docstrings" in updated_content
    assert "BANH-MI-GUARD DUAL-GATE HOOK" in updated_content

    # Backup should exist
    bak_file = mock_git_repo / "CLAUDE.md.guard.bak"
    assert bak_file.exists()
    assert bak_file.read_text(encoding="utf-8") == user_rules

    # Uninstall should restore original content
    installer.uninstall(mode="agent")
    restored_content = claude_md.read_text(encoding="utf-8")
    assert restored_content == user_rules


def test_cli_hook_install_workspace_selective(tmp_path):
    workspace = tmp_path / "workspace_test"
    workspace.mkdir()

    repo_a = workspace / "repo_a"
    repo_a.mkdir()
    (repo_a / ".git" / "hooks").mkdir(parents=True)

    repo_b = workspace / "repo_b"
    repo_b.mkdir()
    (repo_b / ".git" / "hooks").mkdir(parents=True)

    # Test selecting only repo_a
    result = runner.invoke(app, ["hook", "install", "--repo", str(workspace), "--select-repos", "1"])
    assert result.exit_code == 0
    assert "Hybrid Workspace Protection Active" in result.stdout
    assert (repo_a / ".git" / "hooks" / "pre-commit").exists()
    assert not (repo_b / ".git" / "hooks" / "pre-commit").exists()
    # Agent directives installed at workspace root
    assert (workspace / "CLAUDE.md").exists()


def test_global_git_hooks(monkeypatch, tmp_path):
    from pathlib import Path
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    monkeypatch.setenv("GUARD_HOME", str(fake_home / ".guard"))

    git_globals = {}

    def mock_run(cmd, *args, **kwargs):
        class MockProc:
            returncode = 0
            stdout = ""
            stderr = ""
        if "git" in cmd and "core.hooksPath" in cmd:
            if "--get" in cmd:
                p = git_globals.get("core.hooksPath", "")
                proc = MockProc()
                proc.returncode = 0 if p else 1
                proc.stdout = p
                return proc
            elif "--unset" in cmd:
                git_globals.pop("core.hooksPath", None)
                return MockProc()
            else:
                idx = cmd.index("core.hooksPath")
                git_globals["core.hooksPath"] = cmd[idx + 1]
                return MockProc()
        return MockProc()

    import subprocess
    monkeypatch.setattr(subprocess, "run", mock_run)

    success, msgs = HookInstaller.install_global_git_hooks()
    assert success is True
    assert (fake_home / ".guard" / "hooks" / "pre-commit").exists()
    assert (fake_home / ".guard" / "hooks" / "prepare-commit-msg").exists()

    status = HookInstaller.get_global_hooks_status()
    assert status["is_active"] is True

    # Test CLI command
    res = runner.invoke(app, ["hook", "status"])
    assert res.exit_code == 0
    assert "Global Git Hooks" in res.stdout

    # Uninstall
    un_success, un_msgs = HookInstaller.uninstall_global_git_hooks()
    assert un_success is True
    assert "core.hooksPath" not in git_globals


def test_hook_install_keeps_a_laya_hook_as_a_copy_it_never_chains(mock_git_repo):
    hooks = mock_git_repo / ".git" / "hooks"
    old = "#!/usr/bin/env sh\n# --- LAYA-OCR-GUARD AUTO-GENERATED HOOK ---\nguard post\n"
    (hooks / "pre-commit").write_text(old, encoding="utf-8")
    success, _ = HookInstaller(mock_git_repo).install(mode="all")
    assert success
    assert (hooks / "pre-commit.laya.bak").read_text(encoding="utf-8") == old
    assert not (hooks / "pre-commit.guard.bak").exists()  # a .guard.bak would run on every commit
    assert "BANH-MI-GUARD" in (hooks / "pre-commit").read_text(encoding="utf-8")


LAYA_LINE = "if command -v guard >/dev/null 2>&1; then guard post --hook || exit 1; fi  # LAYA-OCR-GUARD"


def test_hook_install_chains_a_users_hook_without_its_old_guard_line(mock_git_repo):
    hooks = mock_git_repo / ".git" / "hooks"
    (hooks / "pre-commit").write_text(f"#!/bin/sh\nnpm run lint\n{LAYA_LINE}\n", encoding="utf-8")
    assert HookInstaller(mock_git_repo).install(mode="all")[0]
    chained = (hooks / "pre-commit.guard.bak").read_text(encoding="utf-8")
    assert "npm run lint" in chained and "LAYA" not in chained  # the old line would run guard a second time


def test_uninstall_keeps_a_users_hook_and_drops_only_the_old_guard_line(mock_git_repo):
    hook = mock_git_repo / ".git" / "hooks" / "pre-commit"
    hook.write_text(f"#!/bin/sh\nnpm test\n{LAYA_LINE}\n", encoding="utf-8")
    HookInstaller(mock_git_repo).uninstall(mode="git")
    assert hook.read_text(encoding="utf-8") == "#!/bin/sh\nnpm test\n"


def test_hook_install_never_overwrites_an_earlier_laya_copy(mock_git_repo):
    hooks = mock_git_repo / ".git" / "hooks"
    (hooks / "pre-commit.laya.bak").write_text("first copy\n", encoding="utf-8")
    (hooks / "pre-commit").write_text("#!/usr/bin/env sh\n# --- LAYA-OCR-GUARD AUTO-GENERATED HOOK ---\n", encoding="utf-8")
    assert HookInstaller(mock_git_repo).install(mode="all")[0]
    assert (hooks / "pre-commit.laya.bak").read_text(encoding="utf-8") == "first copy\n"
    assert "LAYA-OCR-GUARD AUTO-GENERATED" in (hooks / "pre-commit.laya.2.bak").read_text(encoding="utf-8")


def test_uninstall_keeps_a_users_hook_with_both_old_and_current_guard_lines(mock_git_repo):
    from guard.core.repo_setup import HOOK_BLOCK
    hook = mock_git_repo / ".git" / "hooks" / "pre-commit"
    hook.write_text(f"#!/bin/sh\n{HOOK_BLOCK}npm test\n{LAYA_LINE}\n", encoding="utf-8")
    HookInstaller(mock_git_repo).uninstall(mode="git")
    assert hook.read_text(encoding="utf-8") == "#!/bin/sh\nnpm test\n"


def test_uninstall_never_deletes_a_users_hook_that_only_names_the_old_guard(mock_git_repo):
    hook = mock_git_repo / ".git" / "hooks" / "pre-commit"
    text = "#!/bin/sh\n# migrated from LAYA-OCR-GUARD by hand\nnpm test\n"
    hook.write_text(text, encoding="utf-8")
    HookInstaller(mock_git_repo).uninstall(mode="git")
    assert hook.read_text(encoding="utf-8") == text


def test_uninstall_removes_only_an_old_directive_block_from_an_agent_doc(mock_git_repo):
    from guard.core.repo_setup import LEGACY_DIRECTIVE_END, LEGACY_DIRECTIVE_START
    doc = mock_git_repo / "CLAUDE.md"
    doc.write_text(f"# My rules\n\n{LEGACY_DIRECTIVE_START}\nold\n{LEGACY_DIRECTIVE_END}\n", encoding="utf-8")
    HookInstaller(mock_git_repo).uninstall(mode="all")
    assert doc.read_text(encoding="utf-8") == "# My rules\n"


def test_uninstall_keeps_a_copy_of_an_old_whole_file_hook(mock_git_repo):
    hooks = mock_git_repo / ".git" / "hooks"
    old = "#!/usr/bin/env sh\n# --- LAYA-OCR-GUARD AUTO-GENERATED HOOK ---\nguard post\n"
    (hooks / "pre-commit").write_text(old, encoding="utf-8")
    HookInstaller(mock_git_repo).uninstall(mode="git")
    assert not (hooks / "pre-commit").exists()
    assert (hooks / "pre-commit.laya.bak").read_text(encoding="utf-8") == old
