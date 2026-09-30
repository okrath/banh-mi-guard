"""
Lazy repository setup and refresh-after-upgrade. Rule under test: guard never creates a diff in
the user's repository; it writes only inside .git and the Git-excluded .guard/ folder, and it
reports (never edits) repository files such as agent docs and hooks kept in the tree.
"""

import subprocess
from pathlib import Path

from guard.cli import execute_pre_task
from guard.core import repo_setup
from guard.core.repo_setup import (
    DIRECTIVE_END,
    DIRECTIVE_START,
    HOOK_BLOCK_START,
    ensure_repo_setup,
    guard_home,
    refresh_after_upgrade,
    refresh_directive_block,
    setup_health,
)
from guard.hooks.templates import AGENT_DIRECTIVES_TEMPLATE

AGENT_MD = "# App\n\n## Core invariants\n\n1. **Chat never times out**\n"


def git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout


def make_repo(tmp_path: Path, hooks_path: str = "") -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "t@t")
    git(repo, "config", "user.name", "t")
    if hooks_path:
        git(repo, "config", "core.hooksPath", hooks_path)
    (repo / "AGENT.md").write_text(AGENT_MD, encoding="utf-8")
    (repo / "package.json").write_text('{"scripts": {"build": "node -e \\"process.exit(0)\\""}}', encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "init")
    return repo


def assert_clean(repo: Path):
    assert git(repo, "status", "--porcelain", "-uall") == "", "guard must not create a diff in the repository"


def test_setup_creates_local_invariants_and_no_repository_diff(tmp_path):
    repo = make_repo(tmp_path, str(guard_home() / "hooks"))
    msgs = ensure_repo_setup(repo)
    local = repo / ".guard" / "invariants.json"
    assert local.is_file() and "Chat never times out" in local.read_text(encoding="utf-8")
    assert not (repo / "guard.invariants.json").exists()
    assert any("local .guard/invariants.json" in m for m in msgs)
    assert_clean(repo)
    assert ensure_repo_setup(repo) == []  # second run: nothing to do


def test_hooks_inside_git_dir_are_set_up(tmp_path):
    repo = make_repo(tmp_path)  # no hooksPath at all: Git runs .git/hooks
    ensure_repo_setup(repo)
    hook = repo / ".git" / "hooks" / "pre-commit"
    assert hook.is_file() and "guard post --hook" in hook.read_text(encoding="utf-8")
    assert_clean(repo)


def test_hooks_kept_in_the_repository_are_never_edited(tmp_path):
    repo = make_repo(tmp_path, ".husky")
    hook = repo / ".husky" / "pre-commit"
    hook.parent.mkdir()
    hook.write_text("#!/usr/bin/env sh\nnpm run lint\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "--no-verify", "-m", "husky")  # the sample hook itself is not under test

    ensure_repo_setup(repo)
    assert hook.read_text(encoding="utf-8") == "#!/usr/bin/env sh\nnpm run lint\n"
    assert HOOK_BLOCK_START not in hook.read_text(encoding="utf-8")
    assert_clean(repo)
    # ...and the user is told exactly what to add
    row = [r for r in setup_health(repo) if r["item"] == "Git hooks"][0]
    assert row["level"] == "missing" and "guard post --hook" in row["fix"]


def test_repository_agent_docs_are_reported_not_refreshed(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, str(guard_home() / "hooks"))
    (repo / "CLAUDE.md").write_text(f"# Team\n\n{DIRECTIVE_START}\nold directives\n{DIRECTIVE_END}\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "docs")
    ensure_repo_setup(repo)
    monkeypatch.setattr(repo_setup, "__version__", "9.9.9")
    refresh_after_upgrade()
    assert "old directives" in (repo / "CLAUDE.md").read_text(encoding="utf-8")
    assert_clean(repo)
    rows = [r for r in setup_health(repo) if r["item"] == "Agent directives" and r["level"] == "warn"]
    assert any("guard does not edit it" in r["detail"] for r in rows)


def test_directive_block_refresh_only_touches_marked_blocks(tmp_path):
    marked = tmp_path / "CLAUDE.md"
    marked.write_text(f"# Mine\n\nkeep me\n\n{DIRECTIVE_START}\nold directives\n{DIRECTIVE_END}\n\nafter\n", encoding="utf-8")
    assert "refreshed" in refresh_directive_block(marked)
    text = marked.read_text(encoding="utf-8")
    assert "keep me" in text and "after" in text and "old directives" not in text
    assert AGENT_DIRECTIVES_TEMPLATE.strip().splitlines()[0] in text
    assert refresh_directive_block(marked) is None  # already current

    unmarked = tmp_path / "AGENT.md"
    unmarked.write_text("# BANH-MI-GUARD protocol, pasted by hand\n", encoding="utf-8")
    assert refresh_directive_block(unmarked).startswith("WARN")
    assert unmarked.read_text(encoding="utf-8") == "# BANH-MI-GUARD protocol, pasted by hand\n"


def test_refresh_after_upgrade_updates_guard_hooks_inside_git_once(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    ensure_repo_setup(repo)
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text(hook.read_text(encoding="utf-8").replace("guard post --hook", "guard post"), encoding="utf-8")
    monkeypatch.setattr(repo_setup, "__version__", "9.9.9")
    msgs = refresh_after_upgrade()
    assert msgs and "guard post --hook" in hook.read_text(encoding="utf-8")
    assert refresh_after_upgrade() == []  # once per version


def test_pre_with_local_invariants_keeps_the_tree_clean(tmp_path):
    repo = make_repo(tmp_path, str(guard_home() / "hooks"))
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    assert (repo / ".guard" / "invariants.json").is_file()
    assert_clean(repo)


def test_unmarked_directives_warning_says_how_to_fix(tmp_path):
    doc = tmp_path / "AGENT.md"
    doc.write_text("# BANH-MI-GUARD protocol pasted by hand\n", encoding="utf-8")
    msg = refresh_directive_block(doc)
    assert DIRECTIVE_START in msg and "guard hook install --mode agent" in msg


def test_update_self_refreshes_with_the_new_binary(monkeypatch):
    from unittest.mock import patch
    from typer.testing import CliRunner
    from guard.cli import app

    calls = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)

        class P:
            returncode = 0
        return P()

    with patch("guard.commands.maintenance.perform_self_upgrade", return_value=(True, "upgraded")), \
         patch("guard.cli.subprocess.run", side_effect=fake_run):
        result = CliRunner().invoke(app, ["update", "self"])
    assert result.exit_code == 0
    assert any(cmd[-2:] == ["hook", "refresh"] for cmd in calls)
