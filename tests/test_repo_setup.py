"""
Lazy repository setup and refresh-after-upgrade. Rule under test: guard never creates a diff in
the user's repository; it writes only inside .git and the Git-excluded .guard/ folder, and it
reports (never edits) repository files such as agent docs and hooks kept in the tree.
"""

import os
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
)
from guard.core.setup_health import setup_health
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


# --- what guard <= 0.10 (laya-ocr-guard) left behind ----------------------------------------------
# The 0.1.0 hooks verbatim (1a571a5:guard/hooks/templates.py) and the 0.10 markers (181bb82^)

LAYA_PRE_COMMIT = """#!/usr/bin/env sh
# --- LAYA-OCR-GUARD AUTO-GENERATED HOOK ---
echo "🛡️  Running Laya-OCR-Guard Pre-Commit Check..."
guard post
STATUS=$?
if [ $STATUS -ne 0 ]; then
  echo "❌ Guard Verification FAILED! Commit aborted."
  echo "💡 Tip: Review the violations above or run 'guard post' manually."
  exit 1
fi
echo "✅ Guard Verification PASSED. Proceeding with commit."
exit 0
"""
LAYA_PREPARE_COMMIT_MSG = """#!/usr/bin/env sh
# --- LAYA-OCR-GUARD COMMIT MSG HOOK ---
COMMIT_MSG_FILE=$1
COMMIT_SOURCE=$2

# Only append if message is not an amend or merge
if [ "$COMMIT_SOURCE" != "commit" ] && [ -f ".guard/session.json" ]; then
  echo "" >> "$COMMIT_MSG_FILE"
  echo "Approved-by: Laya-OCR-Guard (Muse Verification)" >> "$COMMIT_MSG_FILE"
fi
"""
LAYA_HOOK_BLOCK = """# >>> LAYA-OCR-GUARD >>>
# Added by guard: this repository sets its own core.hooksPath, so the global guard hook does not run here.
if command -v guard >/dev/null 2>&1; then
  guard post --hook || exit 1
fi
# <<< LAYA-OCR-GUARD <<<
"""
LAYA_MANUAL_LINE = "if command -v guard >/dev/null 2>&1; then guard post --hook || exit 1; fi  # LAYA-OCR-GUARD"


def plant_laya_hooks(repo: Path) -> Path:
    hooks = repo / ".git" / "hooks"
    for name, text in (("pre-commit", LAYA_PRE_COMMIT), ("prepare-commit-msg", LAYA_PREPARE_COMMIT_MSG)):
        (hooks / name).write_text(text, encoding="utf-8", newline="\n")
        (hooks / name).chmod(0o755)
    return hooks


def use_global_guard_hooks(repo: Path) -> None:
    from guard.hooks.templates import GIT_PRE_COMMIT_HOOK, GIT_PREPARE_COMMIT_MSG_HOOK
    hooks = guard_home() / "hooks"
    for name, text in (("pre-commit", GIT_PRE_COMMIT_HOOK), ("prepare-commit-msg", GIT_PREPARE_COMMIT_MSG_HOOK)):
        repo_setup._write_exec(hooks / name, text)
    git(repo, "config", "--global", "core.hooksPath", str(hooks))  # GIT_CONFIG_GLOBAL is the test's own


def test_global_hooks_never_chain_a_laya_hook_on_a_real_commit(tmp_path):
    repo = make_repo(tmp_path)
    plant_laya_hooks(repo)
    use_global_guard_hooks(repo)
    (repo / ".guard").mkdir(exist_ok=True)
    (repo / ".guard" / "session.json").write_text("{}", encoding="utf-8")  # 0.1.0's trailer condition
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    git(repo, "add", "a.txt")
    # the hook's `guard` runs this checkout's code, so it never rewrites the hook it runs from
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    out = subprocess.run(["git", "commit", "-m", "feat: short comment"], cwd=repo, capture_output=True,
                         text=True, encoding="utf-8", errors="replace", env=env)
    assert out.returncode == 0, out.stderr
    assert "Laya" not in out.stdout + out.stderr  # no old banner, no second guard post
    assert "Laya-OCR-Guard" not in git(repo, "log", "-1", "--format=%B")  # no trailer


def test_laya_hooks_are_removed_when_the_global_hooks_serve_the_repo(tmp_path):
    repo = make_repo(tmp_path)
    hooks = plant_laya_hooks(repo)
    use_global_guard_hooks(repo)
    messages = repo_setup.refresh_repo(repo)
    assert not (hooks / "pre-commit").exists() and not (hooks / "prepare-commit-msg").exists()
    assert (hooks / "pre-commit.laya.bak").read_text(encoding="utf-8") == LAYA_PRE_COMMIT
    assert any("removed the old laya-ocr-guard hook" in m for m in messages)
    assert_clean(repo)


def test_laya_hooks_are_replaced_when_the_repo_uses_its_own_hooks(tmp_path):
    from guard.hooks.templates import GIT_PRE_COMMIT_HOOK, GIT_PREPARE_COMMIT_MSG_HOOK
    repo = make_repo(tmp_path)
    hooks = plant_laya_hooks(repo)
    repo_setup.refresh_repo(repo)
    assert (hooks / "pre-commit").read_text(encoding="utf-8") == GIT_PRE_COMMIT_HOOK
    assert (hooks / "prepare-commit-msg").read_text(encoding="utf-8") == GIT_PREPARE_COMMIT_MSG_HOOK
    assert (hooks / "prepare-commit-msg.laya.bak").exists()


def test_a_laya_block_or_line_in_the_users_own_hook_is_updated(tmp_path):
    repo = make_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\n" + LAYA_HOOK_BLOCK + "npm run lint\n", encoding="utf-8", newline="\n")
    repo_setup.refresh_repo(repo)
    text = hook.read_text(encoding="utf-8")
    assert "LAYA" not in text and repo_setup.HOOK_BLOCK in text and "npm run lint" in text
    hook.write_text("#!/bin/sh\n" + LAYA_MANUAL_LINE + "\nnpm test\n", encoding="utf-8", newline="\n")
    repo_setup.refresh_repo(repo)
    text = hook.read_text(encoding="utf-8")
    assert repo_setup.MANUAL_HOOK_LINE in text and "LAYA" not in text and "npm test" in text


def test_the_laya_wrapper_and_exclude_comment_are_cleaned(tmp_path):
    repo = make_repo(tmp_path)
    wrapper = repo / ".guard" / "bin" / "guard-exec"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text("#!/usr/bin/env sh\n# --- LAYA-OCR-GUARD AGENT HARNESS ---\n", encoding="utf-8")
    exclude = repo / ".git" / "info" / "exclude"
    exclude.write_text("# Laya-OCR-Guard local exclude\n.guard/\n", encoding="utf-8")
    repo_setup.refresh_repo(repo)
    assert not wrapper.exists()
    assert exclude.read_text(encoding="utf-8") == "# Banh-Mi-Guard local exclude\n.guard/\n"


def test_a_laya_directive_block_in_a_global_doc_is_refreshed(tmp_path):
    doc = tmp_path / "CLAUDE.md"
    doc.write_text("# mine\n\n" + repo_setup.LEGACY_DIRECTIVE_START + "\nold rules\n" + repo_setup.LEGACY_DIRECTIVE_END + "\n",
                   encoding="utf-8")
    assert refresh_directive_block(doc)
    text = doc.read_text(encoding="utf-8")
    assert "LAYA" not in text and DIRECTIVE_START in text and "old rules" not in text and "# mine" in text


def test_a_lone_old_directive_start_never_takes_user_text_with_it(tmp_path):
    from guard.core.repo_setup import remove_directive_block
    doc = tmp_path / "CLAUDE.md"
    text = f"{repo_setup.LEGACY_DIRECTIVE_START}\nmy own notes\n{DIRECTIVE_START}\nrules\n{DIRECTIVE_END}\n"
    doc.write_text(text, encoding="utf-8")
    remove_directive_block(doc)
    assert "my own notes" in doc.read_text(encoding="utf-8")


def test_an_old_hook_copy_is_never_overwritten(tmp_path):
    repo = make_repo(tmp_path)
    hooks = plant_laya_hooks(repo)
    (hooks / "pre-commit.laya.bak").write_text("an older copy\n", encoding="utf-8")
    repo_setup.refresh_repo(repo)
    assert (hooks / "pre-commit.laya.bak").read_text(encoding="utf-8") == "an older copy\n"
    assert (hooks / "pre-commit.laya.2.bak").read_text(encoding="utf-8") == LAYA_PRE_COMMIT



def test_an_old_hook_parked_as_guard_bak_never_runs_and_is_cleaned(tmp_path):
    repo = make_repo(tmp_path)
    hooks = repo / ".git" / "hooks"
    (hooks / "prepare-commit-msg.guard.bak").write_text(LAYA_PREPARE_COMMIT_MSG, encoding="utf-8", newline="\n")
    (hooks / "prepare-commit-msg.guard.bak").chmod(0o755)
    use_global_guard_hooks(repo)
    (repo / ".guard").mkdir(exist_ok=True)
    (repo / ".guard" / "session.json").write_text("{}", encoding="utf-8")
    (repo / "b.txt").write_text("b\n", encoding="utf-8")
    git(repo, "add", "b.txt")
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    subprocess.run(["git", "commit", "-m", "feat: b"], cwd=repo, capture_output=True, env=env, check=True)
    assert "Laya-OCR-Guard" not in git(repo, "log", "-1", "--format=%B")  # skipped by the global hook
    repo_setup.refresh_repo(repo)  # (the commit's own guard run may already have cleaned it)
    assert not (hooks / "prepare-commit-msg.guard.bak").exists()
    assert (hooks / "prepare-commit-msg.laya.bak").exists()


def test_the_cleanup_message_names_the_copy_it_really_made(tmp_path):
    repo = make_repo(tmp_path)
    hooks = plant_laya_hooks(repo)
    (hooks / "pre-commit.laya.bak").write_text("older\n", encoding="utf-8")
    messages = repo_setup.refresh_repo(repo)
    assert any("copy in pre-commit.laya.2.bak" in m for m in messages)


def test_under_global_hooks_a_users_hook_keeps_its_commands_and_still_runs(tmp_path):
    repo = make_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\n" + LAYA_HOOK_BLOCK + "npm run lint\n", encoding="utf-8", newline="\n")
    use_global_guard_hooks(repo)
    repo_setup.refresh_repo(repo)
    text = hook.read_text(encoding="utf-8")
    assert text == "#!/bin/sh\nnpm run lint\n"  # no guard marker: the global hook still chains it
