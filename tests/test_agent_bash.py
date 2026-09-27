"""
Which shell commands an agent may run before `guard pre` without being measured, and how a
command's effect on the working tree is found.
"""

import subprocess

import pytest

from guard.agent.bash import changed_between, is_git_commit, is_read_only, worktree_fingerprint


@pytest.mark.parametrize("command", [
    "ls -la", "cat README.md", "git status", "git diff HEAD -- src", "git log --oneline -5 | head -3",
    "grep -rn foo src && wc -l src/a.py", "find . -name '*.py'", "FOO=1 git show HEAD:a.py",
    "git -C repo status", "git branch --show-current", 'guard pre "fix it" --scope a.py', "echo hello",
    "rg -n 'x > y' src",  # a quoted ">" is text, not a redirect
])
def test_read_only_commands(command):
    assert is_read_only(command) is True


@pytest.mark.parametrize("command", [
    "echo x > a.py", "cat a >> b", "git status > out.txt", "ls | tee list.txt", "sed -i s/a/b/ a.py",
    "python script.py", "npm run build", "rm -rf build", "git checkout -- a.py", "git commit -m x",
    "find . -name '*.pyc' -delete", "find . -exec rm {} ;", "echo $(rm a.py)", "cat `ls`",
    "ls && python x.py", "git branch -D old", "echo 'unbalanced",
])
def test_commands_that_are_measured(command):
    assert is_read_only(command) is False


@pytest.mark.parametrize("command, commit", [
    ("git commit -m 'x'", True), ("git -C repo -c user.name=x commit -am y", True),
    ("git add . && git commit -m x", True), ("git log --grep commit", False), ("echo git commit", False),
])
def test_git_commit_detection(command, commit):
    assert is_git_commit(command) is commit


def test_fingerprint_sees_edits_new_and_removed_files_but_not_ignored_ones(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    for cmd in (["git", "init"], ["git", "config", "user.email", "t@t"], ["git", "config", "user.name", "t"]):
        subprocess.run(cmd, cwd=repo, check=True, capture_output=True)
    (repo / ".gitignore").write_text("build/\n", encoding="utf-8")
    (repo / "a.py").write_text("a = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

    before = worktree_fingerprint(repo)
    (repo / "a.py").write_text("a = 2\n", encoding="utf-8")
    (repo / "b.py").write_text("b = 1\n", encoding="utf-8")
    (repo / "build").mkdir()
    (repo / "build" / "out.js").write_text("x", encoding="utf-8")  # gitignored: not a code change
    assert changed_between(before, worktree_fingerprint(repo)) == ["a.py", "b.py"]


def test_command_wrappers_are_not_readers():
    assert is_read_only("env rm -rf build") is False  # env runs its arguments
    assert is_read_only("printenv PATH") is True


def test_a_retargeted_symlink_is_a_change(tmp_path):
    import os
    from guard.agent.bash import content_hash
    (tmp_path / "a").write_text("same", encoding="utf-8")
    (tmp_path / "b").write_text("same", encoding="utf-8")
    link = tmp_path / "link"
    try:
        os.symlink(tmp_path / "a", link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks need extra rights on this machine")
    first = content_hash(link)
    link.unlink()
    os.symlink(tmp_path / "b", link)
    assert content_hash(link) != first  # same bytes behind it, different link


@pytest.mark.parametrize("command", [
    "git diff --output=patch.txt", "git log -o out.txt", "tree -o list.txt", "date -s 2020-01-01",
    "guard post", "guard hook install", "guard pre x && guard post",
])
def test_readers_with_write_options_and_writing_guard_commands_are_measured(command):
    assert is_read_only(command) is False


@pytest.mark.parametrize("command", ["guard doctor", "guard invariants check", "guard config", "guard --help"])
def test_reading_guard_commands_pass(command):
    assert is_read_only(command) is True


@pytest.mark.parametrize("command", [
    'sh -c "git commit -m x"', "bash -lc 'git add . && git commit -m y'", "env GIT_AUTHOR_NAME=a git commit -m x",
    "sudo -u me git commit -m x", "echo x | xargs git commit -m", "timeout 30 git commit -m x",
    'powershell -Command "git commit -m x"',
])
def test_wrapped_commits_are_found(command):
    assert is_git_commit(command) is True


def test_git_alias_for_commit_is_found(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "alias.ci", "commit -v"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "alias.save", "!git add -A && git commit -m wip"], cwd=repo, check=True, capture_output=True)
    assert is_git_commit("git ci -m x", repo) is True and is_git_commit("git save", repo) is True
    assert is_git_commit("git st", repo) is False
