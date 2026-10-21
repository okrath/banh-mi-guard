"""
The suite never reaches the repository whose git hook runs it.

A git hook exports GIT_DIR, GIT_INDEX_FILE and friends; without the scrub in conftest.py a test's
`git -C <tmp repo>` acts on the hook's repository instead (it once wrote `.git/guard-build.json`,
set `core.bare` and registered worktrees there).
"""

import os
import subprocess
import sys
from pathlib import Path

from guard.core.build_command import set_build_command

ROOT = Path(__file__).resolve().parents[1]
WORKLOAD = "tests/test_git_env_isolation.py::test_git_calls_in_a_temp_repo_stay_in_the_temp_repo"


def git(repo: Path, *args: str, env: dict | None = None) -> str:
    res = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8",
                         errors="replace", check=True, env=env)
    return (res.stdout or "").strip()


def test_git_calls_in_a_temp_repo_stay_in_the_temp_repo(tmp_path):
    """The workload: what the leaking tests did. On its own it only touches tmp_path."""
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
    (repo / "a.txt").write_text("one\n", encoding="utf-8")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-q", "-m", "init")
    set_build_command(repo, f'{Path(sys.executable).as_posix()} -c "import sys; sys.exit(3)"')
    git(repo, "worktree", "add", "-q", str(tmp_path / "linked"))
    git(repo, "config", "core.bare", "true")
    assert (repo / ".git" / "guard-build.json").is_file()


def _snapshot(sentinel: Path) -> tuple:
    return (
        (sentinel / ".git" / "config").read_bytes(),
        git(sentinel, "worktree", "list", "--porcelain"),
        (sentinel / ".git" / "guard-build.json").exists(),
    )


def test_an_inherited_git_dir_never_reaches_the_hook_repository(tmp_path):
    sentinel = tmp_path / "sentinel"
    subprocess.run(["git", "init", "-q", str(sentinel)], check=True, capture_output=True)
    (sentinel / "s.txt").write_text("sentinel\n", encoding="utf-8")
    git(sentinel, "add", "s.txt")
    git(sentinel, "commit", "-q", "-m", "sentinel")
    before = _snapshot(sentinel)

    hook_env = {  # what a pre-commit hook in the sentinel exports to the suite it runs
        **os.environ,
        "GIT_DIR": str(sentinel / ".git"),
        "GIT_WORK_TREE": str(sentinel),
        "GIT_INDEX_FILE": str(sentinel / ".git" / "index"),
        "GIT_PREFIX": "",
    }
    res = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", WORKLOAD],
                         cwd=ROOT, env=hook_env, capture_output=True, text=True, encoding="utf-8", errors="replace")

    assert _snapshot(sentinel) == before  # config, worktree list, no guard-build.json: all untouched
    assert res.returncode == 0, res.stdout[-2000:] + res.stderr[-2000:]  # the workload ran in its temp repo
