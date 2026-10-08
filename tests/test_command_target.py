"""Tests for strict command target resolution across shells."""

from __future__ import annotations

import ast
import importlib.util
import os
import subprocess
import time
from pathlib import Path

import pytest

from guard.agent.bash import _extract_literal_path, is_git_commit, is_read_only, strict_target

GC = "git " + "commit"

RESOLVE_CASES = [
    # Reported shapes with shell="powershell"
    ("Set-Location {wt}; git commit -m x", "powershell", "wt"),
    ("Set-Location -LiteralPath '{wt_space}'; git commit", "powershell", "wt_space"),
    ("Set-Location wt; git commit", "powershell", "wt"),
    ("sl wt; git commit", "powershell", "wt"),
    ("chdir wt; git commit", "powershell", "wt"),
    ("sl -LiteralPath '{wtx}'; git commit", "powershell", "wtx"),
    ("pushd {wt}; git commit", "powershell", "wt"),
    ("pushd wt; git commit", "powershell", "wt"),
    ("Set-Location -Path {wt}; git commit", "powershell", "wt"),
    ("Set-Location -Path wt; git commit", "powershell", "wt"),
    # Safe quoted commit messages (T1c/T1d rows narrowed per review rule 2)
    ("Set-Location {wt}; git commit -m 'release'", "powershell", "wt"),
    ("Set-Location wt; git commit -m 'release'", "powershell", "wt"),
    ('cd wt && git commit -m "release"', "bash", "wt"),
    # git -C in every shell
    ("git -C wt commit -m x", None, "wt"),
    ("git -C wt commit -m x", "powershell", "wt"),
    ("git -C wt commit -m x", "bash", "wt"),
    ("git -C wt commit -m x", "cmd", "wt"),
    ("git -C {wt} commit -m x", "powershell", "wt"),
    ("git -C {wt} commit -m x", "cmd", "wt"),
    ("git -C wt -c core.x=y commit", None, "wt"),
    ("git -C wt -c core.x=y commit", "bash", "wt"),
    ("git -C wt -c core.x=y commit", "powershell", "wt"),
    ('git -C wt commit -m "release v1"', "bash", "wt"),
    # cmd
    ("cd /d {wt} && git commit", "cmd", "wt"),
    ("cd wt && git commit", "cmd", "wt"),
    # bash (relative path)
    ("cd wt && git commit", "bash", "wt"),
    # powershell
    ("cd {wt} && git commit", "powershell", "wt"),
    ("cd wt && git commit", "powershell", "wt"),
    # None (unknown shell: plain cd, no backslash)
    ("cd wt && git commit", None, "wt"),
]


@pytest.mark.parametrize("cmd_tmpl,shell,target_key", RESOLVE_CASES)
def test_resolve_to_worktree(cmd_tmpl: str, shell: str | None, target_key: str, tmp_path: Path):
    wt = tmp_path / "wt"
    wt_space = tmp_path / "wt space"
    wtx = tmp_path / "wt[x]"
    wt.mkdir(exist_ok=True)
    wt_space.mkdir(exist_ok=True)
    wtx.mkdir(exist_ok=True)

    targets = {
        "wt": os.path.normcase(str(wt.resolve())),
        "wt_space": os.path.normcase(str(wt_space.resolve())),
        "wtx": os.path.normcase(str(wtx.resolve())),
    }
    expected = targets[target_key]
    cmd = cmd_tmpl.format(wt=str(wt), wt_space=str(wt_space), wtx=str(wtx))
    cwd_str = str(tmp_path)
    assert strict_target(cmd, cwd_str, shell=shell) == expected, f"Failed on {cmd} ({shell=})"


ATTACK_CASES = [
    # Attack vectors and cd chains
    "cd wt && cd .. && git commit",
    "cd wt && cd ../other && git commit",
    "cd wt; cd ..; git commit",
    "cd wt || git commit",
    "cd wt && echo foo | git commit",
    "cd wt && git commit `cd ..`",
    "cd wt && git commit $(cd ..)",
    "cd wt && git commit <(echo foo)",
    "cd wt && VAR=1 git commit",
    "cd wt && env -C .. git commit",
    "cd wt && sudo -D .. git commit",
    "cd wt && git -C .. commit",
    "cd wt && git --git-dir=../.git commit",
    "cd wt && git --work-tree=.. commit",
    "cd wt && GIT_DIR=../.git git commit",
    "cd wt && GIT_WORK_TREE=.. git commit",
    "git -C wt -C .. commit",
    "git -C wt; cd ..; git commit",
    "git -C wt && cd .. && git commit",
    "git -C wt || git commit",
    "git -C wt | git commit",
    "git -C wt\ncd ..\ngit commit",
    "git -C wt commit; git commit",
    "git -C wt log; git commit",
    'cd "$HOME/x" && git commit',
    'cd "`pwd`" && git commit',
    "cd /d/repo && git commit",
    "cd -d wt; git commit",
    "cd -- wt; git commit",
    "cd -; git commit",
    "cd wt; cd ..; git commit",
    "cd $X; git commit",
    "cd newdir_missing; git ci",
    "git --git-dir=.git ci",
    "GIT_DIR=.git git ci",
    "cd ~; git commit",
    "cd ~user; git commit",
    "cd HKCU:\\Software; git commit",
    "cd C:relative\\path; git commit",
]


@pytest.mark.parametrize("cmd", ATTACK_CASES)
def test_attack_cases_return_none(cmd: str, tmp_path: Path):
    wt = tmp_path / "wt"
    wt.mkdir(exist_ok=True)
    cwd_str = str(tmp_path)
    assert strict_target(cmd, cwd_str) is None, f"Expected None for {cmd}"


SHELL_SPECIFIC_CASES = [
    # Backslash in bash/None cd target
    ("cd wt\\sub && git commit", "bash"),
    ("cd wt\\sub && git commit", None),
    # Wildcards in PowerShell without -LiteralPath
    ("Set-Location '{wtx}'; git commit", "powershell"),
    ("sl '{wtx}'; git commit", "powershell"),
    # Semicolon in bash cd
    ("cd wt; cd ..; git commit", "bash"),
    ("cd ../other; git commit", "bash"),
    # Semicolon in cmd cd (cmd does not support ; as separator)
    ("cd wt; git commit", "cmd"),
    # cd across drives without /d in cmd
    ("cd X:\\wt && git commit", "cmd"),
    # Unknown shell cd with ;
    ("cd wt; git commit", None),
    # Unquoted rest quotes in unknown shell
    ("cd wt && git commit -m 'a & cd /d other & git commit -m 'b'", None),
    # PowerShell $(...) inside double quotes expands in-process
    ('Set-Location wt; git commit -m "$(cd ..)"', "powershell"),
    ('Set-Location {wt}; git commit -m "$(cd ..)"', "powershell"),
    # Narrowed rows from T1c/T1d where quotes contain cd or command separators
    ("Set-Location {wt}; git commit -m 'cd ..'", "powershell"),
    ("Set-Location wt; git commit -m 'cd ..'", "powershell"),
    ('cd wt && git commit -m "$(cd ..)"', "bash"),
    ('git -C wt commit -m "cd elsewhere; bash $x"', "bash"),
    # Review item 1: PowerShell/cmd backslash is NOT an escape inside double quotes
    ('Set-Location wt; git log -1 "src\\"; cd ..; git commit -m "y"', "powershell"),
    ('git -C wt status "src\\"; cd ..; git commit "y"', "powershell"),
    ('git -C wt status "src\\"; cd ..; git commit "y"', "cmd"),
    ('git -C wt status "src\\"; cd ..; git commit "y"', None),
    ('cd /d wt && echo "dir\\" && cd .. && git commit "y"', "cmd"),
    # Review item 1: Bash apostrophe idioms
    ("cd wt && echo 'it'\\''s'; cd ..; git commit -m 'x'", "bash"),
    ("cd wt && echo don\\'t; cd ..; git commit -m 'x'", "bash"),
    ("git -C wt log --format='it'\\''s'; cd ..; git commit 'x'", "bash"),
    # Review item 1: Comments with apostrophes
    ("Set-Location wt; echo x # it's\ncd ..\ngit commit 'z'", "powershell"),
    ("Set-Location wt; echo x <# it's #> ; cd .. ; git commit # '", "powershell"),
    ("cd wt && echo x # it's\ncd ..\ngit commit 'x'", "bash"),
    ("git -C wt status # it's\ncd ..\ngit commit 'x'", "bash"),
    ("cd wt && echo x # it's\ncd ..\ngit commit 'x'", None),
    ("git -C wt status # it's\ncd ..\ngit commit 'x'", None),
    # Review item 1: Heredoc / here-string with apostrophe in body
    ("cd wt && cat <<'EOF'\nit's\nEOF\ncd ..\ngit commit 'x'", "bash"),
    ("Set-Location wt; echo @'\nit's\n'@\ncd ..\ngit commit 'x'", "powershell"),
    # Review item 1: PowerShell curly quotes (U+2018..U+201E)
    ("Set-Location wt; echo 'x\u2019; cd ..; git commit; echo \u2019y'", "powershell"),
    # Review item 1: Indirect execution
    ("cd wt && eval 'cd ..'; git commit", "bash"),
    ('cd wt && eval "cd .."; git commit', "bash"),
    ("cd wt && source /dev/stdin <<< 'cd ..'; git commit", "bash"),
    ("Set-Location wt; . ([scriptblock]::Create('cd ..')); git commit", "powershell"),
    ("Invoke-Command -ScriptBlock ([scriptblock]::Create('Set-Location ..'))", "powershell"),
    ("cd wt && zsh -c 'cd ..'; git commit", "bash"),
    ("cd wt && dash -c 'cd ..'; git commit", "bash"),
    ("cd wt && ksh -c 'cd ..'; git commit", "bash"),
    ("cd wt && wsl cd ..; git commit", "bash"),
    ("Set-Location wt; icm -ScriptBlock { cd .. }; git commit", "powershell"),
    ("cd wt && exec cd ..; git commit", "bash"),
    ("cd wt && . ./run.sh; git commit", "bash"),
    # Review item 1: cmd caret
    ("cd w^t && git commit", "cmd"),
    ('cd "w^t" && git commit', "cmd"),
]


@pytest.mark.parametrize("cmd_tmpl,shell", SHELL_SPECIFIC_CASES)
def test_shell_specific_cases_return_none(cmd_tmpl: str, shell: str | None, tmp_path: Path):
    wt = tmp_path / "wt"
    wtx = tmp_path / "wt[x]"
    wt.mkdir(exist_ok=True)
    wtx.mkdir(exist_ok=True)
    cwd_str = str(tmp_path)
    cmd = cmd_tmpl.format(wt=str(wt), wtx=str(wtx)) if ("{wt}" in cmd_tmpl or "{wtx}" in cmd_tmpl) else cmd_tmpl
    assert strict_target(cmd, cwd_str, shell=shell) is None, f"Expected None for {cmd} in {shell}"


def test_bash_cdpath_relative_returns_none(tmp_path: Path):
    wt = tmp_path / "wt"
    wt.mkdir(exist_ok=True)
    cwd_str = str(tmp_path)
    env = {"CDPATH": str(tmp_path)}
    assert strict_target(f"cd wt; {GC}", cwd_str, shell="bash", env=env) is None
    assert strict_target(f"cd wt && {GC}", cwd_str, shell="bash", env=env) is None


@pytest.mark.parametrize("shell", [None, "bash", "powershell", "cmd"])
@pytest.mark.parametrize("pattern", ['"\\', '\\"', '\n', '; '])
def test_linear_regex_timing_100k(shell: str | None, pattern: str, tmp_path: Path):
    wt = tmp_path / "wt"
    wt.mkdir(exist_ok=True)
    cwd_str = str(tmp_path)
    repeat_count = 100_000 if len(pattern) == 1 else 50_000
    if pattern in ('"\\', '\\"'):
        huge_input = f"cd wt && {GC} -m {pattern * repeat_count}"
    else:
        huge_input = f"cd wt && {GC} -m x" + (pattern * repeat_count) + "cd .."
    t0 = time.perf_counter()
    res = strict_target(huge_input, cwd_str, shell=shell)
    elapsed = time.perf_counter() - t0
    # Real measured time: 0.00003s - 0.015s across quote, newline, and separator repeats
    # (strictly linear O(N) segmentation and scanning; former regexes took >90s at 100k).
    # Generous ceiling is 1.0s.
    assert res is None
    assert elapsed < 1.0, f"Quadratic performance detected: took {elapsed:.2f}s for {shell=}, {pattern=}"


@pytest.mark.parametrize("bad_cwd", ["", "   ", "relative/path", "./rel"])
def test_relative_or_empty_cwd_returns_none(bad_cwd: str, tmp_path: Path):
    wt = tmp_path / "wt"
    wt.mkdir(exist_ok=True)
    assert strict_target(f"cd {wt} && {GC}", bad_cwd) is None


def test_aliases_is_git_commit(tmp_path: Path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init", str(repo_dir)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "alias.ci", "commit"], check=True, capture_output=True)

    alias_cases = [
        "cd newdir_missing; git ci",
        "git --git-dir=.git ci",
        "GIT_DIR=.git git ci",
    ]

    cwd_str = str(repo_dir)
    for cmd in alias_cases:
        assert strict_target(cmd, cwd_str) is None
        assert is_git_commit(cmd, repo_dir) is True, f"Expected is_git_commit True for {cmd}"


def test_unchanged_functions(tmp_path: Path):
    repo_root = Path(__file__).resolve().parent.parent
    old_code = None
    for ref in ["origin/main:guard/agent/bash.py", "main:guard/agent/bash.py"]:
        try:
            old_code = subprocess.check_output(
                ["git", "show", ref],
                text=True,
                encoding="utf-8",
                cwd=repo_root,
                stderr=subprocess.DEVNULL,
            )
            break
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue

    if old_code is None:
        pytest.skip("baseline origin/main:guard/agent/bash.py not available in this clone")

    old_file = tmp_path / "old_bash.py"
    old_file.write_text(old_code, encoding="utf-8")

    spec = importlib.util.spec_from_file_location("old_bash_baseline", old_file)
    assert spec is not None and spec.loader is not None
    old_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old_mod)

    # Harvest string constants from tests/test_agent_events.py and tests/test_hooks.py via AST
    commands: set[str] = set()
    for rel_path in ["tests/test_agent_events.py", "tests/test_hooks.py"]:
        test_file = repo_root / rel_path
        if test_file.exists():
            tree = ast.parse(test_file.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    val = node.value.strip()
                    if any(val.startswith(p) for p in ("git", "cd", "ls", "echo", "sh", "bash", "env", "sudo")):
                        commands.add(val)

    assert len(commands) >= 20
    for cmd in commands:
        assert is_git_commit(cmd) == old_mod.is_git_commit(cmd), f"Mismatch for is_git_commit: {cmd}"
        assert is_read_only(cmd) == old_mod.is_read_only(cmd), f"Mismatch for is_read_only: {cmd}"


def test_extract_literal_path_helper():
    res = _extract_literal_path("dir and_more")
    assert res is not None
    assert res[0] == "dir"
    assert _extract_literal_path('"quoted dir" and_more') == ("quoted dir", " and_more")
    assert _extract_literal_path("") is None

