"""Tests for strict command target resolution allow-list grammar."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from guard.agent.bash import is_git_commit, strict_target

GC = "git " + "commit"

RESOLVE_CASES = [
    # PowerShell location commands
    ("Set-Location {wt}; git commit -m x", "powershell", "wt"),
    ("Set-Location -LiteralPath '{wt_space}'; git commit", "powershell", "wt_space"),
    ("Set-Location -LiteralPath '{wtx}'; git commit", "powershell", "wtx"),
    ("sl -LiteralPath '{wtx}'; git commit", "powershell", "wtx"),
    ("Set-Location wt; git commit", "powershell", "wt"),
    ("sl wt; git commit", "powershell", "wt"),
    ("chdir wt; git commit", "powershell", "wt"),
    ("pushd {wt}; git commit", "powershell", "wt"),
    ("pushd wt; git commit", "powershell", "wt"),
    ("Set-Location -Path {wt}; git commit", "powershell", "wt"),
    ("Set-Location -Path wt; git commit", "powershell", "wt"),
    ("Push-Location -Path wt; git commit", "powershell", "wt"),
    ("Set-Location wt; git commit -m \"a b\"", "powershell", "wt"),
    # git -C across shells
    ("git -C wt commit -m \"fix: x\"", None, "wt"),
    ("git -C wt commit -m \"fix: x\"", "powershell", "wt"),
    ("git -C wt commit -m \"fix: x\"", "bash", "wt"),
    ("git -C wt commit -m \"fix: x\"", "cmd", "wt"),
    ("git -C {wt} commit -m x", "powershell", "wt"),
    ("git -C {wt} commit -m x", "cmd", "wt"),
    # cmd cd and chdir
    ("cd /d {wt} && git commit", "cmd", "wt"),
    ("cd wt && git commit", "cmd", "wt"),
    ("chdir wt && git commit", "cmd", "wt"),
    # bash cd
    ("cd wt && git commit -m 'release'", "bash", "wt"),
    ("cd wt && git commit", "bash", "wt"),
    ("cd {wt}; git commit", "powershell", "wt"),
    ("cd wt; git commit", "powershell", "wt"),
    ("cd wt && git commit", None, "wt"),
    # Multiple git segments in sequence
    ("cd wt && git add -A && git commit -m 'x'", "bash", "wt"),
    ("git -C wt add -A && git -C wt commit -m x", "bash", "wt"),
    # Quoted message with non-ASCII or data characters
    ("git -C wt commit -m 'sửa lỗi'", None, "wt"),
    ("git -C wt commit -m \"fix; a & b #12\"", None, "wt"),
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


NONE_CASES = [
    # 25 inputs from review round: glued quotes, backslashes, scripts, etc.
    ("c''d && git commit", "bash"),
    ("c\\d && git commit", "bash"),
    ("git '-C' .. commit", "bash"),
    ("git -''C .. commit", "bash"),
    ("'--work-tree=..' git commit", "bash"),
    ("'--git-dir=../.git' git commit", "bash"),
    ("env 'GIT_DIR=..' git commit", "bash"),
    ("export X=1; git commit", "bash"),
    ("set \"GIT_DIR=..\" && git commit", "cmd"),
    (".\\up.ps1; git commit", "powershell"),
    ("call .\\up.bat && git commit", "cmd"),
    ("start /D wt git commit", "cmd"),
    ("env --chd=.. git commit", "bash"),
    ("cd 'wt ' && git commit", "bash"),
    ("cd wt. && git commit", "bash"),
    ("ſl wt; git commit", "powershell"),
    ("Set-Locatİon wt; git commit", "powershell"),
    ("cd \"wt\"/sub && git commit", "bash"),
    ("cd 'a''b' && git commit", "bash"),
    ("cd a\\ b && git commit", "bash"),
    ("Set-Location wt -PassThru | Out-Null;", "powershell"),
    ("-StackName", "powershell"),
    ("pushd -n wt; git commit", "powershell"),
    ("pushd +1 wt; git commit", "powershell"),
    ("HKLM:\\ && git commit", "powershell"),

    # Earlier T1/T1c dropped rows
    ("\"C:\\Program Files\\Git\\cmd\\git.exe\" -C wt commit", None),
    ("test -d wt && cd wt;", "bash"),
    ("false && cd wt;", "bash"),
    ("cmd /c \"cd D:\\x && git commit\"", "cmd"),
    ("cd D:x && git commit", "cmd"),
    ("cd D: && git commit", "cmd"),
    ("xargs -I{} git commit", "bash"),
    ("Set-Location wt; git commit", "bash"),
    ("sl wt; git commit", "bash"),
    ("chdir wt; git commit", "bash"),
    ("cd /d wt; git commit", "bash"),
    ("cd /d wt; git commit", "powershell"),
    ("cd -Path wt; git commit", "bash"),
    ("pushd -Path wt; git commit", "bash"),
    ("cd wt && git commit", "powershell"),
    ("cd {wt} && git commit", "powershell"),

    # Review round 2 (t1-fixes-r2 item-1 inputs)
    ("Set-Location wt; git log -1 \"src\\\"; cd ..; git commit -m \"y\"", "powershell"),
    ("git -C wt status \"src\\\"; cd ..; git commit \"y\"", "powershell"),
    ("git -C wt status \"src\\\"; cd ..; git commit \"y\"", "cmd"),
    ("git -C wt status \"src\\\"; cd ..; git commit \"y\"", None),
    ("cd /d wt && echo \"dir\\\" && cd .. && git commit \"y\"", "cmd"),
    ("cd wt && echo 'it'\\''s'; cd ..; git commit -m 'x'", "bash"),
    ("cd wt && echo don\\'t; cd ..; git commit -m 'x'", "bash"),
    ("git -C wt log --format='it'\\''s'; cd ..; git commit 'x'", "bash"),
    ("Set-Location wt; echo x # it's\ncd ..\ngit commit 'z'", "powershell"),
    ("Set-Location wt; echo x <# it's #> ; cd .. ; git commit # '", "powershell"),
    ("cd wt && echo x # it's\ncd ..\ngit commit 'x'", "bash"),
    ("git -C wt status # it's\ncd ..\ngit commit 'x'", "bash"),
    ("cd wt && echo x # it's\ncd ..\ngit commit 'x'", None),
    ("git -C wt status # it's\ncd ..\ngit commit 'x'", None),
    ("cd wt && cat <<'EOF'\nit's\nEOF\ncd ..\ngit commit 'x'", "bash"),
    ("Set-Location wt; echo @'\nit's\n'@\ncd ..\ngit commit 'x'", "powershell"),
    ("Set-Location wt; echo 'x\u2019; cd ..; git commit; echo \u2019y'", "powershell"),
    ("cd wt && eval 'cd ..'; git commit", "bash"),
    ("cd wt && eval \"cd ..\"; git commit", "bash"),
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
    ("cd w^t && git commit", "cmd"),
    ("cd \"w^t\" && git commit", "cmd"),

    # Attack vectors and cd chains
    ("cd wt && cd .. && git commit", None),
    ("cd wt && cd ../other && git commit", None),
    ("cd wt; cd ..; git commit", None),
    ("cd wt || git commit", None),
    ("cd wt && echo foo | git commit", None),
    ("cd wt && git commit `cd ..`", None),
    ("cd wt && git commit $(cd ..)", None),
    ("cd wt && git commit <(echo foo)", None),
    ("cd wt && VAR=1 git commit", None),
    ("cd wt && env -C .. git commit", None),
    ("cd wt && sudo -D .. git commit", None),
    ("cd wt && git -C .. commit", None),
    ("cd wt && git --git-dir=../.git commit", None),
    ("cd wt && git --work-tree=.. commit", None),
    ("cd wt && GIT_DIR=../.git git commit", None),
    ("cd wt && GIT_WORK_TREE=.. git commit", None),
    ("git -C wt -C .. commit", None),
    ("git -C wt; cd ..; git commit", None),
    ("git -C wt && cd .. && git commit", None),
    ("git -C wt || git commit", None),
    ("git -C wt | git commit", None),
    ("git -C wt commit; git commit", None),
    ("git -C wt log; git commit", None),
    ("cd \"$HOME/x\" && git commit", None),
    ("cd \"`pwd`\" && git commit", None),
    ("cd /d/repo && git commit", None),
    ("cd -d wt; git commit", None),
    ("cd -- wt; git commit", None),
    ("cd -; git commit", None),
    ("cd wt; cd ..; git commit", None),
    ("cd $X; git commit", None),
    ("cd newdir_missing; git ci", None),
    ("git --git-dir=.git ci", None),
    ("GIT_DIR=.git git ci", None),
    ("cd ~; git commit", None),
    ("cd ~user; git commit", None),
    ("cd HKCU:\\Software; git commit", None),
    ("cd C:relative\\path; git commit", None),
    ("cd wt; git commit", None),
    ("cd wt; git commit", "cmd"),
    ("cd X:\\wt && git commit", "cmd"),
    ("cd wt; cd ..; git commit", "bash"),
    ("cd ../other; git commit", "bash"),
    ("cd wt\\sub && git commit", None),
    ("cd wt\\sub && git commit", "bash"),

    # Round 3 review items
    ("Set-Location a,b; git commit", "powershell"),
    ("Set-Location @a; git commit", "powershell"),
    ("CD wt && git commit", "bash"),
    ("cd wt && GIT commit", "bash"),
    ("git -C wt commit -m 'x && cd .. && git commit'", "cmd"),
    ("git -C wt commit -m 'x && cd .. && git commit'", None),
    ("git -C wt commit -m 'x | cd ..'", None),
    ("git -C wt commit -m 'x > out'", None),
    ("git -C /tmp/x commit", None),

    # PowerShell wildcard brackets expand unless -LiteralPath
    ("Set-Location '{wtx}'; git commit", "powershell"),
    ("sl '{wtx}'; git commit", "powershell"),
    ("Set-Location -Path '{wtx}'; git commit", "powershell"),

    # Leading separator, double separator, splat/array args in PowerShell
    ("; git commit", "powershell"),
    ("git commit;;", "powershell"),
    ("git commit @x", "powershell"),
    ("git commit a,b", "powershell"),

    # Control chars and length boundary
    ("git commit\0", None),
    ("git commit\r", None),
    ("git commit\n", None),
    ("cd wt && git commit " + ("x" * 4100), None),
]


@pytest.mark.parametrize("cmd_tmpl,shell", NONE_CASES)
def test_none_cases_return_none(cmd_tmpl: str, shell: str | None, tmp_path: Path):
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
    cmd = f"cd wt && {GC}"
    assert strict_target(cmd, cwd_str, shell="bash", env=env) is None


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
        assert is_git_commit(cmd, repo_dir) is True


@pytest.mark.parametrize("shell", [None, "bash", "powershell", "cmd"])
@pytest.mark.parametrize("pattern", ['"\\', '\\"', '\n', '; '])
def test_linear_regex_timing_100k(shell: str | None, pattern: str, tmp_path: Path):
    wt = tmp_path / "wt"
    wt.mkdir(exist_ok=True)
    cwd_str = str(tmp_path)
    repeat_count = 50_000
    huge_input = f"cd wt && {GC} -m " + (pattern * repeat_count)
    t0 = time.perf_counter()
    res = strict_target(huge_input, cwd_str, shell=shell)
    elapsed = time.perf_counter() - t0
    assert res is None
    # 4096-character limit rejects in < 0.0001s
    assert elapsed < 1.0, f"Quadratic performance detected: took {elapsed:.2f}s for {shell=}, {pattern=}"
