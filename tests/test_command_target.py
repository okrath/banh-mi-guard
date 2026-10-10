"""Tests for strict command target resolution allow-list grammar."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from guard.agent.bash import is_git_commit, strict_target

GC = "git " + "commit"
CI = "com" + "mit"

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
    ("git -C wt commit -m \"feat!: x\"", None, "wt"),
    # Parts after the commit segment are not read: only the segments up to it must parse
    ("cd wt && git add a && git commit -q -m \"x\" && git push -q 2>&1 | grep -v \"^remote:\"; git log --oneline -1", "bash", "wt"),
    ("cd wt && git commit -m x && gh pr create --body \"$(git log -1)\"", "bash", "wt"),
    ("git -C wt commit -m x; echo $HOME > out.txt", "bash", "wt"),
    ("Set-Location wt; git commit -m x; Write-Output $x", "powershell", "wt"),
    ("cd wt && git commit -m x; git log --oneline -1", "bash", "wt"),
    ("cd wt && git commit -m x && git push -q 2>&1 | grep -v \"^remote:\"", "bash", "wt"),
    ("cd wt && git commit -m x && npm ci", "bash", "wt"),
    ("cd wt && git commit -m x; echo python", "bash", "wt"),
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
    # Item 1: Subcommand allow-list and options after subcommand
    ("git -C wt difftool --cached -y -x \"unset GIT_DIR GIT_WORK_TREE; cd .. && git commit -m y; true\"", None),
    ("git -C wt rebase --autostash --root -x 'unset GIT_DIR GIT_WORK_TREE; cd .. && git commit -m y'", None),
    ("git -C wt ci", None),
    ("cd wt && git ci", None),
    ("git config alias.ci x && git -C wt commit", None),
    ("git -C wt commit -x cmd", None),
    ("git -C wt commit --exec cmd", None),
    ("git -C wt commit --extcmd cmd", None),
    ("git -C wt commit --exec=cmd", None),
    ("git -C wt commit --extcmd=cmd", None),
    ("git -C wt diff --ext-diff", None),
    ("git -C wt diff --textconv", None),
    ("git -C wt diff --output=out.txt", None),
    ("git -C wt log -o out.txt", None),
    ("git -C wt log --output out.txt", None),
    ("git -C wt commit -m \"100%\"", "cmd"),

    # Item 2: Empty quoted tokens
    ("git -C '' wt commit", None),
    ("git -C \"\" wt commit", None),
    ("git -C '' wt commit -m x", None),
    ("git -C '' wt commit", "powershell"),
    ("git -C \"\" wt commit", "powershell"),
    ("git -C '' wt commit", "cmd"),
    ("git -C \"\" wt commit", "cmd"),

    # Item 3: Trailing dot or space in ANY path component
    ("cd wt./sub; git commit", "bash"),
    ("cd 'wt /sub'; git commit", "bash"),
    ("Set-Location wt./sub; git commit", "powershell"),
    ("cd 'wt ' && git commit", "bash"),
    ("cd wt. && git commit", "bash"),

    # Item 4: Unknown shell and drives
    ("cd D:/ && git commit", None),

    # Item 5: UNC and device paths
    (r"git -C \\10.255.255.7\s commit", None),
    (r"git -C \\.\C:\Windows commit", None),
    ("git -C //./C:/Windows commit", None),

    # Item 7: Restored rows (both original and item-7 shapes)
    ("cd wt && git '--work-tree=..' commit", "bash"),
    ("cd wt && git '--git-dir=../.git' commit", "bash"),
    ("'--work-tree=..' git commit", "bash"),
    ("'--git-dir=../.git' git commit", "bash"),
    ("Set-Location wt; -StackName; git commit", "powershell"),
    ("Set-Location wt -StackName foo; git commit", "powershell"),
    ("-StackName", "powershell"),
    (".\\up.ps1; git commit", "powershell"),
    ("Set-Location wt; .\\up.ps1; git commit", "powershell"),
    ("test -d wt && cd wt;", "bash"),
    ("test -d wt && cd wt; git commit", "bash"),
    ("false && cd wt;", "bash"),
    ("false && cd wt; git commit", "bash"),
    ("Set-Location wt -PassThru | Out-Null;", "powershell"),
    ("Set-Location wt -PassThru | Out-Null; git commit", "powershell"),
    ("pushd +1 && git commit", "bash"),
    ("pushd +1 wt; git commit", "powershell"),
    ("pushd -n wt; git commit", "powershell"),
    ("HKLM:\\ && git commit", "powershell"),
    ("cd wt; HKLM:\\ && git commit", "powershell"),
    ("cd wt; HKLM:\\; git commit", "powershell"),
    ("Set-Location wt; . ([scriptblock]::Create('cd ..')); git commit", "powershell"),
    ("Set-Location wt; Invoke-Command -ScriptBlock ([scriptblock]::Create('Set-Location ..')); git commit", "powershell"),

    # Glued quotes, backslashes, scripts, etc.
    ("c''d && git commit", "bash"),
    ("c\\d && git commit", "bash"),
    ("git '-C' .. commit", "bash"),
    ("git -''C .. commit", "bash"),
    ("env 'GIT_DIR=..' git commit", "bash"),
    ("export X=1; git commit", "bash"),
    ("set \"GIT_DIR=..\" && git commit", "cmd"),
    ("call .\\up.bat && git commit", "cmd"),
    ("start /D wt git commit", "cmd"),
    ("env --chd=.. git commit", "bash"),
    ("ſl wt; git commit", "powershell"),
    ("Set-Locatİon wt; git commit", "powershell"),
    ("cd \"wt\"/sub && git commit", "bash"),
    ("cd 'a''b' && git commit", "bash"),
    ("cd a\\ b && git commit", "bash"),

    # Dropped rows
    ("\"C:\\Program Files\\Git\\cmd\\git.exe\" -C wt commit", None),
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

    # Review round 2 inputs
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

    # Control chars, non-ASCII outside quotes, and length boundary
    ("git commit\0", None),
    ("git commit\r", None),
    ("git commit\n", None),
    ("git commit \xe9", None),
    ("cd wt && git commit " + ("x" * 4100), None),
    ("git commit " + ("x" * 4096), None),

    # Unknown text before or inside the commit segment, or a commit after the first one
    ("cd \"$(pwd)/wt\" && git commit -m x && git push", "bash"),
    ("cd `pwd`/wt && git commit -m x && git push", "bash"),
    ("cd {wt} && git commit -m \"a `b`\" && git push", "bash"),
    ("cd {wt} && git commit -m \"$(date)\"; git push", "bash"),
    ("cd {wt} | git commit -m x && git push", "bash"),
    ("cd {wt} && git commit -m x && cd .. && git commit -m y | cat", "bash"),
    ("cd {wt} && git commit -m x; cd ..; git commit -m y | cat", "bash"),
    ("cd {wt} && git commit -m x; git -C .. commit -m y; echo $HOME", "bash"),

    # A second commit hidden in the text after the first one, quoted or not
    ("cd {wt} && git commit -m x; cd {wtx} && git commit -m y", "bash"),
    ("cd {wt} && git commit -m x; cd {wtx} && eval \"git commit -m y\"", "bash"),
    ("cd {wt} && git commit -m x; cd {wtx} && bash -c \"git commit -m y\"", "bash"),
    ("cd {wt} && git commit -m x; cd {wtx} && $(echo git) commit -m y", "bash"),
    ("cd {wt} && git commit -m x; cd {wtx} && git -c a=b commit -m y", "bash"),
    ("cd {wt} && git commit -m x; cd {wtx} && git ci -m y", "bash"),
    ("cd {wt} && git commit -m x; cd {wtx} && git -C {wtx} log", "bash"),
    ("cd {wt} && git commit -m x; cd {wtx} && git merge z", "bash"),
    ("cd {wt} && git commit -m x; cd {wtx} && git cherry-pick abc", "bash"),
    ("cd {wt} && git commit -m x; cd {wtx} && git rebase main", "bash"),
    ("cd {wt} && git commit -m x; cd {wtx} && git pull", "bash"),
    ("cd {wt} && git commit -m x; cd {wtx} && git commit --amend --no-edit", "bash"),
    ("cd {wt} && git commit -m x; python -c \"print(1)\"", "bash"),
    ("cd {wt} && git commit -m x; source ./run.sh", "bash"),
    ("cd {wt} && git commit -m x & cd {wtx} && git push", "bash"),
    ("cd {wt} && git commit -m x; cd {wtx}\n/bin/bash -l", "bash"),
    ("cd {wt} && git commit -m x; sudo -u root bash -l", "bash"),
    ("cd {wt} && git commit -m x; env A=1 python -V", "bash"),
    ("cd {wt} && git commit -m x; sh -l", "bash"),
    ("cd {wt} && git commit -m x; then bash x.sh", "bash"),
    ("cd {wt} && git commit -m x; (sh -l)", "bash"),
    ("cd {wt} && git commit -m x; \"bash\" -l", "bash"),
    ("cd {wt} && git commit -m x; setsid bash -l", "bash"),
    ("cd {wt} && git commit -m x; su -c \"sh -l\"", "bash"),
    ("cd {wt} && git commit -m x; g=git; $g merge z", "bash"),
]


@pytest.mark.skipif(os.name != "nt", reason="drive-letter paths are only read as drives on Windows")
@pytest.mark.parametrize("cmd_tmpl", [
    "cd {msys} && git commit -m x",
    "git -C {msys} commit -m x",
    "cd {msys} && git commit -m x && gh pr create --body \"$(git log -1)\"",
])
def test_msys_drive_path_resolves_on_windows(cmd_tmpl: str, tmp_path: Path):
    wt = tmp_path / "wt"
    wt.mkdir(exist_ok=True)
    posix = wt.resolve().as_posix()  # C:/Users/...
    msys = "/" + posix[0].lower() + posix[2:]  # /c/Users/...
    assert strict_target(cmd_tmpl.format(msys=msys), str(tmp_path), shell="bash") == os.path.normcase(str(wt.resolve()))
    assert strict_target(f"cd {msys} && git commit -m x", str(tmp_path)) is None  # MSYS paths are a bash form only


@pytest.mark.parametrize("cmd_tmpl,shell", NONE_CASES)
def test_none_cases_return_none(cmd_tmpl: str, shell: str | None, tmp_path: Path):
    wt = tmp_path / "wt"
    wtx = tmp_path / "wt[x]"
    wt.mkdir(exist_ok=True)
    wtx.mkdir(exist_ok=True)
    cwd_str = str(tmp_path)
    cmd = cmd_tmpl.format(wt=str(wt), wtx=str(wtx)) if ("{wt}" in cmd_tmpl or "{wtx}" in cmd_tmpl) else cmd_tmpl
    assert strict_target(cmd, cwd_str, shell=shell) is None, f"Expected None for {cmd} in {shell}"


def test_item7_restored_rows_with_benign_counterparts(tmp_path: Path):
    wt = tmp_path / "wt"
    wt.mkdir(exist_ok=True)
    cwd_str = str(tmp_path)
    wt_norm = os.path.normcase(str(wt.resolve()))
    cwd_norm = os.path.normcase(str(Path(cwd_str).resolve()))

    # Pair: (malformed_command, shell, benign_command, expected_target)
    checks = [
        # Options before subcommand vs clean cd && commit
        (f"cd wt && git '--work-tree=..' {CI}", "bash", f"cd wt && {GC}", wt_norm),
        (f"cd wt && git '--git-dir=../.git' {CI}", "bash", f"cd wt && {GC}", wt_norm),
        (f"'--work-tree=..' {GC}", "bash", GC, cwd_norm),
        (f"'--git-dir=../.git' {GC}", "bash", GC, cwd_norm),
        # Extra stack flag in PowerShell vs clean Set-Location
        (f"Set-Location wt; -StackName; {GC}", "powershell", f"Set-Location wt; {GC}", wt_norm),
        (f"Set-Location wt -StackName foo; {GC}", "powershell", f"Set-Location -Path wt; {GC}", wt_norm),
        # Dot-slash script execution vs clean location
        (f"Set-Location wt; .\\up.ps1; {GC}", "powershell", f"Set-Location wt; {GC}", wt_norm),
        # Unrecognized commands at start vs clean cd
        (f"test -d wt && cd wt; {GC}", "bash", f"cd wt && {GC}", wt_norm),
        (f"false && cd wt; {GC}", "bash", f"cd wt && {GC}", wt_norm),
        # Pipeline and PassThru vs clean Set-Location
        (f"Set-Location wt -PassThru | Out-Null; {GC}", "powershell", f"Set-Location wt; {GC}", wt_norm),
        # pushd +1 in bash vs clean cd
        (f"pushd +1 && {GC}", "bash", f"cd wt && {GC}", wt_norm),
        (f"pushd +1 wt; {GC}", "powershell", f"pushd wt; {GC}", wt_norm),
        # Registry prefix in path vs clean cd
        (f"cd wt; HKLM:\\ && {GC}", "powershell", f"cd wt; {GC}", wt_norm),
        (f"cd wt; HKLM:\\; {GC}", "powershell", f"cd wt; {GC}", wt_norm),
        # Indirect invocation vs clean Set-Location
        (f"Set-Location wt; . ([scriptblock]::Create('cd ..')); {GC}", "powershell", f"Set-Location wt; {GC}", wt_norm),
        (f"Set-Location wt; Invoke-Command -ScriptBlock ([scriptblock]::Create('Set-Location ..')); {GC}", "powershell", f"Set-Location wt; {GC}", wt_norm),
    ]

    for bad_cmd, sh, benign_cmd, expected_target in checks:
        assert strict_target(bad_cmd, cwd_str, shell=sh) is None, f"Expected None for {bad_cmd=}"
        assert strict_target(benign_cmd, cwd_str, shell=sh) == expected_target, f"Expected {expected_target} for {benign_cmd=}"


def test_unc_path_makes_no_filesystem_call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cwd_str = str(tmp_path)
    called: list[str] = []
    monkeypatch.setattr(os.path, "isdir", lambda p: called.append(p) or True)

    # Control: a local path does reach the filesystem check, so the patch is effective.
    (tmp_path / "wt").mkdir(exist_ok=True)
    strict_target(f"git -C wt {CI}", cwd_str)
    assert called, "control: a local path must reach os.path.isdir"
    called.clear()

    for cmd in (
        r"git -C \\10.255.255.7\s " + CI,
        r"git -C \\?\C:\wt " + CI,
        r"git -C \\.\pipe\x " + CI,
    ):
        assert strict_target(cmd, cwd_str) is None
    assert called == [], "os.path.isdir must NOT be called for UNC/device paths"


@pytest.mark.parametrize("var", ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "git_dir", "Git_Dir"])
def test_env_git_vars_return_none(var: str, tmp_path: Path):
    wt = tmp_path / "wt"
    wt.mkdir(exist_ok=True)
    cwd_str = str(tmp_path)
    cmd = f"git -C wt {CI} -m x"
    assert strict_target(cmd, cwd_str, env={var: "/override/path"}) is None


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
    # Test 1: within 4096 cap (~2000 chars) exercises regexes linearly without hitting length cap
    inp_within = f"cd wt && {GC} -m " + (pattern * 500)
    t0 = time.perf_counter()
    res1 = strict_target(inp_within, cwd_str, shell=shell)
    el1 = time.perf_counter() - t0
    assert res1 is None
    assert el1 < 0.5, f"Took {el1:.2f}s within cap"

    # Test 1b: just under the 4096 cap, the longest input the regex path accepts
    prefix = f"cd wt && {GC} -m "
    inp_under = prefix + (pattern * ((4095 - len(prefix)) // len(pattern)))
    assert len(inp_under) <= 4096
    t0 = time.perf_counter()
    res1b = strict_target(inp_under, cwd_str, shell=shell)
    el1b = time.perf_counter() - t0
    assert res1b is None
    assert el1b < 0.5, f"Took {el1b:.2f}s just under cap"

    # Test 2: above 4096 cap (25,000 repeats) tests fast rejection
    inp_above = f"cd wt && {GC} -m " + (pattern * 25_000)
    t0 = time.perf_counter()
    res2 = strict_target(inp_above, cwd_str, shell=shell)
    el2 = time.perf_counter() - t0
    assert res2 is None
    assert el2 < 0.5, f"Took {el2:.2f}s above cap"
