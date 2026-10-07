from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from guard.core import repo_setup
from guard.core.repo_setup import (
    _clean_git_env,
    _clear_repo_cache,
    _dir_for_path,
    _normalise_path,
    git_root,
    group_by_repo,
    repo_for_path,
)


def _init_git_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", str(path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(path), "commit", "--allow-empty", "-m", "init"],
        check=True,
        capture_output=True,
    )
    return path.resolve()


def test_normalise_path_and_dir_for_path(tmp_path: Path):
    repo = _init_git_repo(tmp_path / "norm_repo")
    sub = repo / "sub"
    sub.mkdir()
    f = sub / "file.txt"
    f.write_text("hello", encoding="utf-8")

    # _normalise_path
    norm = _normalise_path(f)
    assert norm == f.resolve()

    norm_rel = _normalise_path("sub/file.txt", base=repo)
    assert norm_rel == f.resolve()

    # _dir_for_path for existing file
    assert _dir_for_path(f.resolve()) == sub.resolve()

    # _dir_for_path for existing directory
    assert _dir_for_path(sub.resolve()) == sub.resolve()

    # _dir_for_path for non-existent file in existing directory
    assert _dir_for_path(sub / "nonexistent.txt") == sub.resolve()

    # _dir_for_path for deeply nested non-existent directory
    deep_future = sub / "future1" / "future2" / "file.txt"
    assert _dir_for_path(deep_future) == sub.resolve()


def test_repo_for_path_main_and_worktree(tmp_path: Path):
    _clear_repo_cache()
    main = _init_git_repo(tmp_path / "main_repo")
    wt = (tmp_path / "wt_repo").resolve()
    subprocess.run(["git", "-C", str(main), "worktree", "add", str(wt)], check=True, capture_output=True)

    main_file = main / "src" / "app.py"
    main_file.parent.mkdir(parents=True, exist_ok=True)
    main_file.write_text("print('main')", encoding="utf-8")

    wt_file = wt / "src" / "wt.py"
    wt_file.parent.mkdir(parents=True, exist_ok=True)
    wt_file.write_text("print('wt')", encoding="utf-8")

    wt_new_file = wt / "new_folder" / "deep_folder" / "new_file.py"
    outside_file = tmp_path / "outside_dir" / "outside.txt"
    outside_file.parent.mkdir(parents=True, exist_ok=True)
    outside_file.write_text("outside", encoding="utf-8")

    # Absolute paths
    assert repo_for_path(main_file) == main
    assert repo_for_path(wt_file) == wt
    assert repo_for_path(wt_new_file) == wt
    assert repo_for_path(outside_file) is None

    # Relative paths resolved against base
    assert repo_for_path("src/app.py", base=main) == main
    assert repo_for_path("src/wt.py", base=wt) == wt
    assert repo_for_path("new_folder/deep_folder/new_file.py", base=wt) == wt
    assert repo_for_path("../outside_dir/outside.txt", base=main) is None

    # Path object vs str
    assert repo_for_path(str(main_file)) == main
    assert repo_for_path(str(wt_file)) == wt
    assert repo_for_path(str(wt_new_file)) == wt


def test_repo_for_path_nested_repo(tmp_path: Path):
    _clear_repo_cache()
    outer = _init_git_repo(tmp_path / "outer")
    inner = _init_git_repo(outer / "nested" / "inner")

    outer_file = outer / "outer.py"
    outer_file.write_text("outer", encoding="utf-8")

    inner_file = inner / "sub" / "inner.py"
    inner_file.parent.mkdir(parents=True, exist_ok=True)
    inner_file.write_text("inner", encoding="utf-8")

    inner_new_file = inner / "new_dir" / "future.py"

    # Innermost root wins
    assert repo_for_path(inner_file) == inner
    assert repo_for_path(inner_new_file) == inner
    assert repo_for_path(outer_file) == outer

    # Relative to outer
    assert repo_for_path("nested/inner/sub/inner.py", base=outer) == inner
    assert repo_for_path("nested/inner/new_dir/future.py", base=outer) == inner


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific path formats")
def test_repo_for_path_windows_normalisation(tmp_path: Path):
    _clear_repo_cache()
    repo = _init_git_repo(tmp_path / "win_repo")
    sub_dir = repo / "sub"
    sub_dir.mkdir(parents=True, exist_ok=True)
    file_path = sub_dir / "target.py"
    file_path.write_text("win", encoding="utf-8")

    expected = git_root(repo)
    assert expected is not None

    # Drive letter lowercase
    lower_drive = str(file_path)
    if lower_drive[1:3] == ":\\":
        lower_drive = lower_drive[0].lower() + lower_drive[1:]
        assert repo_for_path(lower_drive) == expected

    # Mixed slashes
    slash_path = str(file_path).replace("\\", "/")
    assert repo_for_path(slash_path) == expected
    mixed_path = slash_path.replace("/sub/", "\\sub/")
    assert repo_for_path(mixed_path) == expected

    # Trailing separators
    assert repo_for_path(str(repo) + "/") == expected
    assert repo_for_path(str(repo) + "\\") == expected
    assert repo_for_path(str(sub_dir) + "/") == expected

    # \\?\ and //?/ prefixes
    assert repo_for_path("\\\\?\\" + str(file_path)) == expected
    assert repo_for_path("//?/" + str(file_path).replace("\\", "/")) == expected

    # Comparisons equal to git_root
    assert repo_for_path(file_path) == expected


def test_repo_for_path_caching(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _clear_repo_cache()
    repo = _init_git_repo(tmp_path / "cache_repo")
    d1 = repo / "pkg1"
    d1.mkdir()
    f1 = d1 / "mod1.py"
    f2 = d1 / "mod2.py"
    f3 = d1 / "mod3.py"
    f1.write_text("1", encoding="utf-8")
    f2.write_text("2", encoding="utf-8")
    f3.write_text("3", encoding="utf-8")

    d2 = repo / "pkg2"
    d2.mkdir()
    f4 = d2 / "mod4.py"
    f4.write_text("4", encoding="utf-8")

    git_calls: list[tuple] = []
    orig_git = repo_setup._git

    def counting_git(*args, **kwargs):
        git_calls.append(args)
        return orig_git(*args, **kwargs)

    monkeypatch.setattr(repo_setup, "_git", counting_git)

    # First file in pkg1 costs 1 git call
    assert repo_for_path(f1) == repo
    assert len(git_calls) == 1

    # Remaining files in pkg1 use cache, 0 additional git calls
    assert repo_for_path(f2) == repo
    assert len(git_calls) == 1
    assert repo_for_path(f3) == repo
    assert len(git_calls) == 1

    # Non-existent file in pkg1 also reuses pkg1 cache
    f_nonexistent = d1 / "new_nonexistent.py"
    assert repo_for_path(f_nonexistent) == repo
    assert len(git_calls) == 1

    # File in pkg2 costs 1 additional git call
    assert repo_for_path(f4) == repo
    assert len(git_calls) == 2

    # Second query for pkg2 hits cache
    assert repo_for_path(f4) == repo
    assert len(git_calls) == 2


def test_group_by_repo(tmp_path: Path):
    _clear_repo_cache()
    main = _init_git_repo(tmp_path / "main_repo")
    wt = (tmp_path / "wt_repo").resolve()
    subprocess.run(["git", "-C", str(main), "worktree", "add", str(wt)], check=True, capture_output=True)

    main_f1 = "src/a.py"
    main_f2 = "src/b.py"
    main_future = "new_pkg/future.py"
    (main / "src").mkdir(parents=True, exist_ok=True)
    (main / "src" / "a.py").write_text("a", encoding="utf-8")
    (main / "src" / "b.py").write_text("b", encoding="utf-8")

    wt_f1 = str(wt / "wt_a.py")
    wt_f2 = str(wt / "wt_b.py")
    (wt / "wt_a.py").write_text("wta", encoding="utf-8")
    (wt / "wt_b.py").write_text("wtb", encoding="utf-8")

    outside_f = str(tmp_path / "outside.txt")
    (tmp_path / "outside.txt").write_text("outside", encoding="utf-8")

    input_paths = [
        main_f1,
        wt_f1,
        outside_f,
        main_f2,
        wt_f2,
        main_future,
    ]

    grouped = group_by_repo(input_paths, base=main)

    # Keys are exactly main, wt, and None
    assert set(grouped.keys()) == {main, wt, None}

    # Original order of paths preserved in each list
    assert grouped[main] == [main_f1, main_f2, main_future]
    assert grouped[wt] == [wt_f1, wt_f2]
    assert grouped[None] == [outside_f]

    # Empty iterable
    assert group_by_repo([], base=main) == {}


def test_repo_for_path_edge_cases(tmp_path: Path):
    _clear_repo_cache()
    # Invalid path with embedded null byte
    assert repo_for_path("invalid\x00path") is None

    # Empty path resolves relative to base or cwd
    repo = _init_git_repo(tmp_path / "empty_path_repo")
    assert repo_for_path("", base=repo) == repo

    # Path completely outside any repo
    assert repo_for_path(tmp_path / "nonexistent" / "file.txt") is None


def test_repo_for_path_inside_git_dir(tmp_path: Path):
    _clear_repo_cache()
    main = _init_git_repo(tmp_path / "main_repo")
    wt = (tmp_path / "wt_repo").resolve()
    subprocess.run(["git", "-C", str(main), "worktree", "add", str(wt)], check=True, capture_output=True)

    # 1. <main>/.git/hooks/pre-commit
    hook_file = main / ".git" / "hooks" / "pre-commit"
    hook_file.parent.mkdir(parents=True, exist_ok=True)
    hook_file.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    assert repo_for_path(hook_file) == main

    # 2. <main>/.git/config
    assert repo_for_path(main / ".git" / "config") == main

    # 3. <main>/.git
    assert repo_for_path(main / ".git") == main
    assert repo_for_path(str(main / ".git") + "/") == main
    assert repo_for_path(str(main / ".git") + "\\") == main

    # 4. <main>/.git/worktrees/wt/HEAD
    wt_head = main / ".git" / "worktrees" / "wt_repo" / "HEAD"
    assert wt_head.exists()
    assert repo_for_path(wt_head) == main

    # 5. Non-existent file inside .git
    assert repo_for_path(main / ".git" / "nonexistent" / "file.txt") == main

    # 6. Worktree .git file resolves to worktree
    wt_git_file = wt / ".git"
    assert wt_git_file.is_file()
    assert repo_for_path(wt_git_file) == wt

    # 7. Case-insensitive .git on Windows
    if sys.platform == "win32":
        assert repo_for_path(str(main) + "/.GIT/config") == main
        assert repo_for_path(str(main) + "/.Git/hooks/pre-commit") == main


def test_repo_for_path_deep_paths(tmp_path: Path):
    _clear_repo_cache()
    repo = _init_git_repo(tmp_path / "deep_repo")

    deep_dir = repo
    for i in range(25):
        deep_dir = deep_dir / f"long_sub_dir_level_{i:02d}"

    assert len(str(deep_dir)) >= 500

    # Non-existent deep path resolves to repo
    assert repo_for_path(deep_dir / "future.py") == repo

    # Existing deep path also resolves to repo
    deep_dir.mkdir(parents=True, exist_ok=True)
    deep_leaf = deep_dir / "leaf.py"
    deep_leaf.write_text("leaf", encoding="utf-8")

    assert repo_for_path(deep_dir) == repo
    assert repo_for_path(deep_leaf) == repo

    # Deep path outside any repo
    outside_deep = tmp_path / "outside_deep"
    for i in range(25):
        outside_deep = outside_deep / f"long_outside_level_{i:02d}"
    assert repo_for_path(outside_deep / "future.py") is None
    outside_deep.mkdir(parents=True, exist_ok=True)
    assert repo_for_path(outside_deep) is None


def test_repo_for_path_clean_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _clear_repo_cache()
    main = _init_git_repo(tmp_path / "main_repo")
    wt = (tmp_path / "wt_repo").resolve()
    subprocess.run(["git", "-C", str(main), "worktree", "add", str(wt)], check=True, capture_output=True)

    outside_dir = tmp_path / "outside_repo"
    outside_dir.mkdir(parents=True, exist_ok=True)
    outside_file = outside_dir / "outside.txt"
    outside_file.write_text("outside", encoding="utf-8")

    wt_file = wt / "wt_file.txt"
    wt_file.write_text("wt", encoding="utf-8")

    main_file = main / "main_file.txt"
    main_file.write_text("main", encoding="utf-8")

    # GIT_DIR set to main/.git must not make outside_file resolve to main
    monkeypatch.setenv("GIT_DIR", str(main / ".git"))
    _clear_repo_cache()
    assert repo_for_path(outside_file) is None

    # GIT_WORK_TREE set to main must not make wt_file resolve to main
    monkeypatch.setenv("GIT_WORK_TREE", str(main))
    _clear_repo_cache()
    assert repo_for_path(wt_file) == wt

    # All 4 stripped variables simultaneously
    monkeypatch.setenv("GIT_COMMON_DIR", str(main / ".git"))
    monkeypatch.setenv("GIT_INDEX_FILE", str(main / ".git" / "index"))
    _clear_repo_cache()
    assert repo_for_path(outside_file) is None
    assert repo_for_path(wt_file) == wt
    assert repo_for_path(main_file) == main


def test_repo_for_path_msys_bash_paths(tmp_path: Path):
    _clear_repo_cache()
    repo = _init_git_repo(tmp_path / "msys_repo")
    sub = repo / "sub"
    sub.mkdir(parents=True, exist_ok=True)
    target_file = sub / "app.py"
    target_file.write_text("print('msys')", encoding="utf-8")

    if sys.platform == "win32":
        drive = target_file.drive[0].lower()
        tail = target_file.as_posix()[len(target_file.drive):]
        repo_tail = repo.as_posix()[len(repo.drive):]

        # Shape 1: /<letter>/...
        msys_file = f"/{drive}{tail}"
        msys_repo = f"/{drive}{repo_tail}"
        msys_future = f"/{drive}{tail}_future.py"
        assert repo_for_path(msys_file) == repo
        assert repo_for_path(msys_repo) == repo
        assert repo_for_path(msys_future) == repo

        # Shape 2: /cygdrive/<letter>/...
        cygdrive_file = f"/cygdrive/{drive}{tail}"
        cygdrive_repo = f"/cygdrive/{drive}{repo_tail}"
        cygdrive_future = f"/cygdrive/{drive}{tail}_future.py"
        assert repo_for_path(cygdrive_file) == repo
        assert repo_for_path(cygdrive_repo) == repo
        assert repo_for_path(cygdrive_future) == repo
    else:
        # On Linux/macOS, these shapes are not translated to Windows drive paths
        norm = _normalise_path("/c/Users/foo")
        assert not str(norm).startswith("C:")


def test_repo_for_path_specific_exceptions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _clear_repo_cache()
    repo = _init_git_repo(tmp_path / "exc_repo")
    file_path = repo / "file.py"
    file_path.write_text("ok", encoding="utf-8")

    def raise_value_error(*args, **kwargs):
        raise ValueError("invalid value")

    def raise_os_error(*args, **kwargs):
        raise OSError("filesystem error")

    def raise_runtime_error(*args, **kwargs):
        raise RuntimeError("symlink loop")

    monkeypatch.setattr(repo_setup, "git_root", raise_value_error)
    _clear_repo_cache()
    assert repo_for_path(file_path) is None

    monkeypatch.setattr(repo_setup, "git_root", raise_os_error)
    _clear_repo_cache()
    assert repo_for_path(file_path) is None

    monkeypatch.setattr(repo_setup, "git_root", raise_runtime_error)
    _clear_repo_cache()
    assert repo_for_path(file_path) is None


def test_clean_git_env_helper(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GIT_DIR", "/some/git/dir")
    monkeypatch.setenv("GIT_WORK_TREE", "/some/work/tree")
    monkeypatch.setenv("GIT_COMMON_DIR", "/some/common/dir")
    monkeypatch.setenv("GIT_INDEX_FILE", "/some/index")
    monkeypatch.setenv("OTHER_VAR", "keep_me")

    assert os.environ.get("GIT_DIR") == "/some/git/dir"
    with _clean_git_env():
        assert "GIT_DIR" not in os.environ
        assert "GIT_WORK_TREE" not in os.environ
        assert "GIT_COMMON_DIR" not in os.environ
        assert "GIT_INDEX_FILE" not in os.environ
        assert os.environ.get("OTHER_VAR") == "keep_me"

    assert os.environ.get("GIT_DIR") == "/some/git/dir"
    assert os.environ.get("GIT_WORK_TREE") == "/some/work/tree"
    assert os.environ.get("GIT_COMMON_DIR") == "/some/common/dir"
    assert os.environ.get("GIT_INDEX_FILE") == "/some/index"
