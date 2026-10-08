"""
info/exclude is shared by every guard writer under one lock; decisions count only while Git's
effective rules agree with them; unresolvable paths are handled errors, never crashes.
"""

import pathlib
import subprocess
import threading

import pytest
from test_untracked import exclude_text, make_repo
from typer.testing import CliRunner

from guard.cli import app, execute_pre_task
from guard.core import git_exclude
from guard.core.git_exclude import ensure_excluded, exclude_file, remove_excluded, write_bytes_atomic
from guard.core.ocr_engine import GitDiffInspector
from guard.core.session import SessionManager
from guard.core.untracked import DECISIONS_FILE, RegistryError, decide, load_decisions, undecided
from guard.core.untracked_names import is_guard_dir


def test_a_folder_named_like_guard_is_the_users(tmp_path):
    repo = make_repo(tmp_path)
    (repo / ".guardian").mkdir()
    (repo / ".guardian" / "notes.md").write_text("x\n", encoding="utf-8")
    SessionManager(repo).ensure_gitignore()
    (repo / ".guard").mkdir(exist_ok=True)
    (repo / ".guard" / "session.json").write_text("{}", encoding="utf-8")
    files = GitDiffInspector(repo).get_working_files()
    assert any(f.startswith(".guardian/") for f in files) and not any(f.startswith(".guard/") for f in files)
    assert is_guard_dir(".guard/") and not is_guard_dir(".guard") and not is_guard_dir(".guardian/")  # a file .guard is the user's


def test_concurrent_writers_never_lose_each_others_lines(tmp_path):
    repo = make_repo(tmp_path)
    for i in range(8):
        (repo / f"scratch{i}.md").write_text("x\n", encoding="utf-8")
    jobs = [lambda i=i: decide(repo, f"scratch{i}.md", "ignore") for i in range(8)]
    jobs += [lambda i=i: ensure_excluded(repo, f"/doc{i}.md") for i in range(8)]
    jobs += [lambda: SessionManager(repo).ensure_gitignore()]
    errors = []

    def run(job):
        try:
            job()
        except Exception as e:  # noqa: BLE001 - collected and asserted below
            errors.append(e)
    threads = [threading.Thread(target=run, args=(j,)) for j in jobs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    text = exclude_text(repo)
    assert all(f"/scratch{i}.md" in text and f"/doc{i}.md" in text for i in range(8)) and ".guard/" in text
    assert set(load_decisions(repo)) == {f"scratch{i}.md" for i in range(8)}
    assert remove_excluded(repo, ["/doc0.md"]) and "/doc0.md\n" not in exclude_text(repo)
    assert ensure_excluded(repo, "/doc1.md") is False  # already there: nothing written


def test_rewriting_info_exclude_keeps_its_mode(tmp_path):
    import os
    import stat

    import pytest
    if os.name == "nt":
        pytest.skip("POSIX permission bits")
    repo = make_repo(tmp_path)
    ensure_excluded(repo, "/first.md")
    common = pathlib.Path(repo / ".git" / "info" / "exclude")
    os.chmod(common, 0o664)  # group-shared Git directory
    ensure_excluded(repo, "/second.md")
    assert stat.S_IMODE(os.stat(common).st_mode) == 0o664


def test_an_ignore_that_git_no_longer_applies_is_asked_again(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "notes").write_text("x\n", encoding="utf-8")
    decide(repo, "notes", "ignore")
    assert undecided(repo) == []
    # a folder of the same name replaces the file: the file rule does not ignore it
    (repo / "notes").unlink()
    (repo / "notes").mkdir()
    (repo / "notes" / "a.md").write_text("x\n", encoding="utf-8")
    assert undecided(repo) == ["notes/"]
    assert "not in effect" in CliRunner().invoke(app, ["untracked", "--repo", str(repo)]).output
    # the user's own negation after guard's block: Git lists the file again, so it is not decided
    (repo / "notes" / "a.md").unlink()
    (repo / "notes").rmdir()
    (repo / "notes").write_text("x\n", encoding="utf-8")
    ensure_excluded(repo, "!/notes")
    assert undecided(repo) == ["notes"]
    listing = CliRunner().invoke(app, ["untracked", "--repo", str(repo)]).output
    assert "not in effect" in listing


def test_an_unresolvable_registry_path_is_a_handled_error(tmp_path, monkeypatch, capsys):
    repo = make_repo(tmp_path)
    (repo / "scratch.md").write_text("x\n", encoding="utf-8")
    real = pathlib.Path.resolve

    def loop(self, *a, **k):
        if self.name == DECISIONS_FILE:
            raise RuntimeError(f"Symlink loop from '{self}'")
        return real(self, *a, **k)
    monkeypatch.setattr(pathlib.Path, "resolve", loop)
    try:
        load_decisions(repo)
        raise AssertionError("expected RegistryError")
    except RegistryError as e:
        assert "cannot be resolved" in str(e)
    result = CliRunner().invoke(app, ["untracked", "--repo", str(repo)])
    assert result.exit_code == 1 and "Cannot list untracked paths" in result.output
    result = CliRunner().invoke(app, ["untracked", "scratch.md", "--ignore", "--repo", str(repo)])
    assert result.exit_code == 1 and "cannot be read" in result.output  # no traceback, no decision written
    assert "scratch.md" not in exclude_text(repo)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is False
    assert "could not check untracked paths" in capsys.readouterr().out


def test_a_worktree_under_a_non_ascii_folder_finds_the_shared_exclude(tmp_path):
    folder = tmp_path / "tài liệu"  # git prints the main repository's path as UTF-8, whatever the code page
    folder.mkdir()
    repo = make_repo(folder)
    wt = tmp_path / "wt"
    subprocess.run(["git", "worktree", "add", "-q", str(wt)], cwd=repo, check=True, capture_output=True)
    found = exclude_file(wt)
    assert found is not None and found.resolve() == exclude_file(repo).resolve()  # type: ignore[union-attr]


def _held(times: int):
    """An os.replace that another process blocks `times` times (Windows: the file is open), then works."""
    real, refusals = git_exclude.os.replace, []

    def replace(src, dst):
        if len(refusals) < times:
            refusals.append(dst)
            raise PermissionError(13, "Access is denied")
        real(src, dst)
    return replace, refusals


def test_replacing_info_exclude_waits_while_another_process_holds_it(tmp_path, monkeypatch):
    target = tmp_path / "exclude"
    target.write_bytes(b"old\n")
    replace, refusals = _held(2)
    monkeypatch.setattr(git_exclude.os, "replace", replace)
    monkeypatch.setattr(git_exclude, "WINDOWS", True)
    monkeypatch.setattr(git_exclude.time, "sleep", lambda s: None)
    write_bytes_atomic(target, b"new\n")
    assert target.read_bytes() == b"new\n" and len(refusals) == 2
    assert not list(tmp_path.glob("*.guard-tmp"))  # no temporary file left behind


def test_replacing_info_exclude_gives_up_after_its_attempts(tmp_path, monkeypatch):
    target = tmp_path / "exclude"
    target.write_bytes(b"old\n")
    replace, refusals = _held(10**6)
    monkeypatch.setattr(git_exclude.os, "replace", replace)
    monkeypatch.setattr(git_exclude, "WINDOWS", True)
    monkeypatch.setattr(git_exclude.time, "sleep", lambda s: None)
    with pytest.raises(PermissionError):
        write_bytes_atomic(target, b"new\n")
    assert len(refusals) == git_exclude.REPLACE_ATTEMPTS and target.read_bytes() == b"old\n"
    assert not list(tmp_path.glob("*.guard-tmp"))
