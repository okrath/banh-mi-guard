"""
Untracked paths in the user's repository: pre asks once per path, the user's choice (include or
ignore) is recorded and can be changed, and ignoring never edits a repository file.
"""

import subprocess
from pathlib import Path

from typer.testing import CliRunner

from guard.cli import app, execute_post_task, execute_pre_task
from guard.core.untracked import MARK, decide, load_decisions, undecided
from guard.core.untracked import _save as REAL_SAVE  # restored by hand: monkeypatch.undo() would also undo conftest's isolation


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    (repo / "src").mkdir(parents=True)
    for cmd in (["git", "init"], ["git", "config", "user.email", "t@t"], ["git", "config", "user.name", "t"],
                ["git", "config", "core.hooksPath", ".git/hooks"]):
        subprocess.run(cmd, cwd=repo, check=True, capture_output=True)
    (repo / "package.json").write_text('{"name": "fe", "scripts": {"build": "node -e \\"process.exit(0)\\""}}', encoding="utf-8")
    (repo / "src" / "chat.ts").write_text("export const a = 1;\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)
    return repo


def exclude_text(repo: Path) -> str:
    common = subprocess.run(["git", "-C", str(repo), "rev-parse", "--git-common-dir"], capture_output=True, text=True).stdout.strip()
    path = (repo / common if not Path(common).is_absolute() else Path(common)) / "info" / "exclude"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def test_pre_stops_until_the_user_decides_then_ignore_keeps_the_repo_untouched(tmp_path, capsys):
    repo = make_repo(tmp_path)
    (repo / "plans" / "x").mkdir(parents=True)
    (repo / "plans" / "x" / "plan.md").write_text("# plan\n", encoding="utf-8")
    assert undecided(repo) == ["plans/"]  # a folder is asked about once
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is False
    assert "guard untracked <path> --include" in capsys.readouterr().out

    assert "always ignored" in decide(repo, "plans", "ignore")
    assert load_decisions(repo) == {"plans/": "ignore"} and undecided(repo) == []
    assert subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True).stdout == ""
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True  # clean tree: nothing pre-existing
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo) is True  # no SCOPE-003, no DEAD-001 for the plan


def test_the_choice_can_be_changed_and_only_guards_own_lines_go(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "notes.md").write_text("mine\n", encoding="utf-8")
    common = subprocess.run(["git", "-C", str(repo), "rev-parse", "--git-common-dir"], capture_output=True, text=True).stdout.strip()
    exclude = repo / common / "info" / "exclude"
    decide(repo, "notes.md", "ignore")
    exclude.write_text(exclude.read_text(encoding="utf-8") + "/notes.md\n", encoding="utf-8")  # the user's own line
    decide(repo, "notes.md", "include")
    text = exclude_text(repo)
    assert MARK not in text and text.count("/notes.md") == 1  # the user's line stays, guard's pair is gone
    assert load_decisions(repo) == {"notes.md": "include"}


def test_cli_lists_and_rejects_ambiguous_choices(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    (repo / "scratch.txt").write_text("x\n", encoding="utf-8")
    monkeypatch.chdir(repo)
    assert "not decided" in CliRunner().invoke(app, ["untracked"]).output
    assert CliRunner().invoke(app, ["untracked", "scratch.txt"]).exit_code == 1  # neither flag
    assert CliRunner().invoke(app, ["untracked", "scratch.txt", "--include", "--ignore"]).exit_code == 1
    assert CliRunner().invoke(app, ["untracked", "scratch.txt", "--ignore"]).exit_code == 0
    assert "always ignored" in CliRunner().invoke(app, ["untracked"]).output


def test_files_the_task_creates_are_not_asked_about(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Add src/new.ts", repo_path=repo) is True
    (repo / "src" / "new.ts").write_text("export const n = 1;\n", encoding="utf-8")
    assert undecided(repo) == []  # the task's own new file


def test_after_a_finished_task_new_untracked_paths_are_asked_again(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo) is True
    subprocess.run(["git", "commit", "-qam", "fix"], cwd=repo, check=True, capture_output=True)
    (repo / "reports").mkdir()
    (repo / "reports" / "r.md").write_text("r\n", encoding="utf-8")
    assert undecided(repo) == ["reports/"]


def test_only_listed_or_decided_paths_are_accepted(tmp_path):
    import pytest
    repo = make_repo(tmp_path)
    with pytest.raises(ValueError, match="not an untracked path"):
        decide(repo, "src/chat.ts", "ignore")  # tracked
    with pytest.raises(ValueError, match="control characters"):
        decide(repo, "bad\nname", "ignore")
    (repo / ".guardian").mkdir()
    (repo / ".guardian" / "x.txt").write_text("x", encoding="utf-8")
    assert undecided(repo) == [".guardian/"]  # not guard's own .guard folder


def test_pre_blocks_when_git_cannot_list_untracked_paths(tmp_path, monkeypatch, capsys):
    import guard.core.untracked as untracked
    repo = make_repo(tmp_path)
    real = untracked.subprocess.run

    def broken(cmd, **kw):
        if "ls-files" in cmd:
            return subprocess.CompletedProcess(cmd, 128, b"", b"fatal: index file corrupt")
        return real(cmd, **kw)

    monkeypatch.setattr(untracked.subprocess, "run", broken)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is False
    assert "could not check untracked paths" in capsys.readouterr().out


def test_a_lost_registry_does_not_strand_an_ignored_path(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "plans").mkdir()
    (repo / "plans" / "p.md").write_text("p\n", encoding="utf-8")
    decide(repo, "plans", "ignore")
    from guard.core.untracked import _decisions_path
    _decisions_path(repo).unlink()  # the registry is gone, the exclude pair is not
    assert "always included" in decide(repo, "plans", "include")
    assert undecided(repo) == []  # included now: listed again but decided


def test_pre_asks_even_while_an_earlier_task_is_open(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True  # a task is running
    (repo / "reports").mkdir()
    (repo / "reports" / "r.md").write_text("r\n", encoding="utf-8")
    assert undecided(repo) == []  # listing: the running task's own new files
    assert undecided(repo, skip_task_files=False) == ["reports/"]  # what pre checks


def test_a_failed_update_leaves_the_path_undecided(tmp_path, monkeypatch):
    import pytest
    import guard.core.untracked as untracked
    repo = make_repo(tmp_path)
    (repo / "plans").mkdir()
    (repo / "plans" / "p.md").write_text("p\n", encoding="utf-8")
    before = exclude_text(repo)

    real_write = untracked._write_bytes_atomic
    monkeypatch.setattr(untracked, "_write_bytes_atomic", lambda p, d: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(ValueError, match="nothing changed"):
        decide(repo, "plans", "ignore")  # the exclude write fails
    assert load_decisions(repo) == {} and undecided(repo) == ["plans/"]

    monkeypatch.setattr(untracked, "_write_bytes_atomic", real_write)
    monkeypatch.setattr(untracked, "_save", lambda r, d: (_ for _ in ()).throw(OSError("read-only")))
    with pytest.raises(ValueError, match="nothing changed"):
        decide(repo, "plans", "ignore")  # the exclude write works, recording fails: rolled back
    assert exclude_text(repo) == before and undecided(repo) == ["plans/"]

    monkeypatch.setattr(untracked, "_save", REAL_SAVE)
    decide(repo, "plans", "ignore")
    monkeypatch.setattr(untracked, "_save", lambda r, d: (_ for _ in ()).throw(OSError("read-only")))
    ignored = exclude_text(repo)
    with pytest.raises(ValueError, match="nothing changed"):
        decide(repo, "plans", "include")  # include fails the same way
    assert exclude_text(repo) == ignored and load_decisions(repo) == {"plans/": "ignore"}


def test_linked_worktrees_share_the_rule_and_the_decision(tmp_path):
    repo = make_repo(tmp_path)
    other = tmp_path / "wt"
    subprocess.run(["git", "-C", str(repo), "worktree", "add", "-q", str(other)], check=True, capture_output=True)
    (repo / "plans").mkdir()
    (repo / "plans" / "p.md").write_text("p\n", encoding="utf-8")
    (other / "plans").mkdir()
    (other / "plans" / "p.md").write_text("p\n", encoding="utf-8")
    decide(repo, "plans", "ignore")
    assert load_decisions(other) == {"plans/": "ignore"} and undecided(other) == []  # same scope as the exclude rule
    decide(other, "plans", "include")
    assert load_decisions(repo) == {"plans/": "include"} and undecided(repo) == []


def test_parallel_decisions_do_not_overwrite_each_other(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    repo = make_repo(tmp_path)
    names = [f"n{i}.md" for i in range(8)]
    for n in names:
        (repo / n).write_text("x\n", encoding="utf-8")
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda n: decide(repo, n, "ignore"), names))
    assert sorted(load_decisions(repo)) == names and undecided(repo) == []


def test_a_recorded_folder_can_be_included_after_it_is_gone(tmp_path):
    import shutil
    repo = make_repo(tmp_path)
    (repo / "plans").mkdir()
    (repo / "plans" / "p.md").write_text("p\n", encoding="utf-8")
    decide(repo, "plans", "ignore")
    shutil.rmtree(repo / "plans")
    decide(repo, "plans", "include")  # no trailing slash, no folder on disk
    assert load_decisions(repo) == {"plans/": "include"}
    assert "/plans/" not in exclude_text(repo)


def test_a_broken_registry_is_reported_and_never_overwritten(tmp_path, capsys):
    import pytest
    from guard.core.untracked import RegistryError, _decisions_path
    repo = make_repo(tmp_path)
    (repo / "a.md").write_text("x\n", encoding="utf-8")
    decide(repo, "a.md", "ignore")
    reg = _decisions_path(repo)
    reg.write_text("{not json", encoding="utf-8")  # damaged by hand
    (repo / "b.md").write_text("y\n", encoding="utf-8")
    with pytest.raises(RegistryError):
        decide(repo, "b.md", "ignore")
    assert reg.read_text(encoding="utf-8") == "{not json"  # left for the user to repair
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is False
    assert "could not check untracked paths" in capsys.readouterr().out


def test_a_file_decision_does_not_cover_a_folder_that_replaces_it(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "plans").write_text("a file\n", encoding="utf-8")
    decide(repo, "plans", "include")  # the file
    (repo / "plans").unlink()
    (repo / "plans").mkdir()  # now a folder with the same name
    (repo / "plans" / "p.md").write_text("p\n", encoding="utf-8")
    assert undecided(repo) == ["plans/"]  # asked again: a different thing


def test_an_ignored_file_does_not_hide_a_folder_that_replaces_it(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "notes").write_text("a file\n", encoding="utf-8")
    decide(repo, "notes", "ignore")
    assert undecided(repo) == []
    (repo / "notes").unlink()
    (repo / "notes").mkdir()
    (repo / "notes" / "n.md").write_text("n\n", encoding="utf-8")
    assert undecided(repo) == ["notes/"]  # Git lists the folder again; guard asks about it


def test_a_forced_restart_also_checks_untracked_paths(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    execute_post_task(repo_path=repo)
    from guard.core.session import SessionManager, SessionStatus
    session = SessionManager(repo).load_local_session()
    session.status = SessionStatus.NEEDS_FIX  # a rejected task being restarted
    SessionManager(repo)._save(session)
    # created after this task began, so for the restart it is the task's own file: not asked
    (repo / "helper.ts").write_text("export const h = 1;\n", encoding="utf-8")
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, force=True) is True
    from guard.core.untracked import _decisions_path
    _decisions_path(repo).write_text("[broken", encoding="utf-8")
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, force=True) is False  # still checked


def test_registry_resolution_failures_are_registry_errors(tmp_path, monkeypatch):
    import pytest
    import guard.core.untracked as untracked
    from guard.core.untracked import RegistryError
    repo = make_repo(tmp_path)
    monkeypatch.setattr(untracked, "_exclude_file", lambda r: None)  # git gave no common dir
    with pytest.raises(RegistryError):
        untracked.load_decisions(repo)


def test_an_interrupted_ignore_is_still_a_decision(tmp_path):
    from guard.core.untracked import _decisions_path, _exclude_lines
    repo = make_repo(tmp_path)
    (repo / "scratch").mkdir()
    (repo / "scratch" / "s.md").write_text("s\n", encoding="utf-8")
    common = subprocess.run(["git", "-C", str(repo), "rev-parse", "--git-common-dir"], capture_output=True, text=True).stdout.strip()
    exclude = repo / common / "info" / "exclude"
    # the process died after writing the exclude block and before recording it
    exclude.write_text(exclude.read_text(encoding="utf-8") + "\n".join(_exclude_lines("scratch/")) + "\n", encoding="utf-8")
    assert not _decisions_path(repo).exists()
    assert load_decisions(repo) == {"scratch/": "ignore"} and undecided(repo) == []


def test_a_failed_undo_is_reported_and_a_stale_ignore_hides_nothing(tmp_path, monkeypatch):
    import pytest
    import guard.core.untracked as untracked
    repo = make_repo(tmp_path)
    (repo / "plans").mkdir()
    (repo / "plans" / "p.md").write_text("p\n", encoding="utf-8")
    decide(repo, "plans", "ignore")

    real_write = untracked._write_bytes_atomic
    writes = []

    def write_once(path, data):  # the exclude change works, the undo does not
        writes.append(path)
        if len(writes) > 1:
            raise OSError("disk gone")
        real_write(path, data)

    monkeypatch.setattr(untracked, "_write_bytes_atomic", write_once)
    monkeypatch.setattr(untracked, "_save", lambda r, d: (_ for _ in ()).throw(OSError("read-only")))
    with pytest.raises(ValueError, match="could not be recorded .* or undone"):
        decide(repo, "plans", "include")  # the block is gone, the registry still says ignore
    monkeypatch.setattr(untracked, "_write_bytes_atomic", real_write)
    monkeypatch.setattr(untracked, "_save", REAL_SAVE)
    assert load_decisions(repo) == {} and undecided(repo) == ["plans/"]  # visible again, and asked about


def test_what_is_on_disk_decides_file_or_folder(tmp_path):
    import shutil
    repo = make_repo(tmp_path)
    (repo / "out").mkdir()
    (repo / "out" / "o.txt").write_text("o\n", encoding="utf-8")
    decide(repo, "out", "include")  # recorded as the folder out/
    shutil.rmtree(repo / "out")
    (repo / "out").write_text("now a file\n", encoding="utf-8")
    decide(repo, "out", "ignore")  # the file on disk now, not the old folder decision
    assert load_decisions(repo)["out"] == "ignore" and undecided(repo) == []


def test_a_complete_guard_block_wins_over_a_stale_include(tmp_path):
    import json
    from guard.core.untracked import _decisions_path
    repo = make_repo(tmp_path)
    (repo / "logs").mkdir()
    (repo / "logs" / "l.txt").write_text("l\n", encoding="utf-8")
    decide(repo, "logs", "ignore")
    _decisions_path(repo).write_text(json.dumps({"logs/": "include"}), encoding="utf-8")  # stale record
    assert load_decisions(repo) == {"logs/": "ignore"}  # the block in info/exclude is the effect


def test_task_files_are_matched_by_path_component(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "ab.txt").write_text("x\n", encoding="utf-8")
    from guard.core.untracked import decide as record
    record(repo, "ab.txt", "include")
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, allow_dirty=True) is True  # ab.txt is in the baseline
    (repo / "a").write_text("new\n", encoding="utf-8")  # created by the task
    assert undecided(repo) == []  # "a" is not covered by the baseline entry "ab.txt": it is the task's
    assert undecided(repo, skip_task_files=False) == ["a"]
