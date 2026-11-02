"""Tests for guard.core.worker_runtime: git worktree probes, camponi terminal-list parsing, nudges."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from guard.core import worker_runtime as wr

# A real captured `camponi --json --no-start terminal ls` row.
SAMPLE_ROW = {
    "args": [],
    "attached": 0,
    "cols": 143,
    "cwd": "/mnt/ssd-data/Projects/camponi",
    "id": "t-0e5d40644195",
    "kind": "omp",
    "lastOutputAt": 1793624957511,
    "pid": 105443,
    "program": "/home/u/.local/bin/omp",
    "restored": False,
    "rows": 18,
    "runtimeId": "3782c05d015508e7",
    "screenTitle": "omp > HEROIC: Connect games",
    "seq": 175210460,
    "startedAt": 1793597926641,
    "status": "running",
    "title": "omp · camponi",
    "worktree": "/mnt/ssd-data/Projects/camponi",
}
RUN_KWARGS = {"capture_output": True, "text": True, "encoding": "utf-8", "errors": "replace", "check": False,
              "timeout": 60}


def terminals_payload(*rows: dict) -> str:
    return json.dumps({"terminals": list(rows)})


def fake_run(monkeypatch, *, returncode: int = 0, stdout: str = "", stderr: str = "", exc: Exception | None = None):
    """Replace subprocess.run with a recorder; returns the [(argv, kwargs)] calls made."""
    calls = []

    def run(cmd, **kwargs):
        calls.append((list(cmd), kwargs))
        if exc is not None:
            raise exc
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)

    monkeypatch.setattr(wr.subprocess, "run", run)
    return calls


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    res = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8",
                         errors="replace", check=True, env={**os.environ, **(env or {})})
    return (res.stdout or "").strip()


def make_repo(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True, capture_output=True)
    return path


# --- resolve_camponi -----------------------------------------------------------


def test_resolve_camponi_prefers_the_environment(monkeypatch):
    monkeypatch.setenv("CAMPONI_CLI", "C:/custom/camponi.exe")
    monkeypatch.setattr(wr.shutil, "which", lambda name: "/from/path/camponi")
    assert wr.resolve_camponi() == "C:/custom/camponi.exe"


def test_resolve_camponi_falls_back_to_path(monkeypatch):
    monkeypatch.delenv("CAMPONI_CLI", raising=False)
    monkeypatch.setattr(wr.shutil, "which", lambda name: "/from/path/camponi" if name == "camponi" else None)
    assert wr.resolve_camponi() == "/from/path/camponi"


def test_resolve_camponi_returns_none_without_environment_or_path(monkeypatch):
    monkeypatch.delenv("CAMPONI_CLI", raising=False)
    monkeypatch.setattr(wr.shutil, "which", lambda name: None)
    assert wr.resolve_camponi() is None


# --- list_terminals ------------------------------------------------------------


def test_list_terminals_parses_a_real_row(monkeypatch):
    calls = fake_run(monkeypatch, stdout=terminals_payload(SAMPLE_ROW))
    terminals = wr.list_terminals("camponi")

    assert calls[0] == (["camponi", "--no-start", "--json", "terminal", "ls"], RUN_KWARGS)
    assert terminals == [wr.CamponiTerminal(
        id="t-0e5d40644195", kind="omp", status="running", cwd="/mnt/ssd-data/Projects/camponi",
        worktree=Path("/mnt/ssd-data/Projects/camponi"), started_at=1793597926641 / 1000,
        last_output_at=1793624957511 / 1000, args=(),
    )]
    assert terminals[0].running is True


def test_list_terminals_passes_the_runtime_folder(monkeypatch):
    calls = fake_run(monkeypatch, stdout=terminals_payload())
    assert wr.list_terminals("camponi", runtime_dir="/srv/camponi-rt") == []
    assert calls[0][0] == ["camponi", "--no-start", "--dir", "/srv/camponi-rt", "--json", "terminal", "ls"]


def test_list_terminals_reads_a_bare_array_too(monkeypatch):
    fake_run(monkeypatch, stdout=json.dumps([dict(SAMPLE_ROW, status="ended")]))
    terminal = wr.list_terminals("camponi")[0]
    assert terminal.status == "ended"
    assert terminal.running is False


def test_list_terminals_falls_back_to_the_cwd_and_tolerates_missing_fields(monkeypatch):
    row = {"id": "t-1", "cwd": "C:/w/app", "worktree": "", "args": ["--resume=C:/s.jsonl", 7], "startedAt": "soon",
           "future": {"a": 1}}
    fake_run(monkeypatch, stdout=terminals_payload(row, {"kind": "omp"}, "junk"))
    terminals = wr.list_terminals("camponi")
    assert len(terminals) == 1  # rows without an id are no terminals
    assert terminals[0].worktree == Path("C:/w/app")
    assert terminals[0].args == ("--resume=C:/s.jsonl", "7")
    assert terminals[0].kind == ""
    assert terminals[0].started_at is None
    assert terminals[0].last_output_at is None


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 10 ** 400, True])
def test_list_terminals_ignores_an_unusable_stamp(monkeypatch, value):
    fake_run(monkeypatch, stdout=terminals_payload(dict(SAMPLE_ROW, lastOutputAt=value)))
    assert wr.list_terminals("camponi")[0].last_output_at is None


def test_list_terminals_raises_with_the_stderr_tail(monkeypatch):
    fake_run(monkeypatch, returncode=1, stderr="noise\nno Camponi runtime is running\n")
    with pytest.raises(wr.WorkerRuntimeError, match="no Camponi runtime"):
        wr.list_terminals("camponi")


def test_list_terminals_trims_the_stderr_tail(monkeypatch):
    fake_run(monkeypatch, returncode=1, stderr="x" * 600 + "tail-marker")
    with pytest.raises(wr.WorkerRuntimeError) as error:
        wr.list_terminals("camponi")
    message = str(error.value)
    assert "tail-marker" in message
    assert "x" * 390 not in message  # only the last 400 characters of stderr are kept


def test_list_terminals_raises_on_unparseable_json(monkeypatch):
    fake_run(monkeypatch, stdout="<html>not json</html>")
    with pytest.raises(wr.WorkerRuntimeError, match="unparseable JSON"):
        wr.list_terminals("camponi")


def test_list_terminals_raises_without_a_terminals_list(monkeypatch):
    fake_run(monkeypatch, stdout=json.dumps({"ok": True}))
    with pytest.raises(wr.WorkerRuntimeError, match="no terminals list"):
        wr.list_terminals("camponi")


def test_list_terminals_raises_when_camponi_cannot_be_started(monkeypatch):
    fake_run(monkeypatch, exc=FileNotFoundError("no camponi here"))
    with pytest.raises(wr.WorkerRuntimeError, match="could not start"):
        wr.list_terminals("camponi")


def test_list_terminals_raises_when_camponi_times_out(monkeypatch):
    fake_run(monkeypatch, exc=subprocess.TimeoutExpired(["camponi"], 60))
    with pytest.raises(wr.WorkerRuntimeError, match="timed out after 60s"):
        wr.list_terminals("camponi")


def test_list_terminals_raises_on_an_unusable_argument_list(monkeypatch):
    fake_run(monkeypatch, exc=ValueError("embedded null byte"))
    with pytest.raises(wr.WorkerRuntimeError, match="could not start"):
        wr.list_terminals("camponi")


# --- send_nudge ---------------------------------------------------------------


def test_send_nudge_pastes_the_text_and_presses_enter(monkeypatch):
    calls = fake_run(monkeypatch)
    monkeypatch.setattr(wr.time, "sleep", lambda seconds: pytest.fail("a plain nudge never pauses"))
    assert wr.send_nudge("camponi", "t-1", "keep going") is None
    assert calls == [(["camponi", "--no-start", "terminal", "send", "--terminal", "t-1", "--text", "keep going",
                       "--paste", "--enter"], RUN_KWARGS)]


def test_send_nudge_interrupt_sends_escape_then_pauses_then_the_text(monkeypatch):
    events = []
    calls = fake_run(monkeypatch)
    monkeypatch.setattr(wr.time, "sleep", lambda seconds: events.append(("sleep", seconds, len(calls))))
    wr.send_nudge("camponi", "t-1", "stop the loop", interrupt=True, runtime_dir="/rt")
    assert [argv for argv, _ in calls] == [
        ["camponi", "--no-start", "--dir", "/rt", "terminal", "send", "--terminal", "t-1", "--text", "\x1b"],
        ["camponi", "--no-start", "--dir", "/rt", "terminal", "send", "--terminal", "t-1", "--text", "stop the loop",
         "--paste", "--enter"],
    ]
    assert events == [("sleep", wr.INTERRUPT_PAUSE_SECONDS, 1)]  # after the Escape, before the text


def test_send_nudge_raises_on_failure(monkeypatch):
    fake_run(monkeypatch, returncode=1, stderr="terminal t-gone is not running\n")
    with pytest.raises(wr.WorkerRuntimeError, match="t-gone"):
        wr.send_nudge("camponi", "t-gone", "hello")


def test_send_nudge_raises_when_camponi_cannot_be_started(monkeypatch):
    fake_run(monkeypatch, exc=FileNotFoundError("no camponi here"))
    with pytest.raises(wr.WorkerRuntimeError, match="could not start"):
        wr.send_nudge("camponi", "t-1", "hello")


def test_send_nudge_raises_when_camponi_times_out(monkeypatch):
    fake_run(monkeypatch, exc=subprocess.TimeoutExpired(["camponi"], 60))
    with pytest.raises(wr.WorkerRuntimeError, match="timed out after 60s"):
        wr.send_nudge("camponi", "t-1", "hello")


# --- probe_worktree -----------------------------------------------------------


def test_probe_worktree_clean_edit_and_commit(tmp_path):
    repo = make_repo(tmp_path / "repo")
    (repo / "a.txt").write_text("one\n", encoding="utf-8")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-m", "init")
    head = git(repo, "rev-parse", "HEAD")

    first = wr.probe_worktree(repo)
    assert first.head == head
    assert first.dirty is False
    assert first.activity_ts is not None

    (repo / "a.txt").write_text("two\n", encoding="utf-8")
    edited_at = first.activity_ts + 5
    os.utime(repo / "a.txt", (edited_at, edited_at))

    second = wr.probe_worktree(repo)
    assert second.head == head
    assert second.dirty is True
    assert second.activity_ts > first.activity_ts
    assert second.activity_ts == pytest.approx(edited_at, abs=0.01)

    committed_at = int(first.activity_ts) + 20
    git(repo, "add", "a.txt")
    git(repo, "commit", "-m", "second", env={"GIT_COMMITTER_DATE": f"@{committed_at}"})

    third = wr.probe_worktree(repo)
    assert third.head == git(repo, "rev-parse", "HEAD")
    assert third.head != head
    assert third.dirty is False
    assert third.activity_ts > second.activity_ts
    assert third.activity_ts == float(committed_at)


def test_probe_worktree_reads_changed_paths_with_spaces(tmp_path):
    repo = make_repo(tmp_path / "spaced")
    (repo / "sub dir").mkdir()
    tracked = repo / "sub dir" / "tracked.txt"
    tracked.write_text("one\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "init")
    first = wr.probe_worktree(repo)

    tracked.write_text("two\n", encoding="utf-8")
    edited_at = first.activity_ts + 5
    os.utime(tracked, (edited_at, edited_at))

    probe = wr.probe_worktree(repo)
    assert probe.dirty is True
    assert probe.activity_ts == pytest.approx(edited_at, abs=0.01)


def test_probe_worktree_reads_files_inside_a_new_untracked_folder(tmp_path):
    repo = make_repo(tmp_path / "new-folder")
    (repo / "tracked.txt").write_text("one\n", encoding="utf-8")
    git(repo, "add", "tracked.txt")
    git(repo, "commit", "-m", "init")
    first = wr.probe_worktree(repo)

    folder = repo / "models" / "characters"
    folder.mkdir(parents=True)
    new_file = folder / "chibi.glb"
    new_file.write_bytes(b"glb")
    edited_at = first.activity_ts + 50
    os.utime(new_file, (edited_at, edited_at))
    for parent in (folder, repo / "models"):  # a collapsed `?? models/` line would read these older stamps
        os.utime(parent, (first.activity_ts + 1, first.activity_ts + 1))

    probe = wr.probe_worktree(repo)
    assert probe.dirty is True
    assert probe.activity_ts == pytest.approx(edited_at, abs=0.01)


@pytest.mark.skipif(os.name == "nt", reason="Windows file names cannot contain '>'")
def test_probe_worktree_counts_an_untracked_name_with_an_arrow(tmp_path):
    repo = make_repo(tmp_path / "arrows")
    (repo / "tracked.txt").write_text("one\n", encoding="utf-8")
    git(repo, "add", "tracked.txt")
    git(repo, "commit", "-m", "init")
    first = wr.probe_worktree(repo)

    odd = repo / "a -> b.txt"
    odd.write_text("new\n", encoding="utf-8")
    edited_at = first.activity_ts + 5
    os.utime(odd, (edited_at, edited_at))
    quoted = git(repo, "status", "--porcelain")
    assert quoted in ("?? a -> b.txt", '?? "a -> b.txt"')
    assert wr._porcelain_paths(quoted) == ["a -> b.txt"]

    probe = wr.probe_worktree(repo)
    assert probe.dirty is True
    assert probe.activity_ts == pytest.approx(edited_at, abs=0.01)


def test_probe_worktree_reads_a_linked_worktree(tmp_path):
    repo = make_repo(tmp_path / "main")
    (repo / "a.txt").write_text("one\n", encoding="utf-8")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-m", "init")

    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "-q", str(linked))
    assert (linked / ".git").is_file()
    index = Path(git(linked, "rev-parse", "--git-path", "index"))
    assert (index if index.is_absolute() else linked / index).exists()

    first = wr.probe_worktree(linked)
    assert first.head == git(repo, "rev-parse", "HEAD")
    assert first.dirty is False

    (linked / "a.txt").write_text("two\n", encoding="utf-8")
    edited_at = first.activity_ts + 5
    os.utime(linked / "a.txt", (edited_at, edited_at))

    second = wr.probe_worktree(linked)
    assert second.dirty is True
    assert second.activity_ts > first.activity_ts
    assert second.activity_ts == pytest.approx(edited_at, abs=0.01)


def test_probe_worktree_unborn_branch_has_no_head(tmp_path):
    repo = tmp_path / "fresh"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)

    probe = wr.probe_worktree(repo)
    assert probe.head is None
    assert probe.dirty is False


def test_probe_worktree_outside_a_repository_reads_nothing(tmp_path):
    assert wr.probe_worktree(tmp_path / "missing") == wr.WorktreeProbe(head=None, dirty=False, activity_ts=None)


def test_porcelain_paths_reads_renames_and_quoted_names():
    porcelain = 'R  a.txt -> b.txt\n?? "sub dir/x.txt"\n M plain.txt\n'
    assert wr._porcelain_paths(porcelain) == ["b.txt", "sub dir/x.txt", "plain.txt"]


def test_porcelain_paths_splits_arrows_only_on_rename_and_copy_codes():
    porcelain = '?? a -> b.txt\nR  old.txt -> new.txt\nC  src.txt -> copy.txt\n M x -> y.txt\n'
    assert wr._porcelain_paths(porcelain) == ["a -> b.txt", "new.txt", "copy.txt", "x -> y.txt"]


def test_porcelain_paths_parses_quoted_arrows_and_renames():
    assert wr._porcelain_paths('?? "a -> b.txt"') == ["a -> b.txt"]
    assert wr._porcelain_paths("R  old.txt -> new.txt") == ["new.txt"]
    assert wr._porcelain_paths('R  "old name.txt" -> "new name.txt"') == ["new name.txt"]
    assert wr._porcelain_paths('?? "caf\\303\\251"') == ["café"]


def test_unquote_decodes_a_full_octal_escape():
    assert wr._unquote('"caf\\303\\251"') == "café"


def test_unquote_tolerates_a_short_octal_escape():
    assert wr._unquote('"caf\\5"') == "caf\x05"
    assert wr._unquote('"\\1x"') == "\x01x"
