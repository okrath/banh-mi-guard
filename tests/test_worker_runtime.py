"""Tests for guard.core.worker_runtime: git worktree probes, orca worker-list parsing, nudges."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from guard.core import worker_runtime as wr

# A real captured `orca orchestration worker-list` row (phase spec fixture).
SAMPLE_ROW = {
    "workerState": "ready",
    "dispatchStatus": "dispatched",
    "agentTerminalHandle": "term_63459aa6-d73e-489f-bd1f-230b046e05e6",
    "terminalState": "active",
    "resource": {
        "worktreeId": "da4c74d8-728f-4fb3-b7cf-ddc8ac9efcc2::C:/orca/workspaces/mystery-box/v8w5-reels",
        "terminalHandle": "term_63459aa6-d73e-489f-bd1f-230b046e05e6",
    },
    "projection": {
        "stage": {"worker": "ready", "dispatch": "dispatched", "detail": "input_accepted", "activity": "working"},
        "outcome": "in_progress",
        "liveness": {"verdict": "live", "observedAt": 1792380735663, "source": "agent_status"},
    },
}


def orca_payload(*rows: dict) -> str:
    return json.dumps({"ok": True, "result": {"workers": list(rows)}})


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


# --- resolve_orca -------------------------------------------------------------


def test_resolve_orca_prefers_the_environment(monkeypatch):
    monkeypatch.setenv("ORCA_CLI_COMMAND", "C:/custom/orca.exe")
    monkeypatch.setattr(wr.shutil, "which", lambda name: "/from/path/orca")
    assert wr.resolve_orca() == "C:/custom/orca.exe"


def test_resolve_orca_falls_back_to_path(monkeypatch):
    monkeypatch.delenv("ORCA_CLI_COMMAND", raising=False)
    monkeypatch.setattr(wr.shutil, "which", lambda name: "/from/path/orca" if name == "orca" else None)
    assert wr.resolve_orca() == "/from/path/orca"


def test_resolve_orca_returns_none_without_environment_or_path(monkeypatch):
    monkeypatch.delenv("ORCA_CLI_COMMAND", raising=False)
    monkeypatch.setattr(wr.shutil, "which", lambda name: None)
    assert wr.resolve_orca() is None


# --- list_workers -------------------------------------------------------------


def test_list_workers_parses_a_real_worker_row(monkeypatch):
    calls = fake_run(monkeypatch, stdout=orca_payload(SAMPLE_ROW))
    workers = wr.list_workers("orca.exe", "run_1")

    assert calls[0] == (
        ["orca.exe", "orchestration", "worker-list", "--run", "run_1", "--json"],
        {"capture_output": True, "text": True, "encoding": "utf-8", "errors": "replace", "check": False},
    )
    assert len(workers) == 1
    worker = workers[0]
    assert worker.name == "v8w5-reels"
    assert worker.worktree == Path("C:/orca/workspaces/mystery-box/v8w5-reels")
    assert worker.terminal == "term_63459aa6-d73e-489f-bd1f-230b046e05e6"
    assert worker.worker_state == "ready"
    assert worker.stage_detail == "input_accepted"
    assert worker.activity == "working"
    assert worker.liveness == "live"
    assert worker.observed_at == 1792380735663 / 1000
    assert worker.settled is False


@pytest.mark.parametrize("state", ["succeeded", "failed", "abandoned", "stopped"])
def test_list_workers_marks_settled_states(monkeypatch, state):
    fake_run(monkeypatch, stdout=orca_payload(dict(SAMPLE_ROW, workerState=state)))
    assert wr.list_workers("orca", "run_1")[0].settled is True


@pytest.mark.parametrize("state", ["ready", "starting", "released", "unknown"])
def test_list_workers_leaves_other_states_unsettled(monkeypatch, state):
    fake_run(monkeypatch, stdout=orca_payload(dict(SAMPLE_ROW, workerState=state)))
    assert wr.list_workers("orca", "run_1")[0].settled is False


def test_list_workers_filters_by_name(monkeypatch):
    other = dict(SAMPLE_ROW, resource={"worktreeId": "repo::C:/w/other"})
    fake_run(monkeypatch, stdout=orca_payload(SAMPLE_ROW, other))
    assert [w.name for w in wr.list_workers("orca", "run_1")] == ["v8w5-reels", "other"]
    assert [w.name for w in wr.list_workers("orca", "run_1", names=["other"])] == ["other"]
    assert wr.list_workers("orca", "run_1", names=[]) == []


def test_list_workers_keeps_a_row_without_a_worktree_only_when_named(monkeypatch):
    fake_run(monkeypatch, stdout=orca_payload({"taskId": "task_abc", "workerState": "ready"}))
    assert wr.list_workers("orca", "run_1") == []
    kept = wr.list_workers("orca", "run_1", names=["task_abc"])
    assert [w.name for w in kept] == ["task_abc"]
    assert kept[0].worktree is None
    assert wr.list_workers("orca", "run_1", names=["task_other"]) == []


def test_list_workers_tolerates_missing_optionals_and_unknown_fields(monkeypatch):
    row = {"workerState": "ready", "taskId": "task_x", "resource": {"worktreeId": "repo::C:/w/x"}, "future": {"a": 1}}
    fake_run(monkeypatch, stdout=orca_payload(row))
    worker = wr.list_workers("orca", "run_1")[0]
    assert worker.name == "x"
    assert worker.worktree == Path("C:/w/x")
    assert worker.terminal is None
    assert worker.stage_detail == ""
    assert worker.activity == ""
    assert worker.liveness == ""
    assert worker.observed_at is None
    assert worker.settled is False


def test_list_workers_ignores_a_non_numeric_liveness_stamp(monkeypatch):
    row = dict(SAMPLE_ROW, projection={"stage": {}, "liveness": {"verdict": "live", "observedAt": "yesterday"}})
    fake_run(monkeypatch, stdout=orca_payload(row))
    assert wr.list_workers("orca", "run_1")[0].observed_at is None


def test_list_workers_raises_with_the_stderr_tail(monkeypatch):
    fake_run(monkeypatch, returncode=1, stderr="noise\nfatal: run not found\n")
    with pytest.raises(wr.WorkerRuntimeError, match="run not found"):
        wr.list_workers("orca", "run_missing")


def test_list_workers_trims_the_stderr_tail(monkeypatch):
    fake_run(monkeypatch, returncode=1, stderr="x" * 600 + "tail-marker")
    with pytest.raises(wr.WorkerRuntimeError) as error:
        wr.list_workers("orca", "run_missing")
    message = str(error.value)
    assert "tail-marker" in message
    assert "x" * 390 not in message  # only the last 400 characters of stderr are kept


def test_list_workers_raises_on_unparseable_json(monkeypatch):
    fake_run(monkeypatch, stdout="<html>not json</html>")
    with pytest.raises(wr.WorkerRuntimeError, match="unparseable JSON"):
        wr.list_workers("orca", "run_1")


def test_list_workers_raises_without_a_workers_list(monkeypatch):
    fake_run(monkeypatch, stdout=json.dumps({"ok": True, "result": {}}))
    with pytest.raises(wr.WorkerRuntimeError, match="result.workers"):
        wr.list_workers("orca", "run_1")


def test_list_workers_raises_when_orca_cannot_be_started(monkeypatch):
    fake_run(monkeypatch, exc=FileNotFoundError("no orca here"))
    with pytest.raises(wr.WorkerRuntimeError, match="could not start"):
        wr.list_workers("orca", "run_1")


# --- send_nudge ---------------------------------------------------------------


def test_send_nudge_builds_the_exact_command(monkeypatch):
    calls = fake_run(monkeypatch, stdout='{"ok": true}')
    assert wr.send_nudge("orca.exe", "term_1", "keep going") is None
    argv, kwargs = calls[0]
    assert argv == ["orca.exe", "terminal", "send", "--terminal", "term_1", "--text", "keep going",
                    "--enter", "--json"]
    assert kwargs == {"capture_output": True, "text": True, "encoding": "utf-8", "errors": "replace", "check": False}


def test_send_nudge_raises_on_failure(monkeypatch):
    fake_run(monkeypatch, returncode=1, stderr="terminal term_gone is not connected\n")
    with pytest.raises(wr.WorkerRuntimeError, match="term_gone"):
        wr.send_nudge("orca", "term_gone", "hello")


def test_send_nudge_raises_when_orca_cannot_be_started(monkeypatch):
    fake_run(monkeypatch, exc=FileNotFoundError("no orca here"))
    with pytest.raises(wr.WorkerRuntimeError, match="could not start"):
        wr.send_nudge("orca", "term_1", "hello")


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
