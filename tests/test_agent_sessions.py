"""Tests for guard.core.agent_sessions: session folders, which log a terminal writes, its subagents."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from guard.core import agent_sessions as sessions
from guard.core.worker_runtime import CamponiTerminal

CWD = "/mnt/ssd-data/Projects/camponi"
T0 = datetime(2026, 11, 2, 5, 12, 51, tzinfo=timezone.utc).timestamp()  # whole seconds: stamps compare exactly


def terminal(tid="t-1", *, kind="omp", cwd=CWD, started_at=T0, status="running", args=()) -> CamponiTerminal:
    return CamponiTerminal(id=tid, kind=kind, status=status, cwd=cwd, worktree=Path(cwd), started_at=started_at,
                           last_output_at=None, args=tuple(args))


def omp_name(ts: float, sid: str) -> str:
    stamp = datetime.fromtimestamp(ts, tz=timezone.utc)
    return f"{stamp:%Y-%m-%dT%H-%M-%S}-{stamp.microsecond // 1000:03d}Z_{sid}.jsonl"


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def write_log(path: Path, *rows: dict, mtime: float | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


def omp_folder(root: Path) -> Path:
    folder = root / "--mnt-ssd-data-Projects-camponi--"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def find(tmp_path: Path, term: CamponiTerminal, *others: CamponiTerminal):
    return sessions.session_log(term, [term, *others], home="/home/u", tmp="/tmp",
                                omp_root=tmp_path / "omp", claude_root=tmp_path / "claude")


# --- folder names ---------------------------------------------------------------


def test_omp_folder_names_follow_omps_rule():
    assert sessions.omp_dir_name(CWD, "/home/u", "/tmp") == "--mnt-ssd-data-Projects-camponi--"
    assert sessions.omp_dir_name("/home/u/code/shop", "/home/u", "/tmp") == "-code-shop"
    assert sessions.omp_dir_name("/home/u", "/home/u", "/tmp") == "-"
    assert sessions.omp_dir_name("/tmp/work-1", "/home/u", "/tmp") == "-tmp-work-1"
    assert sessions.omp_dir_name("C:\\orchard\\camponi\\t13", "C:\\Users\\Admin", "C:\\Temp") == "--C--orchard-camponi-t13--"
    assert sessions.omp_dir_name("c:\\users\\admin\\code\\shop", "C:\\Users\\Admin", "C:\\Temp") == "-code-shop"
    assert sessions.legacy_dir_name("E:\\Projects\\camponi\\") == "--E--Projects-camponi--"


def test_claude_folder_names_turn_every_non_alphanumeric_into_a_dash():
    assert sessions.claude_dir_name("C:\\Users\\Admin\\.oh-my-studio\\agent\\work") == "C--Users-Admin--oh-my-studio-agent-work"
    assert sessions.claude_dir_name("/mnt/ssd-data/Projects/camponi/") == "-mnt-ssd-data-Projects-camponi"


def test_same_path_folds_case_only_for_windows_drives():
    assert sessions.same_path("C:\\W\\App\\", "c:/w/app")
    assert not sessions.same_path("/W/App", "/w/app")


# --- which session belongs to a terminal ----------------------------------------


def test_omp_session_is_the_newest_log_created_after_the_terminal_started(tmp_path):
    folder = omp_folder(tmp_path / "omp")
    write_log(folder / omp_name(T0 - 3600, "old"), {"type": "session"}, mtime=T0 + 500)  # an older run
    first = write_log(folder / omp_name(T0 + 1, "a"), {"type": "session"}, mtime=T0 + 100)
    second = write_log(folder / omp_name(T0 + 50, "b"), {"type": "session"}, mtime=T0 + 200)  # /new in the same terminal
    write_log(folder / "notes.jsonl", {"type": "session"}, mtime=T0 + 900)  # no omp name: never a session

    assert find(tmp_path, terminal()) == second
    assert first.exists()


def test_two_agents_in_one_folder_split_the_logs_at_the_next_start(tmp_path):
    folder = omp_folder(tmp_path / "omp")
    t2_start = T0 + 1555
    mine = write_log(folder / omp_name(T0 + 0.8, "mine"), {"type": "session"}, mtime=T0 + 9000)
    theirs = write_log(folder / omp_name(t2_start + 0.7, "theirs"), {"type": "session"}, mtime=T0 + 8000)
    first, second = terminal("t-1"), terminal("t-2", started_at=t2_start)
    claude_there = terminal("t-3", kind="claude", started_at=T0 + 10)  # another kind: not a boundary
    ended_there = terminal("t-4", started_at=T0 + 20, status="ended")  # not running: not a boundary

    assert find(tmp_path, first, second, claude_there, ended_there) == mine
    assert find(tmp_path, second, first) == theirs


def test_a_log_created_just_before_the_recorded_start_still_counts(tmp_path):
    folder = omp_folder(tmp_path / "omp")
    log = write_log(folder / omp_name(T0 - 4, "early"), {"type": "session"})
    write_log(folder / omp_name(T0 - 6, "too-early"), {"type": "session"}, mtime=T0 + 99)
    assert find(tmp_path, terminal()) == log


def test_no_session_when_nothing_matches(tmp_path):
    folder = omp_folder(tmp_path / "omp")
    write_log(folder / omp_name(T0 - 600, "old"), {"type": "session"})
    assert find(tmp_path, terminal()) is None
    assert find(tmp_path, terminal(cwd="/srv/elsewhere")) is None  # no folder at all
    assert find(tmp_path, terminal(kind="codex")) is None  # codex keeps no subagent logs
    assert find(tmp_path, terminal(kind="shell")) is None


def test_omp_resume_arg_names_the_session_by_file_or_id(tmp_path):
    folder = omp_folder(tmp_path / "omp")
    resumed = write_log(folder / omp_name(T0 - 86400, "01a19aac-b668"), {"type": "session"}, mtime=T0 - 80000)
    write_log(folder / omp_name(T0 + 1, "fresh"), {"type": "session"})

    assert find(tmp_path, terminal(args=[f"--resume={resumed}"])) == resumed
    assert find(tmp_path, terminal(args=["--model=x", "--resume", "01A19AAC-B668"])) == resumed
    assert find(tmp_path, terminal(args=["--resume=nothing-like-it"])) is None


def test_omp_sessions_respect_the_agent_dir_variable(tmp_path, monkeypatch):
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(tmp_path / "agent"))
    log = write_log(omp_folder(tmp_path / "agent" / "sessions") / omp_name(T0 + 1, "a"), {"type": "session"})
    assert sessions.session_log(terminal(), [], home="/home/u", tmp="/tmp") == log


def test_claude_session_matches_by_first_timestamp_and_its_own_cwd(tmp_path):
    folder = tmp_path / "claude" / "-mnt-ssd-data-Projects-camponi"
    meta = {"type": "mode", "mode": "normal"}
    mine = write_log(folder / "u-mine.jsonl", meta, {"type": "user", "cwd": CWD, "timestamp": iso(T0 + 3)}, mtime=T0 + 50)
    # Same slug, other folder (`Projects-camponi` vs `Projects/camponi`), written later.
    other_cwd = "/mnt/ssd-data/Projects-camponi"
    write_log(folder / "u-other.jsonl", {"type": "user", "cwd": other_cwd, "timestamp": iso(T0 + 4)}, mtime=T0 + 90)
    write_log(folder / "u-old.jsonl", {"type": "user", "cwd": CWD, "timestamp": iso(T0 - 900)}, mtime=T0 + 99)

    assert find(tmp_path, terminal(kind="claude")) == mine
    resumed = find(tmp_path, terminal(kind="claude", args=["/c", "claude.cmd", "--resume", "u-old"]))
    assert resumed == folder / "u-old.jsonl"


# --- subagents ------------------------------------------------------------------


def test_omp_subagents_include_nested_ones_and_their_end(tmp_path):
    session = omp_folder(tmp_path / "omp") / omp_name(T0 + 1, "s")
    write_log(session, {"type": "session"})
    folder = session.with_suffix("")
    head = {"type": "title", "title": ""}
    exit_line = {"type": "custom", "customType": "session_exit", "data": {"reason": "dispose"}}
    write_log(folder / "Fixer.jsonl", head, {"type": "session", "timestamp": iso(T0 + 60), "parentSession": str(session)},
              {"type": "message"}, mtime=T0 + 300)
    write_log(folder / "Review.jsonl", {"type": "session", "timestamp": iso(T0 + 70)}, exit_line, mtime=T0 + 400)
    write_log(folder / "Review" / "Review.Backend.jsonl", {"type": "session", "timestamp": iso(T0 + 80)}, mtime=T0 + 380)
    # A tool output that quotes the exit line is no exit.
    quoted = {"type": "message", "content": json.dumps(exit_line)}
    write_log(folder / "Review" / "Review.Backend" / "Review.Backend.Probe.jsonl",
              {"type": "session", "timestamp": iso(T0 + 90)}, quoted, mtime=T0 + 390)
    (folder / "Fixer.md").write_text("report", encoding="utf-8")
    (folder / "12.bash.log").write_text("output", encoding="utf-8")

    logs = sessions.subagent_logs("omp", session, now=T0 + 500, quiet_sec=90)

    assert [(log.name, log.created, log.mtime, log.ended) for log in logs] == [
        ("Fixer", T0 + 60, T0 + 300, False),
        ("Review", T0 + 70, T0 + 400, True),
        ("Review/Backend", T0 + 80, T0 + 380, False),
        ("Review/Backend/Probe", T0 + 90, T0 + 390, False),
    ]


def test_omp_session_without_subagents_has_none(tmp_path):
    session = write_log(omp_folder(tmp_path / "omp") / omp_name(T0 + 1, "s"), {"type": "session"})
    assert sessions.subagent_logs("omp", session, now=T0, quiet_sec=90) == []
    assert sessions.subagent_logs("codex", session, now=T0, quiet_sec=90) == []


def test_omp_exit_line_found_past_a_long_log(tmp_path, monkeypatch):
    monkeypatch.setattr(sessions, "TAIL_BYTES", 256)
    session = write_log(omp_folder(tmp_path / "omp") / omp_name(T0 + 1, "s"), {"type": "session"})
    rows = [{"type": "session", "timestamp": iso(T0 + 5)}] + [{"type": "message", "n": n} for n in range(50)]
    write_log(session.with_suffix("") / "Long.jsonl", *rows, {"type": "custom", "customType": "session_exit"})
    assert [log.ended for log in sessions.subagent_logs("omp", session, now=T0, quiet_sec=90)] == [True]


def test_claude_subagent_ends_on_a_quiet_end_turn(tmp_path):
    session = write_log(tmp_path / "claude" / "-p" / "u-1.jsonl", {"type": "user"})
    folder = session.with_suffix("") / "subagents"

    def assistant(stop):
        return {"type": "assistant", "message": {"role": "assistant", "stop_reason": stop}}

    start = {"type": "user", "timestamp": iso(T0 + 10), "message": {"role": "user"}}
    write_log(folder / "agent-done.jsonl", start, assistant("end_turn"), {"type": "cost-state"}, mtime=T0 + 100)
    write_log(folder / "agent-tool.jsonl", start, assistant("tool_use"), mtime=T0 + 100)
    write_log(folder / "agent-fresh.jsonl", start, assistant("end_turn"), mtime=T0 + 150)
    (folder / "notes.jsonl").write_text("{}\n", encoding="utf-8")

    logs = {log.name: log for log in sessions.subagent_logs("claude", session, now=T0 + 200, quiet_sec=90)}

    assert sorted(logs) == ["agent-done", "agent-fresh", "agent-tool"]
    assert logs["agent-done"].ended is True
    assert logs["agent-done"].created == T0 + 10
    assert logs["agent-tool"].ended is False  # waiting on a tool
    assert logs["agent-fresh"].ended is False  # its last write is younger than one interval
