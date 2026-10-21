"""Tests for guard.core.worker_runtime: terminal screens, interrupt nudges, dev-server stops, `since`."""

import os
import subprocess
import time
from pathlib import Path

import pytest

from guard.core import worker_runtime as wr

SPINNER = "\u280b"  # a braille spinner glyph
OTHER_SPINNER = "\u2819"


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


# --- parse_screen -------------------------------------------------------------


def test_parse_screen_reads_the_opencode_footer_as_busy():
    screen = "Build the page\n\n\u25a0\u25a0\u2b1d\u2b1d  esc interrupt   ctrl+p commands"
    assert wr.parse_screen(screen).busy is True
    assert wr.parse_screen("Build the page\n\n  ctrl+p commands").busy is False


def test_parse_screen_reads_a_spinner_with_a_timer_as_busy():
    for timer in ("12s", "45m", "1h"):
        assert wr.parse_screen(f"> fix the bug\n{SPINNER} {timer} Working on it").busy is True
    assert wr.parse_screen(f"{SPINNER} Working").busy is False  # a glyph without a timer is no turn
    assert wr.parse_screen("> waiting for input").busy is False


def test_parse_screen_strips_the_animated_parts():
    first = wr.parse_screen(f"{SPINNER} 12s 3s Thinking\ntokens 12.5K (40%)\n\u25a0\u2b1d\u25a0 esc interrupt\nupload 37%")
    later = wr.parse_screen(f"{OTHER_SPINNER} 13s 4s Thinking\ntokens 13K (41%)\n\u2b1d\u25a0\u2b1d esc interrupt\nupload 38.5 %")
    assert first.stable == later.stable
    assert "Thinking" in first.stable
    assert "esc interrupt" in first.stable
    assert "%" not in first.stable


def test_parse_screen_keeps_real_progress_in_the_stable_text():
    first = wr.parse_screen(f"{SPINNER} 12s\nwrote a.py")
    later = wr.parse_screen(f"{SPINNER} 12s\nwrote b.py")
    assert first.stable != later.stable


def test_parse_screen_reads_the_running_command_while_busy():
    state = wr.parse_screen(f"{SPINNER} 4m  Bash\n{OTHER_SPINNER} $ pnpm exec playwright test --retries 50  \nattempt 56")
    assert state.command == "pnpm exec playwright test --retries 50"


def test_parse_screen_command_ignores_a_counter_after_it():
    first = wr.parse_screen(f"{SPINNER} 4m\n{SPINNER} $ node upload.js 12%")
    later = wr.parse_screen(f"{SPINNER} 5m\n{SPINNER} $ node upload.js 97%")
    assert first.command == later.command == "node upload.js"


def test_parse_screen_has_no_command_when_idle():
    assert wr.parse_screen(f"{SPINNER} $ npm test\n> ").command is None
    assert wr.parse_screen(f"{SPINNER} 3s\nno command header").command is None


@pytest.mark.parametrize(
    "line",
    [
        "  VITE v5.0.0  ready in 312 ms",
        "  \u279c  Local:   http://localhost:5173/",
        "[Nest] 1234  - LOG [NestApplication] Nest application successfully started",
        "[12:00:00] Starting compilation in watch mode... Watching for file changes.",
    ],
)
def test_parse_screen_sees_dev_server_output(line):
    assert wr.parse_screen(f"$ pnpm dev\n{line}\n").dev_server is True


def test_parse_screen_without_dev_server_output():
    assert wr.parse_screen("All 12 tests passed\nLocal changes committed").dev_server is False


def test_parse_screen_is_safe_on_non_ascii_text():
    screen = f"Vi\u1ec7t Nam: \u0111\u00e3 xong \U0001f600\n{SPINNER} 7s \u0110ang ch\u1ea1y\n\u2588\u2591 \ufffd caf\u00e9 50\uff05"
    state = wr.parse_screen(screen)
    assert state.busy is True
    assert "Vi\u1ec7t Nam: \u0111\u00e3 xong \U0001f600" in state.stable
    assert "caf\u00e9" in state.stable
    assert wr.parse_screen("").busy is False


def test_screen_patterns_use_escapes_instead_of_glyphs():
    source = Path(wr.__file__).read_text(encoding="utf-8")
    assert all(ord(char) < 0x2800 or ord(char) > 0x2BFF for char in source)  # no braille or bar glyphs
    assert "\\u2800-\\u28FF" in source


# --- read_screen --------------------------------------------------------------


def test_read_screen_builds_the_exact_command(monkeypatch):
    calls = fake_run(monkeypatch, stdout=f"{SPINNER} 3s working\n")
    assert wr.read_screen("orca.exe", "term_1") == f"{SPINNER} 3s working\n"
    argv, kwargs = calls[0]
    assert argv == ["orca.exe", "terminal", "read", "--terminal", "term_1", "--screen", "--limit", "25"]
    assert kwargs["encoding"] == "utf-8"
    assert kwargs["errors"] == "replace"
    assert kwargs["timeout"] == wr.CALL_TIMEOUT_SECONDS


def test_read_screen_passes_the_limit(monkeypatch):
    calls = fake_run(monkeypatch, stdout="x")
    wr.read_screen("orca", "term_1", limit=40)
    assert calls[0][0][-2:] == ["--limit", "40"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"returncode": 1, "stderr": "terminal term_1 is gone"},
        {"exc": FileNotFoundError("no orca")},
        {"exc": subprocess.TimeoutExpired(["orca"], 60)},
    ],
)
def test_read_screen_returns_none_when_there_is_no_screen(monkeypatch, kwargs):
    fake_run(monkeypatch, **kwargs)
    assert wr.read_screen("orca", "term_1") is None


# --- send_nudge interrupt -----------------------------------------------------


def test_send_nudge_interrupt_adds_the_flag(monkeypatch):
    calls = fake_run(monkeypatch, stdout='{"ok": true}')
    wr.send_nudge("orca.exe", "term_1", "stop the loop", interrupt=True)
    assert calls[0][0] == ["orca.exe", "terminal", "send", "--terminal", "term_1", "--text", "stop the loop",
                           "--enter", "--interrupt", "--json"]


def test_send_nudge_without_interrupt_has_no_flag(monkeypatch):
    calls = fake_run(monkeypatch, stdout='{"ok": true}')
    wr.send_nudge("orca.exe", "term_1", "keep going")
    assert "--interrupt" not in calls[0][0]


# --- stop_dev_servers ---------------------------------------------------------


def test_stop_dev_servers_stops_only_the_worktrees_own_dev_processes(monkeypatch):
    wt = Path("C:/orca/workspaces/app/fix-a")
    processes = [
        (101, r'"C:\Program Files\nodejs\node.exe" C:\orca\workspaces\app\fix-a\node_modules\vite\bin\vite.js'),
        (102, r"node C:\orca\workspaces\app\fix-a\node_modules\@nestjs\cli\bin\nest.js start --watch"),
        (103, r"node C:\orca\workspaces\app\fix-a-2\node_modules\vite\bin\vite.js"),  # a sibling worktree
        (104, r"node C:\orca\workspaces\app\other\node_modules\vite\bin\vite.js"),
        (105, r"node C:\orca\workspaces\app\fix-a\node_modules\typescript\lib\tsserver.js"),  # not a dev server
        (106, "node c:/ORCA/workspaces/app/fix-a/node_modules/.bin/ts-node src/main.ts"),
    ]
    killed = []
    monkeypatch.setattr(wr, "_node_processes", lambda: processes)
    monkeypatch.setattr(wr.os, "kill", lambda pid, sig: killed.append((pid, sig)))

    stopped = wr.stop_dev_servers(wt)

    assert [pid for pid, _sig in killed] == [101, 106]
    assert all(sig == wr.signal.SIGTERM for _pid, sig in killed)
    assert stopped[0] == "101: " + processes[0][1][:120]
    assert stopped[1].startswith("106: node c:/ORCA/workspaces/app/fix-a/")


def test_stop_dev_servers_matches_nest_start(monkeypatch):
    monkeypatch.setattr(wr, "_node_processes", lambda: [(7, r"node C:\w\fix-a\x.js nest start")])
    killed = []
    monkeypatch.setattr(wr.os, "kill", lambda pid, sig: killed.append(pid))
    assert wr.stop_dev_servers(Path("C:/w/fix-a")) == [r"7: node C:\w\fix-a\x.js nest start"]
    assert killed == [7]


def test_stop_dev_servers_skips_a_process_that_already_exited(monkeypatch):
    monkeypatch.setattr(wr, "_node_processes", lambda: [(9, "node /w/fix-a/node_modules/vite/bin/vite.js")])

    def gone(pid, sig):
        raise ProcessLookupError(pid)

    monkeypatch.setattr(wr.os, "kill", gone)
    assert wr.stop_dev_servers(Path("/w/fix-a")) == []


def test_stop_dev_servers_never_stops_itself(monkeypatch):
    monkeypatch.setattr(wr, "_node_processes", lambda: [(os.getpid(), "node /w/fix-a/vite.js")])
    monkeypatch.setattr(wr.os, "kill", lambda pid, sig: pytest.fail("killed the watcher"))
    assert wr.stop_dev_servers(Path("/w/fix-a")) == []


def test_node_processes_on_windows_reads_the_cim_json(monkeypatch):
    monkeypatch.setattr(wr.sys, "platform", "win32")
    stdout = '[{"ProcessId":11,"CommandLine":"node a.js"},{"ProcessId":12,"CommandLine":null}]'
    calls = fake_run(monkeypatch, stdout=stdout)
    assert wr._node_processes() == [(11, "node a.js")]
    argv = calls[0][0]
    assert argv[:4] == ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
    assert "Win32_Process" in argv[4] and "node.exe" in argv[4]


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [("", []), ('{"ProcessId":5,"CommandLine":"node vite"}', [(5, "node vite")]), ("[]", [])],
)
def test_windows_processes_reads_none_one_or_many(stdout, expected):
    assert wr._windows_processes(stdout) == expected


def test_windows_processes_rejects_unparseable_output():
    with pytest.raises(wr.WorkerRuntimeError, match="unparseable"):
        wr._windows_processes("Get-CimInstance : access denied")


def test_node_processes_elsewhere_reads_ps(monkeypatch):
    monkeypatch.setattr(wr.sys, "platform", "linux")
    stdout = "  11 node     node /w/a/vite.js --port 5173\n  12 bash     bash -c vite\nnoise\n"
    calls = fake_run(monkeypatch, stdout=stdout)
    assert wr._node_processes() == [(11, "node /w/a/vite.js --port 5173")]
    assert calls[0][0] == ["ps", "-eo", "pid=,comm=,args="]


@pytest.mark.parametrize("platform", ["win32", "linux"])
def test_node_processes_raises_when_the_listing_fails(monkeypatch, platform):
    monkeypatch.setattr(wr.sys, "platform", platform)
    fake_run(monkeypatch, returncode=1, stderr="denied")
    with pytest.raises(wr.WorkerRuntimeError, match="denied"):
        wr._node_processes()


def test_mentions_path_matches_the_path_and_its_children_only():
    wt = Path("C:/orca/workspaces/app/fix-a")
    assert wr.mentions_path(r"FAIL node_modules -> C:\orca\workspaces\app\fix-a\node_modules", wt)
    assert wr.mentions_path("points at c:/orca/workspaces/app/fix-a", wt)
    assert wr.mentions_path('"C:/orca/workspaces/app/fix-a" broke it', wt)
    assert not wr.mentions_path(r"C:\orca\workspaces\app\fix-a-2\node_modules", wt)
    assert not wr.mentions_path(r"C:\orca\workspaces\app\fix-ab", wt)
    assert not wr.mentions_path("FAIL something else", wt)


# --- probe_worktree since -----------------------------------------------------


def test_probe_worktree_ignores_an_old_base_commit_since_first_seen(tmp_path):
    repo = tmp_path / "old-base"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
    (repo / "a.txt").write_text("one\n", encoding="utf-8")
    old = 1_600_000_000
    env = {**os.environ, "GIT_AUTHOR_DATE": f"{old} +0000", "GIT_COMMITTER_DATE": f"{old} +0000"}
    for args in (["add", "a.txt"], ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base"]):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)
    index = repo / ".git" / "index"
    os.utime(index, (old - 100, old - 100))  # an index older than the commit: the commit time wins

    assert wr.probe_worktree(repo).activity_ts == pytest.approx(old)
    first_seen = time.time()
    assert wr.probe_worktree(repo, since=first_seen).activity_ts == pytest.approx(old - 100)
    assert wr.probe_worktree(repo, since=old).activity_ts == pytest.approx(old)  # a commit after `since` counts


# --- background jobs ----------------------------------------------------------

JOB_PREFIX = "\u2514\u2500 \u27e8bash\u27e9 "  # the corner, the dash and the tool tag omp draws


def test_parse_screen_reads_a_background_job_and_its_elapsed_time():
    screen = f"Waiting for the tests\n  {JOB_PREFIX}bg_1 python -m pytest tests/x.py -q\u2026 \u00b7 17m42s\n"
    assert wr.parse_screen(screen).jobs == (("python -m pytest tests/x.py -q", 17 * 60 + 42.0),)


@pytest.mark.parametrize(("elapsed", "seconds"), [("42s", 42.0), ("3m05s", 185.0), ("1h05m", 3900.0)])
def test_parse_screen_reads_every_elapsed_format(elapsed, seconds):
    assert wr.parse_screen(f"{JOB_PREFIX}bg_2 pnpm build \u00b7 {elapsed}").jobs == (("pnpm build", seconds),)


def test_parse_screen_takes_the_time_after_the_last_middle_dot():
    screen = f"{JOB_PREFIX}bg_3 echo a \u00b7 b\u2026 \u00b7 2m10s\n{JOB_PREFIX}bg_4 npm test \u00b7 9s"
    assert wr.parse_screen(screen).jobs == (("echo a \u00b7 b", 130.0), ("npm test", 9.0))


def test_parse_screen_without_background_jobs():
    assert wr.parse_screen(f"{SPINNER} 3s\n\u2514\u2500 done \u00b7 12s\n").jobs == ()
