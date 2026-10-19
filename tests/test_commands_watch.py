"""Tests for the `guard worker-verify` and `guard watch` commands (tests/test_commands_watch.py)."""

import json
import re
import subprocess
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

import guard.cli
from guard.commands import watch as watch_mod
from guard.core import worker_verify as engine
from guard.core.worker_runtime import OrcaWorker, WorkerRuntimeError, WorktreeProbe

app = guard.cli.app

LOG_LINE_RE = re.compile(r"^\d\d:\d\d:\d\d  \S+  \S+  .*$")


def git(repo: Path, *args: str) -> str:
    res = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8",
                         errors="replace", check=True)
    return (res.stdout or "").strip()


def make_repo(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True, capture_output=True)
    return path


def committed_repo(path: Path) -> Path:
    """A repo with one tracked file committed; returns the commit sha."""
    repo = make_repo(path)
    (repo / "a.py").write_text("VALUE = 1\n", encoding="utf-8")
    git(repo, "add", "a.py")
    git(repo, "commit", "-m", "init")
    return repo


_DEFAULT = object()


def worker_row(name: str, *, terminal="term_1", settled=False, observed_at=None, worktree=_DEFAULT) -> OrcaWorker:
    path = Path("C:/w") / name if worktree is _DEFAULT else worktree
    return OrcaWorker(
        name=name,
        worktree=path,
        terminal=terminal,
        worker_state="succeeded" if settled else "ready",
        stage_detail="",
        activity="",
        liveness="",
        observed_at=observed_at,
        settled=settled,
    )


def fake_probe(head="b" * 40, *, dirty=False, activity_ts=None):
    stamp = time.time() if activity_ts is None else activity_ts
    return lambda worktree: WorktreeProbe(head=head, dirty=dirty, activity_ts=stamp)


def empty_verify(worktree, **kwargs) -> engine.VerifyResult:
    return engine.VerifyResult()


# --- guard worker-verify ------------------------------------------------------


def test_worker_verify_passes_a_clean_repo_within_ownership(tmp_path):
    repo = committed_repo(tmp_path / "clean")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "a.py").write_text("VALUE = 2\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py"])

    assert result.exit_code == 0
    assert "RESULT: PASS" in result.output


def test_worker_verify_fails_an_out_of_scope_edit(tmp_path):
    repo = committed_repo(tmp_path / "outside")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "b.py").write_text("STOLEN = True\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py"])

    assert result.exit_code == 1
    assert "FAIL  [scope-outside-ownership]" in result.output
    assert "RESULT: FAIL (1)" in result.output


def test_worker_verify_own_splits_a_comma_separated_value(tmp_path):
    repo = committed_repo(tmp_path / "comma")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
    (repo / "b.py").write_text("B = 1\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py, b.py"]
    )

    assert result.exit_code == 0
    assert "RESULT: PASS" in result.output


def test_worker_verify_role_test_rejects_tracked_edits(tmp_path):
    repo = committed_repo(tmp_path / "testrole")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "a.py").write_text("VALUE = 2\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--role", "test", "--own", "**"]
    )

    assert result.exit_code == 1
    assert "test-worker-tracked-edits" in result.output


def test_worker_verify_json_matches_to_dict(tmp_path):
    repo = committed_repo(tmp_path / "json")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "b.py").write_text("STOLEN = True\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py", "--json"]
    )

    assert result.exit_code == 1
    assert json.loads(result.output) == engine.verify_worker(repo, base=base, own=["a.py"]).to_dict()


def test_worker_verify_quick_skips_the_check_commands(tmp_path):
    repo = committed_repo(tmp_path / "quick")
    base = git(repo, "rev-parse", "HEAD")
    failing = 'python -c "import sys; sys.exit(1)"'

    result = CliRunner().invoke(
        app,
        ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py", "--quick", "--check", failing],
    )

    assert result.exit_code == 0
    assert "RESULT: PASS" in result.output


def test_worker_verify_failing_check_fails_the_audit(tmp_path):
    repo = committed_repo(tmp_path / "check")
    base = git(repo, "rev-parse", "HEAD")

    result = CliRunner().invoke(
        app,
        ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py",
         "--check", 'python -c "import sys; sys.exit(1)"'],
    )

    assert result.exit_code == 1
    assert "FAIL  [check-failed]" in result.output
    assert "RESULT: FAIL (1)" in result.output


def test_worker_verify_prints_warnings_before_failures(tmp_path):
    repo = committed_repo(tmp_path / "warn")
    tests_dir = repo / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_x.py").write_text("def test_x():\n    assert 1 == 1\n    assert 2 == 2\n", encoding="utf-8")
    git(repo, "add", "tests/test_x.py")
    git(repo, "commit", "-m", "tests")
    base = git(repo, "rev-parse", "HEAD")
    (tests_dir / "test_x.py").write_text("def test_x():\n    pass\n", encoding="utf-8")
    (repo / "src").mkdir()
    (repo / "src" / "other.py").write_text("X = 1\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "tests/**"]
    )

    assert result.exit_code == 1
    output = result.output
    assert "WARN  [fewer-assertions]" in output
    assert "FAIL  [scope-outside-ownership]" in output
    assert output.index("WARN ") < output.index("FAIL ")
    assert "RESULT: FAIL (1)" in output


def test_worker_verify_reports_a_pass_with_warnings(tmp_path):
    repo = committed_repo(tmp_path / "warnonly")
    tests_dir = repo / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_y.py").write_text("def test_y():\n    assert 1 == 1\n    assert 2 == 2\n", encoding="utf-8")
    git(repo, "add", "tests/test_y.py")
    git(repo, "commit", "-m", "tests")
    base = git(repo, "rev-parse", "HEAD")
    (tests_dir / "test_y.py").write_text("def test_y():\n    assert 1 == 1\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "tests/**"]
    )

    assert result.exit_code == 0
    assert "RESULT: PASS with 1 warning(s)" in result.output


def test_worker_verify_accepts_epoch_since(tmp_path):
    repo = committed_repo(tmp_path / "since")
    base = git(repo, "rev-parse", "HEAD")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py", "--since", "1"]
    )

    assert result.exit_code == 0
    assert "RESULT: PASS" in result.output


@pytest.mark.parametrize(
    "extra",
    [
        ["--since", "not-a-time"],
        ["--since", "2026-13-99T99:99:99"],
        ["--role", "reviewer"],
    ],
)
def test_worker_verify_invalid_option_values_are_usage_errors(tmp_path, extra):
    repo = committed_repo(tmp_path / ("bad" + extra[-1].replace(":", "").replace("-", "")))
    base = git(repo, "rev-parse", "HEAD")

    result = CliRunner().invoke(app, ["worker-verify", "--worktree", str(repo), "--base", base, *extra])

    assert result.exit_code == 2


def test_worker_verify_missing_worktree_is_a_usage_error(tmp_path):
    result = CliRunner().invoke(app, ["worker-verify", "--worktree", str(tmp_path / "missing"), "--base", "HEAD"])

    assert result.exit_code == 2


def test_worker_verify_unresolvable_base_is_a_usage_error(tmp_path):
    repo = committed_repo(tmp_path / "badbase")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", "no-such-ref^{commit}"]
    )

    assert result.exit_code == 2
    assert "does not resolve" in result.output


def test_worker_verify_report_relative_to_the_worktree(tmp_path):
    repo = committed_repo(tmp_path / "report")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "report.md").write_text("All tests pass.\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py", "--own", "report.md",
              "--report", "report.md", "--quick"]
    )

    assert result.exit_code == 0  # --quick skips the report check: the file is not read

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py", "--own", "report.md",
              "--report", "report.md"]
    )

    assert result.exit_code == 0
    assert "WARN  [report-unchecked-claim]" in result.output


# --- guard watch: usage -------------------------------------------------------


def test_watch_without_run_or_worktree_is_a_usage_error():
    result = CliRunner().invoke(app, ["watch", "--once"])

    assert result.exit_code == 2


def test_watch_unresolvable_orca_is_a_usage_error(monkeypatch):
    monkeypatch.setattr(watch_mod, "resolve_orca", lambda: None)

    result = CliRunner().invoke(app, ["watch", "--run", "run_1", "--once"])

    assert result.exit_code == 2


def test_watch_rejects_a_broken_ownership_file(tmp_path):
    broken = tmp_path / "ownership.json"
    broken.write_text('{"a": {"role": "reviewer"}}', encoding="utf-8")

    result = CliRunner().invoke(
        app, ["watch", "--worktree", str(tmp_path), "--ownership", str(broken), "--once"]
    )

    assert result.exit_code == 2


def test_help_lists_both_new_commands():
    output = CliRunner().invoke(app, ["--help"]).output

    assert "watch" in output
    assert "worker-verify" in output


# --- guard watch: --once ------------------------------------------------------


def test_watch_once_json_reports_the_pass_and_writes_the_log(tmp_path, monkeypatch):
    now = time.time()
    rows = [
        worker_row("fix-a", terminal="term_1", observed_at=now),
        worker_row("test-b", terminal=None, settled=True, observed_at=now),
    ]
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run: list(rows))
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(dirty=True))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    log = tmp_path / "watch.log"

    result = CliRunner().invoke(
        app,
        ["watch", "--run", "run_1", "--orca", "orca", "--workers", "fix-a,test-b", "--test-workers", "test-b",
         "--once", "--json", "--log", str(log)],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert [row["name"] for row in payload] == ["fix-a", "test-b"]
    assert set(payload[0]) == {
        "name", "head", "head_moved", "dirty", "activity_ts", "heartbeat_ts", "settled", "quick_fails", "state",
        "actions",
    }
    assert payload[0]["heartbeat_ts"] == pytest.approx(now, abs=1.0)
    assert payload[0]["head"] == "b" * 40
    assert payload[0]["head_moved"] is False
    assert payload[0]["dirty"] is True
    assert payload[0]["settled"] is False
    assert payload[0]["quick_fails"] == []
    assert payload[0]["state"] == "working"
    assert payload[1]["state"] == "needs-human"
    assert payload[1]["actions"][0]["reason"] == "settled-dirty"
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert all(LOG_LINE_RE.match(line) for line in lines)
    assert "  test-b  needs-human  " in lines[1]


def test_watch_once_never_sends_a_nudge(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run: [worker_row("fix-a", terminal="term_1")])
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(dirty=False))
    monkeypatch.setattr(
        watch_mod, "verify_worker",
        lambda worktree, **kwargs: engine.VerifyResult(
            issues=[engine.VerifyIssue(engine.FAIL, "scope-outside-ownership", "edited outside its ownership: x.py")]
        ),
    )
    monkeypatch.setattr(watch_mod, "send_nudge", lambda *args: sent.append(args))
    log = tmp_path / "once.log"

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--once", "--json", "--log", str(log)]
    )

    assert result.exit_code == 0
    assert sent == []
    payload = json.loads(result.output)
    assert payload[0]["state"] == "suspect"
    assert payload[0]["quick_fails"] == ["scope-outside-ownership: edited outside its ownership: x.py"]
    assert payload[0]["actions"][0]["kind"] == "nudge"
    assert "nudge skipped: dry run (--once)" in log.read_text(encoding="utf-8")


def test_watch_run_without_workers_skips_settled_rows(tmp_path, monkeypatch):
    rows = [worker_row("fix-a"), worker_row("old-c", settled=True)]
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run: list(rows))
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe())
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--once", "--json", "--log", str(tmp_path / "s.log")]
    )

    assert result.exit_code == 0
    assert [row["name"] for row in json.loads(result.output)] == ["fix-a"]


def test_watch_logs_and_skips_a_row_without_a_worktree(tmp_path, monkeypatch):
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run: [worker_row("ghost", worktree=None)])
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe())
    log = tmp_path / "ghost.log"

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--once", "--json", "--log", str(log)]
    )

    assert result.exit_code == 0
    assert json.loads(result.output) == []
    assert "no worktree" in log.read_text(encoding="utf-8")


def test_watch_survives_a_failing_probe_and_quick_scan(tmp_path, monkeypatch):
    rows = [worker_row("bad-probe"), worker_row("bad-scan"), worker_row("good")]
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run: list(rows))

    def probe(worktree: Path):
        if worktree.name == "bad-probe":
            raise WorkerRuntimeError("orca timed out after 60s")
        return WorktreeProbe(head="c" * 40, dirty=False, activity_ts=100.0)

    def scan(worktree: Path, **kwargs):
        if worktree.name == "bad-scan":
            raise OSError("git vanished")
        return engine.VerifyResult()

    monkeypatch.setattr(watch_mod, "probe_worktree", probe)
    monkeypatch.setattr(watch_mod, "verify_worker", scan)
    log = tmp_path / "broken.log"

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--once", "--json", "--log", str(log)]
    )

    assert result.exit_code == 0
    assert [row["name"] for row in json.loads(result.stdout)] == ["good"]
    assert "watch: bad-probe: probe failed: orca timed out after 60s" in result.stderr
    assert "probe failed: git vanished" in log.read_text(encoding="utf-8")


def test_watch_reads_roles_and_own_from_the_ownership_file(tmp_path, monkeypatch):
    ownership = tmp_path / "ownership.json"
    ownership.write_text(
        json.dumps({"fix-a": {"role": "fix", "own": ["src/**"]}, "watcher": {"role": "test", "own": ["tests/**"]}}),
        encoding="utf-8",
    )
    seen = {}

    def scan(worktree: Path, **kwargs):
        seen[worktree.name] = kwargs
        return engine.VerifyResult()

    rows = [worker_row("fix-a"), worker_row("watcher", settled=True)]
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run: list(rows))
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(dirty=False))
    monkeypatch.setattr(watch_mod, "verify_worker", scan)

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--workers", "fix-a,watcher",
              "--ownership", str(ownership), "--once", "--json", "--log", str(tmp_path / "own.log")]
    )

    assert result.exit_code == 0
    assert seen["fix-a"]["role"] == "fix"
    assert seen["fix-a"]["own"] == ["src/**"]
    assert seen["watcher"]["role"] == "test"
    assert seen["watcher"]["own"] == ["tests/**"]
    assert json.loads(result.output)[1]["state"] == "done"


# --- guard watch: loop, plain-git and defaults --------------------------------


def test_watch_logs_a_skipped_nudge_without_a_terminal(tmp_path, monkeypatch):
    base = "a" * 40
    heads = iter([base, "b" * 40])
    sent = []
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run: [worker_row("fix-a", terminal=None)])
    monkeypatch.setattr(watch_mod, "probe_worktree", lambda worktree: WorktreeProbe(head=next(heads), dirty=False,
                                                                                    activity_ts=100.0))
    monkeypatch.setattr(
        watch_mod, "verify_worker",
        lambda worktree, **kwargs: engine.VerifyResult(
            issues=[engine.VerifyIssue(engine.FAIL, "scope-outside-ownership", "edited outside its ownership: x.py")]
        ),
    )
    monkeypatch.setattr(watch_mod, "send_nudge", lambda *args: sent.append(args))
    sleeps = []
    monkeypatch.setattr(watch_mod.time, "sleep", lambda seconds: sleeps.append(seconds))
    log = tmp_path / "loop.log"

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--base", base, "--interval-sec", "1",
              "--json", "--log", str(log)]
    )

    assert result.exit_code == 0
    assert sent == []
    assert sleeps == [1.0]
    assert json.loads(result.output)[0]["state"] == "done"
    assert "nudge skipped: no terminal" in log.read_text(encoding="utf-8")


def test_watch_final_summary_keeps_a_needs_human_line(tmp_path, monkeypatch):
    from guard.core.watchdog import SETTLED_DIRTY_TEXT

    heads = iter(["a" * 40, "b" * 40])

    def probe(worktree: Path) -> WorktreeProbe:
        if worktree.name == "test-a":
            return WorktreeProbe(head="a" * 40, dirty=True, activity_ts=time.time())
        return WorktreeProbe(head=next(heads), dirty=False, activity_ts=time.time())

    rows = [worker_row("test-a", terminal=None, settled=True), worker_row("fix-b")]
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run: list(rows))
    monkeypatch.setattr(watch_mod, "probe_worktree", probe)
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    monkeypatch.setattr(watch_mod.time, "sleep", lambda seconds: None)
    log = tmp_path / "final.log"

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--test-workers", "test-a", "--log", str(log)]
    )

    assert result.exit_code == 0
    assert "test-a" in result.output
    assert "fix-b" in result.output
    log_text = log.read_text(encoding="utf-8")
    assert log_text.count("test-a  needs-human") == 2  # one status line per pass, line kept to the end
    assert SETTLED_DIRTY_TEXT in log_text


def test_watch_plain_git_mode_on_a_real_repo(tmp_path):
    repo = committed_repo(tmp_path / "plain-watch")
    head = git(repo, "rev-parse", "HEAD")
    log = tmp_path / "plain.log"

    result = CliRunner().invoke(
        app, ["watch", "--worktree", str(repo), "--once", "--json", "--log", str(log)]
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload[0]["name"] == "plain-watch"
    assert payload[0]["head"] == head
    assert payload[0]["heartbeat_ts"] is None
    assert payload[0]["settled"] is False
    assert payload[0]["state"] == "working"
    assert LOG_LINE_RE.match(log.read_text(encoding="utf-8").splitlines()[0])


def test_watch_plain_git_mode_logs_an_uncommitted_repo(tmp_path):
    repo = make_repo(tmp_path / "unborn")
    log = tmp_path / "unborn.log"

    result = CliRunner().invoke(
        app, ["watch", "--worktree", str(repo), "--once", "--json", "--log", str(log)]
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload[0]["head"] is None
    assert payload[0]["state"] == "working"
    assert "quick scan skipped: no base or start head" in log.read_text(encoding="utf-8")


def test_watch_default_log_uses_the_first_worktree_name(tmp_path, monkeypatch):
    repo = committed_repo(tmp_path / "default-name")
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["watch", "--worktree", str(repo), "--once"])

    assert result.exit_code == 0
    assert (tmp_path / "guard-watch-default-name.log").is_file()


def test_watch_default_log_uses_the_run_id(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run: [worker_row("fix-a")])
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe())
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)

    result = CliRunner().invoke(app, ["watch", "--run", "run_7", "--orca", "orca", "--once"])

    assert result.exit_code == 0
    assert (tmp_path / "guard-watch-run_7.log").is_file()


def test_watch_table_prints_one_row_per_worker(tmp_path, monkeypatch):
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run: [worker_row("fix-a", observed_at=1000.0)])
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe())
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--once", "--log", str(tmp_path / "t.log")]
    )

    assert result.exit_code == 0
    assert "fix-a" in result.output
    assert "working" in result.output
    assert "bbbbbbb" in result.output  # the short head sha
