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
from guard.core.watchdog import WatchConfig
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


def settles_on_refresh(name: str, **kwargs):
    """A worker-list stub: the dispatch is active on the first call and settled from the next one on."""
    calls = []

    def list_workers(orca, run, names=None):
        calls.append(run)
        return [worker_row(name, settled=len(calls) > 1, **kwargs)]

    return list_workers


def fake_probe(head="b" * 40, *, dirty=False, activity_ts=None):
    stamp = time.time() if activity_ts is None else activity_ts
    return lambda worktree, **kwargs: WorktreeProbe(head=head, dirty=dirty, activity_ts=stamp)


def empty_verify(worktree, **kwargs) -> engine.VerifyResult:
    return engine.VerifyResult()


def record_nudges(monkeypatch) -> list:
    """Replace send_nudge; returns the (orca, terminal, text, interrupt) of every nudge sent."""
    sent = []
    monkeypatch.setattr(watch_mod, "send_nudge",
                        lambda orca, terminal, text, *, interrupt=False: sent.append((orca, terminal, text, interrupt)))
    return sent


@pytest.fixture(autouse=True)
def no_real_orca(monkeypatch):
    """No test reaches the real Orca CLI, process list or dependency check: no screen, healthy links."""
    monkeypatch.setattr(watch_mod, "read_screen", lambda orca, terminal, limit=25: None)
    monkeypatch.setattr(watch_mod, "main_checkout_of", lambda worktree: None)
    monkeypatch.setattr(watch_mod, "check_main_checkout", lambda repo: [])

    def no_stop(worktree):
        raise AssertionError("stop_dev_servers called without a dev-server stall")

    monkeypatch.setattr(watch_mod, "stop_dev_servers", no_stop)


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


def test_worker_verify_accepts_an_iso_8601_since(tmp_path):
    repo = committed_repo(tmp_path / "iso-since")
    base = git(repo, "rev-parse", "HEAD")

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--own", "a.py",
              "--since", "2020-01-01T00:00:00"]
    )

    assert result.exit_code == 0
    assert "RESULT: PASS" in result.output


def test_worker_verify_evidence_path_is_relative_to_the_worktree(tmp_path):
    repo = committed_repo(tmp_path / "evidence")
    base = git(repo, "rev-parse", "HEAD")
    evidence = repo / "evidence-artifacts"
    evidence.mkdir()
    (evidence / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * 9000)

    result = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--evidence", "evidence-artifacts"]
    )

    assert result.exit_code == 0
    assert "evidence-empty" not in result.output

    missing = CliRunner().invoke(
        app, ["worker-verify", "--worktree", str(repo), "--base", base, "--evidence", "no-such-dir"]
    )

    assert missing.exit_code == 0
    assert "WARN  [evidence-empty]" in missing.output


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


def test_watch_rejects_an_unresolvable_base_in_plain_git_mode(tmp_path):
    repo = committed_repo(tmp_path / "plain-bad-base")
    head = git(repo, "rev-parse", "HEAD")

    result = CliRunner().invoke(
        app, ["watch", "--worktree", str(repo), "--base", "deadbeef", "--once", "--log", str(tmp_path / "b.log")]
    )

    assert result.exit_code == 2
    assert "does not resolve" in result.output

    good = CliRunner().invoke(
        app, ["watch", "--worktree", str(repo), "--base", head, "--once", "--json",
              "--log", str(tmp_path / "g.log")]
    )

    assert good.exit_code == 0  # a resolvable base keeps the plain-git pass working
    assert json.loads(good.output)[0]["head"] == head


def test_watch_rejects_an_unresolvable_base_in_orca_mode(tmp_path, monkeypatch):
    repo = committed_repo(tmp_path / "orca-bad-base")
    monkeypatch.setattr(watch_mod, "list_workers",
                        lambda orca, run, names=None: [worker_row("fix-a", worktree=repo)])

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--workers", "fix-a", "--base", "deadbeef",
              "--once", "--log", str(tmp_path / "b.log")]
    )

    assert result.exit_code == 2
    assert "does not resolve" in result.output


def test_watch_accepts_a_resolvable_base_in_orca_mode(tmp_path, monkeypatch):
    repo = committed_repo(tmp_path / "orca-good-base")
    head = git(repo, "rev-parse", "HEAD")
    monkeypatch.setattr(watch_mod, "list_workers",
                        lambda orca, run, names=None: [worker_row("fix-a", worktree=repo)])
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head=head))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--workers", "fix-a", "--base", head,
              "--once", "--json", "--log", str(tmp_path / "good.log")]
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload[0]["head"] == head
    assert payload[0]["state"] == "working"


def test_watch_resolves_a_short_base_to_the_full_sha(tmp_path):
    repo = committed_repo(tmp_path / "short-base")
    head = git(repo, "rev-parse", "HEAD")
    payloads = []
    for base in (head, head[:7]):
        result = CliRunner().invoke(
            app, ["watch", "--worktree", str(repo), "--base", base, "--once", "--json",
                  "--log", str(tmp_path / "short.log")]
        )
        assert result.exit_code == 0
        payloads.append(json.loads(result.output)[0])

    full, short = ({k: v for k, v in payload.items() if k != "activity_ts"} for payload in payloads)
    assert short["head_moved"] is False  # the short SHA names the current HEAD: nothing moved
    assert short["state"] == "working"
    assert short == full  # a short base behaves exactly like the full one (activity stamps aside)


def test_watch_passes_the_full_base_to_the_quick_scan(tmp_path, monkeypatch):
    repo = committed_repo(tmp_path / "short-scan")
    head = git(repo, "rev-parse", "HEAD")
    seen = []
    monkeypatch.setattr(watch_mod, "verify_worker",
                        lambda worktree, **kwargs: seen.append(kwargs["base"]) or engine.VerifyResult())

    result = CliRunner().invoke(
        app, ["watch", "--worktree", str(repo), "--base", head[:7], "--once", "--log", str(tmp_path / "s.log")]
    )

    assert result.exit_code == 0
    assert seen == [head]


def test_watch_orca_first_commit_while_the_dispatch_is_active_is_working(tmp_path, monkeypatch):
    repo = committed_repo(tmp_path / "early-commit")
    base = git(repo, "rev-parse", "HEAD")
    monkeypatch.setattr(watch_mod, "list_workers",
                        lambda orca, run, names=None: [worker_row("fix-a", worktree=repo)])
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head="b" * 40, dirty=False))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--workers", "fix-a", "--base", base,
              "--once", "--json", "--log", str(tmp_path / "early.log")]
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)[0]
    assert payload["head_moved"] is True
    assert payload["state"] == "working"  # a commit is progress; only a settled dispatch is done


def test_watch_plain_git_needs_a_clean_head_held_for_two_passes(tmp_path, monkeypatch):
    repo = committed_repo(tmp_path / "plain-two-passes")
    base = git(repo, "rev-parse", "HEAD")
    probes = iter([
        WorktreeProbe(head="b" * 40, dirty=False, activity_ts=time.time()),  # first commit
        WorktreeProbe(head="b" * 40, dirty=True, activity_ts=time.time()),  # still editing
        WorktreeProbe(head="c" * 40, dirty=False, activity_ts=time.time()),  # second commit
        WorktreeProbe(head="c" * 40, dirty=False, activity_ts=time.time()),  # held still: done
    ])
    monkeypatch.setattr(watch_mod, "probe_worktree", lambda worktree, **kwargs: next(probes))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    monkeypatch.setattr(watch_mod.time, "sleep", lambda seconds: None)
    log = tmp_path / "two.log"

    result = CliRunner().invoke(
        app, ["watch", "--worktree", str(repo), "--base", base, "--interval-sec", "1", "--json", "--log", str(log)]
    )

    assert result.exit_code == 0
    assert json.loads(result.output)[0]["state"] == "done"
    states = [line.split("  ")[2] for line in log.read_text(encoding="utf-8").splitlines()]
    assert states == ["working", "working", "working", "done"]


def test_help_lists_both_new_commands():
    output = CliRunner().invoke(app, ["--help"]).output

    assert "watch" in output
    assert "worker-verify" in output


# --- guard watch: --once ------------------------------------------------------


def test_watch_once_json_reports_the_pass_and_writes_the_log(tmp_path, monkeypatch):
    now = time.time()
    rows = [
        worker_row("fix-a", terminal="term_1", observed_at=now),
        worker_row("test-b", terminal="term_2", settled=True, observed_at=now),
    ]
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run, names=None: list(rows))
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
        "name", "head", "head_moved", "dirty", "activity_ts", "heartbeat_ts", "settled", "quick_fails", "busy",
        "command", "deps_fails", "state", "actions",
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
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run, names=None: [worker_row("fix-a", terminal="term_1")])
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(dirty=False))
    monkeypatch.setattr(
        watch_mod, "verify_worker",
        lambda worktree, **kwargs: engine.VerifyResult(
            issues=[engine.VerifyIssue(engine.FAIL, "scope-outside-ownership", "edited outside its ownership: x.py")]
        ),
    )
    sent = record_nudges(monkeypatch)
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
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run, names=None: list(rows))
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe())
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--once", "--json", "--log", str(tmp_path / "s.log")]
    )

    assert result.exit_code == 0
    assert [row["name"] for row in json.loads(result.output)] == ["fix-a"]


def test_watch_logs_and_skips_a_row_without_a_worktree(tmp_path, monkeypatch):
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run, names=None: [worker_row("ghost", worktree=None)])
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe())
    log = tmp_path / "ghost.log"

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--once", "--json", "--log", str(log)]
    )

    assert result.exit_code == 0
    assert json.loads(result.output) == []
    assert "no worktree" in log.read_text(encoding="utf-8")


def test_watch_passes_the_requested_names_to_the_worker_list(tmp_path, monkeypatch):
    seen = []

    def fake_list(orca, run, names=None):
        seen.append(names)
        return [worker_row("fix-a"), worker_row("test-b", worktree=None)]

    monkeypatch.setattr(watch_mod, "list_workers", fake_list)
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe())
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    log = tmp_path / "names.log"

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--workers", "fix-a", "--test-workers", "test-b",
              "--once", "--json", "--log", str(log)]
    )

    assert result.exit_code == 0
    assert seen == [["fix-a", "test-b"]]
    assert "test-b  skipped  no worktree" in log.read_text(encoding="utf-8")


def test_watch_keeps_the_worker_list_unfiltered_when_only_test_workers_are_named(tmp_path, monkeypatch):
    seen = []

    def fake_list(orca, run, names=None):
        seen.append(names)
        return [worker_row("fix-a")]

    monkeypatch.setattr(watch_mod, "list_workers", fake_list)
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe())
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--test-workers", "test-b",
              "--once", "--json", "--log", str(tmp_path / "unfiltered.log")]
    )

    assert result.exit_code == 0
    assert seen == [None]  # no --workers: every unsettled row stays watched
    assert [row["name"] for row in json.loads(result.output)] == ["fix-a"]


def test_watch_logs_a_worktree_less_row_named_on_the_command_line(tmp_path, monkeypatch):
    def fake_list(orca, run, names=None):
        row = worker_row("ghost", worktree=None)
        return [row] if names and "ghost" in names else []

    monkeypatch.setattr(watch_mod, "list_workers", fake_list)
    log = tmp_path / "ghost-named.log"

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--workers", "ghost", "--once", "--json",
              "--log", str(log)]
    )

    assert result.exit_code == 0
    assert json.loads(result.output) == []
    assert "ghost  skipped  no worktree" in log.read_text(encoding="utf-8")


def test_watch_survives_a_failing_probe_and_quick_scan(tmp_path, monkeypatch):
    rows = [worker_row("bad-probe"), worker_row("bad-scan"), worker_row("good")]
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run, names=None: list(rows))

    def probe(worktree: Path, **kwargs):
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


def test_watch_json_stays_parseable_when_the_log_cannot_be_written(tmp_path, monkeypatch):
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run, names=None: [worker_row("fix-a")])
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe())
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    log_dir = tmp_path / "log-is-a-directory"
    log_dir.mkdir()

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--once", "--json", "--log", str(log_dir)]
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)[0]["name"] == "fix-a"  # the warning never lands on stdout
    assert "cannot write" in result.stderr
    assert "cannot write" not in result.stdout


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
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run, names=None: list(rows))
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
    # A row without a terminal has no agent to nudge: it is skipped before probing, logged once,
    # and it does not keep the run alive.
    repo = committed_repo(tmp_path / "no-terminal")
    base = git(repo, "rev-parse", "HEAD")
    probed = []
    monkeypatch.setattr(watch_mod, "list_workers",
                        lambda orca, run, names=None: [worker_row("fix-a", terminal=None, worktree=repo)])
    monkeypatch.setattr(watch_mod, "probe_worktree", lambda worktree, **kwargs: probed.append(worktree))
    monkeypatch.setattr(
        watch_mod, "verify_worker",
        lambda worktree, **kwargs: engine.VerifyResult(
            issues=[engine.VerifyIssue(engine.FAIL, "scope-outside-ownership", "edited outside its ownership: x.py")]
        ),
    )
    sent = record_nudges(monkeypatch)
    sleeps = []
    monkeypatch.setattr(watch_mod.time, "sleep", lambda seconds: sleeps.append(seconds))
    log = tmp_path / "loop.log"

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--base", base, "--interval-sec", "1",
              "--json", "--log", str(log)]
    )

    assert result.exit_code == 0
    assert sent == []
    assert probed == []
    assert sleeps == []
    assert json.loads(result.output) == []
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert "  fix-a  skipped  no terminal" in lines[0]


def test_watch_delivers_a_stalled_nudge_to_the_terminal(tmp_path, monkeypatch):
    from guard.core.watchdog import STALLED_TEXT

    repo = committed_repo(tmp_path / "stalled-nudge")
    base = git(repo, "rev-parse", "HEAD")
    heads = iter([base, "b" * 40])
    monkeypatch.setattr(watch_mod, "list_workers", settles_on_refresh("fix-a", terminal="term_1", worktree=repo))
    monkeypatch.setattr(watch_mod, "probe_worktree",
                        lambda worktree, **kwargs: WorktreeProbe(head=next(heads), dirty=False, activity_ts=100.0))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    sent = record_nudges(monkeypatch)
    monkeypatch.setattr(watch_mod.time, "sleep", lambda seconds: None)
    log = tmp_path / "stalled.log"

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--workers", "fix-a", "--base", base,
              "--stall-min", "1", "--interval-sec", "1", "--json", "--log", str(log)]
    )

    assert result.exit_code == 0
    assert sent == [("orca", "term_1", STALLED_TEXT.format(stall_min=1.0), True)]  # stalled always interrupts
    assert json.loads(result.output)[0]["state"] == "done"  # the second pass saw the commit and the settled dispatch
    assert "nudge skipped" not in log.read_text(encoding="utf-8")


def test_watch_treats_an_empty_terminal_as_no_terminal(tmp_path, monkeypatch):
    repo = committed_repo(tmp_path / "empty-terminal")
    base = git(repo, "rev-parse", "HEAD")
    probed = []
    monkeypatch.setattr(watch_mod, "list_workers",
                        lambda orca, run, names=None: [worker_row("fix-a", terminal="", worktree=repo)])
    monkeypatch.setattr(watch_mod, "probe_worktree", lambda worktree, **kwargs: probed.append(worktree))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    sent = record_nudges(monkeypatch)
    monkeypatch.setattr(watch_mod.time, "sleep", lambda seconds: None)
    log = tmp_path / "empty-terminal.log"

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--workers", "fix-a", "--base", base,
              "--stall-min", "1", "--interval-sec", "1", "--json", "--log", str(log)]
    )

    assert result.exit_code == 0
    assert sent == []
    assert probed == []
    assert json.loads(result.output) == []
    assert "  fix-a  skipped  no terminal" in log.read_text(encoding="utf-8")


def test_watch_final_summary_keeps_a_needs_human_line(tmp_path, monkeypatch):
    from guard.core.watchdog import SETTLED_DIRTY_TEXT

    heads = iter(["a" * 40, "b" * 40])

    def probe(worktree: Path, **kwargs) -> WorktreeProbe:
        if worktree.name == "test-a":
            return WorktreeProbe(head="a" * 40, dirty=True, activity_ts=time.time())
        return WorktreeProbe(head=next(heads), dirty=False, activity_ts=time.time())

    calls = []

    def rows(orca, run, names=None):
        calls.append(run)
        return [worker_row("test-a", terminal="term_2", settled=True), worker_row("fix-b", settled=len(calls) > 1)]

    monkeypatch.setattr(watch_mod, "list_workers", rows)
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
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1  # one log line per pass: the skip reason rides on the state line
    assert LOG_LINE_RE.match(lines[0])
    assert "  working  quick scan skipped: no base or start head" in lines[0]


def test_watch_default_log_uses_the_first_worktree_name(tmp_path, monkeypatch):
    repo = committed_repo(tmp_path / "default-name")
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["watch", "--worktree", str(repo), "--once"])

    assert result.exit_code == 0
    assert (tmp_path / "guard-watch-default-name.log").is_file()


def test_watch_default_log_uses_the_run_id(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run, names=None: [worker_row("fix-a")])
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe())
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)

    result = CliRunner().invoke(app, ["watch", "--run", "run_7", "--orca", "orca", "--once"])

    assert result.exit_code == 0
    assert (tmp_path / "guard-watch-run_7.log").is_file()


def test_watch_table_prints_one_row_per_worker(tmp_path, monkeypatch):
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run, names=None: [worker_row("fix-a", observed_at=1000.0)])
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe())
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--once", "--log", str(tmp_path / "t.log")]
    )

    assert result.exit_code == 0
    assert "fix-a" in result.output
    assert "working" in result.output
    assert "bbbbbbb" in result.output  # the short head sha


# --- guard watch: screen supervision -------------------------------------------

SPIN = "\u280b"  # a braille spinner glyph
BASE = "a" * 40


def watcher(tmp_path, *rows, cfg=None, base=BASE, once=False, ownership_path=None, ownership=None):
    """A watcher over Orca rows, driven pass by pass with explicit clocks."""
    targets = {
        row.name: watch_mod._Target(name=row.name, worktree=row.worktree, role="fix", own=["**"], row=row)
        for row in rows
    }
    return watch_mod._Watcher(
        run_id="run_1", base=base, cfg=cfg or WatchConfig(), log_path=tmp_path / "w.log", orca="orca", once=once,
        targets=targets, ownership_path=ownership_path, ownership=ownership or {},
    )


def screens(monkeypatch, *frames):
    """read_screen answers the given frames in order, then repeats the last; returns the (orca, terminal) reads."""
    reads = []
    queue = list(frames)

    def read(orca, terminal, limit=25):
        reads.append((orca, terminal))
        return queue.pop(0) if len(queue) > 1 else queue[0]

    monkeypatch.setattr(watch_mod, "read_screen", read)
    return reads


def busy_screen(body: str = "Thinking about the bug") -> str:
    return f"{SPIN} 3m 12s  {body}\n"


def test_watch_once_reads_the_worker_screen(tmp_path, monkeypatch):
    reads = screens(monkeypatch, f"{SPIN} 2m\n{SPIN} $ pnpm test --watch\n")
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run, names=None: [worker_row("fix-a", terminal="term_7")])
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(dirty=True))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--once", "--json", "--log", str(tmp_path / "s.log")]
    )

    assert result.exit_code == 0
    assert reads == [("orca", "term_7")]
    record = json.loads(result.output)[0]
    assert record["busy"] is True
    assert record["command"] == "pnpm test --watch"


def test_watch_loop_min_option_reaches_the_monitor(tmp_path, monkeypatch):
    screens(monkeypatch, f"{SPIN} 2m\n{SPIN} $ node poll.js\n")
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run, names=None: [worker_row("fix-a")])
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(dirty=True))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    sent = record_nudges(monkeypatch)

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--loop-min", "0", "--once", "--json",
              "--log", str(tmp_path / "loop.log")]
    )

    assert result.exit_code == 0
    record = json.loads(result.output)[0]
    assert record["state"] == "looping"
    assert record["actions"][0]["interrupt"] is True
    assert sent == []  # --once never sends


def test_watch_frozen_busy_screen_gets_an_interrupting_stall_nudge(tmp_path, monkeypatch):
    from guard.core.watchdog import STALLED_TEXT

    t0 = 1_000_000.0
    row = worker_row("fix-a", observed_at=t0 + 480)  # a fresh heartbeat must not mask the frozen screen
    screens(monkeypatch, busy_screen(), f"{SPIN} 11m 20s  Thinking about the bug\n")  # only the timer moved
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head=BASE, dirty=True, activity_ts=t0 + 480))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    sent = record_nudges(monkeypatch)
    w = watcher(tmp_path, row)

    assert w.tick_pass(t0)[0].record["state"] == "working"
    rows = w.tick_pass(t0 + 480)

    assert rows[0].record["state"] == "stalled"
    assert sent == [("orca", "term_1", STALLED_TEXT.format(stall_min=8.0), True)]  # no dev server: nothing stopped


def test_watch_stops_the_dev_server_before_the_stall_nudge(tmp_path, monkeypatch):
    t0 = 1_000_000.0
    events = []
    screen = f"{SPIN} 9m  Bash\n$ pnpm dev\n  VITE v5.0.0  ready in 312 ms\n  Local:   http://localhost:5173/\n"
    screens(monkeypatch, screen)
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head=BASE, dirty=True, activity_ts=t0))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)

    def stop(worktree):
        events.append(("stop", worktree))
        return ["4242: node C:/w/fix-a/node_modules/vite/bin/vite.js"]

    monkeypatch.setattr(watch_mod, "stop_dev_servers", stop)
    monkeypatch.setattr(watch_mod, "send_nudge",
                        lambda orca, terminal, text, *, interrupt=False: events.append(("nudge", interrupt)))
    row = worker_row("fix-a")
    w = watcher(tmp_path, row)

    w.tick_pass(t0)
    assert events == []  # dev-server output alone is no reason to stop anything
    w.tick_pass(t0 + 480)

    assert events == [("stop", row.worktree), ("nudge", True)]
    assert "  fix-a  dev-server-stopped  4242: node C:/w/fix-a/node_modules/vite/bin/vite.js" in (
        tmp_path / "w.log").read_text(encoding="utf-8")


def test_watch_once_never_stops_a_dev_server(tmp_path, monkeypatch):
    t0 = 1_000_000.0
    screens(monkeypatch, f"{SPIN} 9m\nwatching for file changes\n")
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head=BASE, dirty=True, activity_ts=t0))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    w = watcher(tmp_path, worker_row("fix-a"), once=True)

    w.tick_pass(t0)
    rows = w.tick_pass(t0 + 480)  # the autouse fake fails the test if a stop is attempted

    assert rows[0].record["state"] == "stalled"
    assert "nudge skipped: dry run (--once)" in rows[0].note


def test_watch_interrupts_a_looping_command(tmp_path, monkeypatch):
    from guard.core.watchdog import LOOPING_TEXT

    t0 = 1_000_000.0
    frames = [f"{SPIN} {n}m\n{SPIN} $ node retry.js\nattempt {n}\n" for n in (1, 6, 11)]
    screens(monkeypatch, *frames)  # the output changes every pass, so the stall check never fires
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head=BASE, dirty=True, activity_ts=t0))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    sent = record_nudges(monkeypatch)
    w = watcher(tmp_path, worker_row("fix-a"))

    w.tick_pass(t0)
    w.tick_pass(t0 + 300)
    rows = w.tick_pass(t0 + 600)

    assert rows[0].record["state"] == "looping"
    assert sent == [("orca", "term_1", LOOPING_TEXT.format(loop_min=10.0, command="node retry.js"), True)]


def test_watch_idle_screen_nudge_is_not_an_interrupt(tmp_path, monkeypatch):
    from guard.core.watchdog import IDLE_TEXT

    t0 = 1_000_000.0
    screens(monkeypatch, "> \n  ? for shortcuts\n")
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head=BASE, dirty=True, activity_ts=t0))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    sent = record_nudges(monkeypatch)
    w = watcher(tmp_path, worker_row("fix-a", observed_at=t0))

    w.tick_pass(t0)
    w.tick_pass(t0 + 90)

    assert sent == [("orca", "term_1", IDLE_TEXT, False)]


def test_watch_keeps_watching_a_committed_but_busy_worker(tmp_path, monkeypatch):
    t0 = 1_000_000.0
    screens(monkeypatch, busy_screen("taking stills"), busy_screen("writing the report"), "> \n")
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head="c" * 40, dirty=False, activity_ts=t0))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    sent = record_nudges(monkeypatch)
    w = watcher(tmp_path, worker_row("fix-a"))

    assert w.tick_pass(t0)[0].record["state"] == "working"
    assert w.tick_pass(t0 + 90)[0].record["state"] == "working"
    assert w._finished("fix-a") is False
    w.targets["fix-a"].row = worker_row("fix-a", settled=True)  # the report is sent: the dispatch settles
    assert w.tick_pass(t0 + 180)[0].record["state"] == "done"
    assert sent == []


def test_watch_clean_commit_with_findings_is_a_reject_candidate(tmp_path, monkeypatch):
    from guard.core.watchdog import REJECT_TEXT

    finding = "weakened-skip-focus: tests/test_x.py adds pytest.skip"
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head="c" * 40, dirty=False))
    monkeypatch.setattr(
        watch_mod, "verify_worker",
        lambda worktree, **kwargs: engine.VerifyResult(
            issues=[engine.VerifyIssue(engine.FAIL, "weakened-skip-focus", "tests/test_x.py adds pytest.skip")]
        ),
    )
    sent = record_nudges(monkeypatch)
    w = watcher(tmp_path, worker_row("fix-a", settled=True))  # the worker finished: its dispatch settled
    log = tmp_path / "w.log"

    record = w.tick_pass(time.time())[0].record

    assert sent == []
    assert w.monitors["fix-a"].done is False
    assert record["state"] == "needs-human"
    assert record["actions"] == [
        {"kind": "needs-human", "reason": "reject-candidate", "text": REJECT_TEXT.format(findings=finding),
         "interrupt": False}
    ]
    log_text = log.read_text(encoding="utf-8")
    assert finding in log_text
    assert "  done  " not in log_text


def test_watch_rereads_the_ownership_file_every_pass(tmp_path, monkeypatch):
    t0 = 1_000_000.0
    path = tmp_path / "ownership.json"
    path.write_text(json.dumps({"fix-a": {"role": "fix", "own": ["src/**"]}}), encoding="utf-8")
    seen = []
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head=BASE, dirty=True, activity_ts=t0))
    monkeypatch.setattr(watch_mod, "verify_worker", lambda worktree, **kwargs: seen.append(kwargs["own"]) or engine.VerifyResult())
    w = watcher(tmp_path, worker_row("fix-a"), ownership_path=path, ownership={"fix-a": {"role": "fix", "own": ["src/**"]}})

    w.tick_pass(t0)
    path.write_text(json.dumps({"fix-a": {"role": "fix", "own": ["src/**", "docs/**"]}}), encoding="utf-8")
    w.tick_pass(t0 + 90)
    path.write_text('{"fix-a": {"role": "fix", "own": ["src/**"', encoding="utf-8")  # caught mid-write
    w.tick_pass(t0 + 180)

    assert seen == [["src/**"], ["src/**", "docs/**"], ["src/**", "docs/**"]]
    log_lines = (tmp_path / "w.log").read_text(encoding="utf-8").splitlines()
    warnings = [line for line in log_lines if "  ownership  warning  " in line]
    assert len(warnings) == 1
    assert "keeping the previous copy" in warnings[0]
    assert all(LOG_LINE_RE.match(line) for line in log_lines)


def test_watch_flags_broken_dependency_links_once(tmp_path, monkeypatch):
    from guard.core.watchdog import DEPS_TEXT

    t0 = 1_000_000.0
    mine = r"FAIL node_modules -> C:\w\fix-a\node_modules (a worker's worktree)"
    other = r"FAIL apps/api/node_modules -> C:\w\old-b\apps\api\node_modules"
    checked = []
    monkeypatch.setattr(watch_mod, "main_checkout_of", lambda worktree: checked.append(worktree) or Path("C:/repo"))
    monkeypatch.setattr(watch_mod, "check_main_checkout", lambda repo: [mine, other])
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head=BASE, dirty=True, activity_ts=t0))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    sent = record_nudges(monkeypatch)
    rows = [worker_row("fix-a", observed_at=t0), worker_row("fix-c", observed_at=t0)]
    w = watcher(tmp_path, *rows)

    first = w.tick_pass(t0)
    w.tick_pass(t0 + 30)

    assert checked == [Path("C:/w/fix-a"), Path("C:/w/fix-a")]  # the first watched worktree, every pass
    assert first[0].record["deps_fails"] == [mine]
    assert first[1].record["deps_fails"] == []
    assert sent == [("orca", "term_1", DEPS_TEXT.format(line=mine), True)]
    log_text = (tmp_path / "w.log").read_text(encoding="utf-8")
    assert log_text.count(f"  deps  deps-broken  {mine}") == 1
    assert log_text.count(f"  deps  deps-broken  {other}") == 1


def test_watch_survives_a_failing_dependency_check(tmp_path, monkeypatch):
    def broken(worktree):
        raise RuntimeError("git vanished")

    monkeypatch.setattr(watch_mod, "main_checkout_of", broken)
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head=BASE, dirty=True))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    w = watcher(tmp_path, worker_row("fix-a"))

    assert w.tick_pass(time.time())[0].record["state"] == "working"
    assert "  deps  warning  dependency check failed: git vanished" in (tmp_path / "w.log").read_text(encoding="utf-8")


@pytest.mark.parametrize("state", ["stopped", "abandoned", "released", "start_unknown", "starting"])
def test_watch_skips_rows_without_an_agent(tmp_path, monkeypatch, state):
    row = OrcaWorker(name="fix-a", worktree=Path("C:/w/fix-a"), terminal="term_1", worker_state=state,
                     stage_detail="", activity="", liveness="", observed_at=None, settled=False)
    probed = []
    monkeypatch.setattr(watch_mod, "probe_worktree", lambda worktree, **kwargs: probed.append(worktree))
    w = watcher(tmp_path, row)

    assert w.tick_pass(1_000_000.0) == []
    w.tick_pass(1_000_090.0)

    assert probed == []
    assert w.monitors == {}
    assert w._finished("fix-a") is (state != "starting")  # a starting worker may still come up
    lines = (tmp_path / "w.log").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1  # logged when the reason changes, not every pass
    assert f"  fix-a  skipped  {state}" in lines[0]


def test_watch_picks_up_a_worker_once_it_has_started(tmp_path, monkeypatch):
    starting = OrcaWorker(name="fix-a", worktree=Path("C:/w/fix-a"), terminal=None, worker_state="starting",
                          stage_detail="", activity="", liveness="", observed_at=None, settled=False)
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run, names=None: [worker_row("fix-a")])
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head=BASE, dirty=True))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    w = watcher(tmp_path, starting)

    assert w.tick_pass(1_000_000.0) == []
    w._refresh_rows()

    assert [row.record["state"] for row in w.tick_pass(1_000_090.0)] == ["working"]


def test_watch_treats_a_cancelled_named_worker_as_settled(tmp_path, monkeypatch):
    row = OrcaWorker(name="fix-a", worktree=Path("C:/w/fix-a"), terminal="term_1", worker_state="cancelled",
                     stage_detail="", activity="", liveness="", observed_at=None, settled=True)
    monkeypatch.setattr(watch_mod, "list_workers", lambda orca, run, names=None: [row])
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head=BASE, dirty=False))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)

    result = CliRunner().invoke(
        app, ["watch", "--run", "run_1", "--orca", "orca", "--workers", "fix-a", "--once", "--json",
              "--log", str(tmp_path / "c.log")]
    )

    assert result.exit_code == 0
    record = json.loads(result.output)[0]
    assert record["settled"] is True
    assert record["actions"][0]["reason"] == "settled-no-commit"


def test_watch_probes_with_the_first_seen_time(tmp_path, monkeypatch):
    t0 = 1_000_000.0
    since = []

    def probe(worktree, **kwargs):
        since.append(kwargs.get("since"))
        return WorktreeProbe(head=BASE, dirty=False, activity_ts=None)

    monkeypatch.setattr(watch_mod, "probe_worktree", probe)
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    w = watcher(tmp_path, worker_row("fix-a"))

    w.tick_pass(t0)
    w.tick_pass(t0 + 90)

    assert since == [t0, t0]  # an old base commit never counts as the worker's activity


def test_watch_logs_the_nudge_limit(tmp_path, monkeypatch):
    from guard.core.watchdog import NUDGE_LIMIT_TEXT

    t0 = 1_000_000.0
    screens(monkeypatch, busy_screen())
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head=BASE, dirty=True, activity_ts=t0))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    sent = record_nudges(monkeypatch)
    w = watcher(tmp_path, worker_row("fix-a"), cfg=WatchConfig(max_nudges=0))

    w.tick_pass(t0)
    rows = w.tick_pass(t0 + 480)

    assert sent == []
    assert rows[0].record["state"] == "needs-human"
    assert f"  fix-a  needs-human  {NUDGE_LIMIT_TEXT.format(max_nudges=0)}" in (tmp_path / "w.log").read_text(
        encoding="utf-8")


def test_watch_background_job_past_loop_min_is_looping_at_once(tmp_path, monkeypatch):
    from guard.core.watchdog import LOOPING_TEXT

    t0 = 1_000_000.0
    job = "\u2514\u2500 \u27e8bash\u27e9 bg_1 python -m pytest tests/x.py -q\u2026 \u00b7 17m42s"
    screens(monkeypatch, f"{SPIN} 18m 2s  Waiting for background jobs\n  {job}\n")
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head=BASE, dirty=True, activity_ts=t0))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    sent = record_nudges(monkeypatch)
    w = watcher(tmp_path, worker_row("fix-a"))

    rows = w.tick_pass(t0)  # the first pass: the job's own clock says it hung long ago

    assert rows[0].record["state"] == "looping"
    assert rows[0].record["command"] == "python -m pytest tests/x.py -q"
    command = "python -m pytest tests/x.py -q"
    assert sent == [("orca", "term_1", LOOPING_TEXT.format(loop_min=10.0, command=command), True)]
    assert w.tick_pass(t0 + 90)[0].record["state"] == "working"  # the clock restarts after the nudge


def test_watch_young_background_job_is_not_looping(tmp_path, monkeypatch):
    t0 = 1_000_000.0
    job = "\u2514\u2500 \u27e8bash\u27e9 bg_1 pnpm build \u00b7 2m10s"
    screens(monkeypatch, f"{SPIN} 3m  Waiting\n  {job}\n")
    monkeypatch.setattr(watch_mod, "probe_worktree", fake_probe(head=BASE, dirty=True, activity_ts=t0))
    monkeypatch.setattr(watch_mod, "verify_worker", empty_verify)
    sent = record_nudges(monkeypatch)
    w = watcher(tmp_path, worker_row("fix-a"))

    assert w.tick_pass(t0)[0].record["state"] == "working"
    assert sent == []
