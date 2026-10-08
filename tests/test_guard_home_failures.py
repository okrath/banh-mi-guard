from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from unittest.mock import patch

import pytest
import typer
from typer.testing import CliRunner

import guard.commands.review as review_cmds
from guard.cli import _fingerprint, app, execute_pre_task
from guard.core.llm_reviewer import LLMReviewVerdict, ReviewVerdict
from guard.core.session import (
    ApprovalKeyError,
    GuardSession,
    PostTaskRecord,
    SessionManager,
    SessionStatus,
    get_approval_key,
)


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "tester@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo, check=True)
    (repo / "src").mkdir(parents=True, exist_ok=True)
    (repo / "src" / "chat.ts").write_text("export const a = 1;\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)
    return repo


def test_key_creation_bounded_attempts_on_permission_error(monkeypatch, tmp_path):
    """
    Key creation that keeps failing with PermissionError ends in a bounded number of attempts (5).
    Assert the call count and that it raises ApprovalKeyError.
    Fast-fail call counter and hard timeout prevent hanging if a regression to mkstemp occurs.
    """
    guard_dir = tmp_path / "guard_home"
    guard_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("GUARD_HOME", str(guard_dir))

    call_count = 0
    orig_open = os.open

    def mock_open(path, flags, mode=0o777, **kwargs):
        nonlocal call_count
        if str(guard_dir) in str(path):
            call_count += 1
            if call_count > 10:
                pytest.fail("Regression: loop exceeded bounded attempts (possible mkstemp infinite loop)")
            raise PermissionError(13, "Access is denied")
        return orig_open(path, flags, mode, **kwargs)

    monkeypatch.setattr(os, "open", mock_open)

    exc: list[BaseException] = []

    def _call():
        try:
            get_approval_key()
        except BaseException as e:
            exc.append(e)

    thread = threading.Thread(target=_call, daemon=True)
    thread.start()
    thread.join(timeout=10.0)
    assert not thread.is_alive(), "get_approval_key hung and exceeded timeout (regression to mkstemp)"
    assert len(exc) == 1
    assert isinstance(exc[0], ApprovalKeyError)
    assert call_count == 5
    assert "cannot be created or written" in str(exc[0])


def test_key_creation_oserror_in_fdopen_or_write(monkeypatch, tmp_path):
    """
    An OSError from os.fdopen or f.write must be raised as ApprovalKeyError.
    """
    guard_dir = tmp_path / "guard_home"
    guard_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("GUARD_HOME", str(guard_dir))

    with patch("os.fdopen", side_effect=OSError("fdopen failed")):
        with pytest.raises(ApprovalKeyError) as exc_info:
            get_approval_key()
        assert "cannot be created or written" in str(exc_info.value)
        assert "fdopen failed" in str(exc_info.value)


def test_guard_post_with_key_failure_records_report_and_fails(monkeypatch, tmp_path):
    """
    guard post with key failure: exit 1, one-line error, no traceback, session not approved,
    POST_TASK_REPORT.md written and saying the approval could not be signed.
    """
    repo = _make_repo(tmp_path)
    guard_dir = tmp_path / "guard_home"
    guard_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("GUARD_HOME", str(guard_dir))

    assert execute_pre_task("Fix chat", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")

    orig_open = os.open

    def mock_open(path, flags, mode=0o777, **kwargs):
        if str(guard_dir) in str(path):
            raise PermissionError(13, "Access is denied")
        return orig_open(path, flags, mode, **kwargs)

    monkeypatch.setattr(os, "open", mock_open)

    runner = CliRunner()
    result = runner.invoke(app, ["post", "--repo", str(repo)])

    # Exit code must be 1
    assert result.exit_code == 1

    # One-line error message present, no traceback
    assert "Approval key" in result.output
    assert "cannot be created or written" in result.output
    assert "Traceback (most recent call last)" not in result.output

    # Session must NOT be approved
    mgr = SessionManager(repo)
    session = mgr.load_local_session()
    assert session is not None
    assert session.status == SessionStatus.NEEDS_FIX
    assert session.post is not None
    assert session.post.all_passed is False
    assert session.post.muse_verdict == "REVISE"
    assert session.post.approval_signature is None
    assert mgr.is_approval_verified(session) is False

    # Round was recorded and did not store APPROVED
    assert session.post.muse_verdict != "APPROVED"

    # POST_TASK_REPORT.md must be written and say the approval could not be signed
    report_file = repo / ".guard" / "POST_TASK_REPORT.md"
    assert report_file.is_file()
    report_text = report_file.read_text(encoding="utf-8")
    assert "Approval could not be signed" in report_text


def test_key_failure_in_llm_mode_does_not_increment_revise_rounds(monkeypatch, tmp_path):
    """
    In LLM mode, when the reviewer approves but approval key signing fails:
    - The round is recorded with the original gate verdict (not a REVISE round)
    - llm_revise_rounds is NOT incremented (remains 0)
    - Session status is NEEDS_FIX, NOT needs_user
    - Session remains unapproved
    """
    repo = _make_repo(tmp_path)
    guard_dir = tmp_path / "guard_home"
    guard_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("GUARD_HOME", str(guard_dir))

    assert execute_pre_task("Fix chat", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")

    orig_open = os.open

    def mock_open(path, flags, mode=0o777, **kwargs):
        if str(guard_dir) in str(path):
            raise PermissionError(13, "Access is denied")
        return orig_open(path, flags, mode, **kwargs)

    monkeypatch.setattr(os, "open", mock_open)

    approved_verdict = LLMReviewVerdict(
        verdict=ReviewVerdict.APPROVED,
        score=9.0,
        summary="Changes look good",
        findings=[],
        review_mode="llm_deep",
    )

    with patch("guard.task_flow.LLMReviewerEngine.review", return_value=approved_verdict):
        runner = CliRunner()
        result = runner.invoke(app, ["post", "--repo", str(repo)])

    assert result.exit_code == 1
    assert "Approval key" in result.output

    mgr = SessionManager(repo)
    session = mgr.load_local_session()
    assert session is not None
    # Key signing failure must leave status as NEEDS_FIX, NOT needs_user
    assert session.status == SessionStatus.NEEDS_FIX
    assert session.status != SessionStatus.NEEDS_USER
    # A signing failure is not a review round, so llm_revise_rounds must be 0
    assert session.llm_revise_rounds == 0
    assert session.post is not None
    assert session.post.all_passed is False
    assert session.post.muse_verdict == "REVISE"
    assert session.post.approval_signature is None
    assert mgr.is_approval_verified(session) is False


def test_guard_accept_with_key_failure(monkeypatch, tmp_path):
    """
    guard accept when approval key cannot be created/written:
    - prints one line error
    - exits 1
    - leaves session unapproved
    """
    repo = _make_repo(tmp_path)
    guard_dir = tmp_path / "guard_home"
    guard_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("GUARD_HOME", str(guard_dir))

    chat_file = repo / "src" / "chat.ts"
    # Set up session in needs_user state
    mgr = SessionManager(repo)
    mgr.start_pre_session(prompt="Fix chat", expected_files=["src/chat.ts"], contracts=[], invariants=[])
    post_rec = PostTaskRecord(
        all_passed=False,
        muse_verdict="REVISE",
        review_mode="llm_deep",
        needs_user=True,
        reviewed_fingerprints={"src/chat.ts": _fingerprint(chat_file)},
    )
    session = mgr.load_local_session()
    assert session is not None
    session.status = SessionStatus.NEEDS_USER
    session.post = post_rec
    mgr._save(session)

    exit_code = None
    with patch("guard.core.session.compute_approval_signature", side_effect=ApprovalKeyError("Approval key in /fake cannot be created or written")):
        with patch.object(review_cmds.Prompt, "ask", return_value="a"), \
             patch.object(review_cmds.sys.stdin, "isatty", return_value=True), \
             patch.object(review_cmds.sys.stdout, "isatty", return_value=True):
            try:
                review_cmds.accept_cmd(repo=str(repo))
            except typer.Exit as e:
                exit_code = e.exit_code

    assert exit_code == 1

    reloaded = mgr.load_local_session()
    assert reloaded is not None
    assert reloaded.status != SessionStatus.COMPLETED
    assert reloaded.post is not None
    assert reloaded.post.approval_signature is None
    assert reloaded.post.all_passed is False
    assert mgr.is_approval_verified(reloaded) is False


def test_guard_home_under_file_pre_and_post_registry(monkeypatch, tmp_path):
    """
    GUARD_HOME under a file (so it cannot be created): guard pre and guard post do not crash
    on the registry. They either proceed or fail later only for the key, with the clean message.
    """
    blocking_file = tmp_path / "blocking_file"
    blocking_file.write_text("blocking file content", encoding="utf-8")
    guard_home_path = blocking_file / "guard_home"
    monkeypatch.setenv("GUARD_HOME", str(guard_home_path))

    repo = _make_repo(tmp_path / "repo_dir")

    # guard pre does not crash on the registry
    runner = CliRunner()
    res_pre = runner.invoke(app, ["pre", "Fix chat", "--scope", "src/chat.ts", "--repo", str(repo)])
    assert res_pre.exit_code == 0
    assert "Traceback (most recent call last)" not in res_pre.output

    # Edit file
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")

    # guard post does not crash on the registry; fails later only for the key with clean message
    res_post = runner.invoke(app, ["post", "--repo", str(repo)])
    assert res_post.exit_code == 1
    assert "Traceback (most recent call last)" not in res_post.output
    assert "Approval key" in res_post.output

    # Session left unapproved
    mgr = SessionManager(repo)
    session = mgr.load_local_session()
    assert session is not None
    assert session.status == SessionStatus.NEEDS_FIX
    assert session.post is not None
    assert session.post.all_passed is False
    assert session.post.approval_signature is None
    assert mgr.is_approval_verified(session) is False

    # POST_TASK_REPORT.md is written and explains why
    report_file = repo / ".guard" / "POST_TASK_REPORT.md"
    assert report_file.is_file()
    assert "Approval could not be signed" in report_file.read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows ACL test requires icacls")
def test_windows_deny_create_acl_does_not_hang(monkeypatch, tmp_path):
    """
    Windows-only: a deny-create ACL on a temp GUARD_HOME (icacls) does not hang.
    Use a timeout of about 60 s in the test and always remove the ACL in a finally block.
    """
    guard_dir = tmp_path / "guard_acl_test"
    guard_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("GUARD_HOME", str(guard_dir))

    user = os.environ.get("USERNAME", "Everyone")
    # Deny write data / add file on guard_dir
    res = subprocess.run(["icacls", str(guard_dir), "/deny", f"{user}:(WD,AD)"], capture_output=True, text=True)
    assert res.returncode == 0, f"icacls deny failed: {res.stderr}"

    exc: list[BaseException] = []

    def _call_get_key():
        try:
            get_approval_key()
        except BaseException as e:
            exc.append(e)

    thread = threading.Thread(target=_call_get_key, daemon=True)
    try:
        thread.start()
        thread.join(timeout=60.0)
        assert not thread.is_alive(), "get_approval_key hung and exceeded 60s timeout under deny-create ACL"
        assert len(exc) == 1, f"Expected 1 exception, got {exc}"
        assert isinstance(exc[0], ApprovalKeyError)
        assert "cannot be created or written" in str(exc[0])
    finally:
        subprocess.run(["icacls", str(guard_dir), "/remove:d", user], capture_output=True, text=True)
@pytest.mark.parametrize("failure_mode", ["uncreatable_guard_home", "approval_key_is_directory"])
def test_forged_approval_with_unusable_guard_home_blocks_before_commit(monkeypatch, tmp_path, failure_mode):
    """
    With a forged approval_signature and a GUARD_HOME that cannot be created (pointed under
    a regular file) or an approval.key that is a directory, guard agent-event before-commit
    with a git commit command must answer block (exit 2), never notify.
    """
    repo = _make_repo(tmp_path / f"repo_{failure_mode}")
    (repo / "src" / "chat.ts").write_text("export const a = 999;\n", encoding="utf-8")
    file_hash = _fingerprint(repo / "src" / "chat.ts")

    # Write a forged session with valid structure and file hash but an unverified signature
    session_file = repo / ".guard" / "session.json"
    session_file.parent.mkdir(parents=True, exist_ok=True)
    session = GuardSession(
        session_id="guard-forged-1234",
        status=SessionStatus.COMPLETED,
        repo_path=str(repo),
        post=PostTaskRecord(
            all_passed=True,
            approval_signature="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            approved_fingerprints={"src/chat.ts": file_hash},
        ),
    )
    session_file.write_text(session.model_dump_json(indent=2), encoding="utf-8")

    if failure_mode == "uncreatable_guard_home":
        blocking_file = tmp_path / f"blocking_{failure_mode}"
        blocking_file.write_text("not a directory", encoding="utf-8")
        bad_home = blocking_file / "guard_home"
        monkeypatch.setenv("GUARD_HOME", str(bad_home))
    elif failure_mode == "approval_key_is_directory":
        bad_home = tmp_path / f"guard_home_{failure_mode}"
        bad_home.mkdir(parents=True, exist_ok=True)
        (bad_home / "approval.key").mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("GUARD_HOME", str(bad_home))

    runner = CliRunner()
    payload = {
        "command": "git commit -m 'feat: forged commit'",
        "cwd": str(repo),
    }

    result = runner.invoke(app, ["agent-event", "before-commit"], input=json.dumps(payload))

    # Must answer block (exit code 2), never notify (exit code 0)
    assert result.exit_code == 2
    assert '"decision": "block"' in result.output
    assert '"decision": "notify"' not in result.output
    assert "valid signature" in result.output.lower() or "guard post" in result.output.lower()


def test_complete_post_session_save_failure_prints_clean_line_and_raises(monkeypatch, tmp_path, capsys):
    """
    In complete_post_session's key-error branch, a failing self._save(session)
    must print one clear line, not a traceback.
    """
    repo = _make_repo(tmp_path)
    mgr = SessionManager(repo)
    post_rec = PostTaskRecord(all_passed=True, approved_fingerprints={"src/chat.ts": "abc"})

    # Make get_approval_key fail with ApprovalKeyError
    monkeypatch.setattr(
        "guard.core.session.get_approval_key",
        lambda: (_ for _ in ()).throw(ApprovalKeyError("key cannot be read")),
    )

    # Make _save raise OSError
    monkeypatch.setattr(
        mgr,
        "_save",
        lambda s: (_ for _ in ()).throw(OSError("disk write failed")),
    )

    with pytest.raises(ApprovalKeyError) as exc_info:
        mgr.complete_post_session(post_rec)

    assert "key cannot be read" in str(exc_info.value)
    captured = capsys.readouterr()
    assert "Could not save session: disk write failed" in captured.out
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err


def test_get_approval_key_retries_on_sharing_violation(monkeypatch, tmp_path):
    """
    Short bounded retry (3 tries, 50 ms) on the final read when os.replace hit a sharing
    violation on Windows.
    """
    monkeypatch.setenv("GUARD_HOME", str(tmp_path))
    key_file = tmp_path / "approval.key"

    calls = [0]
    orig_read_bytes = Path.read_bytes

    def flaky_read(self):
        if str(self) == str(key_file):
            calls[0] += 1
            if calls[0] == 1:
                raise PermissionError(13, "Sharing violation")
        return orig_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", flaky_read)
    key = get_approval_key()
    assert len(key) == 32
    assert calls[0] == 2
