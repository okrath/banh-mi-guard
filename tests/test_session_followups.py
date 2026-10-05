import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from guard.core.diff_inspector import GitDiffInspector
from guard.core.session import (
    ApprovalKeyError,
    DomainType,
    GuardSession,
    PostTaskRecord,
    PreTaskRecord,
    SessionManager,
    SessionStatus,
)
from guard.reporters.markdown import generate_post_task_markdown, generate_pre_task_markdown, snapshot_missing_reason
from guard.task_flow import _post_check_hook_and_session, execute_post_task, execute_pre_task


@pytest.fixture(autouse=True)
def isolate_guard_home(tmp_path, monkeypatch):
    """Ensure no test ever touches the real ~/.guard/approval.key."""
    gh = tmp_path / "fake_guard_home"
    gh.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("GUARD_HOME", str(gh))
    monkeypatch.setattr("guard.core.session.guard_home", lambda: gh)
    monkeypatch.setattr("guard.core.repo_setup.guard_home", lambda: gh)
    yield gh


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "a@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "A"], cwd=repo, check=True)
    (repo / "src").mkdir(parents=True, exist_ok=True)
    (repo / "src" / "chat.ts").write_text("export const a = 1;\n", encoding="utf-8")
    (repo / "src" / "other.ts").write_text("export const b = 1;\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)
    return repo


def test_baseline_snapshot_error_field_and_backward_compatibility(tmp_path):
    """Item 1: baseline_snapshot_error field on PreTaskRecord and old sessions loading."""
    # Field defaults to None
    rec_empty = PreTaskRecord(prompt="test", domain=DomainType.BACKEND)
    assert rec_empty.baseline_snapshot_error is None

    # Field accepts error message
    rec_err = PreTaskRecord(
        prompt="test",
        domain=DomainType.BACKEND,
        baseline_snapshot_error="git update-ref failed",
    )
    assert rec_err.baseline_snapshot_error == "git update-ref failed"
    assert snapshot_missing_reason(rec_err) == "git update-ref failed"

    # Backward compatibility: old session file without baseline_snapshot_error loads cleanly
    repo = _make_repo(tmp_path)
    old_session_dict = {
        "session_id": "guard-legacy-1",
        "status": "awaiting_post",
        "repo_path": str(repo),
        "pre": {
            "prompt": "Fix chat",
            "domain": "backend",
            "non_regression_strategy": "Isolate changes to domain BACKEND. Maintain 100% existing baseline contracts.",
            "baseline_dirty": {"src/other.ts": "abc123"},
        },
    }
    session_file = repo / ".guard" / "session.json"
    session_file.parent.mkdir(parents=True, exist_ok=True)
    session_file.write_text(json.dumps(old_session_dict), encoding="utf-8")

    mgr = SessionManager(repo)
    loaded = mgr.load_local_session()
    assert loaded is not None
    assert loaded.pre is not None
    assert loaded.pre.baseline_snapshot_error is None
    assert snapshot_missing_reason(loaded.pre) is None


def test_baseline_snapshot_failure_records_error_and_restores_clean_strategy(tmp_path):
    """Item 1: task_flow records baseline_snapshot_error directly; non_regression_strategy has no error marker."""
    repo = _make_repo(tmp_path)
    (repo / "src" / "other.ts").write_text("export const b = 99;\n", encoding="utf-8")

    # Simulate snapshot creation failure
    def fake_create_snapshot(self):
        self.last_error = "simulated git stash failure"
        return None

    with patch.object(GitDiffInspector, "create_baseline_snapshot", fake_create_snapshot):
        ok = execute_pre_task("Fix chat", repo_path=repo, allow_dirty=True)
        assert ok is True

    session = SessionManager(repo).load_local_session()
    assert session is not None
    assert session.pre is not None
    assert session.pre.baseline_snapshot is None
    assert session.pre.baseline_snapshot_error == "simulated git stash failure"
    # non_regression_strategy is restored to clean text without "Baseline snapshot missing: ..."
    assert "Baseline snapshot missing" not in session.pre.non_regression_strategy
    assert "Isolate changes to domain BACKEND" in session.pre.non_regression_strategy

    # Markdown reports include the error in both pre-task and post-task notes
    pre_md = generate_pre_task_markdown(session.pre)
    assert "Baseline snapshot missing (simulated git stash failure):" in pre_md

    post_rec = PostTaskRecord(
        all_passed=True,
        muse_verdict="APPROVED",
        files_modified=["src/chat.ts"],
    )
    post_md = generate_post_task_markdown(post_rec, session.pre)
    assert "Baseline snapshot missing (simulated git stash failure):" in post_md


def test_unwritable_guard_home_in_complete_post_session(tmp_path, capsys):
    """Item 2: Unwritable GUARD_HOME prints a one-line error, leaves session unapproved, and exits non-zero."""
    repo = _make_repo(tmp_path)
    assert execute_pre_task("Fix chat", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")

    # Simulate unwritable GUARD_HOME by making get_approval_key raise PermissionError
    with patch("guard.core.session.get_approval_key", side_effect=PermissionError("Permission denied: /fake/.guard/approval.key")):
        passed = execute_post_task(repo_path=repo)
        assert passed is False  # Exits non-zero

    captured = capsys.readouterr()
    # Output must have a one-line error about approval key cannot be created or written
    assert "Approval key" in captured.out
    assert "cannot be created or written" in captured.out
    # Must NOT have Python traceback
    assert "Traceback (most recent call last)" not in captured.err
    assert "Traceback (most recent call last)" not in captured.out

    # Session must be left unapproved
    mgr = SessionManager(repo)
    session = mgr.load_local_session()
    assert session is not None
    assert session.status != SessionStatus.COMPLETED
    assert session.status == SessionStatus.NEEDS_FIX
    assert session.post is not None
    assert session.post.approval_signature is None
    assert mgr.is_approval_verified(session) is False


def test_complete_post_session_direct_call_handles_unwritable_guard_home(tmp_path):
    """Item 2: Calling complete_post_session directly when key is unwritable saves session as unapproved."""
    repo = _make_repo(tmp_path)
    mgr = SessionManager(repo)
    mgr.start_pre_session(prompt="Fix chat", expected_files=["src/chat.ts"], contracts=[], invariants=[])

    post_rec = PostTaskRecord(
        all_passed=True,
        muse_verdict="APPROVED",
        approved_fingerprints={"src/chat.ts": "abc"},
    )

    with patch("guard.core.session.get_approval_key", side_effect=OSError("Read-only filesystem")):
        with pytest.raises(ApprovalKeyError, match="Read-only filesystem"):
            mgr.complete_post_session(post_rec)
    saved = mgr.load_local_session()
    assert saved is not None
    assert saved.status == SessionStatus.NEEDS_FIX
    assert saved.post is not None
    assert saved.post.approval_signature is None
    assert mgr.is_approval_verified(saved) is False


def test_unsigned_completed_session_empty_commit_hook_message(tmp_path, capsys):
    """Item 3: Unsigned COMPLETED session on empty commit reports unsigned/older version and to post again."""
    repo = _make_repo(tmp_path)
    (repo / ".guard").mkdir(parents=True, exist_ok=True)
    mgr = SessionManager(repo)

    # Legacy unsigned COMPLETED session
    legacy_session = GuardSession(
        session_id="guard-unsigned-legacy",
        repo_path=str(repo),
        status=SessionStatus.COMPLETED,
        pre=PreTaskRecord(prompt="Past task", domain=DomainType.BACKEND),
        post=PostTaskRecord(
            all_passed=True,
            muse_verdict="APPROVED",
            approved_fingerprints={"src/chat.ts": "hash1"},
            approval_signature=None,  # Unsigned!
        ),
    )
    mgr._save(legacy_session)

    # Working tree is clean (empty commit): no uncovered files
    capsys.readouterr()
    passed = execute_post_task(repo_path=repo, hook=True)
    assert passed is False

    captured = capsys.readouterr()
    out = captured.out
    normalized_out = " ".join(out.split())
    # Must NOT report "0 changed file(s) are not covered"
    assert "0 changed file(s)" not in out
    # Must explain the approval is unsigned or from an older version and guard post must run again
    assert "unsigned or from an older version" in normalized_out
    assert "guard post" in normalized_out
    assert "again" in normalized_out

    # Also directly verify _post_check_hook_and_session output
    capsys.readouterr()
    proceed, result, _ = _post_check_hook_and_session(repo, mgr, hook=True)
    assert proceed is False
    assert result is False
    direct_out = " ".join(capsys.readouterr().out.split())
    assert "0 changed file(s)" not in direct_out
    assert "unsigned or from an older version" in direct_out
    assert "guard post" in direct_out
