"""
Tests for approval signature integrity:
- HMAC-SHA256 signature on approved sessions
- Tamper detection on approved_fingerprints and missing signatures
- Blocking Edit/Write on .guard/ files while allowing Read
- Shell edits to .guard/session.json notify unless from a guard command
- Key creation, atomic write, reuse, and 0600 mode on POSIX
"""

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from guard.agent.events import (
    AgentEvent,
    _is_guard_path,
    _uncovered,
    decide,
    is_guard_command,
)
from guard.core.session import (
    SessionManager,
    SessionStatus,
    compute_approval_signature,
    get_approval_key,
)
from guard.task_flow import execute_post_task, execute_pre_task


@pytest.fixture(autouse=True)
def isolate_guard_home(tmp_path, monkeypatch):
    """Ensure no test ever reads or writes the real ~/.guard/approval.key."""
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


def _app_edit(repo: Path, path: str, tool: str = "Edit"):
    return decide(AgentEvent(event="before-edit", cwd=str(repo), tool=tool, file_paths=[str(repo / path)]))


def _bash(repo: Path, command: str, call_id: str = "c1"):
    return decide(AgentEvent(event="before-edit", cwd=str(repo), tool="Bash", command=command, call_id=call_id))


def _after_bash_ev(repo: Path, call_id: str = "c1"):
    return decide(AgentEvent(event="after-bash", cwd=str(repo), tool="Bash", call_id=call_id))


def test_saved_session_after_approval_verifies(tmp_path, fake_ocr_review):
    repo = _make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")

    assert execute_post_task(repo_path=repo) is True

    mgr = SessionManager(repo)
    session = mgr.load_local_session()
    assert session is not None
    assert session.status == SessionStatus.COMPLETED
    assert session.post is not None
    assert session.post.approval_signature is not None
    assert len(session.post.approval_signature) == 64  # SHA256 hex digest
    assert SessionManager.is_approval_verified(session) is True

    verified = SessionManager.verified_approval(session)
    assert verified == session.post.approved_fingerprints
    assert "src/chat.ts" in verified

    # Commit is allowed because approval verifies
    commit = "git add -A && git commit -m 'fix chat'"
    assert _bash(repo, commit).action == "allow"
    assert decide(AgentEvent(event="before-commit", cwd=str(repo))).action == "allow"


def test_tampered_fingerprints_returns_empty_and_blocks_commit(tmp_path, fake_ocr_review):
    repo = _make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo) is True

    # Tamper with approved_fingerprints in session.json
    session_file = repo / ".guard" / "session.json"
    data = json.loads(session_file.read_text(encoding="utf-8"))
    data["post"]["approved_fingerprints"]["src/chat.ts"] = "0000000000000000000000000000000000000000"
    session_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    session = SessionManager(repo).load_local_session()
    assert session is not None
    assert SessionManager.is_approval_verified(session) is False
    assert SessionManager.verified_approval(session) == {}

    # Calling _save on tampered session does NOT mint a valid signature
    SessionManager(repo)._save(session)
    reloaded = SessionManager(repo).load_local_session()
    assert SessionManager.is_approval_verified(reloaded) is False
    assert SessionManager.verified_approval(reloaded) == {}

    # Commit decision blocks
    blocked = decide(AgentEvent(event="before-commit", cwd=str(repo)))
    assert blocked.action == "block"
    assert "guard post" in blocked.reason.lower()

    commit = "git add -A && git commit -m 'forged'"
    assert _bash(repo, commit).action == "block"


def test_session_without_signature_is_treated_as_not_approved(tmp_path, fake_ocr_review):
    repo = _make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo) is True

    # Remove signature as an older version would have
    session_file = repo / ".guard" / "session.json"
    data = json.loads(session_file.read_text(encoding="utf-8"))
    data["post"]["approval_signature"] = None
    session_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    session = SessionManager(repo).load_local_session()
    assert session is not None
    assert SessionManager.is_approval_verified(session) is False
    assert SessionManager.verified_approval(session) == {}

    # Calling _save on unsigned loaded session does NOT mint a signature
    SessionManager(repo)._save(session)
    reloaded = SessionManager(repo).load_local_session()
    assert reloaded.post.approval_signature is None

    # Commit refusal must say to run guard post again
    blocked = decide(AgentEvent(event="before-commit", cwd=str(repo)))
    assert blocked.action == "block"
    assert "guard post" in blocked.reason.lower()
    assert "again" in blocked.reason.lower()


def test_edit_tool_on_guard_session_json_blocked_read_allowed(tmp_path):
    repo = _make_repo(tmp_path)
    # Target directly inside .guard
    assert _app_edit(repo, ".guard/session.json", tool="Edit").action == "block"
    assert "guard's state is written only by guard commands" in _app_edit(repo, ".guard/session.json", tool="Edit").reason

    assert _app_edit(repo, ".guard/session.json", tool="Write").action == "block"
    assert "guard's state is written only by guard commands" in _app_edit(repo, ".guard/session.json", tool="Write").reason

    # Reading is allowed
    assert _app_edit(repo, ".guard/session.json", tool="Read").action == "allow"
    assert _app_edit(repo, ".guard/session.json", tool="read").action == "allow"

    grep_ev = AgentEvent(
        event="before-edit",
        cwd=str(repo),
        tool="grep",
        file_paths=[str(repo / ".guard" / "session.json")],
    )
    assert decide(grep_ev).action == "allow"


def test_shell_command_modifying_session_json_notifies(tmp_path):
    repo = _make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True

    # 1. Non-guard command modifying session.json -> notify
    _bash(repo, "python -c \"open('.guard/session.json', 'w').write('{}')\"", call_id="cmd1")
    (repo / ".guard" / "session.json").write_text("{}", encoding="utf-8")
    decision = _after_bash_ev(repo, call_id="cmd1")
    assert decision.action == "notify"
    assert ".guard/session.json" in decision.reason

    # 2. Guard command modifying session.json -> no notify
    _bash(repo, "guard post", call_id="cmd2")
    (repo / ".guard" / "session.json").write_text('{"mock": 2}', encoding="utf-8")
    decision2 = _after_bash_ev(repo, call_id="cmd2")
    assert decision2.action != "notify"

    # 3. python -m guard post -> no notify
    _bash(repo, "python -m guard post", call_id="cmd3")
    (repo / ".guard" / "session.json").write_text('{"mock": 3}', encoding="utf-8")
    decision3 = _after_bash_ev(repo, call_id="cmd3")
    assert decision3.action != "notify"

    # 4. Quoted guard command -> no notify
    _bash(repo, 'guard pre "Fix A; then B" --scope src/chat.ts', call_id="cmd4")
    (repo / ".guard" / "session.json").write_text('{"mock": 4}', encoding="utf-8")
    decision4 = _after_bash_ev(repo, call_id="cmd4")
    assert decision4.action != "notify"

    # 5. Dangerous chained command modifying session.json -> notify
    _bash(repo, 'python forge.py; guard post', call_id="cmd5")
    (repo / ".guard" / "session.json").write_text('{"mock": 5}', encoding="utf-8")
    decision5 = _after_bash_ev(repo, call_id="cmd5")
    assert decision5.action == "notify"


def test_key_file_created_once_reused_and_mode_0600(tmp_path, monkeypatch):
    custom_home = tmp_path / "custom_guard_home"
    custom_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("GUARD_HOME", str(custom_home))
    monkeypatch.setattr("guard.core.session.guard_home", lambda: custom_home)
    monkeypatch.setattr("guard.core.repo_setup.guard_home", lambda: custom_home)

    key_file = custom_home / "approval.key"
    assert not key_file.exists()

    # First use: creates the key
    key1 = get_approval_key()
    assert len(key1) == 32
    assert key_file.is_file()

    # Mode 0600 on POSIX
    if os.name != "nt":
        mode = stat.S_IMODE(key_file.stat().st_mode)
        assert mode == 0o600, f"Expected 0600, got {oct(mode)}"

    # Second use: reuses existing key
    key2 = get_approval_key()
    assert key2 == key1

    # Atomic write did not leave temporary files
    leftover = [f.name for f in custom_home.iterdir() if f.name.endswith(".tmp") or f.name.startswith(".approval-key")]
    assert leftover == []


def test_guard_path_and_uncovered_logic(tmp_path):
    repo = _make_repo(tmp_path)
    assert _is_guard_path(".guard/session.json") is True
    assert _is_guard_path(".GUARD/session.json") is True  # case-insensitive check
    assert _is_guard_path("src/chat.ts") is False

    mgr = SessionManager(repo)
    session = mgr.load_local_session()
    # Without an approved session, modified files are uncovered
    (repo / "src" / "chat.ts").write_text("modified", encoding="utf-8")
    assert "src/chat.ts" in _uncovered(repo, session)

    # Test is_guard_command helper
    assert is_guard_command("guard post") is True
    assert is_guard_command("guard status > .guard/session.json") is False
    assert is_guard_command("python -c 'pass'") is False
