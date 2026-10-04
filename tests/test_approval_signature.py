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
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from guard.agent.bash import content_hash

from guard.agent.events import (
    AgentEvent,
    _is_guard_path,
    _uncovered,
    decide,
    is_guard_command,
)
from guard.core.session import (
    DomainType,
    GuardSession,
    PostTaskRecord,
    PreTaskRecord,
    SessionManager,
    SessionStatus,
    compute_approval_signature,
    get_approval_key,
)
from guard.task_flow import _post_check_hook_and_session, execute_post_task, execute_pre_task


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
    assert mgr.is_approval_verified(session) is True

    verified = mgr.verified_approval(session)
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

    # Real forgery: modify a tracked file, write its correct content_hash into approved_fingerprints, keep old signature
    (repo / "src" / "chat.ts").write_text("export const a = 999;\n", encoding="utf-8")
    new_hash = content_hash(repo / "src" / "chat.ts")
    session_file = repo / ".guard" / "session.json"
    data = json.loads(session_file.read_text(encoding="utf-8"))
    data["post"]["approved_fingerprints"]["src/chat.ts"] = new_hash
    session_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    mgr = SessionManager(repo)
    session = mgr.load_local_session()
    assert session is not None
    assert mgr.is_approval_verified(session) is False
    assert mgr.verified_approval(session) == {}

    # Calling _save on tampered session does NOT mint a valid signature
    mgr._save(session)
    reloaded = mgr.load_local_session()
    assert mgr.is_approval_verified(reloaded) is False
    assert mgr.verified_approval(reloaded) == {}

    # Commit decision blocks
    blocked = decide(AgentEvent(event="before-commit", cwd=str(repo)))
    assert blocked.action == "block"
    assert "guard post" in blocked.reason.lower()

    commit = "git add -A && git commit -m 'forged'"
    assert _bash(repo, commit).action == "block"

    # Git pre-commit hook path refuses the forged approval
    assert execute_post_task(repo_path=repo, hook=True) is False


def test_hook_path_refuses_forged_approval(tmp_path, fake_ocr_review, capsys):
    repo = _make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo) is True

    # Genuine signed approval passes the git pre-commit hook path
    capsys.readouterr()
    assert execute_post_task(repo_path=repo, hook=True) is True
    out_pass = capsys.readouterr().out
    assert "changes match the last approved guard session" in out_pass

    # Forged approval: modified file + its correct hash, stale signature
    (repo / "src" / "chat.ts").write_text("export const a = 999;\n", encoding="utf-8")
    new_hash = content_hash(repo / "src" / "chat.ts")
    session_file = repo / ".guard" / "session.json"
    data = json.loads(session_file.read_text(encoding="utf-8"))
    data["post"]["approved_fingerprints"]["src/chat.ts"] = new_hash
    session_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # Hook path does NOT report "changes match the last approved session" and commit is refused
    capsys.readouterr()
    assert execute_post_task(repo_path=repo, hook=True) is False
    out_fail = capsys.readouterr().out
    assert "changes match the last approved guard session" not in out_fail
    assert "not covered by the last approved guard session" in out_fail

    # _post_check_hook_and_session directly verifies this behavior
    proceed, result, _ = _post_check_hook_and_session(repo, SessionManager(repo), hook=True)
    assert proceed is False and result is False


def test_session_without_signature_is_treated_as_not_approved(tmp_path):
    repo = _make_repo(tmp_path)
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    (repo / ".guard").mkdir(parents=True, exist_ok=True)
    mgr = SessionManager(repo)
    # Build an unsigned approved session (as older guard versions wrote)
    session = GuardSession(
        session_id="unsigned_test_session",
        repo_path=str(repo),
        status=SessionStatus.COMPLETED,
        pre=PreTaskRecord(
            prompt="Fix src/chat.ts",
            domain=DomainType.BACKEND,
            base_ref="HEAD",
        ),
        post=PostTaskRecord(
            all_passed=True,
            approved_fingerprints={"src/chat.ts": content_hash(repo / "src" / "chat.ts")},
            approval_signature=None,
        ),
    )
    mgr._save(session)

    loaded = mgr.load_local_session()
    assert loaded is not None
    assert mgr.is_approval_verified(loaded) is False
    assert mgr.verified_approval(loaded) == {}

    # Calling _save on unsigned loaded session does NOT mint a signature
    mgr._save(loaded)
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
    assert _is_guard_path(".guard/notes.txt") is True

    mgr = SessionManager(repo)
    session = mgr.load_local_session()
    # Without an approved session, modified files are uncovered
    (repo / "src" / "chat.ts").write_text("modified", encoding="utf-8")
    assert "src/chat.ts" in _uncovered(repo, session)

    # Test is_guard_command helper
    assert is_guard_command("guard post") is True
    assert is_guard_command("guard status > .guard/session.json") is False
    assert is_guard_command("python -c 'pass'") is False


def test_guard_accept_write_path_produces_verifiable_signature(tmp_path, fake_ocr_review, monkeypatch):
    import sys
    from guard.commands.review import accept_cmd, Prompt

    repo = _make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo) is True

    mgr = SessionManager(repo)
    session = mgr.load_local_session()
    assert session is not None

    # Set up session in NEEDS_USER state for guard accept
    session.status = SessionStatus.NEEDS_USER
    session.post.review_mode = "llm_deep"
    session.post.needs_user = True
    session.post.approval_signature = None
    session.post.all_passed = False
    session.post.accepted_by_user = False
    mgr._save(session)

    # Call the real guard accept command path (monkeypatch isatty and the prompt)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(Prompt, "ask", lambda *a, **k: "a")
    accept_cmd(repo=str(repo))

    reloaded = mgr.load_local_session()
    assert reloaded is not None
    assert reloaded.status == SessionStatus.COMPLETED
    assert reloaded.post.accepted_by_user is True
    assert reloaded.post.approval_signature is not None
    assert mgr.is_approval_verified(reloaded) is True
    assert mgr.verified_approval(reloaded) == session.post.reviewed_fingerprints
    assert decide(AgentEvent(event="before-commit", cwd=str(repo))).action == "allow"


def test_command_leak_and_init_py_reported(tmp_path):
    repo = _make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", scope=["src/chat.ts"], repo_path=repo) is True
    _bash(repo, "touch __init__.py", call_id="c1")
    (repo / "__init__.py").write_text("# root package\n", encoding="utf-8")
    after_ev = AgentEvent(event="after-bash", cwd=str(repo), tool="Bash", command="touch __init__.py", call_id="c1")
    dec = decide(after_ev)
    assert dec.action == "notify"
    assert "__init__.py" in dec.reason


def test_session_json_and_other_file_edits_both_reported_and_block_stop(tmp_path):
    repo = _make_repo(tmp_path)
    (repo / "src" / "x").write_text("initial\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "src/x"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "add src/x"], check=True)

    (repo / ".guard").mkdir(parents=True, exist_ok=True)
    (repo / ".guard" / "session.json").write_text("{}", encoding="utf-8")
    _bash(repo, "echo foo > src/x && echo bar > .guard/session.json", call_id="c_both")
    (repo / "src" / "x").write_text("modified src/x\n", encoding="utf-8")
    (repo / ".guard" / "session.json").write_text('{"modified": true}', encoding="utf-8")

    after_dec = decide(AgentEvent(event="after-bash", cwd=str(repo), tool="Bash", call_id="c_both"))
    assert after_dec.action == "notify"
    assert ".guard/session.json" in after_dec.reason
    assert "src/x" in after_dec.reason

    stop_dec = decide(AgentEvent(event="stop", cwd=str(repo)))
    assert stop_dec.action == "block"
    assert "src/x" in stop_dec.reason


def test_unsigned_completed_session_with_clean_tree_allows_stop_but_blocks_commit(tmp_path, fake_ocr_review):
    repo = _make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo) is True

    # Commit the changes while approved so the working tree is clean
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "complete task"], check=True)

    # Strip signature to simulate an old session
    mgr = SessionManager(repo)
    session = mgr.load_local_session()
    assert session is not None
    session.post.approval_signature = None
    session_file = repo / ".guard" / "session.json"
    session_file.write_text(session.model_dump_json(indent=2), encoding="utf-8")

    # Clean tree: stop is allowed
    stop_dec = decide(AgentEvent(event="stop", cwd=str(repo)))
    assert stop_dec.action == "allow"

    # Commit is blocked without signature
    commit_dec = decide(AgentEvent(event="before-commit", cwd=str(repo)))
    assert commit_dec.action == "block"
    assert "signature" in commit_dec.reason.lower() or "guard post" in commit_dec.reason.lower()

def test_signed_session_copied_to_another_repo_does_not_verify(tmp_path, fake_ocr_review):
    repo_a = _make_repo(tmp_path / "repo_a")
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo_a) is True
    (repo_a / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo_a) is True

    repo_b = _make_repo(tmp_path / "repo_b")
    (repo_b / ".guard").mkdir(parents=True, exist_ok=True)
    shutil.copy2(repo_a / ".guard" / "session.json", repo_b / ".guard" / "session.json")

    mgr_b = SessionManager(repo_b)
    session_b = mgr_b.load_local_session()
    assert session_b is not None
    # Stored repo_path is repo_a, but verification uses SessionManager(repo_b).repo_path
    assert mgr_b.is_approval_verified(session_b) is False
    assert mgr_b.verified_approval(session_b) == {}

    commit_dec = decide(AgentEvent(event="before-commit", cwd=str(repo_b)))
    assert commit_dec.action == "block"


@pytest.mark.parametrize(
    "cmd,expected",
    [
        # Windows paths and launchers that must count as guard commands
        (r"C:\Python311\python.exe -m guard post", True),
        (r'"C:\Program Files\Python311\python.exe" -m guard post', True),
        (r"C:\Users\x\Scripts\guard.exe post", True),
        ("cd sub && guard post", True),
        ('guard finding X --defer "run later"', True),
        ('guard pre "fix run tests" --scope a.py', True),
        ("python3.11 -m guard post", True),
        ("py -3 -m guard post", True),
        # Commands that must NOT count as guard commands
        ('guard run "x" -- python forge.py', False),
        ("python forge.py && guard post", False),
        ("echo guard post > x", False),
        ("python script.py -m guard", False),
        ("cd x>file", False),
        ("guard post>.guard/session.json", False),
        # Existing variants and edge cases
        ("guard pre 'Fix'", True),
        ("guard.exe pre 'Fix'", True),
        ("python -m guard pre 'Fix'", True),
        ("python3 -m guard pre 'Fix'", True),
        ("python3.11 -m guard pre 'Fix'", True),
        ("python3.12.exe -m guard pre 'Fix'", True),
        ("py -3 -m guard pre 'Fix'", True),
        ("py -3.11 -m guard pre 'Fix'", True),
        ("guard post", True),
        ("guard post --full", True),
        ("guard pre 'x' && echo done", True),
        ("guard pre 'x'; cat .guard/session.json", True),
        ("echo start | guard post", True),
        ("guard pre 'x' && echo 1 > .guard/session.json", False),
        ("guard status > .guard/session.json", False),
        ("guard run 'x' -- echo hi", False),
        ("python3.11 -m guard run 'x' -- echo hi", False),
        ('guard --repo X run "x"', False),
        ('python -m guard --repo X run "x"', False),
        ("guard --repo X post", True),
        ("python -m guard --repo X post", True),
        ("python -c 'pass'", False),
    ],
)
def test_guard_command_detection_table(cmd, expected):
    assert is_guard_command(cmd) is expected


def test_guard_command_detection_variants():
    assert is_guard_command("guard pre 'Fix'") is True
    assert is_guard_command("guard.exe pre 'Fix'") is True
    assert is_guard_command("python -m guard pre 'Fix'") is True
    assert is_guard_command("python3 -m guard pre 'Fix'") is True
    assert is_guard_command("python3.11 -m guard pre 'Fix'") is True
    assert is_guard_command("python3.12.exe -m guard pre 'Fix'") is True
    assert is_guard_command("py -3 -m guard pre 'Fix'") is True
    assert is_guard_command("py -3.11 -m guard pre 'Fix'") is True
    assert is_guard_command("guard post") is True
    assert is_guard_command("guard post --full") is True
    assert is_guard_command("guard pre 'x' && echo done") is True
    assert is_guard_command("guard pre 'x'; cat .guard/session.json") is True
    assert is_guard_command("echo start | guard post") is True
    assert is_guard_command("guard pre 'x' && echo 1 > .guard/session.json") is False
    assert is_guard_command("guard status > .guard/session.json") is False
    assert is_guard_command("guard run 'x' -- echo hi") is False
    assert is_guard_command("python3.11 -m guard run 'x' -- echo hi") is False
    assert is_guard_command("python -c 'pass'") is False


def test_save_oserror_in_finding_command(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from guard.cli import app

    repo = _make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    mgr = SessionManager(repo)
    session = mgr.load_local_session()
    assert session is not None
    session.findings_ledger = [{"id": "abc12345", "status": "open", "description": "issue"}]
    mgr._save(session)

    # Monkeypatch _save to simulate OSError (e.g. disk full or permission error)
    def failing_save(self, s):
        raise OSError("Permission denied: simulated disk failure")
    monkeypatch.setattr(SessionManager, "_save", failing_save)

    runner = CliRunner()
    result = runner.invoke(app, ["finding", "abc12345", "--defer", "will fix later", "--repo", str(repo)])
    assert result.exit_code == 1
    # One-line error message shown, not a traceback
    assert "Could not save session" in result.output
    assert "Traceback" not in result.output
