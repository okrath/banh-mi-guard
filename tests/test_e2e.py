"""
End-to-End Integration Tests for Banh-Mi-Guard.
Simulates real-world workflows across Frontend and Backend repositories:
1. UI Regression detection (removing Escape key handler) -> REVISE
2. Security & Out-of-Scope violation (hardcoded secret in undeclared file) -> REVISE
3. Clean Golden Task execution -> APPROVED (10/10)
4. Hook injection into external repo
"""

import subprocess
from pathlib import Path

from guard.cli import execute_post_task, execute_pre_task
from guard.core.session import SessionManager, SessionStatus
from guard.hooks.installer import HookInstaller


def init_git_repo(repo_dir: Path):
    """Helper to initialize a real git repo in tmp_path"""
    subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "guard@test.local"], cwd=str(repo_dir), check=True)
    subprocess.run(["git", "config", "user.name", "GuardTester"], cwd=str(repo_dir), check=True)


def test_e2e_frontend_regression_flow(tmp_path):
    repo = tmp_path / "frontend_app"
    repo.mkdir()
    init_git_repo(repo)

    # Initial codebase
    (repo / "package.json").write_text('{"name": "fe", "scripts": {"build": "node -e \\"process.exit(0)\\""}}', encoding="utf-8")
    src = repo / "src"
    src.mkdir()
    modal = src / "Modal.tsx"
    modal.write_text("""
    export function Modal({ onClose }) {
      useEffect(() => {
        window.addEventListener("keydown", (e) => { if (e.key === "Escape") onClose(); });
      }, []);
      return <div className="modal">Content</div>;
    }
    """, encoding="utf-8")

    # Initial commit
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=str(repo), check=True)

    # 1. Developer runs Pre-Task Guard
    pre_ok = execute_pre_task(
        prompt="Update CSS and responsive styling for Modal.tsx",
        repo_path=repo,
    )
    assert pre_ok is True

    mgr = SessionManager(repo)
    session = mgr.load_session()
    assert session is not None
    assert session.status == SessionStatus.AWAITING_POST

    # 2. Agent inadvertently deletes the Escape key handler!
    modal.write_text("""
    export function Modal({ onClose }) {
      // Regression: deleted Escape listener
      return <div className="modal sm:p-4">Content</div>;
    }
    """, encoding="utf-8")

    # 3. Developer runs Post-Task Guard
    post_ok = execute_post_task(repo_path=repo)

    # Guard MUST flag the regression and REVISE the code
    assert post_ok is False

    reloaded = mgr.load_session()
    assert reloaded.post is not None
    assert reloaded.post.muse_verdict == "REVISE"
    # No LLM is configured here: the keyword hint on the template invariant decides (an LLM would judge it)
    assert reloaded.post.review_mode == "heuristic"
    assert any("Escape" in c.description and c.status == "unverified" and c.notes.startswith("Keyword hint")
               for c in reloaded.post.invariant_result.checks)


def test_e2e_backend_security_and_scope_violation_flow(tmp_path):
    repo = tmp_path / "backend_service"
    repo.mkdir()
    init_git_repo(repo)

    # Initial codebase
    (repo / "go.mod").write_text("module service\ngo 1.22", encoding="utf-8")
    (repo / "main.go").write_text("package main\nfunc main() {}", encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=str(repo), check=True)

    # 1. Developer runs Pre-Task Guard for main.go
    pre_ok = execute_pre_task(
        prompt="Refactor main.go startup log",
        repo_path=repo,
    )
    assert pre_ok is True

    # 2. Agent touches an undeclared file AND leaves a secret!
    auth_file = repo / "auth_secret.go"
    auth_file.write_text("""package main
const JWT_SECRET = "sk_live_verysecret1234567890abcdef"
""", encoding="utf-8")

    # 3. Developer runs Post-Task Guard
    post_ok = execute_post_task(repo_path=repo)

    # Guard MUST catch out-of-scope file and the hardcoded secret
    assert post_ok is False
    mgr = SessionManager(repo)
    reloaded = mgr.load_session()
    assert reloaded.post.muse_verdict == "REVISE"
    assert "auth_secret.go" in reloaded.post.out_of_scope_files
    assert any(v.rule_id == "SEC-001" for v in reloaded.post.rule_violations)


def test_e2e_golden_clean_workflow(tmp_path):
    repo = tmp_path / "golden_project"
    repo.mkdir()
    init_git_repo(repo)

    (repo / "README.md").write_text("# Project\nInitial docs\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=str(repo), check=True)

    # 1. Pre-Task
    pre_ok = execute_pre_task(
        prompt="Update documentation in README.md",
        repo_path=repo,
    )
    assert pre_ok is True

    # 2. Make clean, comprehensive edits in declared scope
    (repo / "README.md").write_text("""# Project

Comprehensive user guide and documentation.

## Features
- Dual-Gate impact analysis & regression guard.
- Deterministic scope, invariant and build checks.
- Blast radius measurement via Alibaba Open Code Review (OCR).
- Final review and verification gate by configured LLM.

## Installation & Usage
Run `guard pre "<prompt>"` before editing code.
Run `guard post` after editing to verify compilation and invariants.
""", encoding="utf-8")

    # 3. Post-Task
    post_ok = execute_post_task(repo_path=repo)
    assert post_ok is True

    mgr = SessionManager(repo)
    reloaded = mgr.load_session()
    assert reloaded.post.muse_verdict == "APPROVED"
    assert reloaded.post.muse_score >= 8.0
    assert len(reloaded.post.out_of_scope_files) == 0


def test_e2e_hook_injection_on_foreign_repo(tmp_path):
    foreign_repo = tmp_path / "foreign_repo"
    foreign_repo.mkdir()
    init_git_repo(foreign_repo)

    # Install hook
    installer = HookInstaller(foreign_repo)
    success, msgs = installer.install(mode="all")
    assert success is True

    status = installer.get_status()
    assert status["pre_commit_installed"] is True
    assert status["prepare_commit_msg_installed"] is True
    assert status["agent_wrapper_installed"] is True
