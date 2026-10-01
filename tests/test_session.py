"""
Unit tests for Session Manager.
"""

import pytest

from guard.core.invariant_eval import DomainType
from guard.core.session import (
    DomainContract,
    LockedInvariant,
    PostTaskRecord,
    SessionManager,
    SessionStatus,
)


@pytest.fixture
def temp_repo(tmp_path):
    repo = tmp_path / "target_project"
    repo.mkdir()
    return repo


def test_session_lifecycle(temp_repo):
    mgr = SessionManager(temp_repo)
    assert mgr.load_session() is None

    domain = DomainType.FRONTEND

    contracts = [
        DomainContract(category="UI_STATE", name="loading_spinner", description="Must show spinner on click"),
    ]
    invariants = [
        LockedInvariant(id="INV-01", description="Do not remove Escape key handler"),
    ]

    # 1. Start Pre-Session
    session = mgr.start_pre_session(
        prompt="Add sticky checkout button",
        domain=domain,
        expected_files=["src/Checkout.tsx"],
        contracts=contracts,
        invariants=invariants,
        non_regression_strategy="Isolate component in portal",
    )

    assert session.status == SessionStatus.AWAITING_POST
    assert session.pre is not None
    assert session.pre.expected_files == ["src/Checkout.tsx"]

    # Guard never creates or edits a .gitignore (outside Git there is nothing to keep clean)
    assert not (temp_repo / ".gitignore").exists()

    # 2. Complete Post-Session
    post_rec = PostTaskRecord(
        files_modified=["src/Checkout.tsx"],
        all_passed=True,
        muse_verdict="APPROVED",
        muse_score=9.5,
        muse_notes="Clean component styling and proper responsive handling.",
    )
    completed_session = mgr.complete_post_session(post_rec)

    assert completed_session.status == SessionStatus.COMPLETED
    assert completed_session.post is not None
    assert completed_session.post.muse_verdict == "APPROVED"

    # Reload from disk
    reloaded = mgr.load_session()
    assert reloaded is not None
    assert reloaded.session_id == session.session_id
    assert reloaded.status == SessionStatus.COMPLETED
    assert len(reloaded.pre.existing_contracts) == 1

    # 3. Clear session
    mgr.clear()
    assert mgr.load_session() is None


def test_session_parent_walk_up(tmp_path):
    workspace = tmp_path / "workspace"
    sub_repo = workspace / "services" / "api"
    sub_repo.mkdir(parents=True)

    ws_mgr = SessionManager(workspace)
    domain = DomainType.BACKEND
    ws_session = ws_mgr.start_pre_session(
        prompt="Workspace task across sub-repos",
        domain=domain,
        expected_files=["services/api/main.py"],
        contracts=[],
        invariants=[],
    )

    # Sub-repo SessionManager should discover the parent workspace session via walk-up
    sub_mgr = SessionManager(sub_repo)
    discovered = sub_mgr.load_session()
    assert discovered is not None
    assert discovered.session_id == ws_session.session_id
    assert discovered.pre.prompt == "Workspace task across sub-repos"

    ws_mgr.clear()


def test_session_records_repo_domain_and_sources(temp_repo):
    mgr = SessionManager(temp_repo)
    session = mgr.start_pre_session(
        prompt="Configure docker for backend",
        domain=DomainType.INFRA,
        repo_domain=DomainType.BACKEND,
        domain_source="LLM",
        domain_reason="Scoped Dockerfile configures container infra.",
        contracts_source="LLM",
        expected_files=["Dockerfile"],
        contracts=[],
        invariants=[],
    )
    assert session.pre.domain == DomainType.INFRA
    assert session.pre.repo_domain == DomainType.BACKEND
    assert session.pre.domain_source == "LLM"
    assert session.pre.domain_reason == "Scoped Dockerfile configures container infra."
    assert session.pre.contracts_source == "LLM"
    reloaded = mgr.load_session()
    assert reloaded.pre.domain == DomainType.INFRA
    assert reloaded.pre.repo_domain == DomainType.BACKEND
    assert reloaded.pre.domain_source == "LLM"
    assert reloaded.pre.domain_reason == "Scoped Dockerfile configures container infra."
    assert reloaded.pre.contracts_source == "LLM"
