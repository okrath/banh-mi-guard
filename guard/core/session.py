"""
Session Manager for Banh-Mi-Guard.
Persists and transitions state between PRE-TASK and POST-TASK:
- Pre-task: intent, risk score, baseline contracts, locked invariants, target files
- Post-task: actual diff stats, out-of-scope files, build status, rule violations, Muse verdict
Stored at `<repo_root>/.guard/session.json`.
Automatically ensures `.guard/` is ignored in `.gitignore` or local `.git/info/exclude`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from guard.core.impact import ImpactRange
from guard.core.invariant_eval import DomainType, InvariantResult
from guard.core.ocr_engine import DiffSummary, RuleViolation
from guard.core.repo_setup import guard_home


class SessionStatus(str, Enum):
    IDLE = "idle"
    AWAITING_POST = "awaiting_post"
    COMPLETED = "completed"
    FAILED = "failed"
    NEEDS_FIX = "needs_fix"
    NEEDS_USER = "needs_user"  # the round budget is spent: only the user decides (guard accept)


class DomainContract(BaseModel):
    category: str  # "UI_STATE", "API_ENDPOINT", "INFRA_PORT", "MOBILE_PERMISSION", etc.
    name: str
    description: str
    must_preserve: bool = True


class LockedInvariant(BaseModel):
    id: str  # e.g., "INV-01"
    description: str
    rationale: str = ""
    source: str = "template"  # "project" (guard.invariants.json) or "template" (generic domain sample)
    checks: List[dict] = Field(default_factory=list)  # [{"files": glob, "forbid"|"require": regex}]


class PreTaskRecord(BaseModel):
    prompt: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    domain: DomainType
    repo_domain: Optional[DomainType] = None
    domain_source: str = ""
    domain_reason: str = ""
    contracts_source: str = ""
    expected_files: List[str] = Field(default_factory=list)
    existing_contracts: List[DomainContract] = Field(default_factory=list)
    locked_invariants: List[LockedInvariant] = Field(default_factory=list)
    non_regression_strategy: str = ""
    # Files already dirty when pre ran: path -> content sha1 ("<deleted>" if missing)
    baseline_dirty: Dict[str, str] = Field(default_factory=dict)
    baseline_invariant_status: Dict[str, str] = Field(default_factory=dict)
    base_ref: Optional[str] = None  # HEAD at the first pre; post diffs against it so mid-task commits stay visible
    # `git stash create` of the dirty tree at pre (--allow-dirty): diff against it = exactly the task's edits
    baseline_snapshot: Optional[str] = None
    baseline_snapshot_error: Optional[str] = None
    late_scope: List[str] = Field(default_factory=list)  # Scope added by a restart after edits began
    restarts: List[Dict[str, str]] = Field(default_factory=list)  # Superseded sessions: id, status, at
    # Recorded by the agent hook (guard agent-event): the user's own words, and files an agent
    # command changed before this pre ran
    user_prompt: Optional[str] = None
    pre_edit_changes: List[str] = Field(default_factory=list)
    # The agent session that ran this pre ({"agent", "session"}); None for a pre run by hand or by an
    # agent that sends no session id. Other agent sessions are then judged on their own work only
    owner: Optional[Dict[str, str]] = None
    # Symbols of the scoped files with their references, tests and invariants (None: a session from before it existed)
    impact: Optional[ImpactRange] = None


def describe_owner(owner: Dict[str, str]) -> str:
    """`claude-code session 1a2b3c4d`: the agent and a short session id, never its prompt."""
    session = str(owner.get("session", "")).split(":", 1)[-1]  # the key is `<agent>:<id>`
    return f"{owner.get('agent') or 'an agent'} session {session[:8]}"


class BuildCheckResult(BaseModel):
    command: str
    passed: bool
    exit_code: int
    output: str = ""
    duration_s: float


class PostTaskRecord(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    files_modified: List[str] = Field(default_factory=list)
    out_of_scope_files: List[str] = Field(default_factory=list)
    diff_summary: Optional[DiffSummary] = None
    build_check: Optional[BuildCheckResult] = None
    rule_violations: List[RuleViolation] = Field(default_factory=list)
    invariant_result: Optional[InvariantResult] = None
    all_passed: bool = False
    muse_verdict: str = "PENDING"  # "APPROVED" or "REVISE"
    muse_score: float = 0.0
    muse_notes: str = ""
    review_mode: str = "heuristic"  # "llm_deep" only when the configured LLM actually answered
    llm_error: Optional[str] = None
    scope_declared: bool = True
    preexisting_files: List[str] = Field(default_factory=list)
    deleted_files: List[str] = Field(default_factory=list)
    # Content fingerprints of every changed file when APPROVED: the approval covers exactly these
    approved_fingerprints: Dict[str, str] = Field(default_factory=dict)
    approval_signature: Optional[str] = None
    learned_invariants: List[str] = Field(default_factory=list)  # ids the LLM added to guard.invariants.json
    rejected_invariant_proposals: List[str] = Field(default_factory=list)
    ocr_status: str = ""  # "complete: N finding(s) ..." or "did not run: <reason>"
    ocr_complete: bool = False  # OCR reviewed the whole task and did not fail (what an agent commit requires)
    impact_summary: str = ""  # changed symbols compared with the expected impact range
    commit_mode: Optional[str] = None  # "auto" | "ask" | None (not chosen yet)
    findings: List[Dict] = Field(default_factory=list)  # this round's structured LLM findings
    followups: List[Dict] = Field(default_factory=list)  # findings approved without being fixed
    # Content of every file this post reviewed, whatever the verdict (what guard accept can approve)
    reviewed_fingerprints: Dict[str, str] = Field(default_factory=dict)
    accepted_by_user: bool = False  # approved by `guard accept`, not by the gate
    needs_user: bool = False  # this post used the last review round: the user decides next


class GuardSession(BaseModel):
    session_id: str
    status: SessionStatus = SessionStatus.IDLE
    repo_path: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    pre: Optional[PreTaskRecord] = None
    post: Optional[PostTaskRecord] = None
    # Across the posts of one task (kept by a --force restart): every finding raised with its status,
    # how many LLM reviews said REVISE, and how many are allowed before the user decides
    findings_ledger: List[Dict] = Field(default_factory=list)
    llm_rounds: int = 0
    llm_revise_rounds: int = 0
    revise_budget: int = 3

class ApprovalKeyError(RuntimeError):
    """Raised when the approval key cannot be read, created, or written."""


def get_approval_key() -> bytes:
    """
    Return the 32-byte approval key from ~/.guard/approval.key.
    Created on first use, written atomically, mode 0600 on POSIX.
    """
    key_dir = guard_home()
    key_file = key_dir / "approval.key"
    if key_file.is_file():
        data = key_file.read_bytes()
        if len(data) == 32:
            return data
    key_dir.mkdir(parents=True, exist_ok=True)
    new_key = secrets.token_bytes(32)
    fd, tmp = tempfile.mkstemp(dir=key_dir, prefix=".approval-key-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(new_key)
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        try:
            os.link(tmp, key_file)
        except (FileExistsError, OSError):
            try:
                if not key_file.is_file() or len(key_file.read_bytes()) != 32:
                    os.replace(tmp, key_file)
            except OSError:
                pass
    finally:
        Path(tmp).unlink(missing_ok=True)
    if key_file.is_file():
        data = key_file.read_bytes()
        if len(data) == 32:
            return data
    raise RuntimeError(f"Approval key file {key_file} is corrupt or invalid length")


def compute_approval_signature(repo_path: str | Path, session_id: str, approved_fingerprints: Dict[str, str]) -> str:
    """
    HMAC-SHA256 over canonical JSON of repo root path, session id, and approved_fingerprints.
    """
    key = get_approval_key()
    payload = {
        "approved_fingerprints": approved_fingerprints,
        "repo_path": str(Path(repo_path).resolve()),
        "session_id": str(session_id),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


class SessionManager:
    """
    Manages `.guard/session.json` lifecycle.
    """

    @staticmethod
    def _verify_session_signature(
        session: Optional[GuardSession], repo_path: str | Path
    ) -> bool:
        if not session or not session.post or not session.post.approval_signature:
            return False
        sig = session.post.approval_signature
        try:
            expected = compute_approval_signature(
                Path(repo_path).resolve(), session.session_id, session.post.approved_fingerprints
            )
            return hmac.compare_digest(sig, expected)
        except (OSError, RuntimeError, ValueError, TypeError):
            # A key that cannot be read or created means "not verified": the commit gate must
            # block, and an exception here would reach the hook boundary, which allows the action.
            return False

    def is_approval_verified(self, session: Optional[GuardSession]) -> bool:
        """
        True when the session has an approval signature that verifies against the HMAC key.
        Uses SessionManager.repo_path (resolved), never the repo_path stored in session.json.
        """
        return self._verify_session_signature(session, self.repo_path)

    def verified_approval(self, session: Optional[GuardSession]) -> Dict[str, str]:
        """
        Return approved_fingerprints if the session's approval signature verifies.
        Returns {} when the signature is missing, wrong, or invalid.
        """
        if session and session.post and self.is_approval_verified(session):
            return session.post.approved_fingerprints
        return {}

    def __init__(self, repo_path: Optional[Path] = None):
        self.repo_path = Path(repo_path or Path.cwd()).resolve()
        self.guard_dir = self.repo_path / ".guard"
        self.session_file = self.guard_dir / "session.json"

    def ensure_gitignore(self):
        """
        Keep `.guard/` out of Git through the repository's `info/exclude` (never a tracked
        `.gitignore`). Works in linked worktrees, where `.git` is a file. Outside Git there is
        nothing to keep clean, so nothing is written.
        """
        from guard.core.git_exclude import ensure_excluded

        try:
            ensure_excluded(self.repo_path, ".guard/", "# Banh-Mi-Guard local exclude", same=(".guard",))
        except OSError:
            pass

    def _get_global_active_session_file(self) -> Path:
        base = Path.home() / ".guard" / "sessions"
        base.mkdir(parents=True, exist_ok=True)
        return base / "active_session.json"

    def load_local_session(self) -> Optional[GuardSession]:
        """Session of this exact repo only (no parent walk-up or global fallback)."""
        if not self.session_file.is_file():
            return None
        try:
            return GuardSession.model_validate_json(self.session_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def load_session(self) -> Optional[GuardSession]:
        # 1. Local workspace session
        if self.session_file.is_file():
            try:
                with open(self.session_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return GuardSession.model_validate(data)
            except (OSError, ValueError):
                pass

        # 2. Parent directory walk-up (for monorepo sub-repos up to 4 levels)
        curr = self.repo_path.parent
        for _ in range(4):
            parent_session = curr / ".guard" / "session.json"
            if parent_session.is_file():
                try:
                    with open(parent_session, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        return GuardSession.model_validate(data)
                except (OSError, ValueError):
                    pass
            if curr.parent == curr:
                break
            curr = curr.parent

        # 3. Global active session fallback (~/.guard/sessions/active_session.json)
        # Only adopt if current directory is inside or identical to the session's workspace
        try:
            global_file = self._get_global_active_session_file()
            if global_file.is_file():
                with open(global_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    sess = GuardSession.model_validate(data)
                    if sess.repo_path:
                        sess_rp = Path(sess.repo_path).resolve()
                        curr_rp = self.repo_path.resolve()
                        try:
                            if curr_rp == sess_rp or curr_rp.is_relative_to(sess_rp):
                                return sess
                        except AttributeError:
                            if curr_rp == sess_rp or str(curr_rp).startswith(str(sess_rp) + os.sep):
                                return sess
        except (OSError, ValueError):
            pass
        return None

    def start_pre_session(
        self,
        prompt: str,
        expected_files: List[str],
        contracts: List[DomainContract],
        invariants: List[LockedInvariant],
        non_regression_strategy: str = "",
        domain: Optional[DomainType] = None,
        repo_domain: Optional[DomainType] = None,
        domain_source: str = "",
        domain_reason: str = "",
        contracts_source: str = "",
        baseline_dirty: Optional[Dict[str, str]] = None,
        baseline_invariant_status: Optional[Dict[str, str]] = None,
        base_ref: Optional[str] = None,
        late_scope: Optional[List[str]] = None,
        baseline_snapshot: Optional[str] = None,
        baseline_snapshot_error: Optional[str] = None,
        restarts: Optional[List[Dict[str, str]]] = None,
        user_prompt: Optional[str] = None,
        pre_edit_changes: Optional[List[str]] = None,
        impact: Optional[ImpactRange] = None,
        carry: Optional["GuardSession"] = None,
        owner: Optional[Dict[str, str]] = None,
    ) -> GuardSession:
        self.guard_dir.mkdir(parents=True, exist_ok=True)
        self.ensure_gitignore()
        previous = self.load_local_session()
        if previous:
            self._archive(previous)  # a new pre must not erase the record of the last decision

        session_id = f"guard-{int(time.time())}"
        pre_rec = PreTaskRecord(
            prompt=prompt,
            domain=domain or DomainType.BACKEND,
            repo_domain=repo_domain,
            domain_source=domain_source,
            domain_reason=domain_reason,
            contracts_source=contracts_source,
            baseline_dirty=baseline_dirty or {},
            baseline_invariant_status=baseline_invariant_status or {},
            base_ref=base_ref,
            late_scope=late_scope or [],
            baseline_snapshot=baseline_snapshot,
            baseline_snapshot_error=baseline_snapshot_error,
            restarts=restarts or [],
            user_prompt=user_prompt,
            owner=owner,
            pre_edit_changes=pre_edit_changes or [],
            impact=impact,
            expected_files=expected_files,
            existing_contracts=contracts,
            locked_invariants=invariants,
            non_regression_strategy=non_regression_strategy,
        )

        session = GuardSession(
            session_id=session_id,
            status=SessionStatus.AWAITING_POST,
            repo_path=str(self.repo_path),
            pre=pre_rec,
        )
        if carry is not None:  # a restart continues the same task: its findings and round count stay
            session.findings_ledger = list(carry.findings_ledger)
            session.llm_rounds, session.llm_revise_rounds = carry.llm_rounds, carry.llm_revise_rounds
            session.revise_budget = carry.revise_budget

        self._save(session)
        return session

    def complete_post_session(self, post_rec: PostTaskRecord) -> GuardSession:
        session = self.load_session()
        if not session:
            session = GuardSession(
                session_id=f"guard-{int(time.time())}",
                status=SessionStatus.COMPLETED if post_rec.all_passed else SessionStatus.NEEDS_FIX,
                repo_path=str(self.repo_path),
            )
        else:
            session.status = SessionStatus.COMPLETED if post_rec.all_passed else SessionStatus.NEEDS_FIX
            session.updated_at = datetime.now(timezone.utc).isoformat()

        # Sign upon successful post approval transition
        if post_rec.all_passed:
            try:
                post_rec.approval_signature = compute_approval_signature(
                    self.repo_path,
                    session.session_id,
                    post_rec.approved_fingerprints,
                )
            except (OSError, RuntimeError) as e:
                post_rec.approval_signature = None
                session.status = SessionStatus.NEEDS_FIX
                session.post = post_rec
                self._save(session)
                raise ApprovalKeyError(f"Approval key in {guard_home()} cannot be created or written: {e}") from e
        else:
            post_rec.approval_signature = None

        session.post = post_rec
        self._save(session)
        return session

    def archive_and_clear(self) -> Optional[Path]:
        """Move the current session to .guard/history/<session_id>.json, then clear it."""
        session = self.load_local_session()
        archived = self._archive(session) if session else None
        self.clear()
        return archived

    def _archive(self, session: GuardSession) -> Path:
        history = self.guard_dir / "history"
        history.mkdir(parents=True, exist_ok=True)
        content = session.model_dump_json(indent=2)
        n = 0
        while True:  # ids have 1 s resolution: never overwrite an earlier record, even under concurrent runs
            archived = history / (f"{session.session_id}.json" if n == 0 else f"{session.session_id}-{n}.json")
            try:
                with open(archived, "x", encoding="utf-8") as f:  # exclusive create reserves the name
                    f.write(content)
                return archived
            except FileExistsError:
                n += 1

    def clear(self):
        if self.session_file.exists():
            try:
                self.session_file.unlink()
            except OSError:
                pass
        try:
            global_file = self._get_global_active_session_file()
            if global_file.is_file():
                with open(global_file, "r", encoding="utf-8") as f:
                    g_data = json.load(f)
                g_repo = g_data.get("repo_path")
                if g_repo:
                    g_rp = Path(g_repo).resolve()
                    curr_rp = self.repo_path.resolve()
                    try:
                        if curr_rp == g_rp or curr_rp.is_relative_to(g_rp):
                            global_file.unlink(missing_ok=True)
                    except AttributeError:
                        if curr_rp == g_rp or str(curr_rp).startswith(str(g_rp) + os.sep):
                            global_file.unlink(missing_ok=True)
                else:
                    global_file.unlink(missing_ok=True)
        except (OSError, ValueError):
            pass

    def _save(self, session: GuardSession):
        # Keep an existing valid signature; if invalid or tampered, clear it!
        # Never mint a signature for an unapproved or loaded session here.
        if session and session.post:
            if session.post.approval_signature is not None and not self.is_approval_verified(session):
                session.post.approval_signature = None

        self.guard_dir.mkdir(parents=True, exist_ok=True)
        temp_file = self.session_file.with_suffix(".tmp")
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(session.model_dump_json(indent=2))
            temp_file.replace(self.session_file)
        except OSError:
            if temp_file.exists():
                temp_file.unlink(missing_ok=True)
            raise
        # Sync to global active session for cross-workspace/cross-repo discovery
        global_temp = None
        try:
            global_file = self._get_global_active_session_file()
            global_temp = global_file.with_suffix(".tmp")
            with open(global_temp, "w", encoding="utf-8") as f:
                f.write(session.model_dump_json(indent=2))
            global_temp.replace(global_file)
        except OSError:
            if global_temp is not None and global_temp.exists():
                global_temp.unlink(missing_ok=True)
