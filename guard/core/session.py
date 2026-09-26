"""
Session Manager for Banh-Mi-Guard.
Persists and transitions state between PRE-TASK and POST-TASK:
- Pre-task: intent, risk score, baseline contracts, locked invariants, target files
- Post-task: actual diff stats, out-of-scope files, build status, rule violations, Muse verdict
Stored at `<repo_root>/.guard/session.json`.
Automatically ensures `.guard/` is ignored in `.gitignore` or local `.git/info/exclude`.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from guard.core.invariant_eval import DomainType, InvariantResult
from guard.core.ocr_engine import DiffSummary, RuleViolation


class SessionStatus(str, Enum):
    IDLE = "idle"
    AWAITING_POST = "awaiting_post"
    COMPLETED = "completed"
    FAILED = "failed"
    NEEDS_FIX = "needs_fix"


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
    late_scope: List[str] = Field(default_factory=list)  # Scope added by a restart after edits began
    restarts: List[Dict[str, str]] = Field(default_factory=list)  # Superseded sessions: id, status, at


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
    learned_invariants: List[str] = Field(default_factory=list)  # ids the LLM added to guard.invariants.json
    rejected_invariant_proposals: List[str] = Field(default_factory=list)


class GuardSession(BaseModel):
    session_id: str
    status: SessionStatus = SessionStatus.IDLE
    repo_path: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    pre: Optional[PreTaskRecord] = None
    post: Optional[PostTaskRecord] = None


class SessionManager:
    """
    Manages `.guard/session.json` lifecycle.
    """

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
        import subprocess

        try:
            res = subprocess.run(["git", "-C", str(self.repo_path), "rev-parse", "--git-common-dir"],
                                 capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
        except OSError:
            return
        common = res.stdout.strip()
        if res.returncode != 0 or not common:
            return
        git_dir = Path(common) if Path(common).is_absolute() else self.repo_path / common
        exclude_file = git_dir / "info" / "exclude"
        try:
            exclude_file.parent.mkdir(parents=True, exist_ok=True)
            content = exclude_file.read_text(encoding="utf-8", errors="ignore") if exclude_file.exists() else ""
            lines = [line.strip() for line in content.splitlines()]
            if ".guard/" not in lines and ".guard" not in lines:
                new_content = content.rstrip() + ("\n" if content else "") + "\n# Banh-Mi-Guard local exclude\n.guard/\n"
                exclude_file.write_text(new_content, encoding="utf-8")
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
        except Exception:
            return None

    def load_session(self) -> Optional[GuardSession]:
        # 1. Local workspace session
        if self.session_file.is_file():
            try:
                with open(self.session_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return GuardSession.model_validate(data)
            except Exception:
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
                except Exception:
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
                            import os
                            if curr_rp == sess_rp or str(curr_rp).startswith(str(sess_rp) + os.sep):
                                return sess
        except Exception:
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
        baseline_dirty: Optional[Dict[str, str]] = None,
        baseline_invariant_status: Optional[Dict[str, str]] = None,
        base_ref: Optional[str] = None,
        late_scope: Optional[List[str]] = None,
        baseline_snapshot: Optional[str] = None,
        restarts: Optional[List[Dict[str, str]]] = None,
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
            baseline_dirty=baseline_dirty or {},
            baseline_invariant_status=baseline_invariant_status or {},
            base_ref=base_ref,
            late_scope=late_scope or [],
            baseline_snapshot=baseline_snapshot,
            restarts=restarts or [],
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
        archived = history / f"{session.session_id}.json"
        archived.write_text(session.model_dump_json(indent=2), encoding="utf-8")
        return archived

    def clear(self):
        if self.session_file.exists():
            try:
                self.session_file.unlink()
            except Exception:
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
                        import os
                        if curr_rp == g_rp or str(curr_rp).startswith(str(g_rp) + os.sep):
                            global_file.unlink(missing_ok=True)
                else:
                    global_file.unlink(missing_ok=True)
        except Exception:
            pass

    def _save(self, session: GuardSession):
        self.guard_dir.mkdir(parents=True, exist_ok=True)
        temp_file = self.session_file.with_suffix(".tmp")
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(session.model_dump_json(indent=2))
            temp_file.replace(self.session_file)
        except Exception:
            if temp_file.exists():
                temp_file.unlink(missing_ok=True)
        # Sync to global active session for cross-workspace/cross-repo discovery
        try:
            global_file = self._get_global_active_session_file()
            global_temp = global_file.with_suffix(".tmp")
            with open(global_temp, "w", encoding="utf-8") as f:
                f.write(session.model_dump_json(indent=2))
            global_temp.replace(global_file)
        except Exception:
            pass
