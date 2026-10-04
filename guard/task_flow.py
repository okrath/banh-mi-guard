"""
Task flow execution for Banh-Mi-Guard.
Runs guard pre and guard post pipelines.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

from guard.core.config import load_config, load_global_config
from guard.core.hygiene_engine import HygieneEngine
from guard.core.impact import check_impact, expected_impact
from guard.core.invariant_eval import DomainType, InvariantResult, evaluate_invariants
from guard.core.llm_reviewer import LLMReviewerEngine, ReviewVerdict
from guard.core.ocr_engine import DiffSummary, GitDiffInspector, OCRRulebookRunner, RuleViolation, run_ocr_review
from guard.core.project_invariants import (
    INVARIANTS_FILENAME,
    InvariantsFileError,
    append_learned_invariants,
    evaluate_checks,
    load_local_invariants,
    load_project_invariants,
    load_shared_invariants,
    removed_or_relaxed,
)
from guard.core.removal_check import check_removed_symbols
from guard.core.repo_setup import ensure_repo_setup
from guard.core.session import BuildCheckResult, PostTaskRecord, SessionManager, SessionStatus
from guard.core.simplicity_engine import SimplicityEngine
from guard.domains.detector import detect_build_command, extract_contracts_and_invariants
from guard.domains.pre_analysis import analyze_task
from guard.reporters.markdown import generate_post_task_markdown, generate_pre_task_markdown
from guard.reporters.terminal import render_post_task_terminal, render_pre_task_terminal

console = Console()
# The project's build and test command: a hung command must not hold the gate forever, but a
# test suite routinely takes longer than a minute
BUILD_TIMEOUT_S = 1800
AGENT_OCR_CONCURRENCY = 2  # each OCR request starts the agent CLI: a few at a time, not OCR's default of 8


def _fingerprint(path: Path) -> str:
    """Content hash used to tell whether a pre-existing dirty file was touched during the task."""
    if not path.is_file():
        return "<deleted>"
    return hashlib.sha1(path.read_bytes()).hexdigest()


def _file_at(repo: Path, ref: Optional[str], path: str) -> Optional[str]:
    """Content of `path` at commit `ref`, or None."""
    if not ref:
        return None
    res = subprocess.run(
        ["git", "-C", str(repo), "show", f"{ref}:{path}"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    return res.stdout if res.returncode == 0 else None


def _drop_diff_files(raw_diff: str, drop: set) -> str:
    """Remove the per-file chunks of `drop` paths from a unified diff."""
    if not drop:
        return raw_diff
    chunks = raw_diff.split("diff --git ")
    kept = [c for c in chunks[1:] if not any(c.startswith(f"a/{p} b/") for p in drop)]
    return (chunks[0] + "".join("diff --git " + c for c in kept)) if kept else ""


def _prompt_paths(prompt: str, repo: Path) -> List[str]:
    """Paths named in the prompt: existing files/dirs, or new `dir/file.ext` paths to be created."""
    # Globs are only accepted through --scope: prose like "do not edit *.css" must not widen scope.
    tokens = re.findall(r"[\w\-\.\/\\\[\]]+\.[a-zA-Z0-9]+|[\w\-\.]+[\/\\][\w\-\.\/\\\[\]]*", prompt)
    out = []
    for t in tokens:
        t = t.replace("\\", "/")
        if t.startswith("./"):
            t = t[2:]
        is_new_file_path = "/" in t and bool(re.search(r"\.[a-zA-Z0-9]+$", t))
        if t and ((repo / t).exists() or is_new_file_path):
            out.append(t)
    return sorted(set(out))


def _pre_check_session_and_owner(
    session_mgr: SessionManager, target_repo: Path, force: bool,
) -> Optional[Tuple[Optional[Any], Optional[dict]]]:
    """Validate prior session status, ownership, and restart permission; returns (superseded, owner) or None."""
    # A pre-task gate that can be re-run after editing would let scope be declared retroactively.
    # An unfinished (AWAITING_POST) or rejected (NEEDS_FIX) session can only be superseded with
    # --force, and the new session inherits its baseline, base commit and scope: a restart can
    # never turn the task's own edits into "pre-existing" baseline or widen the audited scope.
    previous = session_mgr.load_local_session()
    superseded = previous if (
        previous and previous.pre and previous.status in (
            SessionStatus.AWAITING_POST, SessionStatus.NEEDS_FIX, SessionStatus.NEEDS_USER)
    ) else None
    if superseded and superseded.status == SessionStatus.NEEDS_USER:
        # A restart would take back the decision the round budget handed to the user
        console.print(
            f"[bold red]❌ The guard session {superseded.session_id} is waiting for the user.[/bold red] "
            "Stop and ask the user to run [bold]guard accept[/bold] in their own terminal."
        )
        return None

    # The agent session that started this pre (a claim taken by the agent hook seconds ago); a restart
    # keeps the first pre's owner, and another agent session cannot take over a held working tree
    from guard.agent.events import fresh_claim, load_state
    from guard.core.session import describe_owner
    claim = fresh_claim(load_state(target_repo))
    held_by = superseded.pre.owner if superseded and isinstance(superseded.pre.owner, dict) else None
    if held_by and claim and claim["session"] != held_by.get("session"):
        console.print(
            f"[bold red]❌ This working tree is held by another agent's guard session[/bold red] "
            f"({escape(describe_owner(held_by))}, task: {escape(' '.join(superseded.pre.prompt.split())[:80])}).\n"
            "Do parallel work in a separate [bold]git worktree add[/bold], or wait until that task is committed. "
            "The user can release it with [bold]guard reset[/bold].")
        return None
    owner = held_by if superseded else claim
    if superseded and not force:
        state = {SessionStatus.AWAITING_POST: "unfinished", SessionStatus.NEEDS_USER: "waiting for the user (guard accept)"}.get(
            superseded.status, "rejected (REVISE)")
        console.print(
            f"[bold red]❌ The previous guard session {superseded.session_id} is {state}.[/bold red]\n"
            "Finish it with [bold]guard post[/bold]. [bold]guard pre --force[/bold] restarts it, keeping its baseline and scope; "
            "the restart is recorded and any scope added by it is reported as SCOPE-004."
        )
        return None

    return superseded, owner


def _pre_check_untracked(target_repo: Path, superseded: Optional[Any], invariants_existed: bool) -> bool:
    """Ensure all untracked paths have user decisions before starting the baseline."""
    # Untracked paths nobody decided about (agent folders such as plans/) cannot be snapshotted as a
    # baseline: the user says once whether each is part of the repository or always ignored. Checked
    # for a first pre and for a --force restart alike (a restart does not ask about its task's files).
    from guard.core.untracked import ASK_USER, RegistryError, printable, shown, undecided
    try:
        pending = [p for p in undecided(target_repo, skip_task_files=bool(superseded))
                   if invariants_existed or p != INVARIANTS_FILENAME]
    except (RuntimeError, RegistryError) as e:
        console.print("[bold red]❌ Guard could not check untracked paths:[/bold red]")
        console.print(printable(str(e)), markup=False)
        return False
    if pending:
        listing = "\n".join(f"  • {shown(p)}" for p in pending[:20])
        if len(pending) > 20:
            listing += f"\n  … and {len(pending) - 20} more (guard untracked lists them all)"
        console.print(f"[bold yellow]⚠️ Untracked path(s) without a decision:[/bold yellow]\n{listing}")
        console.print(ASK_USER, markup=False)
        return False
    return True


@dataclass
class _PreBaseline:
    baseline_dirty: Dict[str, str]
    base_ref: Optional[str]
    baseline_snapshot: Optional[str]
    candidate_files: List[str]
    late_scope: List[str]
    restarts: List[dict]
    impact: Optional[dict]


def _pre_scope_and_baseline(
    target_repo: Path, requested_scope: List[str], superseded: Optional[Any],
    allow_dirty: bool, invariants_existed: bool,
) -> Optional[_PreBaseline]:
    """Audit working tree cleanliness, capture baseline dirty state and candidate scope."""
    diff_inspector = GitDiffInspector(target_repo)
    if superseded:
        old = superseded.pre
        baseline_dirty = dict(old.baseline_dirty)
        base_ref = old.base_ref
        baseline_snapshot = old.baseline_snapshot  # never re-snapshot: that would absorb the task's edits
        candidate_files = list(old.expected_files)
        late_scope = sorted(set(old.late_scope) | (set(requested_scope) - set(old.expected_files)))
        restarts = old.restarts + [{
            "session_id": superseded.session_id,
            "status": superseded.status.value,
            "at": datetime.now(timezone.utc).isoformat(),
        }]
        # Expected impact of the scoped files; a restart keeps the first pre's (the task may have edited them since)
        impact = superseded.pre.impact
    else:
        working_files = diff_inspector.get_working_files()
        if not invariants_existed:
            # The file guard setup just created is not the user's pending work
            working_files = [f for f in working_files if f != INVARIANTS_FILENAME]
        if working_files and not allow_dirty:
            listing = "\n".join(f"  • {f}" for f in working_files[:20])
            more = f"\n  … and {len(working_files) - 20} more" if len(working_files) > 20 else ""
            console.print(
                f"[bold red]❌ Working tree already has {len(working_files)} modified file(s) before the task starts:[/bold red]\n{listing}{more}\n"
                "Pre-task must run BEFORE editing. Commit or stash them first. Only if they are unrelated work that must stay, "
                "pass [bold]--allow-dirty[/bold]: they are then reported as pre-existing and never vouched for."
            )
            return None
        baseline_dirty = {f: _fingerprint(target_repo / f) for f in working_files}
        base_ref = diff_inspector.get_head()
        baseline_snapshot = diff_inspector.create_baseline_snapshot() if working_files else None
        candidate_files, late_scope, restarts = requested_scope, [], []
        impact = expected_impact(target_repo, candidate_files, []) if candidate_files else None

    return _PreBaseline(
        baseline_dirty=baseline_dirty, base_ref=base_ref, baseline_snapshot=baseline_snapshot,
        candidate_files=candidate_files, late_scope=late_scope, restarts=restarts, impact=impact,
    )


@dataclass
class _PreAnalysis:
    task_domain: DomainType
    repo_domain: DomainType
    domain_source: str
    domain_reason: str
    contracts: list
    contracts_source: str


def _pre_analyze(
    target_repo: Path, prompt: str, candidate_files: List[str],
    impact: Optional[dict], config, superseded: Optional[Any],
) -> _PreAnalysis:
    """Analyze domain, reason, and baseline contracts with LLM or inheritance."""
    # A restart keeps the first pre's analysis: the task may have edited the scoped files since
    if superseded:
        old = superseded.pre
        return _PreAnalysis(
            task_domain=old.domain, repo_domain=getattr(old, "repo_domain", None) or old.domain,
            domain_source=getattr(old, "domain_source", ""), domain_reason=getattr(old, "domain_reason", ""),
            contracts=list(getattr(old, "existing_contracts", [])),
            contracts_source=getattr(old, "contracts_source", ""),
        )
    res = analyze_task(repo=target_repo, prompt=prompt, scope=candidate_files, impact=impact, config=config)
    return _PreAnalysis(
        task_domain=res.task_domain, repo_domain=res.repo_domain, domain_source=res.domain_source,
        domain_reason=res.reason, contracts=res.contracts, contracts_source=res.contracts_source,
    )


def _pre_lock_invariants(
    target_repo: Path, prompt: str, task_domain: DomainType,
    baseline: _PreBaseline, superseded: Optional[Any],
) -> Optional[Tuple[list, dict]]:
    """Extract and evaluate baseline invariants; updates baseline.impact in place when checked invariants exist."""
    # Template invariants follow task_domain
    try:
        _, invariants = extract_contracts_and_invariants(
            repo_path=target_repo, prompt=prompt, domain=task_domain, files=baseline.candidate_files,
        )
    except InvariantsFileError as e:
        console.print(f"[bold red]❌ {e}[/bold red]\nFix guard.invariants.json before starting the task.")
        return None
    baseline_eval = evaluate_invariants(
        invariants=[inv.model_dump() for inv in invariants], git_diff="", files_changed=[], repo_path=target_repo,
    )
    # Only real checks have a meaningful baseline; diff heuristics trivially "pass" on an empty diff
    checked = {inv.id for inv in invariants if inv.checks}
    baseline_status = {c.id: c.status for c in baseline_eval.checks if c.id in checked}
    if superseded:
        # A restart keeps the rules locked at the first pre: re-locking from a rulebook edited in the
        # meantime would let the task choose the rules it is judged by
        baseline_status = dict(superseded.pre.baseline_invariant_status)
        invariants = list(superseded.pre.locked_invariants)
    elif baseline.candidate_files and baseline.impact is not None and any(inv.checks for inv in invariants):
        # the first scan had no invariants to map onto the scoped files; only checked ones add anything
        baseline.impact = expected_impact(target_repo, baseline.candidate_files, [inv.model_dump() for inv in invariants])
    return invariants, baseline_status


def _pre_save_session(
    session_mgr: SessionManager, target_repo: Path, prompt: str, baseline: _PreBaseline,
    analysis: _PreAnalysis, invariants: list, baseline_status: dict,
    owner: Optional[dict], superseded: Optional[Any],
):
    """Save the pre-task session with agent state integration."""
    # What the agent hook recorded before this pre: the user's own prompt, files changed early
    from guard.agent.events import session_state, update_state

    def take(state):  # consumed by this pre: never reused for a later task
        if owner:  # this pre's claim is consumed; another session's claim stays for its own pre
            (state.get("claims") or {}).pop(owner["session"], None)
        own = session_state(state, owner["session"]) if owner else state  # the owner's prompt, not the last one typed
        taken = {k: own.pop(k, None) for k in ("user_prompt", "prompt_at", "pre_edit_changes")}  # in-flight "bash" stays
        return taken["user_prompt"], taken["pre_edit_changes"] or []

    recorded_prompt, recorded_changes = update_state(target_repo, take)
    user_prompt = recorded_prompt or (superseded.pre.user_prompt if superseded else None)  # a new prompt wins
    pre_edit_changes = sorted(set(recorded_changes) | set(superseded.pre.pre_edit_changes if superseded else []))

    session = session_mgr.start_pre_session(
        user_prompt=user_prompt, pre_edit_changes=pre_edit_changes, impact=baseline.impact,
        carry=superseded,  # a restart keeps the task's findings ledger and round count
        owner=owner, prompt=prompt, expected_files=baseline.candidate_files,
        contracts=analysis.contracts, invariants=invariants,
        non_regression_strategy=f"Isolate changes to domain {analysis.task_domain.value.upper()}. Maintain 100% existing baseline contracts.",
        domain=analysis.task_domain, repo_domain=analysis.repo_domain,
        domain_source=analysis.domain_source, domain_reason=analysis.domain_reason,
        contracts_source=analysis.contracts_source, baseline_dirty=baseline.baseline_dirty,
        baseline_invariant_status=baseline_status, base_ref=baseline.base_ref,
        late_scope=baseline.late_scope, baseline_snapshot=baseline.baseline_snapshot, restarts=baseline.restarts,
    )
    return session


def _pre_write_note(target_repo: Path, pre_record) -> None:
    """Render terminal summary and write PRE_TASK_NOTE.md."""
    render_pre_task_terminal(pre_record)
    md_content = generate_pre_task_markdown(pre_record)
    pre_note_path = target_repo / ".guard" / "PRE_TASK_NOTE.md"
    try:
        pre_note_path.write_text(md_content, encoding="utf-8")
        console.print(f"\n[dim]📄 Pre-Task Note written to: {pre_note_path}[/dim]")
    except Exception:
        pass


def execute_pre_task(
    prompt: str, repo_path: Optional[Path] = None, quick: bool = False,
    scope: Optional[List[str]] = None, allow_dirty: bool = False, force: bool = False,
) -> bool:
    """Entry point for guard pre."""
    target_repo = Path(repo_path or Path.cwd()).resolve()
    invariants_existed = (target_repo / INVARIANTS_FILENAME).exists()
    for msg in ensure_repo_setup(target_repo):
        console.print(f"[cyan]🔧 guard setup: {msg}[/cyan]")
    config = load_config(target_repo)
    session_mgr = SessionManager(target_repo)

    session_check = _pre_check_session_and_owner(session_mgr, target_repo, force)
    if session_check is None:
        return False
    superseded, owner = session_check

    requested_scope = sorted(
        {p.replace("\\", "/").rstrip("/") for p in _prompt_paths(prompt, target_repo) + list(scope or [])} - {""}
    )
    if not _pre_check_untracked(target_repo, superseded, invariants_existed):
        return False

    baseline = _pre_scope_and_baseline(target_repo, requested_scope, superseded, allow_dirty, invariants_existed)
    if baseline is None:
        return False

    analysis = _pre_analyze(target_repo, prompt, baseline.candidate_files, baseline.impact, config, superseded)

    locked = _pre_lock_invariants(target_repo, prompt, analysis.task_domain, baseline, superseded)
    if locked is None:
        return False
    invariants, baseline_status = locked

    session = _pre_save_session(
        session_mgr, target_repo, prompt, baseline, analysis, invariants, baseline_status, owner, superseded,
    )
    _pre_write_note(target_repo, session.pre)
    return True


def execute_post_task(
    repo_path: Optional[Path] = None, auto_fix: bool = False, focus: str = "all", hook: bool = False, full: bool = False,
) -> bool:
    """guard post, marked as running while it works (an agent waiting for it may stop its turn)."""
    from guard.agent.events import post_running
    target_repo = Path(repo_path or Path.cwd()).resolve()
    with post_running(target_repo):
        return _execute_post_task(target_repo, auto_fix=auto_fix, focus=focus, hook=hook, full=full)


def _post_check_hook_and_session(
    target_repo: Path, session_mgr: SessionManager, hook: bool,
) -> Tuple[bool, bool, Optional[Any]]:
    """Verify session existence, git hook skip conditions, and user wait states; returns (proceed, result, session)."""
    # In a git hook only this repo's own session counts; never adopt another repo's session.
    session = session_mgr.load_local_session() if hook else session_mgr.load_session()
    if hook and session is None:
        console.print("[dim]Banh-Mi-Guard: no guard session in this repository, skipping.[/dim]")
        return False, True, None
    if hook and session.status == SessionStatus.COMPLETED:
        # An approval covers only the exact file contents it approved, not later or unrelated work
        approved = session_mgr.verified_approval(session)
        uncovered = [
            f for f in GitDiffInspector(target_repo).get_working_files()
            if approved.get(f) != _fingerprint(target_repo / f)
        ]
        if not uncovered and session_mgr.is_approval_verified(session):
            console.print("[dim]Banh-Mi-Guard: changes match the last approved guard session, skipping.[/dim]")
            return False, True, None
        listing = "\n".join(f"  • {f}" for f in uncovered[:20])
        console.print(
            f"[bold red]❌ {len(uncovered)} changed file(s) are not covered by the last approved guard session "
            f"({session.session_id}):[/bold red]\n{listing}\n"
            "Run [bold]guard pre \"<task>\"[/bold] before editing and [bold]guard post[/bold] after, or "
            "[bold]guard reset[/bold] to stop guarding this work."
        )
        return False, False, None

    if session is not None and session.status == SessionStatus.NEEDS_USER:
        # Another round would take back the decision the round budget handed to the user
        console.print(
            f"[bold red]❌ Guard session {session.session_id} is waiting for the user.[/bold red] "
            "Stop and ask the user to run [bold]guard accept[/bold] in their own terminal."
        )
        return False, False, None

    return True, False, session


@dataclass
class _PostDiffScope:
    diff_summary: DiffSummary
    task_diff: str
    task_summary: DiffSummary
    scope_declared: bool
    preexisting_files: List[str]
    deleted_files: List[str]
    expected_files: List[str]
    baseline_dirty: Dict[str, str]
    snapshot: Optional[str]
    diff_inspector: GitDiffInspector


def _post_diff_and_scope_audit(target_repo: Path, pre: Optional[Any]) -> _PostDiffScope:
    """Inspect raw git diff against pre base_ref, separate preexisting changes, and build task diff."""
    # OCR diff & blast radius audit (no declared scope -> no scope verdict, instead of flagging every file)
    expected_files = pre.expected_files if pre else []
    scope_declared = bool(expected_files)
    baseline_dirty = pre.baseline_dirty if pre else {}

    diff_inspector = GitDiffInspector(target_repo)
    # Diff against the commit recorded at pre, so commits made mid-task are still audited
    raw_diff = diff_inspector.get_diff(base_ref=pre.base_ref if pre else None) or ""
    diff_summary = diff_inspector.parse_diff(raw_diff, expected_files=expected_files if scope_declared else None)

    # Files dirty before pre-task and untouched since are not attributed to this task.
    for f in diff_summary.files:
        if f.path in baseline_dirty and baseline_dirty[f.path] == _fingerprint(target_repo / f.path):
            f.preexisting = True
            f.is_out_of_scope = False
        elif f.path == INVARIANTS_FILENAME:
            # guard.invariants.json may grow outside the declared scope (guard writes learned rules into it);
            # removing or relaxing an existing rule is checked separately below and blocks.
            f.is_out_of_scope = False
    diff_summary.out_of_scope_files = [f.path for f in diff_summary.files if f.is_out_of_scope]
    preexisting_files = [f.path for f in diff_summary.files if f.preexisting]
    deleted_files = [f.path for f in diff_summary.files if f.status == "deleted" and not f.preexisting]

    # With a baseline snapshot, rules and the LLM see exactly the task's own edits; pre-existing
    # changes stay listed (and scope-audited) but are not reviewed as if the task wrote them.
    task_diff = raw_diff
    snapshot = pre.baseline_snapshot if pre else None
    if snapshot:
        task_diff = _drop_diff_files(diff_inspector.get_diff(base_ref=snapshot) or "", set(preexisting_files))
    task_summary = diff_inspector.parse_diff(task_diff)

    return _PostDiffScope(
        diff_summary=diff_summary, task_diff=task_diff, task_summary=task_summary,
        scope_declared=scope_declared, preexisting_files=preexisting_files,
        deleted_files=deleted_files, expected_files=expected_files,
        baseline_dirty=baseline_dirty, snapshot=snapshot, diff_inspector=diff_inspector,
    )


def _scan_scope_violations(diff_scope: _PostDiffScope, pre: Optional[Any]) -> List[RuleViolation]:
    """Scan diff for late scope, deleted file, and pre-existing modification violations."""
    rulebook = OCRRulebookRunner()
    violations = rulebook.scan_diff(diff_scope.task_diff)

    late_scope = pre.late_scope if pre else []
    for f in diff_scope.diff_summary.out_of_scope_files:
        if late_scope and diff_scope.diff_inspector._is_expected(f, late_scope):
            violations.append(RuleViolation(
                rule_id="SCOPE-004", severity="HIGH", file_path=f,
                message="Scope for this file was only declared by a `guard pre --force` restart after edits began.",
            ))
    for d in diff_scope.deleted_files:
        violations.append(RuleViolation(
            rule_id="SCOPE-002", severity="MEDIUM", file_path=d,
            message="File deleted. Confirm the task explicitly asked for this removal.",
        ))
    baseline_dirty, snapshot = diff_scope.baseline_dirty, diff_scope.snapshot
    if baseline_dirty:
        attributable = bool(snapshot)
        violations.append(RuleViolation(
            rule_id="SCOPE-003", severity="MEDIUM" if attributable else "HIGH",
            file_path=", ".join(sorted(baseline_dirty)[:10]) + (" …" if len(baseline_dirty) > 10 else ""),
            message=(
                f"{len(baseline_dirty)} file(s) were already modified before pre-task (--allow-dirty). "
                + ("Review covers only edits made after pre-task (diff vs baseline snapshot); the pre-existing changes are not vouched for."
                   if attributable else "Guard cannot attribute or vouch for those changes.")
            ),
        ))
    return violations


def _audit_invariants_rulebook(
    target_repo: Path, pre: Optional[Any], diff_scope: _PostDiffScope,
) -> Tuple[List[RuleViolation], Set[str], Dict[str, list]]:
    """Audit changes to INVARIANTS_FILENAME for retired, redefined, or weakened rules."""
    # Weakening the rulebook is never a side effect: a removed or relaxed invariant blocks
    rulebook_retired: Set[str] = set()
    rulebook_redefined: Dict[str, list] = {}
    violations: List[RuleViolation] = []
    if pre and any(f.path == INVARIANTS_FILENAME for f in diff_scope.diff_summary.files):
        base_text = _file_at(target_repo, pre.baseline_snapshot or pre.base_ref, INVARIANTS_FILENAME)
        if base_text:
            try:
                old_items = json.loads(base_text).get("invariants", [])
                new_items = load_shared_invariants(target_repo) or []
            except (ValueError, AttributeError, InvariantsFileError):
                old_items, new_items = [], []
            declared = diff_scope.scope_declared and diff_scope.diff_inspector._is_expected(
                INVARIANTS_FILENAME, diff_scope.expected_files
            )
            if declared:
                # An explicit, scoped rulebook edit: judge the locked rules by what the task decided
                new_by_id = {str(i["id"]): i for i in new_items}
                for old in old_items:
                    oid = str(old["id"])
                    if oid not in new_by_id:
                        rulebook_retired.add(oid)
                    elif (old.get("checks") or []) != (new_by_id[oid].get("checks") or []):
                        rulebook_redefined[oid] = new_by_id[oid].get("checks") or []
            for note in removed_or_relaxed(old_items, new_items):
                violations.append(RuleViolation(
                    rule_id="INV-WEAKENED",
                    # An explicitly scoped rulebook edit is reported to the reviewer; a silent one blocks
                    severity="MEDIUM" if declared else "CRITICAL",
                    file_path=INVARIANTS_FILENAME,
                    message=f"Invariant {note}. Removing or relaxing a project invariant needs an explicit task and review.",
                ))
    return violations, rulebook_retired, rulebook_redefined


@dataclass
class _PostRulesResult:
    violations: List[RuleViolation]
    evidence: List[str]
    impact_summary: Optional[str]
    rulebook_retired: Set[str]
    rulebook_redefined: Dict[str, list]


def _post_rules_and_hygiene(
    target_repo: Path, pre: Optional[Any], diff_scope: _PostDiffScope, focus: str,
) -> _PostRulesResult:
    """Run rulebook, symbol removals, blast radius impact, invariant edits, hygiene and simplicity."""
    violations = _scan_scope_violations(diff_scope, pre)
    # Removals a compiler cannot see (string keys, exports, CSS classes) checked over the whole repo
    removal_violations, removal_summary = check_removed_symbols(target_repo, diff_scope.task_diff)
    violations.extend(removal_violations)
    evidence = [removal_summary] if removal_summary else []

    # Changed symbols against the impact range pre expected (MEDIUM: reported, never blocking)
    impact_violations, impact_summary = check_impact(
        target_repo, diff_scope.task_diff, pre.impact if pre else None, diff_scope.expected_files,
    )
    violations.extend(impact_violations)
    if impact_summary:
        evidence.append(impact_summary)

    inv_violations, rulebook_retired, rulebook_redefined = _audit_invariants_rulebook(target_repo, pre, diff_scope)
    violations.extend(inv_violations)

    hygiene = HygieneEngine(target_repo)
    if (focus or "").lower() in ("dead-code", "hygiene"):
        touched = [f.path for f in diff_scope.diff_summary.files]
        hygiene_violations = hygiene.scan_focus_level(touched)
    else:
        hygiene_violations = hygiene.scan_diff_level(diff_scope.task_diff, diff_scope.task_summary)
    violations.extend(hygiene_violations)

    # dependency bloat is read from the diff, with or without --focus simplicity
    violations.extend(SimplicityEngine(target_repo).scan_diff_level(diff_scope.task_diff, diff_scope.task_summary))
    return _PostRulesResult(
        violations=violations, evidence=evidence, impact_summary=impact_summary,
        rulebook_retired=rulebook_retired, rulebook_redefined=rulebook_redefined,
    )


@dataclass
class _PostOcrResult:
    ocr_status: str
    with_ocr: bool
    pool: ThreadPoolExecutor
    build_future: Any
    violations: List[RuleViolation]


def _post_ocr(
    target_repo: Path, config, pre: Optional[Any], task_diff: str,
    preexisting_files: List[str], hook: bool, full: bool,
) -> _PostOcrResult:
    """Coordinate Alibaba OCR review and start the background build; returns OCR result with findings."""
    # Alibaba OCR (an LLM review that reads the repository) runs only for a full review (--full, never
    # in a Git hook); then OCR not running blocks like a HIGH finding. Without it the report says so.
    # The user can make it permanent: `guard config ocr always` (machine-wide) runs it on every post
    always = bool(load_global_config().ocr.always)
    full = full or always

    # The build (tests) runs in parallel with the reviews: with OCR it starts once OCR has taken its
    # snapshot (build output never enters the reviewed tree), without OCR it starts now
    pool = ThreadPoolExecutor(max_workers=1)
    build = {}

    def start_build() -> None:
        if "future" not in build:
            build["future"] = pool.submit(_run_build, target_repo)

    # The status always names the setting, so the user knows when OCR runs and how to change it
    setting = (
        "`guard config ocr always` is on: every guard post runs it" if always
        else "optional: guard post --full adds it; `guard config ocr always` runs it on every post"
    )
    ocr_status = f"not run in the Git hook ({setting})" if hook else f"not run ({setting})"
    ocr_violations: List[RuleViolation] = []
    if full and not hook and not task_diff.strip():
        ocr_status = f"skipped: no changes ({setting})"
    elif full and not hook:
        console.print(
            "[cyan]🔎 Alibaba OCR is reviewing the changes (no time limit; it ends when OCR finishes or reports an error, Ctrl+C stops it)...[/cyan]"
        )
        review = dict(
            base_ref=pre.base_ref if pre else None, background=pre.prompt if pre else "Post-task verification",
            skip_files=preexisting_files, binary=config.ocr.binary_path, concurrency=config.ocr.concurrency,
            on_snapshot=start_build, cache_key=_ocr_cache_key(config, pre),
        )
        if config.llm.protocol.value == "cli" and config.llm.cli_agent:
            ocr_status, found = _ocr_through_agent(target_repo, config, review)
        else:
            ocr_status, found = run_ocr_review(target_repo, **review)
        ocr_violations.extend(found)
        if ocr_status.startswith("did not run"):  # a failed review names the setting too
            ocr_status += f" ({setting})"

    with_ocr = full and not hook and bool(task_diff.strip())  # then the gate waits for OCR and the build
    start_build()  # no OCR (or it stopped before its snapshot): the build starts here

    return _PostOcrResult(
        ocr_status=ocr_status, with_ocr=with_ocr, pool=pool,
        build_future=build["future"], violations=ocr_violations,
    )


def _post_invariants(
    target_repo: Path, pre: Optional[Any], diff_scope: _PostDiffScope, rules_res: _PostRulesResult,
) -> Tuple[InvariantResult, List[RuleViolation]]:
    """Evaluate project and template invariants on current code; returns (eval_result, violations)."""
    # Invariants: project checks run on current files; template invariants only get diff heuristics
    invariants_dicts = [inv.model_dump() for inv in (pre.locked_invariants if pre else [])]
    inv_eval = evaluate_invariants(
        invariants=invariants_dicts, git_diff=diff_scope.task_diff,
        files_changed=[f.path for f in diff_scope.diff_summary.files], repo_path=target_repo,
    )
    baseline_status = pre.baseline_invariant_status if pre else {}
    for c in inv_eval.checks:
        if c.status == "failed" and baseline_status.get(c.id) == "failed":
            # Not a regression caused by this task: warn, do not block
            c.status = "baseline_failed"
            c.passed = True
            c.notes += " (already failing before this task)"
    for c in inv_eval.checks:
        if c.id in rules_res.rulebook_retired:
            c.status, c.passed = "retired", True
            c.notes = f"retired by this task's declared edit of {INVARIANTS_FILENAME} (reported as INV-WEAKENED for review)"
        elif c.id in rules_res.rulebook_redefined:
            status, note = evaluate_checks(target_repo, rules_res.rulebook_redefined[c.id])
            c.status, c.passed = status, status != "failed"
            c.notes = f"re-evaluated with the definition changed by this task: {note}"

    inv_violations: List[RuleViolation] = []
    if any(f.path == INVARIANTS_FILENAME for f in diff_scope.diff_summary.files):
        # A new or edited guard.invariants.json is not locked by this session, so self-check it on the
        # current tree: a rule that fails on the code it was written for is a broken rule.
        try:
            new_items = load_shared_invariants(target_repo) or []
        except InvariantsFileError as e:
            inv_violations.append(
                RuleViolation(rule_id="INV-FILE", severity="CRITICAL", file_path=INVARIANTS_FILENAME, message=str(e))
            )
        else:
            self_check = evaluate_invariants(
                invariants=[
                    {"id": i["id"], "description": i["description"], "checks": i.get("checks") or []}
                    for i in new_items
                ],
                git_diff="", files_changed=[], repo_path=target_repo,
            )
            for c in self_check.checks:
                c.id = f"{c.id} (new {INVARIANTS_FILENAME}, self-check)"
                inv_eval.checks.append(c)
            inv_eval.unverified_count += self_check.unverified_count
    inv_eval.all_passed = not any(c.status == "failed" for c in inv_eval.checks)
    return inv_eval, inv_violations


@dataclass
class _PostGateResult:
    review_verdict: Any
    build_res: Optional[BuildCheckResult]
    learned: List[str]
    rejected_props: List[dict]


def _record_learned_invariants(
    target_repo: Path, review_verdict, session_id: str,
) -> Tuple[List[str], List[dict]]:
    """Persist and format rules proposed by LLM review after verifying they pass on current code."""
    # Rules the reviewer discovered are written only after validation (new, and passing on this code),
    # before fingerprints are taken so the updated file is part of what was approved.
    learned, rejected_props = append_learned_invariants(
        target_repo, review_verdict.proposed_invariants, session_id,
    )
    # The report says what verified each added rule: how many of its checks pass on the current code
    # counted from the rules as written, not from the proposals (two proposals may share an id)
    check_counts = {str(i["id"]): len(i.get("checks") or []) for i in (load_local_invariants(target_repo) or [])} if learned else {}
    learned = [f"{i} ({check_counts.get(i, 0)} check(s) pass on the current code)" for i in learned]
    return learned, rejected_props


def _run_gate_review(gate, target_repo: Path, ocr_res: _PostOcrResult) -> Tuple[Any, Optional[BuildCheckResult]]:
    """Coordinate the gate review with parallel build execution."""
    if ocr_res.with_ocr:  # the gate sees OCR's findings and the build result
        build_res = ocr_res.build_future.result()
        review_verdict = gate(build_res, True, [])
    else:  # the LLM reviews while the build runs; a failing build still rejects on its own
        build_cmd = detect_build_command(target_repo)
        notes = [
            f"The build and tests ({build_cmd}) run in parallel with this review; guard rejects the change by "
            "itself if they fail, so do not raise findings about missing test evidence."
        ] if build_cmd else []
        review_verdict = gate(None, True, notes)
        build_res = ocr_res.build_future.result()
        if build_res is not None and not build_res.passed:
            # decided by the build, not by the LLM: the heuristic verdict (REVISE), and no LLM round counted
            llm_ran = review_verdict.review_mode == "llm_deep"
            review_verdict = gate(build_res, False, [])
            if llm_ran:
                review_verdict.summary += " The LLM review ran in parallel; the failing build decides, so it is not counted."
    ocr_res.pool.shutdown(wait=False)
    return review_verdict, build_res


def _post_llm_gate(
    target_repo: Path, config, session: Optional[Any], pre: Optional[Any],
    diff_scope: _PostDiffScope, rules_res: _PostRulesResult,
    inv_eval: InvariantResult, ocr_res: _PostOcrResult, focus: str,
) -> _PostGateResult:
    """Execute LLM reviewer gate, await build check, and record learned invariants."""
    reviewer = LLMReviewerEngine(config=config)
    domain = pre.domain if pre else DomainType.BACKEND
    prompt = pre.prompt if pre else "Post-task verification"
    if pre and pre.user_prompt and pre.user_prompt.strip() != pre.prompt.strip():
        # The agent wrote `prompt`; the hook recorded what the user actually asked
        prompt = f"{pre.prompt}\n\nThe user's own message before this pre (verbatim, recorded by the agent hook; judge the task against it): {pre.user_prompt}"

    def gate(build_res: Optional[BuildCheckResult], use_llm: bool, notes: List[str]):
        return reviewer.review(
            prompt=prompt, domain=domain,
            diff_summary=diff_scope.diff_summary.model_copy(update={"raw_diff": diff_scope.task_diff}),
            build_check=build_res, violations=rules_res.violations, invariant_result=inv_eval,
            contracts=pre.existing_contracts if pre else None, use_llm=use_llm, focus=focus,
            evidence=rules_res.evidence + notes, ledger=session.findings_ledger if session else [],
            known_rules=_known_rules(target_repo),
        )

    review_verdict, build_res = _run_gate_review(gate, target_repo, ocr_res)
    learned, rejected_props = _record_learned_invariants(
        target_repo, review_verdict, session.session_id if session else "unknown",
    )
    return _PostGateResult(
        review_verdict=review_verdict, build_res=build_res, learned=learned, rejected_props=rejected_props,
    )


def _post_record_and_report(
    target_repo: Path, session_mgr: SessionManager, session: Optional[Any], pre: Optional[Any],
    diff_scope: _PostDiffScope, rules_res: _PostRulesResult, inv_eval: InvariantResult,
    ocr_res: _PostOcrResult, gate_res: _PostGateResult,
) -> bool:
    """Save PostTaskRecord, record round, render terminal, and write markdown report."""
    review_verdict = gate_res.review_verdict
    all_passed = review_verdict.verdict == ReviewVerdict.APPROVED

    post_rec = PostTaskRecord(
        files_modified=[f.path for f in diff_scope.diff_summary.files],
        diff_summary=diff_scope.diff_summary,
        out_of_scope_files=diff_scope.diff_summary.out_of_scope_files,
        build_check=gate_res.build_res, rule_violations=rules_res.violations,
        invariant_result=inv_eval, all_passed=all_passed,
        muse_verdict=review_verdict.verdict.value, muse_score=review_verdict.score,
        muse_notes=review_verdict.summary, review_mode=review_verdict.review_mode,
        llm_error=review_verdict.llm_error, scope_declared=diff_scope.scope_declared,
        preexisting_files=diff_scope.preexisting_files, deleted_files=diff_scope.deleted_files,
        approved_fingerprints=(
            {p: _fingerprint(target_repo / p) for p in {f.path for f in diff_scope.diff_summary.files}}
            if all_passed else {}
        ),
        reviewed_fingerprints={p: _fingerprint(target_repo / p) for p in {f.path for f in diff_scope.diff_summary.files}},
        findings=[f.model_dump() for f in review_verdict.findings],
        learned_invariants=gate_res.learned, rejected_invariant_proposals=gate_res.rejected_props,
        ocr_status=ocr_res.ocr_status, impact_summary=rules_res.impact_summary,
        ocr_complete=ocr_res.ocr_status.startswith("complete") and not any(v.rule_id == "OCR-RUN" for v in rules_res.violations),
        commit_mode=load_global_config().commit_mode,  # machine-wide choice, whatever the local config says
    )

    session_mgr.complete_post_session(post_rec)
    post_rec.needs_user = _record_round(session_mgr, review_verdict, post_rec)

    render_post_task_terminal(post_rec, pre)
    _write_post_report(target_repo, post_rec, pre)

    if not all_passed and review_verdict.remediation_steps:
        console.print(Panel(
            "\n".join(f"  [bold red]•[/bold red] {s}" for s in review_verdict.remediation_steps),
            title="🔧 Actionable Remediation Checklist",
            border_style="red",
        ))

    return all_passed


def _execute_post_task(
    target_repo: Path, auto_fix: bool = False, focus: str = "all", hook: bool = False, full: bool = False,
) -> bool:
    for msg in ensure_repo_setup(target_repo, create_invariants=not hook):
        console.print(f"[cyan]🔧 guard setup: {msg}[/cyan]")
    config = load_config(target_repo)
    session_mgr = SessionManager(target_repo)

    proceed, result, session = _post_check_hook_and_session(target_repo, session_mgr, hook)
    if not proceed:
        return result
    pre = session.pre if session else None

    diff_scope = _post_diff_and_scope_audit(target_repo, pre)
    rules_res = _post_rules_and_hygiene(target_repo, pre, diff_scope, focus)
    ocr_res = _post_ocr(target_repo, config, pre, diff_scope.task_diff, diff_scope.preexisting_files, hook, full)
    rules_res.violations.extend(ocr_res.violations)
    rules_res.evidence.append(f"Alibaba OCR review: {ocr_res.ocr_status}")

    inv_eval, inv_violations = _post_invariants(target_repo, pre, diff_scope, rules_res)
    rules_res.violations.extend(inv_violations)
    if pre and pre.pre_edit_changes:
        rules_res.evidence.append(
            f"Files an agent command changed before guard pre ran: {', '.join(pre.pre_edit_changes)}"
        )

    # Build and tests: running in parallel (see start_build); waited for before the gate decides
    gate_res = _post_llm_gate(
        target_repo, config, session, pre, diff_scope, rules_res, inv_eval, ocr_res, focus,
    )
    return _post_record_and_report(
        target_repo, session_mgr, session, pre, diff_scope, rules_res, inv_eval, ocr_res, gate_res,
    )


def _ocr_through_agent(target_repo: Path, config, review: dict):
    """
    OCR answered by the agent CLI the LLM gate uses (`protocol: cli`), through a local endpoint that
    lives for this review only; the user's own OCR settings are never changed. The status names the
    agent and the path, and an agent failure is an OCR failure with the agent's reason. When that
    does not run, guard warns and falls back to OCR's delegation mode answered by the same CLI; the
    status then names the fallback and why the first path failed.
    """
    from guard.core.ocr_bridge import AgentBridge
    from guard.core.ocr_delegate import run_delegate_review
    agent = config.llm.cli_agent
    review = {**review, "concurrency": min(review.get("concurrency") or AGENT_OCR_CONCURRENCY, AGENT_OCR_CONCURRENCY)}
    with AgentBridge(agent, model=config.llm.model, timeout=config.llm.timeout or None) as bridge:
        status, found = run_ocr_review(target_repo, env_for=bridge.env, **review)
    path = f"answered by the {agent} CLI (tool calls written as text)"
    if bridge.errors:  # a failed agent call is an OCR failure, even when OCR carried on and says complete
        reason = f"{len(bridge.errors)} {agent} CLI call(s) failed, the last said: {bridge.errors[-1][:200]}"
        if not status.startswith("did not run"):
            status = f"did not run: {reason} (OCR reported: {status})"
            found = list(found) + [RuleViolation(
                rule_id="OCR-RUN", severity="HIGH", file_path="(ocr)",
                message=f"Alibaba OCR review did not run completely: {reason}. Run guard post --full again.")]
        else:
            status += f"; {reason}"
    if not status.startswith("did not run"):
        return f"{status}; {path}", found
    why = f"OCR {path} did not run: {status[len('did not run: '):]}"
    console.print(f"[yellow]⚠️ {escape(why[:300])}. Falling back to OCR's delegation mode: its rules and the diff, "
                  f"one prompt per rule group, answered by the same {agent} CLI.[/yellow]")
    d_status, d_found = run_delegate_review(target_repo, review.get("base_ref"), review.get("background") or "",
                                            review.get("skip_files"), review.get("binary") or "ocr", bridge.ask)
    if d_status.startswith("did not run"):  # both paths failed: the first one's findings and failure stay
        return f"{d_status}; answered by the {agent} CLI as the fallback after {why}", list(found) + [
            v for v in d_found if v.rule_id != "OCR-RUN"]
    return f"{d_status}; answered by the {agent} CLI as the fallback after {why}", d_found


def _ocr_cache_key(config, pre) -> Optional[str]:
    """
    What an earlier OCR result depends on: the LLM OCR has, its version, the binary and the base
    commit. None (no reuse, every file reviewed) when the OCR version is not known for this binary.
    """
    import hashlib
    import re
    from guard.core.config import _llm_fingerprint
    from guard.core.updater import get_installed_ocr_version
    # the version is read from `ocr`: for another configured binary it says nothing
    version = get_installed_ocr_version() if config.ocr.binary_path == "ocr" else None
    if not version or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        return None
    parts = [_llm_fingerprint(load_global_config().llm), version, config.ocr.binary_path, (pre.base_ref or "") if pre else ""]
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def _run_build(target_repo: Path) -> Optional[BuildCheckResult]:
    """The project's build and tests (0 tokens); None when the project has no build command."""
    build_cmd = detect_build_command(target_repo)
    build_res: Optional[BuildCheckResult] = None
    if build_cmd:
        start_t = time.perf_counter()
        try:
            # detect_build_command returns guard's own fixed commands (never user config); shell=True needed for npm/pnpm on Windows.
            # Turn into an argument list before ever reading a build command from config.
            p = subprocess.run(
                build_cmd,
                shell=True,
                cwd=str(target_repo),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=BUILD_TIMEOUT_S,
            )
            duration = time.perf_counter() - start_t
            stdout_str = p.stdout or ""
            stderr_str = p.stderr or ""
            build_res = BuildCheckResult(
                command=build_cmd,
                passed=(p.returncode == 0),
                exit_code=p.returncode,
                output=stdout_str + stderr_str,
                duration_s=duration,
            )
        except Exception as e:
            duration = time.perf_counter() - start_t
            build_res = BuildCheckResult(
                command=build_cmd,
                passed=False,
                exit_code=1,
                output=str(e),
                duration_s=duration,
            )
    return build_res


def _known_rules(target_repo: Path) -> List[dict]:
    """Every rule that exists now (team file, local file with this session's learned rules), for the reviewer."""
    try:
        return [{"id": i["id"], "description": i["description"]} for i in load_project_invariants(target_repo) or []]
    except InvariantsFileError:
        return []  # a broken file is reported by the invariant checks themselves


def _write_post_report(target_repo: Path, post_rec, pre) -> None:
    post_report_path = target_repo / ".guard" / "POST_TASK_REPORT.md"
    try:
        post_report_path.write_text(generate_post_task_markdown(post_rec, pre), encoding="utf-8")
        console.print(f"\n[dim]📄 Post-Task Report written to: {post_report_path}[/dim]")
    except Exception:
        pass


def _followups(ledger: list) -> list:
    """Every advisory of the task and every deferral stays a follow-up, not only the last round's."""
    return [e for e in ledger if e.get("status") != "rejected" and (not e.get("blocking") or e.get("status") == "deferred")]


def _record_round(session_mgr: SessionManager, verdict, post_rec) -> bool:
    """
    Keep the task's findings ledger and round count, and stop at the round budget: after that many
    LLM REVISE rounds the session waits for the user (needs_user) instead of starting another round.
    """
    session = session_mgr.load_local_session()
    if session is None:
        return False
    if verdict.review_mode != "llm_deep":
        # No LLM round to count, but an approval still carries the task's follow-ups
        if post_rec.all_passed and session.post:
            post_rec.followups = session.post.followups = _followups(session.findings_ledger)
            session_mgr._save(session)
        return False
    session.llm_rounds += 1
    raised = {f.id for f in verdict.findings}
    by_id = {entry.get("id"): entry for entry in session.findings_ledger}
    for entry in session.findings_ledger:  # earlier findings this round did not raise again
        if entry.get("status") == "open" and entry.get("id") not in raised:
            entry["status"], entry["note"] = "not raised again", f"round {session.llm_rounds}"
    for f in verdict.findings:
        entry = by_id.get(f.id)
        record = {**f.model_dump(), "round": session.llm_rounds}
        if entry is None:
            session.findings_ledger.append({**record, "status": "open", "note": ""})
        elif entry.get("status") in ("deferred", "rejected"):
            entry["round"] = session.llm_rounds
            entry["note"] = f"{entry.get('note', '')}; raised again in round {session.llm_rounds}".lstrip("; ")
        else:
            entry.update({**record, "status": "open", "note": ""})
    if verdict.verdict == ReviewVerdict.REVISE:
        session.llm_revise_rounds += 1
        if session.llm_revise_rounds >= session.revise_budget:
            session.status = SessionStatus.NEEDS_USER
    if post_rec.all_passed:
        post_rec.followups = _followups(session.findings_ledger)
    if session.post:
        session.post.needs_user = session.status == SessionStatus.NEEDS_USER
        session.post.followups = post_rec.followups
    session_mgr._save(session)
    if session.status == SessionStatus.NEEDS_USER:
        console.print(Panel(
            f"{session.llm_revise_rounds} review rounds said REVISE. Guard stops here: stop and ask the user. They read "
            "the remaining findings in the report and run [bold]guard accept[/bold] in their own terminal to accept "
            "them as follow-ups or to allow three more rounds.",
            title="🧑 needs_user", border_style="yellow",
        ))
    return session.status == SessionStatus.NEEDS_USER
