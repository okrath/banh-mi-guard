"""
Complete CLI for Banh-Mi-Guard (`guard`).
Provides:
- `guard pre "<prompt>"`: Triage, Baseline Contracts, Invariants, Pre-task Note
- `guard post [--auto-fix] [--focus]`: Diff Audit, Build Check, OCR Rules, Invariants, LLM Final Gate Verdict
- `guard config` [show | llm | test | sync]: Manage LLM and OCR credentials
- `guard hook` [install | uninstall | status]: Bind hooks and AI Agent directives to target repos
- `guard run "<prompt>" -- <cmd>`: Sandwich pattern wrapper
- `guard doctor`: System diagnostic check & supply-chain update quarantine audit
- `guard update` [ocr | self]: Safe upgrades respecting 3-day quarantine policy
- `guard review [--focus]`: Final Safety Gate Review by the configured LLM
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from guard import __app_name__, __version__
from guard.core.config import (
    get_global_config_path,
    get_local_config_path,
    load_config,
    load_global_config,
    print_config_table,
    save_config,
)
from guard.core.invariant_eval import DomainType, evaluate_invariants
from guard.core.hygiene_engine import HygieneEngine
from guard.core.impact import check_impact, expected_impact
from guard.core.llm_reviewer import LLMReviewerEngine, ReviewVerdict
from guard.core.ocr_engine import GitDiffInspector, OCRRulebookRunner, RuleViolation, run_ocr_review
from guard.core.removal_check import check_removed_symbols
from guard.core.repo_setup import (
    ensure_repo_setup,
    git_root,
    install_global,
    install_workspace,
    needs_refresh,
    refresh_after_upgrade,
    setup_health,
    refresh_repo,
    uninstall_global,
    uninstall_workspace,
)
from guard.core.project_invariants import (
    INVARIANTS_FILENAME,
    InvariantsFileError,
    append_learned_invariants,
    evaluate_checks,
    init_invariants_file,
    learned_without_checks,
    load_local_invariants,
    load_project_invariants,
    load_shared_invariants,
    prune_learned_without_checks,
    removed_or_relaxed,
    similar_groups,
)
from guard.core.simplicity_engine import SimplicityEngine
from guard.core.session import BuildCheckResult, PostTaskRecord, SessionManager, SessionStatus
from guard.core.updater import (
    UpdateSecurityStatus,
    check_guard_self_update,
    check_ocr_update,
    get_cached_update_notice,
    maybe_trigger_background_update_check,
    perform_ocr_upgrade,
    perform_self_upgrade,
)
from guard.domains.detector import (
    analyzer_domain,
    detect_domain,
    detect_build_command,
    detect_repo_domain,
    extract_contracts_and_invariants,
)
from guard.hooks.installer import HookInstaller
from guard.reporters.markdown import generate_post_task_markdown, generate_pre_task_markdown
from guard.reporters.terminal import render_post_task_terminal, render_pre_task_terminal

app = typer.Typer(
    name=__app_name__,
    help="🛡️ Banh-Mi-Guard: Dual-gate impact analysis & regression guard for AI-assisted development",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()
# The project's build and test command: a hung command must not hold the gate forever, but a
# test suite routinely takes longer than a minute
BUILD_TIMEOUT_S = 1800
# A hook payload is a small JSON object; anything bigger is not read (and the action is allowed, logged)
MAX_EVENT_BYTES = 5_000_000


def version_callback(value: bool):
    if value:
        console.print(f"[bold cyan]{__app_name__}[/bold cyan] version [bold green]{__version__}[/bold green]")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show guard version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
):
    pass


# ---------------------------------------------------------
# Core Task Execution Logic (Callable by CLI & Runner)
# ---------------------------------------------------------

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


def execute_pre_task(
    prompt: str,
    repo_path: Optional[Path] = None,
    quick: bool = False,
    scope: Optional[List[str]] = None,
    allow_dirty: bool = False,
    force: bool = False,
) -> bool:
    target_repo = Path(repo_path or Path.cwd()).resolve()
    invariants_existed = (target_repo / INVARIANTS_FILENAME).exists()
    for msg in ensure_repo_setup(target_repo):
        console.print(f"[cyan]🔧 guard setup: {msg}[/cyan]")
    config = load_config(target_repo)
    session_mgr = SessionManager(target_repo)

    # 0. A pre-task gate that can be re-run after editing would let scope be declared retroactively.
    #    An unfinished (AWAITING_POST) or rejected (NEEDS_FIX) session can only be superseded with
    #    --force, and the new session inherits its baseline, base commit and scope: a restart can
    #    never turn the task's own edits into "pre-existing" baseline or widen the audited scope.
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
        return False
    if superseded and not force:
        state = {SessionStatus.AWAITING_POST: "unfinished", SessionStatus.NEEDS_USER: "waiting for the user (guard accept)"}.get(
            superseded.status, "rejected (REVISE)")
        console.print(
            f"[bold red]❌ The previous guard session {superseded.session_id} is {state}.[/bold red]\n"
            "Finish it with [bold]guard post[/bold]. [bold]guard pre --force[/bold] restarts it, keeping its baseline and scope; "
            "the restart is recorded and any scope added by it is reported as SCOPE-004."
        )
        return False

    diff_inspector = GitDiffInspector(target_repo)
    requested_scope = sorted(
        {p.replace("\\", "/").rstrip("/") for p in _prompt_paths(prompt, target_repo) + list(scope or [])} - {""}
    )
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
            return False
        baseline_dirty = {f: _fingerprint(target_repo / f) for f in working_files}
        base_ref = diff_inspector.get_head()
        baseline_snapshot = diff_inspector.create_baseline_snapshot() if working_files else None
        candidate_files = requested_scope
        late_scope = []
        restarts = []

    # 1. Domain comes from the repository itself
    domain = detect_domain(target_repo)

    # 3. Domain Contracts & Invariants Extraction
    try:
        contracts, invariants = extract_contracts_and_invariants(
            repo_path=target_repo,
            prompt=prompt,
            domain=domain,
            files=candidate_files,
        )
    except InvariantsFileError as e:
        console.print(f"[bold red]❌ {e}[/bold red]\nFix guard.invariants.json before starting the task.")
        return False
    baseline_eval = evaluate_invariants(
        invariants=[inv.model_dump() for inv in invariants],
        git_diff="",
        files_changed=[],
        repo_path=target_repo,
    )
    # Only real checks have a meaningful baseline; diff heuristics trivially "pass" on an empty diff
    checked = {inv.id for inv in invariants if inv.checks}
    baseline_status = {c.id: c.status for c in baseline_eval.checks if c.id in checked}
    if superseded:
        # A restart keeps the rules locked at the first pre: re-locking from a rulebook edited in the
        # meantime would let the task choose the rules it is judged by
        baseline_status = dict(superseded.pre.baseline_invariant_status)
        invariants = list(superseded.pre.locked_invariants)
    # Expected impact of the scoped files; a restart keeps the first pre's (the task may have edited them since)
    if superseded:
        impact = superseded.pre.impact
    else:
        impact = expected_impact(target_repo, candidate_files, [inv.model_dump() for inv in invariants]) if candidate_files else None

    # 4. Save Session
    # What the agent hook recorded before this pre: the user's own prompt, files changed early
    from guard.agent.events import update_state

    def take(state):  # consumed by this pre: never reused for a later task
        taken = {k: state.pop(k, None) for k in ("user_prompt", "prompt_at", "pre_edit_changes")}  # in-flight "bash" stays
        return taken["user_prompt"], taken["pre_edit_changes"] or []

    recorded_prompt, recorded_changes = update_state(target_repo, take)
    user_prompt = recorded_prompt or (superseded.pre.user_prompt if superseded else None)  # a new prompt wins
    pre_edit_changes = sorted(set(recorded_changes) | set(superseded.pre.pre_edit_changes if superseded else []))

    session = session_mgr.start_pre_session(
        user_prompt=user_prompt,
        pre_edit_changes=pre_edit_changes,
        impact=impact,
        carry=superseded,  # a restart keeps the task's findings ledger and round count
        prompt=prompt,
        expected_files=candidate_files,
        contracts=contracts,
        invariants=invariants,
        non_regression_strategy=f"Isolate changes to domain {domain.value.upper()}. Maintain 100% existing baseline contracts.",
        domain=domain,
        baseline_dirty=baseline_dirty,
        baseline_invariant_status=baseline_status,
        base_ref=base_ref,
        late_scope=late_scope,
        baseline_snapshot=baseline_snapshot,
        restarts=restarts,
    )

    # 5. Output Terminal & Write Markdown
    render_pre_task_terminal(session.pre)
    md_content = generate_pre_task_markdown(session.pre)
    pre_note_path = target_repo / ".guard" / "PRE_TASK_NOTE.md"
    try:
        pre_note_path.write_text(md_content, encoding="utf-8")
        console.print(f"\n[dim]📄 Pre-Task Note written to: {pre_note_path}[/dim]")
    except Exception:
        pass

    return True


def execute_post_task(
    repo_path: Optional[Path] = None,
    auto_fix: bool = False,
    focus: str = "all",
    hook: bool = False,
    full: bool = False,
) -> bool:
    """guard post, marked as running while it works (an agent waiting for it may stop its turn)."""
    from guard.agent.events import post_running
    target_repo = Path(repo_path or Path.cwd()).resolve()
    with post_running(target_repo):
        return _execute_post_task(target_repo, auto_fix=auto_fix, focus=focus, hook=hook, full=full)


def _execute_post_task(
    target_repo: Path,
    auto_fix: bool = False,
    focus: str = "all",
    hook: bool = False,
    full: bool = False,
) -> bool:
    for msg in ensure_repo_setup(target_repo, create_invariants=not hook):
        console.print(f"[cyan]🔧 guard setup: {msg}[/cyan]")
    config = load_config(target_repo)
    session_mgr = SessionManager(target_repo)
    # In a git hook only this repo's own session counts; never adopt another repo's session.
    session = session_mgr.load_local_session() if hook else session_mgr.load_session()
    if hook and session is None:
        console.print("[dim]Banh-Mi-Guard: no guard session in this repository, skipping.[/dim]")
        return True
    if hook and session.status == SessionStatus.COMPLETED:
        # An approval covers only the exact file contents it approved, not later or unrelated work
        approved = session.post.approved_fingerprints if session.post else {}
        uncovered = [
            f for f in GitDiffInspector(target_repo).get_working_files()
            if approved.get(f) != _fingerprint(target_repo / f)
        ]
        if not uncovered:
            console.print("[dim]Banh-Mi-Guard: changes match the last approved guard session, skipping.[/dim]")
            return True
        listing = "\n".join(f"  • {f}" for f in uncovered[:20])
        console.print(
            f"[bold red]❌ {len(uncovered)} changed file(s) are not covered by the last approved guard session "
            f"({session.session_id}):[/bold red]\n{listing}\n"
            "Run [bold]guard pre \"<task>\"[/bold] before editing and [bold]guard post[/bold] after, or "
            "[bold]guard reset[/bold] to stop guarding this work."
        )
        return False

    if session is not None and session.status == SessionStatus.NEEDS_USER:
        # Another round would take back the decision the round budget handed to the user
        console.print(
            f"[bold red]❌ Guard session {session.session_id} is waiting for the user.[/bold red] "
            "Stop and ask the user to run [bold]guard accept[/bold] in their own terminal."
        )
        return False

    pre = session.pre if session else None
    expected_files = pre.expected_files if pre else []
    scope_declared = bool(expected_files)
    baseline_dirty = pre.baseline_dirty if pre else {}
    invariants_dicts = [inv.model_dump() for inv in (pre.locked_invariants if pre else [])]

    # 1. OCR Diff & Blast Radius Audit (no declared scope -> no scope verdict, instead of flagging every file)
    diff_inspector = GitDiffInspector(target_repo)
    # Diff against the commit recorded at pre, so commits made mid-task are still audited
    raw_diff = diff_inspector.get_diff(base_ref=pre.base_ref if pre else None) or ""
    diff_summary = diff_inspector.parse_diff(raw_diff, expected_files=expected_files if scope_declared else None)

    # Files dirty before pre-task and untouched since are not attributed to this task.
    for f in diff_summary.files:
        if f.path in baseline_dirty and baseline_dirty[f.path] == _fingerprint(target_repo / f.path):
            f.preexisting = True
            f.is_out_of_scope = False
    # guard.invariants.json may grow outside the declared scope (guard writes learned rules into it);
    # removing or relaxing an existing rule is checked separately below and blocks.
    for f in diff_summary.files:
        if f.path == INVARIANTS_FILENAME:
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

    # 2. OCR Rulebook & Code Hygiene scan (Two-tier: diff-level vs full-file focus)
    rulebook = OCRRulebookRunner()
    violations = rulebook.scan_diff(task_diff)

    late_scope = pre.late_scope if pre else []
    for f in diff_summary.out_of_scope_files:
        if late_scope and diff_inspector._is_expected(f, late_scope):
            violations.append(RuleViolation(
                rule_id="SCOPE-004",
                severity="HIGH",
                file_path=f,
                message="Scope for this file was only declared by a `guard pre --force` restart after edits began.",
            ))
    for d in deleted_files:
        violations.append(RuleViolation(
            rule_id="SCOPE-002",
            severity="MEDIUM",
            file_path=d,
            message="File deleted. Confirm the task explicitly asked for this removal.",
        ))
    if baseline_dirty:
        attributable = bool(snapshot)
        violations.append(RuleViolation(
            rule_id="SCOPE-003",
            severity="MEDIUM" if attributable else "HIGH",
            file_path=", ".join(sorted(baseline_dirty)[:10]) + (" …" if len(baseline_dirty) > 10 else ""),
            message=(
                f"{len(baseline_dirty)} file(s) were already modified before pre-task (--allow-dirty). "
                + ("Review covers only edits made after pre-task (diff vs baseline snapshot); the pre-existing changes are not vouched for."
                   if attributable else "Guard cannot attribute or vouch for those changes.")
            ),
        ))

    # Removals a compiler cannot see (string keys, exports, CSS classes) checked over the whole repo
    removal_violations, removal_summary = check_removed_symbols(target_repo, task_diff)
    violations.extend(removal_violations)
    evidence = [removal_summary] if removal_summary else []
    # Changed symbols against the impact range pre expected (MEDIUM: reported, never blocking)
    impact_violations, impact_summary = check_impact(target_repo, task_diff, pre.impact if pre else None, expected_files)
    violations.extend(impact_violations)
    if impact_summary:
        evidence.append(impact_summary)

    # Weakening the rulebook is never a side effect: a removed or relaxed invariant blocks
    rulebook_retired: set = set()
    rulebook_redefined: dict = {}
    if pre and any(f.path == INVARIANTS_FILENAME for f in diff_summary.files):
        base_text = _file_at(target_repo, pre.baseline_snapshot or pre.base_ref, INVARIANTS_FILENAME)
        if base_text:
            try:
                old_items = json.loads(base_text).get("invariants", [])
                new_items = load_shared_invariants(target_repo) or []
            except (ValueError, AttributeError, InvariantsFileError):
                old_items, new_items = [], []
            declared = scope_declared and diff_inspector._is_expected(INVARIANTS_FILENAME, expected_files)
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

    hygiene = HygieneEngine(target_repo)
    if (focus or "").lower() in ("dead-code", "hygiene"):
        touched = [f.path for f in diff_summary.files]
        hygiene_violations = hygiene.scan_focus_level(touched)
    else:
        hygiene_violations = hygiene.scan_diff_level(task_diff, task_summary)
    violations.extend(hygiene_violations)

    simplicity = SimplicityEngine(target_repo)
    if (focus or "").lower() in ("simplicity", "yagni", "lazy"):
        touched = [f.path for f in diff_summary.files]
        simplicity_violations = simplicity.scan_focus_level(touched)
    else:
        simplicity_violations = simplicity.scan_diff_level(task_diff, task_summary)
    violations.extend(simplicity_violations)

    # Alibaba OCR (an LLM review that reads the repository) runs only for a full review (--full, never
    # in a Git hook); then OCR not running blocks like a HIGH finding. Without it the report says so.
    # The user can make it permanent: `guard config ocr always` (machine-wide) runs it on every post
    always = bool(load_global_config().ocr.always)
    full = full or always

    # The build (tests) runs in parallel with the reviews: with OCR it starts once OCR has taken its
    # snapshot (build output never enters the reviewed tree), without OCR it starts now
    from concurrent.futures import ThreadPoolExecutor
    pool = ThreadPoolExecutor(max_workers=1)
    build = {}

    def start_build() -> None:
        if "future" not in build:
            build["future"] = pool.submit(_run_build, target_repo)
    # The status always names the setting, so the user knows when OCR runs and how to change it
    setting = ("`guard config ocr always` is on: every guard post runs it" if always else
               "optional: guard post --full adds it; `guard config ocr always` runs it on every post")
    ocr_status = f"not run in the Git hook ({setting})" if hook else f"not run ({setting})"
    if full and not hook and not task_diff.strip():
        ocr_status = f"skipped: no changes ({setting})"
    elif full and not hook:
        console.print("[cyan]🔎 Alibaba OCR is reviewing the changes (no time limit; it ends when OCR finishes or reports an error, Ctrl+C stops it)...[/cyan]")
        ocr_status, ocr_violations = run_ocr_review(
            target_repo,
            base_ref=pre.base_ref if pre else None,
            background=pre.prompt if pre else "Post-task verification",
            skip_files=preexisting_files,
            binary=config.ocr.binary_path,
            concurrency=config.ocr.concurrency,
            on_snapshot=start_build,
            cache_key=_ocr_cache_key(config, pre),
        )
        violations.extend(ocr_violations)
        if ocr_status.startswith("did not run"):  # a failed review names the setting too
            ocr_status += f" ({setting})"

    evidence.append(f"Alibaba OCR review: {ocr_status}")
    with_ocr = full and not hook and bool(task_diff.strip())  # then the gate waits for OCR and the build
    start_build()  # no OCR (or it stopped before its snapshot): the build starts here

    # 3. Build and tests: running in parallel (see start_build); waited for before the gate decides

    # 4. Invariants: project checks run on current files; template invariants only get diff heuristics
    inv_eval = evaluate_invariants(
        invariants=invariants_dicts,
        git_diff=task_diff,
        files_changed=[f.path for f in diff_summary.files],
        repo_path=target_repo,
    )
    baseline_status = pre.baseline_invariant_status if pre else {}
    for c in inv_eval.checks:
        if c.status == "failed" and baseline_status.get(c.id) == "failed":
            # Not a regression caused by this task: warn, do not block
            c.status = "baseline_failed"
            c.passed = True
            c.notes += " (already failing before this task)"
    for c in inv_eval.checks:
        if c.id in rulebook_retired:
            c.status, c.passed = "retired", True
            c.notes = f"retired by this task's declared edit of {INVARIANTS_FILENAME} (reported as INV-WEAKENED for review)"
        elif c.id in rulebook_redefined:
            status, note = evaluate_checks(target_repo, rulebook_redefined[c.id])
            c.status, c.passed = status, status != "failed"
            c.notes = f"re-evaluated with the definition changed by this task: {note}"

    # A new or edited guard.invariants.json is not locked by this session, so self-check it on the
    # current tree: a rule that fails on the code it was written for is a broken rule.
    if any(f.path == INVARIANTS_FILENAME for f in diff_summary.files):
        try:
            new_items = load_shared_invariants(target_repo) or []
        except InvariantsFileError as e:
            violations.append(RuleViolation(rule_id="INV-FILE", severity="CRITICAL", file_path=INVARIANTS_FILENAME, message=str(e)))
        else:
            self_check = evaluate_invariants(
                invariants=[{"id": i["id"], "description": i["description"], "checks": i.get("checks") or []} for i in new_items],
                git_diff="",
                files_changed=[],
                repo_path=target_repo,
            )
            for c in self_check.checks:
                c.id = f"{c.id} (new {INVARIANTS_FILENAME}, self-check)"
                inv_eval.checks.append(c)
            inv_eval.unverified_count += self_check.unverified_count
    inv_eval.all_passed = not any(c.status == "failed" for c in inv_eval.checks)

    # 5. LLM Final Gatekeeper Review (Calling the user-configured LLM)
    reviewer = LLMReviewerEngine(config=config)
    domain = pre.domain if pre else DomainType.BACKEND
    prompt = pre.prompt if pre else "Post-task verification"
    if pre and pre.user_prompt and pre.user_prompt.strip() != pre.prompt.strip():
        # The agent wrote `prompt`; the hook recorded what the user actually asked
        prompt = f"{pre.prompt}\n\nThe user's own message before this pre (verbatim, recorded by the agent hook; judge the task against it): {pre.user_prompt}"
    if pre and pre.pre_edit_changes:
        evidence.append(f"Files an agent command changed before guard pre ran: {', '.join(pre.pre_edit_changes)}")

    def gate(build_res: Optional[BuildCheckResult], use_llm: bool, notes: List[str]):
        return reviewer.review(
            prompt=prompt,
            domain=domain,
            diff_summary=diff_summary.model_copy(update={"raw_diff": task_diff}),
            build_check=build_res,
            violations=violations,
            invariant_result=inv_eval,
            contracts=pre.existing_contracts if pre else None,
            use_llm=use_llm,
            focus=focus,
            evidence=evidence + notes,
            ledger=session.findings_ledger if session else [],
            known_rules=_known_rules(target_repo),
        )

    if with_ocr:  # the gate sees OCR's findings and the build result
        build_res = build["future"].result()
        review_verdict = gate(build_res, True, [])
    else:  # the LLM reviews while the build runs; a failing build still rejects on its own
        build_cmd = detect_build_command(target_repo)
        review_verdict = gate(None, True, [
            f"The build and tests ({build_cmd}) run in parallel with this review; guard rejects the change by "
            "itself if they fail, so do not raise findings about missing test evidence."] if build_cmd else [])
        build_res = build["future"].result()
        if build_res is not None and not build_res.passed:
            # decided by the build, not by the LLM: the heuristic verdict (REVISE), and no LLM round counted
            llm_ran = review_verdict.review_mode == "llm_deep"
            review_verdict = gate(build_res, False, [])
            if llm_ran:
                review_verdict.summary += " The LLM review ran in parallel; the failing build decides, so it is not counted."
    pool.shutdown(wait=False)

    all_passed = (review_verdict.verdict == ReviewVerdict.APPROVED)

    # Rules the reviewer discovered are written only after validation (new, and passing on this code),
    # before fingerprints are taken so the updated file is part of what was approved.
    learned, rejected_props = append_learned_invariants(
        target_repo, review_verdict.proposed_invariants, session.session_id if session else "unknown",
    )
    # The report says what verified each added rule: how many of its checks pass on the current code
    # counted from the rules as written, not from the proposals (two proposals may share an id)
    check_counts = {str(i["id"]): len(i.get("checks") or []) for i in (load_local_invariants(target_repo) or [])} if learned else {}
    learned = [f"{i} ({check_counts.get(i, 0)} check(s) pass on the current code)" for i in learned]

    # 6. Save Post Record
    post_rec = PostTaskRecord(
        files_modified=[f.path for f in diff_summary.files],
        diff_summary=diff_summary,
        out_of_scope_files=diff_summary.out_of_scope_files,
        build_check=build_res,
        rule_violations=violations,
        invariant_result=inv_eval,
        all_passed=all_passed,
        muse_verdict=review_verdict.verdict.value,
        muse_score=review_verdict.score,
        muse_notes=review_verdict.summary,
        review_mode=review_verdict.review_mode,
        llm_error=review_verdict.llm_error,
        scope_declared=scope_declared,
        preexisting_files=preexisting_files,
        deleted_files=deleted_files,
        approved_fingerprints=(
            {
                p: _fingerprint(target_repo / p)
                for p in {f.path for f in diff_summary.files}
            } if all_passed else {}
        ),
        reviewed_fingerprints={p: _fingerprint(target_repo / p) for p in {f.path for f in diff_summary.files}},
        findings=[f.model_dump() for f in review_verdict.findings],
        learned_invariants=learned,
        rejected_invariant_proposals=rejected_props,
        ocr_status=ocr_status,
        impact_summary=impact_summary,
        ocr_complete=ocr_status.startswith("complete") and not any(v.rule_id == "OCR-RUN" for v in violations),
        commit_mode=load_global_config().commit_mode,  # machine-wide choice, whatever the local config says
    )

    session_mgr.complete_post_session(post_rec)
    post_rec.needs_user = _record_round(session_mgr, review_verdict, post_rec)

    # 7. Render Terminal & Markdown
    render_post_task_terminal(post_rec, pre)
    _write_post_report(target_repo, post_rec, pre)

    if not all_passed and review_verdict.remediation_steps:
        console.print(Panel(
            "\n".join(f"  [bold red]•[/bold red] {s}" for s in review_verdict.remediation_steps),
            title="🔧 Actionable Remediation Checklist",
            border_style="red",
        ))

    return all_passed


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


# ---------------------------------------------------------
# CLI Commands
# ---------------------------------------------------------

@app.command("pre")
def pre_cmd(
    prompt: str = typer.Argument(..., help="Prompt or task about to be executed by developer/agent"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
    quick: bool = typer.Option(False, "--quick", "-q", help="Accepted for compatibility; has no effect"),
    scope: Optional[List[str]] = typer.Option(None, "--scope", "-s", help="Allowed file/dir/glob (repeatable), e.g. --scope 'src/ui/**'"),
    allow_dirty: bool = typer.Option(False, "--allow-dirty", help="Start even though files are already modified (recorded as pre-existing baseline)"),
    force: bool = typer.Option(False, "--force", help="Restart an unfinished or rejected session (inherits its baseline and scope)"),
):
    """
    Run Pre-Task Guard BEFORE editing: scope declaration, baseline contracts & invariants.
    """
    success = execute_pre_task(
        prompt=prompt,
        repo_path=Path(repo) if repo else None,
        quick=quick,
        scope=scope,
        allow_dirty=allow_dirty,
        force=force,
    )
    if not success:
        raise typer.Exit(code=1)


@app.command("post")
def post_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
    auto_fix: bool = typer.Option(False, "--auto-fix", help="Trigger self-healing suggestions"),
    focus: str = typer.Option("all", "--focus", "-f", help="Quality pillar focus: 'all', 'security', 'memory', 'performance', 'ux', 'dead-code', 'simplicity'"),
    hook: bool = typer.Option(False, "--hook", help="Git-hook mode: skip when this repository has no guard session"),
    full: bool = typer.Option(False, "--full", help="Full review: also run the Alibaba OCR review (minutes, no time limit); OCR failing or a high/critical finding blocks"),
):
    """
    Run Post-Task Guard: diff audit, build checks, invariant checks & LLM final verification.
    """
    passed = execute_post_task(repo_path=Path(repo) if repo else None, auto_fix=auto_fix, focus=focus, hook=hook, full=full)
    if not passed:
        raise typer.Exit(code=1)


@app.command("reset")
def reset_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
):
    """
    Close the current guard session (e.g. after its work was committed or abandoned).
    The session is archived under .guard/history/ so the decision stays auditable.
    """
    target_repo = Path(repo).resolve() if repo else Path.cwd().resolve()
    mgr = SessionManager(target_repo)
    session = mgr.load_local_session()
    if session is None:
        console.print("[yellow]No guard session in this repository.[/yellow]")
        return
    if session.status == SessionStatus.NEEDS_USER:
        # Only guard accept clears needs_user; to drop the task, allow more rounds there (c), then reset
        console.print("[bold red]❌ This session is waiting for the user's decision: run guard accept in an interactive terminal.[/bold red]")
        raise typer.Exit(code=1)
    archived = mgr.archive_and_clear()
    console.print(
        f"[bold yellow]Guard session {session.session_id} ({session.status.value}) closed.[/bold yellow] "
        f"Archived to {archived}."
    )


@app.command("run")
def run_cmd(
    prompt: str = typer.Argument(..., help="Prompt/task to execute"),
    command: List[str] = typer.Argument(..., help="Command to run after pre-task (e.g. -- git status)"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
    auto_fix: bool = typer.Option(False, "--auto-fix", help="Auto-fix loop"),
    scope: Optional[List[str]] = typer.Option(None, "--scope", "-s", help="Allowed file/dir/glob (repeatable)"),
    allow_dirty: bool = typer.Option(False, "--allow-dirty", help="Start even though files are already modified"),
    force: bool = typer.Option(False, "--force", help="Restart an unfinished or rejected session (inherits its baseline and scope)"),
):
    """
    Execute Sandwich Pattern: `guard pre` -> `agent-command` -> `guard post`.
    """
    from guard.hooks.runner import run_sandwich_task
    code = run_sandwich_task(
        prompt=prompt,
        command=command,
        repo_path=Path(repo) if repo else None,
        auto_fix=auto_fix,
        scope=scope,
        allow_dirty=allow_dirty,
        force=force,
    )
    if code != 0:
        raise typer.Exit(code=code)


# Subcommand: guard invariants
invariants_app = typer.Typer(
    name="invariants",
    help="📜 Create and check guard.invariants.json (project rules checked by pre/post)",
    no_args_is_help=True,
)
app.add_typer(invariants_app, name="invariants")


@invariants_app.command("init")
def invariants_init_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
    shared: bool = typer.Option(False, "--shared", help="Create guard.invariants.json in the repository root (to commit for the team)"),
):
    """
    Create the invariants file, importing numbered items under an 'Invariants' / 'Bất biến'
    heading of AGENT.md / AGENTS.md / CLAUDE.md. Default: the local, Git-excluded
    .guard/invariants.json (no repository change). Never overwrites an existing file.
    """
    target_repo = Path(repo).resolve() if repo else Path.cwd().resolve()
    path, created, imported = init_invariants_file(target_repo, shared=shared)
    if not created:
        console.print(f"[yellow]{path} already exists; nothing changed. Run `guard invariants check`.[/yellow]")
        return
    console.print(f"[bold green]✅ Created {path}[/bold green] with {imported} invariant(s) imported from agent docs.")
    if imported:
        console.print("[dim]Imported entries have no checks yet (UNVERIFIED): add {\"files\": glob, \"forbid\"|\"require\": regex} checks, then run `guard invariants check`.[/dim]")


@invariants_app.command("check")
def invariants_check_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
):
    """
    Evaluate guard.invariants.json on the current tree, without a guard session.
    Exit code 1 when a check fails, 2 when the file is missing or malformed.
    """
    target_repo = Path(repo).resolve() if repo else Path.cwd().resolve()
    try:
        items = load_project_invariants(target_repo)
    except InvariantsFileError as e:
        console.print(f"[bold red]❌ {e}[/bold red]")
        raise typer.Exit(code=2)
    if items is None:
        console.print(f"[yellow]No {INVARIANTS_FILENAME} in {target_repo}. Create it with `guard invariants init`.[/yellow]")
        raise typer.Exit(code=2)

    table = Table(title=f"📜 {INVARIANTS_FILENAME} ({len(items)} invariants)", show_header=True)
    table.add_column("ID", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Notes", style="dim")
    failed = 0
    for inv in items:
        status, note = evaluate_checks(target_repo, inv.get("checks") or [])
        failed += status == "failed"
        badge = {"passed": "[green]✅ PASSED[/green]", "failed": "[bold red]❌ FAILED[/bold red]"}.get(status, "[yellow]⚪ UNVERIFIED[/yellow]")
        table.add_row(str(inv["id"]), badge, note)
    console.print(table)
    unchecked = learned_without_checks(target_repo)
    if unchecked:
        console.print(f"[yellow]⚪ {len(unchecked)} rule(s) learned by the review gate have no check and are never verified:[/yellow] "
                      f"{', '.join(str(i['id']) for i in unchecked)}. Remove them with [bold]guard invariants prune[/bold].")
    for group in similar_groups(items):
        console.print(f"[yellow]≈ These rules say the same thing:[/yellow] {', '.join(group)}")
    if failed:
        raise typer.Exit(code=1)


@invariants_app.command("prune")
def invariants_prune_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
):
    """
    For the user, in an interactive terminal: remove the rules the review gate learned without any
    check from the local .guard/invariants.json. The team's guard.invariants.json is never touched.
    """
    target_repo = Path(repo).resolve() if repo else Path.cwd().resolve()
    try:
        unchecked = learned_without_checks(target_repo)
    except InvariantsFileError as e:
        console.print(f"[bold red]❌ {e}[/bold red]")
        raise typer.Exit(code=2)
    if not unchecked:
        console.print("[green]No learned rule without a check.[/green]")
        return
    for inv in unchecked:
        console.print(f"  • {inv['id']}: ", end="")
        console.print(str(inv["description"]), markup=False)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        console.print("[bold red]❌ Removing rules is the user's decision: run guard invariants prune yourself in an interactive terminal.[/bold red]")
        raise typer.Exit(code=1)
    if typer.prompt(f"Remove these {len(unchecked)} rule(s) from .guard/invariants.json? (y/N)", default="n").strip().lower() != "y":
        console.print("[dim]Nothing changed.[/dim]")
        return
    gone = prune_learned_without_checks(target_repo, confirmed=unchecked)  # only what was listed and confirmed
    console.print(f"[bold green]✅ Removed {len(gone)} learned rule(s) without a check.[/bold green]")


# Subcommand: guard config
config_app = typer.Typer(
    name="config",
    help="⚙️ Manage Guard configuration (LLM, Alibaba OCR)",
    no_args_is_help=False,
)
app.add_typer(config_app, name="config")


@config_app.callback(invoke_without_command=True)
def config_main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        local_p = get_local_config_path()
        global_p = get_global_config_path()
        active_p = local_p if local_p.is_file() else global_p
        info = f"Source: {active_p}" if active_p.is_file() else "Default (No config file saved yet)"
        cfg = load_config()
        print_config_table(cfg, info)


@config_app.command("llm")
def config_llm_cmd(
    local: bool = typer.Option(False, "--local", "-l", help="Save config to local repository (.guard/config.json)"),
):
    """
    Interactive Step-by-Step wizard to configure LLM (OpenAI-compatible or Anthropic) and auto-sync to Alibaba OCR.
    """
    from guard.core.config import run_llm_wizard
    run_llm_wizard(local=local)


@config_app.command("test")
def config_test_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
):
    """
    Ping test the currently configured LLM endpoint.
    """
    from guard.core.llm_client import ping_llm
    from guard.core.config import LLMProtocol
    cfg = load_config(Path(repo) if repo else None)
    if cfg.llm.protocol == LLMProtocol.CLI:
        console.print(f"[cyan]Checking the [bold]{cfg.llm.cli_agent or '(none chosen)'}[/bold] CLI (model: "
                      f"{cfg.llm.model or 'its default'}): its sign-in and models...[/cyan]")
    else:
        console.print(f"[cyan]Testing connection to [bold]{cfg.llm.base_url}[/bold] (model: {cfg.llm.model})...[/cyan]")
    success, msg, latency = ping_llm(cfg.llm)
    if success:
        console.print(f"[bold green]✅ Ping SUCCESS![/bold green] Response time: {latency:.1f}ms"
                      + (f" — {msg}" if cfg.llm.protocol == LLMProtocol.CLI else ""), highlight=False)
    else:
        console.print(f"[bold red]❌ Ping FAILED:[/bold red] {msg}")


@config_app.command("sync")
def config_sync_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
):
    """
    Manually synchronize LLM credentials to Alibaba Open Code Review (ocr) CLI.
    """
    from guard.core.config import sync_to_alibaba_ocr
    cfg = load_config(Path(repo) if repo else None)
    synced, msg = sync_to_alibaba_ocr(cfg.llm, cfg.ocr.binary_path)
    if synced:
        console.print(f"[bold green]✅ {msg}[/bold green]")
    else:
        console.print(f"[yellow]⚠️ {msg}[/yellow]")


@config_app.command("ocr")
def config_ocr_cmd(
    mode: str = typer.Argument(..., help="always: every guard post runs the Alibaba OCR review; optional: only guard post --full"),
):
    """
    Choose whether every guard post runs the Alibaba OCR review (machine-wide, ~/.guard/config.json).
    It takes minutes; a failed review or a high/critical finding blocks. The Git hook never runs it.
    """
    if mode not in ("always", "optional"):
        console.print("[bold red]❌ The mode is `always` or `optional`.[/bold red]")
        raise typer.Exit(code=1)
    cfg = load_global_config()
    cfg.ocr.always = mode == "always"
    path = save_config(cfg)
    what = "every guard post runs it" if cfg.ocr.always else "only guard post --full runs it"
    console.print(f"[bold green]✅ Alibaba OCR review `{mode}`: {what}.[/bold green] [dim]Saved to {path}[/dim]")


@config_app.command("commit")
def config_commit_cmd(
    mode: str = typer.Argument(..., help="auto: the agent writes commit messages; ask: the agent asks you for each one"),
):
    """
    Choose who writes commit messages for approved work (machine-wide, ~/.guard/config.json).
    """
    if mode not in ("auto", "ask"):
        console.print("[bold red]❌ The mode is `auto` or `ask`.[/bold red]")
        raise typer.Exit(code=1)
    cfg = load_global_config()
    cfg.commit_mode = mode
    path = save_config(cfg)
    who = "the agent writes commit messages" if mode == "auto" else "the agent asks you for every commit message"
    console.print(f"[bold green]✅ Commit mode `{mode}`: {who}.[/bold green] [dim]Saved to {path}[/dim]")


def print_setup_health(cwd: Path, title: str, only_problems: bool = False) -> int:
    """Print the setup check; returns the number of missing items."""
    rows = setup_health(cwd)
    problems = [r for r in rows if r["level"] != "ok"]
    if only_problems and not problems:
        return 0
    table = Table(title=title, show_header=True, header_style="bold magenta")
    table.add_column("Item", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Detail")
    table.add_column("How to fix", style="cyan")
    badge = {"ok": "[green]✅ OK[/green]", "warn": "[yellow]⚠️ WARN[/yellow]", "missing": "[bold red]❌ MISSING[/bold red]"}
    for r in (problems if only_problems else rows):
        table.add_row(r["item"], badge[r["level"]], r["detail"], r["fix"])
    console.print(table)
    return sum(1 for r in rows if r["level"] == "missing")


def finish_setup(cwd: Path) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """
    Do what guard still needs on this machine, in order: an LLM, Alibaba OCR, OCR synced with the
    LLM, the commit mode, and guard's hooks in the agents found here. Steps that need an answer are
    asked in an interactive terminal and listed otherwise (an agent never types a key or confirms a
    diff for the user); a declined or failed step is listed and the next one runs. Returns (done, left).
    """
    from guard.agent.adapter import installed
    from guard.core.config import load_global_config, ocr_in_sync, run_llm_wizard, sync_to_alibaba_ocr
    from guard.core.repo_setup import _detected_adapters
    from guard.core.updater import perform_ocr_upgrade

    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    done, left = [], []  # (item, what happened) / (item, command to run)

    def step(item: str, command: str, question: str, action) -> None:
        if not interactive:
            left.append((item, command))
            return
        if not typer.confirm(question, default=True):
            left.append((item, f"declined; later: {command}"))
            return
        try:
            result = action()
        except (Exception, SystemExit) as e:  # a failing step (or a wizard that exits) never stops the others
            left.append((item, f"failed ({type(e).__name__}: {e}); later: {command}"))
            return
        if result is False:
            left.append((item, f"not done; later: {command}"))
        else:
            done.append((item, result or "done"))

    # 1. An LLM for the review gate (the wizard also gives it to Alibaba OCR)
    if not load_global_config().llm.ready:  # an API key, or the user's own agent CLI
        step("LLM", "guard config llm", "No LLM is configured for the review gate. Set one up now?",
             lambda: run_llm_wizard().llm.ready and "configured")

    # 2. Alibaba OCR, for `guard post --full` (installed through the same quarantine as `guard update ocr`).
    # The binary is the one guard post and doctor use here (a repository may name its own)
    ocr_binary = load_config(cwd).ocr.binary_path
    if not shutil.which(ocr_binary):
        def install_ocr():
            ok, msg = perform_ocr_upgrade()
            console.print(msg, markup=False)
            # done only when the binary guard uses here is now found (the updater installs `ocr`)
            return ok and bool(shutil.which(ocr_binary)) and "installed"
        step("Alibaba OCR", "guard update ocr", "Alibaba OCR (the full review, guard post --full) is not installed. Install it with npm now?",
             install_ocr)

    # 3. OCR uses the current LLM: no question, it only mirrors guard's own setting. The LLM is the
    # machine-wide one (OCR is machine-wide: a repository's credentials never reach it as a side effect)
    llm = load_global_config().llm
    if llm.api_key and shutil.which(ocr_binary) and not ocr_in_sync(llm, ocr_binary):
        try:
            ok, msg = sync_to_alibaba_ocr(llm, ocr_binary)
        except Exception as e:  # like every step: a failure is listed and the others still run
            ok, msg = False, f"failed ({type(e).__name__}: {e})"
        (done if ok else left).append(("OCR sync", "synced with the current LLM" if ok else f"{msg}; later: guard config sync"))

    # 3b. Whether every post runs OCR: asked once, once OCR is here (the answer is kept either way)
    if shutil.which(ocr_binary) and load_global_config().ocr.always is None:
        def choose_ocr():
            mode = typer.prompt("Alibaba OCR review: always (on every guard post, minutes each) or optional (only guard post --full)?",
                                default="optional").strip().lower()
            if mode not in ("always", "optional"):
                return False
            config_ocr_cmd(mode)
            return f"OCR {mode}"
        step("OCR on every post", "guard config ocr always   (or: guard config ocr optional)",
             "Alibaba OCR is installed. Choose whether every guard post runs its review?", choose_ocr)

    # 4. Who writes commit messages
    if not load_global_config().commit_mode:
        def choose_mode():
            mode = typer.prompt("Commit messages: auto (the agent writes them) or ask (the agent asks you)?", default="auto").strip().lower()
            if mode not in ("auto", "ask"):
                return False
            config_commit_cmd(mode)
            return f"mode {mode}"
        step("Commit mode", "guard config commit auto   (or: guard config commit ask)", "Choose who writes commit messages now?", choose_mode)

    # 5. Guard's hooks in the agents found on this machine (the diff is shown and confirmed there)
    for adapter in _detected_adapters():
        if not installed(adapter):
            def add_hooks(name=adapter["name"], adapter=adapter):
                try:
                    agent_add_cmd(name)
                except typer.Exit:
                    pass  # declined or refused: the check below says so
                return installed(adapter) and "hooks added"  # what the agent's config really holds
            step(f"{adapter['title']} hooks", f"guard agent add {adapter['name']}",
                 f"{adapter['title']} is here without guard's hooks. Add them (you see the diff first)?", add_hooks)

    if not done and not left:
        console.print("[green]✅ Setup complete: nothing is missing.[/green]")
        return done, left
    table = Table(title="🧩 guard setup", show_header=True, header_style="bold magenta")
    table.add_column("Item", style="bold")
    table.add_column("Result")
    for item, what in done:
        table.add_row(item, f"[green]✅ {what}[/green]")
    for item, what in left:
        table.add_row(item, f"[yellow]⏳ {what}[/yellow]")
    console.print(table)
    if left and not interactive:
        console.print("[yellow]Run these yourself in an interactive terminal (or run `guard setup` there).[/yellow]")
    return done, left


@app.command("setup")
def setup_cmd():
    """
    Do what is still missing on this machine: LLM, Alibaba OCR (installed and synced), commit mode,
    and guard's hooks in the agents found here. Asks before each step; `guard install` and
    `guard update` run it at the end.
    """
    finish_setup(Path.cwd())


def _print_install(result) -> None:
    ok, messages = result
    for msg in messages:
        style = "yellow" if msg.startswith("WARN") else "green"
        console.print(f"[{style}]• {msg}[/{style}]")
    if not ok:
        raise typer.Exit(code=1)


@app.command("install")
def install_cmd(
    workspace: Optional[str] = typer.Option(
        None, "--workspace", "-w",
        help="Guard only this folder: agent docs in it, Git hooks in every repository below it",
    ),
):
    """
    Install guard. Default (global): Git hooks for every repository on this machine plus the guard
    directives in the global instruction files of the agents found here (Claude Code, Codex,
    Gemini CLI, opencode). Repositories are then set up automatically the first time guard runs.
    """
    if workspace:
        _print_install(install_workspace(Path(workspace)))
        console.print("[bold green]✅ Guard active in this workspace only.[/bold green]")
    else:
        _print_install(install_global(Path.cwd()))
        console.print("[bold green]✅ Guard active on this machine. Agents read the directives; repositories set themselves up on first use.[/bold green]")
    # Do what is still missing (LLM, OCR, commit mode, agent hooks), then show what remains
    cwd = Path(workspace) if workspace else Path.cwd()
    finish_setup(cwd)
    print_setup_health(cwd, "🧩 guard setup check", only_problems=True)


@app.command("uninstall")
def uninstall_cmd(
    workspace: Optional[str] = typer.Option(None, "--workspace", "-w", help="Remove guard from this workspace only"),
):
    """
    Remove what `guard install` added: the marked directive blocks and guard's Git hooks
    (global core.hooksPath is unset only when it points at guard's hooks).
    """
    messages = uninstall_workspace(Path(workspace)) if workspace else uninstall_global()
    for msg in messages or ["nothing to remove"]:
        console.print(f"[yellow]• {msg}[/yellow]")


# Subcommand: guard hook
hook_app = typer.Typer(
    name="hook",
    help="🪝 Manage Guard Hooks in target repositories",
    no_args_is_help=False,
)
app.add_typer(hook_app, name="hook")


@hook_app.command("refresh")
def hook_refresh_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Also set up / refresh this repository"),
):
    """
    Rewrite what guard installed earlier to the current version: global hooks, guard blocks in
    repository hooks and the directive block in agent docs (only where guard markers exist).
    """
    target = Path(repo).resolve() if repo else Path.cwd().resolve()
    messages = refresh_after_upgrade(force=True) + ensure_repo_setup(target, create_invariants=False) + refresh_repo_if_git(target)
    for msg in messages or ["everything is already up to date"]:
        style = "yellow" if msg.startswith("WARN") else "green"
        console.print(f"[{style}]• {msg}[/{style}]")
    print_setup_health(target, "🧩 guard setup check", only_problems=True)


def refresh_repo_if_git(path: Path) -> List[str]:
    root = git_root(path)
    return refresh_repo(root) if root else []


@hook_app.command("install")
def hook_install_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
    mode: Optional[str] = typer.Option(None, "--mode", "-m", help="Mode: 'git' (stealth), 'agent', or 'all'"),
    stealth: bool = typer.Option(False, "--stealth", "-s", help="Shortcut for --mode git (Zero workspace footprint, Git hooks only)"),
    global_hooks: bool = typer.Option(False, "--global", "-g", help="Configure Git hooks globally (git config --global core.hooksPath ~/.guard/hooks)"),
    all_repos: bool = typer.Option(False, "--all-repos", help="Install Git hooks to all discovered child Git repositories in workspace"),
    select_repos: Optional[str] = typer.Option(None, "--select-repos", help="Comma-separated indices (1,2) or names of child repositories"),
):
    """
    Legacy entry point, kept for existing scripts: prefer `guard install` (global) or
    `guard install --workspace <dir>`. Without options this is the same as `guard install`.
    """
    if not any([repo, mode, stealth, all_repos, select_repos, global_hooks]):
        console.print("[dim]`guard hook install` is now `guard install`; running the global install.[/dim]")
        _print_install(install_global(Path.cwd()))
        return
    console.print("[dim]Note: prefer `guard install` (global) or `guard install --workspace <dir>`.[/dim]")

    if global_hooks:
        console.print("[cyan]Configuring Global Git Hooks (~/.guard/hooks)...[/cyan]")
        success, msgs = HookInstaller.install_global_git_hooks()
        for m in msgs:
            console.print(f"[green]• {m}[/green]")
        if success:
            console.print("[bold green]✅ Global Git Hooks active! Every Git repository on this machine is protected.[/bold green]")
        else:
            console.print("[bold red]❌ Failed to configure global Git hooks.[/bold red]")
            raise typer.Exit(code=1)
        # Set up the current repository now instead of on the first guard run
        for msg in ensure_repo_setup(Path.cwd()):
            console.print(f"[green]• {msg}[/green]")
        console.print("[dim]Other repositories are set up automatically the first time guard runs in them.[/dim]")
        return

    target_path = Path(repo).resolve() if repo else Path.cwd().resolve()
    installer = HookInstaller(target_path)

    # 1. Multi-Repo Workspace Auto-Discovery (when current folder has no .git)
    if not installer.is_git_repo():
        child_repos = installer.find_child_git_repos()
        if child_repos:
            console.print(f"\n[bold cyan]🔍 Workspace Mode:[/bold cyan] Current directory has no .git, but found [bold green]{len(child_repos)}[/bold green] child Git repositories:")
            for idx, cr in enumerate(child_repos, start=1):
                rel = cr.relative_to(target_path)
                console.print(f"  [bold yellow][{idx}][/bold yellow] ./{rel} [dim](.git)[/dim]")
            console.print("  [bold green][A][/bold green] All repositories (Install to all child repos)")
            console.print("  [bold magenta][G][/bold magenta] Global Git Hooks (Configure git config --global core.hooksPath - protects ALL repos on machine)")
            console.print("  [dim][N][/dim] None (Skip Git hooks, install workspace Agent Directives at root only)\n")
            # Respect --mode / --stealth in workspace mode
            effective_mode = "git" if stealth else (mode.lower().strip() if mode else "all")

            chosen_repos: List[Path] = []
            if effective_mode != "agent":
                if all_repos:
                    chosen_repos = child_repos
                elif select_repos:
                    parts = [p.strip() for p in select_repos.split(",")]
                    for p in parts:
                        if p.lower() in ("a", "all"):
                            chosen_repos = child_repos
                            break
                        elif p.isdigit() and 1 <= int(p) <= len(child_repos):
                            chosen_repos.append(child_repos[int(p) - 1])
                        else:
                            for cr in child_repos:
                                if cr.name == p or str(cr.relative_to(target_path)) == p:
                                    chosen_repos.append(cr)
                    if not chosen_repos:
                        console.print(f"[bold yellow]⚠️ No child repositories matched '--select-repos {select_repos}'.[/bold yellow]")
                elif sys.stdin and sys.stdin.isatty():
                    ans = typer.prompt("Select repositories to install Git hooks into [A, 1-N, G, N]", default="A").strip()
                    if ans.lower() in ("g", "global"):
                        console.print("\n[cyan]Configuring Global Git Hooks (~/.guard/hooks)...[/cyan]")
                        g_success, g_msgs = HookInstaller.install_global_git_hooks()
                        for m in g_msgs:
                            console.print(f"[green]• {m}[/green]")
                        if g_success:
                            console.print("[bold green]✅ Global Git Hooks active! Every Git repository on this machine is protected.[/bold green]")
                        chosen_repos = []
                    elif ans.lower() in ("a", "all", "y", "yes"):
                        chosen_repos = child_repos
                    elif ans.lower() in ("n", "no", "none", ""):
                        chosen_repos = []
                    else:
                        for s in ans.replace(" ", ",").split(","):
                            s = s.strip()
                            if s.isdigit() and 1 <= int(s) <= len(child_repos):
                                chosen_repos.append(child_repos[int(s) - 1])
                else:
                    chosen_repos = child_repos
            installed_count = 0
            if chosen_repos:
                console.print(f"\n[cyan]Installing Git hooks into {len(chosen_repos)} repository(s)...[/cyan]")
                res = installer.install_multi(chosen_repos, mode="git")
                for r_path, r_info in res.items():
                    r_rel = Path(r_path).relative_to(target_path)
                    if r_info["success"]:
                        installed_count += 1
                        console.print(f"  [bold green]✅ Git hooks active in: ./{r_rel}[/bold green]")
                    else:
                        console.print(f"  [red]❌ Failed in: ./{r_rel}[/red]")

            # Install workspace agent directives at root if mode is 'agent' or 'all'
            agent_installed = False
            if effective_mode in ("agent", "all"):
                console.print("\n[cyan]Installing Workspace Agent Directives (CLAUDE.md & AGENT.md) at root...[/cyan]")
                success, msgs = installer.install(mode="agent")
                for m in msgs:
                    console.print(f"[green]• {m}[/green]")
                agent_installed = success

            if installed_count > 0 and agent_installed:
                console.print("[bold green]✅ Hybrid Workspace Protection Active (Git Hooks in sub-repos + Agent Directives at root)[/bold green]")
            elif installed_count > 0:
                console.print(f"[bold green]✅ Git hooks installed into {installed_count} repository(s).[/bold green]")
            elif agent_installed:
                console.print("[bold green]✅ Agent Directives installed at workspace root.[/bold green]")
            else:
                console.print("[yellow]ℹ️ No hooks or directives were installed.[/yellow]")
            return
    # 2. Standard Single-Repo Installation
    if stealth:
        selected_mode = "git"
    elif mode:
        m = mode.lower().strip()
        if m in ("git", "stealth", "1"):
            selected_mode = "git"
        elif m in ("agent", "2"):
            selected_mode = "agent"
        elif m in ("all", "dual", "3"):
            selected_mode = "all"
        else:
            console.print(f"[bold red]❌ Invalid mode '{mode}'. Choose 'git' (or --stealth), 'agent', or 'all'.[/bold red]")
            raise typer.Exit(code=1)
    else:
        # Interactive selection if terminal is interactive
        if sys.stdin and sys.stdin.isatty():
            console.print("\n[bold cyan]🛡️  Banh-Mi-Guard Installation Setup[/bold cyan]")
            console.print("Choose how you want Guard to protect this workspace:\n")
            console.print("  [bold green][1] 👻 Stealth Mode (Git Hooks Only - Recommended for company/shared repos)[/bold green]")
            console.print("      • Installs local .git/hooks/pre-commit gate")
            console.print("      • [bold]ZERO files added to workspace root[/bold] (Never pushed to remote repo)")
            console.print("  [bold yellow][2] 🤖 Agent Directives Only (CLAUDE.md & AGENT.md)[/bold yellow]")
            console.print("      • Injects AI guidelines directly into workspace root")
            console.print("      • No Git hooks installed")
            console.print("  [bold magenta][3] 🛡️  Dual-Gate Full Protection (Git Hooks + Agent Directives)[/bold magenta]")
            console.print("      • Maximum protection: both pre-commit gate and AI agent instructions\n")

            choice_map = {
                "1": "git", "git": "git", "stealth": "git",
                "2": "agent", "agent": "agent",
                "3": "all", "all": "all", "dual": "all",
            }
            while True:
                choice = typer.prompt("Select installation mode [1-3]", default="1")
                choice_clean = choice.strip().lower()
                if choice_clean in choice_map:
                    selected_mode = choice_map[choice_clean]
                    break
                console.print("[yellow]Invalid choice. Please enter 1, 2, or 3.[/yellow]")
        else:
            selected_mode = "all"
            console.print("[dim]• Non-interactive environment: defaulting to mode 'all' (use --stealth for git-only)[/dim]")

    success, messages = installer.install(mode=selected_mode)
    for m in messages:
        console.print(f"[green]• {m}[/green]")
    if success:
        mode_desc = {
            "git": "Ghost/Stealth Mode (Git hooks only, zero workspace footprint)",
            "agent": "Agent Directives Mode (CLAUDE.md & AGENT.md)",
            "all": "Dual-Gate Full Protection Mode (Git hooks + Agent directives)",
        }.get(selected_mode, selected_mode)
        console.print(f"[bold green]✅ Guard installed successfully! ({mode_desc})[/bold green]")
    else:
        console.print("[bold red]❌ Failed to install Guard hooks.[/bold red]")


@hook_app.command("uninstall")
def hook_uninstall_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
    mode: str = typer.Option("all", "--mode", "-m", help="Mode to uninstall: 'git', 'agent', or 'all'"),
    global_hooks: bool = typer.Option(False, "--global", "-g", help="Uninstall global Git hooks (git config --global --unset core.hooksPath)"),
):
    """
    Safely uninstall Guard hooks and restore previous user files.
    """
    if global_hooks:
        success, messages = HookInstaller.uninstall_global_git_hooks()
        for m in messages:
            console.print(f"[yellow]• {m}[/yellow]")
        console.print("[bold green]✅ Global Git hooks uninstalled.[/bold green]")
        return

    installer = HookInstaller(Path(repo) if repo else None)
    success, messages = installer.uninstall(mode=mode)
    for m in messages:
        console.print(f"[yellow]• {m}[/yellow]")
    console.print("[bold green]✅ Guard hooks uninstalled.[/bold green]")


@hook_app.command("status")
def hook_status_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
):
    """
    Check active hook status and AI agent directives in target repository.
    """
    installer = HookInstaller(Path(repo) if repo else None)
    status = installer.get_status()

    mode_labels = {
        "all": "[bold magenta]🛡️ Dual-Gate Full Protection (Git Hooks + Agent Directives)[/bold magenta]",
        "git": "[bold green]👻 Stealth Mode (Git Hooks Only - Zero Workspace Footprint)[/bold green]",
        "agent": "[bold yellow]🤖 Agent Directives Only (CLAUDE.md & AGENT.md)[/bold yellow]",
        "none": "[dim]⚪ Inactive (No Guard hooks or directives active)[/dim]",
    }
    mode_label = mode_labels.get(status.get("mode", "none"), "[dim]⚪ Inactive[/dim]")
    console.print(f"\n[bold]Active Profile:[/bold] {mode_label}\n")

    table = Table(title=f"🪝 Guard Hook & Agent Status ({installer.repo_path.name})", show_header=True)
    table.add_column("Component / Directive", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Target / Notes")

    table.add_row("Git Repository", "✅ Yes" if status["is_git_repo"] else "❌ No", "Git VCS")
    g_stat = HookInstaller.get_global_hooks_status()
    table.add_row("Global Git Hooks", "✅ Active" if g_stat["is_active"] else "⚪ Inactive", g_stat["configured_path"] or "git config --global core.hooksPath (~/.guard/hooks)")
    table.add_row("Git prepare-commit-msg", "✅ Active" if status["prepare_commit_msg_installed"] else "⚪ Inactive", ".git/hooks/prepare-commit-msg")
    table.add_row("Local Git Exclude", "✅ Active" if status.get("git_exclude_active") else "⚪ Inactive", ".git/info/exclude (.guard/ hidden)")
    table.add_row("CLAUDE.md Directive", "✅ Active" if status["claude_md_active"] else "⚪ Inactive", "Directives for omp & Claude Code")
    table.add_row("AGENT.md Directive", "✅ Active" if status["agent_md_active"] else "⚪ Inactive", "Directives for Cursor, Windsurf, Aider")
    table.add_row("Agent Wrapper (.guard/bin)", "✅ Active" if status["agent_wrapper_installed"] else "⚪ Inactive", ".guard/bin/guard-exec")

    console.print(table)

    # If in a multi-repo workspace (no root git), report status of child git repos
    if not status["is_git_repo"]:
        child_repos = installer.find_child_git_repos()
        if child_repos:
            console.print(f"\n[cyan]🔍 Discovered {len(child_repos)} child Git repositories in workspace:[/cyan]")
            sub_table = Table(title="Child Repositories Hook Status", show_header=True)
            sub_table.add_column("Repository", style="bold")
            sub_table.add_column("pre-commit", justify="center")
            sub_table.add_column("prepare-commit-msg", justify="center")
            for cr in child_repos:
                sub_installer = HookInstaller(cr)
                sub_stat = sub_installer.get_status()
                rel = cr.relative_to(installer.repo_path)
                sub_table.add_row(
                    f"./{rel}",
                    "✅ Active" if sub_stat["pre_commit_installed"] else "⚪ Inactive",
                    "✅ Active" if sub_stat["prepare_commit_msg_installed"] else "⚪ Inactive",
                )
            console.print(sub_table)


@app.command("finding")
def finding_cmd(
    finding_id: str = typer.Argument(..., help="Id shown in the post report, e.g. 3f9a1c2b"),
    defer: Optional[str] = typer.Option(None, "--defer", help="Deferred: why, and where it will be handled"),
    reject: Optional[str] = typer.Option(None, "--reject", help="Rejected: the evidence that the finding is wrong"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
):
    """
    Record a deferral or a rejection of a finding for the next review of this task. The next review
    sees the reason; a finding still blocks until the review agrees or it is fixed.
    """
    if (defer is None) == (reject is None) or not (defer or reject or "").strip():
        console.print("[bold red]❌ Give exactly one of --defer or --reject, with a reason.[/bold red]")
        raise typer.Exit(code=1)
    mgr = SessionManager(Path(repo).resolve() if repo else Path.cwd().resolve())
    session = mgr.load_local_session()
    entry = next((e for e in (session.findings_ledger if session else []) if e.get("id") == finding_id), None)
    if entry is None:
        console.print(f"[bold red]❌ No finding {finding_id!r} in this session's ledger.[/bold red]")
        raise typer.Exit(code=1)
    entry["status"], entry["note"] = ("deferred", defer) if defer is not None else ("rejected", reject)
    mgr._save(session)
    console.print(f"[bold green]✅ Finding {finding_id} {entry['status']}; the next review sees why.[/bold green]")


@app.command("accept")
def accept_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
):
    """
    For the user, in an interactive terminal: decide a task that used its review rounds (needs_user).
    Accept the remaining findings as follow-ups (approves exactly the files last reviewed), or allow
    three more rounds. An agent cannot run it: it needs a terminal.
    """
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        console.print("[bold red]❌ guard accept is the user's decision: run it yourself in an interactive terminal.[/bold red]")
        raise typer.Exit(code=1)
    target = Path(repo).resolve() if repo else Path.cwd().resolve()
    mgr = SessionManager(target)
    session = mgr.load_local_session()
    if session is None or session.status != SessionStatus.NEEDS_USER or not session.post:
        console.print("[yellow]No task is waiting for a decision (status needs_user).[/yellow]")
        return
    post = session.post
    reviewed = post.reviewed_fingerprints
    # Every reviewed file is as it was reviewed, and nothing unreviewed has changed since
    changed = [f for f, h in reviewed.items() if _fingerprint(target / f) != h]
    changed += [f for f in GitDiffInspector(target).get_working_files() if f not in reviewed]
    # Accepting covers the LLM's findings only: the LLM reviews only after build, invariants and scope
    # passed, and they must still show passed in the round being accepted
    gates_failed = (post.review_mode != "llm_deep" or (post.build_check is not None and not post.build_check.passed)
                    or bool(post.out_of_scope_files)
                    or any(v.rule_id.startswith("OCR-") and v.severity in ("HIGH", "CRITICAL") for v in post.rule_violations)
                    or (post.invariant_result is not None and any(c.status == "failed" for c in post.invariant_result.checks)))
    # Everything the task still carries: every follow-up, what is still open, and any raised again last round
    carried = _followups(session.findings_ledger)
    remaining = [e for e in session.findings_ledger if e in carried or e.get("status") == "open"
                 or e.get("round") == session.llm_rounds]
    for e in remaining:
        console.print(f"  • [{e.get('id')}] {e.get('status')} {e.get('severity')} {e.get('kind')} {e.get('location')}: {e.get('description')}", markup=False)
    choice = typer.prompt("Accept these as follow-ups and approve (a), allow three more rounds (c), or quit (q)?", default="q").strip().lower()
    if choice == "a" and (changed or gates_failed):
        if changed:
            console.print("[bold red]❌ Changed since the last review:[/bold red] ", end="")
            console.print(", ".join(changed[:10]), markup=False)
        else:
            console.print("[bold red]❌ The last round did not pass build, invariants and scope; only the LLM's findings can be accepted.[/bold red]")
        console.print("Restore the reviewed files, or allow more rounds (c) and run guard post.")
        raise typer.Exit(code=1)
    if choice == "a":
        session.status = SessionStatus.COMPLETED
        session.post.approved_fingerprints = dict(reviewed)
        session.post.all_passed, session.post.accepted_by_user = True, True
        session.post.followups, session.post.needs_user = remaining, False
        mgr._save(session)
        _write_post_report(target, session.post, session.pre)
        console.print("[bold green]✅ Approved by you; the remaining findings are kept as follow-ups.[/bold green]")
    elif choice == "c":
        session.revise_budget += 3
        session.status, session.post.needs_user = SessionStatus.NEEDS_FIX, False
        mgr._save(session)
        _write_post_report(target, session.post, session.pre)
        console.print(f"[bold green]✅ Three more review rounds allowed (budget {session.revise_budget}).[/bold green]")
    else:
        console.print("[dim]Nothing changed.[/dim]")


@app.command("untracked")
def untracked_cmd(
    path: Optional[str] = typer.Argument(None, help="Untracked file or folder, e.g. plans/"),
    include: bool = typer.Option(False, "--include", help="Always include: a normal part of the repository"),
    ignore: bool = typer.Option(False, "--ignore", help="Always ignore: local info/exclude, no repository file changes"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
):
    """
    Decide once, per path, whether an untracked file or folder is part of the repository or always
    ignored. Run it again with the other flag to change the decision. Without a path: list them.
    """
    from guard.core.untracked import RegistryError, covers, decide, load_decisions, printable, shown, suggest, undecided
    target = git_root(Path(repo).resolve() if repo else Path.cwd().resolve())
    if target is None:
        console.print("[bold red]❌ Not inside a Git repository.[/bold red]")
        raise typer.Exit(code=1)
    if path is None:
        try:
            decisions = load_decisions(target)
            pending = undecided(target)
        except (RuntimeError, RegistryError) as e:
            console.print(f"[bold red]❌ Cannot list untracked paths: {shown(str(e))}[/bold red]")
            raise typer.Exit(code=1)
        for entry, choice in decisions.items():
            # Git still listing a path an "ignore" covers, or the same name as a file/folder in its
            # place, means that rule is not in effect for what is there now
            stale = choice == "ignore" and any(covers(entry, p) or p.rstrip("/") == entry.rstrip("/") for p in pending)
            note = " [yellow](not in effect: Git still lists it, decide again)[/yellow]" if stale else ""
            console.print(f"  {shown(entry)}: always {'included' if choice == 'include' else 'ignored'}{note}")
        for entry in pending:
            console.print(f"  {shown(entry)}: [yellow]not decided[/yellow] ({suggest(entry)})")
        return
    if include == ignore:
        console.print("[bold red]❌ Choose exactly one: --include or --ignore.[/bold red]")
        raise typer.Exit(code=1)
    try:
        console.print(f"[bold green]✅ {decide(target, path, 'include' if include else 'ignore')}[/bold green]")
    except ValueError as e:
        console.print("[bold red]❌[/bold red] ", end="")
        console.print(printable(str(e)), markup=False)
        raise typer.Exit(code=1)


AGENT_TEST_FLAG = "agent-test.json"  # present while `guard agent test` listens: every event is logged

agent_app = typer.Typer(name="agent", help="🤖 Put guard on an agent's path through its hooks", no_args_is_help=True)
app.add_typer(agent_app, name="agent")


def _adapter_or_exit(name: str) -> dict:
    from guard.agent.adapter import BUILT_IN, load_adapter
    adapter = load_adapter(name)
    if adapter is None:
        console.print(f"[bold red]❌ No adapter named {name!r}.[/bold red] Built in: {', '.join(BUILT_IN)}")
        raise typer.Exit(code=1)
    return adapter


def _unchanged_since_diff(path: Path, shown: dict) -> None:
    """The config is written only as confirmed: if it changed while the diff was on screen, nothing is written."""
    from guard.agent.adapter import AdapterError, read_config
    try:
        now = read_config(path)
    except AdapterError as e:
        now = str(e)
    if now != shown:
        console.print(f"[bold red]❌ {path} changed while you were reading the diff; nothing was written. Run the command again.[/bold red]")
        raise typer.Exit(code=1)


def _forget_switches(name: str, path: Path) -> None:
    """Delete the record of what guard switched on; one left behind would be trusted by a later add, so it is said."""
    from guard.agent.adapter import switched_path
    try:
        switched_path(name).unlink(missing_ok=True)
    except OSError as e:
        console.print(f"[bold red]❌ Guard's hooks are out of {path}, but {switched_path(name)} could not be deleted "
                      f"({e}). Delete it yourself before adding guard again.[/bold red]", highlight=False)
        raise typer.Exit(code=1)


def _file_state(path: Path):
    """A file's bytes, None when there is none (an empty file is not an absent one), False when it cannot be read."""
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        return False


def _file_unchanged(path: Path, shown) -> None:
    """A file is written or deleted only as shown: if it changed while the question was on screen, nothing happens."""
    if _file_state(path) != shown or shown is False:
        console.print(f"[bold red]❌ {path} changed while you were reading; nothing was done. Run the command again.[/bold red]")
        raise typer.Exit(code=1)


def _test_listening() -> bool:
    """`guard agent test` started less than an hour ago (an abandoned test stops logging by itself)."""
    from guard.core.repo_setup import guard_home
    try:
        since = datetime.fromisoformat(json.loads((guard_home() / AGENT_TEST_FLAG).read_text(encoding="utf-8"))["since"])
    except (OSError, ValueError, KeyError, TypeError):
        return False
    return (datetime.now(timezone.utc) - since).total_seconds() < 3600


def _show_diff(text: str) -> None:
    for line in text.splitlines():
        style = "green" if line.startswith("+") and not line.startswith("+++") else (
            "red" if line.startswith("-") and not line.startswith("---") else "dim")
        console.print(line, style=style, markup=False, highlight=False)


def _home_relative(path: Path) -> str:
    """A config file as discovery shows it (`~/…`, `%APPDATA%/…`), never a full path with the user's name."""
    from guard.agent.discover import _shown
    return _shown(path, path.parent, Path.home())


def _cannot_set_up(name: str, problem: str, inv=None) -> None:
    """Tell the user guard could not make this agent work, what they can do, and exit."""
    from guard.agent.discover import issue_url
    console.print(f"[bold yellow]⚠️ Guard could not set up {name}:[/bold yellow] ", end="")
    console.print(problem, markup=False, highlight=False)
    console.print(
        f"What you can do: look in {name}'s documentation for hooks that run a command before an edit or a shell "
        f"command (then [bold]guard agent fix {name} --note \"<what the docs say>\"[/bold]), or ask for support with "
        "this prefilled GitHub issue (read it first; guard sends nothing itself):")
    console.print(issue_url(name, problem, inv), markup=False, highlight=False, soft_wrap=True)
    console.print(f"Until then guard still protects {name} through the agent directive and the Git pre-commit hook.")
    raise typer.Exit(code=1)


def _proposed_adapter(name: str, inv, previous: Optional[dict] = None, log: str = "") -> dict:
    """The LLM's adapter after validation (one retry with the problems named), or exit with what to do next."""
    from guard.agent.adapter import NOT_JSON, validate_adapter
    from guard.agent.discover import propose
    from guard.core.llm_client import LLMClientError
    problems: List[str] = []
    for _ in range(2):
        try:
            proposal = propose(_work_llm(), inv, previous=previous, problems=problems, log=log)
        except (LLMClientError, ValueError) as e:
            console.print(f"[bold red]❌ The LLM gave no usable adapter:[/bold red] {printable_error(e)}", highlight=False)
            console.print("Registering an agent needs a working LLM: check it with [bold]guard config test[/bold] "
                          "(set it up with [bold]guard config llm[/bold]).")
            _cannot_set_up(name, f"the LLM gave no usable adapter ({type(e).__name__})", inv)
        if "no_hooks" in proposal:
            _cannot_set_up(name, f"no hooks guard can use ({str(proposal['no_hooks'])[:300]})", inv)
        proposal["name"] = name  # the adapter is registered under the name the user typed
        problems = [p for p in validate_adapter(proposal) if p != NOT_JSON]
        if not problems:
            return proposal
    _cannot_set_up(name, "the proposed adapter is not safe to install: " + "; ".join(problems), inv)


def _work_llm():
    """The configured LLM without a time limit, as for a review: llm.timeout is only for `guard config test` pings."""
    return load_config(Path.cwd()).llm.model_copy(update={"timeout": None})


def printable_error(e: Exception) -> str:
    return " ".join(str(e).split())[:300]


def _investigate(name: str, need_found: bool = True):
    """
    What this machine says about an agent guard does not know, or exit with what to do next. With
    `need_found` False (fix with a note), an agent nothing points to goes on with the note alone.
    """
    from guard.agent.discover import investigate
    try:
        inv = investigate(name)
    except ValueError as e:
        console.print(f"[bold red]❌ {name!r}: {e}.[/bold red]", highlight=False)
        raise typer.Exit(code=1)
    console.print(f"[cyan]🔎 {name}: binary {inv.binary or 'not on PATH'}; {len(inv.listing)} config file(s) found, "
                  f"{len(inv.files)} read as structure only (no text values).[/cyan]")
    for note in inv.notes:
        console.print(f"[dim]{note}[/dim]", highlight=False)
    if need_found and not inv.found():
        _cannot_set_up(name, "it is not on PATH and has no config folder in your home folder", inv)
    return inv


def _write_text_atomic(path: Path, text: str) -> None:
    import os
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="." + path.name + ".", suffix=".guard-tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _install_extension(adapter: dict, name: str) -> None:
    """omp, pi, opencode: guard writes one file of its own (shown first, confirmed); a file of anyone else's stays."""
    import difflib
    from guard.agent.adapter import (
        AdapterError, adapters_dir, config_path, extension_is_guards, extension_text, save_adapter, _record_name,
    )
    path = config_path(adapter)
    if path.exists() and not extension_is_guards(adapter):
        console.print(f"[bold red]❌ {path} is not guard's file:[/bold red] guard does not replace it. Move it away, then add again.")
        raise typer.Exit(code=1)
    try:
        text = extension_text(adapter)
    except AdapterError as e:
        console.print(f"[bold red]❌ {e}[/bold red]", highlight=False)
        raise typer.Exit(code=1)
    seen = _file_state(path)
    old = seen.decode("utf-8", errors="replace") if isinstance(seen, bytes) else ""
    if old == text:
        save_adapter(adapter)
        console.print(f"[green]✅ {adapter['title']} already loads guard's {path.name} ({path}).[/green]")
        return
    _show_diff("".join(difflib.unified_diff(old.splitlines(keepends=True), text.splitlines(keepends=True), str(path), str(path))))
    if not typer.confirm(f"Write guard's {path.name} to {path}?", default=False):
        console.print("[dim]Nothing changed.[/dim]")
        raise typer.Exit(code=1)
    _file_unchanged(path, seen)  # before anything is saved: never replaces a file put there meanwhile
    record = adapters_dir() / f"{_record_name(name)}.json"
    kept = record.read_bytes() if record.is_file() else None
    save_adapter(adapter)  # the record first, as for a config
    try:
        _write_text_atomic(path, text)
    except OSError as e:  # the file is as it was: so is the record
        if kept is None:
            record.unlink(missing_ok=True)
        else:
            record.write_bytes(kept)
        console.print(f"[bold red]❌ {e}[/bold red]", highlight=False)  # the full error, on this screen only
        _cannot_set_up(name, f"writing {_home_relative(path)} failed ({type(e).__name__})")
    events = ", ".join(sorted({h["event"] for h in adapter["hooks"]}))
    console.print(f"[bold green]✅ {adapter['title']} now calls guard on: {events}.[/bold green] Restart it so it loads the file.")
    console.print(f"Check it with [bold]guard agent test {name}[/bold]; undo with [bold]guard agent remove {name}[/bold].")


def _install_adapter(adapter: dict, name: str) -> None:
    """Show the config diff, confirm, back up and write; a config guard cannot edit gets the entries to add by hand."""
    from guard.agent.adapter import (
        AdapterError, adapters_dir, config_path, diff, dump, guard_command, installed, load_adapter, others_under,
        read_config, save_adapter, switched_on, switched_path, with_guard, write_config, _at, _entry, _record_name,
    )
    _registered_ok(adapter, name)  # every install, including one from a record written earlier
    for limit in adapter.get("limits") or []:  # what guard cannot do for this agent, said before anything is written
        console.print("[yellow]⚠️ [/yellow]", end="")
        console.print(limit, markup=False, highlight=False)
    if adapter.get("kind") == "extension":
        _install_extension(adapter, name)
        return
    path = config_path(adapter)
    try:
        before = read_config(path, adapter) if path.suffix == ".json" else {}
        after = with_guard(before, adapter)  # builds guard's entries: refuses a command a shell would misread
    except AdapterError as e:
        console.print(f"[bold red]❌ {e}[/bold red]", highlight=False)  # the full error, on this screen only
        _cannot_set_up(name, f"{_home_relative(path)} could not be read or filled ({type(e).__name__})")
    if path.suffix != ".json":
        entries: dict = {}  # every entry of an event, in order (one event may carry several matchers)
        for h in adapter["hooks"]:
            entries.setdefault(h["harness_event"], []).append(_entry(adapter, h, guard_command()))
        console.print(f"[bold yellow]⚠️ {path} is not JSON: guard does not edit it.[/bold yellow] These are the hook "
                      "entries to add there yourself, in its own format:")
        console.print(dump(entries), markup=False, highlight=False)
        if not typer.confirm(f"Register this adapter for {name} (guard answers these hooks with it)?", default=False):
            console.print("[dim]Nothing changed.[/dim]")
            raise typer.Exit(code=1)
        save_adapter(adapter)  # agent-event reads its answers from it
        console.print(f"Add the entries, then check it with [bold]guard agent test {name}[/bold].")
        return
    change = diff(path, before, after)
    if not change:
        # the entries are in place, but the adapter decides how guard reads and answers them
        if load_adapter(name) != adapter:
            if not typer.confirm(f"{path} needs no change. Save the new adapter for {name}?", default=False):
                console.print("[dim]Nothing changed.[/dim]")
                raise typer.Exit(code=1)
            save_adapter(adapter)
        if not installed(adapter):  # the entries are there, but the agent's own switch is off (ZCode's hooks.enabled)
            console.print(f"[yellow]⚠️ Guard's entries are in {path}, but its hooks are switched off there "
                          "(hooks.enabled is false). Turn them on in that file; guard does not override your choice.[/yellow]")
            return
        console.print(f"[green]✅ {adapter['title']} already runs guard's hooks ({path}).[/green]")
        return
    _show_diff(change)
    switched = switched_on(adapter, before)
    others = others_under(adapter, before)
    if switched and others:
        console.print(f"[bold yellow]⚠️ This turns on {', '.join(switched)} in {path}: the {others} hook(s) already "
                      "there start running too.[/bold yellow] `guard agent remove` switches it back off.")
    if not typer.confirm(f"Write these hooks to {path}?", default=False):
        console.print("[dim]Nothing changed.[/dim]")
        raise typer.Exit(code=1)
    _unchanged_since_diff(path, before)
    # the adapter first: a config that calls `agent-event --agent <name>` must never exist without it
    record, switch_record = adapters_dir() / f"{_record_name(name)}.json", switched_path(name)
    kept = record.read_bytes() if record.is_file() else None
    kept_switch = switch_record.read_bytes() if switch_record.is_file() else None
    save_adapter(adapter)
    try:
        # what guard turns on now, so that remove turns exactly that back off; an earlier record stays
        # while the switch it names is still on (guard's hooks put back after being taken out by hand)
        try:
            earlier = json.loads(kept_switch) if kept_switch else []
        except ValueError:
            earlier = []
        still_on = [k for k in earlier if isinstance(k, str) and _at(before, k.split(".")) is True] \
            if isinstance(earlier, list) else []
        if switched or still_on:
            switch_record.write_text(json.dumps(sorted(set(switched) | set(still_on))), encoding="utf-8")
        else:
            switch_record.unlink(missing_ok=True)
        backup = write_config(path, after)
    except (OSError, AdapterError) as e:  # the config is as it was: so are the records about it
        for file, old in ((record, kept), (switch_record, kept_switch)):
            if old is None:
                file.unlink(missing_ok=True)
            else:
                file.write_bytes(old)
        console.print(f"[bold red]❌ {e}[/bold red]", highlight=False)  # the full error, on this screen only
        _cannot_set_up(name, f"writing {_home_relative(path)} failed ({type(e).__name__})")
    events = ", ".join(sorted({h["event"] for h in adapter["hooks"]}))
    if installed(adapter):
        console.print(f"[bold green]✅ {adapter['title']} now calls guard on: {events}.[/bold green]")
    else:  # written, but the agent's own switch is off (ZCode's hooks.enabled): nothing runs yet
        console.print(f"[yellow]⚠️ Guard's entries are in {path}, but its hooks are switched off there "
                      "(hooks.enabled is false). Turn them on in that file; guard does not override your choice.[/yellow]")
    if backup:
        console.print(f"[dim]Original kept as {backup}.[/dim]")
    console.print(f"Check it with [bold]guard agent test {name}[/bold]; undo with [bold]guard agent remove {name}[/bold].")


@agent_app.command("add")
def agent_add_cmd(
    name: str = typer.Argument(..., help="An agent, e.g. claude-code (built in), cursor, codex"),
):
    """
    Add guard's hooks to the agent's own config (global, never a repository file): shows the diff,
    asks you to confirm, keeps the original as <file>.guard.bak, and changes only guard's entries.
    An agent guard does not know is investigated first (binary, version, the structure of its config
    files without their values) and the configured LLM proposes the adapter, which guard validates;
    `guard agent test` then shows whether it really works. When guard cannot set it up, it says what
    you can do and prints a prefilled GitHub issue.
    """
    from guard.agent.adapter import load_adapter
    adapter = load_adapter(name)
    if adapter is None:
        adapter = _proposed_adapter(name, _investigate(name))
        console.print(f"[bold cyan]Proposed adapter for {name}[/bold cyan] (saved to ~/.guard/agents/{name}.json when installed):")
        console.print(json.dumps(adapter, indent=2), markup=False, highlight=False)
    _install_adapter(adapter, name)


def _registered_ok(adapter: dict, name: str) -> None:
    """
    A registered adapter is a file anyone can edit: it is validated again before guard writes with
    it, and it must be the adapter of the agent asked for (`name`), not another agent's record.
    """
    from guard.agent.adapter import BUILT_IN, NOT_JSON, validate_adapter
    if name in BUILT_IN and adapter is BUILT_IN[name]:
        return  # shipped with this guard version
    problems = [p for p in validate_adapter(adapter) if p != NOT_JSON]
    if isinstance(adapter, dict) and adapter.get("name") != name:
        problems.insert(0, f"name: the record is {adapter.get('name')!r}, not {name!r}")
    if problems:
        console.print(f"[bold red]❌ ~/.guard/agents/{name}.json is not safe to install:[/bold red]")
        for p in problems:
            console.print(f"  • {p}", markup=False, highlight=False)
        console.print(f"Regenerate it with [bold]guard agent fix {name}[/bold].")
        raise typer.Exit(code=1)


@agent_app.command("fix")
def agent_fix_cmd(
    name: str = typer.Argument(..., help="An agent (registered or not)"),
    note: str = typer.Option("", "--note", help="What went wrong, or what the agent's docs say about its hooks"),
):
    """
    Regenerate an agent's adapter from the current one (if any), the events guard received from it
    (guard agent test) and your note; the result is validated and installed like `guard agent add`.
    An agent `guard agent add` could not set up starts over here with your note.
    """
    from guard.agent.adapter import BUILT_IN, adapter_diff, load_adapter
    from guard.core.repo_setup import guard_home
    if name in BUILT_IN:
        console.print(f"[bold red]❌ {name} is built into guard: update guard instead.[/bold red]")
        raise typer.Exit(code=1)
    previous = load_adapter(name)  # None: add could not set it up, so this starts from the investigation
    inv = _investigate(name, need_found=not note)
    log_path = guard_home() / "agent-events.log"
    from guard.agent.discover import event_summary
    lines = [l for l in (log_path.read_text(encoding="utf-8", errors="replace").splitlines() if log_path.is_file() else [])
             if f" {name} " in l][-50:]
    log = event_summary(lines) + (f"\nThe user says: {note}" if note else "")  # the note is the user's own words
    adapter = _proposed_adapter(name, inv, previous=previous, log=log or "none")
    change = adapter_diff(previous or {}, adapter)
    if not change:
        console.print(f"[green]The LLM proposes no change to {name}'s adapter[/green]; checking its hooks are in place.")
    else:
        _show_diff(change)
    _install_adapter(adapter, name)  # also restores hook entries removed or gone stale in the agent's config


@agent_app.command("list")
def agent_list_cmd():
    """Built-in and registered agents, and whether each one's config runs guard's hooks now."""
    from guard.agent.adapter import BUILT_IN, adapters_dir, config_path, installed, load_adapter
    from guard.core.repo_setup import _agent_present
    registered = ({p.stem for p in adapters_dir().glob("*.json") if "." not in p.stem}  # not test or switch records
                  if adapters_dir().is_dir() else set())
    names = sorted(set(BUILT_IN) | registered)
    table = Table(title="🤖 Agents", show_header=True)
    for column in ("Name", "Agent", "Source", "On this machine", "Config", "Hooks"):
        table.add_column(column)
    for n in names:
        adapter = load_adapter(n)
        if adapter is None:
            continue
        extension = adapter.get("kind") == "extension"
        if adapter.get("name") != n or not isinstance(adapter.get("install" if extension else "config"), str) or not isinstance(adapter.get("hooks"), list):
            # an edited or broken record: shown, never allowed to hide the others
            table.add_row(n, "-", "registered", "-", "-", f"[red]broken record: guard agent fix {n}[/red]")
            continue
        path = config_path(adapter)
        here = "yes" if _agent_present(adapter) else "[dim]no[/dim]"
        state = ("add by hand" if not extension and path.suffix != ".json" else "[green]installed[/green]"
                 if installed(adapter) else "[yellow]not installed[/yellow]")
        table.add_row(n, adapter.get("title", n), "built in" if n in BUILT_IN else "registered", here, str(path), state)
    console.print(table)


@agent_app.command("remove")
def agent_remove_cmd(name: str = typer.Argument(..., help="Adapter, e.g. claude-code")):
    """
    For the user, in an interactive terminal: take guard's hooks out of the agent's config (only
    guard's entries; everything else stays as it is). An agent cannot remove its own guard.
    """
    from guard.agent.adapter import (
        AdapterError, config_path, diff, read_config, switched_path, without_guard, write_config, _at, _drop_at,
    )
    adapter = _adapter_or_exit(name)
    _registered_ok(adapter, name)  # an edited record cannot point remove at another config file
    path = config_path(adapter)
    if adapter.get("kind") == "extension":
        import difflib
        from guard.agent.adapter import extension_state, extension_text
        state = extension_state(adapter)
        if state in ("missing", "foreign"):
            console.print(f"[green]No guard file at {path}.[/green]")
            return
        seen = _file_state(path)
        if state == "stale":  # guard's file, but not as this guard writes it: what differs is shown first
            current = path.read_text(encoding="utf-8")
            console.print(f"[yellow]{path} differs from the file this guard writes (guard moved, another version, or "
                          "an edit):[/yellow]")
            _show_diff("".join(difflib.unified_diff(extension_text(adapter).splitlines(keepends=True),
                                                    current.splitlines(keepends=True), "guard's file", str(path))))
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            console.print("[bold red]❌ Removing guard's hooks is the user's decision: run it yourself in an interactive terminal.[/bold red]")
            raise typer.Exit(code=1)
        if not typer.confirm(f"Delete guard's file {path}?", default=False):
            console.print("[dim]Nothing changed.[/dim]")
            raise typer.Exit(code=1)
        _file_unchanged(path, seen)  # never deletes a file put there while the question was on screen
        path.unlink()
        console.print(f"[bold green]✅ {path} removed; restart {adapter['title']}.[/bold green]")
        return
    if path.suffix != ".json":
        console.print(f"[yellow]Guard does not edit {path}: remove the entries that run `guard agent-event` from it yourself.[/yellow]")
        return
    try:
        before = read_config(path, adapter)
    except AdapterError as e:
        console.print(f"[bold red]❌ {e}[/bold red]")
        raise typer.Exit(code=1)
    after = without_guard(before, adapter["name"], adapter)
    record = switched_path(name)
    try:  # the settings guard turned on at add (ZCode's hooks.enabled), still as guard left them
        switched = json.loads(record.read_text(encoding="utf-8")) if record.exists() else []
    except (OSError, ValueError):
        switched = None
    if not isinstance(switched, list) or not all(isinstance(k, str) for k in switched):
        console.print(f"[bold red]❌ {record} cannot be read, so guard does not know what it switched on in {path}."
                      "[/bold red] Nothing was changed. Delete that file to keep every switch as it is now, then run "
                      f"guard agent remove {name} again.", highlight=False)
        raise typer.Exit(code=1)
    own = {k for k, v in (adapter.get("defaults") or {}).items() if v is True} if isinstance(adapter.get("defaults"), dict) else set()
    # the diff below shows it before anything is written: a switch the user wants kept is kept by declining
    # (asked only in a terminal: without one, remove stops below before writing anything)
    if not record.exists() and before != after and sys.stdin.isatty() and sys.stdout.isatty():
        for key in sorted(own):
            if _at(after, key.split(".")) is True and typer.confirm(
                    f"{key} is on in {path}. Guard may have switched it on when it was added (before it kept a record "
                    "of that). Switch it off too? It also stops the other hooks there", default=False):
                switched.append(key)
    for key in switched:
        if key in own and _at(after, key.split(".")) is True:
            after = _drop_at(after, key.split("."))
    change = diff(path, before, after)
    if not change:
        _forget_switches(name, path)  # nothing of guard's there: nothing to switch back later
        console.print(f"[green]No guard hooks in {path}.[/green]")
        return
    _show_diff(change)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        console.print("[bold red]❌ Removing guard's hooks is the user's decision: run it yourself in an interactive terminal.[/bold red]")
        raise typer.Exit(code=1)
    if not typer.confirm(f"Remove guard's hooks from {path}?", default=False):
        console.print("[dim]Nothing changed.[/dim]")
        raise typer.Exit(code=1)
    _unchanged_since_diff(path, before)
    write_config(path, after)
    _forget_switches(name, path)
    console.print(f"[bold green]✅ Guard's hooks removed from {path}.[/bold green]")


@agent_app.command("test")
def agent_test_cmd(
    name: str = typer.Argument(..., help="Adapter, e.g. claude-code"),
    report: bool = typer.Option(False, "--report", help="Report the events that arrived since the test started, and stop listening"),
):
    """
    Check that the agent really calls guard. Step 1 starts listening; then, in the agent, ask for one
    small file edit in a repository with no guard session. Step 2 (--report) lists the events that
    arrived and whether the edit was blocked.
    """
    from guard.agent.adapter import installed
    from guard.core.repo_setup import guard_home
    adapter = _adapter_or_exit(name)
    flag, log_path = guard_home() / AGENT_TEST_FLAG, guard_home() / "agent-events.log"
    if not report:
        if not installed(adapter):
            console.print(f"[yellow]⚠️ {adapter['title']} does not run guard's hooks yet: guard agent add {name}[/yellow]")
        flag.parent.mkdir(parents=True, exist_ok=True)
        flag.write_text(json.dumps({"agent": name, "since": datetime.now(timezone.utc).isoformat()}), encoding="utf-8")
        console.print(f"[bold cyan]Listening.[/bold cyan] In {adapter['title']}, in a repository without a guard session, ask it to "
                      "create or edit one small file. Then run [bold]guard agent test " + name + " --report[/bold].")
        return
    try:
        started = json.loads(flag.read_text(encoding="utf-8"))
        since = started["since"] if isinstance(started, dict) and started.get("agent") == name else None
    except (OSError, ValueError, KeyError, TypeError):
        since = None
    if not isinstance(since, str):
        console.print(f"[bold red]❌ No test of {name} is running: start it with guard agent test {name}[/bold red]")
        raise typer.Exit(code=1)
    lines = []
    if log_path.is_file():
        lines = [l for l in log_path.read_text(encoding="utf-8", errors="replace").splitlines()
                 if l[:32] >= since[:32] and f" {name} " in l and " EVENT " in l]
    flag.unlink(missing_ok=True)
    def same(name: str) -> str:  # `PreToolUse`, `preToolUse` and `pre_tool_use` are one event
        return name.replace("_", "").lower()
    seen = {h["harness_event"]: [] for h in adapter["hooks"]}
    by_key = {same(e): e for e in seen}
    for line in lines:
        parts = line.split(" EVENT ", 1)[1].split()
        seen.setdefault(by_key.get(same(parts[0]), parts[0]), []).append(" ".join(parts[1:]))
    table = Table(title=f"🤖 {adapter['title']}: events since {since[:19]}", show_header=True)
    table.add_column("Harness event", style="bold")
    table.add_column("Arrived", justify="right")
    table.add_column("Decisions")
    for event, results in seen.items():
        table.add_row(event, str(len(results)), ", ".join(sorted(set(results))) or "[yellow]none[/yellow]")
    console.print(table)
    # the harness's own name for its before-edit hook (PreToolUse for Claude Code, preToolUse for Cursor, …)
    edit_events = {h["harness_event"] for h in adapter["hooks"] if h["event"] == "before-edit"}
    blocked_edit = any("-> block" in r for e in edit_events for r in seen.get(e, []))
    missing = [e for e, r in seen.items() if not r]
    from guard.agent.adapter import test_record_path  # what doctor shows as this agent's last test
    record = test_record_path(name)
    record.parent.mkdir(parents=True, exist_ok=True)
    from guard.agent.adapter import config_path, config_fingerprint
    record.write_text(json.dumps({"at": datetime.now(timezone.utc).isoformat(), "events": len(lines),
                                  "blocked_edit": blocked_edit, "missing": missing,
                                  "config": config_fingerprint(config_path(adapter))}), encoding="utf-8")
    if not lines:
        console.print("[bold red]❌ No event arrived: the agent is not calling guard.[/bold red] Restart the agent and try "
                      "once more; some agents only read their hooks at start.")
        _cannot_set_up(name, f"guard agent test: no event arrived from {adapter['title']} after an edit was asked for")
    if blocked_edit:
        # the log shows what guard answered, not what the agent did with it: only the user can see that
        console.print("[green]✅ Guard answered the edit with a block.[/green] Now check in the agent that the file was "
                      "NOT changed and that it showed guard's reason; if the edit went through anyway, run "
                      f"[bold]guard agent fix {name} --note \"the edit was not blocked\"[/bold].")
    else:
        console.print("[yellow]⚠️ No edit was blocked: ask for a file edit in a repository without a guard session.[/yellow] "
                      f"If you did and the edit went through, run [bold]guard agent fix {name} --note \"edits are not "
                      "blocked\"[/bold], or ask for support with this prefilled issue:")
        from guard.agent.discover import issue_url
        console.print(issue_url(name, f"guard agent test: events arrived from {adapter['title']} but no edit was blocked"),
                      markup=False, highlight=False, soft_wrap=True)
    if missing:
        console.print(f"[yellow]Events that did not arrive: {', '.join(missing)} (a stop arrives when the agent finishes its turn).[/yellow]")


@app.command("agent-event")
def agent_event_cmd(
    event: str = typer.Argument(..., help="prompt | before-edit | after-bash | stop | before-commit"),
    agent: Optional[str] = typer.Option(None, "--agent", "-a", help="Adapter whose field mapping and output style to use"),
):
    """
    Called by an agent harness hook with the hook payload (JSON) on stdin. Prints the decision as
    JSON; a block also exits 2 with the reason on stderr. A payload guard cannot read is allowed and
    logged: a broken adapter must never lock the user out of their agent.
    """
    from guard.agent.adapter import harness_event, load_adapter, render
    from guard.agent.events import EVENTS, Decision, decide, normalise
    from guard.core.repo_setup import guard_home

    if event not in EVENTS:
        console.print(f"[bold red]❌ Unknown event {event!r}; expected one of: {', '.join(EVENTS)}[/bold red]")
        raise typer.Exit(code=1)
    def log(message: str) -> None:
        try:
            path = guard_home() / "agent-events.log"
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"{datetime.now(timezone.utc).isoformat()} {agent or '-'} {event} {message}\n")
        except OSError:
            pass

    adapter = load_adapter(agent) if agent else None  # where this harness puts each field, how it reads answers
    payload: dict = {}
    try:
        # Harnesses send UTF-8 JSON; the console code page (cp1252 on Windows) would garble the user's prompt
        stream = getattr(sys.stdin, "buffer", None)
        raw = stream.read(MAX_EVENT_BYTES + 1).decode("utf-8", "replace") if stream else sys.stdin.read(MAX_EVENT_BYTES + 1)
        if len(raw) > MAX_EVENT_BYTES:
            raise ValueError(f"payload larger than {MAX_EVENT_BYTES} characters")
        payload = json.loads(raw) if raw.strip() else {}
        if not isinstance(payload, dict):
            raise ValueError(f"payload is a JSON {type(payload).__name__}, not an object")
        fields = adapter.get("fields") if adapter else None
        ev = normalise(event, payload, fields)
        if event != "stop" and not (ev.prompt or ev.tool or ev.file_paths or ev.command):
            log(f"INCOMPLETE payload without the fields this event needs (keys: {sorted(payload)[:12]})")
    except Exception as e:  # a payload guard cannot read: never break the agent because of guard
        ev, decision = None, Decision()
        log(f"UNREADABLE {type(e).__name__}: {e}")
    if ev is not None:
        try:
            decision = decide(ev)
        except Exception as e:  # guard's own failure: allowed, but the agent is told it was not checked
            decision = Decision(action="notify", reason=f"Guard could not check this action ({type(e).__name__}: {e}); it was allowed. Tell the user.")
            log(f"ERROR {type(e).__name__}: {e}")
    harness = harness_event(adapter, event, payload if isinstance(payload, dict) else {})
    if _test_listening():  # `guard agent test` is listening
        tool = f" tool={ev.tool}" if ev is not None and ev.tool else ""
        log(f"EVENT {harness or '-'}{tool} -> {decision.action}")
    out, err, code = render((adapter or {}).get("output"), harness, decision)
    sys.stdout.write(out)
    sys.stderr.write(err)
    if code:
        raise typer.Exit(code=code)


@app.command("review")
def review_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
    focus: str = typer.Option("all", "--focus", "-f", help="Quality pillar focus: 'all', 'security', 'memory', 'performance', 'ux', 'dead-code', 'simplicity'"),
):
    """
    Run Final Safety Review on current Git diff using the configured LLM.
    """
    target_repo = Path(repo).resolve() if repo else Path.cwd().resolve()
    inspector = GitDiffInspector(target_repo)
    raw_diff = inspector.get_diff() or ""
    if not raw_diff.strip():
        console.print("[yellow]Working tree is clean. Nothing to review.[/yellow]")
        return

    summary = inspector.parse_diff(raw_diff)
    rulebook = OCRRulebookRunner()
    violations = rulebook.scan_diff(raw_diff)

    hygiene = HygieneEngine(target_repo)
    if (focus or "").lower() in ("dead-code", "hygiene"):
        touched = [f.path for f in summary.files]
        hygiene_violations = hygiene.scan_focus_level(touched)
    else:
        hygiene_violations = hygiene.scan_diff_level(raw_diff, summary)
    violations.extend(hygiene_violations)

    simplicity = SimplicityEngine(target_repo)
    if (focus or "").lower() in ("simplicity", "yagni", "lazy"):
        touched = [f.path for f in summary.files]
        simplicity_violations = simplicity.scan_focus_level(touched)
    else:
        simplicity_violations = simplicity.scan_diff_level(raw_diff, summary)
    violations.extend(simplicity_violations)
    reviewer = LLMReviewerEngine(config=load_config(target_repo))
    dom_type = detect_domain(target_repo)

    verdict = reviewer.review(
        prompt="Manual review requested",
        domain=dom_type,
        diff_summary=summary,
        violations=violations,
        focus=focus,
    )

    badge_color = "green" if verdict.verdict == ReviewVerdict.APPROVED else "red"
    focus_label = f" | Focus: {verdict.focus_area.upper()}" if verdict.focus_area != "all" else ""
    console.print(Panel(
        f"[bold]{verdict.verdict.value}[/bold] (Mode: {verdict.review_mode}, Model: {verdict.reviewer_model}{focus_label}, Score: {verdict.score:.1f}/10)\n{verdict.summary}",
        title="🤖 LLM Code Review & Approval" if verdict.review_mode == "llm_deep" else "⚙️ Heuristic Review (LLM did not answer)",
        border_style=badge_color,
    ))


@app.command("update")
def update_cmd(
    target: str = typer.Argument("ocr", help="Update target: 'ocr' (Alibaba OCR) or 'self' (Banh-Mi-Guard)"),
    check_only: bool = typer.Option(False, "--check", "-c", help="Check for available updates without installing"),
    force: bool = typer.Option(False, "--force", "-f", help="Bypass the 3-day supply-chain quarantine cooling period"),
    quarantine_days: float = typer.Option(3.0, "--quarantine-days", "-q", help="Quarantine cooling period in days"),
):
    """
    Safely update Alibaba OCR (with 3-day supply-chain quarantine) or Guard CLI itself.
    """
    if target.lower() in ["self", "guard"]:
        if check_only:
            console.print("[cyan]Checking for Banh-Mi-Guard updates on GitHub...[/cyan]")
            check_res = check_guard_self_update(force=True)
            console.print(f"Installed Version: v{check_res.installed_version}")
            console.print(f"Latest Version:    v{check_res.latest_version or 'N/A'}")
            console.print(f"Status:            [bold]{check_res.status.value}[/bold]")
            console.print(f"Recommendation:    {check_res.recommendation}")
            return
        console.print("[cyan]Upgrading Banh-Mi-Guard CLI from GitHub...[/cyan]")
        success, msg = perform_self_upgrade()
        if success:
            console.print(f"[bold green]{msg}[/bold green]")
            _refresh_with_new_version()
            _run_new_version("setup")  # what the new version needs, asked by the new version
        else:
            console.print(f"[bold red]{msg}[/bold red]")
            raise typer.Exit(code=1)
        return

    # Default target: ocr
    console.print(f"[cyan]Checking updates for Alibaba OCR (@alibaba-group/open-code-review)...[/cyan]")
    check_res = check_ocr_update(quarantine_days=quarantine_days)

    if check_only:
        console.print(f"Installed Version: {check_res.installed_version or '(none)'}")
        console.print(f"Latest Version: v{check_res.latest_version or 'N/A'}")
        console.print(f"Security Status: [bold]{check_res.status.value}[/bold]")
        console.print(f"Recommendation: {check_res.recommendation}")
        return

    success, msg = perform_ocr_upgrade(force=force, quarantine_days=quarantine_days)
    if success:
        console.print(f"[bold green]{msg}[/bold green]")
        finish_setup(Path.cwd())  # a new OCR gets the current LLM, and anything else missing is offered
    else:
        console.print(f"[bold yellow]{msg}[/bold yellow]")
        if not force and "QUARANTINE" in msg:
            raise typer.Exit(code=1)


@app.command("doctor")
def doctor_cmd(
    check_updates: bool = typer.Option(True, "--updates/--no-updates", help="Check npm for Alibaba OCR updates with supply-chain quarantine"),
    quarantine_days: float = typer.Option(3.0, "--quarantine-days", "-q", help="Cooling period in days (default 3 days) to protect against zero-day backdoors"),
):
    """
    Check system health and audit Alibaba OCR supply-chain security updates.
    """
    console.print("[bold cyan]🩺 BANH-MI-GUARD SYSTEM DOCTOR[/bold cyan]\n")
    
    # 1. Environment Table
    table = Table(title="💻 System Environment & Engines", show_header=True, header_style="bold magenta")
    table.add_column("Component", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Version / Details")

    # Guard CLI itself
    table.add_row("Banh-Mi-Guard CLI", "✅ Active", f"v{__version__} (github.com/okrath/banh-mi-guard)")

    # Python
    py_ver = sys.version.split()[0]
    table.add_row("Python Environment", "✅ OK", f"Python {py_ver}")

    # Git
    git_bin = shutil.which("git")
    if git_bin:
        try:
            gv = subprocess.run(
                ["git", "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            ).stdout or ""
            table.add_row("Git VCS", "✅ OK", gv.strip())
        except Exception:
            table.add_row("Git VCS", "⚠️ Warn", "Git installed but version query failed")
    else:
        table.add_row("Git VCS", "❌ Missing", "git not found in PATH")

    # Node & npm
    node_bin = shutil.which("node")
    if node_bin:
        try:
            nv = subprocess.run(
                ["node", "-v"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            ).stdout or ""
            table.add_row("Node.js Runtime", "✅ OK", f"Node {nv.strip()}")
        except Exception:
            table.add_row("Node.js Runtime", "⚠️ Warn", "Node installed but query failed")
    else:
        table.add_row("Node.js Runtime", "❌ Missing", "node not found in PATH")

    # Alibaba OCR CLI
    ocr_bin = shutil.which("ocr")
    if ocr_bin:
        table.add_row("Alibaba OCR CLI", "✅ OK", f"Binary found at {ocr_bin}")
    else:
        table.add_row("Alibaba OCR CLI", "ℹ️ Optional", "Run 'npm install -g @alibaba-group/open-code-review'")

    console.print(table)

    # Installation & repository setup: what is missing after installing/upgrading, and how to fix it
    console.print()
    missing = print_setup_health(Path.cwd(), "🧩 Installation & Repository Setup")
    if missing:
        console.print(f"[bold red]{missing} item(s) missing.[/bold red] Run the command in 'How to fix'.")

    # 2. Supply-Chain Security & Update Quarantine Table (Focused on Alibaba OCR)
    if check_updates:
        console.print(f"\n[bold yellow]🛡️  RELEASES & SUPPLY-CHAIN AUDIT (Alibaba OCR Quarantine: {quarantine_days:.0f} days)[/bold yellow]")
        with console.status("[cyan]Checking GitHub & npm for releases...[/cyan]"):
            guard_check = check_guard_self_update(force=True)
            ocr_check = check_ocr_update(quarantine_days=quarantine_days)

        sec_table = Table(show_header=True, header_style="bold cyan")
        sec_table.add_column("Software Component", style="bold", width=34)
        sec_table.add_column("Installed", width=12)
        sec_table.add_column("Latest Release", width=18)
        sec_table.add_column("Status", justify="center", width=22)
        sec_table.add_column("Recommendation & Action")

        # Row 1: Banh-Mi-Guard
        g_inst = f"v{guard_check.installed_version}" if guard_check.installed_version else "v" + __version__
        g_latest = f"v{guard_check.latest_version}" if guard_check.latest_version else "N/A"
        if guard_check.status == UpdateSecurityStatus.SAFE_UPDATE_AVAILABLE:
            g_badge = "[bold white on blue]⬆️ UPDATE AVAILABLE[/bold white on blue]"
        elif guard_check.status == UpdateSecurityStatus.UP_TO_DATE:
            g_badge = "[bold green]✅ UP TO DATE[/bold green]"
        else:
            g_badge = "[yellow]⚠️ CHECK FAILED[/yellow]"
        sec_table.add_row(f"{guard_check.package_name} ({guard_check.registry})", g_inst, g_latest, g_badge, guard_check.recommendation)

        # Row 2: Alibaba OCR
        inst_str = ocr_check.installed_version or "(not installed)"
        latest_str = f"v{ocr_check.latest_version}" if ocr_check.latest_version else "N/A"
        if ocr_check.age_days is not None:
            latest_str += f" ({ocr_check.age_days:.1f}d)"

        if ocr_check.status == UpdateSecurityStatus.QUARANTINE_HOLD:
            status_badge = "[bold white on red]🛡️ QUARANTINE HOLD[/bold white on red]"
        elif ocr_check.status == UpdateSecurityStatus.SAFE_UPDATE_AVAILABLE:
            status_badge = "[bold white on blue]⬆️ SAFE UPDATE[/bold white on blue]"
        elif ocr_check.status == UpdateSecurityStatus.UP_TO_DATE:
            status_badge = "[bold green]✅ UP TO DATE[/bold green]"
        elif ocr_check.status == UpdateSecurityStatus.NOT_INSTALLED:
            status_badge = "[dim]⚪ NOT INSTALLED[/dim]"
        else:
            status_badge = "[yellow]⚠️ CHECK FAILED[/yellow]"

        sec_table.add_row(f"{ocr_check.package_name} ({ocr_check.registry})", inst_str, latest_str, status_badge, ocr_check.recommendation)

        console.print(sec_table)
        console.print(
            f"[dim]💡 Safety principle: Newly published Alibaba OCR releases < {quarantine_days:.0f} days are automatically placed "
            "on QUARANTINE HOLD to protect against npm supply-chain backdoors.[/dim]\n"
        )

@app.command("laya", context_settings={"allow_extra_args": True, "ignore_unknown_options": True}, hidden=True)
def laya_removed_cmd(ctx: typer.Context):
    """Removed in 0.11: the Laya neural triage never influenced a gate decision."""
    console.print(
        "[yellow]`guard laya` was removed in 0.11.[/yellow] The Laya triage (domain / intent / risk guesses) was only "
        "displayed and never changed a gate decision, and the neural model scored at chance level. "
        "The repository domain is detected from the repository itself.\n"
        f"Downloaded model files are no longer used: delete {Path.home() / '.guard' / 'models'} to free the space."
    )


def _run_new_version(*args: str) -> None:
    """Run a guard command with the freshly installed code (this process still runs the old one)."""
    try:
        subprocess.run([sys.executable, "-c", "from guard.cli import main; main()", *args], check=False)
    except OSError as e:
        console.print(f"[yellow]Could not start the new guard ({e}); run `guard {' '.join(args)}`.[/yellow]")


def _refresh_with_new_version() -> None:
    """
    This process still runs the old code, so start the freshly installed guard to refresh
    hooks and directive blocks now, instead of waiting for the next guard command.
    """
    console.print("[cyan]Refreshing installed hooks and agent directives with the new version...[/cyan]")
    try:
        proc = subprocess.run(
            [sys.executable, "-c", "from guard.cli import main; main()", "hook", "refresh"],
            check=False, timeout=120,
        )
        if proc.returncode == 0:
            return
    except Exception:
        pass
    console.print("[yellow]Automatic refresh did not complete. Run `guard hook refresh` to update hooks and directives.[/yellow]")


def _force_utf8_console():
    """Git hooks and legacy Windows consoles default to cp1252; emoji output would crash the run."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream and (stream.encoding or "").lower().replace("-", "") != "utf8":
                stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main():
    _force_utf8_console()
    # After an upgrade, refresh the hooks and directive blocks guard wrote earlier (once per version).
    # `guard hook refresh` does the same work itself, so it is not run twice.
    try:
        if sys.argv[1:3] != ["hook", "refresh"] and needs_refresh():
            for msg in refresh_after_upgrade():
                console.print(f"[cyan]🔄 guard {__version__}: {msg}[/cyan]")
            # Once per version: tell users of older setups what is still missing and how to fix it
            print_setup_health(Path.cwd(), f"🧩 guard {__version__} setup check", only_problems=True)
    except Exception as e:  # never block the actual command
        console.print(f"[yellow]guard refresh skipped: {e}[/yellow]")
    maybe_trigger_background_update_check()
    try:
        app()
    finally:
        notice = get_cached_update_notice()
        if notice:
            console.print(f"\n[dim yellow]{notice}[/dim yellow]")


if __name__ == "__main__":
    main()
