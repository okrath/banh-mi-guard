"""
LLM Reviewer Engine — The Final Safety Gate.
Uses the LLM configured by the user (OpenAI, Anthropic, DeepSeek, Ollama, etc.)
to act as the Senior Architect & Code Reviewer:
1. Reads the aggregated verification report (diff summary, build status, OCR rules, invariant checks)
2. Evaluates Technical Soundness (architectural integrity, memory leaks, security, out-of-scope files)
3. Evaluates Ergonomics & UX/UI Polish
4. Issues Final Score (0-10) and Verdict: APPROVED or REVISE with Actionable Remediation.
Supports selective focus mode: `security`, `memory`, `performance`, `ux`, `all`.

Budget semantics: `options.max_llm_calls` caps the extra review stages (reviewer panel and finding validation).
These extra stages check the remaining budget before starting and skip themselves (with a coverage note)
when the budget is insufficient. The base single review always runs, retries included, and is never skipped.

If no LLM API key is configured, falls back to deterministic local heuristic evaluation.
"""
from __future__ import annotations

import concurrent.futures
import re
import threading
from enum import Enum
from typing import Callable, List, Optional, Union

from pydantic import BaseModel, Field

from guard.core.config import GuardConfig, LLMConfig
from guard.core.diff_partition import (
    REVIEW_BATCH_CHARS,
    REVIEW_MAX_BATCHES,
    DiffPartition,
    part_manifest,
    partition_diff,
)
from guard.core.finding_validation import validate_findings
from guard.core.findings import (
    Finding,
    _parse_invariant_proposals,
    _resolved_script,
    parse_findings,
)  # noqa: F401
from guard.core.invariant_eval import HINT, DomainType, InvariantResult
from guard.core.llm_client import call_llm
from guard.core.ocr_engine import DiffSummary, RuleViolation
from guard.core.review_checklists import TEST_QUALITY_CHECKLIST
from guard.core.review_coverage import build_coverage_notes
from guard.core.review_ensemble import run_ensemble
from guard.core.review_lenses import build_lenses
from guard.core.review_options import ReviewOptions
from guard.core.session import BuildCheckResult, DomainContract, LockedInvariant
from guard.core.test_evidence import test_evidence_lines
from guard.core.threat_frame import (
    THREAT_FRAME_INSTRUCTIONS,
    SurfaceReport,
    parse_threat_sections,
    security_surface,
)

FORMAT_REMINDER = (
    "\nYour previous answer could not be parsed. Answer again, starting with exactly these lines:\n"
    "SCORE: <0.0-10.0>\nSUMMARY: <one paragraph>\n"
    "FINDINGS: <'None', or one line per issue: - severity | kind | file:line | requirement | description>\n"
    "severity is one of critical, high, medium, low; kind is one of correctness, security, requirement, "
    "maintainability, style, documentation, other; requirement is '-' or a verbatim quote from the task.\n"
)


class ReviewVerdict(str, Enum):
    APPROVED = "APPROVED"
    REVISE = "REVISE"


class LLMReviewVerdict(BaseModel):
    verdict: ReviewVerdict
    score: float = Field(ge=0.0, le=10.0)
    summary: str
    reviewer_model: str = "Local Deterministic Engine"
    focus_area: str = "all"
    technical_audit: List[str] = Field(default_factory=list)
    ergonomics_ux: List[str] = Field(default_factory=list)
    remediation_steps: List[str] = Field(default_factory=list)
    # Durable project rules the reviewer found, for guard.invariants.json (validated before writing)
    proposed_invariants: List[dict] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)  # structured; the verdict is computed from them
    review_mode: str = "heuristic"  # "heuristic" or "llm_deep"
    llm_error: Optional[str] = None
    coverage_notes: List[str] = Field(default_factory=list)
    validation_log: List[dict] = Field(default_factory=list)
    llm_calls: int = 0
    llm_chars: int = 0

class LLMReviewerEngine:
    """
    Final Gatekeeper powered by the user-configured LLM (or local deterministic fallback).
    """

    def __init__(self, config: Optional[GuardConfig] = None):
        self.config = config

    def review(
        self,
        prompt: str,
        domain: Union[DomainType, str],
        diff_summary: Optional[DiffSummary] = None,
        build_check: Optional[BuildCheckResult] = None,
        violations: Optional[List[RuleViolation]] = None,
        invariant_result: Optional[InvariantResult] = None,
        contracts: Optional[List[DomainContract]] = None,
        invariants: Optional[List[LockedInvariant]] = None,
        use_llm: bool = True,
        focus: Optional[str] = "all",
        evidence: Optional[List[str]] = None,
        ledger: Optional[List[dict]] = None,
        known_rules: Optional[List[dict]] = None,
        options: Optional[ReviewOptions] = None,
    ) -> LLMReviewVerdict:
        violations = violations or []
        focus_str = (focus or "all").lower()
        opts = options if options is not None else ReviewOptions()

        # 1. Deterministic Heuristic Scoring (Safety baseline)
        heuristic_verdict = self._evaluate_heuristics(
            build_check=build_check,
            diff_summary=diff_summary,
            violations=violations,
            invariant_result=invariant_result,
            focus=focus_str,
        )

        # If hard blockers triggered (build failed, invariant broken, secret leaked), reject immediately
        if heuristic_verdict.verdict == ReviewVerdict.REVISE:
            if opts.coverage_notes:
                partition = partition_diff(
                    diff_summary.raw_diff if diff_summary else "",
                    batch_chars=REVIEW_BATCH_CHARS,
                    max_batches=REVIEW_MAX_BATCHES,
                )
                heuristic_verdict.coverage_notes = build_coverage_notes(partition, [])
            return heuristic_verdict

        # 2. Deep LLM Review using the configured LLM (OpenAI, Anthropic, Ollama, DeepSeek, etc.)
        llm_error: Optional[str] = None
        self._last_llm_calls = 0  # per review: an error path never reports the previous review's counts
        self._last_llm_chars = 0
        if use_llm and self.config and self.config.llm and self.config.llm.ready:
            try:
                llm_verdict = self._evaluate_with_llm(
                    prompt=prompt,
                    domain=domain,
                    diff_summary=diff_summary,
                    build_check=build_check,
                    violations=violations,
                    invariant_result=invariant_result,
                    contracts=contracts,
                    focus=focus_str,
                    evidence=evidence or [],
                    ledger=ledger or [],
                    known_rules=known_rules or [],
                    options=opts,
                )
                if llm_verdict:
                    return llm_verdict
                llm_error = getattr(self, "last_failure", "") or "LLM response did not follow the SCORE/VERDICT format"
            except Exception as e:  # Record failure reason and fall back to heuristic evaluation
                llm_error = f"{type(e).__name__}: {str(e)[:200]}"
        elif use_llm:
            llm_error = "No LLM configured (run: guard config llm)"

        if llm_error:
            heuristic_verdict.llm_error = llm_error
            heuristic_verdict.llm_calls = getattr(self, "_last_llm_calls", 0)
            heuristic_verdict.llm_chars = getattr(self, "_last_llm_chars", 0)
            heuristic_verdict.summary += f" LLM review did NOT run ({llm_error})."
            if opts.coverage_notes:
                partition = partition_diff(
                    diff_summary.raw_diff if diff_summary else "",
                    batch_chars=REVIEW_BATCH_CHARS,
                    max_batches=REVIEW_MAX_BATCHES,
                )
                heuristic_verdict.coverage_notes = build_coverage_notes(partition, [])
        # A keyword hint on a template invariant is the LLM's to judge; with no LLM verdict it stays a blocker
        hints = [c for c in (invariant_result.checks if invariant_result else []) if c.notes.startswith(HINT)]
        if hints and heuristic_verdict.verdict == ReviewVerdict.APPROVED:
            heuristic_verdict.verdict = ReviewVerdict.REVISE
            heuristic_verdict.summary += " No LLM judged the invariant hints, so they decide: " + "; ".join(
                f"[{c.id}] {c.notes[len(HINT):]}" for c in hints) + "."
            heuristic_verdict.remediation_steps.extend(
                f"Invariant [{c.id}] {c.description}: {c.notes[len(HINT):]}. Restore it, or run guard post with an LLM "
                "configured so the hint is judged from the diff." for c in hints)
        return heuristic_verdict

    @staticmethod
    def _check_build_and_scope(
        diff_summary: Optional[DiffSummary],
        build_check: Optional[BuildCheckResult],
    ) -> tuple[List[float], List[str], List[str]]:
        penalties: List[float] = []
        tech_notes: List[str] = []
        remediation: List[str] = []

        # Check 0: Git diff inspection error
        if diff_summary and diff_summary.error:
            penalties.append(5.0)
            tech_notes.append(f"Diff Inspection Error: {diff_summary.error}")
            remediation.append(f"Resolve Git error preventing diff inspection: {diff_summary.error}")

        # Check 1: Build check
        if build_check:
            if build_check.no_tests:
                tech_notes.append(f"Compile Check: NO TESTS (`{build_check.command}` found no test to run; nothing was tested)")
            elif build_check.passed:
                tech_notes.append(f"Compile Check: PASSED (`{build_check.command}` in {build_check.duration_s:.1f}s)")
            else:
                penalties.append(4.5)
                tech_notes.append(f"Compile Check: FAILED with exit code {build_check.exit_code}")
                remediation.append(f"Fix compilation errors causing `{build_check.command}` to fail:\n{build_check.output[:300]}")

        # Check 2: Out of scope files
        if diff_summary and diff_summary.out_of_scope_files:
            penalties.append(2.5 * len(diff_summary.out_of_scope_files))
            tech_notes.append(f"Scope Compliance: Modified {len(diff_summary.out_of_scope_files)} undeclared files: {', '.join(diff_summary.out_of_scope_files)}")
            remediation.append(f"Revert changes to out-of-scope files: {', '.join(diff_summary.out_of_scope_files)}")

        return penalties, tech_notes, remediation

    @staticmethod
    def _check_violations(
        violations: List[RuleViolation],
        focus: str,
        diff_summary: Optional[DiffSummary],
    ) -> tuple[List[float], List[str], List[str], bool, bool]:
        penalties: List[float] = []
        tech_notes: List[str] = []
        remediation: List[str] = []

        # Check 3: Rule Violations
        crit_violations = [v for v in violations if v.severity == "CRITICAL"]
        high_violations = [v for v in violations if v.severity == "HIGH"]
        if crit_violations:
            penalties.append(3.5 * len(crit_violations))
            for cv in crit_violations:
                tech_notes.append(f"Security Alert [{cv.rule_id}]: {cv.message} ({cv.file_path})")
                remediation.append(f"Resolve critical security violation {cv.rule_id} in `{cv.file_path}`")
        if high_violations:
            penalties.append(1.5 * len(high_violations))
            for hv in high_violations:
                tech_notes.append(f"Stability Warning [{hv.rule_id}]: {hv.message} ({hv.file_path})")
                remediation.append(f"Resolve stability/performance warning {hv.rule_id} in `{hv.file_path}`")

        # Check 4: Code Hygiene & Dead Code Violations
        dead_violations = [v for v in violations if v.rule_id.startswith("DEAD-")]
        if dead_violations:
            weight = 2.0 if focus in ("dead-code", "hygiene") else 0.8
            penalties.append(weight * len(dead_violations))
            for dv in dead_violations:
                tech_notes.append(f"Hygiene Alert [{dv.rule_id}]: {dv.message} ({dv.file_path})")
                remediation.append(f"Clean up code hygiene issue [{dv.rule_id}]: {dv.message} in `{dv.file_path}`")

        # Check 5: Simplicity & Engineering Frugality (KISS & YAGNI)
        lazy_violations = [v for v in violations if v.rule_id.startswith("LAZY-")]
        if lazy_violations:
            weight = 2.5 if focus in ("simplicity", "yagni", "lazy") else 1.0
            penalties.append(weight * len(lazy_violations))
            for lv in lazy_violations:
                tech_notes.append(f"Simplicity Alert [{lv.rule_id}]: {lv.message} ({lv.file_path})")
                remediation.append(f"Apply KISS/YAGNI to resolve [{lv.rule_id}]: {lv.message} in `{lv.file_path}`")

        if diff_summary and diff_summary.total_deletions > diff_summary.total_insertions:
            net_loc = diff_summary.total_insertions - diff_summary.total_deletions
            tech_notes.append(f"Net {net_loc} LOC (informational, not scored).")

        hygiene_blocked = focus in ("dead-code", "hygiene") and bool(dead_violations)
        simplicity_blocked = focus in ("simplicity", "yagni", "lazy") and bool(lazy_violations)
        return penalties, tech_notes, remediation, hygiene_blocked, simplicity_blocked

    @staticmethod
    def _tally_invariant_deductions(
        invariant_result: Optional[InvariantResult],
    ) -> tuple[List[float], List[str], List[str], bool]:
        penalties: List[float] = []
        ux_notes: List[str] = []
        remediation: List[str] = []
        invariant_violated = False

        if invariant_result:
            if invariant_result.all_passed:
                verified = len(invariant_result.checks) - invariant_result.unverified_count
                ux_notes.append(f"Invariants Check: {verified} verified, {invariant_result.unverified_count} unverified (manual).")
            else:
                invariant_violated = True
                failed_checks = [c for c in invariant_result.checks if not c.passed]
                penalties.append(3.0 * len(failed_checks))
                for fc in failed_checks:
                    ux_notes.append(f"Invariant Violation [{fc.id}]: {fc.description} -> {fc.notes}")
                    remediation.append(f"Restore invariant behavior `{fc.id}`: {fc.description}")

        return penalties, ux_notes, remediation, invariant_violated

    def _evaluate_heuristics(
        self,
        build_check: Optional[BuildCheckResult],
        diff_summary: Optional[DiffSummary],
        violations: List[RuleViolation],
        invariant_result: Optional[InvariantResult],
        focus: str = "all",
    ) -> LLMReviewVerdict:
        penalties_bs, tech_bs, rem_bs = self._check_build_and_scope(diff_summary, build_check)
        penalties_v, tech_v, rem_v, hygiene_blocked, simplicity_blocked = self._check_violations(
            violations, focus, diff_summary
        )
        penalties_inv, ux_notes, rem_inv, invariant_violated = self._tally_invariant_deductions(invariant_result)

        tech_notes = tech_bs + tech_v
        remediation = rem_bs + rem_v + rem_inv

        score = 10.0
        for penalty in penalties_bs + penalties_v + penalties_inv:
            score -= penalty
        score = max(0.0, min(10.0, score))

        crit_violations = [v for v in violations if v.severity == "CRITICAL"]
        is_hard_blocked = (
            invariant_violated
            or bool(crit_violations)
            or (build_check is not None and not build_check.passed)
            or (diff_summary is not None and bool(diff_summary.out_of_scope_files))
            or hygiene_blocked
            or simplicity_blocked
            # Alibaba OCR not running, or reporting a high/critical finding, blocks
            or any(v.rule_id.startswith("OCR-") and v.severity in ("HIGH", "CRITICAL") for v in violations)
        )
        verdict = ReviewVerdict.APPROVED if (score >= 7.5 and not is_hard_blocked) else ReviewVerdict.REVISE

        unverified = invariant_result.unverified_count if invariant_result else 0
        if verdict == ReviewVerdict.APPROVED:
            summary = f"HEURISTIC GATE PASS ({score:.1f}/10): build and static rules found no blocking issue."
            if unverified:
                summary += f" {unverified} invariant(s) are UNVERIFIED and need manual checking."
        else:
            summary = f"HEURISTIC GATE REJECT ({score:.1f}/10): {len(remediation)} issue(s) to fix before handover."

        model_name = self.config.llm.model if (self.config and self.config.llm and self.config.llm.ready) else "Local Rule Engine"

        return LLMReviewVerdict(
            verdict=verdict,
            score=score,
            summary=summary,
            reviewer_model=model_name,
            focus_area=focus,
            technical_audit=tech_notes,
            ergonomics_ux=ux_notes,
            remediation_steps=remediation,
            review_mode="heuristic",
        )

    @staticmethod
    def _build_focus_instruction(focus: str) -> str:
        if focus == "security":
            return "CRITICAL FOCUS ON SECURITY: Rigorously audit for hardcoded secrets, injection (SQLi, XSS, Command), CSRF, insecure endpoints, and auth bypass."
        if focus == "memory":
            return "CRITICAL FOCUS ON MEMORY SAFETY: Rigorously audit for dangling event listeners, unclosed streams/sockets/db connections, retained closures, and DOM leaks."
        if focus == "performance":
            return "CRITICAL FOCUS ON PERFORMANCE & LATENCY: Rigorously audit for blocking synchronous I/O, N+1 query patterns, excessive re-renders, and thread lockups."
        if focus == "ux":
            return "CRITICAL FOCUS ON ERGONOMICS & UX: Rigorously audit for broken keyboard shortcuts, modal backdrop handling, viewport responsiveness, and visual state feedback."
        if focus in ("dead-code", "hygiene"):
            return "CRITICAL FOCUS ON CODE HYGIENE & DEAD CODE: Rigorously audit for orphan/unused files, commented-out blocks of code, unused imports, unreferenced helper functions/variables, redundant duplicate logic, and obsolete scratchpad or temporary files."
        if focus in ("simplicity", "yagni", "lazy"):
            return (
                "CRITICAL FOCUS ON SIMPLICITY & PRODUCTIVE LAZINESS (KISS & YAGNI): "
                "Act as the Laziest Senior Architect in the room. Ruthlessly audit for over-engineering, "
                "unnecessary new dependencies, multi-layer abstractions for trivial logic, reinvented wheels, "
                "and code that should not have been written. The best code is code you never write. "
                "Demand the simplest one-liner, standard library, or native runtime solution."
            )
        return "FULL 360-DEGREE AUDIT: Evaluate across all 5 Quality Pillars (Security, Memory Safety, Performance, Data Integrity, Ergonomics/UX)."

    @staticmethod
    def _build_system_prompt(model_name: str, focus_instruction: str) -> str:
        return (
            f"You are the Senior Lead Architect and Code Reviewer acting as the final safety gate (using model {model_name}).\n"
            f"Review Directive: {focus_instruction}\n"
            "Your task is to audit the post-task verification report and git diff produced by an AI coding agent.\n"
            "Only the facts in the report are verified: the build status is exactly as stated, and no behavioral test suite has run unless stated.\n"
            "A passing build does NOT prove behavior is preserved. Invariants marked UNVERIFIED must be judged from the diff itself.\n"
            "Deleted files and large deletions must be justified by the task prompt; REVISE when the diff removes behavior the task did not ask to remove.\n"
            "For each listed contract, say whether the diff preserved, changed or removed it; a contract that the diff changes or removes when the task did not ask for it is a correctness finding naming the contract.\n"
            "Checklist across all languages:\n"
            "- Leaks: resources opened without a guaranteed close (files, sockets, DB connections, child processes); "
            "listeners, timers and subscriptions never removed on teardown; caches and collections that only grow; "
            "closures that hold large objects.\n"
            "- Null dereference: values that can be null/None/undefined/nil (optional returns, dict.get, find, "
            "regex matches, API/JSON fields) used without a check.\n"
            "- Blocking calls inside async or event-loop code; dead code (dead-code: commented-out code, unused imports "
            "and private functions); over-engineering (pass-through wrappers, one-method classes, reinvented standard helpers).\n"
            "- Each such finding names the file and line where the value or resource is created and the line where it "
            "is used or leaked. Leaks and null dereferences are kind correctness (they block at high/critical through the existing rules).\n"
            "Evaluate across 3 pillars:\n"
            "1. Technical Audit (Code integrity, memory leaks, dangling listeners, breaking API changes, security vulnerabilities)\n"
            "2. Invariants & Contracts (Ensure baseline UI states, interactions, and DB schemas are preserved)\n"
            "3. Ergonomics Polish (UX, responsive styling, accessibility across technical domains)\n"
            "You do not decide the verdict: guard computes it from your findings. A finding blocks only when it is "
            "critical or high AND about correctness or security, or when it quotes, verbatim, a requirement from the "
            "Task Prompt that the change violates. Rate severity honestly; do not inflate a nice-to-have.\n"
            "Findings already raised in this session are listed under 'Findings so far'. Do not raise one of them "
            "again unless the current diff gives new evidence; then say what is new. A deferral or rejection the "
            "agent recorded is a decision to respect unless you can show it is wrong.\n"
            "Mandatory Output Format:\n"
            "SCORE: <float between 0.0 and 10.0, informational>\n"
            "SUMMARY: <concise summary>\n"
            "FINDINGS: <'None', or one line per issue: `- severity | kind | file:line | requirement | description` "
            "with severity critical/high/medium/low, kind correctness/security/requirement/maintainability/style/"
            "documentation/other, requirement = a short verbatim quote from the Task Prompt the change violates or '-'>\n"
            "TECHNICAL: <bullet points>\n"
            "ERGONOMICS: <bullet points>\n"
            "INVARIANTS: <'None', or one line per DURABLE project rule this diff reveals that is not already among the "
            "existing project rules listed above (in any wording) and that the current code satisfies. Format: "
            "`- ID | description | files-glob | forbid-or-require | python-regex`. A machine check is required: guard "
            "rejects a rule without one, a glob that matches no file, and a regex that does not hold on the current "
            "code; a rule a regex cannot check is not proposed. ID: UPPERCASE letters/digits/dashes. "
            "Write each description in the same language as the existing invariant descriptions listed above "
            "(English when there are none), and wrap file paths in backticks. "
            "Propose only rules the project must keep in every future change, not task-specific notes.>"
        )

    @staticmethod
    def _build_review_header(
        prompt: str,
        domain_str: str,
        focus: str,
        diff_summary: Optional[DiffSummary],
        build_check: Optional[BuildCheckResult],
        violations: List[RuleViolation],
        invariant_result: Optional[InvariantResult],
        contracts: Optional[List[DomainContract]],
        evidence: Optional[List[str]],
        ledger: Optional[List[dict]],
        known_rules: Optional[List[dict]],
    ) -> str:
        files_summary = ", ".join(f"{f.path} ({f.status})" for f in (diff_summary.files if diff_summary else []))
        if build_check and build_check.no_tests:
            build_info = f"NO TESTS ({build_check.command} found no test to run; nothing was tested)"
        else:
            build_info = f"PASSED ({build_check.command} exit 0)" if (build_check and build_check.passed) else ("FAILED" if build_check else "NOT RUN")
        script = _resolved_script(build_check.output) if build_check else None
        if script:
            # `pnpm run build` alone does not tell the reviewer whether a typecheck ran
            build_info += f"; the script actually executed was: `{script}`"
        violations_info = "\n".join(f"- [{v.severity}] {v.rule_id} {v.file_path}: {v.message}" for v in violations[:30])
        invariants_info = "\n".join(
            f"- [{c.status.upper()}] {c.id}: {c.description} ({c.notes})" for c in (invariant_result.checks if invariant_result else [])
        ) or "- none declared"
        contracts_info = "\n".join(
            f"- [{c.category}] {c.name}: {c.description}" for c in (contracts or [])
        ) or "- none recorded"
        evidence_info = "\n".join(f"- {e}" for e in (evidence or [])) or "- none"
        known_info = "\n".join(f"- {r.get('id')}: {r.get('description')}" for r in (known_rules or [])) or "- none"
        ledger_lines = []
        for f in (ledger or []):
            desc = f.get("description", "")
            if "[contested:" in desc:
                status = "contested (a validation step disputed it; re-check it against the current diff)"
            else:
                status = f.get("status", "open")
            note_str = f" ({f.get('note')})" if f.get("note") else ""
            ledger_lines.append(
                f"- [{f.get('id')}] round {f.get('round')}, {status}{note_str}: {f.get('severity')} {f.get('kind')} {f.get('location')}: {desc}"
            )
        ledger_info = "\n".join(ledger_lines) or "- none"
        has_contested = any("[contested:" in f.get("description", "") for f in (ledger or []))
        ledger_title = (
            "Findings so far in this session (id, round, status, your earlier wording; "
            "the instruction not to raise findings already raised does NOT apply to contested entries; "
            "re-check them against the current diff):"
            if has_contested
            else "Findings so far in this session (id, round, status, your earlier wording):"
        )

        return f"""
Domain: {domain_str}
Review Focus: {focus.upper()}
Task Prompt: {prompt}
Build Status: {build_info}
Rule Violations: {len(violations)} issues
{violations_info}
Out of Scope Files: {diff_summary.out_of_scope_files if diff_summary else []}
All Touched Files: {files_summary}
Invariants:
{invariants_info}
Baseline contracts recorded at guard pre (what callers rely on):
{contracts_info}
Every project rule that exists now (team file, local file, learned earlier in this session; never propose one again, not even reworded):
{known_info}
Verified evidence (computed by guard over the whole repository, valid for every diff part):
{evidence_info}
{ledger_title}
{ledger_info}
"""

    def _review_diff_batches(
        self,
        review_cfg: LLMConfig,
        batches: List[str],
        header: str,
        system_prompt: str,
        model_name: str,
        focus: str,
        options: Optional[ReviewOptions] = None,
        counted_call: Optional[Callable[[str, str], str]] = None,
        partition: Optional[DiffPartition] = None,
    ) -> Optional[List[LLMReviewVerdict]]:
        opts = options or ReviewOptions()
        caller = counted_call or (
            lambda sys, pr: call_llm(
                cfg=review_cfg,
                prompt=pr,
                system_prompt=sys,
                temperature=0.1,
                max_tokens=2000,
            )
        )
        verdicts: List[LLMReviewVerdict] = []
        self._last_unreviewed = []
        for i, batch in enumerate(batches, start=1):
            if len(batches) > 1:
                part = f"Diff part {i}/{len(batches)} (other parts are reviewed separately; judge only this part):\n"
                if opts.part_manifest and partition is not None:
                    manifest = part_manifest(partition, i)
                    if manifest:
                        part += f"{manifest}\n"
            else:
                part = ""
            prompt_text = f"{header}\n{part}Git Diff:\n```\n{batch}\n```\n"
            verdict = None
            raw_response = None
            for attempt in range(2):  # one retry when the answer ignores the SCORE/FINDINGS format
                raw_response = caller(
                    system_prompt,
                    prompt_text if attempt == 0 else prompt_text + FORMAT_REMINDER,
                )
                verdict = self._parse_llm_response(raw_response, model_name=model_name, focus=focus)
                if verdict is not None:
                    self._last_unreviewed.extend(getattr(verdict, "_unreviewed_topics", []))
                    break
            if verdict is None:
                self.last_failure = f"part {i}/{len(batches)} answer was not a review: {(raw_response or '').strip()[:160]}"
                return None
            verdicts.append(verdict)
        return verdicts

    def _evaluate_with_llm(
        self,
        prompt: str,
        domain: Union[DomainType, str],
        diff_summary: Optional[DiffSummary],
        build_check: Optional[BuildCheckResult],
        violations: List[RuleViolation],
        invariant_result: Optional[InvariantResult],
        contracts: Optional[List[DomainContract]],
        focus: str = "all",
        evidence: Optional[List[str]] = None,
        ledger: Optional[List[dict]] = None,
        known_rules: Optional[List[dict]] = None,
        options: Optional[ReviewOptions] = None,
    ) -> Optional[LLMReviewVerdict]:
        if not self.config or not self.config.llm:
            return None
        self._task_text = prompt  # what a quoted requirement is checked against
        opts = options if options is not None else ReviewOptions()

        model_name = self.config.llm.model
        domain_str = domain.value if isinstance(domain, DomainType) else str(domain)

        # 1. Partition diff
        raw_diff = diff_summary.raw_diff if diff_summary else ""
        partition = partition_diff(
            raw_diff,
            batch_chars=REVIEW_BATCH_CHARS,
            max_batches=REVIEW_MAX_BATCHES,
        )
        batches = partition.parts

        # 2. Header and evidence additions
        evidence_list = list(evidence or [])
        if opts.test_evidence:
            evidence_list.extend(test_evidence_lines(raw_diff))

        surface: Optional[SurfaceReport] = None
        threat_active = False
        if opts.threat_frame == "auto":
            surface = security_surface(raw_diff)
            if surface.sensitive:
                threat_active = True
                evidence_list.append(f"Security-sensitive surface detected: {', '.join(surface.reasons)}")

        focus_instruction = self._build_focus_instruction(focus)
        system_prompt = self._build_system_prompt(model_name, focus_instruction)
        if opts.test_checklist:
            system_prompt = f"{system_prompt}\n\n{TEST_QUALITY_CHECKLIST}"

        header = self._build_review_header(
            prompt=prompt,
            domain_str=domain_str,
            focus=focus,
            diff_summary=diff_summary,
            build_check=build_check,
            violations=violations,
            invariant_result=invariant_result,
            contracts=contracts,
            evidence=evidence_list,
            ledger=ledger,
            known_rules=known_rules,
        )
        if threat_active:
            header = f"{header}\n{THREAT_FRAME_INSTRUCTIONS}\n"

        review_cfg = self.config.llm.model_copy(update={"timeout": None})

        # 3. Thread-safe call counter setup
        counter_lock = threading.Lock()
        calls_count = 0
        chars_count = 0

        validation_cancelled = threading.Event()

        def counted_call(sys_text: str, pr_text: str) -> str:
            nonlocal calls_count, chars_count
            with counter_lock:
                if validation_cancelled.is_set():
                    raise RuntimeError("finding validation was cancelled after its stage timed out")
                calls_count += 1
                chars_count += len(sys_text or "") + len(pr_text or "")
                self._last_llm_calls = calls_count
                self._last_llm_chars = chars_count
            return call_llm(
                cfg=review_cfg,
                prompt=pr_text,
                system_prompt=sys_text,
                temperature=0.1,
                max_tokens=2000,
            )

        # 4. Stage 1: Ensemble or Single Reviewer
        panel_note: Optional[str] = None
        validation_note: Optional[str] = None
        unreviewed_topics: List[str] = []
        merged_verdict: Optional[LLMReviewVerdict] = None

        if opts.reviewers > 1:
            worst_case_panel = 2 * opts.reviewers * len(batches)
            remaining_budget = opts.max_llm_calls - calls_count
            if worst_case_panel > remaining_budget:
                panel_note = "Reviewer panel unavailable (budget exceeded); one reviewer ran."
            else:
                extra_dict = {}
                if opts.test_checklist:
                    extra_dict["tests"] = TEST_QUALITY_CHECKLIST
                if threat_active:
                    extra_dict["adversary"] = THREAT_FRAME_INSTRUCTIONS
                try:
                    panel_lenses = build_lenses(extra=extra_dict)[:opts.reviewers]
                    ensemble_res = run_ensemble(
                        lenses=panel_lenses,
                        call=counted_call,
                        header=header,
                        parts=batches,
                        parse=lambda t: parse_findings(t, self._task_text),
                        max_calls=remaining_budget,
                        format_reminder=FORMAT_REMINDER,
                        system_prompt=system_prompt,
                        stage_timeout_s=float(opts.stage_timeout_s),
                    )
                except Exception as e:
                    ensemble_res = None
                    panel_note = f"Reviewer panel unavailable ({type(e).__name__}); one reviewer ran."
                if ensemble_res is None:
                    if not panel_note:
                        panel_note = "Reviewer panel unavailable (insufficient usable lenses); one reviewer ran."
                else:
                    panel_findings = ensemble_res.findings
                    is_rejected = any(f.blocking for f in panel_findings)
                    panel_score = 6.0 if is_rejected else 8.5
                    remed = [f"[{f.id}] {f.location}: {f.description}" for f in panel_findings if f.blocking]
                    merged_verdict = LLMReviewVerdict(
                        verdict=ReviewVerdict.REVISE if is_rejected else ReviewVerdict.APPROVED,
                        score=panel_score,
                        summary=f"Reviewer panel ({ensemble_res.usable} lenses) evaluated {len(batches)} diff parts.",
                        reviewer_model=f"Panel ({len(panel_lenses)} lenses)",
                        focus_area=focus,
                        technical_audit=[f"[{f.id}] {f.location}: {f.description}" for f in panel_findings],
                        ergonomics_ux=[],
                        remediation_steps=remed,
                        findings=panel_findings,
                        proposed_invariants=[],
                        review_mode="llm_deep",
                    )

        if merged_verdict is None:
            verdicts = self._review_diff_batches(
                review_cfg=review_cfg,
                batches=batches,
                header=header,
                system_prompt=system_prompt,
                model_name=model_name,
                focus=focus,
                options=opts,
                counted_call=counted_call,
                partition=partition,
            )
            if verdicts is None:
                self._last_llm_calls = calls_count
                self._last_llm_chars = chars_count
                return None
            unreviewed_topics.extend(getattr(self, "_last_unreviewed", []))
            merged_verdict = self._merge_verdicts(verdicts)

        # 5. Stage 2: Finding Validation (opt-in)
        validation_records: List[dict] = []
        if (
            opts.validate_findings
            and any(f.blocking for f in merged_verdict.findings)
            and (len(batches) > 1 or partition.cut_parts > 0)
        ):
            remaining_for_val = opts.max_llm_calls - calls_count
            blocking_count = sum(1 for f in merged_verdict.findings if f.blocking)
            worst_case_val = min(5, blocking_count)
            if worst_case_val > remaining_for_val:
                validation_note = "Finding validation skipped (budget exceeded)."
            else:
                def do_validate():
                    return validate_findings(
                        findings=merged_verdict.findings,
                        full_diff=raw_diff,
                        task_text=prompt,
                        call=counted_call,
                        max_validations=min(5, remaining_for_val),
                    )

                pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                try:
                    future = pool.submit(do_validate)
                    try:
                        updated_findings, val_objs = future.result(timeout=float(opts.stage_timeout_s))
                        merged_verdict.findings = updated_findings
                        for vr in val_objs:
                            validation_records.append({
                                "finding_id": vr.finding_id,
                                "verdict": vr.verdict,
                                "evidence_verified": vr.evidence_verified,
                                "reason": vr.reason,
                            })
                        still_blocking = any(f.blocking for f in updated_findings)
                        if not still_blocking:
                            merged_verdict.verdict = ReviewVerdict.APPROVED
                            merged_verdict.score = max(merged_verdict.score, 8.0)
                            merged_verdict.remediation_steps = []
                        else:
                            merged_verdict.verdict = ReviewVerdict.REVISE
                            merged_verdict.remediation_steps = [
                                f"[{f.id}] {f.location}: {f.description}"
                                for f in updated_findings if f.blocking
                            ]
                    except concurrent.futures.TimeoutError:
                        with counter_lock:
                            validation_cancelled.set()  # late calls from the abandoned thread are refused
                        validation_note = f"Finding validation timed out after {opts.stage_timeout_s}s."
                    except Exception as e:
                        # Fail safe: the findings stay as the reviewers left them, and the crash is visible
                        validation_note = f"Finding validation failed ({type(e).__name__}); findings unchanged."
                finally:
                    pool.shutdown(wait=False, cancel_futures=True)

        # 6. Final verdict fields
        merged_verdict.validation_log = validation_records
        merged_verdict.llm_calls = calls_count
        merged_verdict.llm_chars = chars_count
        self._last_llm_calls = calls_count
        self._last_llm_chars = chars_count
        if opts.coverage_notes:
            notes = build_coverage_notes(partition, unreviewed_topics)
            if panel_note:
                notes.append(panel_note)
            if validation_note:
                notes.append(validation_note)
            merged_verdict.coverage_notes = notes
        else:
            merged_verdict.coverage_notes = []

        return merged_verdict

    @staticmethod
    def _merge_verdicts(verdicts: List[LLMReviewVerdict]) -> LLMReviewVerdict:
        """One REVISE part rejects the whole diff; the score is the weakest part's score."""
        if len(verdicts) == 1:
            return verdicts[0]
        first = verdicts[0]
        findings = [f for v in verdicts for f in v.findings]
        rejected = any(v.verdict == ReviewVerdict.REVISE for v in verdicts) or any(f.blocking for f in findings)
        return LLMReviewVerdict(
            verdict=ReviewVerdict.REVISE if rejected else ReviewVerdict.APPROVED,
            score=min(v.score for v in verdicts),
            summary=" ".join(f"[Part {i}/{len(verdicts)}: {v.verdict.value} {v.score:.1f}] {v.summary}" for i, v in enumerate(verdicts, 1)),
            reviewer_model=first.reviewer_model,
            focus_area=first.focus_area,
            technical_audit=[t for v in verdicts for t in v.technical_audit],
            ergonomics_ux=[t for v in verdicts for t in v.ergonomics_ux],
            remediation_steps=[t for v in verdicts for t in v.remediation_steps],
            findings=findings,
            proposed_invariants=[t for v in verdicts for t in v.proposed_invariants],
            review_mode="llm_deep",
        )

    def _prepare_diff_batches(self, diff_summary: Optional[DiffSummary]) -> List[str]:
        """Code diff split on file boundaries into parts of at most REVIEW_BATCH_CHARS characters."""
        raw = diff_summary.raw_diff if diff_summary else ""
        return partition_diff(raw, batch_chars=REVIEW_BATCH_CHARS, max_batches=REVIEW_MAX_BATCHES).parts

    def _parse_llm_response(self, text: str, model_name: str = "LLM", focus: str = "all") -> Optional[LLMReviewVerdict]:
        try:
            score_match = re.search(r"SCORE:\s*([\d\.]+)", text)
            findings = parse_findings(text, getattr(self, "_task_text", ""))
            if findings is None:
                # No readable FINDINGS list is no LLM review: asked again once (format reminder), then
                # reported as not run. Only structured findings approve or block
                return None

            score = float(score_match.group(1)) if score_match else 8.0
            score = max(0.0, min(10.0, score))
            verdict = ReviewVerdict.REVISE if any(f.blocking for f in findings) else ReviewVerdict.APPROVED

            summary_match = re.search(r"SUMMARY:\s*(.+?)(?=\n[A-Z]+:|$)", text, re.DOTALL)
            summary = summary_match.group(1).strip() if summary_match else "LLM Review completed."

            tech_items = self._extract_bullet_items(text, "TECHNICAL")
            ergo_items = self._extract_bullet_items(text, "ERGONOMICS")
            remed_items = self._extract_bullet_items(text, "REMEDIATION")
            proposals = _parse_invariant_proposals(text)
            tm_text, unreviewed_items = parse_threat_sections(text)
            if tm_text:
                tech_items.append(f"Threat model: {tm_text}")
            if any(item.lower() == "none" for item in remed_items):
                remed_items = []
            # What to fix is what blocks; advisory findings are follow-ups, not remediation
            remed_items = [f"[{f.id}] {f.location}: {f.description}" for f in findings if f.blocking]

            v = LLMReviewVerdict(
                verdict=verdict,
                score=score,
                summary=summary,
                reviewer_model=model_name,
                focus_area=focus,
                technical_audit=tech_items,
                ergonomics_ux=ergo_items,
                remediation_steps=remed_items,
                proposed_invariants=proposals,
                findings=findings,
                review_mode="llm_deep",
            )
            v._unreviewed_topics = unreviewed_items  # type: ignore[attr-defined]
            return v
        except Exception:
            # Parsing boundary: return None so caller falls back to heuristic
            return None

    def _extract_bullet_items(self, text: str, section_header: str) -> List[str]:
        # A section ends at an unindented `WORD:` header, or at a known section name however it is indented or
        # wrapped in markdown; an indented `SQL:` inside a bullet list is content
        known = r"(?i:threat[ \t]*model|unreviewed|technical|ergonomics|remediation|invariants|findings|summary|score|verdict)"
        pattern = (
            rf"{section_header}:\s*(.+?)(?=\n(?:(?:\*{{1,2}}|#{{1,6}}[ \t]*)?[A-Z]+[ \t]*(?::|\*{{1,2}}:)"
            rf"|[ \t]*(?:\*{{1,2}}|#{{1,6}}[ \t]*)?{known}[ \t]*(?::|\*{{1,2}}:))|$)"
        )
        match = re.search(pattern, text, re.DOTALL)
        if not match:
            return []
        lines = match.group(1).strip().splitlines()
        results = []
        for line in lines:
            line_str = re.sub(r"^[\s\*\-\d\.\)]+", "", line).strip()
            if line_str and line_str.lower() != "none":
                results.append(line_str)
        return results
