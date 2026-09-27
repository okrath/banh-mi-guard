"""
LLM Reviewer Engine — The Final Safety Gate.
Uses the LLM configured by the user (OpenAI, Anthropic, DeepSeek, Ollama, etc.)
to act as the Senior Architect & Code Reviewer:
1. Reads the aggregated verification report (diff summary, build status, OCR rules, invariant checks)
2. Evaluates Technical Soundness (architectural integrity, memory leaks, security, out-of-scope files)
3. Evaluates Ergonomics & UX/UI Polish
4. Issues Final Score (0-10) and Verdict: APPROVED or REVISE with Actionable Remediation.
Supports selective focus mode: `security`, `memory`, `performance`, `ux`, `all`.

If no LLM API key is configured, falls back to deterministic local heuristic evaluation.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, Field

from guard.core.config import GuardConfig
from guard.core.invariant_eval import DomainType, InvariantResult
from guard.core.llm_client import call_llm
from guard.core.ocr_engine import DiffSummary, RuleViolation
from guard.core.session import BuildCheckResult, DomainContract, LockedInvariant

REVIEW_BATCH_CHARS = 80000
REVIEW_MAX_BATCHES = 6
FORMAT_REMINDER = (
    "\nYour previous answer could not be parsed. Answer again, starting with exactly these lines:\n"
    "SCORE: <0.0-10.0>\nVERDICT: <APPROVED or REVISE>\nSUMMARY: <one paragraph>\n"
)


def _parse_invariant_proposals(text: str) -> List[dict]:
    """`INVARIANTS:` lines -> [{"id", "description", "checks"}]; malformed lines are dropped."""
    m = re.search(r"INVARIANTS:\s*(.+?)(?=\n[A-Z]+:|\Z)", text, re.DOTALL)
    if not m:
        return []
    out = []
    for line in m.group(1).strip().splitlines():
        line = re.sub(r"^[\s*\-\d.)]+", "", line).strip().strip("`")
        if not line or line.lower() == "none":
            continue
        parts = [x.strip().strip("`") for x in line.split(" | ")]
        if len(parts) == 2:
            out.append({"id": parts[0], "description": parts[1], "checks": []})
        elif len(parts) >= 5 and parts[3].lower() in ("forbid", "require"):
            # `\_` is a markdown escape; in a regex it means `_`, so dropping it keeps the meaning
            regex = " | ".join(parts[4:]).replace("\\_", "_")
            # Models often markdown-escape paths (`project\_invariants.py`); a glob never needs that
            files = re.sub(r"\\([_*\[\]])", r"\1", parts[2])
            out.append({"id": parts[0], "description": parts[1],
                        "checks": [{"files": files, parts[3].lower(): regex}]})
    return out


def _resolved_script(output: str) -> Optional[str]:
    """Script line echoed by pnpm/yarn (`$ tsc && vite build`) or npm (`> tsc && vite build`)."""
    for line in (output or "").splitlines():
        m = re.match(r"^\s*[$>]\s+(?!\S+@\S+\s)(\S.*)$", line)
        if m:
            return m.group(1).strip()
    return None


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
    review_mode: str = "heuristic"  # "heuristic" or "llm_deep"
    llm_error: Optional[str] = None  # Why the LLM review did not run or failed


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
    ) -> LLMReviewVerdict:
        violations = violations or []
        focus_str = (focus or "all").lower()

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
            return heuristic_verdict

        # 2. Deep LLM Review using the configured LLM (OpenAI, Anthropic, Ollama, DeepSeek, etc.)
        llm_error: Optional[str] = None
        if use_llm and self.config and self.config.llm and self.config.llm.api_key:
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
                )
                if llm_verdict:
                    return llm_verdict
                llm_error = getattr(self, "last_failure", "") or "LLM response did not follow the SCORE/VERDICT format"
            except Exception as e:
                llm_error = f"{type(e).__name__}: {str(e)[:200]}"
        elif use_llm:
            llm_error = "No LLM configured (run: guard config llm)"

        if llm_error:
            heuristic_verdict.llm_error = llm_error
            heuristic_verdict.summary += f" LLM review did NOT run ({llm_error})."
        return heuristic_verdict

    def _evaluate_heuristics(
        self,
        build_check: Optional[BuildCheckResult],
        diff_summary: Optional[DiffSummary],
        violations: List[RuleViolation],
        invariant_result: Optional[InvariantResult],
        focus: str = "all",
    ) -> LLMReviewVerdict:
        score = 10.0
        tech_notes: List[str] = []
        ux_notes: List[str] = []
        remediation: List[str] = []

        # Check 1: Build check
        if build_check:
            if build_check.passed:
                tech_notes.append(f"Compile Check: PASSED (`{build_check.command}` in {build_check.duration_s:.1f}s)")
            else:
                score -= 4.5
                tech_notes.append(f"Compile Check: FAILED with exit code {build_check.exit_code}")
                remediation.append(f"Fix compilation errors causing `{build_check.command}` to fail:\n{build_check.output[:300]}")

        # Check 2: Out of scope files
        if diff_summary and diff_summary.out_of_scope_files:
            score -= 2.5 * len(diff_summary.out_of_scope_files)
            tech_notes.append(f"Scope Compliance: Modified {len(diff_summary.out_of_scope_files)} undeclared files: {', '.join(diff_summary.out_of_scope_files)}")
            remediation.append(f"Revert changes to out-of-scope files: {', '.join(diff_summary.out_of_scope_files)}")

        # Check 3: Rule Violations
        crit_violations = [v for v in violations if v.severity == "CRITICAL"]
        high_violations = [v for v in violations if v.severity == "HIGH"]
        if crit_violations:
            score -= 3.5 * len(crit_violations)
            for cv in crit_violations:
                tech_notes.append(f"Security Alert [{cv.rule_id}]: {cv.message} ({cv.file_path})")
                remediation.append(f"Resolve critical security violation {cv.rule_id} in `{cv.file_path}`")
        if high_violations:
            score -= 1.5 * len(high_violations)
            for hv in high_violations:
                tech_notes.append(f"Stability Warning [{hv.rule_id}]: {hv.message} ({hv.file_path})")
                remediation.append(f"Resolve stability/performance warning {hv.rule_id} in `{hv.file_path}`")

        # Check 4: Code Hygiene & Dead Code Violations
        dead_violations = [v for v in violations if v.rule_id.startswith("DEAD-")]
        if dead_violations:
            weight = 2.0 if focus in ("dead-code", "hygiene") else 0.8
            score -= weight * len(dead_violations)
            for dv in dead_violations:
                tech_notes.append(f"Hygiene Alert [{dv.rule_id}]: {dv.message} ({dv.file_path})")
                remediation.append(f"Clean up code hygiene issue [{dv.rule_id}]: {dv.message} in `{dv.file_path}`")
        # Check 5: Simplicity & Engineering Frugality (KISS & YAGNI)
        lazy_violations = [v for v in violations if v.rule_id.startswith("LAZY-")]
        if lazy_violations:
            weight = 2.5 if focus in ("simplicity", "yagni", "lazy") else 1.0
            score -= weight * len(lazy_violations)
            for lv in lazy_violations:
                tech_notes.append(f"Simplicity Alert [{lv.rule_id}]: {lv.message} ({lv.file_path})")
                remediation.append(f"Apply KISS/YAGNI to resolve [{lv.rule_id}]: {lv.message} in `{lv.file_path}`")

        if diff_summary and diff_summary.total_deletions > diff_summary.total_insertions:
            net_loc = diff_summary.total_insertions - diff_summary.total_deletions
            tech_notes.append(f"Net {net_loc} LOC (informational, not scored).")

        # Check 6: Invariants (CRITICAL: Invariant violation is a HARD BLOCKER)
        invariant_violated = False
        if invariant_result:
            if invariant_result.all_passed:
                verified = len(invariant_result.checks) - invariant_result.unverified_count
                ux_notes.append(f"Invariants Check: {verified} verified, {invariant_result.unverified_count} unverified (manual).")
            else:
                invariant_violated = True
                failed_checks = [c for c in invariant_result.checks if not c.passed]
                score -= 3.0 * len(failed_checks)
                for fc in failed_checks:
                    ux_notes.append(f"Invariant Violation [{fc.id}]: {fc.description} -> {fc.notes}")
                    remediation.append(f"Restore invariant behavior `{fc.id}`: {fc.description}")

        score = max(0.0, min(10.0, score))
        
        hygiene_blocked = focus in ("dead-code", "hygiene") and bool(dead_violations)
        simplicity_blocked = focus in ("simplicity", "yagni", "lazy") and bool(lazy_violations)
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

        model_name = self.config.llm.model if (self.config and self.config.llm and self.config.llm.api_key) else "Local Rule Engine"

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
    ) -> Optional[LLMReviewVerdict]:
        if not self.config or not self.config.llm:
            return None

        model_name = self.config.llm.model
        domain_str = domain.value if hasattr(domain, "value") else str(domain)

        focus_instruction = ""
        if focus == "security":
            focus_instruction = "CRITICAL FOCUS ON SECURITY: Rigorously audit for hardcoded secrets, injection (SQLi, XSS, Command), CSRF, insecure endpoints, and auth bypass."
        elif focus == "memory":
            focus_instruction = "CRITICAL FOCUS ON MEMORY SAFETY: Rigorously audit for dangling event listeners, unclosed streams/sockets/db connections, retained closures, and DOM leaks."
        elif focus == "performance":
            focus_instruction = "CRITICAL FOCUS ON PERFORMANCE & LATENCY: Rigorously audit for blocking synchronous I/O, N+1 query patterns, excessive re-renders, and thread lockups."
        elif focus == "ux":
            focus_instruction = "CRITICAL FOCUS ON ERGONOMICS & UX: Rigorously audit for broken keyboard shortcuts, modal backdrop handling, viewport responsiveness, and visual state feedback."
        elif focus in ("dead-code", "hygiene"):
            focus_instruction = "CRITICAL FOCUS ON CODE HYGIENE & DEAD CODE: Rigorously audit for orphan/unused files, commented-out blocks of code, unused imports, unreferenced helper functions/variables, redundant duplicate logic, and obsolete scratchpad or temporary files."
        elif focus in ("simplicity", "yagni", "lazy"):
            focus_instruction = (
                "CRITICAL FOCUS ON SIMPLICITY & PRODUCTIVE LAZINESS (KISS & YAGNI): "
                "Act as the Laziest Senior Architect in the room. Ruthlessly audit for over-engineering, "
                "unnecessary new dependencies, multi-layer abstractions for trivial logic, reinvented wheels, "
                "and code that should not have been written. The best code is code you never write. "
                "Demand the simplest one-liner, standard library, or native runtime solution."
            )
        else:
            focus_instruction = "FULL 360-DEGREE AUDIT: Evaluate across all 5 Quality Pillars (Security, Memory Safety, Performance, Data Integrity, Ergonomics/UX)."

        system_prompt = (
            f"You are the Senior Lead Architect and Code Reviewer acting as the final safety gate (using model {model_name}).\n"
            f"Review Directive: {focus_instruction}\n"
            "Your task is to audit the post-task verification report and git diff produced by an AI coding agent.\n"
            "Only the facts in the report are verified: the build status is exactly as stated, and no behavioral test suite has run unless stated.\n"
            "A passing build does NOT prove behavior is preserved. Invariants marked UNVERIFIED must be judged from the diff itself.\n"
            "Deleted files and large deletions must be justified by the task prompt; REVISE when the diff removes behavior the task did not ask to remove.\n"
            "Evaluate across 3 pillars:\n"
            "1. Technical Audit (Code integrity, memory leaks, dangling listeners, breaking API changes, security vulnerabilities)\n"
            "2. Invariants & Contracts (Ensure baseline UI states, interactions, and DB schemas are preserved)\n"
            "3. Ergonomics Polish (UX, responsive styling, accessibility across technical domains)\n"
            "Mandatory Output Format:\n"
            "SCORE: <float between 0.0 and 10.0>\n"
            "VERDICT: <APPROVED or REVISE>\n"
            "SUMMARY: <concise summary>\n"
            "TECHNICAL: <bullet points>\n"
            "ERGONOMICS: <bullet points>\n"
            "REMEDIATION: <bullet points of required fixes if REVISE, or 'None' if APPROVED>\n"
            "INVARIANTS: <'None', or one line per DURABLE project rule this diff reveals that is not already in the "
            "Invariants list above and that the current code satisfies. Format: "
            "`- ID | description | files-glob | forbid-or-require | python-regex` for a machine check, or "
            "`- ID | description` for a rule that cannot be checked by regex. ID: UPPERCASE letters/digits/dashes. "
            "Write each description in the same language as the existing invariant descriptions listed above "
            "(English when there are none), and wrap file paths in backticks. "
            "Propose only rules the project must keep in every future change, not task-specific notes.>"
        )

        files_summary = ", ".join(f"{f.path} ({f.status})" for f in (diff_summary.files if diff_summary else []))
        build_info = f"PASSED ({build_check.command} exit 0)" if (build_check and build_check.passed) else ("FAILED" if build_check else "NOT RUN")
        script = _resolved_script(build_check.output) if build_check else None
        if script:
            # `pnpm run build` alone does not tell the reviewer whether a typecheck ran
            build_info += f"; the script actually executed was: `{script}`"
        violations_info = "\n".join(f"- [{v.severity}] {v.rule_id} {v.file_path}: {v.message}" for v in violations[:30])
        invariants_info = "\n".join(
            f"- [{c.status.upper()}] {c.id}: {c.description} ({c.notes})" for c in (invariant_result.checks if invariant_result else [])
        ) or "- none declared"
        evidence_info = "\n".join(f"- {e}" for e in (evidence or [])) or "- none"

        header = f"""
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
Verified evidence (computed by guard over the whole repository, valid for every diff part):
{evidence_info}
"""

        # No time limit on a review: it ends when the LLM answers or its provider returns an error.
        # llm.timeout is only for `guard config test` pings.
        review_cfg = self.config.llm.model_copy(update={"timeout": None})

        # A large diff is reviewed in parts instead of being truncated, so no change goes unreviewed.
        batches = self._prepare_diff_batches(diff_summary)
        verdicts: List[LLMReviewVerdict] = []
        for i, batch in enumerate(batches, start=1):
            part = f"Diff part {i}/{len(batches)} (other parts are reviewed separately; judge only this part):\n" if len(batches) > 1 else ""
            prompt_text = f"{header}\n{part}Git Diff:\n```\n{batch}\n```\n"
            verdict = None
            for attempt in range(2):  # one retry when the answer ignores the SCORE/VERDICT format
                raw_response = call_llm(
                    cfg=review_cfg,
                    prompt=prompt_text if attempt == 0 else prompt_text + FORMAT_REMINDER,
                    system_prompt=system_prompt,
                    temperature=0.1,
                    max_tokens=1000,
                )
                verdict = self._parse_llm_response(raw_response, model_name=model_name, focus=focus)
                if verdict is not None:
                    break
            if verdict is None:
                self.last_failure = f"part {i}/{len(batches)} answer was not a review: {(raw_response or '').strip()[:160]}"
                return None
            verdicts.append(verdict)
        return self._merge_verdicts(verdicts)

    @staticmethod
    def _merge_verdicts(verdicts: List[LLMReviewVerdict]) -> LLMReviewVerdict:
        """One REVISE part rejects the whole diff; the score is the weakest part's score."""
        if len(verdicts) == 1:
            return verdicts[0]
        first = verdicts[0]
        rejected = any(v.verdict == ReviewVerdict.REVISE for v in verdicts)
        return LLMReviewVerdict(
            verdict=ReviewVerdict.REVISE if rejected else ReviewVerdict.APPROVED,
            score=min(v.score for v in verdicts),
            summary=" ".join(f"[Part {i}/{len(verdicts)}: {v.verdict.value} {v.score:.1f}] {v.summary}" for i, v in enumerate(verdicts, 1)),
            reviewer_model=first.reviewer_model,
            focus_area=first.focus_area,
            technical_audit=[t for v in verdicts for t in v.technical_audit],
            ergonomics_ux=[t for v in verdicts for t in v.ergonomics_ux],
            remediation_steps=[t for v in verdicts for t in v.remediation_steps],
            proposed_invariants=[t for v in verdicts for t in v.proposed_invariants],
            review_mode="llm_deep",
        )


    def _prepare_diff_batches(self, diff_summary: Optional[DiffSummary]) -> List[str]:
        """Code diff split on file boundaries into parts of at most REVIEW_BATCH_CHARS characters."""
        if not diff_summary or not diff_summary.raw_diff:
            return ["No diff"]
        # Filter out asset files, binary/data files, and large non-code JSON tables
        code_chunks = []
        # File headers start a line; "diff --git " inside a changed line (a test fixture, a doc) is content
        for c in re.split(r"(?m)^diff --git ", diff_summary.raw_diff):
            if not c.strip():
                continue
            first_line = c.splitlines()[0] if c.splitlines() else ""
            if any(k in first_line for k in ["assets/", ".lock", "-lock.", ".svg", ".png", ".onnx", "tokenizer.json"]):
                continue
            chunk = "diff --git " + c
            if "\ndeleted file mode" in chunk.split("@@", 1)[0]:
                # A deleted file's full content adds little to a review (removed-symbol references are
                # checked separately) and large blocks of removed code can make a model refuse the part
                head = chunk.split("\n@@", 1)[0]
                removed = sum(1 for line in chunk.splitlines() if line.startswith("-") and not line.startswith("---"))
                chunk = f"{head}\n[file deleted: {removed} lines removed; content omitted]\n"
            # A single oversized file is split too, never cut off; every piece names its file
            prefix = f"{chunk.splitlines()[0]}\n[continued: next part of this file's diff]\n"
            code_chunks.append(chunk[:REVIEW_BATCH_CHARS])
            step = max(1, REVIEW_BATCH_CHARS - len(prefix))  # the prefix counts toward the part limit
            for k in range(REVIEW_BATCH_CHARS, len(chunk), step):
                code_chunks.append(prefix + chunk[k:k + step])
        if not code_chunks:
            return ["No code diff (only lockfiles/assets changed)"]
        batches, current = [], ""
        for chunk in code_chunks:
            if current and len(current) + len(chunk) > REVIEW_BATCH_CHARS:
                batches.append(current)
                current = ""
            current += chunk
        batches.append(current)
        return batches[:REVIEW_MAX_BATCHES] + (
            [f"[{len(batches) - REVIEW_MAX_BATCHES} more diff parts were NOT reviewed (limit {REVIEW_MAX_BATCHES}); treat them as unreviewed]"]
            if len(batches) > REVIEW_MAX_BATCHES else []
        )

    def _parse_llm_response(self, text: str, model_name: str = "LLM", focus: str = "all") -> Optional[LLMReviewVerdict]:
        try:
            score_match = re.search(r"SCORE:\s*([\d\.]+)", text)
            verdict_match = re.search(r"VERDICT:\s*(APPROVED|REVISE)", text, re.IGNORECASE)
            if not score_match and not verdict_match:
                return None

            score = float(score_match.group(1)) if score_match else 8.0
            score = max(0.0, min(10.0, score))
            verdict = ReviewVerdict.APPROVED if (verdict_match and verdict_match.group(1).upper() == "APPROVED") else ReviewVerdict.REVISE

            summary_match = re.search(r"SUMMARY:\s*(.+?)(?=\n[A-Z]+:|$)", text, re.DOTALL)
            summary = summary_match.group(1).strip() if summary_match else "LLM Review completed."

            tech_items = self._extract_bullet_items(text, "TECHNICAL")
            ergo_items = self._extract_bullet_items(text, "ERGONOMICS")
            remed_items = self._extract_bullet_items(text, "REMEDIATION")
            proposals = _parse_invariant_proposals(text)
            if any(item.lower() == "none" for item in remed_items):
                remed_items = []

            return LLMReviewVerdict(
                verdict=verdict,
                score=score,
                summary=summary,
                reviewer_model=model_name,
                focus_area=focus,
                technical_audit=tech_items,
                ergonomics_ux=ergo_items,
                remediation_steps=remed_items,
                proposed_invariants=proposals,
                review_mode="llm_deep",
            )
        except Exception:
            return None

    def _extract_bullet_items(self, text: str, section_header: str) -> List[str]:
        pattern = rf"{section_header}:\s*(.+?)(?=\n[A-Z]+:|$)"
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
