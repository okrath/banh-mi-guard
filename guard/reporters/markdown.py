"""
Markdown Reporter for Banh-Mi-Guard.
Generates standardized Markdown notes strictly matching the dual-gate protocol:
- `### 🔍 PRE-TASK IMPACT NOTE:`
- `### 🧪 POST-TASK VERIFICATION:`
"""

from __future__ import annotations

from typing import Optional

from guard.core.impact import ImpactRange, is_test
from guard.core.session import PostTaskRecord, PreTaskRecord, describe_owner

INVARIANT_ICONS = {"passed": "✅", "failed": "❌", "unverified": "⚪", "baseline_failed": "⚠️", "retired": "🗑️"}


def snapshot_missing_reason(pre: Optional[PreTaskRecord]) -> Optional[str]:
    """Extract baseline snapshot failure reason recorded at pre, if any."""
    if not pre:
        return None
    return pre.baseline_snapshot_error


def restart_lines(pre: PreTaskRecord) -> list:
    lines = []
    for r in pre.restarts:
        lines.append(f"  - ⚠️ Restarted with --force over session `{r.get('session_id')}` ({r.get('status')}) at {r.get('at')}")
    if pre.late_scope:
        lines.append(f"  - ⚠️ Scope added only by a restart (reported as SCOPE-004): {', '.join(f'`{s}`' for s in pre.late_scope)}")
    return lines


def gate_label(post: PostTaskRecord) -> str:
    """Name the gate by what actually ran, never claim an LLM review that did not happen."""
    return "LLM Gate" if post.review_mode == "llm_deep" else "Heuristic Gate (no LLM review)"


def heuristic_reason(post: PostTaskRecord) -> str:
    """Why the heuristic gate decided, or "" when the LLM answered; never claims a review that did not happen."""
    if post.review_mode == "llm_deep":
        return ""
    return post.llm_error or "a failed build or a hard rule decided before the LLM was asked"


def validation_summary(post: PostTaskRecord) -> str:
    """"Finding validation: N checked, M demoted (evidence quoted)", or "" when the stage did not check anything."""
    if not post.validation_log:
        return ""
    checked = {str(e.get("finding_id")) for e in post.validation_log}
    demoted = sum(1 for f in post.findings if str(f.get("id")) in checked and not f.get("blocking")
                  and "[contested:" in str(f.get("description", "")))
    return f"Finding validation: {len(post.validation_log)} checked, {demoted} demoted (evidence quoted)"


def limit_lines(post: PostTaskRecord) -> list:
    """What the review did not see, as plain lines (empty when it saw everything); the caller renders them."""
    if not post.coverage_notes:
        return []
    lead = ["The approval covers only what the review saw."] if post.muse_verdict == "APPROVED" else []
    return lead + [str(n) for n in post.coverage_notes]


COMMIT_INSTRUCTIONS = {
    "auto": "Commit mode `auto`: write the commit message yourself (conventional commit describing the change; never mention guard, its gates or scores).",
    "ask": "Commit mode `ask`: before committing, ask the user for the commit message and use it as given.",
}


def commit_instruction(post: PostTaskRecord) -> str:
    """What the agent does before and for the commit; the choices are the user's (guard config commit, --full)."""
    message = COMMIT_INSTRUCTIONS.get(post.commit_mode or "", (
        "Commit mode not set: ask the user whether you write commit messages (`auto`) or they type them (`ask`), "
        "then run `guard config commit auto` or `guard config commit ask`."
    ))
    if post.ocr_status.startswith("not run"):
        # Approved by the gate alone: the user decides whether a full Alibaba OCR review comes first
        message = (
            "Before committing, ask the user whether they want a full review with Alibaba OCR first "
            "(`guard post --full`, takes minutes). If yes, run it and follow its report; if no, this gate approval is enough. "
            "Tell them `guard config ocr always` runs it on every post, if they want that. "
            + message
        )
    return message


def inert(text: str) -> str:
    """
    OCR output is written by an LLM that read the diff: shown as one line of inline code so it can
    never add a report section, a link, HTML or an instruction to the report the agent reads.
    """
    flat = " ".join(str(text).split()).replace("`", "'")
    return f"`{flat}`" if flat else "*(empty)*"


def _clean_inert(text: str) -> str:
    """Remove backticks and replace newlines with spaces so LLM output remains inert inline code."""
    return str(text).replace("`", "").replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def ocr_findings(post: PostTaskRecord) -> list:
    return [v for v in post.rule_violations if v.rule_id.startswith("OCR-")]


def impact_lines(impact: ImpactRange) -> list:
    """Per scoped file: its invariants, then each symbol with its callers and tests (repository names shown inert)."""
    by_file: dict = {}
    for sym in impact.symbols:
        by_file.setdefault(sym.file, []).append(sym)
    lines = []
    for f in sorted(set(by_file) | set(impact.invariants)):
        ids = impact.invariants.get(f)
        lines.append(f"  - {inert(f)}" + (f" (invariants: {inert(', '.join(ids))})" if ids else ""))
        unreferenced = []
        for sym in by_file.get(f, []):
            if not sym.references:
                unreferenced.append(inert(sym.name))
                continue
            callers = ", ".join(inert(r) for r in sym.references if not is_test(r)) or "only tests"
            tests = ", ".join(inert(t) for t in sym.tests) or "none"
            lines.append(f"    - {inert(sym.name)} ({sym.kind}): {callers}{' …' if sym.capped else ''}; tests: {tests}")
        if unreferenced:
            lines.append(f"    - not referenced from other files: {', '.join(unreferenced)}")
    lines.extend(f"  - ⚠️ capped: {inert(n)}" for n in impact.notes)
    return lines


def _format_domain_description(pre: PreTaskRecord) -> str:
    task_str = pre.domain.value.upper()
    repo_dom = pre.repo_domain or pre.domain
    repo_str = repo_dom.value.upper()
    source_str = f" (`{_clean_inert(pre.domain_source)}`)" if pre.domain_source else " (source unknown)"
    if repo_str != task_str:
        base = f"{task_str} (task) in a {repo_str} repository{source_str}"
    else:
        base = f"{task_str}{source_str}"
    if getattr(pre, "domain_reason", ""):
        return f"{base}: `{_clean_inert(pre.domain_reason)}`"
    return base


def owner_lines(pre: PreTaskRecord) -> list:
    """The agent session that owns the task (other agent sessions in this working tree are judged apart)."""
    owner = pre.owner if isinstance(pre.owner, dict) and pre.owner.get("session") else None
    return [f"* **Owner:** `{_clean_inert(describe_owner(owner))}`"] if owner else []


def contract_lines(pre: PreTaskRecord) -> list:
    """The baseline contracts recorded at pre and where they came from (the LLM, or why none)."""
    md = []
    if pre.existing_contracts:
        if pre.contracts_source:
            md.append(f"  - Source: `{_clean_inert(pre.contracts_source)}`")
        else:
            md.append("  - Source: source unknown (session recorded before guard tracked it)")
        for c in pre.existing_contracts:
            md.append(f"  - `[{_clean_inert(c.category)}]` `{_clean_inert(c.name)}`: `{_clean_inert(c.description)}`")
    elif not pre.contracts_source:
        md.append("  - contracts: source unknown (session recorded before guard tracked it)")
    elif pre.contracts_source.startswith("not extracted"):
        md.append(f"  - contracts: `{_clean_inert(pre.contracts_source)}`")
    elif pre.contracts_source.startswith("LLM"):
        md.append(f"  - none found (`{_clean_inert(pre.contracts_source)}`)")
    else:
        md.append(f"  - contracts: not extracted (`{_clean_inert(pre.contracts_source)}`)")
    return md


def generate_pre_task_markdown(pre: PreTaskRecord) -> str:
    """
    Generate standard Pre-Task Impact Note.
    """
    md = []
    md.append("### 🔍 PRE-TASK IMPACT NOTE:\n")
    md.append(f"* **Task Request:** {pre.prompt}")
    md.extend(owner_lines(pre))
    md.append(f"* **Technical Domain:** {_format_domain_description(pre)}")

    # Baseline
    md.append("\n* **Current Baseline Contracts:**")
    md.extend(contract_lines(pre))
    # Expected Impact Range
    md.append("\n* **Expected Impact Range (Target Files):**")
    if pre.expected_files:
        for f in pre.expected_files:
            md.append(f"  - `{f}`")
    else:
        md.append("  - ⚠️ No scope declared (name files in the prompt or pass `--scope`). Scope will NOT be audited.")
    if pre.impact and (pre.impact.symbols or pre.impact.invariants or pre.impact.notes):
        md.append("\n* **Expected Impact Range (symbols, their callers, covering tests, invariants):**")
        md.extend(impact_lines(pre.impact))

    if pre.base_ref:
        md.append(f"\n* **Base commit:** `{pre.base_ref[:12]}` (post-task diffs against it, including mid-task commits)")
    if pre.restarts or pre.late_scope:
        md.append("\n* **Session restarts:**")
        md.extend(restart_lines(pre))

    if pre.baseline_dirty:
        md.append("\n* **⚠️ Pre-existing modifications (started with --allow-dirty):**")
        if not pre.baseline_snapshot:
            snapshot_reason = pre.baseline_snapshot_error
            reason_part = f" ({snapshot_reason})" if snapshot_reason else ""
            md.append(f"  - ⚠️ *Baseline snapshot missing{reason_part}:* post will review the full diff.")
        for f in sorted(pre.baseline_dirty):
            md.append(f"  - `{f}`")

    # Non-Regression Strategy & Invariants
    md.append("\n* **Non-Regression Strategy & Locked Invariants:**")
    if pre.non_regression_strategy:
        md.append(f"  - *Strategy:* {pre.non_regression_strategy}")
    if pre.locked_invariants and all(inv.source == "template" for inv in pre.locked_invariants):
        md.append("  - ⚠️ Generic domain templates (no `guard.invariants.json` in repo); most cannot be verified automatically. Create the file with `guard invariants init`, then validate it with `guard invariants check`.")
    for inv in pre.locked_invariants:
        status = pre.baseline_invariant_status.get(inv.id)
        badge = f" {INVARIANT_ICONS.get(status, '')} baseline: {status}" if status else (" ⚪ manual" if not inv.checks else "")
        md.append(f"  - `[{inv.id}]` **{inv.description}** {f'({inv.rationale})' if inv.rationale else ''}{badge}")

    return "\n".join(md)


def _markdown_prelude(pre: Optional[PreTaskRecord]) -> list:
    md = []
    if not pre:
        return md
    if pre.restarts or pre.late_scope:
        md.append("* **Session restarts:**")
        md.extend(restart_lines(pre))
        md.append("")
    md.extend(owner_lines(pre))
    md.append(f"* **Technical Domain:** {_format_domain_description(pre)}")
    md.append("* **Baseline Contracts:**")
    md.extend(contract_lines(pre))
    md.append("")
    return md


def _markdown_impact_range(post: PostTaskRecord, pre: Optional[PreTaskRecord]) -> list:
    md = ["* **Actual Impact Range:**"]
    if post.files_modified:
        for f in post.files_modified:
            if f in post.preexisting_files:
                badge = "⏸️ [PRE-EXISTING, untouched]"
            elif f in post.out_of_scope_files:
                badge = "⚠️ [OUT-OF-SCOPE]"
            elif f in post.deleted_files:
                badge = "🗑️ [DELETED]"
            elif not post.scope_declared:
                badge = "❔ [scope not declared]"
            else:
                badge = "✅"
            md.append(f"  - {badge} `{f}`")
    else:
        md.append("  - No files were modified.")

    if pre and pre.baseline_dirty and not pre.baseline_snapshot:
        snapshot_reason = pre.baseline_snapshot_error
        reason_part = f" ({snapshot_reason})" if snapshot_reason else ""
        md.append(f"  - ⚠️ *Baseline snapshot missing{reason_part}:* review covers the full diff.")
    if post.diff_summary:
        net = post.diff_summary.total_insertions - post.diff_summary.total_deletions
        md.append(f"  - *Diff Statistics:* +{post.diff_summary.total_insertions} lines / -{post.diff_summary.total_deletions} lines across {len(post.diff_summary.files)} files (net {net:+d} LOC, not scored).")
        if post.diff_summary.error:
            md.append(f"  - ⚠️ *Diff inspection error:* {post.diff_summary.error}")
    return md


def _markdown_build_check(post: PostTaskRecord) -> list:
    md = ["\n* **Build & Project Health Check:**"]
    if post.build_check:
        icon = "✅" if post.build_check.passed else "❌"
        md.append(f"  - {icon} Command: `{post.build_check.command}` (Exit Code: {post.build_check.exit_code}, Duration: {post.build_check.duration_s:.1f}s)")
        if post.build_check.related:
            md.append(f"  - Related tests only ({len(post.build_check.related)} file(s)); the full suite runs before any approval.")
        if not post.build_check.passed:
            md.append(f"    ```\n    {post.build_check.output[:400]}\n    ```")
    else:
        md.append("  - ℹ️ No automated build command detected.")
    return md


def _markdown_violations_and_invariants(post: PostTaskRecord) -> list:
    md = []
    if post.rule_violations:
        rule_viols = [v for v in post.rule_violations if not v.rule_id.startswith(("DEAD-", "LAZY-", "OCR-"))]
        dead_viols = [v for v in post.rule_violations if v.rule_id.startswith("DEAD-")]
        lazy_viols = [v for v in post.rule_violations if v.rule_id.startswith("LAZY-")]

        if rule_viols:
            md.append("\n* **Built-in Rulebook Alerts:**")
            for v in rule_viols:
                md.append(f"  - `[{v.severity}]` **{v.rule_id}**: {v.message} at `{v.file_path}`")

        if dead_viols:
            md.append("\n* **Code & Asset Hygiene Alerts (Dead Code Gate):**")
            for v in dead_viols:
                md.append(f"  - `[{v.severity}]` **{v.rule_id}**: {v.message} at `{v.file_path}`")

        if lazy_viols:
            md.append("\n* **Engineering Frugality & Simplicity Alerts (KISS / YAGNI):**")
            for v in lazy_viols:
                md.append(f"  - `[{v.severity}]` **{v.rule_id}**: {v.message} at `{v.file_path}`")

    if post.ocr_status:
        md.append(f"\n* **Alibaba OCR Review:** {inert(post.ocr_status)}")
        for v in ocr_findings(post):
            loc = f"{v.file_path}:{v.line_number}" if v.line_number else v.file_path
            md.append(f"  - `[{v.severity}]` {inert(v.rule_id)} at {inert(loc)}: {inert(v.message)}")

    if post.impact_summary:
        md.append(f"\n* **Impact Range:** {inert(post.impact_summary)} (IMPACT findings are MEDIUM and never block.)")

    if post.invariant_result:
        md.append("\n* **Invariant Verification (deterministic checks):**")
        for c in post.invariant_result.checks:
            icon = INVARIANT_ICONS.get(c.status, "❔")
            md.append(f"  - {icon} `[{c.id}]` {c.description} -> *{c.status.upper()}: {c.notes}*")
    return md


def _markdown_gate_and_findings(post: PostTaskRecord) -> list:
    md = [f"\n* **Final {gate_label(post)}:**"]
    icon = "🤖" if post.review_mode == "llm_deep" else "⚙️"
    md.append(f"  - {icon} **[{post.muse_verdict}]** (Score: {post.muse_score:.1f}/10)")
    if post.muse_notes:
        md.append(f"  - *Assessment:* {post.muse_notes}")
    if post.llm_error:
        md.append(f"  - ⚠️ *LLM review did not run:* {post.llm_error}")
    if validation_summary(post):
        md.append(f"  - {validation_summary(post)}")
    limits = limit_lines(post)
    if limits:
        md.append("\n* **Not reviewed / limits:**")
        md.extend(f"  - {inert(line)}" for line in limits)

    blocking = [f for f in post.findings if f.get("blocking")]
    advisory = [f for f in post.findings if not f.get("blocking")]
    if blocking:
        md.append("\n* **Blocking findings** (guard's rule: critical/high correctness or security, or a stated requirement):")
        for f in blocking:
            md.append(f"  - `[{f.get('id')}]` {f.get('severity')} {f.get('kind')} at {inert(f.get('location') or '-')} "
                      f"({f.get('why_blocking')}): {inert(f.get('description', ''))}")
    if advisory:
        md.append("\n* **Advisory findings** (not blocking; kept as follow-ups):")
        for f in advisory:
            md.append(f"  - `[{f.get('id')}]` {f.get('severity')} {f.get('kind')} at {inert(f.get('location') or '-')}: "
                      f"{inert(f.get('description', ''))}")
    if blocking or advisory:
        md.append("  - A finding you will not fix now: `guard finding <id> --defer \"<why, where it is handled>\"`, "
                  "or `--reject \"<evidence>\"` when it is wrong; the next review sees the reason.")
    if post.needs_user:
        md.append("\n* **needs_user:** this task used its review rounds. Stop and ask the user: they read the findings "
                  "above and run `guard accept` in their own terminal (accept them as follow-ups, or allow more rounds).")
    if post.accepted_by_user:
        md.append("\n* **Approved by the user** (`guard accept`); the remaining findings are follow-ups.")
    if post.followups:
        md.append("\n* **Follow-ups of this task** (advisory or deferred, from every round):")
        for f in post.followups:
            md.append(f"  - `[{f.get('id')}]` {f.get('status', 'open')} {f.get('severity')} {f.get('kind')} at "
                      f"{inert(f.get('location') or '-')}: {inert(f.get('description', ''))}")

    if post.learned_invariants or post.rejected_invariant_proposals:
        md.append("\n* **Invariants learned in this review (`.guard/invariants.json`, local):**")
        for i in post.learned_invariants:
            md.append(f"  - ➕ {i}: added, enforced from the next `guard pre`")
        for r in post.rejected_invariant_proposals:
            md.append(f"  - ✖️ proposal not added: {r}")

    if post.all_passed:
        md.append(f"\n* **Commit:** {commit_instruction(post)}")
    else:
        md.append(f"\n* **Commit:** nothing to commit until the gate approves (commit mode: `{post.commit_mode or 'not set'}`).")
    return md


def generate_post_task_markdown(post: PostTaskRecord, pre: Optional[PreTaskRecord] = None) -> str:
    """
    Generate standard Post-Task Verification report.
    """
    md = ["### 🧪 POST-TASK VERIFICATION:\n"]
    if heuristic_reason(post):
        md.append(f"* **Heuristic gate ran, not an LLM review:** {inert(heuristic_reason(post))}")
    md.extend(_markdown_prelude(pre))
    md.extend(_markdown_impact_range(post, pre))
    md.extend(_markdown_build_check(post))
    md.extend(_markdown_violations_and_invariants(post))
    md.extend(_markdown_gate_and_findings(post))
    return "\n".join(md)
