"""
Markdown Reporter for Banh-Mi-Guard.
Generates standardized Markdown notes strictly matching the dual-gate protocol:
- `### 🔍 PRE-TASK IMPACT NOTE:`
- `### 🧪 POST-TASK VERIFICATION:`
"""

from __future__ import annotations

from typing import Optional

from guard.core.session import PostTaskRecord, PreTaskRecord

INVARIANT_ICONS = {"passed": "✅", "failed": "❌", "unverified": "⚪", "baseline_failed": "⚠️", "retired": "🗑️"}


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


def ocr_findings(post: PostTaskRecord) -> list:
    return [v for v in post.rule_violations if v.rule_id.startswith("OCR-")]


def generate_pre_task_markdown(pre: PreTaskRecord) -> str:
    """
    Generate standard Pre-Task Impact Note.
    """
    md = []
    md.append("### 🔍 PRE-TASK IMPACT NOTE:\n")
    md.append(f"* **Task Request:** {pre.prompt}")
    md.append(f"* **Technical Domain:** {pre.domain.value.upper()} (detected from repository)")
    
    # Baseline
    md.append("\n* **Current Baseline Contracts:**")
    if pre.existing_contracts:
        for c in pre.existing_contracts:
            md.append(f"  - `[{c.category}]` **{c.name}**: {c.description}")
    else:
        md.append("  - Initializing scoped module or no conflicting baseline contracts detected.")

    # Expected Impact Range
    md.append("\n* **Expected Impact Range (Target Files):**")
    if pre.expected_files:
        for f in pre.expected_files:
            md.append(f"  - `{f}`")
    else:
        md.append("  - ⚠️ No scope declared (name files in the prompt or pass `--scope`). Scope will NOT be audited.")

    if pre.base_ref:
        md.append(f"\n* **Base commit:** `{pre.base_ref[:12]}` (post-task diffs against it, including mid-task commits)")
    if pre.restarts or pre.late_scope:
        md.append("\n* **Session restarts:**")
        md.extend(restart_lines(pre))

    if pre.baseline_dirty:
        md.append("\n* **⚠️ Pre-existing modifications (started with --allow-dirty):**")
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


def generate_post_task_markdown(post: PostTaskRecord, pre: Optional[PreTaskRecord] = None) -> str:
    """
    Generate standard Post-Task Verification report.
    """
    md = []
    md.append("### 🧪 POST-TASK VERIFICATION:\n")
    if pre and (pre.restarts or pre.late_scope):
        md.append("* **Session restarts:**")
        md.extend(restart_lines(pre))
        md.append("")

    # Actual Impact Range
    md.append("* **Actual Impact Range:**")
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

    if post.diff_summary:
        net = post.diff_summary.total_insertions - post.diff_summary.total_deletions
        md.append(f"  - *Diff Statistics:* +{post.diff_summary.total_insertions} lines / -{post.diff_summary.total_deletions} lines across {len(post.diff_summary.files)} files (net {net:+d} LOC, not scored).")

    # Build Check
    md.append("\n* **Build & Project Health Check:**")
    if post.build_check:
        icon = "✅" if post.build_check.passed else "❌"
        md.append(f"  - {icon} Command: `{post.build_check.command}` (Exit Code: {post.build_check.exit_code}, Duration: {post.build_check.duration_s:.1f}s)")
        if not post.build_check.passed:
            md.append(f"    ```\n    {post.build_check.output[:400]}\n    ```")
    else:
        md.append("  - ℹ️ No automated build command detected.")

    # Rule Violations (OCR, Hygiene & Simplicity)
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

    if post.invariant_result:
        md.append("\n* **Invariant Verification (deterministic checks):**")
        for c in post.invariant_result.checks:
            icon = INVARIANT_ICONS.get(c.status, "❔")
            md.append(f"  - {icon} `[{c.id}]` {c.description} -> *{c.status.upper()}: {c.notes}*")

    # LLM Gate Review Report
    md.append(f"\n* **Final {gate_label(post)}:**")
    icon = "🤖" if post.review_mode == "llm_deep" else "⚙️"
    md.append(f"  - {icon} **[{post.muse_verdict}]** (Score: {post.muse_score:.1f}/10)")
    if post.muse_notes:
        md.append(f"  - *Assessment:* {post.muse_notes}")
    if post.llm_error:
        md.append(f"  - ⚠️ *LLM review did not run:* {post.llm_error}")

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

    return "\n".join(md)
