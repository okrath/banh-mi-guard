"""
Terminal Rich UI Reporter for Banh-Mi-Guard.
Renders visually striking CLI outputs with colorized badges, tables, and panels.
"""

from __future__ import annotations

from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from guard.core.session import PostTaskRecord, PreTaskRecord
from guard.reporters.markdown import commit_instruction, gate_label, ocr_findings

console = Console()


def render_pre_task_terminal(pre: PreTaskRecord):
    # Header panel
    header_text = Text()
    header_text.append("🛡️ BANH-MI-GUARD: PRE-TASK IMPACT NOTE\n", style="bold cyan")
    header_text.append(f"Prompt: ", style="bold white")
    header_text.append(f"{pre.prompt}\n", style="italic yellow")
    header_text.append(f"Domain: ", style="bold white")
    header_text.append(f"{pre.domain.value.upper()}  ", style="bold green")
    console.print(Panel(header_text, border_style="cyan"))

    # Contracts Table
    if pre.existing_contracts:
        table = Table(title="📌 Existing Domain Contracts (Baseline)", show_header=True, header_style="bold magenta")
        table.add_column("Category", style="cyan", width=18)
        table.add_column("Contract Name", style="bold white", width=28)
        table.add_column("Constraint Description", style="dim")

        for c in pre.existing_contracts:
            table.add_row(c.category, c.name, c.description)
        console.print(table)

    # Invariants Panel
    if pre.locked_invariants:
        inv_table = Table(title="🔒 Locked Invariants (Must NOT be broken)", show_header=True, header_style="bold yellow")
        inv_table.add_column("ID", style="bold yellow", width=12)
        inv_table.add_column("Invariant Rule", style="bold white")
        inv_table.add_column("Rationale", style="dim")

        for inv in pre.locked_invariants:
            status = pre.baseline_invariant_status.get(inv.id) or ("manual" if not inv.checks else "")
            inv_table.add_row(inv.id, inv.description, f"{inv.rationale} [{inv.source}{', ' + status if status else ''}]")
        console.print(inv_table)
        if all(inv.source == "template" for inv in pre.locked_invariants):
            console.print("[yellow]⚠️ Generic domain templates: run `guard invariants init` to create guard.invariants.json with this project's real invariants.[/yellow]")

    for r in pre.restarts:
        console.print(f"[bold yellow]⚠️ Restarted over session {r.get('session_id')} ({r.get('status')}); baseline and scope inherited.[/bold yellow]")
    if pre.late_scope:
        console.print(f"[bold yellow]⚠️ Scope added by restart (SCOPE-004 if touched): {', '.join(pre.late_scope)}[/bold yellow]")

    if pre.baseline_dirty:
        console.print(f"[bold yellow]⚠️ Started with {len(pre.baseline_dirty)} pre-existing modified file(s); they will be reported, not vouched for.[/bold yellow]")

    # Target Files
    if pre.expected_files:
        files_str = "\n".join(f"  • [green]{f}[/green]" for f in pre.expected_files)
        console.print(Panel(files_str, title="📁 Expected Impact Range (Target Files)", border_style="green"))
    else:
        console.print("[yellow]⚠️ No scope declared (name files in the prompt or pass --scope); scope will not be audited.[/yellow]")


def render_post_task_terminal(post: PostTaskRecord, pre: Optional[PreTaskRecord] = None):
    # Overall Verdict Badge (from the configured LLM / Gatekeeper)
    is_approved = post.muse_verdict == "APPROVED"
    badge_style = "bold white on green" if is_approved else "bold white on red"
    label = gate_label(post).upper()
    badge_title = f"✅ FINAL {label}: APPROVED" if is_approved else f"❌ FINAL {label}: REVISE REQUIRED"

    summary_text = Text()
    summary_text.append(f"{badge_title}\n\n", style=badge_style)
    summary_text.append("Score: ", style="bold")
    summary_text.append(f"{post.muse_score:.1f} / 10.0\n", style="bold yellow" if is_approved else "bold red")
    if post.muse_notes:
        summary_text.append(f"Assessment: {post.muse_notes}\n", style="italic")
    if post.llm_error:
        summary_text.append(f"LLM review did not run: {post.llm_error}\n", style="bold yellow")

    console.print(Panel(summary_text, border_style="green" if is_approved else "red"))

    # Diff & Blast Radius Table
    if post.diff_summary:
        diff_table = Table(title="📊 Actual Impact Range & Blast Radius (OCR Inspector)", show_header=True)
        diff_table.add_column("File Path", style="bold")
        diff_table.add_column("Status", width=10)
        diff_table.add_column("+ Add", style="green", justify="right", width=8)
        diff_table.add_column("- Del", style="red", justify="right", width=8)
        diff_table.add_column("Scope Audit", justify="center")

        for f in post.diff_summary.files:
            if f.preexisting:
                scope_badge = Text("⏸️ Pre-existing", style="yellow")
            elif f.path in post.out_of_scope_files:
                scope_badge = Text("⚠️ OUT OF SCOPE", style="bold red")
            elif not post.scope_declared:
                scope_badge = Text("❔ Not declared", style="yellow")
            else:
                scope_badge = Text("✅ In Scope", style="green")
            diff_table.add_row(f.path, f.status, str(f.insertions), str(f.deletions), scope_badge)
        console.print(diff_table)

    # Build Check status
    if post.build_check:
        b_color = "green" if post.build_check.passed else "red"
        b_icon = "✅" if post.build_check.passed else "❌"
        b_text = f"{b_icon} Command: [bold]{post.build_check.command}[/bold] | Exit Code: {post.build_check.exit_code} | Duration: {post.build_check.duration_s:.1f}s"
        if not post.build_check.passed:
            b_text += f"\n[dim]{post.build_check.output[:300]}[/dim]"
        console.print(Panel(b_text, title="⚙️ Project Health & Build Verification", border_style=b_color))

    # Invariants Verification
    if post.invariant_result:
        inv_table = Table(title="🧪 Invariant Verification (deterministic checks)", show_header=True)
        inv_table.add_column("ID", width=12)
        inv_table.add_column("Description")
        inv_table.add_column("Verdict", justify="center", width=12)
        inv_table.add_column("Notes", style="dim")

        for c in post.invariant_result.checks:
            v_text = {
                "passed": Text("✅ PASSED", style="bold green"),
                "failed": Text("❌ VIOLATED", style="bold red"),
                "baseline_failed": Text("⚠️ WAS FAILING", style="yellow"),
                "retired": Text("🗑️ RETIRED", style="dim"),
            }.get(c.status, Text("⚪ UNVERIFIED", style="yellow"))
            inv_table.add_row(c.id, c.description, v_text, c.notes)
        console.print(inv_table)

    # Rule Violations (OCR, Code Hygiene & Simplicity)
    if post.rule_violations:
        ocr_viols = [v for v in post.rule_violations if not v.rule_id.startswith(("DEAD-", "LAZY-", "OCR-"))]
        dead_viols = [v for v in post.rule_violations if v.rule_id.startswith("DEAD-")]
        lazy_viols = [v for v in post.rule_violations if v.rule_id.startswith("LAZY-")]

        if ocr_viols:
            viol_table = Table(title="🚨 Built-in Rulebook Violations", show_header=True, header_style="bold red")
            viol_table.add_column("Rule ID", style="bold red", width=10)
            viol_table.add_column("Severity", width=10)
            viol_table.add_column("Location")
            viol_table.add_column("Violation Message")

            for v in ocr_viols:
                loc = f"{v.file_path}:{v.line_number}" if v.line_number else v.file_path
                viol_table.add_row(v.rule_id, v.severity, loc, v.message)
            console.print(viol_table)

        if dead_viols:
            hygiene_table = Table(title="🧹 Code & Asset Hygiene Audit (Dead Code Gate)", show_header=True, header_style="bold yellow")
            hygiene_table.add_column("Rule ID", style="bold yellow", width=10)
            hygiene_table.add_column("Severity", width=10)
            hygiene_table.add_column("Location")
            hygiene_table.add_column("Hygiene Issue & Recommendation")

            for v in dead_viols:
                loc = f"{v.file_path}:{v.line_number}" if v.line_number else v.file_path
                hygiene_table.add_row(v.rule_id, v.severity, loc, v.message)
            console.print(hygiene_table)

        if lazy_viols:
            simplicity_table = Table(title="🛋️ Engineering Frugality & KISS Audit (Simplicity Gate)", show_header=True, header_style="bold magenta")
            simplicity_table.add_column("Rule ID", style="bold magenta", width=10)
            simplicity_table.add_column("Severity", width=10)
            simplicity_table.add_column("Location")
            simplicity_table.add_column("Simplicity & YAGNI Recommendation")

            for v in lazy_viols:
                loc = f"{v.file_path}:{v.line_number}" if v.line_number else v.file_path
                simplicity_table.add_row(v.rule_id, v.severity, loc, v.message)
            console.print(simplicity_table)

    if post.ocr_status:
        style = "red" if post.ocr_status.startswith("did not run") else "cyan"
        console.print(f"[bold {style}]🔎 Alibaba OCR review:[/bold {style}] ", end="")
        console.print(post.ocr_status, markup=False)
        for v in ocr_findings(post):
            loc = f"{v.file_path}:{v.line_number}" if v.line_number else v.file_path
            console.print(f"  [{v.severity}] {v.rule_id} {loc}: {v.message}", markup=False)

    for i in post.learned_invariants:
        console.print(f"[bold green]➕ Learned invariant {i} → .guard/invariants.json (enforced from next guard pre)[/bold green]")
    for r in post.rejected_invariant_proposals:
        console.print(f"[dim]✖️ Invariant proposal not added: {r}[/dim]")

    if post.diff_summary:
        net = post.diff_summary.total_insertions - post.diff_summary.total_deletions
        console.print(f"[dim]Net change: {net:+d} LOC (informational, not scored).[/dim]")

    if post.all_passed:
        console.print("[bold cyan]📝 Commit:[/bold cyan] ", end="")
        console.print(commit_instruction(post), markup=False)
