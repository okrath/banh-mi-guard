"""
Terminal Rich UI Reporter for Banh-Mi-Guard.
Renders visually striking CLI outputs with colorized badges, tables, and panels.
"""

from __future__ import annotations

from typing import Optional

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from guard.core.session import PostTaskRecord, PreTaskRecord
from guard.reporters.markdown import commit_instruction, gate_label, ocr_findings

console = Console()


def _format_terminal_domain(pre: PreTaskRecord) -> str:
    task_str = pre.domain.value.upper()
    repo_dom = pre.repo_domain or pre.domain
    repo_str = repo_dom.value.upper()
    source_str = f" ({pre.domain_source})" if pre.domain_source else " (source unknown)"
    if repo_str != task_str:
        base = f"{task_str} (task) in a {repo_str} repository{source_str}"
    else:
        base = f"{task_str}{source_str}"
    if getattr(pre, "domain_reason", ""):
        return f"{base}: {pre.domain_reason}"
    return base


def render_pre_task_terminal(pre: PreTaskRecord):
    # Header panel
    header_text = Text()
    header_text.append("🛡️ BANH-MI-GUARD: PRE-TASK IMPACT NOTE\n", style="bold cyan")
    header_text.append(f"Prompt: ", style="bold white")
    header_text.append(f"{pre.prompt}\n", style="italic yellow")
    header_text.append(f"Domain: ", style="bold white")
    header_text.append(f"{_format_terminal_domain(pre)}  ", style="bold green")
    console.print(Panel(header_text, border_style="cyan"))

    # Contracts Table
    if pre.existing_contracts:
        table = Table(title="📌 Existing Domain Contracts (Baseline)", show_header=True, header_style="bold magenta")
        table.add_column("Category", style="cyan", width=18)
        table.add_column("Contract Name", style="bold white", width=28)
        table.add_column("Constraint Description", style="dim")

        for c in pre.existing_contracts:
            table.add_row(escape(c.category), escape(c.name), escape(c.description))
        console.print(table)
        if pre.contracts_source:
            console.print(f"[dim]Source: {escape(pre.contracts_source)}[/dim]")
        else:
            console.print("[dim]Source: source unknown (session recorded before guard tracked it)[/dim]")
    elif not pre.contracts_source:
        console.print("[dim]📌 Existing Domain Contracts: contracts: source unknown (session recorded before guard tracked it)[/dim]")
    elif pre.contracts_source.startswith("not extracted"):
        console.print(f"[dim]📌 Existing Domain Contracts: contracts: {escape(pre.contracts_source)}[/dim]")
    elif pre.contracts_source.startswith("LLM"):
        console.print(f"[dim]📌 Existing Domain Contracts: none found ({escape(pre.contracts_source)})[/dim]")
    else:
        console.print(f"[dim]📌 Existing Domain Contracts: contracts: not extracted ({escape(pre.contracts_source)})[/dim]")
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
    if pre.impact and (pre.impact.symbols or pre.impact.invariants or pre.impact.notes):
        rows = []
        for f in sorted({s.file for s in pre.impact.symbols} | set(pre.impact.invariants)):
            syms = [s for s in pre.impact.symbols if s.file == f]
            callers = {r for s in syms for r in s.references}
            tests = {t for s in syms for t in s.tests}
            ids = pre.impact.invariants.get(f)
            rows.append(f"  • {f}: {len(syms)} symbol(s), {len(callers)} referencing file(s), {len(tests)} test file(s)"
                        + (f"; invariants {', '.join(ids)}" if ids else ""))
        rows.extend(f"  ⚠️ capped: {n}" for n in pre.impact.notes)
        console.print(Panel(Text("\n".join(rows)), title="🧭 Expected symbols, callers and tests (details in PRE_TASK_NOTE.md)",
                            border_style="green"))


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

    for f in post.findings:
        label = "[bold red]BLOCKING[/bold red]" if f.get("blocking") else "[dim]advisory[/dim]"
        console.print(f"{label} [{f.get('id')}] {f.get('severity')} {f.get('kind')} ", end="")
        console.print(f"{f.get('location') or '-'}: {f.get('description', '')}", markup=False)
    for f in post.followups:
        console.print(f"[dim]follow-up [{f.get('id')}] {f.get('status', 'open')}[/dim] ", end="")
        console.print(f"{f.get('location') or '-'}: {f.get('description', '')}", markup=False)
    if post.needs_user:
        console.print("[bold yellow]🧑 needs_user: stop and ask the user to run guard accept in their terminal.[/bold yellow]")

    if post.ocr_status:
        style = "red" if post.ocr_status.startswith("did not run") else "cyan"
        console.print(f"[bold {style}]🔎 Alibaba OCR review:[/bold {style}] ", end="")
        console.print(post.ocr_status, markup=False)
        for v in ocr_findings(post):
            loc = f"{v.file_path}:{v.line_number}" if v.line_number else v.file_path
            console.print(f"  [{v.severity}] {v.rule_id} {loc}: {v.message}", markup=False)

    if post.impact_summary:
        console.print("[bold cyan]🧭 Impact range:[/bold cyan] ", end="")
        console.print(post.impact_summary, markup=False)

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
