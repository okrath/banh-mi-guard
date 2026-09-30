"""`guard review`, `update` and `doctor`: a review outside a task, and keeping an installation current and healthy."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table

from guard import __version__
from guard.cli import app, console
from guard.core.config import load_config
from guard.core.hygiene_engine import HygieneEngine
from guard.core.llm_reviewer import LLMReviewerEngine, ReviewVerdict
from guard.core.ocr_engine import GitDiffInspector, OCRRulebookRunner
from guard.core.simplicity_engine import SimplicityEngine
from guard.core.updater import (
    UpdateSecurityStatus, check_guard_self_update, check_ocr_update, perform_ocr_upgrade, perform_self_upgrade,
)
from guard.domains.detector import detect_domain


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
    from guard.commands.setup import finish_setup  # at call time: groups register in order
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
    from guard.commands.setup import print_setup_health  # at call time: groups register in order
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
