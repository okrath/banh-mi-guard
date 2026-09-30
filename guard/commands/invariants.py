"""`guard invariants`: the project's rulebook (init, check, prune)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table

from guard.cli import app, console
from guard.core.project_invariants import (
    INVARIANTS_FILENAME, InvariantsFileError, evaluate_checks, init_invariants_file, learned_without_checks, load_project_invariants, prune_learned_without_checks, similar_groups,
)


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
