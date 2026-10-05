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

import subprocess  # noqa: F401  # mocked as guard.cli.subprocess by tests/test_repo_setup.py
import sys
from pathlib import Path
from typing import List, Optional

import typer

from guard import __app_name__, __version__
from guard.core.repo_setup import needs_refresh, refresh_after_upgrade
from guard.core.session import SessionManager, SessionStatus
from guard.core.updater import get_cached_update_notice, maybe_trigger_background_update_check
from guard.task_flow import (  # noqa: F401
    BUILD_TIMEOUT_S,
    _drop_diff_files,
    _execute_post_task,
    _file_at,
    _fingerprint,
    _followups,
    _known_rules,
    _ocr_cache_key,
    _prompt_paths,
    _record_round,
    _run_build,
    _write_post_report,
    console,
    execute_post_task,
    execute_pre_task,
)

app = typer.Typer(
    name=__app_name__,
    help="🛡️ Banh-Mi-Guard: Dual-gate impact analysis & regression guard for AI-assisted development",
    no_args_is_help=True,
    add_completion=False,
)


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


# The command groups register themselves on `app`, in this order (the order `guard --help` lists them);
# the names imported are what the pipeline above looks up here at call time. Run as `python -m guard.cli`,
# this file is __main__ and registers nothing: its end runs the guard.cli module's main instead.
if __name__ != "__main__":
    import guard.commands.agent  # noqa: E402,F401
    import guard.commands.config  # noqa: E402,F401
    import guard.commands.invariants  # noqa: E402,F401
    import guard.commands.maintenance  # noqa: E402,F401
    import guard.commands.review  # noqa: E402,F401
    from guard.commands.setup import print_setup_health  # noqa: E402


def _force_utf8_console():
    """Git hooks and legacy Windows consoles default to cp1252; emoji output would crash the run."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream and (stream.encoding or "").lower().replace("-", "") != "utf8":
                reconfig = getattr(stream, "reconfigure", None)
                if callable(reconfig):
                    reconfig(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            # Best-effort console UTF-8 reconfigure: never crash on non-standard streams
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
    except Exception as e:
        # CLI boundary: post-upgrade hook refresh must never block the user's command
        console.print(f"[yellow]guard refresh skipped: {e}[/yellow]")
    maybe_trigger_background_update_check()
    try:
        app()
    finally:
        notice = get_cached_update_notice()
        if notice:
            console.print(f"\n[dim yellow]{notice}[/dim yellow]")


if __name__ == "__main__":
    # `python -m guard.cli` runs this file as __main__, but the command groups register on the
    # guard.cli module's app: its main runs, so hooks written as `python -m guard.cli agent-event …` work
    from guard.cli import main as _main
    _main()
