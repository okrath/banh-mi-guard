"""`guard finding`, `accept` and `untracked`: deciding on what a post found."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.markup import escape
from rich.prompt import Prompt

from guard.cli import _fingerprint, _followups, _write_post_report, app, console
from guard.core.ocr_engine import GitDiffInspector
from guard.core.repo_setup import git_root
from guard.core.session import SessionManager, SessionStatus
from guard.reporters.terminal import (
    EXTRA_ROUNDS,
    accept_blocker,
    render_accept_choices,
    render_accept_findings,
    render_accept_gates,
    render_accept_header,
    render_accept_result,
    symbol,
)


def _save_or_exit(mgr: SessionManager, session) -> None:
    try:
        mgr._save(session)
    except OSError as err:
        console.print(f"[bold red]❌ Could not save session: {err}[/bold red]")
        raise typer.Exit(code=1) from err


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
    _save_or_exit(mgr, session)
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
    def changed_since_review() -> list:
        # Every reviewed file is as it was reviewed, and nothing unreviewed has changed since
        return ([f for f, h in reviewed.items() if _fingerprint(target / f) != h]
                + [f for f in GitDiffInspector(target).get_working_files() if f not in reviewed])

    changed = changed_since_review()
    # Everything the task still carries: every follow-up, what is still open, and any raised again last round
    carried = _followups(session.findings_ledger)
    remaining = [e for e in session.findings_ledger if e in carried or e.get("status") == "open"
                 or e.get("round") == session.llm_rounds]
    # Accepting covers the LLM's findings only: the LLM reviews only after build, invariants and scope
    # passed, and they must still show passed in the round being accepted
    blocker = accept_blocker(post, changed)
    render_accept_header(session, console)
    render_accept_gates(post, changed, console)
    render_accept_findings(remaining, console)
    render_accept_choices(blocker, session.revise_budget, console)
    choice = Prompt.ask("Your choice", choices=["c", "q"] if blocker else ["a", "c", "q"], default="q",
                        console=console).strip().lower()
    # checked again: a file may have changed while the prompt waited
    changed = changed_since_review()
    blocker = accept_blocker(post, changed)
    if choice == "a" and blocker:
        console.print(f"[bold red]{escape(symbol(console, '❌', '[x]'))} Not approved: {escape(blocker)}.[/bold red]")
        if changed:
            console.print("Changed since the review: " + ", ".join(changed[:10]), markup=False)
        console.print("Restore the reviewed files, or allow more rounds (c) and run guard post.")
        raise typer.Exit(code=1)
    if choice == "a":
        from guard.core.session import ApprovalKeyError, compute_approval_signature
        try:
            sig = compute_approval_signature(
                mgr.repo_path,
                session.session_id,
                dict(reviewed),
            )
        except (ApprovalKeyError, OSError) as e:
            session.post.approval_signature = None
            session.post.all_passed = False
            session.post.accepted_by_user = False
            _save_or_exit(mgr, session)
            console.print(f"[bold red]❌ {e}[/bold red]")
            raise typer.Exit(code=1) from e

        session.status = SessionStatus.COMPLETED
        session.post.approved_fingerprints = dict(reviewed)
        session.post.all_passed, session.post.accepted_by_user = True, True
        session.post.followups, session.post.needs_user = remaining, False
        session.post.approval_signature = sig
        _save_or_exit(mgr, session)
        _write_post_report(target, session.post, session.pre)
    elif choice == "c":
        session.revise_budget += EXTRA_ROUNDS
        session.status, session.post.needs_user = SessionStatus.NEEDS_FIX, False
        _save_or_exit(mgr, session)
        _write_post_report(target, session.post, session.pre)
    render_accept_result(choice, session, console)


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
            raise typer.Exit(code=1) from e
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
        raise typer.Exit(code=1) from e
