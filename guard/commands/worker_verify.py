"""`guard worker-verify`: audit one worker's delivery before the coordinator accepts it."""

from __future__ import annotations

import json
import math
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Sequence

import typer

from guard.cli import app, console
from guard.core.worker_verify import VerifyResult, verify_worker


def _split_own(values: Optional[Sequence[str]]) -> List[str]:
    """`--own` values flattened: every value may itself be a comma-separated list of globs."""
    return [glob.strip() for value in values or [] for glob in value.split(",") if glob.strip()]


def _parse_since(raw: str) -> float:
    """`--since` as epoch seconds: a plain number or ISO 8601 (a trailing Z counts as UTC)."""
    try:
        seconds = float(raw)
    except ValueError:
        try:
            seconds = datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
        except ValueError as e:
            raise typer.BadParameter(
                f"not an ISO 8601 timestamp or epoch seconds: {raw!r}", param_hint="--since"
            ) from e
    if not math.isfinite(seconds):
        raise typer.BadParameter(f"not a finite epoch time: {raw!r}", param_hint="--since")
    return seconds


def _git(worktree: Path, *args: str) -> Optional[str]:
    """Stdout of one read-only git command; None when git fails or cannot be started."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(worktree), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError:
        return None
    return proc.stdout if proc.returncode == 0 else None


def _path_in_worktree(worktree: Path, raw: str) -> Path:
    """A relative CLI path stays inside the worker's worktree (the caller runs elsewhere)."""
    path = Path(raw)
    return path if path.is_absolute() else worktree / path


def _result_line(result: VerifyResult) -> str:
    if result.fails:
        return f"RESULT: FAIL ({len(result.fails)})"
    if result.warns:
        return f"RESULT: PASS with {len(result.warns)} warning(s)"
    return "RESULT: PASS"


@app.command("worker-verify")
def worker_verify_cmd(
    worktree: Path = typer.Option(..., "--worktree", help="The worker's worktree to audit"),
    base: str = typer.Option(..., "--base", help="Base commit (usually the branch point)"),
    role: str = typer.Option("fix", "--role", help="Worker role: fix or test"),
    own: Optional[List[str]] = typer.Option(None, "--own", help="Path the worker may change (repeatable, comma-separated)"),
    report: Optional[str] = typer.Option(None, "--report", help="The worker's report, relative to --worktree or absolute"),
    evidence: Optional[str] = typer.Option(None, "--evidence", help="Evidence directory, relative to --worktree or absolute"),
    since: Optional[str] = typer.Option(None, "--since", help="Freshness cutoff: ISO 8601 or epoch seconds"),
    check: Optional[List[str]] = typer.Option(None, "--check", help="Acceptance command to re-run (repeatable)"),
    quick: bool = typer.Option(False, "--quick", help="Skip the report, evidence and re-run checks"),
    json_output: bool = typer.Option(False, "--json", help="Print the result as JSON"),
):
    """
    Audit one worker's delivery against its base commit and declared ownership.
    Exit code 0 when there is no FAIL, 1 when there is one, 2 on a usage or unexpected error.
    """
    if role not in ("fix", "test"):
        raise typer.BadParameter("must be 'fix' or 'test'", param_hint="--role")
    since_ts = _parse_since(since) if since is not None else None

    if not worktree.is_dir():
        console.print(f"[bold red]❌ --worktree is not a directory: {worktree}[/bold red]")
        raise typer.Exit(code=2)
    inside = _git(worktree, "rev-parse", "--is-inside-work-tree")
    if inside is None or inside.strip() != "true":
        console.print(f"[bold red]❌ --worktree is not inside a git work tree: {worktree}[/bold red]")
        raise typer.Exit(code=2)
    if _git(worktree, "rev-parse", "--verify", f"{base}^{{commit}}") is None:
        console.print(f"[bold red]❌ --base does not resolve to a commit in {worktree}: {base}[/bold red]")
        raise typer.Exit(code=2)

    try:
        result = verify_worker(
            worktree,
            base=base,
            role=role,
            own=_split_own(own),
            report=_path_in_worktree(worktree, report) if report else None,
            evidence=_path_in_worktree(worktree, evidence) if evidence else None,
            since=since_ts,
            check_commands=check or (),
            quick=quick,
        )
    except Exception as e:  # an unexpected failure is a usage error, not a traceback
        console.print(f"[bold red]❌ worker-verify failed: {e}[/bold red]")
        raise typer.Exit(code=2) from e

    if json_output:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for issue in result.warns + result.fails:
            console.print(f"{issue.severity}  [{issue.code}] {issue.message}", markup=False, highlight=False)
        console.print(_result_line(result), markup=False, highlight=False)
    if result.fails:
        raise typer.Exit(code=1)
