"""`guard deps-check`: check the dependency links shared by the main checkout and worker worktrees."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import typer

from guard.cli import app, console
from guard.core.deps_check import check_main_checkout, check_worktree, main_checkout_links


def _parse_resolve(values: Optional[Sequence[str]]) -> Optional[Dict[str, List[str]]]:
    """`--resolve app=pkg,pkg` values as app -> packages; None when none was given."""
    if not values:
        return None
    resolve: Dict[str, List[str]] = {}
    for value in values:
        app_name, sep, raw_pkgs = value.partition("=")
        pkgs = [pkg.strip() for pkg in raw_pkgs.split(",") if pkg.strip()]
        if not sep or not app_name.strip() or not pkgs:
            raise typer.BadParameter(f"expected <app>=<pkg>[,<pkg>...], got {value!r}", param_hint="--resolve")
        resolve.setdefault(app_name.strip(), []).extend(pkgs)
    return resolve


def _say(line: str) -> None:
    console.print(line, markup=False, highlight=False, soft_wrap=True)


@app.command("deps-check")
def deps_check_cmd(
    repo: Path = typer.Option(..., "--repo", help="The main checkout whose node_modules the workers share"),
    worktree: Optional[List[Path]] = typer.Option(None, "--worktree", help="Worker worktree to check (repeatable)"),
    resolve: Optional[List[str]] = typer.Option(
        None, "--resolve", help="<app>=<pkg>,<pkg>: packages Node must load from <worktree>/<app> (repeatable)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Print the result as JSON"),
):
    """
    Check that every package link of the main checkout resolves inside it, and that each worktree's
    node_modules junction points into it. Read-only.
    Exit code 0 on PASS, 1 on FAIL, 2 on a usage error.
    """
    resolve_map = _parse_resolve(resolve)
    if not repo.is_dir():
        console.print(f"[bold red]❌ --repo is not a directory: {repo}[/bold red]")
        raise typer.Exit(code=2)
    repo = repo.absolute()  # not resolve(): a checkout reached through a link keeps its given path too

    checked = len(main_checkout_links(repo))
    fails = check_main_checkout(repo)
    progress = [f"main checkout: {checked} links checked under {repo}"]
    for wt in worktree or []:
        fails.extend(check_worktree(repo, wt, resolve_map))
        progress.append(f"worktree checked: {wt}")
    result = "FAIL" if fails else "PASS"

    if json_output:
        print(json.dumps({"result": result, "fails": fails, "checked": checked}, indent=2))
    else:
        for line in progress + fails:
            _say(line)
        _say(f"RESULT: {result}")
    if fails:
        raise typer.Exit(code=1)
