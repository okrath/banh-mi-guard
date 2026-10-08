"""`guard config`: the LLM, Alibaba OCR and commit settings."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.markup import escape

from guard.cli import app, console
from guard.core.config import (
    get_global_config_path,
    get_local_config_path,
    load_config,
    load_global_config,
    print_config_table,
    save_config,
)

# Subcommand: guard config
config_app = typer.Typer(
    name="config",
    help="⚙️ Manage Guard configuration (LLM, Alibaba OCR)",
    no_args_is_help=False,
)
app.add_typer(config_app, name="config")


@config_app.callback(invoke_without_command=True)
def config_main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        local_p = get_local_config_path()
        global_p = get_global_config_path()
        active_p = local_p if local_p.is_file() else global_p
        info = f"Source: {active_p}" if active_p.is_file() else "Default (No config file saved yet)"
        cfg = load_config()
        print_config_table(cfg, info)


@config_app.command("llm")
def config_llm_cmd(
    local: bool = typer.Option(False, "--local", "-l", help="Save config to local repository (.guard/config.json)"),
):
    """
    Interactive Step-by-Step wizard to configure LLM (OpenAI-compatible or Anthropic) and auto-sync to Alibaba OCR.
    """
    from guard.core.config import run_llm_wizard
    run_llm_wizard(local=local)


@config_app.command("test")
def config_test_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
):
    """
    Ping test the currently configured LLM endpoint.
    """
    from guard.core.config import LLMProtocol
    from guard.core.llm_client import ping_llm
    cfg = load_config(Path(repo) if repo else None)
    if cfg.llm.protocol == LLMProtocol.CLI:
        console.print(f"[cyan]Checking the [bold]{cfg.llm.cli_agent or '(none chosen)'}[/bold] CLI (model: "
                      f"{cfg.llm.model or 'its default'}): its sign-in and models...[/cyan]")
    else:
        console.print(f"[cyan]Testing connection to [bold]{cfg.llm.base_url}[/bold] (model: {cfg.llm.model})...[/cyan]")
    success, msg, latency = ping_llm(cfg.llm)
    if success:
        console.print(f"[bold green]✅ Ping SUCCESS![/bold green] Response time: {latency:.1f}ms"
                      + (f" — {msg}" if cfg.llm.protocol == LLMProtocol.CLI else ""), highlight=False)
    else:
        console.print(f"[bold red]❌ Ping FAILED:[/bold red] {msg}")


@config_app.command("sync")
def config_sync_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
):
    """
    Manually synchronize LLM credentials to Alibaba Open Code Review (ocr) CLI.
    """
    from guard.core.config import sync_to_alibaba_ocr
    cfg = load_config(Path(repo) if repo else None)
    synced, msg = sync_to_alibaba_ocr(cfg.llm, cfg.ocr.binary_path)
    if synced:
        console.print(f"[bold green]✅ {msg}[/bold green]")
    else:
        console.print(f"[yellow]⚠️ {msg}[/yellow]")


@config_app.command("ocr")
def config_ocr_cmd(
    mode: str = typer.Argument(..., help="always: every guard post runs the Alibaba OCR review; optional: only guard post --full"),
):
    """
    Choose whether every guard post runs the Alibaba OCR review (machine-wide, ~/.guard/config.json).
    For the user, in an interactive terminal.
    It takes minutes; a failed review or a high/critical finding blocks. The Git hook never runs it.
    """
    if mode not in ("always", "optional"):
        console.print("[bold red]❌ The mode is `always` or `optional`.[/bold red]")
        raise typer.Exit(code=1)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        console.print("[bold red]❌ Whether every guard post runs the Alibaba OCR review is the user's decision: run guard config ocr yourself in an interactive terminal.[/bold red]")
        raise typer.Exit(code=1)
    cfg = load_global_config()
    cfg.ocr.always = mode == "always"
    path = save_config(cfg)
    what = "every guard post runs it" if cfg.ocr.always else "only guard post --full runs it"
    console.print(f"[bold green]✅ Alibaba OCR review `{mode}`: {what}.[/bold green] [dim]Saved to {path}[/dim]")


@config_app.command("review")
def config_review_cmd(
    key: Optional[str] = typer.Argument(None, help="The review option to set (omit to show the effective options)"),
    value: Optional[str] = typer.Argument(None, help="Its new value"),
):
    """
    Show the effective review options and where each comes from, or set one (machine-wide, ~/.guard/config.json).
    Setting is for the user, in an interactive terminal. Options: coverage_notes, part_manifest, test_evidence,
    test_checklist, validate_findings (true/false), threat_frame (off/auto), reviewers (1-5), max_llm_calls, stage_timeout_s.
    A repository's .guard/config.json, when it exists, is read instead of the machine-wide file.
    """
    from guard.core.review_options import ReviewOptions, effective_sources, load_review_options

    if key is None:
        cfg = load_config()
        review_cfg = {"review": cfg.review}
        try:
            opts, sources = load_review_options(review_cfg), effective_sources(review_cfg)
        except ValueError as e:
            console.print(f"[bold red]❌ The saved review options are invalid: {escape(str(e))}[/bold red]")
            raise typer.Exit(code=1) from None
        local_p = get_local_config_path()
        console.print(f"[dim]Read from {local_p if local_p.is_file() else get_global_config_path()}; "
                      "flags of guard post override these for one run.[/dim]")
        for name in ReviewOptions.model_fields:
            console.print(f"  {name} = {getattr(opts, name)}  ({sources[name]})", markup=False, highlight=False)
        return

    if value is None:
        console.print("[bold red]❌ Give the new value: guard config review <option> <value>.[/bold red]")
        raise typer.Exit(code=1)
    if key not in ReviewOptions.model_fields:
        console.print(f"[bold red]❌ Unknown review option `{escape(key)}`. Options: {', '.join(ReviewOptions.model_fields)}.[/bold red]")
        raise typer.Exit(code=1)
    try:
        new_value = load_review_options({"review": {key: value}}).model_dump()[key]
    except ValueError as e:
        console.print(f"[bold red]❌ {escape(str(e))}[/bold red]")
        raise typer.Exit(code=1) from None
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        console.print("[bold red]❌ How the review runs is the user's decision: run guard config review yourself in an interactive terminal.[/bold red]")
        raise typer.Exit(code=1)
    cfg = load_global_config()
    cfg.review = {**cfg.review, key: new_value}
    path = save_config(cfg)
    console.print(f"[bold green]✅ Review option `{key}` = {new_value}.[/bold green] [dim]Saved to {path}[/dim]")
    if get_local_config_path().is_file():
        console.print("[yellow]This repository has its own .guard/config.json, which is read instead of the machine-wide file.[/yellow]")


@config_app.command("tests")
def config_tests_cmd(
    scope: str = typer.Argument(..., help="full: every guard post runs all tests; related: only the tests of the changed files until the gate would approve"),
):
    """
    Choose which tests the build check runs (machine-wide, ~/.guard/config.json). With `related`, a pytest build
    runs only the tests related to the changed Python files; the full suite still runs before any approval.
    """
    if scope not in ("full", "related"):
        console.print("[bold red]❌ The scope is `full` or `related`.[/bold red]")
        raise typer.Exit(code=1)
    cfg = load_global_config()
    cfg.tests_scope = scope  # type: ignore[assignment]  # checked above
    path = save_config(cfg)
    what = ("every guard post runs the full test suite" if scope == "full" else
            "a pytest build runs the related tests first; the full suite runs before any approval")
    console.print(f"[bold green]✅ Tests `{scope}`: {what}.[/bold green] [dim]Saved to {path}[/dim]")
    if get_local_config_path().is_file():
        console.print("[yellow]This repository has its own .guard/config.json, which is read instead of the machine-wide file.[/yellow]")


@config_app.command("commit")
def config_commit_cmd(
    mode: str = typer.Argument(..., help="auto: the agent writes commit messages; ask: the agent asks you for each one"),
):
    """
    Choose who writes commit messages for approved work (machine-wide, ~/.guard/config.json).
    """
    if mode not in ("auto", "ask"):
        console.print("[bold red]❌ The mode is `auto` or `ask`.[/bold red]")
        raise typer.Exit(code=1)
    cfg = load_global_config()
    cfg.commit_mode = mode
    path = save_config(cfg)
    who = "the agent writes commit messages" if mode == "auto" else "the agent asks you for every commit message"
    console.print(f"[bold green]✅ Commit mode `{mode}`: {who}.[/bold green] [dim]Saved to {path}[/dim]")
