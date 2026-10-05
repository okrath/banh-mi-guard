"""`guard config`: the LLM, Alibaba OCR and commit settings."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer

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
