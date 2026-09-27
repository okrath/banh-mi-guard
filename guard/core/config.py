"""
Configuration Management for Banh-Mi-Guard.
Supports Global (~/.guard/config.json) and Local (.guard/config.json).
Provides Interactive Wizard for OpenAI-compatible and Anthropic protocols,
Ping verification, and automatic synchronization to Alibaba OCR CLI.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from enum import Enum
from pathlib import Path
from typing import Literal, Optional, Tuple

from pydantic import BaseModel, Field
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

console = Console()


class LLMProtocol(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class LLMConfig(BaseModel):
    protocol: LLMProtocol = Field(default=LLMProtocol.OPENAI, description="API protocol: openai or anthropic")
    base_url: str = Field(default="https://api.openai.com/v1", description="LLM Base URL")
    api_key: str = Field(default="", description="API Authentication Token")
    model: str = Field(default="gpt-4o", description="Target model name")
    timeout: float = Field(default=60.0, description="HTTP Timeout in seconds")

    @property
    def masked_api_key(self) -> str:
        if not self.api_key:
            return "(none)"
        if len(self.api_key) <= 8:
            return "***"
        return f"{self.api_key[:4]}...{self.api_key[-4:]}"


class OCRConfig(BaseModel):
    auto_sync: bool = Field(default=True, description="Auto synchronize config to Alibaba OCR CLI")
    binary_path: str = Field(default="ocr", description="Command or path for Alibaba OCR CLI")
    concurrency: int = Field(default=0, description="Parallel OCR requests (0 = OCR's default of 8); lower it for a gateway that drops parallel calls")


class GuardConfig(BaseModel):
    llm: LLMConfig = Field(default_factory=LLMConfig)
    ocr: OCRConfig = Field(default_factory=OCRConfig)
    # How the agent gets commit messages: "auto" (it writes them) or "ask" (it asks the user). None: not chosen yet
    commit_mode: Optional[Literal["auto", "ask"]] = None


def get_global_config_path() -> Path:
    return Path.home() / ".guard" / "config.json"


def get_local_config_path(start_path: Optional[Path] = None) -> Path:
    base = start_path or Path.cwd()
    return base / ".guard" / "config.json"


def load_config(repo_path: Optional[Path] = None) -> GuardConfig:
    """The repository's .guard/config.json when it exists, otherwise the machine-wide config."""
    local_path = get_local_config_path(repo_path)
    if local_path.is_file():
        try:
            with open(local_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return GuardConfig.model_validate(data)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not read local config at {local_path}: {e}[/yellow]")

    return load_global_config()


def load_global_config() -> GuardConfig:
    global_path = get_global_config_path()
    if global_path.is_file():
        try:
            with open(global_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return GuardConfig.model_validate(data)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not read global config at {global_path}: {e}[/yellow]")

    return GuardConfig()


def save_config(config: GuardConfig, local: bool = False, repo_path: Optional[Path] = None) -> Path:
    target_path = get_local_config_path(repo_path) if local else get_global_config_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(config.model_dump(mode="json"), f, indent=2)
    return target_path


OCR_PROVIDER = "guard"


def sync_to_alibaba_ocr(llm: LLMConfig, binary: str = "ocr") -> Tuple[bool, str]:
    ocr_bin = shutil.which(binary)
    if not ocr_bin:
        return False, f"CLI '{binary}' (@alibaba-group/open-code-review) not found in PATH."

    # A custom provider keeps guard's protocol: OCR's legacy llm.url is always called as Anthropic
    settings = [
        ("provider", OCR_PROVIDER),
        (f"custom_providers.{OCR_PROVIDER}.url", llm.base_url),
        (f"custom_providers.{OCR_PROVIDER}.protocol", llm.protocol.value),
        (f"custom_providers.{OCR_PROVIDER}.api_key", llm.api_key or "none"),
        (f"custom_providers.{OCR_PROVIDER}.model", llm.model),  # a provider-level model overrides the global one
        ("model", llm.model),
    ]
    try:
        for key, value in settings:
            subprocess.run([ocr_bin, "config", "set", key, value], check=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
        return True, "Successfully synced configuration to Alibaba OCR CLI."
    except subprocess.CalledProcessError as e:
        err_out = (e.stderr or "") + (e.stdout or "")
        return False, f"Failed to sync to OCR CLI: {err_out or str(e)}"
    except Exception as e:
        return False, f"Error executing OCR CLI: {str(e)}"


def run_llm_wizard(local: bool = False, repo_path: Optional[Path] = None) -> GuardConfig:
    current_cfg = load_config(repo_path)
    console.print(Panel(
        "[bold cyan]🤖 BANH-MI-GUARD — LLM CONFIGURATION WIZARD[/bold cyan]\n"
        "[dim]Press Enter to accept default values in brackets [ ].[/dim]",
        border_style="cyan"
    ))

    # Step 1: Select Protocol
    console.print("\n[bold yellow]Step 1: Select API Protocol[/bold yellow]")
    console.print("  [1] [bold green]OpenAI / OpenAI-Compatible[/bold green] (OpenAI, Ollama, DeepSeek, OpenRouter, vLLM, Local Gateway...)")
    console.print("  [2] [bold magenta]Anthropic[/bold magenta] (Claude API)")
    
    choice = Prompt.ask(
        "Choice",
        choices=["1", "2"],
        default="1" if current_cfg.llm.protocol == LLMProtocol.OPENAI else "2",
        show_choices=False,
    )

    if choice == "1":
        protocol = LLMProtocol.OPENAI
        default_url = current_cfg.llm.base_url if current_cfg.llm.base_url != "https://api.anthropic.com/v1" else "https://api.openai.com/v1"
        default_model = current_cfg.llm.model if current_cfg.llm.model not in ["claude-3-7-sonnet", "claude-3-5-sonnet"] else "gpt-4o"
    else:
        protocol = LLMProtocol.ANTHROPIC
        default_url = current_cfg.llm.base_url if current_cfg.llm.base_url != "https://api.openai.com/v1" else "https://api.anthropic.com/v1"
        default_model = current_cfg.llm.model if current_cfg.llm.model not in ["gpt-4o", "gpt-4o-mini"] else "claude-3-7-sonnet"

    # Step 2: Base URL
    console.print(f"\n[bold yellow]Step 2: Base URL[/bold yellow]")
    if protocol == LLMProtocol.OPENAI:
        console.print("[dim]• OpenAI: https://api.openai.com/v1\n• Ollama: http://localhost:11434/v1\n• DeepSeek: https://api.deepseek.com/v1\n• Local Gateway: http://127.0.0.1:8090/v1[/dim]")
    else:
        console.print("[dim]• Anthropic: https://api.anthropic.com/v1[/dim]")
        
    base_url = Prompt.ask("Base URL", default=default_url)

    # Step 3: API Key
    console.print(f"\n[bold yellow]Step 3: API Key[/bold yellow]")
    env_key = os.environ.get("OPENAI_API_KEY" if protocol == LLMProtocol.OPENAI else "ANTHROPIC_API_KEY", "")
    key_default = current_cfg.llm.api_key or env_key
    
    if protocol == LLMProtocol.OPENAI and ("localhost" in base_url or "127.0.0.1" in base_url) and not key_default:
        console.print("[dim]Local model detected (Ollama/Gateway). You can press Enter to leave blank if unauthenticated.[/dim]")
        api_key = Prompt.ask("API Key (or Enter to skip)", default="", password=True)
    else:
        api_key = Prompt.ask("API Key", default=key_default, password=True)

    # Step 4: Model Name
    console.print(f"\n[bold yellow]Step 4: Model Name[/bold yellow]")
    if protocol == LLMProtocol.OPENAI:
        console.print("[dim]Examples: gpt-4o, deepseek-chat, muse, qwen2.5-coder:latest[/dim]")
    else:
        console.print("[dim]Examples: claude-3-7-sonnet, claude-3-5-sonnet, claude-3-5-haiku[/dim]")
        
    model = Prompt.ask("Model Name", default=default_model)

    # Step 5: Timeout
    console.print(f"\n[bold yellow]Step 5: Timeout[/bold yellow]")
    console.print("[dim]Maximum request timeout in seconds. For browser automation or local LLMs, recommend 60-120s.[/dim]")
    timeout_str = Prompt.ask("Timeout (seconds)", default=str(int(current_cfg.llm.timeout or 60.0)))
    try:
        timeout_val = float(timeout_str)
    except ValueError:
        timeout_val = 60.0

    new_llm = LLMConfig(
        protocol=protocol,
        base_url=base_url.rstrip("/"),
        api_key=api_key,
        model=model,
        timeout=timeout_val,
    )
    current_cfg.llm = new_llm

    # Step 6: Test Ping
    console.print(f"\n[bold yellow]Step 6: Connection Test (Ping Test)[/bold yellow]")
    do_ping = Confirm.ask("Do you want to test the connection now?", default=True)
    if do_ping:
        with console.status("[cyan]Sending connection test request to LLM endpoint...[/cyan]"):
            from guard.core.llm_client import ping_llm
            success, msg, latency = ping_llm(new_llm)
        if success:
            console.print(f"[bold green]✅ Connection Successful![/bold green] (Latency: {latency:.1f}ms - {msg})")
        else:
            console.print(f"[bold red]❌ Connection Failed:[/bold red] {msg}")
            if not Confirm.ask("Do you still want to save this configuration?", default=True):
                console.print("[yellow]Configuration discarded.[/yellow]")
                return current_cfg

    # Step 7: Save & Auto-sync
    target_path = save_config(current_cfg, local=local, repo_path=repo_path)
    scope_str = "Local (Repo)" if local else "Global"
    console.print(f"[bold green]💾 Saved {scope_str} configuration at:[/bold green] [dim]{target_path}[/dim]")

    if current_cfg.ocr.auto_sync and local:
        # OCR's configuration is machine-wide: a repository's credentials never reach it as a side effect
        console.print(
            "[dim yellow]ℹ️  Alibaba OCR was not updated: its settings apply to the whole machine. "
            "Run `guard config sync --repo <this repository>` to use this LLM for every OCR review.[/dim yellow]"
        )
    elif current_cfg.ocr.auto_sync:
        synced, ocr_msg = sync_to_alibaba_ocr(new_llm, current_cfg.ocr.binary_path)
        if synced:
            console.print(f"[bold cyan]🔗 {ocr_msg}[/bold cyan]")
        else:
            console.print(f"[dim yellow]ℹ️  Alibaba OCR Sync: {ocr_msg}[/dim yellow]")

    return current_cfg


def print_config_table(config: GuardConfig, path_info: str):
    table = Table(title=f"🛡️ Guard Configuration ({path_info})", show_header=True, header_style="bold cyan")
    table.add_column("Category", style="bold")
    table.add_column("Parameter")
    table.add_column("Value", style="green")

    table.add_row("LLM", "Protocol", config.llm.protocol.value)
    table.add_row("LLM", "Base URL", config.llm.base_url)
    table.add_row("LLM", "Model", config.llm.model)
    table.add_row("LLM", "API Key", config.llm.masked_api_key)
    table.add_row("LLM", "Timeout", f"{config.llm.timeout}s")


    table.add_row("Alibaba OCR", "Auto-Sync", str(config.ocr.auto_sync))
    table.add_row("Alibaba OCR", "CLI Binary", config.ocr.binary_path)
    # The commit mode is machine-wide: show the global value even when a local config is active
    table.add_row("Commit", "Mode", load_global_config().commit_mode or "(not set: guard config commit auto|ask)")
    
    console.print(table)
