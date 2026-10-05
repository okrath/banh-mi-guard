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
from typing import List, Literal, Optional, Tuple

from pydantic import BaseModel, Field, ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

console = Console()


class LLMProtocol(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    CLI = "cli"  # the user's own agent CLI (claude, codex, omp): no API key, the subscription answers


class LLMConfig(BaseModel):
    protocol: LLMProtocol = Field(default=LLMProtocol.OPENAI, description="API protocol: openai or anthropic")
    base_url: str = Field(default="https://api.openai.com/v1", description="LLM Base URL")
    api_key: str = Field(default="", description="API Authentication Token")
    model: str = Field(default="gpt-4o", description="Target model name")
    timeout: float = Field(default=60.0, description="HTTP Timeout in seconds")
    cli_agent: str = Field(default="", description="With protocol cli: the agent CLI that answers (claude, codex, omp)")

    @property
    def ready(self) -> bool:
        """An LLM guard can ask: an agent CLI chosen for the CLI protocol (it signs in on its own), else an API key."""
        if self.protocol == LLMProtocol.CLI:
            return bool(self.cli_agent)
        return bool(self.api_key)

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
    # Whether every guard post runs the OCR review, as --full does (True), or only on request (False).
    # None: the user has not chosen yet (optional, and guard setup asks)
    always: Optional[bool] = Field(default=None, description="Run the Alibaba OCR review on every guard post")


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
        except (OSError, json.JSONDecodeError, ValidationError, TypeError, ValueError) as e:
            console.print(f"[yellow]Warning: Could not read local config at {local_path}: {e}[/yellow]")

    return load_global_config()


def load_global_config() -> GuardConfig:
    global_path = get_global_config_path()
    if global_path.is_file():
        try:
            with open(global_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return GuardConfig.model_validate(data)
        except (OSError, json.JSONDecodeError, ValidationError, TypeError, ValueError) as e:
            console.print(f"[yellow]Warning: Could not read global config at {global_path}: {e}[/yellow]")

    return GuardConfig()


def save_config(config: GuardConfig, local: bool = False, repo_path: Optional[Path] = None) -> Path:
    target_path = get_local_config_path(repo_path) if local else get_global_config_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    # the file can hold an API key: created readable by its owner only; an existing file is narrowed too
    # (POSIX; on Windows the mode cannot express this and the user profile's ACL applies)
    fd = os.open(target_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    if os.name != "nt":
        os.chmod(target_path, 0o600)
    with open(fd, "w", encoding="utf-8") as f:
        json.dump(config.model_dump(mode="json"), f, indent=2)
    return target_path


OCR_PROVIDER = "guard"


def _llm_fingerprint(llm: LLMConfig) -> str:
    """What OCR was given, as a hash (the API key never lands in guard's state in clear)."""
    import hashlib
    raw = "\0".join([llm.base_url or "", llm.protocol.value, llm.model or "", llm.api_key or ""])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _sync_state_path() -> Path:
    from guard.core.repo_setup import guard_home
    return guard_home() / "ocr-sync.json"


def _synced() -> dict:
    """{OCR binary: fingerprint of the LLM guard last gave it}."""
    try:
        data = json.loads(_sync_state_path().read_text(encoding="utf-8")).get("synced")
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, AttributeError):
        return {}


def _ocr_key(binary: str) -> str:
    """The executable `binary` resolves to now (a PATH change to another OCR is another key)."""
    found = shutil.which(binary)
    return str(Path(found).resolve()) if found else binary


def _remember_ocr_sync(llm: LLMConfig, binary: str = "ocr") -> None:
    try:
        path = _sync_state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"synced": {**_synced(), _ocr_key(binary): _llm_fingerprint(llm)}}), encoding="utf-8")
    except OSError:
        pass  # only means the next setup syncs once more


def ocr_in_sync(llm: LLMConfig, binary: str = "ocr") -> bool:
    """
    This OCR binary was last given exactly this LLM by guard. OCR has no `config get`, so guard
    remembers what it set, per binary; a change made in OCR by hand is not seen.
    """
    return _synced().get(_ocr_key(binary)) == _llm_fingerprint(llm)


class _sync_lock:
    """An OS lock on ~/.guard/ocr-sync.lock (released by the OS if the process dies)."""

    def __enter__(self):
        path = _sync_state_path().with_suffix(".lock")
        path.parent.mkdir(parents=True, exist_ok=True)
        self.f = open(path, "a+b")
        if os.name == "nt":
            import msvcrt
            import time
            for _ in range(3000):  # msvcrt only offers a non-blocking try: wait up to ~60 s
                try:
                    self.f.seek(0)
                    msvcrt.locking(self.f.fileno(), msvcrt.LK_NBLCK, 1)
                    return self
                except OSError:
                    time.sleep(0.02)
            self.f.close()
            raise OSError("another guard command is syncing Alibaba OCR; try again")
        import fcntl
        fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        try:
            if os.name == "nt":
                import msvcrt
                self.f.seek(0)
                msvcrt.locking(self.f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
        finally:
            self.f.close()


def sync_to_alibaba_ocr(llm: LLMConfig, binary: str = "ocr") -> Tuple[bool, str]:
    if llm.protocol == LLMProtocol.CLI:
        # nothing to sync: guard post --full gives OCR a local endpoint answered by the CLI, for that review only
        return False, ("Nothing to sync: with an agent CLI, guard post --full runs Alibaba OCR through the same CLI "
                       "and leaves OCR's own settings as they are.")
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
        with _sync_lock():  # one sync at a time: the settings and the marker always describe the same LLM
            for key, value in settings:
                subprocess.run([ocr_bin, "config", "set", key, value], check=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
            _remember_ocr_sync(llm, binary)
        return True, "Successfully synced configuration to Alibaba OCR CLI."
    except subprocess.CalledProcessError as e:
        err_out = (e.stderr or "") + (e.stdout or "")
        return False, f"Failed to sync to OCR CLI: {err_out or str(e)}"
    except (subprocess.SubprocessError, OSError, json.JSONDecodeError, ValueError) as e:
        return False, f"Error executing OCR CLI: {str(e)}"


def _cli_wizard(current_cfg: GuardConfig, found: List[str], local: bool, repo_path: Optional[Path]) -> GuardConfig:
    """Option 3: the review runs through `claude`, `codex` or `omp` on this machine; tested before it is saved."""
    if not found:
        console.print("[bold red]❌ None of `claude`, `codex` or `omp` is on PATH.[/bold red] Install one and sign in, then run "
                      "[bold]guard config llm[/bold] again.")
        return current_cfg
    agent = Prompt.ask("Agent CLI", choices=found, default=current_cfg.llm.cli_agent if current_cfg.llm.cli_agent in found else found[0])
    from guard.core import cli_llm
    with console.status(f"[cyan]Checking {agent}'s sign-in and models...[/cyan]"):
        success, msg, models = cli_llm.probe(agent, timeout=current_cfg.llm.timeout)
    if success:
        console.print(f"[bold green]✅ {agent} is signed in[/bold green]")
    else:
        console.print(f"[bold red]❌ {msg}[/bold red]")
        if not Confirm.ask("Save it anyway?", default=False):
            return current_cfg
    same_cli = current_cfg.llm.protocol == LLMProtocol.CLI and current_cfg.llm.cli_agent == agent
    kept = current_cfg.llm.model if same_cli else ""
    for i, name in enumerate(models, 1):  # the CLI's own list: a number picks one, a name or full ID works too
        console.print(f"  {i}. {name}")
    console.print("[dim]Model: a number from the list, a model name, or Enter for the CLI's own default.[/dim]")
    model = Prompt.ask("Model", default=kept).strip()
    if model.isdigit() and 1 <= int(model) <= len(models):
        model = models[int(model) - 1]
    new_llm = LLMConfig(protocol=LLMProtocol.CLI, cli_agent=agent, model=model, base_url="", api_key="",
                        timeout=current_cfg.llm.timeout)
    current_cfg.llm = new_llm
    target_path = save_config(current_cfg, local=local, repo_path=repo_path)
    console.print(f"[bold green]💾 Saved at:[/bold green] [dim]{target_path}[/dim]")
    console.print(f"[cyan]ℹ️  guard post --full runs Alibaba OCR through {agent} too; OCR's own settings are left as they are.[/cyan]")
    return current_cfg


def _wizard_prompt_protocol(current_cfg: GuardConfig) -> tuple[str, List[str]]:
    """Prompt the user to select an LLM protocol (Step 1)."""
    console.print("\n[bold yellow]Step 1: Select API Protocol[/bold yellow]")
    console.print("  [1] [bold green]OpenAI / OpenAI-Compatible[/bold green] (OpenAI, Ollama, DeepSeek, OpenRouter, vLLM, Local Gateway...)")
    console.print("  [2] [bold magenta]Anthropic[/bold magenta] (Claude API)")
    from guard.core import cli_llm
    found = cli_llm.installed()
    console.print("  [3] [bold cyan]My agent CLI[/bold cyan] (no API key: your Claude or Codex subscription answers)"
                  + (f" [dim]found: {', '.join(found)}[/dim]" if found else " [dim]none found on PATH[/dim]"))

    choice = Prompt.ask(
        "Choice",
        choices=["1", "2", "3"],
        default={LLMProtocol.OPENAI: "1", LLMProtocol.ANTHROPIC: "2"}.get(current_cfg.llm.protocol, "3"),
        show_choices=False,
    )
    return choice, found


def _wizard_prompt_api_config(current_cfg: GuardConfig, protocol: LLMProtocol) -> LLMConfig:
    """Prompt for API base URL, key, model, and timeout (Steps 2-5)."""
    if protocol == LLMProtocol.OPENAI:
        default_url = current_cfg.llm.base_url if current_cfg.llm.base_url != "https://api.anthropic.com/v1" else "https://api.openai.com/v1"
        default_model = current_cfg.llm.model if current_cfg.llm.model not in ["claude-3-7-sonnet", "claude-3-5-sonnet"] else "gpt-4o"
    else:
        default_url = current_cfg.llm.base_url if current_cfg.llm.base_url != "https://api.openai.com/v1" else "https://api.anthropic.com/v1"
        default_model = current_cfg.llm.model if current_cfg.llm.model not in ["gpt-4o", "gpt-4o-mini"] else "claude-3-7-sonnet"

    # Step 2: Base URL
    console.print("\n[bold yellow]Step 2: Base URL[/bold yellow]")
    if protocol == LLMProtocol.OPENAI:
        console.print("[dim]• OpenAI: https://api.openai.com/v1\n• Ollama: http://localhost:11434/v1\n• DeepSeek: https://api.deepseek.com/v1\n• Local Gateway: http://127.0.0.1:8090/v1[/dim]")
    else:
        console.print("[dim]• Anthropic: https://api.anthropic.com/v1[/dim]")

    base_url = Prompt.ask("Base URL", default=default_url)

    # Step 3: API Key
    console.print("\n[bold yellow]Step 3: API Key[/bold yellow]")
    env_key = os.environ.get("OPENAI_API_KEY" if protocol == LLMProtocol.OPENAI else "ANTHROPIC_API_KEY", "")
    key_default = current_cfg.llm.api_key or env_key

    if protocol == LLMProtocol.OPENAI and ("localhost" in base_url or "127.0.0.1" in base_url) and not key_default:
        console.print("[dim]Local model detected (Ollama/Gateway). You can press Enter to leave blank if unauthenticated.[/dim]")
        api_key = Prompt.ask("API Key (or Enter to skip)", default="", password=True)
    else:
        api_key = Prompt.ask("API Key", default=key_default, password=True)

    # Step 4: Model Name
    console.print("\n[bold yellow]Step 4: Model Name[/bold yellow]")
    if protocol == LLMProtocol.OPENAI:
        console.print("[dim]Examples: gpt-4o, deepseek-chat, muse, qwen2.5-coder:latest[/dim]")
    else:
        console.print("[dim]Examples: claude-3-7-sonnet, claude-3-5-sonnet, claude-3-5-haiku[/dim]")

    model = Prompt.ask("Model Name", default=default_model)

    # Step 5: Timeout
    console.print("\n[bold yellow]Step 5: Timeout[/bold yellow]")
    console.print("[dim]Maximum request timeout in seconds. For browser automation or local LLMs, recommend 60-120s.[/dim]")
    timeout_str = Prompt.ask("Timeout (seconds)", default=str(int(current_cfg.llm.timeout or 60.0)))
    try:
        timeout_val = float(timeout_str)
    except ValueError:
        timeout_val = 60.0

    return LLMConfig(
        protocol=protocol,
        base_url=base_url.rstrip("/"),
        api_key=api_key,
        model=model,
        timeout=timeout_val,
    )


def _wizard_test_ping(new_llm: LLMConfig) -> bool:
    """Run connection ping test if user confirms (Step 6). Returns False if discarded."""
    console.print("\n[bold yellow]Step 6: Connection Test (Ping Test)[/bold yellow]")
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
                return False
    return True


def _wizard_save_and_sync(current_cfg: GuardConfig, local: bool, repo_path: Optional[Path]) -> None:
    """Persist wizard configuration and sync to Alibaba OCR if enabled (Step 7)."""
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
        synced, ocr_msg = sync_to_alibaba_ocr(current_cfg.llm, current_cfg.ocr.binary_path)
        if synced:
            console.print(f"[bold cyan]🔗 {ocr_msg}[/bold cyan]")
        else:
            console.print(f"[dim yellow]ℹ️  Alibaba OCR Sync: {ocr_msg}[/dim yellow]")


def run_llm_wizard(local: bool = False, repo_path: Optional[Path] = None) -> GuardConfig:
    current_cfg = load_config(repo_path)
    console.print(Panel(
        "[bold cyan]🤖 BANH-MI-GUARD — LLM CONFIGURATION WIZARD[/bold cyan]\n"
        "[dim]Press Enter to accept default values in brackets [ ].[/dim]",
        border_style="cyan"
    ))

    choice, found = _wizard_prompt_protocol(current_cfg)
    if choice == "3":
        return _cli_wizard(current_cfg, found, local, repo_path)

    protocol = LLMProtocol.OPENAI if choice == "1" else LLMProtocol.ANTHROPIC
    new_llm = _wizard_prompt_api_config(current_cfg, protocol)
    current_cfg.llm = new_llm

    if not _wizard_test_ping(new_llm):
        return current_cfg

    _wizard_save_and_sync(current_cfg, local, repo_path)
    return current_cfg

def print_config_table(config: GuardConfig, path_info: str):
    table = Table(title=f"🛡️ Guard Configuration ({path_info})", show_header=True, header_style="bold cyan")
    table.add_column("Category", style="bold")
    table.add_column("Parameter")
    table.add_column("Value", style="green")

    table.add_row("LLM", "Protocol", config.llm.protocol.value)
    if config.llm.protocol == LLMProtocol.CLI:
        table.add_row("LLM", "Agent CLI", config.llm.cli_agent or "(not set)")
        table.add_row("LLM", "Model", config.llm.model or "(the CLI's default)")
    else:
        table.add_row("LLM", "Base URL", config.llm.base_url)
        table.add_row("LLM", "Model", config.llm.model)
        table.add_row("LLM", "API Key", config.llm.masked_api_key)
    table.add_row("LLM", "Timeout", f"{config.llm.timeout}s")


    table.add_row("Alibaba OCR", "Auto-Sync", str(config.ocr.auto_sync))
    table.add_row("Alibaba OCR", "CLI Binary", config.ocr.binary_path)
    # The commit mode is machine-wide: show the global value even when a local config is active
    table.add_row("Commit", "Mode", load_global_config().commit_mode or "(not set: guard config commit auto|ask)")
    
    console.print(table)
