"""`guard setup`, `install`, `uninstall` and `guard hook`: putting guard into agents and repositories."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import typer
from rich.table import Table

from guard.cli import app, console
from guard.core.config import load_config
from guard.core.repo_setup import (
    ensure_repo_setup,
    git_root,
    install_global,
    install_workspace,
    refresh_after_upgrade,
    refresh_repo,
    uninstall_global,
    uninstall_workspace,
)
from guard.core.setup_health import setup_health
from guard.hooks.installer import HookInstaller


def print_setup_health(cwd: Path, title: str, only_problems: bool = False) -> int:
    """Print the setup check; returns the number of missing items."""
    rows = setup_health(cwd)
    problems = [r for r in rows if r["level"] != "ok"]
    if only_problems and not problems:
        return 0
    table = Table(title=title, show_header=True, header_style="bold magenta")
    table.add_column("Item", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Detail")
    table.add_column("How to fix", style="cyan")
    badge = {"ok": "[green]✅ OK[/green]", "warn": "[yellow]⚠️ WARN[/yellow]", "missing": "[bold red]❌ MISSING[/bold red]"}
    for r in (problems if only_problems else rows):
        table.add_row(r["item"], badge[r["level"]], r["detail"], r["fix"])
    console.print(table)
    return sum(1 for r in rows if r["level"] == "missing")


def _setup_ocr_steps(step: Callable, cwd: Path, done: List[Tuple[str, str]], left: List[Tuple[str, str]]) -> None:
    from guard.commands.config import config_ocr_cmd
    from guard.core.config import load_global_config, ocr_in_sync, sync_to_alibaba_ocr
    from guard.core.updater import perform_ocr_upgrade

    # 2. Alibaba OCR, for `guard post --full` (installed through the same quarantine as `guard update ocr`).
    # The binary is the one guard post and doctor use here (a repository may name its own)
    ocr_binary = load_config(cwd).ocr.binary_path
    if not shutil.which(ocr_binary):
        def install_ocr():
            ok, msg = perform_ocr_upgrade()
            console.print(msg, markup=False)
            # done only when the binary guard uses here is now found (the updater installs `ocr`)
            return ok and bool(shutil.which(ocr_binary)) and "installed"
        step("Alibaba OCR", "guard update ocr", "Alibaba OCR (the full review, guard post --full) is not installed. Install it with npm now?",
             install_ocr)

    # 3. OCR uses the current LLM: no question, it only mirrors guard's own setting. The LLM is the
    # machine-wide one (OCR is machine-wide: a repository's credentials never reach it as a side effect)
    llm = load_global_config().llm
    if llm.api_key and shutil.which(ocr_binary) and not ocr_in_sync(llm, ocr_binary):
        try:
            ok, msg = sync_to_alibaba_ocr(llm, ocr_binary)
        except Exception as e:  # like every step: a failure is listed and the others still run
            ok, msg = False, f"failed ({type(e).__name__}: {e})"
        (done if ok else left).append(("OCR sync", "synced with the current LLM" if ok else f"{msg}; later: guard config sync"))

    # 3b. Whether every post runs OCR: asked once, once OCR is here (the answer is kept either way)
    if shutil.which(ocr_binary) and load_global_config().ocr.always is None:
        def choose_ocr():
            mode = typer.prompt("Alibaba OCR review: always (on every guard post, minutes each) or optional (only guard post --full)?",
                                default="optional").strip().lower()
            if mode not in ("always", "optional"):
                return False
            config_ocr_cmd(mode)
            return f"OCR {mode}"
        step("OCR on every post", "guard config ocr always   (or: guard config ocr optional)",
             "Alibaba OCR is installed. Choose whether every guard post runs its review?", choose_ocr)


def _setup_agent_hooks_step(step: Callable) -> None:
    from guard.agent.adapter import installed
    from guard.commands.agent import agent_add_cmd
    from guard.core.repo_setup import _detected_adapters

    for adapter in _detected_adapters():
        if not installed(adapter):
            def add_hooks(name=adapter["name"], adapter=adapter):
                try:
                    agent_add_cmd(name)
                except typer.Exit:
                    pass  # declined or refused: the check below says so
                return installed(adapter) and "hooks added"  # what the agent's config really holds
            step(f"{adapter['title']} hooks", f"guard agent add {adapter['name']}",
                 f"{adapter['title']} is here without guard's hooks. Add them (you see the diff first)?", add_hooks)


def _print_setup_summary(done: List[Tuple[str, str]], left: List[Tuple[str, str]], interactive: bool) -> None:
    if not done and not left:
        console.print("[green]✅ Setup complete: nothing is missing.[/green]")
        return
    table = Table(title="🧩 guard setup", show_header=True, header_style="bold magenta")
    table.add_column("Item", style="bold")
    table.add_column("Result")
    for item, what in done:
        table.add_row(item, f"[green]✅ {what}[/green]")
    for item, what in left:
        table.add_row(item, f"[yellow]⏳ {what}[/yellow]")
    console.print(table)
    if left and not interactive:
        console.print("[yellow]Run these yourself in an interactive terminal (or run `guard setup` there).[/yellow]")


def finish_setup(cwd: Path) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """
    Do what guard still needs on this machine, in order: an LLM, Alibaba OCR, OCR synced with the
    LLM, the commit mode, and guard's hooks in the agents found here. Steps that need an answer are
    asked in an interactive terminal and listed otherwise (an agent never types a key or confirms a
    diff for the user); a declined or failed step is listed and the next one runs. Returns (done, left).
    """
    from guard.commands.config import config_commit_cmd  # at call time: groups register in order
    from guard.core.config import load_global_config, run_llm_wizard

    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    done, left = [], []  # (item, what happened) / (item, command to run)

    def step(item: str, command: str, question: str, action) -> None:
        if not interactive:
            left.append((item, command))
            return
        if not typer.confirm(question, default=True):
            left.append((item, f"declined; later: {command}"))
            return
        try:
            result = action()
        except (Exception, SystemExit) as e:  # a failing step (or a wizard that exits) never stops the others
            left.append((item, f"failed ({type(e).__name__}: {e}); later: {command}"))
            return
        if result is False:
            left.append((item, f"not done; later: {command}"))
        else:
            done.append((item, result or "done"))

    # 1. An LLM for the review gate (the wizard also gives it to Alibaba OCR)
    if not load_global_config().llm.ready:  # an API key, or the user's own agent CLI
        step("LLM", "guard config llm", "No LLM is configured for the review gate. Set one up now?",
             lambda: run_llm_wizard().llm.ready and "configured")

    # 2. Alibaba OCR, for `guard post --full`, sync, and always/optional setting
    _setup_ocr_steps(step, cwd, done, left)

    # 3. Who writes commit messages
    if not load_global_config().commit_mode:
        def choose_mode():
            mode = typer.prompt("Commit messages: auto (the agent writes them) or ask (the agent asks you)?", default="auto").strip().lower()
            if mode not in ("auto", "ask"):
                return False
            config_commit_cmd(mode)
            return f"mode {mode}"
        step("Commit mode", "guard config commit auto   (or: guard config commit ask)", "Choose who writes commit messages now?", choose_mode)

    # 4. Guard's hooks in the agents found on this machine (the diff is shown and confirmed there)
    _setup_agent_hooks_step(step)

    _print_setup_summary(done, left, interactive)
    return done, left


@app.command("setup")
def setup_cmd():
    """
    Do what is still missing on this machine: LLM, Alibaba OCR (installed and synced), commit mode,
    and guard's hooks in the agents found here. Asks before each step; `guard install` and
    `guard update` run it at the end.
    """
    finish_setup(Path.cwd())


def _print_install(result) -> None:
    ok, messages = result
    for msg in messages:
        style = "yellow" if msg.startswith("WARN") else "green"
        console.print(f"[{style}]• {msg}[/{style}]")
    if not ok:
        raise typer.Exit(code=1)


@app.command("install")
def install_cmd(
    workspace: Optional[str] = typer.Option(
        None, "--workspace", "-w",
        help="Guard only this folder: agent docs in it, Git hooks in every repository below it",
    ),
):
    """
    Install guard. Default (global): Git hooks for every repository on this machine plus the guard
    directives in the global instruction files of the agents found here (Claude Code, Codex,
    Gemini CLI, opencode). Repositories are then set up automatically the first time guard runs.
    """
    if workspace:
        _print_install(install_workspace(Path(workspace)))
        console.print("[bold green]✅ Guard active in this workspace only.[/bold green]")
    else:
        _print_install(install_global(Path.cwd()))
        console.print("[bold green]✅ Guard active on this machine. Agents read the directives; repositories set themselves up on first use.[/bold green]")
    # Do what is still missing (LLM, OCR, commit mode, agent hooks), then show what remains
    cwd = Path(workspace) if workspace else Path.cwd()
    finish_setup(cwd)
    print_setup_health(cwd, "🧩 guard setup check", only_problems=True)


@app.command("uninstall")
def uninstall_cmd(
    workspace: Optional[str] = typer.Option(None, "--workspace", "-w", help="Remove guard from this workspace only"),
):
    """
    Remove what `guard install` added: the marked directive blocks and guard's Git hooks
    (global core.hooksPath is unset only when it points at guard's hooks).
    """
    messages = uninstall_workspace(Path(workspace)) if workspace else uninstall_global()
    for msg in messages or ["nothing to remove"]:
        console.print(f"[yellow]• {msg}[/yellow]")


# Subcommand: guard hook
hook_app = typer.Typer(
    name="hook",
    help="🪝 Manage Guard Hooks in target repositories",
    no_args_is_help=False,
)
app.add_typer(hook_app, name="hook")


@hook_app.command("refresh")
def hook_refresh_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Also set up / refresh this repository"),
):
    """
    Rewrite what guard installed earlier to the current version: global hooks, guard blocks in
    repository hooks and the directive block in agent docs (only where guard markers exist).
    """
    target = Path(repo).resolve() if repo else Path.cwd().resolve()
    messages = refresh_after_upgrade(force=True) + ensure_repo_setup(target, create_invariants=False) + refresh_repo_if_git(target)
    for msg in messages or ["everything is already up to date"]:
        style = "yellow" if msg.startswith("WARN") else "green"
        console.print(f"[{style}]• {msg}[/{style}]")
    print_setup_health(target, "🧩 guard setup check", only_problems=True)


def refresh_repo_if_git(path: Path) -> List[str]:
    root = git_root(path)
    return refresh_repo(root) if root else []


def _install_global_hooks_step() -> None:
    console.print("[cyan]Configuring Global Git Hooks (~/.guard/hooks)...[/cyan]")
    success, msgs = HookInstaller.install_global_git_hooks()
    for m in msgs:
        console.print(f"[green]• {m}[/green]")
    if success:
        console.print("[bold green]✅ Global Git Hooks active! Every Git repository on this machine is protected.[/bold green]")
    else:
        console.print("[bold red]❌ Failed to configure global Git hooks.[/bold red]")
        raise typer.Exit(code=1)
    # Set up the current repository now instead of on the first guard run
    for msg in ensure_repo_setup(Path.cwd()):
        console.print(f"[green]• {msg}[/green]")
    console.print("[dim]Other repositories are set up automatically the first time guard runs in them.[/dim]")


def _select_workspace_repos(
    child_repos: List[Path], target_path: Path, all_repos: bool, select_repos: Optional[str]
) -> List[Path]:
    if all_repos:
        return child_repos
    if select_repos:
        chosen: List[Path] = []
        parts = [p.strip() for p in select_repos.split(",")]
        for p in parts:
            if p.lower() in ("a", "all"):
                return child_repos
            elif p.isdigit() and 1 <= int(p) <= len(child_repos):
                chosen.append(child_repos[int(p) - 1])
            else:
                for cr in child_repos:
                    if cr.name == p or str(cr.relative_to(target_path)) == p:
                        chosen.append(cr)
        if not chosen:
            console.print(f"[bold yellow]⚠️ No child repositories matched '--select-repos {select_repos}'.[/bold yellow]")
        return chosen
    if sys.stdin and sys.stdin.isatty():
        ans = typer.prompt("Select repositories to install Git hooks into [A, 1-N, G, N]", default="A").strip()
        if ans.lower() in ("g", "global"):
            console.print("\n[cyan]Configuring Global Git Hooks (~/.guard/hooks)...[/cyan]")
            g_success, g_msgs = HookInstaller.install_global_git_hooks()
            for m in g_msgs:
                console.print(f"[green]• {m}[/green]")
            if g_success:
                console.print("[bold green]✅ Global Git Hooks active! Every Git repository on this machine is protected.[/bold green]")
            return []
        elif ans.lower() in ("a", "all", "y", "yes"):
            return child_repos
        elif ans.lower() in ("n", "no", "none", ""):
            return []
        else:
            chosen = []
            for s in ans.replace(" ", ",").split(","):
                s = s.strip()
                if s.isdigit() and 1 <= int(s) <= len(child_repos):
                    chosen.append(child_repos[int(s) - 1])
            return chosen
    return child_repos


def _install_workspace_step(
    installer: HookInstaller,
    target_path: Path,
    child_repos: List[Path],
    mode: Optional[str],
    stealth: bool,
    all_repos: bool,
    select_repos: Optional[str],
) -> None:
    console.print(f"\n[bold cyan]🔍 Workspace Mode:[/bold cyan] Current directory has no .git, but found [bold green]{len(child_repos)}[/bold green] child Git repositories:")
    for idx, cr in enumerate(child_repos, start=1):
        rel = cr.relative_to(target_path)
        console.print(f"  [bold yellow][{idx}][/bold yellow] ./{rel} [dim](.git)[/dim]")
    console.print("  [bold green][A][/bold green] All repositories (Install to all child repos)")
    console.print("  [bold magenta][G][/bold magenta] Global Git Hooks (Configure git config --global core.hooksPath - protects ALL repos on machine)")
    console.print("  [dim][N][/dim] None (Skip Git hooks, install workspace Agent Directives at root only)\n")
    # Respect --mode / --stealth in workspace mode
    effective_mode = "git" if stealth else (mode.lower().strip() if mode else "all")

    chosen_repos: List[Path] = []
    if effective_mode != "agent":
        chosen_repos = _select_workspace_repos(child_repos, target_path, all_repos, select_repos)

    installed_count = 0
    if chosen_repos:
        console.print(f"\n[cyan]Installing Git hooks into {len(chosen_repos)} repository(s)...[/cyan]")
        res = installer.install_multi(chosen_repos, mode="git")
        for r_path, r_info in res.items():
            r_rel = Path(r_path).relative_to(target_path)
            if r_info["success"]:
                installed_count += 1
                console.print(f"  [bold green]✅ Git hooks active in: ./{r_rel}[/bold green]")
            else:
                console.print(f"  [red]❌ Failed in: ./{r_rel}[/red]")

    # Install workspace agent directives at root if mode is 'agent' or 'all'
    agent_installed = False
    if effective_mode in ("agent", "all"):
        console.print("\n[cyan]Installing Workspace Agent Directives (CLAUDE.md & AGENT.md) at root...[/cyan]")
        success, msgs = installer.install(mode="agent")
        for m in msgs:
            console.print(f"[green]• {m}[/green]")
        agent_installed = success

    if installed_count > 0 and agent_installed:
        console.print("[bold green]✅ Hybrid Workspace Protection Active (Git Hooks in sub-repos + Agent Directives at root)[/bold green]")
    elif installed_count > 0:
        console.print(f"[bold green]✅ Git hooks installed into {installed_count} repository(s).[/bold green]")
    elif agent_installed:
        console.print("[bold green]✅ Agent Directives installed at workspace root.[/bold green]")
    else:
        console.print("[yellow]ℹ️ No hooks or directives were installed.[/yellow]")


def _resolve_single_repo_mode(mode: Optional[str], stealth: bool) -> str:
    if stealth:
        return "git"
    if mode:
        m = mode.lower().strip()
        if m in ("git", "stealth", "1"):
            return "git"
        elif m in ("agent", "2"):
            return "agent"
        elif m in ("all", "dual", "3"):
            return "all"
        else:
            console.print(f"[bold red]❌ Invalid mode '{mode}'. Choose 'git' (or --stealth), 'agent', or 'all'.[/bold red]")
            raise typer.Exit(code=1)
    # Interactive selection if terminal is interactive
    if sys.stdin and sys.stdin.isatty():
        console.print("\n[bold cyan]🛡️  Banh-Mi-Guard Installation Setup[/bold cyan]")
        console.print("Choose how you want Guard to protect this workspace:\n")
        console.print("  [bold green][1] 👻 Stealth Mode (Git Hooks Only - Recommended for company/shared repos)[/bold green]")
        console.print("      • Installs local .git/hooks/pre-commit gate")
        console.print("      • [bold]ZERO files added to workspace root[/bold] (Never pushed to remote repo)")
        console.print("  [bold yellow][2] 🤖 Agent Directives Only (CLAUDE.md & AGENT.md)[/bold yellow]")
        console.print("      • Injects AI guidelines directly into workspace root")
        console.print("      • No Git hooks installed")
        console.print("  [bold magenta][3] 🛡️  Dual-Gate Full Protection (Git Hooks + Agent Directives)[/bold magenta]")
        console.print("      • Maximum protection: both pre-commit gate and AI agent instructions\n")

        choice_map = {
            "1": "git", "git": "git", "stealth": "git",
            "2": "agent", "agent": "agent",
            "3": "all", "all": "all", "dual": "all",
        }
        while True:
            choice = typer.prompt("Select installation mode [1-3]", default="1")
            choice_clean = choice.strip().lower()
            if choice_clean in choice_map:
                return choice_map[choice_clean]
            console.print("[yellow]Invalid choice. Please enter 1, 2, or 3.[/yellow]")
    console.print("[dim]• Non-interactive environment: defaulting to mode 'all' (use --stealth for git-only)[/dim]")
    return "all"


def _run_single_repo_install(installer: HookInstaller, selected_mode: str) -> None:
    success, messages = installer.install(mode=selected_mode)
    for m in messages:
        console.print(f"[green]• {m}[/green]")
    if success:
        mode_desc = {
            "git": "Ghost/Stealth Mode (Git hooks only, zero workspace footprint)",
            "agent": "Agent Directives Mode (CLAUDE.md & AGENT.md)",
            "all": "Dual-Gate Full Protection Mode (Git hooks + Agent directives)",
        }.get(selected_mode, selected_mode)
        console.print(f"[bold green]✅ Guard installed successfully! ({mode_desc})[/bold green]")
    else:
        console.print("[bold red]❌ Failed to install Guard hooks.[/bold red]")


@hook_app.command("install")
def hook_install_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
    mode: Optional[str] = typer.Option(None, "--mode", "-m", help="Mode: 'git' (stealth), 'agent', or 'all'"),
    stealth: bool = typer.Option(False, "--stealth", "-s", help="Shortcut for --mode git (Zero workspace footprint, Git hooks only)"),
    global_hooks: bool = typer.Option(False, "--global", "-g", help="Configure Git hooks globally (git config --global core.hooksPath ~/.guard/hooks)"),
    all_repos: bool = typer.Option(False, "--all-repos", help="Install Git hooks to all discovered child Git repositories in workspace"),
    select_repos: Optional[str] = typer.Option(None, "--select-repos", help="Comma-separated indices (1,2) or names of child repositories"),
):
    """
    Legacy entry point, kept for existing scripts: prefer `guard install` (global) or
    `guard install --workspace <dir>`. Without options this is the same as `guard install`.
    """
    if not any([repo, mode, stealth, all_repos, select_repos, global_hooks]):
        console.print("[dim]`guard hook install` is now `guard install`; running the global install.[/dim]")
        _print_install(install_global(Path.cwd()))
        return
    console.print("[dim]Note: prefer `guard install` (global) or `guard install --workspace <dir>`.[/dim]")

    if global_hooks:
        _install_global_hooks_step()
        return

    target_path = Path(repo).resolve() if repo else Path.cwd().resolve()
    installer = HookInstaller(target_path)

    # 1. Multi-Repo Workspace Auto-Discovery (when current folder has no .git)
    if not installer.is_git_repo():
        child_repos = installer.find_child_git_repos()
        if child_repos:
            _install_workspace_step(installer, target_path, child_repos, mode, stealth, all_repos, select_repos)
            return

    # 2. Standard Single-Repo Installation
    selected_mode = _resolve_single_repo_mode(mode, stealth)
    _run_single_repo_install(installer, selected_mode)


@hook_app.command("uninstall")
def hook_uninstall_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
    mode: str = typer.Option("all", "--mode", "-m", help="Mode to uninstall: 'git', 'agent', or 'all'"),
    global_hooks: bool = typer.Option(False, "--global", "-g", help="Uninstall global Git hooks (git config --global --unset core.hooksPath)"),
):
    """
    Safely uninstall Guard hooks and restore previous user files.
    """
    if global_hooks:
        success, messages = HookInstaller.uninstall_global_git_hooks()
        for m in messages:
            console.print(f"[yellow]• {m}[/yellow]")
        console.print("[bold green]✅ Global Git hooks uninstalled.[/bold green]")
        return

    installer = HookInstaller(Path(repo) if repo else None)
    success, messages = installer.uninstall(mode=mode)
    for m in messages:
        console.print(f"[yellow]• {m}[/yellow]")
    console.print("[bold green]✅ Guard hooks uninstalled.[/bold green]")


@hook_app.command("status")
def hook_status_cmd(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Target repository directory"),
):
    """
    Check active hook status and AI agent directives in target repository.
    """
    installer = HookInstaller(Path(repo) if repo else None)
    status = installer.get_status()

    mode_labels = {
        "all": "[bold magenta]🛡️ Dual-Gate Full Protection (Git Hooks + Agent Directives)[/bold magenta]",
        "git": "[bold green]👻 Stealth Mode (Git Hooks Only - Zero Workspace Footprint)[/bold green]",
        "agent": "[bold yellow]🤖 Agent Directives Only (CLAUDE.md & AGENT.md)[/bold yellow]",
        "none": "[dim]⚪ Inactive (No Guard hooks or directives active)[/dim]",
    }
    mode_label = mode_labels.get(status.get("mode", "none"), "[dim]⚪ Inactive[/dim]")
    console.print(f"\n[bold]Active Profile:[/bold] {mode_label}\n")

    table = Table(title=f"🪝 Guard Hook & Agent Status ({installer.repo_path.name})", show_header=True)
    table.add_column("Component / Directive", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Target / Notes")

    table.add_row("Git Repository", "✅ Yes" if status["is_git_repo"] else "❌ No", "Git VCS")
    g_stat = HookInstaller.get_global_hooks_status()
    table.add_row("Global Git Hooks", "✅ Active" if g_stat["is_active"] else "⚪ Inactive", g_stat["configured_path"] or "git config --global core.hooksPath (~/.guard/hooks)")
    table.add_row("Git prepare-commit-msg", "✅ Active" if status["prepare_commit_msg_installed"] else "⚪ Inactive", ".git/hooks/prepare-commit-msg")
    table.add_row("Local Git Exclude", "✅ Active" if status.get("git_exclude_active") else "⚪ Inactive", ".git/info/exclude (.guard/ hidden)")
    table.add_row("CLAUDE.md Directive", "✅ Active" if status["claude_md_active"] else "⚪ Inactive", "Directives for omp & Claude Code")
    table.add_row("AGENT.md Directive", "✅ Active" if status["agent_md_active"] else "⚪ Inactive", "Directives for Cursor, Windsurf, Aider")
    table.add_row("Agent Wrapper (.guard/bin)", "✅ Active" if status["agent_wrapper_installed"] else "⚪ Inactive", ".guard/bin/guard-exec")

    console.print(table)

    # If in a multi-repo workspace (no root git), report status of child git repos
    if not status["is_git_repo"]:
        child_repos = installer.find_child_git_repos()
        if child_repos:
            console.print(f"\n[cyan]🔍 Discovered {len(child_repos)} child Git repositories in workspace:[/cyan]")
            sub_table = Table(title="Child Repositories Hook Status", show_header=True)
            sub_table.add_column("Repository", style="bold")
            sub_table.add_column("pre-commit", justify="center")
            sub_table.add_column("prepare-commit-msg", justify="center")
            for cr in child_repos:
                sub_installer = HookInstaller(cr)
                sub_stat = sub_installer.get_status()
                rel = cr.relative_to(installer.repo_path)
                sub_table.add_row(
                    f"./{rel}",
                    "✅ Active" if sub_stat["pre_commit_installed"] else "⚪ Inactive",
                    "✅ Active" if sub_stat["prepare_commit_msg_installed"] else "⚪ Inactive",
                )
            console.print(sub_table)
