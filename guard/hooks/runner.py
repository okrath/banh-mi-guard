"""
Sandwich Pattern Runner for Banh-Mi-Guard.
Executes:
1. `guard pre "<prompt>"`
2. Subprocess execution of the Agent / Developer command
3. `guard post` (with optional auto-fix loop)
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import List, Optional

from rich.console import Console

console = Console()


def run_sandwich_task(
    prompt: str,
    command: List[str],
    repo_path: Optional[Path] = None,
    auto_fix: bool = False,
    max_fix_attempts: int = 2,
    scope: Optional[List[str]] = None,
    allow_dirty: bool = False,
    force: bool = False,
) -> int:
    """
    Executes Pre-task -> Command -> Post-task.
    Returns the overall exit code (0 if all passed, non-zero if failed).
    """
    target_repo = Path(repo_path or Path.cwd()).resolve()

    console.print(f"[bold cyan]🛡️  [1/3] EXECUTING PRE-TASK GUARD[/bold cyan]")
    from guard.task_flow import execute_pre_task
    pre_success = execute_pre_task(
        prompt=prompt, repo_path=target_repo, scope=scope, allow_dirty=allow_dirty, force=force,
    )
    if not pre_success:
        console.print("[bold red]Pre-Task Guard halted execution due to critical block.[/bold red]")
        return 1

    console.print(f"\n[bold green]🤖 [2/3] EXECUTING AGENT COMMAND:[/bold green] [dim]{' '.join(command)}[/dim]")
    cmd_start = time.perf_counter()
    try:
        proc = subprocess.run(command, cwd=str(target_repo), check=False)
        cmd_duration = time.perf_counter() - cmd_start
        console.print(f"[dim]Agent command finished in {cmd_duration:.1f}s with exit code {proc.returncode}[/dim]")
    except Exception as e:
        console.print(f"[bold red]Failed to execute agent command:[/bold red] {e}")
        return 1

    console.print(f"\n[bold magenta]🧪 [3/3] EXECUTING POST-TASK GUARD VERIFICATION[/bold magenta]")
    from guard.task_flow import execute_post_task
    post_passed = execute_post_task(repo_path=target_repo, auto_fix=auto_fix)

    if proc.returncode != 0:
        return proc.returncode

    return 0 if post_passed else 1
