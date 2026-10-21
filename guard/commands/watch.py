"""`guard watch`: supervise the workers of one Orca run, or explicit worktrees, until each settles."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

import typer
from rich.console import Console
from rich.table import Table

from guard.cli import app, console
from guard.core.watchdog import Action, WatchConfig, WorkerMonitor, WorkerTick
from guard.core.worker_runtime import (
    OrcaWorker,
    WorkerRuntimeError,
    list_workers,
    probe_worktree,
    resolve_orca,
    send_nudge,
)
from guard.core.worker_verify import verify_worker

PROBE_FAILED = "probe-failed"
stderr_console = Console(stderr=True)  # warnings only: stdout stays the table or the JSON array


@dataclass
class _Target:
    """One watched worker: its worktree, its role and (Orca mode) its live worker-list row."""

    name: str
    worktree: Path
    role: str
    own: List[str]
    row: Optional[OrcaWorker] = None

    @property
    def terminal(self) -> Optional[str]:
        return self.row.terminal if self.row is not None else None


@dataclass
class _Row:
    """One summary line: the JSON record plus the table-only columns."""

    record: Dict[str, Any]
    nudges: int
    note: str


def _log_line(log_path: Path, name: str, state: str, detail: str) -> None:
    """Append one log line; every line starts `HH:MM:SS  <name>  <state>  <detail>`."""
    line = f"{time.strftime('%H:%M:%S')}  {name}  {state}  {detail or '-'}"
    try:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError as e:
        stderr_console.print(f"[yellow]watch: cannot write {log_path}: {e}[/yellow]")


def _names(raw: Optional[str]) -> Set[str]:
    return {part.strip() for part in (raw or "").split(",") if part.strip()}


def _role(name: str, test_names: Set[str], ownership: Dict[str, Dict[str, Any]]) -> str:
    """`--test-workers` is explicit, the ownership file is the default per worker."""
    if name in test_names:
        return "test"
    entry = ownership.get(name) or {}
    return str(entry.get("role") or "fix")


def _own(name: str, ownership: Dict[str, Dict[str, Any]]) -> List[str]:
    entry = ownership.get(name) or {}
    return [str(glob) for glob in (entry.get("own") or [])]


def _state(monitor: WorkerMonitor, tick: WorkerTick, actions: Sequence[Action]) -> str:
    """The state this pass shows for the worker: terminal, else this pass's nudge reason."""
    if monitor.done:
        return "done"
    if monitor.needs_human:
        return "needs-human"
    for action in actions:
        if action.kind == "nudge":
            return action.reason
    if tick.quick_fails:
        return "suspect"  # already nudged for this finding set, still a suspect worker
    return "working"


def _short(head: Optional[str]) -> str:
    return head[:7] if head else "-"


def _record(tick: WorkerTick, state: str, actions: Sequence[Action]) -> Dict[str, Any]:
    return {
        "name": tick.name,
        "head": tick.head,
        "head_moved": tick.head_moved,
        "dirty": tick.dirty,
        "activity_ts": tick.activity_ts,
        "heartbeat_ts": tick.heartbeat_ts,
        "settled": tick.settled,
        "quick_fails": list(tick.quick_fails),
        "state": state,
        "actions": [{"kind": action.kind, "reason": action.reason, "text": action.text} for action in actions],
    }


def _load_ownership(path: Path) -> Dict[str, Dict[str, Any]]:
    """The coordinator's ownership file `{name: {role, own}}`; a broken file is a usage error."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        console.print(f"[bold red]❌ cannot read --ownership {path}: {e}[/bold red]")
        raise typer.Exit(code=2) from e
    if not isinstance(data, dict):
        console.print(f"[bold red]❌ --ownership {path} must map worker names to {{role, own}}[/bold red]")
        raise typer.Exit(code=2)
    for name, entry in data.items():
        if not isinstance(entry, dict):
            console.print(f"[bold red]❌ --ownership {path}: {name}: must be an object with role and own[/bold red]")
            raise typer.Exit(code=2)
        role = entry.get("role", "fix")
        globs = entry.get("own") or []
        if role not in ("fix", "test"):
            console.print(f"[bold red]❌ --ownership {path}: {name}: role must be 'fix' or 'test'[/bold red]")
            raise typer.Exit(code=2)
        if not isinstance(globs, list) or not all(isinstance(glob, str) for glob in globs):
            console.print(f"[bold red]❌ --ownership {path}: {name}: own must be a list of globs[/bold red]")
            raise typer.Exit(code=2)
    return data


def _log_path(run: Optional[str], worktrees: Sequence[Path], raw: Optional[str]) -> Path:
    if raw:
        return Path(raw)
    if run:
        return Path.cwd() / f"guard-watch-{run}.log"
    return Path.cwd() / f"guard-watch-{worktrees[0].name or 'watch'}.log"


def _resolve_orca(explicit: Optional[str]) -> str:
    resolved = explicit or resolve_orca()
    if not resolved:
        console.print("[bold red]❌ orca CLI not found: pass --orca <path> or set ORCA_CLI_COMMAND[/bold red]")
        raise typer.Exit(code=2)
    return resolved


def _resolve_base(worktree: Path, base: str) -> Optional[str]:
    """The full SHA `--base` names in `worktree`, None when it is not a commit there."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(worktree), "rev-parse", "--verify", f"{base}^{{commit}}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError:
        return None
    return (proc.stdout.strip() or None) if proc.returncode == 0 else None


def _orca_targets(
    rows: Sequence[OrcaWorker],
    wanted: Optional[Set[str]],
    test_names: Set[str],
    ownership: Dict[str, Dict[str, Any]],
    log_path: Path,
) -> Dict[str, _Target]:
    """The rows to watch: with a worktree, and named or (no --workers) not settled yet."""
    targets: Dict[str, _Target] = {}
    for row in rows:
        if row.worktree is None:
            _log_line(log_path, row.name, "skipped", "no worktree")
            continue
        named = row.name in test_names or (wanted is not None and row.name in wanted)
        if not named and (wanted is not None or row.settled):
            continue
        targets[row.name] = _Target(
            name=row.name,
            worktree=row.worktree,
            role=_role(row.name, test_names, ownership),
            own=_own(row.name, ownership),
            row=row,
        )
    return targets


@dataclass
class _Watcher:
    """The state of one watch run: targets, monitors, start heads and the log."""

    run_id: Optional[str]
    base: Optional[str]
    cfg: WatchConfig
    log_path: Path
    orca: Optional[str]
    once: bool
    targets: Dict[str, _Target]
    monitors: Dict[str, WorkerMonitor] = field(default_factory=dict)
    start_heads: Dict[str, Optional[str]] = field(default_factory=dict)
    last_notes: Dict[str, str] = field(default_factory=dict)

    def tick_pass(self, now: float) -> List[_Row]:
        """One pass over every target; one summary row per worker whose probe succeeded."""
        rows = []
        for target in self.targets.values():
            row = self._tick(target, now)
            if row is not None:
                rows.append(row)
        return rows

    def run(self) -> List[_Row]:
        """Passes, sleeping `interval_sec` between them, until every monitor is terminal."""
        rows: List[_Row] = []
        first = True
        while True:
            if not first:
                time.sleep(self.cfg.interval_sec)
                self._refresh_rows()
            first = False
            rows = self.tick_pass(time.time())
            if all(self._terminal(name) for name in self.targets):
                return rows

    def _terminal(self, name: str) -> bool:
        monitor = self.monitors.get(name)
        return monitor is not None and (monitor.done or monitor.needs_human)

    def _refresh_rows(self) -> None:
        """Orca mode: refresh heartbeats, settled flags and terminals of the watched workers."""
        if self.orca is None or self.run_id is None:
            return
        try:
            rows = list_workers(self.orca, self.run_id)
        except WorkerRuntimeError as e:
            _log_line(self.log_path, "orca", "warning", f"worker-list failed: {e}")
            return
        known = {row.name: row for row in rows}
        for name, target in self.targets.items():
            row = known.get(name)
            if row is not None:
                target.row = row

    def _tick(self, target: _Target, now: float) -> Optional[_Row]:
        name = target.name
        try:
            probe = probe_worktree(target.worktree)
        except (WorkerRuntimeError, OSError) as e:
            self._probe_failed(name, e)
            return None

        start = self.start_heads.setdefault(name, self.base)
        moved = bool(start is not None and probe.head is not None and probe.head != start)
        if start is None and probe.head is not None:
            moved = name in self.monitors  # a first real head after an unknown start is a move
            start = probe.head
            self.start_heads[name] = start
        checks_base = self.base or start

        quick_fails: tuple[str, ...] = ()
        if checks_base is not None:
            try:
                quick = verify_worker(target.worktree, base=checks_base, role=target.role, own=target.own, quick=True)
            except (WorkerRuntimeError, OSError) as e:
                self._probe_failed(name, e)
                return None
            quick_fails = tuple(f"{issue.code}: {issue.message}" for issue in quick.fails)

        monitor = self.monitors.get(name)
        if monitor is None:
            monitor = WorkerMonitor(name, target.role, start, self.cfg, now=now, settles=target.row is not None)
            self.monitors[name] = monitor
        tick = WorkerTick(
            name=name,
            head=probe.head,
            head_moved=moved,
            dirty=probe.dirty,
            activity_ts=probe.activity_ts,
            heartbeat_ts=target.row.observed_at if target.row is not None else None,
            settled=target.row.settled if target.row is not None else False,
            quick_fails=quick_fails,
        )
        actions = monitor.observe(tick, now)
        state = _state(monitor, tick, actions)
        note = self._execute(target, actions)
        if checks_base is None:
            note = f"{note}; quick scan skipped: no base or start head" if note else "quick scan skipped: no base or start head"
        if monitor.done or monitor.needs_human:
            note = note or self.last_notes.get(name, "")  # a terminal line keeps its explanation
            self.last_notes[name] = note
        _log_line(self.log_path, name, state, note)
        return _Row(record=_record(tick, state, actions), nudges=monitor.nudges, note=note)

    def _probe_failed(self, name: str, error: Exception) -> None:
        _log_line(self.log_path, name, PROBE_FAILED, f"probe failed: {error}")
        print(f"watch: {name}: probe failed: {error}", file=sys.stderr)  # stdout stays the JSON/table only

    def _execute(self, target: _Target, actions: Sequence[Action]) -> str:
        """Run this pass's actions; returns the summary note of the worker."""
        parts: List[str] = []
        for action in actions:
            if action.kind != "nudge":
                parts.append(action.text or action.reason)
                continue
            skip = self._deliver(target, action)
            parts.append(f"nudge skipped: {skip}" if skip else action.text)
        return "; ".join(parts)

    def _deliver(self, target: _Target, action: Action) -> Optional[str]:
        """Send one nudge; returns why it was not sent, None when it was (or once mode disabled it)."""
        if self.once:
            return "dry run (--once)"
        orca = self.orca
        terminal = target.terminal
        if orca is None or target.row is None:
            return "plain-git mode"
        if not terminal:
            return "no terminal"
        try:
            send_nudge(orca, terminal, action.text)
        except (WorkerRuntimeError, OSError) as e:
            return str(e)
        return None


def _print_table(rows: Sequence[_Row]) -> None:
    table = Table(title="👀 guard watch")
    table.add_column("Worker", style="bold")
    table.add_column("State")
    table.add_column("Head", style="dim")
    table.add_column("Nudges", justify="right")
    table.add_column("Note")
    for row in rows:
        table.add_row(row.record["name"], row.record["state"], _short(row.record["head"]), str(row.nudges), row.note)
    console.print(table)


@app.command("watch")
def watch_cmd(
    run: Optional[str] = typer.Option(None, "--run", help="Orca run id whose workers are supervised"),
    workers: Optional[str] = typer.Option(None, "--workers", help="Comma-separated worker names to watch; default: every unsettled worker"),
    base: Optional[str] = typer.Option(None, "--base", help="Git base commit for the delivery checks; default: each worker's first-seen HEAD"),
    ownership: Optional[str] = typer.Option(None, "--ownership", help="JSON file: {worker: {role, own}} (the coordinator's file)"),
    test_workers: Optional[str] = typer.Option(None, "--test-workers", help="Comma-separated workers treated as test workers"),
    worktree: Optional[List[str]] = typer.Option(None, "--worktree", help="Worktree to watch without Orca (repeatable)"),
    interval_sec: float = typer.Option(90.0, "--interval-sec", help="Seconds between passes"),
    stall_min: float = typer.Option(8.0, "--stall-min", help="Minutes without progress before a stall nudge"),
    budget_min: float = typer.Option(45.0, "--budget-min", help="Minutes a fix worker may work without committing"),
    max_nudges: int = typer.Option(5, "--max-nudges", help="Nudges per worker before it needs a human"),
    log: Optional[str] = typer.Option(None, "--log", help="Log file; default guard-watch-<run>.log in the cwd"),
    orca: Optional[str] = typer.Option(None, "--orca", help="The orca executable; default $ORCA_CLI_COMMAND or orca on PATH"),
    once: bool = typer.Option(False, "--once", help="One pass only: no nudges, print the summary and exit"),
    json_output: bool = typer.Option(False, "--json", help="Print the summary as JSON instead of the table"),
):
    """
    Supervise the workers of one Orca run, or explicit worktrees, by heartbeat and Git activity:
    nudge stalled workers, report done and needs-human ones. Exit code 0, 2 on a usage error.
    """
    plain_worktrees = [Path(path) for path in (worktree or [])]
    if not run and not plain_worktrees:
        console.print("[bold red]❌ give --run <id> for an Orca run, or --worktree <path> to watch worktrees directly[/bold red]")
        raise typer.Exit(code=2)

    ownership_map = _load_ownership(Path(ownership)) if ownership else {}
    test_names = _names(test_workers)
    wanted = _names(workers) if workers is not None else None
    # With --workers the requested names reach the core so a named row without a worktree surfaces
    # and is skipped with a log line; without it the run watches every unsettled worker, so no name
    # filter is passed and --test-workers only assigns the test role.
    names: Optional[List[str]] = sorted(wanted | test_names) if wanted is not None else None

    log_path = _log_path(run, plain_worktrees, log)
    targets: Dict[str, _Target] = {}
    orca_cmd: Optional[str] = None
    if run:
        orca_cmd = _resolve_orca(orca)
        try:
            rows = list_workers(orca_cmd, run, names=names)
        except WorkerRuntimeError as e:
            console.print(f"[bold red]❌ {e}[/bold red]")
            raise typer.Exit(code=2) from e
        targets.update(_orca_targets(rows, wanted, test_names, ownership_map, log_path))
    for path in plain_worktrees:
        name = path.name or str(path)
        if name in targets:
            _log_line(log_path, name, "skipped", f"duplicate worktree name: {path}")
            continue
        targets[name] = _Target(name=name, worktree=path, role=_role(name, test_names, ownership_map),
                                own=_own(name, ownership_map))

    if base and targets:
        # A short SHA would never equal a probed full HEAD, so every head would look moved: compare full SHAs.
        first = next(iter(targets.values())).worktree
        resolved = _resolve_base(first, base)
        if resolved is None:
            console.print(f"[bold red]❌ --base does not resolve to a commit in {first}: {base}[/bold red]")
            raise typer.Exit(code=2)
        base = resolved

    watcher = _Watcher(
        run_id=run,
        base=base,
        cfg=WatchConfig(interval_sec=interval_sec, stall_min=stall_min, budget_min=budget_min, max_nudges=max_nudges),
        log_path=log_path,
        orca=orca_cmd,
        once=once,
        targets=targets,
    )
    rows = watcher.tick_pass(time.time()) if once else watcher.run()
    if json_output:
        print(json.dumps([row.record for row in rows], indent=2))
    else:
        _print_table(rows)
