"""`guard watch`: supervise named Camponi agents and their subagents, or explicit worktrees, until each settles."""

from __future__ import annotations

import dataclasses
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
from guard.core.agent_sessions import SESSION_SLACK_SECONDS, session_log, subagent_logs
from guard.core.deps_check import check_main_checkout, main_checkout_of
from guard.core.watchdog import Action, SubagentMonitor, WatchConfig, WorkerMonitor, WorkerTick
from guard.core.worker_runtime import (
    CamponiTerminal,
    WorkerRuntimeError,
    list_terminals,
    mentions_path,
    parse_screen,
    probe_worktree,
    read_screen,
    resolve_camponi,
    send_nudge,
    stop_dev_servers,
)
from guard.core.worker_verify import verify_worker

PROBE_FAILED = "probe-failed"
stderr_console = Console(stderr=True)  # warnings only: stdout stays the table or the JSON array


@dataclass
class _Target:
    """One watched agent (its Camponi terminal) or plain worktree, with its role and ownership."""

    name: str
    worktree: Path
    role: str
    own: List[str]
    terminal: Optional[CamponiTerminal] = None  # None: a plain worktree


@dataclass
class _ScreenTrack:
    """What the previous passes saw on one agent's screen."""

    stable: Optional[str] = None
    changed_ts: Optional[float] = None
    command: Optional[str] = None
    command_since: Optional[float] = None


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
    """`--test-agents` is explicit, the ownership file is the default per agent."""
    if name in test_names:
        return "test"
    entry = ownership.get(name) or {}
    return str(entry.get("role") or "fix")


def _own(name: str, ownership: Dict[str, Dict[str, Any]]) -> List[str]:
    entry = ownership.get(name) or {}
    return [str(glob) for glob in (entry.get("own") or [])]


def _state(monitor: WorkerMonitor, tick: WorkerTick, actions: Sequence[Action]) -> str:
    """The state this pass shows for the agent: terminal, else this pass's nudge reason."""
    if monitor.done:
        return "done"
    if monitor.needs_human:
        return "needs-human"
    for action in actions:
        if action.kind == "nudge":
            return action.reason
    if tick.quick_fails:
        return "suspect"  # already nudged for this finding set, still a suspect agent
    return "working"


def _subagent_state(monitor: SubagentMonitor, actions: Sequence[Action]) -> str:
    if monitor.done:
        return "done"
    if monitor.needs_human:
        return "needs-human"
    return "stalled" if actions else "working"


def _short(head: Optional[str]) -> str:
    return head[:7] if head else "-"


def _actions(actions: Sequence[Action]) -> List[Dict[str, Any]]:
    return [{"kind": action.kind, "reason": action.reason, "text": action.text, "interrupt": action.interrupt}
            for action in actions]


def _record(tick: WorkerTick, state: str, actions: Sequence[Action]) -> Dict[str, Any]:
    return {
        "name": tick.name,
        "kind": "agent",
        "parent": None,
        "head": tick.head,
        "head_moved": tick.head_moved,
        "dirty": tick.dirty,
        "activity_ts": tick.activity_ts,
        "heartbeat_ts": tick.heartbeat_ts,
        "settled": tick.settled,
        "quick_fails": list(tick.quick_fails),
        "busy": tick.busy,
        "command": tick.command,
        "deps_fails": list(tick.deps_fails),
        "state": state,
        "actions": _actions(actions),
    }


def _parse_ownership(path: Path) -> Dict[str, Dict[str, Any]]:
    """The coordinator's ownership file `{name: {role, own}}`; a broken file raises ValueError."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ValueError(f"cannot read --ownership {path}: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"--ownership {path} must map agent names to {{role, own}}")
    for name, entry in data.items():
        if not isinstance(entry, dict):
            raise ValueError(f"--ownership {path}: {name}: must be an object with role and own")
        role = entry.get("role", "fix")
        globs = entry.get("own") or []
        if role not in ("fix", "test"):
            raise ValueError(f"--ownership {path}: {name}: role must be 'fix' or 'test'")
        if not isinstance(globs, list) or not all(isinstance(glob, str) for glob in globs):
            raise ValueError(f"--ownership {path}: {name}: own must be a list of globs")
    return data


def _load_ownership(path: Path) -> Dict[str, Dict[str, Any]]:
    """The ownership file at start: a broken file is a usage error."""
    try:
        return _parse_ownership(path)
    except ValueError as e:
        console.print(f"[bold red]❌ {e}[/bold red]")
        raise typer.Exit(code=2) from e


def _log_path(agents: Sequence[str], worktrees: Sequence[Path], raw: Optional[str]) -> Path:
    if raw:
        return Path(raw)
    if agents:
        return Path.cwd() / f"guard-watch-{agents[0]}.log"
    return Path.cwd() / f"guard-watch-{worktrees[0].name or 'watch'}.log"


def _resolve_camponi(explicit: Optional[str]) -> str:
    resolved = explicit or resolve_camponi()
    if not resolved:
        console.print("[bold red]❌ camponi CLI not found: pass --camponi <path> or set CAMPONI_CLI[/bold red]")
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


def _agent_targets(
    agents: Sequence[str],
    terminals: Sequence[CamponiTerminal],
    test_names: Set[str],
    ownership: Dict[str, Dict[str, Any]],
    log_path: Path,
) -> Dict[str, _Target]:
    """The named agents to watch: running terminals with a worktree; the others are logged as skipped."""
    known = {terminal.id: terminal for terminal in terminals}
    targets: Dict[str, _Target] = {}
    for name in agents:
        terminal = known.get(name)
        if terminal is None:
            _log_line(log_path, name, "skipped", "no such Camponi terminal")
        elif not terminal.running:
            _log_line(log_path, name, "skipped", f"terminal {terminal.status or 'not running'}")
        elif terminal.worktree is None:
            _log_line(log_path, name, "skipped", "no worktree")
        else:
            targets[name] = _Target(name=name, worktree=terminal.worktree, role=_role(name, test_names, ownership),
                                    own=_own(name, ownership), terminal=terminal)
    return targets


@dataclass
class _Watcher:
    """The state of one watch run: targets, monitors, start heads, screens, subagents and the log."""

    base: Optional[str]
    cfg: WatchConfig
    log_path: Path
    camponi: Optional[str]
    once: bool
    targets: Dict[str, _Target]
    camponi_dir: Optional[str] = None
    terminals: List[CamponiTerminal] = field(default_factory=list)  # the latest terminal list, for session matching
    ownership_path: Optional[Path] = None
    ownership: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    test_names: Set[str] = field(default_factory=set)
    monitors: Dict[str, WorkerMonitor] = field(default_factory=dict)
    start_heads: Dict[str, Optional[str]] = field(default_factory=dict)
    first_seen: Dict[str, float] = field(default_factory=dict)
    screens: Dict[str, _ScreenTrack] = field(default_factory=dict)
    subagents: Dict[str, SubagentMonitor] = field(default_factory=dict)  # "<terminal>/<Name>" -> its monitor
    no_session: Set[str] = field(default_factory=set)  # agents whose session log was not found (logged once)
    deps_fails: List[str] = field(default_factory=list)
    deps_logged: Set[str] = field(default_factory=set)
    last_notes: Dict[str, str] = field(default_factory=dict)

    def tick_pass(self, now: float) -> List[_Row]:
        """One pass over every target and its live subagents; one summary row each that was probed."""
        self._reload_ownership()
        self._check_deps()
        rows = []
        for target in self.targets.values():
            row = self._tick(target, now)
            if row is not None:
                rows.append(row)
            rows.extend(self._tick_subagents(target, now))
        return rows

    def run(self) -> List[_Row]:
        """Passes, sleeping `interval_sec` between them, until no target is left to supervise."""
        rows: List[_Row] = []
        first = True
        while True:
            if not first:
                time.sleep(self.cfg.interval_sec)
                self._refresh_terminals()
            first = False
            rows = self.tick_pass(time.time())
            if all(self._finished(name) for name in self.targets):
                return rows

    def _finished(self, name: str) -> bool:
        monitor = self.monitors.get(name)
        return monitor is not None and (monitor.done or monitor.needs_human)

    def _refresh_terminals(self) -> None:
        """Refresh status, heartbeat and args of the watched agents' terminals; a vanished one counts as ended."""
        if self.camponi is None or not any(target.terminal for target in self.targets.values()):
            return
        try:
            self.terminals = list_terminals(self.camponi, runtime_dir=self.camponi_dir)
        except WorkerRuntimeError as e:
            _log_line(self.log_path, "camponi", "warning", f"terminal ls failed: {e}")
            return
        known = {terminal.id: terminal for terminal in self.terminals}
        for target in self.targets.values():
            if target.terminal is not None:
                target.terminal = known.get(target.name) or dataclasses.replace(target.terminal, status="missing")

    def _reload_ownership(self) -> None:
        """Re-read the ownership file: the coordinator widens ownership mid-run. A bad read keeps the last copy."""
        if self.ownership_path is None:
            return
        try:
            self.ownership = _parse_ownership(self.ownership_path)
        except ValueError as e:
            _log_line(self.log_path, "ownership", "warning", f"{e}; keeping the previous copy")
            return
        for name, target in self.targets.items():
            target.role = _role(name, self.test_names, self.ownership)
            target.own = _own(name, self.ownership)
            monitor = self.monitors.get(name)
            if monitor is not None:
                monitor.role = target.role

    def _check_deps(self) -> None:
        """
        The main checkout's dependency links, once per pass: an agent that runs an install through
        its node_modules junction rewrites them into its own worktree. Each new FAIL line is logged once.
        """
        if not self.targets:
            return
        first = next(iter(self.targets.values())).worktree
        try:
            repo = main_checkout_of(first)
            fails = check_main_checkout(repo) if repo is not None else []
        except Exception as e:  # a broken dependency check must not end supervision
            _log_line(self.log_path, "deps", "warning", f"dependency check failed: {e}")
            fails = []
        for line in fails:
            if line not in self.deps_logged:
                self.deps_logged.add(line)
                _log_line(self.log_path, "deps", "deps-broken", line)
        self.deps_fails = list(fails)

    def _tick(self, target: _Target, now: float) -> Optional[_Row]:
        name = target.name
        first_seen = self.first_seen.setdefault(name, now)
        try:
            probe = probe_worktree(target.worktree, since=first_seen)
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

        # The delivery check runs every pass, so no agent is ever done without one.
        quick_fails: tuple[str, ...] = ()
        if checks_base is not None:
            try:
                quick = verify_worker(target.worktree, base=checks_base, role=target.role, own=target.own, quick=True)
            except (WorkerRuntimeError, OSError) as e:
                self._probe_failed(name, e)
                return None
            quick_fails = tuple(f"{issue.code}: {issue.message}" for issue in quick.fails)

        # A running Camponi terminal never settles; once it ended, its last state is the delivery.
        terminal = target.terminal
        settled = terminal is not None and not terminal.running
        monitor = self.monitors.get(name)
        if monitor is None:
            monitor = WorkerMonitor(name, target.role, start, self.cfg, now=now)
            self.monitors[name] = monitor
        monitor.settles = settled
        screen = self._screen_fields(target, now)
        tick = WorkerTick(
            name=name,
            head=probe.head,
            head_moved=moved,
            dirty=probe.dirty,
            activity_ts=probe.activity_ts,
            heartbeat_ts=terminal.last_output_at if terminal is not None else None,
            settled=settled,
            quick_fails=quick_fails,
            deps_fails=tuple(line for line in self.deps_fails if mentions_path(line, target.worktree)),
            **screen,
        )
        actions = monitor.observe(tick, now)
        state = _state(monitor, tick, actions)
        note = self._execute(target, tick, actions)
        if checks_base is None:
            note = f"{note}; quick scan skipped: no base or start head" if note else "quick scan skipped: no base or start head"
        if monitor.done or monitor.needs_human:
            note = note or self.last_notes.get(name, "")  # a terminal line keeps its explanation
            self.last_notes[name] = note
        _log_line(self.log_path, name, state, note)
        return _Row(record=_record(tick, state, actions), nudges=monitor.nudges, note=note)

    def _tick_subagents(self, target: _Target, now: float) -> List[_Row]:
        """
        The live subagents of one running agent, found again every pass from its session log. A
        subagent counts once its log was created after the agent's terminal started and while it
        has not ended; its row shows until the pass that sees it end.
        """
        terminal = target.terminal
        monitor = self.monitors.get(target.name)
        if terminal is None or not terminal.running or monitor is None or monitor.done or monitor.needs_human:
            return []
        session = session_log(terminal, self.terminals)
        if session is None:
            if target.name not in self.no_session:
                self.no_session.add(target.name)
                _log_line(self.log_path, target.name, "subagents", "no session log found: subagents not watched")
            return []
        self.no_session.discard(target.name)
        since = (terminal.started_at - SESSION_SLACK_SECONDS) if terminal.started_at is not None else self.first_seen[target.name]
        rows: List[_Row] = []
        for log in subagent_logs(terminal.kind, session, now=now, quiet_sec=self.cfg.interval_sec):
            key = f"{target.name}/{log.name}"
            sub = self.subagents.get(key)
            if sub is None:
                if log.ended or log.created is None or log.created < since:
                    continue
                sub = self.subagents[key] = SubagentMonitor(log.name, self.cfg)
            elif sub.done or sub.needs_human:
                continue
            actions = sub.observe(log.mtime, log.ended, now)
            state = _subagent_state(sub, actions)
            parts = []
            for action in actions:
                if action.kind == "nudge":
                    skip = self._deliver(terminal, action)  # a subagent has no terminal: its parent hears about it
                    parts.append(f"nudge skipped: {skip}" if skip else action.text)
                elif action.text:
                    parts.append(action.text)
            note = "; ".join(parts)
            _log_line(self.log_path, key, state, note)
            record = {"name": key, "kind": "subagent", "parent": target.name, "log": str(log.path),
                      "log_ts": log.mtime, "ended": log.ended, "state": state, "actions": _actions(actions)}
            rows.append(_Row(record=record, nudges=sub.nudges, note=note))
        return rows

    def _screen_fields(self, target: _Target, now: float) -> Dict[str, Any]:
        """
        The `WorkerTick` screen fields of the agent's running terminal, remembering since when its
        stable text and its running command are unchanged. Empty (busy None) when there is no screen.
        """
        terminal = target.terminal
        if self.camponi is None or terminal is None or not terminal.running:
            return {}
        screen = read_screen(self.camponi, terminal.id, runtime_dir=self.camponi_dir)
        if screen is None:
            return {}
        state = parse_screen(screen)
        track = self.screens.setdefault(target.name, _ScreenTrack())
        if state.stable != track.stable:
            track.stable = state.stable
            track.changed_ts = now
        if state.command != track.command or track.command_since is None:
            track.command = state.command
            track.command_since = now
        # A background job reports its own elapsed time, so one that hung before this pass counts at once.
        running = [(now - elapsed, command) for command, elapsed in state.jobs]
        if track.command:
            running.append((track.command_since, track.command))
        since, command = min(running) if running else (None, None)
        return {
            "busy": state.busy,
            "screen_changed_ts": track.changed_ts,
            "command": command,
            "command_since": since,
            "dev_server_on_screen": state.dev_server,
        }

    def _probe_failed(self, name: str, error: Exception) -> None:
        _log_line(self.log_path, name, PROBE_FAILED, f"probe failed: {error}")
        print(f"watch: {name}: probe failed: {error}", file=sys.stderr)  # stdout stays the JSON/table only

    def _execute(self, target: _Target, tick: WorkerTick, actions: Sequence[Action]) -> str:
        """Run this pass's actions; returns the summary note of the agent."""
        parts: List[str] = []
        for action in actions:
            if action.kind != "nudge":
                parts.append(action.text or action.reason)
                continue
            if action.reason == "stalled" and tick.dev_server_on_screen and not self.once:
                self._stop_dev_servers(target)  # the blocked foreground call returns once its server is gone
            skip = self._deliver(target.terminal, action)
            parts.append(f"nudge skipped: {skip}" if skip else action.text)
        return "; ".join(parts)

    def _stop_dev_servers(self, target: _Target) -> None:
        try:
            stopped = stop_dev_servers(target.worktree)
        except (WorkerRuntimeError, OSError) as e:
            _log_line(self.log_path, target.name, "warning", f"cannot stop its dev server: {e}")
            return
        for description in stopped:
            _log_line(self.log_path, target.name, "dev-server-stopped", description)

    def _deliver(self, terminal: Optional[CamponiTerminal], action: Action) -> Optional[str]:
        """Type one nudge into `terminal`; returns why it was not sent, None when it was."""
        if self.once:
            return "dry run (--once)"
        if self.camponi is None or terminal is None:
            return "plain-git mode"
        if not terminal.running:
            return f"terminal {terminal.status}"
        try:
            send_nudge(self.camponi, terminal.id, action.text, interrupt=action.interrupt, runtime_dir=self.camponi_dir)
        except (WorkerRuntimeError, OSError) as e:
            return str(e)
        return None


def _print_table(rows: Sequence[_Row]) -> None:
    table = Table(title="👀 guard watch")
    table.add_column("Agent", style="bold")
    table.add_column("State")
    table.add_column("Head", style="dim")
    table.add_column("Nudges", justify="right")
    table.add_column("Note")
    for row in rows:
        table.add_row(row.record["name"], row.record["state"], _short(row.record.get("head")), str(row.nudges), row.note)
    console.print(table)


@app.command("watch")
def watch_cmd(
    agent: Optional[List[str]] = typer.Option(None, "--agent", help="Camponi terminal id of an agent to watch with its subagents (repeatable)"),
    worktree: Optional[List[str]] = typer.Option(None, "--worktree", help="Worktree to watch without Camponi (repeatable)"),
    base: Optional[str] = typer.Option(None, "--base", help="Git base commit for the delivery checks; default: each agent's first-seen HEAD"),
    ownership: Optional[str] = typer.Option(None, "--ownership", help="JSON file: {agent: {role, own}} (the coordinator's file)"),
    test_agents: Optional[str] = typer.Option(None, "--test-agents", help="Comma-separated agents (terminal ids or worktree names) treated as test agents"),
    interval_sec: float = typer.Option(90.0, "--interval-sec", help="Seconds between passes"),
    stall_min: float = typer.Option(8.0, "--stall-min", help="Minutes without progress before a stall nudge"),
    budget_min: float = typer.Option(45.0, "--budget-min", help="Minutes a fix agent may work without committing"),
    max_nudges: int = typer.Option(5, "--max-nudges", help="Nudges per agent or subagent before it needs a human"),
    loop_min: float = typer.Option(10.0, "--loop-min", help="Minutes one shell command may own an agent's screen before it is interrupted"),
    log: Optional[str] = typer.Option(None, "--log", help="Log file; default guard-watch-<first agent or worktree>.log in the cwd"),
    camponi: Optional[str] = typer.Option(None, "--camponi", help="The camponi executable; default $CAMPONI_CLI or camponi on PATH"),
    camponi_dir: Optional[str] = typer.Option(None, "--camponi-dir", help="The Camponi runtime folder (passed to camponi as --dir); default: camponi's own"),
    once: bool = typer.Option(False, "--once", help="One pass only: no nudges, print the summary and exit"),
    json_output: bool = typer.Option(False, "--json", help="Print the summary as JSON instead of the table"),
):
    """
    Supervise named Camponi agents and their subagents, or explicit worktrees, by terminal screen,
    session log and Git activity: nudge idle, stalled and looping agents, nudge an agent about its
    stalled subagents, report done and needs-human ones. Never touches other agents. The ownership
    file is re-read every pass. Exit code 0, 2 on a usage error.
    """
    agent_ids = list(dict.fromkeys(agent or []))
    plain_worktrees = [Path(path) for path in (worktree or [])]
    if not agent_ids and not plain_worktrees:
        console.print("[bold red]❌ give --agent <terminal id> for a Camponi agent, or --worktree <path> to watch worktrees directly[/bold red]")
        raise typer.Exit(code=2)

    ownership_map = _load_ownership(Path(ownership)) if ownership else {}
    test_names = _names(test_agents)
    log_path = _log_path(agent_ids, plain_worktrees, log)
    targets: Dict[str, _Target] = {}
    camponi_cmd: Optional[str] = None
    terminals: List[CamponiTerminal] = []
    if agent_ids:
        camponi_cmd = _resolve_camponi(camponi)
        try:
            terminals = list_terminals(camponi_cmd, runtime_dir=camponi_dir)
        except WorkerRuntimeError as e:
            console.print(f"[bold red]❌ {e}[/bold red]")
            raise typer.Exit(code=2) from e
        targets.update(_agent_targets(agent_ids, terminals, test_names, ownership_map, log_path))
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
        base=base,
        cfg=WatchConfig(interval_sec=interval_sec, stall_min=stall_min, budget_min=budget_min, max_nudges=max_nudges,
                        loop_min=loop_min),
        log_path=log_path,
        camponi=camponi_cmd,
        once=once,
        targets=targets,
        camponi_dir=camponi_dir,
        terminals=terminals,
        ownership_path=Path(ownership) if ownership else None,
        ownership=ownership_map,
        test_names=test_names,
    )
    rows = watcher.tick_pass(time.time()) if once else watcher.run()
    if json_output:
        print(json.dumps([row.record for row in rows], indent=2))
    else:
        _print_table(rows)
