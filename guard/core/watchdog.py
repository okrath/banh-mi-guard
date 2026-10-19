"""
Deterministic supervision state machine for one watched worker.

Pure decision logic ported from the parallel-tasks watchdog: `WorkerTick` observations become
done / nudge / needs-human `Action`s that the caller executes. No I/O, no git, no Orca here -
a leaf module other tasks can depend on. Decisions are deterministic for a given sequence of
(tick, now) and mutate only this monitor's state.
"""

from __future__ import annotations

from dataclasses import dataclass

# Nudge texts the CLI sends verbatim to the worker's terminal.
IDLE_TEXT = "Continue: nothing moved for two checks. If you are blocked, say what blocks you; otherwise take the next step and commit a working step."
STALLED_TEXT = "No progress for {stall_min:g} minutes. Stop circling: measure the smallest next step, make the smallest change, and commit a working step now."
OVERDUE_TEXT = "No commit after {budget_min:g} minutes of work. Commit what works now on your own branch; report blockers instead of holding work uncommitted."
SUSPECT_TEXT = "Delivery check found: {findings}. Revert those edits at once. Never skip, weaken or silence checks."
LOOPING_TEXT = "One command has run for {loop_min:g} minutes ({command}). Stop it now and do not restart it. Keep what you have, write the blocker and what you measured into your report, finish the remaining acceptance steps, then send worker_done."
DEPS_TEXT = "Dependency check: {line}. You ran an install through your node_modules junction and the main checkout now loads packages from your worktree. Never install, clean or prune dependencies. Stop, run no other install, and say in your report which command did it."

# Explanations attached to needs-human actions; the coordinator reads them.
SETTLED_NO_COMMIT_TEXT = "Settled without a commit: HEAD did not move, so there is no committed step to accept."
SETTLED_DIRTY_TEXT = "Settled with uncommitted changes: the worktree is dirty, so there is no clean step to accept."
NUDGE_LIMIT_TEXT = "Nudge limit reached ({max_nudges} sent): this worker needs a human."
REJECT_TEXT = "Reject candidate: the delivery check failed on the finished work: {findings}. Do not accept it without a human review."


@dataclass(frozen=True)
class WatchConfig:
    """Timing and budget knobs of one watch run."""

    interval_sec: float = 90.0
    stall_min: float = 8.0
    budget_min: float = 45.0
    max_nudges: int = 5
    idle_checks: int = 2
    loop_min: float = 10.0


@dataclass(frozen=True)
class WorkerTick:
    """One observation of a worker's worktree, liveness and (when readable) terminal screen."""

    name: str
    head: str | None  # current HEAD sha (None: unknown/unborn)
    head_moved: bool
    dirty: bool
    activity_ts: float | None  # newest git-visible activity (commit or changed-file mtime)
    heartbeat_ts: float | None  # newest liveness heartbeat (None when the provider has none)
    settled: bool = False
    quick_fails: tuple[str, ...] = ()
    busy: bool | None = None  # a turn is running on screen (None: no screen available)
    screen_changed_ts: float | None = None  # last time the stable screen text changed
    command: str | None = None  # the shell command running on screen
    command_since: float | None = None  # since when that same command is on screen
    dev_server_on_screen: bool = False
    deps_fails: tuple[str, ...] = ()  # main-checkout dependency failures naming this worktree


@dataclass(frozen=True)
class Action:
    """One decision for the CLI to execute."""

    kind: str  # "nudge" | "done" | "needs-human"
    reason: str  # "idle" | "stalled" | "overdue" | "suspect" | "looping" | "deps-broken" | "done" | "settled-no-commit" | "settled-dirty" | "reject-candidate" | "nudge-limit"
    text: str
    interrupt: bool = False  # deliver as an interrupt: a plain message queues behind a running command


class WorkerMonitor:
    """
    Supervision state of one worker.

    `observe` decodes one tick into at most one action. `done` and `needs_human` are terminal,
    so every later `observe` returns []. Nudges stop at `cfg.max_nudges`: the trigger that
    would exceed the budget becomes a needs-human `nudge-limit` instead.

    With a screen (`tick.busy` is not None) the screen decides: idle means no running turn for
    `idle_checks` passes, stalled means the stable screen text froze for `stall_min` while busy.
    Without one, the age of the newest git activity or heartbeat decides, as before.
    """

    def __init__(self, name: str, role: str, start_head: str | None, cfg: WatchConfig, *, now: float) -> None:
        self.name = name
        self.role = role  # "fix" | "test"
        self.start_head = start_head  # None: unknown at start
        self.cfg = cfg
        self.started_at = now
        self._nudges = 0
        self._done = False
        self._needs_human = False
        self._nudged_fail_sets: set[frozenset[str]] = set()
        self._nudged_deps: set[str] = set()
        self._overdue_sent = False
        self._last_stalled_signal: float | None = None
        self._last_idle_signal: float | None = None
        self._idle_passes = 0  # consecutive passes without a running turn on screen
        self._screen_stall_reset: float | None = None  # when the last screen stall nudge restarted the clock
        self._loop_reset: float | None = None  # when the last looping nudge restarted the clock

    @property
    def nudges(self) -> int:
        """How many nudges this monitor has sent so far."""
        return self._nudges

    @property
    def done(self) -> bool:
        """True once the worker delivered a clean result."""
        return self._done

    @property
    def needs_human(self) -> bool:
        """True once the machine gave up on the worker."""
        return self._needs_human

    def observe(self, tick: WorkerTick, now: float) -> list[Action]:
        """Decide what to do about one tick; returns [] while there is nothing to do."""
        if self._done or self._needs_human:
            return []
        terminal = self._terminal_action(tick)
        if terminal is not None:
            return [terminal]
        nudge = self._next_nudge(tick, now)
        if nudge is None:
            return []
        if self._nudges >= self.cfg.max_nudges:
            self._needs_human = True
            return [Action("needs-human", "nudge-limit", NUDGE_LIMIT_TEXT.format(max_nudges=self.cfg.max_nudges))]
        self._nudges += 1
        return [nudge]

    def _terminal_action(self, tick: WorkerTick) -> Action | None:
        """Done / needs-human, or None while the worker is still running."""
        if self.role == "test":
            # A test worker commits nothing: done when it settles, a dirty tree means trouble.
            if not tick.settled:
                return None
            if not tick.dirty:
                return self._finish(tick)
            self._needs_human = True
            return Action("needs-human", "settled-dirty", SETTLED_DIRTY_TEXT)

        moved = self._head_moved(tick)
        # Committed but still busy (stills, the report) stays watched: a loop after the commit is waste too.
        if moved and not tick.dirty and (tick.busy is not True or tick.settled):
            return self._finish(tick)
        if tick.settled:
            # Settled without a clean commit: there is nothing acceptable to hand over.
            self._needs_human = True
            if moved:
                return Action("needs-human", "settled-dirty", SETTLED_DIRTY_TEXT)
            return Action("needs-human", "settled-no-commit", SETTLED_NO_COMMIT_TEXT)
        return None

    def _finish(self, tick: WorkerTick) -> Action:
        """Done, unless the delivery check of this same tick failed: then a reject candidate."""
        if tick.quick_fails:
            self._needs_human = True
            return Action("needs-human", "reject-candidate", REJECT_TEXT.format(findings="; ".join(tick.quick_fails)))
        self._done = True
        return Action("done", "done", "")

    def _next_nudge(self, tick: WorkerTick, now: float) -> Action | None:
        """The highest-priority nudge this tick triggers and the monitor has not sent yet."""
        busy = tick.busy is True
        if busy:
            self._idle_passes = 0  # idle counts consecutive passes without a running turn
        for line in tick.deps_fails:  # one interrupt per broken dependency line
            if line not in self._nudged_deps:
                self._nudged_deps.add(line)
                return Action("nudge", "deps-broken", DEPS_TEXT.format(line=line), interrupt=True)

        fail_set = frozenset(tick.quick_fails)
        if fail_set and fail_set not in self._nudged_fail_sets:  # one nudge per distinct finding set
            self._nudged_fail_sets.add(fail_set)
            return Action("nudge", "suspect", SUSPECT_TEXT.format(findings="; ".join(tick.quick_fails)), interrupt=busy)

        looping = self._looping(tick, now)
        if looping is not None:
            return looping
        moved = self._head_moved(tick)
        if self.role != "test" and moved and not tick.dirty:
            return None  # committed and still busy: only the loop check applies

        if self.role != "test" and not moved and not self._overdue_sent:
            if now - self.started_at >= self.cfg.budget_min * 60:  # once ever, and never for a test worker
                self._overdue_sent = True
                return Action("nudge", "overdue", OVERDUE_TEXT.format(budget_min=self.cfg.budget_min), interrupt=busy)

        if tick.busy is False:
            return self._screen_idle()
        if busy and tick.screen_changed_ts is not None:
            return self._screen_stalled(tick.screen_changed_ts, now)

        last_signal = _last_signal(tick)
        if last_signal is None:  # no heartbeat and no git activity: inactivity is unknown, not a stall
            return None
        if now - last_signal >= self.cfg.stall_min * 60 and last_signal != self._last_stalled_signal:
            self._last_stalled_signal = last_signal  # one nudge per window; a newer signal re-arms
            return Action("nudge", "stalled", STALLED_TEXT.format(stall_min=self.cfg.stall_min), interrupt=True)
        if now - last_signal >= self.cfg.interval_sec * self.cfg.idle_checks and last_signal != self._last_idle_signal:
            self._last_idle_signal = last_signal
            return Action("nudge", "idle", IDLE_TEXT, interrupt=busy)
        return None

    def _looping(self, tick: WorkerTick, now: float) -> Action | None:
        """One command on screen for `loop_min`, however much it prints; the clock restarts after a nudge."""
        if not tick.command or tick.command_since is None:
            return None
        since = tick.command_since if self._loop_reset is None else max(tick.command_since, self._loop_reset)
        if now - since < self.cfg.loop_min * 60:
            return None
        self._loop_reset = now
        text = LOOPING_TEXT.format(loop_min=self.cfg.loop_min, command=tick.command)
        return Action("nudge", "looping", text, interrupt=True)

    def _screen_idle(self) -> Action | None:
        """No running turn on screen for `idle_checks` passes in a row."""
        self._idle_passes += 1
        if self._idle_passes < self.cfg.idle_checks:
            return None
        self._idle_passes = 0
        return Action("nudge", "idle", IDLE_TEXT)

    def _screen_stalled(self, changed: float, now: float) -> Action | None:
        """Busy while the stable screen text stayed the same for `stall_min`; a heartbeat never masks it."""
        since = changed if self._screen_stall_reset is None else max(changed, self._screen_stall_reset)
        if now - since < self.cfg.stall_min * 60:
            return None
        self._screen_stall_reset = now  # the clock restarts after each nudge
        return Action("nudge", "stalled", STALLED_TEXT.format(stall_min=self.cfg.stall_min), interrupt=True)

    def _head_moved(self, tick: WorkerTick) -> bool:
        """A caller-observed move, or the first real HEAD after an unknown start."""
        return tick.head_moved or (self.start_head is None and tick.head is not None)


def _last_signal(tick: WorkerTick) -> float | None:
    """Newest of the activity and heartbeat timestamps; None when both are unknown."""
    stamps = [ts for ts in (tick.activity_ts, tick.heartbeat_ts) if ts is not None]
    return max(stamps) if stamps else None
