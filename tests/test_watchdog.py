"""Tests for `guard/core/watchdog.py`: the worker supervision state machine."""

from __future__ import annotations

from guard.core.watchdog import (
    DEPS_TEXT,
    IDLE_TEXT,
    LOOPING_TEXT,
    NUDGE_LIMIT_TEXT,
    OVERDUE_TEXT,
    REJECT_TEXT,
    STALLED_TEXT,
    SUSPECT_TEXT,
    Action,
    WatchConfig,
    WorkerMonitor,
    WorkerTick,
)

START = 1_000_000.0
FAILS = ("scope-outside-ownership: guard/cli.py", "weakened-skip-focus: tests/test_x.py")


def make_tick(**overrides) -> WorkerTick:
    """A tick that triggers nothing by itself: no commit yet, no activity, no findings."""
    values = {
        "name": "w1",
        "head": "b" * 40,
        "head_moved": False,
        "dirty": True,
        "activity_ts": None,
        "heartbeat_ts": None,
    }
    values.update(overrides)
    return WorkerTick(**values)


def monitor(role: str = "fix", cfg: WatchConfig | None = None) -> WorkerMonitor:
    return WorkerMonitor("w1", role, "a" * 40, cfg or WatchConfig(), now=START)


# 1. done: a fix worker that committed on a clean tree.


def test_fix_is_done_when_the_head_moved_and_the_tree_is_clean() -> None:
    mon = monitor()
    assert mon.observe(make_tick(head_moved=True, dirty=False), START + 10) == [Action("done", "done", "")]
    assert mon.done is True
    assert mon.observe(make_tick(), START + 20) == []
    assert mon.observe(make_tick(head_moved=True, dirty=False), START + 30) == []


def test_fix_with_uncommitted_changes_is_not_done() -> None:
    mon = monitor()
    assert mon.observe(make_tick(head_moved=True, dirty=True), START + 10) == []
    assert mon.done is False


def test_unknown_start_head_counts_the_first_real_head_as_moved() -> None:
    mon = WorkerMonitor("w1", "fix", None, WatchConfig(), now=START)
    # Unborn HEAD: no commit to compare against, so nothing is decided.
    assert mon.observe(make_tick(head=None, head_moved=False, dirty=True), START + 10) == []
    assert mon.observe(make_tick(head="c" * 40, head_moved=False, dirty=False), START + 20) == [Action("done", "done", "")]
    assert mon.done is True


# 2. Settled without a clean commit: needs-human instead of a nudge.


def test_fix_settled_without_a_commit_needs_human() -> None:
    mon = monitor()
    actions = mon.observe(make_tick(settled=True), START + 10)
    assert [(a.kind, a.reason) for a in actions] == [("needs-human", "settled-no-commit")]
    assert actions[0].text  # a one-line explanation for the coordinator
    assert mon.needs_human is True
    assert mon.nudges == 0
    assert mon.observe(make_tick(head_moved=True, dirty=False), START + 20) == []


def test_fix_settled_clean_but_unmoved_still_needs_human() -> None:
    mon = monitor()
    actions = mon.observe(make_tick(settled=True, dirty=False), START + 10)
    assert [(a.kind, a.reason) for a in actions] == [("needs-human", "settled-no-commit")]


def test_fix_settled_after_a_move_but_dirty_is_settled_dirty() -> None:
    mon = monitor()
    actions = mon.observe(make_tick(settled=True, head_moved=True, dirty=True), START + 10)
    assert [(a.kind, a.reason) for a in actions] == [("needs-human", "settled-dirty")]
    assert mon.needs_human is True


# 3. The test role: no commit expected, dirty means trouble.


def test_test_worker_is_done_when_it_settles_clean() -> None:
    mon = monitor("test")
    assert mon.observe(make_tick(settled=True, dirty=False), START + 10) == [Action("done", "done", "")]
    assert mon.done is True
    assert mon.observe(make_tick(), START + 20) == []


def test_test_worker_settled_dirty_needs_human() -> None:
    mon = monitor("test")
    actions = mon.observe(make_tick(settled=True), START + 10)
    assert [(a.kind, a.reason) for a in actions] == [("needs-human", "settled-dirty")]
    assert mon.needs_human is True


def test_test_worker_is_not_done_before_it_settles() -> None:
    mon = monitor("test")
    assert mon.observe(make_tick(head_moved=True, dirty=False), START + 10) == []
    assert mon.done is False


# 4. Suspect: one nudge per distinct quick-fail set, alive until the budget runs out.


def test_suspect_nudges_once_per_distinct_finding_set() -> None:
    mon = monitor()
    first = mon.observe(make_tick(quick_fails=FAILS), START + 10)
    assert [(a.kind, a.reason) for a in first] == [("nudge", "suspect")]
    assert first[0].text == SUSPECT_TEXT.format(findings="; ".join(FAILS))
    assert mon.nudges == 1

    assert mon.observe(make_tick(quick_fails=FAILS), START + 20) == []
    assert mon.observe(make_tick(quick_fails=tuple(reversed(FAILS))), START + 30) == []
    assert mon.nudges == 1

    other = mon.observe(make_tick(quick_fails=("ci-workflow-changed: .github/workflows/tests.yml",)), START + 40)
    assert [(a.kind, a.reason) for a in other] == [("nudge", "suspect")]
    assert other[0].text == SUSPECT_TEXT.format(findings="ci-workflow-changed: .github/workflows/tests.yml")
    assert mon.nudges == 2


def test_suspect_nudges_count_towards_the_budget() -> None:
    mon = monitor(cfg=WatchConfig(max_nudges=1))
    assert [a.reason for a in mon.observe(make_tick(quick_fails=("f1",)), START + 10)] == ["suspect"]
    actions = mon.observe(make_tick(quick_fails=("f2",)), START + 20)
    assert [(a.kind, a.reason) for a in actions] == [("needs-human", "nudge-limit")]


# 5. Idle: interval_sec * idle_checks of no signal, once per inactivity window.


def test_idle_fires_at_interval_times_idle_checks_once_per_window() -> None:
    mon = monitor()
    assert mon.observe(make_tick(activity_ts=START - 179), START) == []
    actions = mon.observe(make_tick(activity_ts=START - 180), START)
    assert [(a.kind, a.reason) for a in actions] == [("nudge", "idle")]
    assert actions[0].text == IDLE_TEXT
    assert mon.nudges == 1

    assert mon.observe(make_tick(activity_ts=START - 180), START + 10) == []  # same window

    # A newer signal re-arms the window; it fires once it is itself old enough.
    actions = mon.observe(make_tick(activity_ts=START + 100), START + 280)
    assert [a.reason for a in actions] == ["idle"]
    assert mon.nudges == 2


def test_idle_never_fires_without_a_signal() -> None:
    mon = monitor("test")  # overdue never fires for a test worker, so a far-future `now` is safe
    assert mon.observe(make_tick(activity_ts=None, heartbeat_ts=None), START + 100_000) == []


def test_heartbeat_alone_arms_the_idle_window() -> None:
    mon = monitor()
    actions = mon.observe(make_tick(activity_ts=None, heartbeat_ts=START - 200), START)
    assert [a.reason for a in actions] == ["idle"]


# 6. Stalled: the newest signal is older than stall_min.


def test_stalled_fires_once_the_signal_is_older_than_stall_min() -> None:
    mon = monitor()
    # 300s old: past the idle window, not yet the stall window.
    assert [a.reason for a in mon.observe(make_tick(activity_ts=START - 300), START)] == ["idle"]
    actions = mon.observe(make_tick(activity_ts=START - 300), START + 200)
    assert [(a.kind, a.reason) for a in actions] == [("nudge", "stalled")]
    assert actions[0].text == STALLED_TEXT.format(stall_min=8.0)
    assert mon.nudges == 2
    assert mon.observe(make_tick(activity_ts=START - 300), START + 260) == []


def test_a_fresh_heartbeat_inside_the_window_prevents_stalled() -> None:
    mon = monitor()
    tick = make_tick(activity_ts=START - 10_000, heartbeat_ts=START - 100)
    assert mon.observe(tick, START) == []


def test_stalled_re_arms_on_a_newer_signal() -> None:
    cfg = WatchConfig(idle_checks=100)  # keep idle out of the way
    mon = WorkerMonitor("w1", "fix", "a" * 40, cfg, now=START)
    assert [a.reason for a in mon.observe(make_tick(activity_ts=START - 500), START)] == ["stalled"]
    assert mon.observe(make_tick(activity_ts=START - 500), START + 30) == []
    # A newer heartbeat resets the window: nothing until it is itself older than stall_min.
    assert mon.observe(make_tick(heartbeat_ts=START - 10), START + 30) == []
    assert [a.reason for a in mon.observe(make_tick(heartbeat_ts=START - 10), START + 490)] == ["stalled"]
    assert mon.nudges == 2


# 7. Overdue: fix role, once, only while the worker has not committed.


def test_overdue_fires_once_at_the_budget_and_never_after_a_commit() -> None:
    mon = WorkerMonitor("w1", "fix", "a" * 40, WatchConfig(budget_min=10), now=START)
    assert mon.observe(make_tick(), START + 599) == []
    actions = mon.observe(make_tick(), START + 600)
    assert [(a.kind, a.reason) for a in actions] == [("nudge", "overdue")]
    assert actions[0].text == OVERDUE_TEXT.format(budget_min=10.0)
    assert mon.observe(make_tick(), START + 700) == []
    assert mon.observe(make_tick(head_moved=True), START + 800) == []


def test_overdue_never_fires_after_the_head_moved() -> None:
    mon = WorkerMonitor("w1", "fix", "a" * 40, WatchConfig(budget_min=10), now=START)
    assert mon.observe(make_tick(head_moved=True), START + 6000) == []


def test_overdue_never_fires_for_a_test_worker() -> None:
    mon = WorkerMonitor("w1", "test", "a" * 40, WatchConfig(budget_min=10), now=START)
    assert mon.observe(make_tick(), START + 6000) == []


# 8. One nudge per observe call: suspect > overdue > stalled > idle.


def test_suspect_outranks_overdue_stalled_and_idle() -> None:
    mon = WorkerMonitor("w1", "fix", "a" * 40, WatchConfig(budget_min=1), now=START)
    actions = mon.observe(make_tick(quick_fails=("f1",), activity_ts=START - 500), START + 3000)
    assert [a.reason for a in actions] == ["suspect"]
    assert mon.nudges == 1


def test_one_nudge_per_observe_call_in_priority_order() -> None:
    mon = monitor()
    tick_kwargs = {"quick_fails": ("f1",), "activity_ts": START - 500}
    now = START + 3000
    assert [a.reason for a in mon.observe(make_tick(**tick_kwargs), now)] == ["suspect"]
    assert [a.reason for a in mon.observe(make_tick(**tick_kwargs), now)] == ["overdue"]
    assert [a.reason for a in mon.observe(make_tick(**tick_kwargs), now)] == ["stalled"]
    assert [a.reason for a in mon.observe(make_tick(**tick_kwargs), now)] == ["idle"]
    assert mon.observe(make_tick(**tick_kwargs), now) == []
    assert mon.nudges == 4


def test_overdue_outranks_stalled_and_idle() -> None:
    cfg = WatchConfig(budget_min=1, stall_min=1)
    mon = WorkerMonitor("w1", "fix", "a" * 40, cfg, now=START)
    actions = mon.observe(make_tick(activity_ts=START - 120), START + 120)
    assert [a.reason for a in actions] == ["overdue"]


def test_stalled_outranks_idle() -> None:
    mon = monitor()
    actions = mon.observe(make_tick(activity_ts=START - 500), START)
    assert [a.reason for a in actions] == ["stalled"]


# 9. The nudge budget turns the next trigger into needs-human, then the machine stops.


def test_nudge_limit_turns_the_next_trigger_into_needs_human() -> None:
    mon = monitor(cfg=WatchConfig(max_nudges=2))
    assert [a.reason for a in mon.observe(make_tick(quick_fails=("f1",)), START)] == ["suspect"]
    assert [a.reason for a in mon.observe(make_tick(quick_fails=("f2",)), START)] == ["suspect"]
    actions = mon.observe(make_tick(quick_fails=("f3",)), START)
    assert [(a.kind, a.reason) for a in actions] == [("needs-human", "nudge-limit")]
    assert actions[0].text == NUDGE_LIMIT_TEXT.format(max_nudges=2)
    assert mon.nudges == 2
    assert mon.needs_human is True
    assert mon.observe(make_tick(quick_fails=("f4",)), START + 1) == []


def test_nudge_budget_without_a_pending_trigger_stays_quiet() -> None:
    mon = monitor(cfg=WatchConfig(max_nudges=0))
    assert mon.observe(make_tick(), START) == []
    actions = mon.observe(make_tick(quick_fails=("f1",)), START)
    assert [(a.kind, a.reason) for a in actions] == [("needs-human", "nudge-limit")]


# 10. The frozen nudge texts, exactly as the CLI sends them.


def test_nudge_texts_are_exact() -> None:
    assert IDLE_TEXT == "Continue: nothing moved for two checks. If you are blocked, say what blocks you; otherwise take the next step and commit a working step."
    assert STALLED_TEXT == "No progress for {stall_min:g} minutes. Stop circling: measure the smallest next step, make the smallest change, and commit a working step now."
    assert OVERDUE_TEXT == "No commit after {budget_min:g} minutes of work. Commit what works now on your own branch; report blockers instead of holding work uncommitted."
    assert SUSPECT_TEXT == "Delivery check found: {findings}. Revert those edits at once. Never skip, weaken or silence checks."


def test_nudge_texts_format_their_values() -> None:
    assert STALLED_TEXT.format(stall_min=8.0) == "No progress for 8 minutes. Stop circling: measure the smallest next step, make the smallest change, and commit a working step now."
    assert STALLED_TEXT.format(stall_min=2.5) == "No progress for 2.5 minutes. Stop circling: measure the smallest next step, make the smallest change, and commit a working step now."
    assert OVERDUE_TEXT.format(budget_min=10.0) == "No commit after 10 minutes of work. Commit what works now on your own branch; report blockers instead of holding work uncommitted."
    assert OVERDUE_TEXT.format(budget_min=6.5) == "No commit after 6.5 minutes of work. Commit what works now on your own branch; report blockers instead of holding work uncommitted."
    assert SUSPECT_TEXT.format(findings="a; b") == "Delivery check found: a; b. Revert those edits at once. Never skip, weaken or silence checks."


def test_nudges_use_the_configured_numbers() -> None:
    cfg = WatchConfig(stall_min=2.5, budget_min=6.5)
    mon = WorkerMonitor("w1", "fix", "a" * 40, cfg, now=START)
    actions = mon.observe(make_tick(activity_ts=START - 150), START)
    assert [a.reason for a in actions] == ["stalled"]
    assert actions[0].text == "No progress for 2.5 minutes. Stop circling: measure the smallest next step, make the smallest change, and commit a working step now."

    other = WorkerMonitor("w1", "fix", "a" * 40, cfg, now=START)
    actions = other.observe(make_tick(), START + 390)
    assert [a.reason for a in actions] == ["overdue"]
    assert actions[0].text == "No commit after 6.5 minutes of work. Commit what works now on your own branch; report blockers instead of holding work uncommitted."


# 11. The screen decides idle and stalled when there is one.


def screen_tick(**overrides) -> WorkerTick:
    """A tick with a readable screen: busy, a stable text that changed at START."""
    values = {"busy": True, "screen_changed_ts": START}
    values.update(overrides)
    return make_tick(**values)


def test_screen_idle_needs_idle_checks_passes_without_a_turn() -> None:
    mon = monitor()
    fresh = START + 1  # a fresh heartbeat changes nothing: the screen shows no running turn
    assert mon.observe(screen_tick(busy=False, heartbeat_ts=fresh), START + 10) == []
    actions = mon.observe(screen_tick(busy=False, heartbeat_ts=fresh), START + 20)
    assert actions == [Action("nudge", "idle", IDLE_TEXT, interrupt=False)]
    assert mon.observe(screen_tick(busy=False), START + 30) == []  # the count restarts after a nudge
    assert [a.reason for a in mon.observe(screen_tick(busy=False), START + 40)] == ["idle"]


def test_screen_idle_count_resets_on_a_busy_pass() -> None:
    mon = monitor()
    assert mon.observe(screen_tick(busy=False), START + 10) == []
    assert mon.observe(screen_tick(busy=True), START + 20) == []
    assert mon.observe(screen_tick(busy=False), START + 30) == []
    assert [a.reason for a in mon.observe(screen_tick(busy=False), START + 40)] == ["idle"]


def test_screen_idle_ignores_an_old_signal_age() -> None:
    mon = monitor()
    # Without a screen this tick would be stalled at once; with one, a single quiet pass is not idle yet.
    assert mon.observe(screen_tick(busy=False, activity_ts=START - 10_000), START) == []


def test_frozen_busy_screen_is_stalled_despite_a_fresh_heartbeat() -> None:
    mon = monitor()
    stall = 8 * 60
    assert mon.observe(screen_tick(heartbeat_ts=START + stall - 1), START + stall - 1) == []
    actions = mon.observe(screen_tick(heartbeat_ts=START + stall), START + stall)
    assert actions == [Action("nudge", "stalled", STALLED_TEXT.format(stall_min=8.0), interrupt=True)]
    # The clock restarts at the nudge: the same frozen screen fires again one stall window later.
    assert mon.observe(screen_tick(), START + 2 * stall - 1) == []
    assert [a.reason for a in mon.observe(screen_tick(), START + 2 * stall)] == ["stalled"]


def test_a_changing_screen_is_not_stalled() -> None:
    mon = monitor()
    assert mon.observe(screen_tick(screen_changed_ts=START + 400), START + 600) == []
    assert mon.observe(screen_tick(screen_changed_ts=START + 400), START + 400 + 8 * 60 - 1) == []


def test_busy_without_a_screen_stamp_falls_back_to_the_signal_age() -> None:
    mon = monitor()
    actions = mon.observe(make_tick(busy=True, activity_ts=START - 500), START)
    assert [(a.reason, a.interrupt) for a in actions] == [("stalled", True)]


def test_no_screen_keeps_the_signal_age_behaviour() -> None:
    mon = monitor()
    actions = mon.observe(make_tick(busy=None, activity_ts=START - 180), START)
    assert actions == [Action("nudge", "idle", IDLE_TEXT, interrupt=False)]


# 12. Looping: one command on screen for loop_min, interrupted, clock restarted.


def test_one_command_for_loop_min_is_looping() -> None:
    mon = monitor()
    command = "pnpm exec playwright test --retries 50"

    def tick(now: float) -> WorkerTick:  # the command prints all the time, so the screen keeps changing
        return screen_tick(command=command, command_since=START, screen_changed_ts=now - 1)

    assert mon.observe(tick(START + 599), START + 599) == []
    actions = mon.observe(tick(START + 600), START + 600)
    assert actions == [Action("nudge", "looping", LOOPING_TEXT.format(loop_min=10.0, command=command), interrupt=True)]
    assert command in actions[0].text
    # Reset after the nudge: no repeat until another loop_min passes with the same command.
    assert mon.observe(tick(START + 1199), START + 1199) == []
    assert [a.reason for a in mon.observe(tick(START + 1200), START + 1200)] == ["looping"]


def test_the_loop_clock_starts_when_the_command_appeared() -> None:
    mon = monitor(cfg=WatchConfig(loop_min=1))
    assert mon.observe(screen_tick(command="npm test", command_since=START + 50, screen_changed_ts=START + 99), START + 100) == []
    actions = mon.observe(screen_tick(command="npm test", command_since=START + 50, screen_changed_ts=START + 109), START + 110)
    assert [a.reason for a in actions] == ["looping"]
    assert LOOPING_TEXT.format(loop_min=1.0, command="npm test") == actions[0].text


def test_looping_needs_a_command() -> None:
    mon = monitor(cfg=WatchConfig(loop_min=1))
    assert mon.observe(screen_tick(command=None, command_since=START, screen_changed_ts=START + 290), START + 300) == []


# 13. Interrupts: stalled, looping, deps-broken, and any nudge to a busy worker.


def test_suspect_to_a_busy_worker_interrupts() -> None:
    busy = monitor().observe(screen_tick(quick_fails=("f1",)), START)
    quiet = monitor().observe(screen_tick(busy=False, quick_fails=("f1",)), START)
    unknown = monitor().observe(make_tick(quick_fails=("f1",)), START)
    assert [(a.reason, a.interrupt) for a in busy] == [("suspect", True)]
    assert [(a.reason, a.interrupt) for a in quiet] == [("suspect", False)]
    assert [(a.reason, a.interrupt) for a in unknown] == [("suspect", False)]


def test_overdue_to_a_busy_worker_interrupts() -> None:
    mon = WorkerMonitor("w1", "fix", "a" * 40, WatchConfig(budget_min=1), now=START)
    actions = mon.observe(screen_tick(screen_changed_ts=START + 59), START + 60)
    assert [(a.reason, a.interrupt) for a in actions] == [("overdue", True)]


def test_signal_age_stalled_always_interrupts() -> None:
    actions = monitor().observe(make_tick(activity_ts=START - 500), START)
    assert [(a.reason, a.interrupt) for a in actions] == [("stalled", True)]


# 14. Committed but busy stays watched; done needs a quiet (or unknown) screen.


def test_committed_but_busy_is_not_done() -> None:
    mon = monitor()
    committed = {"head_moved": True, "dirty": False}
    assert mon.observe(screen_tick(**committed, screen_changed_ts=START - 10_000, activity_ts=START - 10_000), START) == []
    assert mon.done is False
    assert mon.nudges == 0  # no idle, stalled or overdue after the commit
    assert mon.observe(screen_tick(busy=False, **committed), START + 10) == [Action("done", "done", "")]
    assert mon.done is True


def test_committed_but_busy_still_gets_the_loop_check() -> None:
    mon = monitor()
    tick = screen_tick(head_moved=True, dirty=False, command="node poll.js", command_since=START)
    actions = mon.observe(tick, START + 600)
    assert [(a.reason, a.interrupt) for a in actions] == [("looping", True)]
    assert mon.done is False


def test_committed_busy_and_settled_is_done() -> None:
    mon = monitor()
    assert mon.observe(screen_tick(head_moved=True, dirty=False, settled=True), START) == [Action("done", "done", "")]


def test_committed_without_a_screen_is_done() -> None:
    assert monitor().observe(make_tick(head_moved=True, dirty=False, busy=None), START) == [Action("done", "done", "")]


# 15. Honesty before done: failing findings on a finished result make a reject candidate.


def test_clean_commit_with_findings_is_a_reject_candidate() -> None:
    mon = monitor()
    actions = mon.observe(make_tick(head_moved=True, dirty=False, quick_fails=FAILS), START)
    assert actions == [Action("needs-human", "reject-candidate", REJECT_TEXT.format(findings="; ".join(FAILS)))]
    assert all(fail in actions[0].text for fail in FAILS)
    assert mon.done is False
    assert mon.needs_human is True
    assert mon.nudges == 0


def test_settled_fix_worker_with_findings_is_a_reject_candidate() -> None:
    actions = monitor().observe(make_tick(head_moved=True, dirty=False, settled=True, quick_fails=("f1",)), START)
    assert [(a.kind, a.reason) for a in actions] == [("needs-human", "reject-candidate")]


def test_settled_test_worker_with_findings_is_a_reject_candidate() -> None:
    mon = monitor("test")
    actions = mon.observe(make_tick(settled=True, dirty=False, quick_fails=("test-worker-tracked-edits: a.py",)), START)
    assert [(a.kind, a.reason) for a in actions] == [("needs-human", "reject-candidate")]
    assert "test-worker-tracked-edits: a.py" in actions[0].text


def test_committed_busy_worker_with_findings_gets_the_suspect_nudge() -> None:
    mon = monitor()
    actions = mon.observe(screen_tick(head_moved=True, dirty=False, quick_fails=("f1",)), START)
    assert [(a.reason, a.interrupt) for a in actions] == [("suspect", True)]
    assert mon.done is False


# 16. Dependency links: one interrupt per broken line naming the worker.


def test_deps_broken_nudges_once_per_line() -> None:
    mon = monitor()
    line_a = "FAIL main checkout node_modules -> C:/w/w1/node_modules"
    line_b = "FAIL apps/api/node_modules -> C:/w/w1/apps/api/node_modules"
    first = mon.observe(make_tick(deps_fails=(line_a,)), START)
    assert first == [Action("nudge", "deps-broken", DEPS_TEXT.format(line=line_a), interrupt=True)]
    assert mon.observe(make_tick(deps_fails=(line_a,)), START + 10) == []
    second = mon.observe(make_tick(deps_fails=(line_a, line_b)), START + 20)
    assert [(a.reason, a.text) for a in second] == [("deps-broken", DEPS_TEXT.format(line=line_b))]
    assert mon.nudges == 2


def test_deps_broken_outranks_suspect() -> None:
    actions = monitor().observe(make_tick(deps_fails=("FAIL x",), quick_fails=("f1",)), START)
    assert [a.reason for a in actions] == ["deps-broken"]


def test_new_nudges_count_towards_the_budget() -> None:
    mon = monitor(cfg=WatchConfig(max_nudges=1, loop_min=1))
    assert [a.reason for a in mon.observe(make_tick(deps_fails=("FAIL x",)), START)] == ["deps-broken"]
    actions = mon.observe(screen_tick(command="npm test", command_since=START, screen_changed_ts=START + 60), START + 60)
    assert [(a.kind, a.reason) for a in actions] == [("needs-human", "nudge-limit")]


def test_new_texts_are_exact() -> None:
    assert LOOPING_TEXT.format(loop_min=10.0, command="npm test") == "One command has run for 10 minutes (npm test). Stop it now and do not restart it. Keep what you have, write the blocker and what you measured into your report, finish the remaining acceptance steps, then send worker_done."
    assert DEPS_TEXT.format(line="FAIL x") == "Dependency check: FAIL x. You ran an install through your node_modules junction and the main checkout now loads packages from your worktree. Never install, clean or prune dependencies. Stop, run no other install, and say in your report which command did it."
    assert REJECT_TEXT.format(findings="a; b") == "Reject candidate: the delivery check failed on the finished work: a; b. Do not accept it without a human review."
    assert WatchConfig().loop_min == 10.0
