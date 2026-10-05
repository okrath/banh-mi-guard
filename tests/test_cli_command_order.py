"""
Pin top-level CLI command order to prevent silent reordering from import sorting.
"""

from typing import cast

import typer
import typer.core
import typer.main
from typer.testing import CliRunner

import guard.cli

EXPECTED_REGISTERED_COMMANDS = [
    "pre",
    "post",
    "reset",
    "run",
    "setup",
    "install",
    "uninstall",
    "finding",
    "accept",
    "untracked",
    "agent-event",
    "review",
    "update",
    "doctor",
    "laya",
]

EXPECTED_REGISTERED_GROUPS = [
    "invariants",
    "config",
    "hook",
    "agent",
]

EXPECTED_HELP_COMMAND_ORDER = [
    "pre",
    "post",
    "reset",
    "run",
    "setup",
    "install",
    "uninstall",
    "finding",
    "accept",
    "untracked",
    "agent-event",
    "review",
    "update",
    "doctor",
    "invariants",
    "config",
    "hook",
    "agent",
]


def test_registered_commands_order():
    """Typer registered command and group names must match the canonical order."""
    cmd_names = [c.name or (c.callback.__name__ if c.callback else "") for c in guard.cli.app.registered_commands]
    group_names = [g.name for g in guard.cli.app.registered_groups]
    assert cmd_names == EXPECTED_REGISTERED_COMMANDS
    assert group_names == EXPECTED_REGISTERED_GROUPS


def test_help_command_order():
    """`guard --help` lists top-level commands and groups in the exact expected order."""
    runner = CliRunner()
    res = runner.invoke(guard.cli.app, ["--help"])
    assert res.exit_code == 0

    group = cast(typer.core.TyperGroup, typer.main.get_command(guard.cli.app))
    ctx = typer.Context(group)
    visible_commands = [
        name
        for name in group.list_commands(ctx)
        if not getattr(group.get_command(ctx, name), "hidden", False)
    ]
    assert visible_commands == EXPECTED_HELP_COMMAND_ORDER
