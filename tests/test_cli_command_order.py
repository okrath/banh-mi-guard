"""
Pin top-level CLI command order to prevent silent reordering from import sorting.
"""

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

    visible_commands = []
    in_commands_section = False
    for line in res.stdout.splitlines():
        if "Commands" in line:
            in_commands_section = True
            continue
        if in_commands_section and "│" in line:
            parts = line.split("│")
            if len(parts) >= 3:
                name = parts[1][:14].strip()
                if name and not name.startswith("─"):
                    visible_commands.append(name)

    assert visible_commands == EXPECTED_HELP_COMMAND_ORDER
