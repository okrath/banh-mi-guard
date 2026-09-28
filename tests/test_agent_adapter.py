"""
The Claude Code adapter: guard's hook entries are merged into the user's settings without touching
anyone else's, removed the same way, and each harness event gets the answer Claude Code reads.
"""

import json
import os
from pathlib import Path

from typer.testing import CliRunner

import guard.cli as cli
from guard.agent.adapter import (
    CLAUDE_CODE, AdapterError, installed, read_config, render, with_guard, without_guard, write_config,
)
from guard.agent.events import Decision
from guard.cli import app, execute_pre_task
from test_agent_events import make_repo

COMMAND = ["C:/tools/guard.exe"]
FOREIGN = {"matcher": "Bash", "hooks": [{"type": "command", "command": "npx", "args": ["lint-staged"]}]}


def settings_path() -> Path:
    return Path(os.path.expanduser("~/.claude/settings.json"))  # conftest points HOME at a temp dir


def test_merge_keeps_other_hooks_and_is_idempotent():
    before = {"theme": "dark", "hooks": {"PreToolUse": [FOREIGN], "SessionStart": [FOREIGN]}}
    once = with_guard(before, CLAUDE_CODE, COMMAND)
    assert with_guard(once, CLAUDE_CODE, COMMAND) == once  # adding again changes nothing
    assert once["theme"] == "dark" and once["hooks"]["SessionStart"] == [FOREIGN]
    pre = once["hooks"]["PreToolUse"]
    assert pre[0] == FOREIGN and len(pre) == 2
    guard_hook = pre[1]["hooks"][0]
    assert guard_hook == {"type": "command", "command": COMMAND[0],
                          "args": ["agent-event", "before-edit", "--agent", "claude-code"]}  # exec form: no shell
    assert pre[1]["matcher"].startswith("Edit|Write")
    assert set(once["hooks"]) == {"PreToolUse", "SessionStart", "UserPromptSubmit", "PostToolUse", "Stop"}
    # a newer guard path replaces guard's entries instead of adding a second set
    moved = with_guard(once, CLAUDE_CODE, ["D:/new/guard.exe"])
    assert len(moved["hooks"]["PreToolUse"]) == 2 and moved["hooks"]["PreToolUse"][1]["hooks"][0]["command"] == "D:/new/guard.exe"


def test_remove_takes_out_only_guards_entries():
    lookalike = {"type": "command", "command": "other-tool", "args": ["agent-event", "after-bash"]}  # not guard's shape
    guards = {"type": "command", "command": "guard", "args": ["agent-event", "after-bash", "--agent", "claude-code"]}
    shared = {"matcher": "Bash", "hooks": [FOREIGN["hooks"][0], guards, lookalike]}
    settings = with_guard({"hooks": {"PreToolUse": [FOREIGN], "PostToolUse": [shared]}}, CLAUDE_CODE, COMMAND)
    removed = without_guard(settings)
    assert removed == {"hooks": {"PreToolUse": [FOREIGN],
                                 "PostToolUse": [{"matcher": "Bash", "hooks": [FOREIGN["hooks"][0], lookalike]}]}}
    assert without_guard(with_guard({"model": "x"}, CLAUDE_CODE, COMMAND)) == {"model": "x"}  # no empty hooks left behind


def test_the_original_settings_are_backed_up_once(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text('{"theme": "dark"}', encoding="utf-8")
    backup = write_config(path, with_guard(read_config(path), CLAUDE_CODE, COMMAND))
    assert backup and backup.read_text(encoding="utf-8") == '{"theme": "dark"}'
    assert write_config(path, without_guard(read_config(path))) is None  # the first original is kept
    assert backup.read_text(encoding="utf-8") == '{"theme": "dark"}'


def test_unreadable_settings_are_never_overwritten(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("{ not json", encoding="utf-8")
    for bad in ("{ not json", "[1, 2]", '{"hooks": []}'):
        path.write_text(bad, encoding="utf-8")
        try:
            read_config(path)
            raise AssertionError("expected AdapterError")
        except AdapterError:
            pass
        assert path.read_text(encoding="utf-8") == bad


def test_each_claude_code_event_gets_the_answer_it_reads():
    allow, note, block = Decision(), Decision(action="notify", reason="n"), Decision(action="block", reason="r")
    assert render(CLAUDE_CODE["output"], "PreToolUse", allow) == ("", "", 0)  # nothing to say
    assert render(CLAUDE_CODE["output"], "PreToolUse", block) == ("", "r\n", 2)  # exit 2: stderr reaches Claude
    assert render(CLAUDE_CODE["output"], "UserPromptSubmit", block) == ("", "r\n", 2)
    out, _, code = render(CLAUDE_CODE["output"], "Stop", block)
    assert code == 0 and json.loads(out) == {"decision": "block", "reason": "r"}  # Stop reads JSON on exit 0
    out, _, code = render(CLAUDE_CODE["output"], "PostToolUse", note)
    assert code == 0 and json.loads(out) == {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "n"}}
    assert json.loads(render(CLAUDE_CODE["output"], "Stop", note)[0]) == {"systemMessage": "n"}
    assert render(None, "", block) == ('{"decision": "block", "reason": "r"}\n', "r\n", 2)  # other agents: unchanged


def _event(event, payload):
    return CliRunner().invoke(app, ["agent-event", event, "--agent", "claude-code"], input=json.dumps(payload))


def test_recorded_claude_code_payloads_round_trip(tmp_path):
    repo = make_repo(tmp_path)
    common = {"session_id": "s1", "transcript_path": "t.jsonl", "cwd": str(repo), "permission_mode": "default"}
    edit = {**common, "hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_use_id": "toolu_1",
            "tool_input": {"file_path": str(repo / "src" / "chat.ts"), "old_string": "a", "new_string": "b"}}
    result = _event("before-edit", edit)
    assert result.exit_code == 2 and result.stdout == "" and "guard pre" in result.stderr  # blocked before pre

    read = {**edit, "tool_name": "Read", "tool_input": {"file_path": str(repo / "src" / "chat.ts")}}
    assert _event("before-edit", read).exit_code == 0

    prompt = {**common, "hook_event_name": "UserPromptSubmit", "prompt": "Fix src/chat.ts"}
    result = _event("prompt", prompt)
    assert result.exit_code == 0 and result.stderr == ""

    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    assert _event("before-edit", edit).exit_code == 0  # after pre: allowed, and silent
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    stop = {**common, "hook_event_name": "Stop", "stop_hook_active": False, "last_assistant_message": "done"}
    result = _event("stop", stop)
    assert result.exit_code == 0 and json.loads(result.stdout)["decision"] == "block"  # no approved post yet
    again = _event("stop", {**stop, "stop_hook_active": True})
    assert again.exit_code == 0 and '"block"' not in again.stdout  # the harness loop flag is respected


def test_add_test_and_remove_through_the_cli(tmp_path, monkeypatch):
    settings_path().parent.mkdir(parents=True)
    settings_path().write_text(json.dumps({"hooks": {"PreToolUse": [FOREIGN]}}), encoding="utf-8")
    assert CliRunner().invoke(app, ["agent", "add", "claude-code"], input="n\n").exit_code == 1  # declined: unchanged
    assert not installed(CLAUDE_CODE)

    def edit_meanwhile(*a, **k):  # the user (or another tool) changes the file while the diff is shown
        settings_path().write_text(json.dumps({"hooks": {"PreToolUse": [FOREIGN]}, "model": "new"}), encoding="utf-8")
        return True
    import pytest
    with pytest.MonkeyPatch.context() as mp:  # local: never undo conftest's HOME isolation
        mp.setattr(cli.typer, "confirm", edit_meanwhile)
        result = CliRunner().invoke(app, ["agent", "add", "claude-code"])
    assert result.exit_code == 1 and "changed while you were reading" in result.output
    assert read_config(settings_path()) == {"hooks": {"PreToolUse": [FOREIGN]}, "model": "new"}  # their change kept
    settings_path().write_text(json.dumps({"hooks": {"PreToolUse": [FOREIGN]}}), encoding="utf-8")
    result = CliRunner().invoke(app, ["agent", "add", "claude-code"], input="y\n")
    assert result.exit_code == 0 and installed(CLAUDE_CODE) and "+" in result.output  # the diff was shown
    assert read_config(settings_path())["hooks"]["PreToolUse"][0] == FOREIGN
    assert settings_path().with_name("settings.json.guard.bak").is_file()
    assert "already" in CliRunner().invoke(app, ["agent", "add", "claude-code"]).output

    # health: the hooks are reported
    from guard.core.repo_setup import setup_health
    rows = [r for r in setup_health(tmp_path) if r["item"] == "Agent hooks"]
    assert rows and rows[0]["level"] == "ok"

    # test: events that arrive while listening are reported, with the block
    repo = make_repo(tmp_path)
    assert CliRunner().invoke(app, ["agent", "test", "claude-code"]).exit_code == 0
    edit = {"cwd": str(repo), "hook_event_name": "PreToolUse", "tool_name": "Write",
            "tool_input": {"file_path": str(repo / "x.md"), "content": "x"}}
    _event("before-edit", edit)
    _event("prompt", {"cwd": str(repo), "hook_event_name": "UserPromptSubmit", "prompt": "write x.md"})
    report = CliRunner().invoke(app, ["agent", "test", "claude-code", "--report"])
    assert report.exit_code == 0 and "The edit was blocked by guard" in report.output
    assert "Stop" in report.output and "did not arrive" in report.output

    # remove: only in the user's terminal, and only guard's entries
    assert CliRunner().invoke(app, ["agent", "remove", "claude-code"]).exit_code == 1
    assert installed(CLAUDE_CODE)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    cli.agent_remove_cmd(name="claude-code")
    assert read_config(settings_path()) == {"hooks": {"PreToolUse": [FOREIGN]}}


def test_install_offers_the_adapter_when_claude_code_is_here(tmp_path):
    from guard.core.repo_setup import setup_health
    assert not [r for r in setup_health(tmp_path) if r["item"] == "Agent hooks"]  # no ~/.claude: nothing to offer
    settings_path().parent.mkdir(parents=True)
    row = [r for r in setup_health(tmp_path) if r["item"] == "Agent hooks"][0]
    assert row["level"] == "warn" and row["fix"] == "guard agent add claude-code"
