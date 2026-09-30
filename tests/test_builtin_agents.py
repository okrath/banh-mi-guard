"""
The adapters guard ships for the popular agents: each writes the shape its agent reads, is found
again as installed, removes only guard's own entries, and answers each harness event the way that
agent reads it. In-process agents (omp, pi, opencode) get one file of guard's instead.
"""

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from guard.agent.adapter import (
    BUILT_IN, config_path, extension_text, installed, load_adapter, render, with_guard, without_guard,
)
from guard.agent.adapter_validation import validate_adapter
from guard.agent.events import Decision, normalise
from guard.cli import app

COMMAND = ["C:/tools/guard.exe"]
POPULAR = ["claude-code", "codex", "cursor", "grok", "gemini", "antigravity", "zcode", "omp", "pi", "opencode"]
CONFIG_KIND = [n for n in POPULAR if BUILT_IN[n].get("kind") != "extension"]
EXTENSION_KIND = [n for n in POPULAR if BUILT_IN[n].get("kind") == "extension"]


def home() -> Path:
    return Path(os.path.expanduser("~"))  # conftest points HOME at a temp dir


def test_every_popular_agent_is_built_in_and_valid():
    assert set(POPULAR) <= set(BUILT_IN)
    for name in CONFIG_KIND:
        adapter = BUILT_IN[name]
        if name == "claude-code":
            continue  # the original shape: its own tests cover it
        shipped_only = ("kind", "install", "source", "protection_note")  # keys a registered adapter may not use
        copy = {k: v for k, v in adapter.items() if k not in shipped_only}
        problems = [p for p in validate_adapter(dict(copy, name=f"{name}-copy")) if not p.startswith("name")]
        assert problems == [], (name, problems)


@pytest.mark.parametrize("name", [n for n in CONFIG_KIND if n != "claude-code"])
def test_config_agents_install_idempotently_and_remove_exactly(name):
    adapter = BUILT_IN[name]
    foreign = {"command": "node audit.js", "timeout": 5}
    once = with_guard({"theme": "dark"}, adapter, COMMAND)
    assert with_guard(once, adapter, COMMAND) == once
    assert once["theme"] == "dark"
    back = without_guard(once, name, adapter)
    assert "agent-event" not in json.dumps(back)
    assert back.get("theme") == "dark"
    del foreign


def test_zcode_nests_hooks_and_enables_them():
    written = with_guard({"provider": "x"}, BUILT_IN["zcode"], COMMAND)
    assert written["hooks"]["enabled"] is True
    entry = written["hooks"]["events"]["PreToolUse"][0]
    assert entry["hooks"][0] == {"type": "process", "command": COMMAND[0],
                                 "args": ["agent-event", "before-edit", "--agent", "zcode"]}
    kept = with_guard({"hooks": {"enabled": False, "events": {}}}, BUILT_IN["zcode"], COMMAND)
    assert kept["hooks"]["enabled"] is False  # a choice the user made is never overridden
    assert without_guard(written, "zcode", BUILT_IN["zcode"]) == {"provider": "x", "hooks": {"enabled": True}}


def test_antigravity_writes_both_entry_shapes():
    hooks = with_guard({}, BUILT_IN["antigravity"], COMMAND)["hooks"]
    assert set(hooks["Stop"][0]) == {"type", "command"}  # bare handler
    assert set(hooks["PreToolUse"][0]) == {"matcher", "hooks"}  # matcher group
    assert without_guard({"hooks": hooks}, "antigravity") == {}


def test_cursor_writes_flat_entries_with_version():
    written = with_guard({}, BUILT_IN["cursor"], COMMAND)
    assert written["version"] == 1
    assert written["hooks"]["stop"] == [{"type": "command", "command": "C:/tools/guard.exe agent-event stop --agent cursor",
                                         "timeout": 600}]


def test_cursor_loop_count_and_antigravity_workspace_are_read():
    # a count above zero is a loop flag; Cursor's loop_count is not mapped (it counts per conversation)
    assert normalise("stop", {"loop": 1}).loop is True and normalise("stop", {"loop": 0}).loop is False
    assert normalise("stop", {"loop_count": 3}, BUILT_IN["cursor"].get("fields")).loop is False
    ag = BUILT_IN["antigravity"]["fields"]
    assert normalise("stop", {"workspacePaths": ["C:/work/repo"]}, ag).cwd == "C:/work/repo"


@pytest.mark.parametrize("name,harness,expect", [
    ("codex", "Stop", {"decision": "block"}),
    ("cursor", "stop", {"followup_message": "no"}),
    ("cursor", "preToolUse", {"permission": "deny"}),
    ("zcode", "Stop", {"decision": "block"}),
])
def test_a_block_is_answered_the_way_each_agent_reads_it(name, harness, expect):
    out, _, code = render(BUILT_IN[name]["output"], harness, Decision(action="block", reason="no"))
    answer = json.loads(out)
    assert code == 0 and all(answer.get(k) == v for k, v in expect.items() if k != "followup_message")
    if "followup_message" in expect:
        assert answer["followup_message"] == "no"


@pytest.mark.parametrize("harness", ["PreToolUse", "pre_tool_use", "Stop", "UserPromptSubmit"])
def test_grok_refuses_with_exit_2_whatever_the_event_is_called(harness):
    out, err, code = render(BUILT_IN["grok"]["output"], harness, Decision(action="block", reason="no"))
    assert code == 2 and err.strip() == "no" and json.loads(out)["decision"] == "deny"


def test_gemini_blocks_with_exit_2():
    out, err, code = render(BUILT_IN["gemini"]["output"], "BeforeTool", Decision(action="block", reason="no"))
    assert code == 2 and err.strip() == "no"


@pytest.mark.parametrize("name", EXTENSION_KIND)
def test_extension_agents_get_one_file_of_guards(name):
    adapter = BUILT_IN[name]
    text = extension_text(adapter, ["C:/Program Files/guard.exe"])
    assert text.splitlines()[0].startswith("// guard-hook:")
    assert json.dumps(["C:/Program Files/guard.exe"]) in text and f'"{name}"' in text
    assert ("session_stop" in text) == (name == "omp")


@pytest.mark.parametrize("name", EXTENSION_KIND)
def test_extension_add_and_remove_through_the_cli(name, monkeypatch):
    adapter = BUILT_IN[name]
    path = config_path(adapter)
    result = CliRunner().invoke(app, ["agent", "add", name], input="y\n")
    assert result.exit_code == 0, result.output
    assert path.is_file() and installed(adapter)
    # limits are said before anything is written
    for limit in adapter.get("limits", []):
        assert limit.split(":")[0][:30] in " ".join(result.output.split())
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    agent_cmds.agent_remove_cmd(name=name)  # in the user's terminal (as the Claude Code adapter's own test does)
    assert not path.exists()


def test_a_file_guard_did_not_write_is_never_replaced():
    adapter = BUILT_IN["omp"]
    path = config_path(adapter)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("// the user's own extension\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["agent", "add", "omp"], input="y\n")
    assert result.exit_code == 1 and path.read_text(encoding="utf-8") == "// the user's own extension\n"


def test_list_shows_every_popular_agent(monkeypatch):
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    monkeypatch.setattr(cli.console, "width", 250, raising=False)
    listed = CliRunner().invoke(app, ["agent", "list"])
    for name in POPULAR:
        assert name in listed.output


def test_protection_says_only_what_each_agent_can_refuse():
    from guard.agent.adapter import protection
    assert "a stop with unapproved edits" in protection(BUILT_IN["claude-code"])
    for name in ("pi", "opencode", "antigravity"):
        text = protection(BUILT_IN[name])
        assert "edits before guard pre" in text and "a stop is not refused" in text, name


def test_doctor_shows_each_agents_protection_and_last_test(tmp_path):
    from guard.agent.adapter import test_record_path
    from guard.core.setup_health import setup_health
    (home() / ".omp").mkdir(parents=True, exist_ok=True)
    rows = [r for r in setup_health(tmp_path) if r["item"] == "Agent hooks"]
    assert any("Oh My Pi" in r["detail"] and r["fix"] == "guard agent add omp" for r in rows)

    path = config_path(BUILT_IN["omp"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(extension_text(BUILT_IN["omp"]), encoding="utf-8")  # exactly as this guard writes it
    row = next(r for r in setup_health(tmp_path) if r["item"] == "Agent hooks" and "Oh My Pi" in r["detail"])
    assert row["level"] == "ok" and "not tested yet" in row["detail"]

    test_record_path("omp").parent.mkdir(parents=True, exist_ok=True)
    test_record_path("omp").write_text(json.dumps({"at": "2026-09-29T01:00:00", "events": 0}), encoding="utf-8")
    row = next(r for r in setup_health(tmp_path) if r["item"] == "Agent hooks" and "Oh My Pi" in r["detail"])
    assert row["level"] == "warn" and row["fix"] == "guard agent fix omp"


def test_a_registered_adapter_can_never_install_a_file():
    record = {k: v for k, v in BUILT_IN["cursor"].items() if k != "protection_note"}
    for key, value in (("kind", "extension"), ("install", "~/work/repo/evil.js"), ("source", "pi")):
        assert any(e.startswith(f"{key}:") for e in validate_adapter(dict(record, name="acme", **{key: value})))


def test_zcode_switched_off_by_the_user_is_not_protected():
    adapter = BUILT_IN["zcode"]
    path = config_path(adapter)
    path.parent.mkdir(parents=True, exist_ok=True)
    written = with_guard({"hooks": {"enabled": False}}, adapter)
    path.write_text(json.dumps(written), encoding="utf-8")
    assert written["hooks"]["enabled"] is False and not installed(adapter)
    path.write_text(json.dumps(with_guard({}, adapter)), encoding="utf-8")
    assert installed(adapter)


def test_a_changed_extension_file_is_shown_before_it_is_deleted(monkeypatch, capsys):
    import typer

    import guard.cli as cli

    import guard.commands.agent as agent_cmds
    adapter = BUILT_IN["pi"]
    path = config_path(adapter)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(extension_text(adapter) + "// the user's own line\n", encoding="utf-8")
    assert not installed(adapter)  # not this guard's file as written: not counted as installed
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: False)
    with pytest.raises(typer.Exit):
        agent_cmds.agent_remove_cmd(name="pi")
    assert path.exists()  # declined after seeing the difference: kept
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    agent_cmds.agent_remove_cmd(name="pi")
    assert not path.exists()


def test_omp_refuses_a_stop_once_then_lets_it_through():
    text = extension_text(BUILT_IN["omp"])
    assert "loop: refusedStop" in text and "refusedStop = true" in text


def test_list_skips_test_records_and_doctor_warns_when_no_edit_was_refused(tmp_path, monkeypatch):
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    from guard.agent.adapter import adapters_dir, test_record_path
    from guard.core.setup_health import setup_health
    monkeypatch.setattr(cli.console, "width", 250, raising=False)
    adapters_dir().mkdir(parents=True, exist_ok=True)
    test_record_path("claude-code").write_text(json.dumps({"at": "2026-09-29", "events": 3, "blocked_edit": False}),
                                               encoding="utf-8")
    listed = CliRunner().invoke(app, ["agent", "list"])
    assert "claude-code.test" not in listed.output and "broken record" not in listed.output
    settings = home() / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps(with_guard({}, BUILT_IN["claude-code"])), encoding="utf-8")
    row = next(r for r in setup_health(tmp_path) if r["item"] == "Agent hooks" and "Claude Code" in r["detail"])
    assert row["level"] == "warn" and "refused no edit" in row["detail"]


def test_guards_file_for_another_guard_is_stale_offered_again_and_removable(monkeypatch, tmp_path):
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    from guard.agent.adapter import extension_state
    from guard.core.setup_health import setup_health
    adapter = BUILT_IN["omp"]
    path = config_path(adapter)
    path.parent.mkdir(parents=True, exist_ok=True)
    for older in (extension_text(adapter, ["D:/old/guard.exe"]),  # guard moved
                  extension_text(adapter).replace("refusedStop", "refused")):  # another guard version
        path.write_text(older, encoding="utf-8")
        assert extension_state(adapter) == "stale" and not installed(adapter)  # it may call nothing: not counted
    row = next(r for r in setup_health(tmp_path) if r["item"] == "Agent hooks" and "Oh My Pi" in r["detail"])
    assert row["level"] == "warn" and "not this guard's" in row["detail"] and row["fix"] == "guard agent add omp"
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    assert CliRunner().invoke(app, ["agent", "add", "omp"], input="y\n").exit_code == 0  # rewritten
    assert extension_state(adapter) == "current"
    path.write_text(extension_text(adapter, ["D:/old/guard.exe"]), encoding="utf-8")
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    agent_cmds.agent_remove_cmd(name="omp")  # guard's own file: the difference is shown, then it goes
    assert not path.exists()
    path.write_bytes(b"\xff\xfe not text")
    assert extension_state(adapter) == "foreign"  # never a crash


def test_a_first_add_into_switched_off_hooks_says_so(monkeypatch):
    adapter = BUILT_IN["zcode"]
    path = config_path(adapter)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"hooks": {"enabled": False}}), encoding="utf-8")
    result = CliRunner().invoke(app, ["agent", "add", "zcode"], input="y\n")
    assert result.exit_code == 0 and "switched off" in result.output and "now calls guard" not in result.output


def test_doctor_skips_a_broken_registered_record(tmp_path):
    from guard.agent.adapter import adapters_dir
    from guard.core.setup_health import setup_health
    adapters_dir().mkdir(parents=True, exist_ok=True)
    (home() / ".acme").mkdir(parents=True, exist_ok=True)
    (adapters_dir() / "acme.json").write_text(json.dumps({"name": "acme", "hooks": [{}], "detect": "~/.acme"}),
                                              encoding="utf-8")
    assert isinstance(setup_health(tmp_path), list)  # no KeyError


def test_grok_snake_case_events_count_in_agent_test(monkeypatch):
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    from guard.core.repo_setup import guard_home
    assert CliRunner().invoke(app, ["agent", "test", "grok"]).exit_code == 0
    with open(guard_home() / "agent-events.log", "a", encoding="utf-8") as f:
        f.write("9999-12-31T00:00:00+00:00 grok EVENT pre_tool_use tool=Write -> block\n")
    monkeypatch.setattr(cli.console, "width", 250, raising=False)
    result = CliRunner().invoke(app, ["agent", "test", "grok", "--report"])
    assert "Guard answered the edit with a block" in result.output


DRIVER = r"""
import { pathToFileURL } from "node:url";
const [dir] = process.argv.slice(2);
const out = {};
for (const name of ["pi", "omp"]) {
  const handlers = {}; const notes = [];
  (await import(pathToFileURL(`${dir}/${name}.mjs`).href)).default({ on: (e, fn) => { handlers[e] = fn; } });
  const ctx = { cwd: dir, ui: { notify: (m) => notes.push(m) } };
  const edit = await handlers.tool_call({ toolName: "write", input: { path: "a.txt" }, toolCallId: "t" }, ctx);
  const read = await handlers.tool_call({ toolName: "read", input: { path: "a.txt" }, toolCallId: "r" }, ctx);
  const stop = handlers.session_stop ? await handlers.session_stop({}, ctx) : null;
  out[name] = { edit, read: read ?? null, stop: stop ?? null, notes };
}
const hooks = await (await import(pathToFileURL(`${dir}/opencode.mjs`).href)).GuardHook({ directory: dir });
let edit = "allowed";
try { await hooks["tool.execute.before"]({ tool: "write", callID: "c" }, { args: { path: "a.txt" } }); }
catch (e) { edit = e.message; }
let read = "allowed";
try { await hooks["tool.execute.before"]({ tool: "read", callID: "r" }, { args: { path: "a.txt" } }); }
catch (e) { read = e.message; }
const result = { output: "done" };
await hooks["tool.execute.after"]({ tool: "bash", callID: "d" }, result);
out.opencode = { edit, read, after: result.output };
console.log(JSON.stringify(out));
"""


def test_an_extension_refuses_an_edit_when_guard_cannot_answer_and_never_holds_a_stop(tmp_path):
    import shutil
    import subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    missing = [str(tmp_path / "no-such-guard.exe")]  # guard uninstalled, extension left behind
    for name in EXTENSION_KIND:
        (tmp_path / f"{name}.mjs").write_text(extension_text(BUILT_IN[name], missing), encoding="utf-8")
    (tmp_path / "driver.mjs").write_text(DRIVER, encoding="utf-8")
    run = subprocess.run([node, str(tmp_path / "driver.mjs"), str(tmp_path)], capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    out = json.loads(run.stdout)
    for name in ("pi", "omp"):
        assert out[name]["edit"]["block"] is True and "guard doctor" in out[name]["edit"]["reason"]
        assert out[name]["stop"] is None and out[name]["read"] is None  # a stop and a read go on
    assert any("guard doctor" in n for n in out["omp"]["notes"])  # ...with a warning
    assert "guard doctor" in out["opencode"]["edit"] and "guard doctor" in out["opencode"]["after"]
    assert out["opencode"]["after"].startswith("done") and out["opencode"]["read"] == "allowed"


def test_antigravity_notifies_on_stderr_without_refusing():
    decision = Decision(action="notify", reason="edits outside the scope")
    stdout, stderr, code = render(BUILT_IN["antigravity"]["output"], "PostToolUse", decision)
    assert stdout == "" and stderr.strip() == "edits outside the scope" and code == 0


def test_doctor_and_install_find_an_agent_by_its_config_when_it_has_no_detect_folder(monkeypatch):
    from guard.core.repo_setup import _agent_present
    assert not _agent_present({"config": "~/.acme.json"})  # home itself is not the agent's folder
    (home() / ".acme.json").write_text("{}", encoding="utf-8")
    assert _agent_present({"config": "~/.acme.json"})
    monkeypatch.setenv("APPDATA", str(home() / "AppData" / "Roaming"))
    (home() / "AppData" / "Roaming" / "Acme").mkdir(parents=True)
    assert _agent_present({"config": "~/.x/hooks.json", "detect": "%APPDATA%/Acme"})


def test_doctor_reads_a_test_record_that_is_not_an_object_as_not_tested(tmp_path):
    from guard.agent.adapter import test_record_path
    from guard.core.setup_health import setup_health
    test_record_path("claude-code").parent.mkdir(parents=True, exist_ok=True)
    test_record_path("claude-code").write_text("[]", encoding="utf-8")
    assert isinstance(setup_health(tmp_path), list)  # no AttributeError


def test_an_edited_record_with_defaults_that_are_not_an_object_is_not_installed():
    adapter = dict(BUILT_IN["cursor"], defaults=["version"])
    path = config_path(adapter)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(with_guard({}, BUILT_IN["cursor"], COMMAND)), encoding="utf-8")
    assert not installed(adapter)


def test_a_report_for_another_agent_than_the_running_test_reads_nothing():
    from guard.core.repo_setup import guard_home
    assert CliRunner().invoke(app, ["agent", "test", "grok"]).exit_code == 0
    result = CliRunner().invoke(app, ["agent", "test", "cursor", "--report"])
    assert result.exit_code == 1 and "No test of cursor is running" in result.output
    assert (guard_home() / "agent-test.json").exists()  # grok's test is still listening


def test_an_extension_path_holding_a_file_that_is_not_utf8_is_not_guards():
    from guard.agent.adapter import extension_is_guards, extension_path
    path = extension_path(BUILT_IN["pi"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\xff\xfe\x00 not text")
    assert not extension_is_guards(BUILT_IN["pi"])


@pytest.mark.parametrize("value", [None, 0, "true"])
def test_zcode_hooks_count_as_on_only_when_enabled_is_exactly_true(value):
    zcode = BUILT_IN["zcode"]
    path = config_path(zcode)
    path.parent.mkdir(parents=True, exist_ok=True)
    config = with_guard({}, zcode, COMMAND)
    config["hooks"]["enabled"] = value
    path.write_text(json.dumps(config), encoding="utf-8")
    assert not installed(zcode)


def test_an_extension_file_changed_while_the_diff_was_shown_is_left_alone(monkeypatch):
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    from guard.agent.adapter import extension_path
    path = extension_path(BUILT_IN["pi"])
    path.parent.mkdir(parents=True, exist_ok=True)

    def someone_writes(*a, **k):  # the user drops their own file there while the question is open
        path.write_text("their own extension", encoding="utf-8")
        return True
    monkeypatch.setattr(cli.typer, "confirm", someone_writes)
    result = CliRunner().invoke(app, ["agent", "add", "pi"])
    assert result.exit_code == 1 and path.read_text(encoding="utf-8") == "their own extension"


def test_a_guard_file_changed_before_removal_is_confirmed_is_not_deleted(monkeypatch):
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    from guard.agent.adapter import extension_path
    path = extension_path(BUILT_IN["pi"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(extension_text(BUILT_IN["pi"]), encoding="utf-8")

    def someone_edits(*a, **k):
        path.write_text(extension_text(BUILT_IN["pi"]) + "// their change\n", encoding="utf-8")
        return True
    monkeypatch.setattr(cli.typer, "confirm", someone_edits)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    cli_result = None
    try:
        agent_cmds.agent_remove_cmd(name="pi")
    except cli.typer.Exit as e:
        cli_result = e.exit_code
    assert cli_result == 1 and path.exists()


def test_zcode_switch_turned_on_by_guard_is_said_and_switched_back_on_remove(monkeypatch, capsys):
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    zcode = BUILT_IN["zcode"]
    path = config_path(zcode)
    path.parent.mkdir(parents=True, exist_ok=True)
    mine = {"type": "process", "command": "node my-audit.js"}
    path.write_text(json.dumps({"hooks": {"events": {"Stop": [mine]}}}), encoding="utf-8")  # no hooks.enabled
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    agent_cmds._install_adapter(zcode, "zcode")
    assert "hook(s) already there start running too" in capsys.readouterr().out
    assert json.loads(path.read_text(encoding="utf-8"))["hooks"]["enabled"] is True
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    agent_cmds.agent_remove_cmd(name="zcode")
    left = json.loads(path.read_text(encoding="utf-8"))
    assert "enabled" not in left["hooks"] and left["hooks"]["events"]["Stop"] == [mine]  # as before guard came


def test_a_zcode_switch_the_user_set_is_left_on_by_remove(monkeypatch):
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    zcode = BUILT_IN["zcode"]
    path = config_path(zcode)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"hooks": {"enabled": True, "events": {}}}), encoding="utf-8")
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    agent_cmds._install_adapter(zcode, "zcode")
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    # no record says guard switched it on, so remove asks: the user keeps it
    monkeypatch.setattr(cli.typer, "confirm", lambda text, **k: "Switch it off too" not in text)
    agent_cmds.agent_remove_cmd(name="zcode")
    assert json.loads(path.read_text(encoding="utf-8"))["hooks"]["enabled"] is True


def test_a_name_that_is_a_path_never_becomes_one():
    from guard.agent.adapter import AdapterError, test_record_path
    assert load_adapter("../outside") is None
    with pytest.raises(AdapterError):
        test_record_path("../outside")
    result = CliRunner().invoke(app, ["agent", "test", "../outside", "--report"])
    assert result.exit_code == 1 and not (home() / ".guard" / "outside.test.json").exists()


def test_presence_without_a_detect_folder_needs_the_config_file():
    from guard.core.repo_setup import _agent_present
    (home() / ".config").mkdir(exist_ok=True)
    assert not _agent_present({"config": "~/.config/acme.json"})  # a shared folder proves nothing
    (home() / ".config" / "acme.json").write_text("{}", encoding="utf-8")
    assert _agent_present({"config": "~/.config/acme.json"})


def test_an_empty_file_that_appeared_after_the_diff_is_not_replaced(monkeypatch):
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    from guard.agent.adapter import extension_path
    path = extension_path(BUILT_IN["pi"])
    path.parent.mkdir(parents=True, exist_ok=True)

    def someone_creates(*a, **k):
        path.write_bytes(b"")
        return True
    monkeypatch.setattr(cli.typer, "confirm", someone_creates)
    assert CliRunner().invoke(app, ["agent", "add", "pi"]).exit_code == 1
    assert path.read_bytes() == b""


def test_antigravity_tells_a_stop_it_cannot_refuse():
    stdout, stderr, code = render(BUILT_IN["antigravity"]["output"], "Stop", Decision(action="block", reason="unapproved edits"))
    assert stderr.strip() == "unapproved edits" and code == 0


def test_doctor_says_a_cli_review_without_an_agent_chosen(tmp_path, monkeypatch):
    from guard.core import config as config_mod
    from guard.core.config import LLMConfig, LLMProtocol
    from guard.core.setup_health import setup_health
    cfg = config_mod.load_global_config()
    cfg.llm = LLMConfig(protocol=LLMProtocol.CLI, cli_agent="", api_key="left-over")
    monkeypatch.setattr(config_mod, "load_global_config", lambda: cfg)
    rows = [r for r in setup_health(tmp_path) if "LLM" in str(r)]
    assert any("none is chosen" in str(r) for r in rows)


def test_doctor_trusts_the_last_test_for_hooks_added_by_hand_to_a_config_that_is_not_json(tmp_path):
    from guard.agent.adapter import adapters_dir, config_fingerprint, test_record_path
    from guard.core.setup_health import setup_health
    (home() / ".acme").mkdir(parents=True, exist_ok=True)
    (home() / ".acme" / "config.toml").write_text("[hooks]\n", encoding="utf-8")
    adapter = {k: v for k, v in BUILT_IN["cursor"].items() if k not in ("protection_note", "limits")}
    adapter.update(name="acme", title="Acme", config="~/.acme/config.toml", detect="~/.acme")
    adapters_dir().mkdir(parents=True, exist_ok=True)
    (adapters_dir() / "acme.json").write_text(json.dumps(adapter), encoding="utf-8")
    rows = [str(r) for r in setup_health(tmp_path) if "Acme" in str(r)]
    assert any("added by hand" in r and "no test" in r for r in rows)
    test_record_path("acme").write_text(json.dumps({"at": "2026-09-29T00:00:00", "events": 3, "config": config_fingerprint(home() / ".acme" / "config.toml")}),
                                        encoding="utf-8")
    rows = [str(r) for r in setup_health(tmp_path) if "Acme" in str(r)]
    assert any("hooks added by hand; the last test" in r for r in rows)


def test_doctor_never_says_an_edit_was_refused_by_an_agent_that_cannot_refuse_one(tmp_path):
    from guard.agent.adapter import adapters_dir, test_record_path
    from guard.core.setup_health import setup_health
    adapter = {k: v for k, v in BUILT_IN["cursor"].items() if k not in ("protection_note", "limits")}
    adapter.update(name="acme", title="Acme", config="~/.acme/hooks.json", detect="~/.acme", can_block=[])
    adapters_dir().mkdir(parents=True, exist_ok=True)
    (adapters_dir() / "acme.json").write_text(json.dumps(adapter), encoding="utf-8")
    path = config_path(adapter)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(with_guard({}, adapter, COMMAND)), encoding="utf-8")
    test_record_path("acme").write_text(json.dumps({"at": "2026-09-29", "events": 2, "blocked_edit": False}), encoding="utf-8")
    rows = [str(r) for r in setup_health(tmp_path) if "Acme" in str(r)]
    assert rows and not any("an edit was refused" in r for r in rows) and any("events arrived" in r for r in rows)


def test_a_switch_record_from_an_earlier_add_stays_while_that_switch_is_on(monkeypatch):
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    from guard.agent.adapter import switched_path
    zcode = BUILT_IN["zcode"]
    path = config_path(zcode)
    path.parent.mkdir(parents=True, exist_ok=True)
    switched_path("zcode").parent.mkdir(parents=True, exist_ok=True)
    switched_path("zcode").write_text('["hooks.enabled"]', encoding="utf-8")  # guard switched it on at an earlier add
    # guard's hooks were taken out by hand, the switch left on: a new add must not forget who turned it on
    path.write_text(json.dumps({"hooks": {"enabled": True, "events": {}}}), encoding="utf-8")
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    agent_cmds._install_adapter(zcode, "zcode")
    assert json.loads(switched_path("zcode").read_text(encoding="utf-8")) == ["hooks.enabled"]
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    agent_cmds.agent_remove_cmd(name="zcode")
    assert "enabled" not in json.loads(path.read_text(encoding="utf-8")).get("hooks", {})


def test_a_switch_record_whose_switch_is_off_is_dropped_on_add(monkeypatch):
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    from guard.agent.adapter import switched_path
    zcode = BUILT_IN["zcode"]
    path = config_path(zcode)
    path.parent.mkdir(parents=True, exist_ok=True)
    switched_path("zcode").parent.mkdir(parents=True, exist_ok=True)
    switched_path("zcode").write_text('["hooks.enabled"]', encoding="utf-8")
    path.write_text(json.dumps({"hooks": {"enabled": False, "events": {}}}), encoding="utf-8")  # the user turned it off
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    agent_cmds._install_adapter(zcode, "zcode")
    assert not switched_path("zcode").exists()

def test_a_config_write_that_fails_leaves_no_switch_record(monkeypatch):
    import typer
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    from guard.agent.adapter import switched_path
    zcode = BUILT_IN["zcode"]
    path = config_path(zcode)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"hooks": {"events": {}}}), encoding="utf-8")

    def fail(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr("guard.agent.adapter.write_config", fail)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    with pytest.raises(typer.Exit):
        agent_cmds._install_adapter(zcode, "zcode")
    assert not switched_path("zcode").exists()


def test_a_switch_the_user_set_to_null_is_theirs_and_never_recorded(monkeypatch):
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    from guard.agent.adapter import switched_on
    zcode = BUILT_IN["zcode"]
    assert switched_on(zcode, {"hooks": {"enabled": None}}) == [] and switched_on(zcode, {"hooks": {}}) == ["hooks.enabled"]
    assert with_guard({"hooks": {"enabled": None}}, zcode, COMMAND)["hooks"]["enabled"] is None


def test_a_switch_record_naming_another_setting_is_ignored_by_remove(monkeypatch):
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    from guard.agent.adapter import switched_path
    zcode = BUILT_IN["zcode"]
    path = config_path(zcode)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(with_guard({"hooks": {"enabled": True}}, zcode, COMMAND), custom={"on": True})),
                    encoding="utf-8")
    switched_path("zcode").parent.mkdir(parents=True, exist_ok=True)
    switched_path("zcode").write_text('["custom.on"]', encoding="utf-8")  # an edited record
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    agent_cmds.agent_remove_cmd(name="zcode")
    assert json.loads(path.read_text(encoding="utf-8"))["custom"] == {"on": True}


def test_a_parent_the_user_set_to_null_is_never_replaced():
    from guard.agent.adapter import AdapterError
    with pytest.raises(AdapterError, match="hooks"):
        with_guard({"hooks": None}, BUILT_IN["zcode"], COMMAND)  # ZCode keeps its events under hooks.events
    with pytest.raises(AdapterError, match="hooks"):
        with_guard({"hooks": None}, BUILT_IN["claude-code"], COMMAND)  # the hooks object itself, held as null


@pytest.mark.parametrize("record", ["not json", '{"hooks.enabled": true}', '[{"k": 1}]'])
def test_remove_stops_when_the_switch_record_cannot_be_read(monkeypatch, record):
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    from guard.agent.adapter import switched_path
    zcode = BUILT_IN["zcode"]
    path = config_path(zcode)
    path.parent.mkdir(parents=True, exist_ok=True)
    installed_config = with_guard({"hooks": {"events": {}}}, zcode, COMMAND)
    path.write_text(json.dumps(installed_config), encoding="utf-8")
    switched_path("zcode").parent.mkdir(parents=True, exist_ok=True)
    switched_path("zcode").write_text(record, encoding="utf-8")
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    with pytest.raises(cli.typer.Exit):
        agent_cmds.agent_remove_cmd(name="zcode")
    assert json.loads(path.read_text(encoding="utf-8")) == installed_config and switched_path("zcode").exists()


def test_hand_added_hooks_that_refused_no_edit_are_not_healthy(tmp_path):
    from guard.agent.adapter import adapters_dir, config_fingerprint, test_record_path
    from guard.core.setup_health import setup_health
    (home() / ".acme").mkdir(parents=True, exist_ok=True)
    (home() / ".acme" / "config.toml").write_text("[hooks]\n", encoding="utf-8")
    adapter = {k: v for k, v in BUILT_IN["cursor"].items() if k not in ("protection_note", "limits")}
    adapter.update(name="acme", title="Acme", config="~/.acme/config.toml", detect="~/.acme")
    adapters_dir().mkdir(parents=True, exist_ok=True)
    (adapters_dir() / "acme.json").write_text(json.dumps(adapter), encoding="utf-8")
    test_record_path("acme").write_text(json.dumps({"at": "2026-09-29", "events": 3, "blocked_edit": False, "config": config_fingerprint(home() / ".acme" / "config.toml")}),
                                        encoding="utf-8")
    rows = [str(r) for r in setup_health(tmp_path) if "Acme" in str(r)]
    assert any("refused no edit" in r for r in rows) and not any("saw guard's events" in r for r in rows)


def test_hand_added_hooks_are_tested_again_after_their_config_changed(tmp_path):
    from guard.agent.adapter import adapters_dir, config_fingerprint, test_record_path
    from guard.core.setup_health import setup_health
    conf = home() / ".acme" / "config.toml"
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text("[hooks]\n", encoding="utf-8")
    adapter = {k: v for k, v in BUILT_IN["cursor"].items() if k not in ("protection_note", "limits")}
    adapter.update(name="acme", title="Acme", config="~/.acme/config.toml", detect="~/.acme")
    adapters_dir().mkdir(parents=True, exist_ok=True)
    (adapters_dir() / "acme.json").write_text(json.dumps(adapter), encoding="utf-8")
    test_record_path("acme").write_text(json.dumps({"at": "2026-09-29", "events": 3, "blocked_edit": True,
                                                    "config": config_fingerprint(conf)}), encoding="utf-8")
    conf.write_text("# the user took the hooks out\n", encoding="utf-8")
    rows = [str(r) for r in setup_health(tmp_path) if "Acme" in str(r)]
    assert any("changed since the last test" in r for r in rows)


def test_remove_of_an_install_older_than_the_switch_record_asks_about_the_switch(monkeypatch):
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    from guard.agent.adapter import switched_path
    zcode = BUILT_IN["zcode"]
    path = config_path(zcode)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(with_guard({"hooks": {"events": {}}}, zcode, COMMAND)), encoding="utf-8")  # no record
    assert not switched_path("zcode").exists()
    asked = []
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.typer, "confirm", lambda text, **k: asked.append(text) or True)
    agent_cmds.agent_remove_cmd(name="zcode")
    assert any("Switch it off too" in q for q in asked)
    assert "enabled" not in json.loads(path.read_text(encoding="utf-8")).get("hooks", {})


def test_a_config_fingerprint_names_its_file_and_an_unreadable_one_has_none(tmp_path):
    from guard.agent.adapter import config_fingerprint
    (tmp_path / "a.toml").write_text("same", encoding="utf-8")
    (tmp_path / "b.toml").write_text("same", encoding="utf-8")
    assert config_fingerprint(tmp_path / "a.toml") != config_fingerprint(tmp_path / "b.toml")
    assert config_fingerprint(tmp_path / "gone.toml").endswith(":missing")
    assert config_fingerprint(tmp_path) is None  # a folder cannot be read as a file: no evidence


def test_a_hand_added_hook_test_older_than_the_fingerprint_is_unverified_not_changed(tmp_path):
    from guard.agent.adapter import adapters_dir, test_record_path
    from guard.core.setup_health import setup_health
    conf = home() / ".acme" / "config.toml"
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text("[hooks]\n", encoding="utf-8")
    adapter = {k: v for k, v in BUILT_IN["cursor"].items() if k not in ("protection_note", "limits")}
    adapter.update(name="acme", title="Acme", config="~/.acme/config.toml", detect="~/.acme")
    adapters_dir().mkdir(parents=True, exist_ok=True)
    (adapters_dir() / "acme.json").write_text(json.dumps(adapter), encoding="utf-8")
    test_record_path("acme").write_text(json.dumps({"at": "2026-09-28", "events": 3, "blocked_edit": True}),
                                        encoding="utf-8")  # written before tests kept the config's fingerprint
    rows = [str(r) for r in setup_health(tmp_path) if "Acme" in str(r)]
    assert any("cannot tell whether" in r for r in rows) and not any("changed since" in r for r in rows)


def test_remove_says_so_when_the_switch_record_cannot_be_deleted(monkeypatch, capsys):
    import typer
    import guard.cli as cli
    import guard.commands.agent as agent_cmds
    from guard.agent import adapter as adapter_mod
    from guard.agent.adapter import switched_path
    zcode = BUILT_IN["zcode"]
    path = config_path(zcode)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(with_guard({"hooks": {"events": {}}}, zcode, COMMAND)), encoding="utf-8")
    switched_path("zcode").parent.mkdir(parents=True, exist_ok=True)
    switched_path("zcode").write_text('["hooks.enabled"]', encoding="utf-8")
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    real_unlink = Path.unlink

    def locked(self, *a, **k):
        if self.name == "zcode.switched.json":
            raise PermissionError("in use")
        return real_unlink(self, *a, **k)
    monkeypatch.setattr(Path, "unlink", locked)
    with pytest.raises(typer.Exit):
        agent_cmds.agent_remove_cmd(name="zcode")
    assert "Delete it yourself before adding guard again" in " ".join(capsys.readouterr().out.split())
