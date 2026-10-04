"""Alibaba OCR answered by the agent CLI: requests rendered for the agent, replies read back as tool calls."""

import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from guard.core import ocr_bridge
from guard.core.ocr_bridge import AgentBridge, complete, parse, render

TOOLS = [{"type": "function", "function": {"name": "file_read", "description": "Read a file.",
                                             "parameters": {"type": "object", "properties": {"file_path": {"type": "string"}}}}},
         {"type": "function", "function": {"name": "task_done", "description": "Finish.",
                                             "parameters": {"type": "object", "properties": {"state": {"type": "string"}}}}}]
BODY = {"model": "m", "tools": TOOLS, "messages": [
    {"role": "system", "content": "Review the diff."},
    {"role": "user", "content": "diff: +x = 1"},
    {"role": "assistant", "content": None, "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": "file_read", "arguments": "{\"file_path\": \"a.py\"}"}}]},
    {"role": "tool", "tool_call_id": "c1", "content": "x = 1"},
]}


def test_render_keeps_the_programs_instructions_apart_from_the_conversation():
    system, conversation = render(BODY)
    assert "Review the diff." in system and "file_read" in system and "task_done" in system
    assert "Review the diff." not in conversation  # repository text never sits with the rules
    assert "[assistant called tool file_read with {\"file_path\": \"a.py\"}]" in conversation
    assert "[tool result]\nx = 1" in conversation


def test_parse_reads_one_tool_call_or_a_final_answer():
    msg = parse('```json\n{"tool": "file_read", "arguments": {"file_path": "b.py"}}\n```', TOOLS)
    call = msg["tool_calls"][0]
    assert call["function"]["name"] == "file_read" and json.loads(call["function"]["arguments"]) == {"file_path": "b.py"}
    assert parse('{"final": "looks fine"}', TOOLS) == {"role": "assistant", "content": "looks fine"}
    # a model that keeps talking after its answer (seen live with omp's default model)
    rambling = '{"tool": "file_read", "arguments": {"file_path": "c.py"}}` Wait! Look at {"tool": "task_done"}'
    assert json.loads(parse(rambling, TOOLS)["tool_calls"][0]["function"]["arguments"]) == {"file_path": "c.py"}
    assert parse('Sure: {not json} then {"final": "ok"}', TOOLS)["content"] == "ok"
    for bad in ("no json here", '{"tool": "shell", "arguments": {}}', '{"tool": "file_read", "arguments": []}', '{"x": 1}'):
        with pytest.raises(ValueError):
            parse(bad, TOOLS)


def test_complete_is_one_agent_call_and_answers_in_the_openai_shape():
    asked = []

    def ask(system, conversation):
        asked.append(conversation)
        return '{"tool": "task_done", "arguments": {"state": "done"}}'

    out = complete(BODY, ask)
    assert len(asked) == 1
    assert out["object"] == "chat.completion" and out["choices"][0]["finish_reason"] == "tool_calls"
    assert out["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "task_done"
    for bad in ("not json", '{"tool": ["file_read"], "arguments": {}}', '{"tool": {"x": 1}}'):
        with pytest.raises(ValueError):
            complete(BODY, lambda s, c, bad=bad: bad)


def _post(url, token, body):
    req = urllib.request.Request(f"{url}/v1/chat/completions", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_the_bridge_needs_its_token_and_points_a_throwaway_ocr_config_at_itself(monkeypatch):
    monkeypatch.setattr(AgentBridge, "ask", lambda self, s, c: '{"final": "ok"}')
    with AgentBridge("claude", model="sonnet") as bridge:
        assert bridge.url.startswith("http://127.0.0.1:")
        assert _post(bridge.url, None, BODY)[0] == 401
        status, out = _post(bridge.url, bridge.token, BODY)
        assert status == 200 and out["choices"][0]["message"]["content"] == "ok"
        assert _post(bridge.url, bridge.token, None)[0] == 502  # JSON null: an error reply, never a crash
        assert _post(bridge.url, bridge.token, {"messages": [None]})[0] == 502
        assert _post(bridge.url, bridge.token, {"messages": [], "tools": [None]})[0] == 502
        env = bridge.env({"HOME": "/real/home", "PATH": "p"})
        home = Path(env["HOME"])
        assert env["USERPROFILE"] == env["HOME"] != "/real/home" and env["PATH"] == "p"
        config = json.loads((home / ".opencodereview" / "config.json").read_text(encoding="utf-8"))
        provider = config["custom_providers"][config["provider"]]
        assert provider["url"] == f"{bridge.url}/v1" and provider["api_key"] == bridge.token
        assert provider["protocol"] == "openai" and provider["model"] == "sonnet"
    assert not home.exists()  # the throwaway config goes with the review


def test_an_agent_failure_is_an_error_reply_with_the_reason(monkeypatch):
    from guard.core import cli_llm

    def fail(self, s, c):
        raise cli_llm.CLILLMError("claude exited with 1: not signed in")

    monkeypatch.setattr(AgentBridge, "ask", fail)
    with AgentBridge("claude") as bridge:
        status, out = _post(bridge.url, bridge.token, BODY)
    assert status == 502 and "not signed in" in out["error"]["message"]
    assert bridge.errors == ["claude exited with 1: not signed in"]


def test_post_runs_ocr_through_the_agent_and_names_the_path(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from guard import task_flow
    seen = {}

    def fake_review(repo, env_for=None, **kw):
        seen["env"] = env_for({"HOME": "/real"})
        seen["concurrency"] = kw["concurrency"]
        return "complete: 1 finding(s)", []

    monkeypatch.setattr(task_flow, "run_ocr_review", fake_review)
    config = SimpleNamespace(llm=SimpleNamespace(cli_agent="codex", model="", timeout=60.0))
    status, found = task_flow._ocr_through_agent(tmp_path, config, {"concurrency": 0})
    assert status == "complete: 1 finding(s); answered by the codex CLI (tool calls written as text)"
    assert seen["env"]["HOME"] != "/real" and seen["concurrency"] == task_flow.AGENT_OCR_CONCURRENCY
    task_flow._ocr_through_agent(tmp_path, config, {"concurrency": 8})  # OCR's own setting is capped for the agent
    assert seen["concurrency"] == task_flow.AGENT_OCR_CONCURRENCY


def test_a_failed_setup_closes_the_listener(monkeypatch):
    import tempfile as tf

    def broken(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(tf, "TemporaryDirectory", broken)
    bridge = AgentBridge("claude")
    with pytest.raises(OSError):
        bridge.__enter__()
    assert bridge._thread is None and bridge._server.socket.fileno() == -1  # closed, never served



def test_a_failed_agent_call_is_named_even_when_ocr_completes(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from guard import task_flow

    def review_with_a_failed_call(repo, env_for=None, **kw):
        env_for({})
        task_flow_bridge[0].errors.append("codex exited with 1: rate limited")
        return "complete: 0 finding(s)", []

    task_flow_bridge = []
    from guard.core import ocr_bridge as ob

    class Spy(ob.AgentBridge):
        def __enter__(self):
            task_flow_bridge.append(self)
            return super().__enter__()

    monkeypatch.setattr(ob, "AgentBridge", Spy)
    monkeypatch.setattr(task_flow, "run_ocr_review", review_with_a_failed_call)
    config = SimpleNamespace(llm=SimpleNamespace(cli_agent="codex", model="", timeout=60.0))
    status, _ = task_flow._ocr_through_agent(tmp_path, config, {"concurrency": 0})
    # the fallback (here without a base commit) cannot run either: both reasons are named
    assert status.startswith("did not run: the delegation mode needs the base commit")
    assert "did not run: 1 codex CLI call(s) failed, the last said: codex exited with 1: rate limited" in status
    assert [v.rule_id for v in _] == ["OCR-RUN"]  # never counted as a complete review


def test_closing_the_bridge_waits_for_an_agent_call_in_flight(monkeypatch):
    import threading
    import time as t

    finished = []

    def slow(self, s, c):
        t.sleep(1.5)
        finished.append(True)
        return '{"final": "late"}'

    monkeypatch.setattr(AgentBridge, "ask", slow)
    with AgentBridge("claude") as bridge:
        caller = threading.Thread(target=lambda: _post(bridge.url, bridge.token, BODY))
        caller.start()
        t.sleep(0.3)  # the request is in the agent call when the review ends
    assert finished == [True]  # the call ended before the bridge was gone
    caller.join(5)
