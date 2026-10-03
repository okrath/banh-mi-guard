"""omp as guard's LLM, and `guard agent add` offering the agent it just added as guard's LLM."""

import json
import subprocess

import pytest

from guard.core import cli_llm

OMP_ANSWER = "\n".join([
    '{"type": "progress"}',
    json.dumps({"messages": [{"role": "user", "content": [{"type": "text", "text": "q"}]},
                             {"role": "assistant", "content": [{"type": "text", "text": " the omp answer "}]}]}),
])


@pytest.fixture
def omp(monkeypatch):
    calls = []

    def fake(cmd, text, cwd, timeout, env):
        calls.append({"cmd": cmd, "input": text, "cwd": cwd})
        if cmd[1:3] == ["models", "--json"]:
            return subprocess.CompletedProcess(cmd, 0, json.dumps({"models": [
                {"selector": "cta/group:cta-worker", "kind": "chat"}, {"selector": "x/embed", "kind": "embedding"}]}), "")
        return subprocess.CompletedProcess(cmd, 0, OMP_ANSWER, "")

    monkeypatch.setattr(cli_llm, "_run", fake)
    monkeypatch.setattr(cli_llm.shutil, "which", lambda b: f"C:/bin/{b}.exe")
    return calls


def test_omp_answers_with_no_tools_and_its_rules_ahead_of_the_marked_data(omp):
    assert cli_llm.call("omp", "review this", system_prompt="be strict", model="cta/group:cta-worker") == "the omp answer"
    cmd = omp[0]["cmd"]
    assert cmd[:6] == ["C:/bin/omp.exe", "-p", "--no-tools", "--no-session", "--mode", "json"]
    assert cmd[-2:] == ["--model", "cta/group:cta-worker"] and "be strict" not in " ".join(cmd)
    text = omp[0]["input"]  # omp ignores a system prompt in print mode: the rules lead the prompt
    assert text.startswith("be strict") and text.index("be strict") < text.index("<untrusted_review_input>")
    assert text.endswith("<untrusted_review_input>\nreview this\n</untrusted_review_input>")


def test_omp_without_an_assistant_answer_is_an_llm_failure(omp, monkeypatch):
    monkeypatch.setattr(cli_llm, "_run", lambda cmd, text, cwd, timeout, env: subprocess.CompletedProcess(cmd, 0, "Working...", ""))
    with pytest.raises(cli_llm.CLILLMError):
        cli_llm.call("omp", "q")


def test_omp_is_ready_when_it_lists_chat_models(omp, monkeypatch):
    ready, msg, models = cli_llm.probe("omp")
    assert ready and models == ["cta/group:cta-worker"]
    monkeypatch.setattr(cli_llm, "_run", lambda cmd, text, cwd, timeout, env: subprocess.CompletedProcess(cmd, 0, '{"models": []}', ""))
    ready, msg, _ = cli_llm.probe("omp")
    assert not ready and "omp login" in msg


def test_agent_add_offers_the_agent_as_guards_llm_in_a_terminal(monkeypatch):
    from guard.commands import agent as agent_cmd
    from guard.core import config
    from guard.core.config import GuardConfig
    asked, wizard = [], []
    monkeypatch.setattr(cli_llm.shutil, "which", lambda b: f"C:/bin/{b}.exe")
    monkeypatch.setattr(config, "load_global_config", lambda: GuardConfig())
    monkeypatch.setattr(config, "_cli_wizard", lambda cfg, found, local, repo_path: wizard.append(found))
    monkeypatch.setattr("rich.prompt.Confirm.ask", lambda q, default=True: asked.append(q) or True)
    monkeypatch.setattr(agent_cmd.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(agent_cmd.sys.stdout, "isatty", lambda: True, raising=False)
    agent_cmd._offer_agent_as_llm("claude-code")
    assert wizard == [["claude"]] and "claude CLI" in asked[0]
    agent_cmd._offer_agent_as_llm("cursor")  # no CLI guard can use as its LLM: nothing asked
    assert len(asked) == 1


def test_agent_add_outside_a_terminal_only_says_how(monkeypatch, capsys):
    from guard.commands import agent as agent_cmd
    from guard.core import config
    from guard.core.config import GuardConfig
    monkeypatch.setattr(cli_llm.shutil, "which", lambda b: f"C:/bin/{b}.exe")
    monkeypatch.setattr(config, "load_global_config", lambda: GuardConfig())
    monkeypatch.setattr(config, "_cli_wizard", lambda *a, **k: pytest.fail("no wizard without a terminal"))
    monkeypatch.setattr(agent_cmd.sys.stdin, "isatty", lambda: False, raising=False)
    agent_cmd._offer_agent_as_llm("omp")
    assert "guard config llm" in capsys.readouterr().out


def test_omp_answer_skips_events_and_stray_text_after_the_conversation():
    out = OMP_ANSWER + '\n{"type": "agent_end"}\nWorking... done'
    assert cli_llm._omp_answer(out) == "the omp answer"
