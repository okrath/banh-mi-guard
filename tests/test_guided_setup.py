"""
`guard setup` (run by install and update) does what is missing, in order, asking in a terminal;
without one it lists what is left. After an LLM is added, OCR is synced without a question.
"""

import os
import shutil
from pathlib import Path

import pytest

import guard.cli as cli

import guard.commands.agent as agent_cmds

import guard.commands.config as config_cmds

import guard.commands.setup as setup_cmds
from guard.agent.adapter import CLAUDE_CODE, installed
from guard.core.config import GuardConfig, LLMConfig, load_global_config, ocr_in_sync, save_config

REAL_WHICH = shutil.which


@pytest.fixture
def machine(monkeypatch):
    """A machine with Claude Code, no LLM, no Alibaba OCR and no commit mode; OCR calls are recorded."""
    Path(os.path.expanduser("~/.claude")).mkdir()
    state = {"ocr": False, "synced": [], "installs": 0}
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: ("/bin/ocr" if state["ocr"] else None) if name == "ocr" else REAL_WHICH(name, *a, **k))

    def install(*a, **k):
        state["installs"] += 1
        state["ocr"] = True
        return True, "installed OCR"

    def sync(llm, binary="ocr"):
        state["synced"].append(llm.model)
        from guard.core.config import _remember_ocr_sync
        _remember_ocr_sync(llm, binary)
        return True, "synced"
    monkeypatch.setattr("guard.core.updater.perform_ocr_upgrade", install)
    monkeypatch.setattr("guard.core.config.sync_to_alibaba_ocr", sync)
    return state


def terminal(monkeypatch, answers=True, mode="auto"):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: answers(a[0]) if callable(answers) else answers)
    monkeypatch.setattr(cli.typer, "prompt", lambda q, *a, **k: "optional" if "Alibaba OCR review" in q else mode)


def fake_wizard():
    cfg = load_global_config()
    cfg.llm = LLMConfig(base_url="http://llm.local/v1", api_key="k", model="m1")
    save_config(cfg)
    return cfg


def test_without_a_terminal_only_the_list_is_shown(machine, tmp_path):
    done, left = setup_cmds.finish_setup(tmp_path)
    commands = " ".join(command for _, command in left)
    assert not done
    for command in ("guard config llm", "guard update ocr", "guard config commit auto", "guard agent add claude-code"):
        assert command in commands, command
    assert load_global_config().commit_mode is None and not installed(CLAUDE_CODE) and machine["installs"] == 0


def test_in_a_terminal_everything_missing_is_done_in_order(machine, tmp_path, monkeypatch, capsys):
    terminal(monkeypatch)
    monkeypatch.setattr("guard.core.config.run_llm_wizard", fake_wizard)
    setup_cmds.finish_setup(tmp_path)
    cfg = load_global_config()
    assert cfg.llm.api_key == "k" and cfg.commit_mode == "auto"
    assert machine["installs"] == 1 and machine["synced"] == ["m1"]  # installed, then given the LLM
    assert ocr_in_sync(cfg.llm) and installed(CLAUDE_CODE)
    capsys.readouterr()
    setup_cmds.finish_setup(tmp_path)  # a second run finds nothing to do
    assert "nothing is missing" in capsys.readouterr().out and machine["synced"] == ["m1"]


def test_a_changed_llm_is_synced_without_a_question(machine, tmp_path, monkeypatch):
    machine["ocr"] = True
    cfg = load_global_config()
    cfg.llm, cfg.commit_mode = LLMConfig(base_url="http://llm.local/v1", api_key="k", model="m2"), "ask"
    save_config(cfg)
    setup_cmds.finish_setup(tmp_path)  # no terminal: the sync needs no answer, so it still runs
    assert machine["synced"] == ["m2"]


def test_declined_and_failed_steps_are_listed_and_the_rest_run(machine, tmp_path, monkeypatch, capsys):
    cfg = load_global_config()
    cfg.llm = LLMConfig(base_url="http://llm.local/v1", api_key="k", model="m1")
    save_config(cfg)
    terminal(monkeypatch, answers=lambda q: "Alibaba OCR" not in q)  # declines only the OCR install

    def broken_add(name):
        raise RuntimeError("settings locked")
    monkeypatch.setattr(agent_cmds, "agent_add_cmd", broken_add)
    setup_cmds.finish_setup(tmp_path)
    out = capsys.readouterr().out
    assert "declined" in out and "guard update ocr" in out  # listed with its command
    assert "failed" in out and "settings locked" in out  # the agent step failed ...
    assert load_global_config().commit_mode == "auto"  # ... and the commit-mode step before it still ran
    assert machine["installs"] == 0


def test_a_crashing_ocr_sync_is_listed_and_setup_goes_on(machine, tmp_path, monkeypatch, capsys):
    machine["ocr"] = True
    cfg = load_global_config()
    cfg.llm = LLMConfig(base_url="http://llm.local/v1", api_key="k", model="m1")
    save_config(cfg)

    def crash(*a, **k):
        raise OSError("ocr cannot start")
    monkeypatch.setattr("guard.core.config.sync_to_alibaba_ocr", crash)
    terminal(monkeypatch)
    done, left = setup_cmds.finish_setup(tmp_path)
    sync = dict(left)["OCR sync"]
    assert "ocr cannot start" in sync and "guard config sync" in sync  # listed with its command
    assert load_global_config().commit_mode == "auto" and "Commit mode" in dict(done)  # the step after it still ran


def test_setup_checks_the_ocr_binary_the_repository_uses(machine, tmp_path):
    from guard.core.setup_health import setup_health
    machine["ocr"] = True  # the global `ocr` is installed ...
    repo_cfg = GuardConfig()
    repo_cfg.ocr.binary_path = "repo-ocr"  # ... but this repository names another binary
    save_config(repo_cfg, local=True, repo_path=tmp_path)
    done, left = setup_cmds.finish_setup(tmp_path)
    assert "Alibaba OCR" in dict(left)  # the same binary guard post and doctor use here
    assert next(r for r in setup_health(tmp_path) if r["item"] == "Alibaba OCR")["level"] == "warn"


def test_what_setup_reports_is_what_happened(machine, tmp_path, monkeypatch):
    from guard.core.config import _remember_ocr_sync
    # yes to the OCR install and to adding the agent's hooks, then no to the diff itself; no to the rest
    terminal(monkeypatch, answers=lambda q: "Alibaba OCR" in q or "without guard's hooks" in q)

    def install_elsewhere(*a, **k):  # npm succeeds, but the binary guard uses here is still missing
        return True, "installed somewhere else"
    monkeypatch.setattr("guard.core.updater.perform_ocr_upgrade", install_elsewhere)
    done, left = setup_cmds.finish_setup(tmp_path)
    assert "Alibaba OCR" in dict(left) and "Claude Code hooks" in dict(left)  # neither is reported as done
    assert not installed(CLAUDE_CODE)

    # a sync is remembered per OCR binary: giving the LLM to one does not mark another as synced
    llm = LLMConfig(base_url="http://llm.local/v1", api_key="k", model="m1")
    machine["ocr"] = True
    _remember_ocr_sync(llm, "ocr")
    assert ocr_in_sync(llm, "ocr") and not ocr_in_sync(llm, "repo-ocr")
    # the executable is what counts: `ocr` resolving to another program is not synced yet
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: "/other/prefix/ocr" if name == "ocr" else REAL_WHICH(name, *a, **k))
    assert not ocr_in_sync(llm, "ocr")


def test_ocr_syncs_run_one_at_a_time():
    import threading
    import time
    from guard.core.config import _sync_lock
    order = []

    def sync(n):
        with _sync_lock():
            order.append(("in", n))
            time.sleep(0.1)
            order.append(("out", n))
    threads = [threading.Thread(target=sync, args=(i,)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(order[i][0] == "in" and order[i + 1] == ("out", order[i][1]) for i in range(0, 6, 2))  # never interleaved


def test_doctor_shows_the_llm_and_the_ocr_sync(machine, tmp_path):
    from guard.core.setup_health import setup_health

    def row(item):
        return next(r for r in setup_health(tmp_path) if r["item"] == item)
    assert row("LLM")["level"] == "missing" and row("LLM")["fix"] == "guard config llm"
    assert "once installed it runs only with guard post --full" in row("Alibaba OCR")["detail"]  # not installed: still named
    machine["ocr"] = True  # OCR without an LLM: said plainly, not "OK"
    assert row("Alibaba OCR")["level"] == "warn" and "no LLM" in row("Alibaba OCR")["detail"]
    machine["ocr"] = False
    cfg = load_global_config()
    cfg.llm = LLMConfig(base_url="https://user:secret@llm.local:8443/v1?token=abc", api_key="k", model="m1")
    save_config(cfg)
    machine["ocr"] = True
    assert row("LLM")["level"] == "ok" and row("LLM")["detail"] == "m1 at https://llm.local:8443/v1"  # no credentials
    bad = load_global_config()
    bad.llm = LLMConfig(base_url="http://llm.local:abc/v1", api_key="k", model="m1")
    save_config(bad)
    assert "invalid URL" in row("LLM")["detail"]  # a malformed URL never stops doctor
    save_config(cfg)
    assert row("Alibaba OCR")["level"] == "warn" and row("Alibaba OCR")["fix"] == "guard config sync"
    assert "not chosen yet: guard config ocr always|optional" in row("Alibaba OCR")["detail"]  # even when out of sync
    setup_cmds.finish_setup(tmp_path)  # syncs
    row_ocr = row("Alibaba OCR")  # synced; the setting is not chosen yet, so doctor says it can run on every post
    assert row_ocr["level"] == "warn" and row_ocr["fix"].startswith("guard config ocr always")
    config_cmds.config_ocr_cmd("always")
    assert row("Alibaba OCR")["level"] == "ok" and "every guard post" in row("Alibaba OCR")["detail"]


def test_ocr_always_runs_the_review_on_a_plain_post_but_never_in_the_hook(tmp_path, fake_ocr_review):
    from guard.cli import execute_post_task, execute_pre_task
    from test_agent_events import make_repo
    repo = make_repo(tmp_path)
    config_cmds.config_ocr_cmd("always")
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    execute_post_task(repo_path=repo, hook=True)
    fake_ocr_review.assert_not_called()  # the Git hook stays fast
    from guard.core.session import SessionManager
    status = SessionManager(repo).load_local_session().post.ocr_status
    assert status.startswith("not run in the Git hook") and "always` is on" in status  # the setting is named
    execute_post_task(repo_path=repo)
    fake_ocr_review.assert_called_once()  # a plain post now runs it, as --full does
    from guard.core.ocr_engine import RuleViolation
    fake_ocr_review.return_value = ("did not run: provider down", [RuleViolation(
        rule_id="OCR-RUN", severity="HIGH", file_path="(ocr)", message="down")])
    execute_post_task(repo_path=repo)
    status = SessionManager(repo).load_local_session().post.ocr_status
    assert status.startswith("did not run: provider down") and "always` is on" in status  # a failure names it too
