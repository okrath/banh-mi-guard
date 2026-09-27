"""
Unit tests for Core Config and LLM Client.
"""

from unittest.mock import patch

from guard.core.config import (
    GuardConfig,
    LLMConfig,
    LLMProtocol,
    load_config,
    save_config,
    sync_to_alibaba_ocr,
)

def test_llm_config_masking():
    cfg = LLMConfig(api_key="sk-1234567890abcdef")
    assert cfg.masked_api_key == "sk-1...cdef"
    
    empty_cfg = LLMConfig(api_key="")
    assert empty_cfg.masked_api_key == "(none)"


def test_config_save_and_load(tmp_path):
    repo = tmp_path / "my_project"
    repo.mkdir()
    
    cfg = GuardConfig(
        llm=LLMConfig(
            protocol=LLMProtocol.ANTHROPIC,
            base_url="https://api.anthropic.com/v1",
            api_key="sk-ant-testkey",
            model="claude-3-7-sonnet",
        )
    )
    
    saved_path = save_config(cfg, local=True, repo_path=repo)
    assert saved_path.is_file()
    assert saved_path == repo / ".guard" / "config.json"
    
    loaded = load_config(repo)
    assert loaded.llm.protocol == LLMProtocol.ANTHROPIC
    assert loaded.llm.model == "claude-3-7-sonnet"
    assert loaded.llm.api_key == "sk-ant-testkey"


def test_sync_to_ocr_when_cli_missing():
    with patch("guard.core.config.shutil.which", return_value=None):
        success, msg = sync_to_alibaba_ocr(LLMConfig(api_key="test-key"))
    assert success is False and "not found" in msg


def test_sync_to_ocr_sets_a_custom_provider_with_guard_protocol():
    calls = []
    llm = LLMConfig(protocol=LLMProtocol.OPENAI, base_url="http://127.0.0.1:8090/v1", api_key="k", model="muse")
    with patch("guard.core.config.shutil.which", return_value="ocr"), \
         patch("guard.core.config.subprocess.run", side_effect=lambda cmd, **kw: calls.append(cmd[3:])):
        success, _ = sync_to_alibaba_ocr(llm)
    assert success is True
    assert ["provider", "guard"] in calls
    assert ["custom_providers.guard.url", "http://127.0.0.1:8090/v1"] in calls
    assert ["custom_providers.guard.protocol", "openai"] in calls
    assert ["model", "muse"] in calls and ["custom_providers.guard.model", "muse"] in calls
    assert not any(c[0].startswith("llm.") for c in calls)  # legacy llm.url is always called as Anthropic


def test_local_config_still_wins_over_the_global_one(tmp_path):
    from guard.core.config import get_global_config_path, load_global_config
    save_config(GuardConfig(llm=LLMConfig(model="global-model")))  # conftest points "global" at a temp file
    repo = tmp_path / "repo"
    save_config(GuardConfig(llm=LLMConfig(model="local-model")), local=True, repo_path=repo)
    assert load_config(repo).llm.model == "local-model"
    assert load_config(tmp_path / "other").llm.model == "global-model"
    assert load_global_config().llm.model == "global-model" and get_global_config_path().is_file()


def test_local_llm_wizard_never_writes_the_machine_wide_ocr_config(tmp_path):
    from guard.core.config import run_llm_wizard
    answers = iter(["openai", "http://127.0.0.1:9/v1", "repo-key", "m", "60"])
    with patch("guard.core.config.Prompt.ask", side_effect=lambda *a, **k: next(answers)), \
         patch("guard.core.config.Confirm.ask", return_value=False), \
         patch("guard.core.config.sync_to_alibaba_ocr") as sync:
        run_llm_wizard(local=True, repo_path=tmp_path)
    sync.assert_not_called()
