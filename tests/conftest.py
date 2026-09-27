import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def isolate_guard_home(tmp_path_factory, monkeypatch):
    """
    Registry, refresh state and global hooks dir live in a throwaway GUARD_HOME, and Git reads a
    throwaway global config, so tests never use (or run) the machine's real global hooks.
    """
    home = tmp_path_factory.mktemp("guard_home")
    monkeypatch.setenv("GUARD_HOME", str(home))
    gitconfig = home / "gitconfig"
    gitconfig.write_text("[user]\n\tname = guard-tests\n\temail = tests@guard.local\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))


@pytest.fixture(autouse=True)
def isolate_global_guard_config(tmp_path_factory):
    """
    Ensure unit and integration tests do not accidentally read or mutate
    the host user's personal ~/.guard/config.json configuration.
    """
    dummy_dir = tmp_path_factory.mktemp("dummy_guard_home")
    dummy_config = dummy_dir / "nonexistent_config.json"
    dummy_session = dummy_dir / "active_session.json"
    with patch("guard.core.config.get_global_config_path", return_value=dummy_config), \
         patch("guard.core.session.SessionManager._get_global_active_session_file", return_value=dummy_session):
        yield


@pytest.fixture(autouse=True)
def fake_ocr_review():
    """guard post never calls the real Alibaba OCR in tests; tests of the runner call it directly."""
    with patch("guard.cli.run_ocr_review", return_value=("complete: 0 finding(s) (test double)", [])) as fake:
        yield fake
