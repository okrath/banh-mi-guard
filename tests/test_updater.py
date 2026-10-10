"""
Unit tests for Supply-Chain Security & Update Quarantine Checker (Alibaba OCR).
"""

import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from guard.core.updater import (
    UpdateSecurityStatus,
    VersionCheckResult,
    check_guard_self_update,
    check_ocr_update,
    get_cached_update_notice,
    is_version_newer,
    parse_version_tuple,
    perform_ocr_upgrade,
)


def test_parse_version_tuple():
    assert parse_version_tuple("1.12.9") == (1, 12, 9)
    assert parse_version_tuple("2.0.0-rc1") == (2, 0, 0, 1)


def test_is_version_newer():
    assert is_version_newer("1.13.0", "1.12.9") is True
    assert is_version_newer("1.12.9", "1.12.9") is False
    assert is_version_newer("1.12.8", "1.12.9") is False


def test_ocr_update_quarantine_hold():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "dist-tags": {"latest": "1.13.0"},
        "time": {
            # released a day ago, whatever today is (a fixed date turned this test into a time bomb)
            "1.13.0": (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        }
    }

    with patch("httpx.Client.get", return_value=mock_response), \
         patch("guard.core.updater.get_installed_ocr_version", return_value="1.12.9"):
        res = check_ocr_update(quarantine_days=3.0)
        assert res.status == UpdateSecurityStatus.QUARANTINE_HOLD
        assert "QUARANTINE HOLD" in res.recommendation


def test_ocr_update_safe_available():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "dist-tags": {"latest": "1.13.0"},
        "time": {
            "1.13.0": "2026-09-20T12:00:00Z"
        }
    }

    with patch("httpx.Client.get", return_value=mock_response), \
         patch("guard.core.updater.get_installed_ocr_version", return_value="1.12.9"):
        res = check_ocr_update(quarantine_days=3.0)
        assert res.status == UpdateSecurityStatus.SAFE_UPDATE_AVAILABLE
        assert "Safe upgrade available" in res.recommendation


def test_ocr_update_up_to_date():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "dist-tags": {"latest": "1.12.9"},
        "time": {
            "1.12.9": "2026-09-22T12:00:00Z"
        }
    }

    with patch("httpx.Client.get", return_value=mock_response), \
         patch("guard.core.updater.get_installed_ocr_version", return_value="1.12.9"):
        res = check_ocr_update(quarantine_days=3.0)
        assert res.status == UpdateSecurityStatus.UP_TO_DATE


def test_perform_ocr_upgrade_blocked_by_quarantine():
    mock_check = VersionCheckResult(
        package_name="@alibaba-group/open-code-review",
        registry="npm",
        installed_version="1.12.9",
        latest_version="1.13.0",
        age_days=1.2,
        status=UpdateSecurityStatus.QUARANTINE_HOLD,
        recommendation="Quarantine active",
    )
    with patch("guard.core.updater.check_ocr_update", return_value=mock_check):
        success, msg = perform_ocr_upgrade(force=False, quarantine_days=3.0)
        assert success is False
        assert "QUARANTINE HOLD" in msg


def test_perform_ocr_upgrade_force_allowed():
    mock_check = VersionCheckResult(
        package_name="@alibaba-group/open-code-review",
        registry="npm",
        installed_version="1.12.9",
        latest_version="1.13.0",
        age_days=1.2,
        status=UpdateSecurityStatus.QUARANTINE_HOLD,
        recommendation="Quarantine active",
    )
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    with patch("guard.core.updater.check_ocr_update", return_value=mock_check), \
         patch("shutil.which", return_value="npm"), \
         patch("subprocess.run", return_value=mock_proc):
        success, msg = perform_ocr_upgrade(force=True, quarantine_days=3.0)
        assert success is True
        assert "Successfully upgraded" in msg
def test_check_guard_self_update_newer(tmp_path):
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.text = '[project]\nname = "banh-mi-guard"\nversion = "9.9.9"\n'

    dummy_cache = tmp_path / "cache.json"
    with patch("httpx.Client.get", return_value=mock_res), \
         patch("guard.core.updater.get_update_cache_path", return_value=dummy_cache):
        res = check_guard_self_update(force=True)
        assert res.package_name == "banh-mi-guard"
        assert res.latest_version == "9.9.9"
        assert res.status == UpdateSecurityStatus.SAFE_UPDATE_AVAILABLE
        assert "New version" in res.recommendation


def test_check_guard_self_update_up_to_date(tmp_path):
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.text = '[project]\nname = "banh-mi-guard"\nversion = "0.1.0"\n'

    dummy_cache = tmp_path / "cache.json"
    with patch("httpx.Client.get", return_value=mock_res), \
         patch("guard.core.updater.get_update_cache_path", return_value=dummy_cache):
        res = check_guard_self_update(force=True)
        assert res.status == UpdateSecurityStatus.UP_TO_DATE


def test_get_cached_update_notice(tmp_path):
    import json
    dummy_cache = tmp_path / "cache.json"

    # Cache has newer version
    dummy_cache.write_text(json.dumps({
        "timestamp": 9999999999.0,
        "result": {
            "package_name": "banh-mi-guard",
            "registry": "github",
            "installed_version": "0.1.0",
            "latest_version": "9.9.9",
            "status": "SAFE_UPDATE_AVAILABLE",
            "recommendation": "New version available"
        }
    }), encoding="utf-8")

    with patch("guard.core.updater.get_update_cache_path", return_value=dummy_cache):
        notice = get_cached_update_notice()
        assert notice is not None
        assert "A new version of guard is available" in notice
        assert "v9.9.9" in notice


@pytest.fixture
def clean_pip_env(monkeypatch):
    monkeypatch.delenv("PIPX_HOME", raising=False)
    monkeypatch.delenv("PIPX_BIN_DIR", raising=False)
    monkeypatch.setattr(sys, "executable", "C:/Python311/python.exe")


def test_perform_self_upgrade_pipx():
    from guard.core.updater import perform_self_upgrade

    mock_proc = MagicMock()
    mock_proc.returncode = 0

    with patch("sys.platform", "linux"), \
         patch("sys.prefix", "/home/u/.local/pipx/venvs/banh-mi-guard"), \
         patch("shutil.which", return_value="/usr/bin/pipx"), \
         patch("subprocess.run", return_value=mock_proc) as mock_run:
        success, msg = perform_self_upgrade()
        assert success is True
        assert "pipx" in msg
        called_cmd = mock_run.call_args[0][0]
        assert "install" in called_cmd
        assert "--force" in called_cmd


def test_perform_self_upgrade_pipx_on_windows_reinstalls_with_the_venv_pip():
    """On Windows the running venv's python.exe is locked, so pipx cannot recreate the venv: use its pip."""
    from guard.core.updater import perform_self_upgrade

    mock_proc = MagicMock()
    mock_proc.returncode = 0

    venv_python = "C:/Users/u/AppData/Local/pipx/pipx/venvs/banh-mi-guard/Scripts/python.exe"
    with patch("sys.platform", "win32"), \
         patch("sys.prefix", "C:/Users/u/AppData/Local/pipx/pipx/venvs/banh-mi-guard"), \
         patch("sys.executable", venv_python), \
         patch("shutil.which", return_value=None), \
         patch("subprocess.run", return_value=mock_proc) as mock_run:
        success, _ = perform_self_upgrade()
        assert success is True
        called_cmd = mock_run.call_args[0][0]
        assert called_cmd[:3] == [venv_python, "-m", "pip"]
        assert "--force-reinstall" in called_cmd


def test_perform_self_upgrade_pip_fallback(clean_pip_env):
    from guard.core.updater import perform_self_upgrade

    mock_proc = MagicMock()
    mock_proc.returncode = 0

    with patch("sys.prefix", "C:/Python311"), \
         patch("sys.executable", "C:/Python311/python.exe"), \
         patch("shutil.which", return_value=None), \
         patch("subprocess.run", return_value=mock_proc) as mock_run:
        success, msg = perform_self_upgrade()
        assert success is True
        called_cmd = mock_run.call_args[0][0]
        assert "--force-reinstall" in called_cmd
        assert "--no-cache-dir" in called_cmd


def test_perform_self_upgrade_windows_fail_restores(clean_pip_env, tmp_path):
    from guard.core.updater import perform_self_upgrade

    exe_path = tmp_path / "guard.exe"
    exe_path.write_text("old_binary", encoding="utf-8")

    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stderr = "pip network failure"

    with patch("sys.platform", "win32"), \
         patch("sys.prefix", "C:/Python311"), \
         patch("shutil.which", return_value=str(exe_path)), \
         patch("subprocess.run", return_value=mock_proc):
        success, msg = perform_self_upgrade()
        assert success is False
        assert "pip upgrade failed" in msg
        # Binary must be restored
        assert exe_path.exists()
        assert exe_path.read_text(encoding="utf-8") == "old_binary"


def test_perform_self_upgrade_windows_success_clean(clean_pip_env, tmp_path):
    from guard.core.updater import perform_self_upgrade

    exe_path = tmp_path / "guard.exe"
    exe_path.write_text("old_binary", encoding="utf-8")

    def fake_pip_install(*args, **kwargs):
        # Simulate pip creating the new binary
        exe_path.write_text("new_binary", encoding="utf-8")
        mock_res = MagicMock()
        mock_res.returncode = 0
        return mock_res

    with patch("sys.platform", "win32"), \
         patch("sys.prefix", "C:/Python311"), \
         patch("shutil.which", return_value=str(exe_path)), \
         patch("subprocess.run", side_effect=fake_pip_install):
        success, msg = perform_self_upgrade()
        assert success is True
        assert exe_path.exists()
        assert exe_path.read_text(encoding="utf-8") == "new_binary"
        # Old backup should be unlinked
        bak_path = tmp_path / "guard.old.exe"
        assert not bak_path.exists()
