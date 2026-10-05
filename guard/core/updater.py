"""
Supply-Chain Security & Update Quarantine Checker for Alibaba Open Code Review (OCR).
Monitors `@alibaba-group/open-code-review` releases on the npm registry.

Implements Supply-Chain Backdoor Protection (Quarantine Period):
- New releases < 2-3 days old are put on QUARANTINE HOLD to allow
  the open-source security community to detect malicious code/backdoors.
- Only releases >= 3 days old are marked SAFE TO UPGRADE.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple

import httpx
from pydantic import BaseModel, ValidationError


class UpdateSecurityStatus(str, Enum):
    UP_TO_DATE = "UP_TO_DATE"
    QUARANTINE_HOLD = "QUARANTINE_HOLD"
    SAFE_UPDATE_AVAILABLE = "SAFE_UPDATE_AVAILABLE"
    NOT_INSTALLED = "NOT_INSTALLED"
    CHECK_FAILED = "CHECK_FAILED"


class VersionCheckResult(BaseModel):
    package_name: str
    registry: str = "npm"
    installed_version: Optional[str] = None
    latest_version: Optional[str] = None
    release_date: Optional[str] = None
    age_days: Optional[float] = None
    status: UpdateSecurityStatus
    recommendation: str


def parse_version_tuple(ver_str: str) -> Tuple[int, ...]:
    """Parse version string into tuple of integers for comparison (e.g. '1.12.9' -> (1, 12, 9))."""
    nums = re.findall(r"\d+", ver_str)
    return tuple(int(n) for n in nums) if nums else (0,)


def is_version_newer(latest: str, current: str) -> bool:
    try:
        return parse_version_tuple(latest) > parse_version_tuple(current)
    except (TypeError, ValueError):
        return latest != current


def get_installed_ocr_version() -> Optional[str]:
    ocr_bin = shutil.which("ocr")
    if not ocr_bin:
        return None
    try:
        res = subprocess.run([ocr_bin, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5)
        out = (res.stdout or "") + (res.stderr or "")
        nums = re.findall(r"\d+\.\d+\.\d+", out)
        return nums[0] if nums else "installed"
    except (subprocess.SubprocessError, OSError, UnicodeDecodeError, TypeError):
        return "installed"


def _parse_npm_release_info(data: dict) -> tuple[str, str, Optional[float]]:
    """Extract latest version, date_display, and age_days from npm registry payload."""
    latest = data.get("dist-tags", {}).get("latest", "")
    times = data.get("time", {})
    upload_iso = times.get(latest)

    age_days: Optional[float] = None
    date_display = "Unknown"
    if upload_iso:
        rel_dt = datetime.fromisoformat(upload_iso.replace("Z", "+00:00"))
        now_dt = datetime.now(timezone.utc)
        age_days = (now_dt - rel_dt).total_seconds() / 86400.0
        date_display = rel_dt.strftime("%Y-%m-%d %H:%M UTC")
    return latest, date_display, age_days


def _evaluate_ocr_update_status(
    package_name: str,
    registry: str,
    installed: Optional[str],
    latest: str,
    date_display: str,
    age_days: Optional[float],
    quarantine_days: float,
) -> VersionCheckResult:
    """Determine the security and update status for an OCR release."""
    if not installed:
        return VersionCheckResult(
            package_name=package_name,
            registry=registry,
            installed_version=None,
            latest_version=latest,
            release_date=date_display,
            age_days=age_days,
            status=UpdateSecurityStatus.NOT_INSTALLED,
            recommendation="Optional: install via `npm install -g @alibaba-group/open-code-review`",
        )

    if installed == "installed" or not is_version_newer(latest, installed):
        return VersionCheckResult(
            package_name=package_name,
            registry=registry,
            installed_version=installed,
            latest_version=latest,
            release_date=date_display,
            age_days=age_days,
            status=UpdateSecurityStatus.UP_TO_DATE,
            recommendation="Up-to-date with latest stable release.",
        )

    # Newer version on npm! Check quarantine period
    if age_days is not None and age_days < quarantine_days:
        return VersionCheckResult(
            package_name=package_name,
            registry=registry,
            installed_version=installed,
            latest_version=latest,
            release_date=date_display,
            age_days=age_days,
            status=UpdateSecurityStatus.QUARANTINE_HOLD,
            recommendation=f"🛡️ QUARANTINE HOLD: v{latest} released {age_days:.1f}d ago (< {quarantine_days:.0f}d). Retain v{installed} to prevent supply-chain backdoors.",
        )

    return VersionCheckResult(
        package_name=package_name,
        registry=registry,
        installed_version=installed,
        latest_version=latest,
        release_date=date_display,
        age_days=age_days,
        status=UpdateSecurityStatus.SAFE_UPDATE_AVAILABLE,
        recommendation=f"⬆️ Safe upgrade available (Released {age_days:.1f}d ago): `npm install -g {package_name}`",
    )


def check_ocr_update(quarantine_days: float = 3.0, timeout: float = 4.0) -> VersionCheckResult:
    """
    Check npm registry for `@alibaba-group/open-code-review` and verify against quarantine period.
    """
    installed = get_installed_ocr_version()
    package_name = "@alibaba-group/open-code-review"
    registry = "npm"

    try:
        with httpx.Client(timeout=timeout) as client:
            res = client.get("https://registry.npmjs.org/@alibaba-group%2Fopen-code-review")
            if res.status_code != 200:
                return VersionCheckResult(
                    package_name=package_name,
                    registry=registry,
                    installed_version=installed,
                    status=UpdateSecurityStatus.CHECK_FAILED,
                    recommendation=f"HTTP {res.status_code} while querying npm registry",
                )
            latest, date_display, age_days = _parse_npm_release_info(res.json())
            return _evaluate_ocr_update_status(
                package_name, registry, installed, latest, date_display, age_days, quarantine_days
            )

    except Exception as e:
        # Best-effort update check: failure to query npm must never crash guard
        return VersionCheckResult(
            package_name=package_name,
            registry=registry,
            installed_version=installed,
            status=UpdateSecurityStatus.CHECK_FAILED,
            recommendation=f"Failed to query npm registry ({str(e)[:60]})",
        )

def perform_ocr_upgrade(force: bool = False, quarantine_days: float = 3.0) -> Tuple[bool, str]:
    """
    Safely upgrades Alibaba OCR via npm if quarantine check passes or --force is specified.
    """
    check = check_ocr_update(quarantine_days=quarantine_days)
    if check.status == UpdateSecurityStatus.UP_TO_DATE:
        return True, f"Alibaba OCR is already up to date ({check.installed_version or 'latest'}). No update needed."

    if check.status == UpdateSecurityStatus.QUARANTINE_HOLD and not force:
        return False, (
            f"🛡️ QUARANTINE HOLD: v{check.latest_version} was released {check.age_days:.1f}d ago (< {quarantine_days:.0f}d).\n"
            f"To prevent zero-day backdoors and npm supply-chain attacks, Guard halts automated upgrade.\n"
            f"💡 To bypass security quarantine explicitly, use: guard update --force"
        )

    npm_bin = shutil.which("npm")
    if not npm_bin:
        return False, "'npm' command not found in PATH. Please install Node.js/npm first."

    pkg_spec = f"@alibaba-group/open-code-review@{check.latest_version}" if check.latest_version else "@alibaba-group/open-code-review@latest"
    try:
        proc = subprocess.run([npm_bin, "install", "-g", pkg_spec], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        if proc.returncode == 0:
            new_ver = get_installed_ocr_version() or check.latest_version or "latest"
            return True, f"✅ Successfully upgraded Alibaba OCR to version v{new_ver}!"
        err_out = (proc.stderr or "") + (proc.stdout or "")
        return False, f"npm install failed (exit code {proc.returncode}): {err_out}"
    except (subprocess.SubprocessError, OSError) as e:
        return False, f"Error running npm install: {str(e)}"


def _upgrade_via_pipx(repo_url: str) -> Optional[Tuple[bool, str]]:
    """Attempt upgrading via pipx if installed in a pipx environment."""
    is_pipx = (
        "pipx" in sys.prefix.lower()
        or "pipx" in sys.executable.lower()
        or bool(os.environ.get("PIPX_HOME"))
        or bool(os.environ.get("PIPX_BIN_DIR"))
    )
    pipx_bin = shutil.which("pipx")
    if not (is_pipx and pipx_bin):
        return None

    cmd = [pipx_bin, "install", repo_url, "--force"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        if proc.returncode == 0:
            return True, "✅ Successfully upgraded Banh-Mi-Guard via pipx!"
        err_out = (proc.stderr or "") + (proc.stdout or "")
        return False, f"pipx upgrade failed: {err_out}"
    except (subprocess.SubprocessError, OSError) as e:
        return False, f"Error upgrading guard via pipx: {str(e)}"


def _prepare_windows_exe_backup() -> Optional[Tuple[Path, Path]]:
    """Rename current guard.exe on Windows to avoid binary locking during pip install."""
    if sys.platform != "win32":
        return None
    guard_bin = shutil.which("guard")
    if not guard_bin:
        return None
    guard_path = Path(guard_bin)
    if guard_path.suffix.lower() == ".exe" and guard_path.exists():
        bak_path = guard_path.with_name(f"{guard_path.stem}.old.exe")
        try:
            if bak_path.exists():
                try:
                    bak_path.unlink()
                except OSError:
                    pass
            guard_path.rename(bak_path)
            return (guard_path, bak_path)
        except OSError:
            pass
    return None


def _upgrade_via_pip(repo_url: str) -> Tuple[bool, str]:
    """Standard pip fallback with --force-reinstall and Windows binary lock mitigation."""
    pip_cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--upgrade",
        "--force-reinstall",
        "--no-cache-dir",
        repo_url,
    ]
    exe_renamed = _prepare_windows_exe_backup()
    try:
        proc = subprocess.run(pip_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        if proc.returncode == 0:
            if exe_renamed:
                # Only unlink backup if new executable was actually created
                if exe_renamed[0].exists():
                    try:
                        exe_renamed[1].unlink(missing_ok=True)
                    except OSError:
                        pass
                else:
                    # Restore backup if new exe is missing
                    try:
                        exe_renamed[1].rename(exe_renamed[0])
                    except OSError:
                        pass
            return True, "✅ Successfully upgraded Banh-Mi-Guard from GitHub repository!"

        err_out = (proc.stderr or "") + (proc.stdout or "")
        return False, f"pip upgrade failed: {err_out}"
    except BaseException as e:
        return False, f"Error upgrading guard: {str(e)}"
    finally:
        # Guarantee safety: any failure/interrupt where guard.exe is missing restores from backup
        if exe_renamed and exe_renamed[1].exists() and not exe_renamed[0].exists():
            try:
                exe_renamed[1].rename(exe_renamed[0])
            except OSError:
                pass


def perform_self_upgrade() -> Tuple[bool, str]:
    """
    Upgrades banh-mi-guard itself from GitHub.
    Intelligently detects if installed via pipx or standard pip,
    uses --force/--force-reinstall to bypass cached builds, and handles
    Windows file locking on guard.exe with atomic fallback.
    """
    repo_url = "git+https://github.com/okrath/banh-mi-guard.git"
    pipx_res = _upgrade_via_pipx(repo_url)
    if pipx_res is not None:
        return pipx_res
    return _upgrade_via_pip(repo_url)
def get_update_cache_path() -> Path:
    return Path.home() / ".guard" / "update_cache.json"


def _read_cached_guard_update(cache_path: Path) -> Optional[VersionCheckResult]:
    """Read update check result from disk cache if younger than 12 hours."""
    if not cache_path.is_file():
        return None
    try:
        cached_data = json.loads(cache_path.read_text(encoding="utf-8"))
        cache_age = time.time() - cached_data.get("timestamp", 0)
        if cache_age < 43200:  # 12 hours
            return VersionCheckResult.model_validate(cached_data["result"])
    except (OSError, AttributeError, ValueError, KeyError, TypeError, ValidationError):
        pass
    return None


def _save_cached_guard_update(cache_path: Path, result: VersionCheckResult) -> None:
    """Save update check result to disk cache."""
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_payload = {
            "timestamp": time.time(),
            "result": result.model_dump(mode="json"),
        }
        cache_path.write_text(json.dumps(cache_payload, indent=2), encoding="utf-8")
    except (OSError, TypeError, ValueError):
        pass


def _parse_github_pyproject_version(text: str) -> Optional[str]:
    """Extract version string from pyproject.toml content."""
    m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', text)
    return m.group(1).strip() if m else None


def check_guard_self_update(timeout: float = 3.0, force: bool = False) -> VersionCheckResult:
    """
    Check if a newer version of banh-mi-guard is available on GitHub.
    Uses cached result if within 12 hours unless force=True.
    """
    from guard import __version__

    installed = __version__
    package_name = "banh-mi-guard"
    registry = "github"
    cache_path = get_update_cache_path()

    if not force:
        cached = _read_cached_guard_update(cache_path)
        if cached is not None:
            return cached

    url = "https://raw.githubusercontent.com/okrath/banh-mi-guard/main/pyproject.toml"
    headers = {"User-Agent": f"guard-cli/{installed}"}
    if force:
        url += f"?_t={int(time.time())}"
        headers["Cache-Control"] = "no-cache"
        headers["Pragma"] = "no-cache"
    try:
        with httpx.Client(timeout=timeout) as client:
            res = client.get(url, headers=headers)
            if res.status_code != 200:
                return VersionCheckResult(
                    package_name=package_name,
                    registry=registry,
                    installed_version=installed,
                    status=UpdateSecurityStatus.CHECK_FAILED,
                    recommendation=f"HTTP {res.status_code} while querying GitHub",
                )

            latest = _parse_github_pyproject_version(res.text)
            if not latest:
                return VersionCheckResult(
                    package_name=package_name,
                    registry=registry,
                    installed_version=installed,
                    status=UpdateSecurityStatus.CHECK_FAILED,
                    recommendation="Could not parse remote version from GitHub",
                )

            if is_version_newer(latest, installed):
                status = UpdateSecurityStatus.SAFE_UPDATE_AVAILABLE
                rec = f"New version v{latest} available! Run 'guard update self' to upgrade."
            else:
                status = UpdateSecurityStatus.UP_TO_DATE
                rec = "Up to date with GitHub repository."

            result = VersionCheckResult(
                package_name=package_name,
                registry=registry,
                installed_version=installed,
                latest_version=latest,
                status=status,
                recommendation=rec,
            )
            _save_cached_guard_update(cache_path, result)
            return result

    except Exception as e:
        # Best-effort update check: background daemon check must never crash CLI commands
        return VersionCheckResult(
            package_name=package_name,
            registry=registry,
            installed_version=installed,
            status=UpdateSecurityStatus.CHECK_FAILED,
            recommendation=f"Network notice ({str(e)[:50]})",
        )

def get_cached_update_notice() -> Optional[str]:
    """
    Quickly read cached update status (<1ms, zero network call).
    Returns a 1-line update notification string if an update is available.
    """
    from guard import __version__

    cache_path = get_update_cache_path()
    if not cache_path.is_file():
        return None
    try:
        cached_data = json.loads(cache_path.read_text(encoding="utf-8"))
        res = cached_data.get("result", {})
        latest = res.get("latest_version")
        if latest and is_version_newer(latest, __version__):
            return f"💡 A new version of guard is available: v{__version__} → v{latest} (Run 'guard update self' to upgrade)"
    except (OSError, AttributeError, ValueError, KeyError, TypeError):
        pass
    return None


def maybe_trigger_background_update_check():
    """
    Spawns a daemon thread to refresh the update cache if missing or older than 24 hours.
    Zero-overhead, non-blocking for user commands.
    """
    cache_path = get_update_cache_path()
    should_check = True
    if cache_path.is_file():
        try:
            cached_data = json.loads(cache_path.read_text(encoding="utf-8"))
            cache_age = time.time() - cached_data.get("timestamp", 0)
            if cache_age < 86400:  # 24 hours
                should_check = False
        except (OSError, AttributeError, ValueError, KeyError, TypeError):
            should_check = True

    if should_check:
        try:
            t = threading.Thread(target=check_guard_self_update, kwargs={"timeout": 3.0, "force": True}, daemon=True)
            t.start()
        except Exception:
            # Best-effort background update check: never crash CLI execution
            pass
