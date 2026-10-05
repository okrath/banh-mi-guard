"""
Hook Installer and Manager for Banh-Mi-Guard.
Supports installing and managing:
1. Git Hooks: `.git/hooks/pre-commit` and `prepare-commit-msg`
2. Agent Directives: `CLAUDE.md` and `AGENT.md` (for omp, Claude Code, Cursor, Windsurf)
3. Agent Wrapper: `.guard/bin/guard-exec`
4. Stealth Mode: Configures `.git/info/exclude` so `.guard/` leaves zero footprint on repository.
Safely backs up any existing user files before modification.
"""

from __future__ import annotations

import stat
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from guard.core.repo_setup import (
    DIRECTIVE_END,
    DIRECTIVE_START,
    is_legacy_whole_file,
    legacy_backup_path,
    legacy_directive_to_current,
    mentions_guard,
    strip_guard_parts,
    strip_legacy_parts,
)
from guard.hooks.templates import (
    AGENT_DIRECTIVES_TEMPLATE,
    AGENT_WRAPPER_SCRIPT,
    GIT_PRE_COMMIT_HOOK,
    GIT_PREPARE_COMMIT_MSG_HOOK,
)


class HookInstaller:
    """
    Manages hook lifecycle and AI Agent directives in target repositories.
    """

    def __init__(self, repo_path: Optional[Path] = None):
        self.repo_path = Path(repo_path or Path.cwd()).resolve()
        self.git_hooks_dir = self.repo_path / ".git" / "hooks"
        self.guard_bin_dir = self.repo_path / ".guard" / "bin"
        self.claude_md_path = self.repo_path / "CLAUDE.md"
        self.agent_md_path = self.repo_path / "AGENT.md"

    def is_git_repo(self) -> bool:
        return (self.repo_path / ".git").is_dir()

    def find_child_git_repos(self, max_depth: int = 3) -> List[Path]:
        """
        Recursively discover all child Git repositories within the workspace.
        Excludes noisy build, dependency, and cache directories.
        """
        if not self.repo_path.is_dir():
            return []

        ignored_names = {
            "node_modules", ".venv", "venv", "env", ".env", "dist", "build",
            "__pycache__", ".git", ".idea", ".vscode", ".pytest_cache"
        }

        discovered: List[Path] = []

        def _scan(current: Path, depth: int):
            if depth > max_depth:
                return
            try:
                for entry in current.iterdir():
                    if not entry.is_dir() or entry.name in ignored_names:
                        continue
                    if (entry / ".git").is_dir():
                        discovered.append(entry.resolve())
                        continue
                    _scan(entry, depth + 1)
            except (PermissionError, OSError):
                pass

        _scan(self.repo_path, 1)
        return sorted(discovered)

    def install_multi(self, target_repos: List[Path], mode: str = "git") -> Dict[str, Any]:
        """
        Install Git hooks into multiple discovered Git repositories.
        """
        results: Dict[str, Any] = {}
        for r in target_repos:
            sub_installer = HookInstaller(r)
            success, msgs = sub_installer.install(mode=mode)
            results[str(r)] = {"success": success, "messages": msgs}
        return results

    @staticmethod
    def get_global_hooks_dir() -> Path:
        from guard.core.repo_setup import guard_home
        return guard_home() / "hooks"

    @classmethod
    def get_global_hooks_status(cls) -> Dict[str, Any]:
        hooks_dir = cls.get_global_hooks_dir()
        pre_commit = hooks_dir / "pre-commit"
        prep_msg = hooks_dir / "prepare-commit-msg"

        current_path = ""
        try:
            res = subprocess.run(
                ["git", "config", "--global", "--get", "core.hooksPath"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if res.returncode == 0:
                current_path = res.stdout.strip()
        except (subprocess.SubprocessError, OSError):
            pass

        is_active = bool(current_path and Path(current_path).resolve() == hooks_dir.resolve())
        return {
            "hooks_dir": str(hooks_dir),
            "configured_path": current_path,
            "is_active": is_active,
            "pre_commit_exists": pre_commit.exists(),
            "prepare_commit_msg_exists": prep_msg.exists(),
        }

    @classmethod
    def install_global_git_hooks(cls) -> Tuple[bool, List[str]]:
        """
        Configure Git globally (git config --global core.hooksPath ~/.guard/hooks)
        so that every repository on this machine is guarded automatically.
        """
        hooks_dir = cls.get_global_hooks_dir()
        hooks_dir.mkdir(parents=True, exist_ok=True)
        messages = []

        pre_commit = hooks_dir / "pre-commit"
        prep_msg = hooks_dir / "prepare-commit-msg"

        pre_commit.write_text(GIT_PRE_COMMIT_HOOK, encoding="utf-8", newline="\n")  # sh scripts must be LF
        prep_msg.write_text(GIT_PREPARE_COMMIT_MSG_HOOK, encoding="utf-8", newline="\n")

        try:
            pre_commit.chmod(pre_commit.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            prep_msg.chmod(prep_msg.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except OSError:
            pass

        messages.append(f"Installed global hook scripts in: {hooks_dir}")

        try:
            subprocess.run(
                ["git", "config", "--global", "core.hooksPath", str(hooks_dir)],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            messages.append("Configured 'git config --global core.hooksPath ~/.guard/hooks'")
            return True, messages
        except (subprocess.SubprocessError, OSError) as e:
            messages.append(f"Failed to set git global config: {e}")
            return False, messages

    @classmethod
    def uninstall_global_git_hooks(cls) -> Tuple[bool, List[str]]:
        messages = []
        try:
            subprocess.run(
                ["git", "config", "--global", "--unset", "core.hooksPath"],
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            messages.append("Unset 'git config --global core.hooksPath'")
        except (subprocess.SubprocessError, OSError):
            pass
        return True, messages

    def _ensure_git_exclude(self) -> bool:
        """
        Ensure .guard/ directory is ignored in .git/info/exclude (Stealth local ignore).
        Zero workspace footprint: never touches workspace .gitignore or triggers remote push.
        """
        from guard.core.git_exclude import ensure_excluded

        if not self.is_git_repo():
            return False
        try:
            return ensure_excluded(self.repo_path, ".guard/", "# Banh-Mi-Guard stealth local exclude", same=(".guard",))
        except OSError:
            return False

    def _remove_git_exclude(self) -> bool:
        """
        Remove .guard/ entry from .git/info/exclude if it exists.
        """
        from guard.core.git_exclude import remove_excluded

        if not self.is_git_repo():
            return False
        try:
            return remove_excluded(self.repo_path, (".guard/", ".guard", "# Banh-Mi-Guard stealth local exclude"))
        except OSError:
            pass
        return False

    def get_status(self) -> Dict[str, Any]:
        """
        Check which hooks and agent directives are currently installed.
        """
        pre_commit = self.git_hooks_dir / "pre-commit"
        prep_msg = self.git_hooks_dir / "prepare-commit-msg"
        agent_exec = self.guard_bin_dir / "guard-exec"

        claude_active = self.claude_md_path.exists() and mentions_guard(self.claude_md_path.read_text(encoding="utf-8", errors="ignore"))
        agent_active = self.agent_md_path.exists() and mentions_guard(self.agent_md_path.read_text(encoding="utf-8", errors="ignore"))
        pre_commit_installed = pre_commit.exists() and mentions_guard(pre_commit.read_text(encoding="utf-8", errors="ignore"))
        prep_msg_installed = prep_msg.exists() and mentions_guard(prep_msg.read_text(encoding="utf-8", errors="ignore"))

        from guard.core.git_exclude import exclude_file

        exclude = exclude_file(self.repo_path)  # the common Git directory's, as the writers use
        git_exclude_active = bool(exclude and exclude.is_file()
                                  and ".guard" in exclude.read_text(encoding="utf-8", errors="ignore"))

        has_git = pre_commit_installed or prep_msg_installed
        has_agent = claude_active or agent_active
        if has_git and has_agent:
            mode = "all"
        elif has_git:
            mode = "git"
        elif has_agent:
            mode = "agent"
        else:
            mode = "none"

        return {
            "is_git_repo": self.is_git_repo(),
            "pre_commit_installed": pre_commit_installed,
            "prepare_commit_msg_installed": prep_msg_installed,
            "agent_wrapper_installed": agent_exec.exists(),
            "claude_md_active": claude_active,
            "agent_md_active": agent_active,
            "git_exclude_active": git_exclude_active,
            "mode": mode,
        }

    def install(self, mode: str = "all") -> Tuple[bool, List[str]]:
        """
        Install hooks and/or agent directives into repository.
        mode:
          - 'git' (or 'stealth'): Local Git hooks only. No CLAUDE.md/AGENT.md (guard.invariants.json is still created).
          - 'agent': Workspace agent directives only (CLAUDE.md & AGENT.md). No Git hooks.
          - 'all' (or 'dual'): Both Git hooks and Agent directives.
        """
        valid_modes = {"git", "stealth", "agent", "all", "dual"}
        mode_clean = (mode or "").lower().strip()
        if mode_clean not in valid_modes:
            raise ValueError(f"Invalid mode '{mode}'. Expected one of: {sorted(valid_modes)}")

        messages = []
        normalized_mode = "git" if mode_clean in ["git", "stealth"] else ("agent" if mode_clean == "agent" else "all")

        if not self.is_git_repo() and normalized_mode in ["git", "all"]:
            return False, ["Target directory is not a Git repository. Cannot install git hooks."]

        # Ensure stealth local exclude so .guard/ session data is never pushed to remote
        if self.is_git_repo():
            if self._ensure_git_exclude():
                messages.append("Added '.guard/' to local .git/info/exclude (Stealth mode: zero workspace footprint)")

        # 1. Install Git Hooks (Stealth / Local only)
        if normalized_mode in ["git", "all"] and self.is_git_repo():
            self.git_hooks_dir.mkdir(parents=True, exist_ok=True)

            # Pre-commit hook
            pre_commit_path = self.git_hooks_dir / "pre-commit"
            self._write_hook_file(pre_commit_path, GIT_PRE_COMMIT_HOOK)
            messages.append(f"Installed Git pre-commit hook at {pre_commit_path}")

            # Prepare commit message hook
            prep_msg_path = self.git_hooks_dir / "prepare-commit-msg"
            self._write_hook_file(prep_msg_path, GIT_PREPARE_COMMIT_MSG_HOOK)
            messages.append(f"Installed Git prepare-commit-msg hook at {prep_msg_path}")

        # 2. Install Agent Directives (CLAUDE.md & AGENT.md)
        if normalized_mode in ["agent", "all"]:
            # Harness wrapper script
            self.guard_bin_dir.mkdir(parents=True, exist_ok=True)
            agent_path = self.guard_bin_dir / "guard-exec"
            self._write_hook_file(agent_path, AGENT_WRAPPER_SCRIPT)
            messages.append(f"Installed Agent harness wrapper at {agent_path}")

            # Inject or create CLAUDE.md
            self._inject_directive(self.claude_md_path)
            messages.append(f"Configured Agent directives in {self.claude_md_path.name}")

            # Inject or create AGENT.md
            self._inject_directive(self.agent_md_path)
            messages.append(f"Configured Agent directives in {self.agent_md_path.name}")

        # 3. Project invariants: a local, Git-excluded file (never a repository diff)
        from guard.core.project_invariants import init_invariants_file
        inv_path, created, imported = init_invariants_file(self.repo_path)
        rel = inv_path.relative_to(self.repo_path).as_posix()
        if created:
            messages.append(f"Created local {rel} ({imported} invariant(s) imported from agent docs)")
        else:
            messages.append(f"Kept existing {rel}")

        return True, messages

    def uninstall(self, mode: str = "all") -> Tuple[bool, List[str]]:
        """
        Safely uninstall Guard hooks and restore backups if they exist.
        mode: 'git', 'agent', or 'all'
        """
        valid_modes = {"git", "stealth", "agent", "all", "dual"}
        mode_clean = (mode or "").lower().strip()
        if mode_clean not in valid_modes:
            raise ValueError(f"Invalid mode '{mode}'. Expected one of: {sorted(valid_modes)}")

        messages = []
        normalized_mode = "git" if mode_clean in ["git", "stealth"] else ("agent" if mode_clean == "agent" else "all")

        # Remove git hooks
        if normalized_mode in ["git", "all"]:
            for hook_name in ["pre-commit", "prepare-commit-msg"]:
                hook_file = self.git_hooks_dir / hook_name
                backup_file = self.git_hooks_dir / f"{hook_name}.guard.bak"

                if hook_file.exists():
                    content = hook_file.read_text(encoding="utf-8", errors="ignore")
                    whole = is_legacy_whole_file(content) or "BANH-MI-GUARD AUTO-GENERATED HOOK" in content \
                        or "BANH-MI-GUARD COMMIT MSG HOOK" in content
                    if not whole and strip_guard_parts(content) != content:
                        # the user's own hook with guard's lines in it (any version): only those lines go
                        hook_file.write_text(strip_guard_parts(content), encoding="utf-8", newline="\n")
                        messages.append(f"Removed guard's lines from {hook_file}")
                    elif not whole and mentions_guard(content):
                        messages.append(f"Left {hook_file} as it is: it names guard in a form guard did not write")
                    elif whole:
                        if is_legacy_whole_file(content):  # guard <= 0.10's file: a copy is kept, as on refresh
                            legacy_backup_path(hook_file).write_text(content, encoding="utf-8", newline="\n")
                        hook_file.unlink()
                        messages.append(f"Removed Guard hook: {hook_file}")

                        # Restore backup if available
                        if backup_file.exists():
                            backup_file.rename(hook_file)
                            messages.append(f"Restored previous hook backup from {backup_file}")

            # Clean stealth local exclude
            if self._remove_git_exclude():
                messages.append("Cleaned '.guard/' entry from local .git/info/exclude")

        # Remove agent wrapper and directives
        if normalized_mode in ["agent", "all"]:
            agent_file = self.guard_bin_dir / "guard-exec"
            if agent_file.exists():
                agent_file.unlink()
                messages.append(f"Removed Agent harness wrapper: {agent_file}")

            # Clean directives from CLAUDE.md & AGENT.md
            # Clean directives from CLAUDE.md & AGENT.md (Safe restore / preserve user content)
            start_marker, end_marker = DIRECTIVE_START, DIRECTIVE_END
            for doc_path in [self.claude_md_path, self.agent_md_path]:
                bak_path_new = doc_path.with_name(f"{doc_path.name}.guard.bak")
                bak_path_legacy = doc_path.with_suffix(".guard.bak")
                bak_path = bak_path_new if bak_path_new.exists() else bak_path_legacy
                if bak_path.exists():
                    doc_path.unlink(missing_ok=True)
                    bak_path.rename(doc_path)
                    if bak_path == bak_path_new and bak_path_legacy.exists():
                        bak_path_legacy.unlink(missing_ok=True)
                    messages.append(f"Restored previous {doc_path.name} from backup")
                elif doc_path.exists():
                    # a guard <= 0.10 block (both markers) is removed the same way as a current one
                    content = legacy_directive_to_current(doc_path.read_text(encoding="utf-8", errors="ignore"))
                    if start_marker in content and end_marker in content:
                        before = content.split(start_marker)[0].rstrip()
                        after = content.split(end_marker)[1].lstrip()
                        remaining = (before + "\n\n" + after).strip()
                        if remaining:
                            doc_path.write_text(remaining + "\n", encoding="utf-8")
                            messages.append(f"Cleaned Guard directives from {doc_path.name}, preserved user directives")
                        else:
                            doc_path.unlink()
                            messages.append(f"Removed Guard-generated {doc_path.name}")
                    elif "BANH-MI-GUARD" in content or content.strip() == AGENT_DIRECTIVES_TEMPLATE.strip():
                        doc_path.unlink()
                        messages.append(f"Removed Guard-generated {doc_path.name}")
        return True, messages

    def _write_hook_file(self, target_path: Path, script_content: str):
        # Backup existing hook if not created by Guard
        if target_path.exists():
            existing_content = target_path.read_text(encoding="utf-8", errors="ignore")
            if is_legacy_whole_file(existing_content):  # guard <= 0.10's own file: kept as a copy, never chained
                target_path.replace(legacy_backup_path(target_path))  # an earlier copy is never overwritten
            elif "BANH-MI-GUARD" not in existing_content:
                # the user's hook is chained as .guard.bak: without guard <= 0.10's lines, which would run guard again
                target_path.write_text(strip_legacy_parts(existing_content), encoding="utf-8", newline="\n")
                backup_path = target_path.with_suffix(".guard.bak")
                target_path.rename(backup_path)

        target_path.write_text(script_content, encoding="utf-8", newline="\n")  # sh scripts must be LF

        try:
            current_mode = target_path.stat().st_mode
            target_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except OSError:
            pass

    def _inject_directive(self, target_path: Path):
        directive_block = (
            f"\n\n{DIRECTIVE_START}\n"
            f"{AGENT_DIRECTIVES_TEMPLATE.strip()}\n"
            f"{DIRECTIVE_END}\n"
        )
        if target_path.exists():
            existing_content = target_path.read_text(encoding="utf-8", errors="ignore")
            if mentions_guard(existing_content):
                return  # Already injected, never duplicate (an old LAYA block is refreshed by guard hook refresh)

            # Backup original user directives before modifying
            backup_path = target_path.with_name(f"{target_path.name}.guard.bak")
            if not backup_path.exists():
                backup_path.write_text(existing_content, encoding="utf-8")

            # STRICT SAFE APPEND: Never overwrite user content!
            new_content = existing_content.rstrip() + directive_block
            target_path.write_text(new_content, encoding="utf-8")
        else:
            target_path.write_text(directive_block.strip() + "\n", encoding="utf-8")
