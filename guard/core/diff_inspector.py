"""
What a task changed, read from Git: the diff against the base commit, its per-file statistics, and
the glob matching that scope uses.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from guard.core.unified_diff import walk_diff


class FileDiffStat(BaseModel):
    path: str
    status: str  # "modified", "added", "deleted"
    insertions: int = 0
    deletions: int = 0
    is_out_of_scope: bool = False
    preexisting: bool = False  # Already dirty before pre-task and left unchanged by this task


class DiffSummary(BaseModel):
    files: List[FileDiffStat] = Field(default_factory=list)
    total_insertions: int = 0
    total_deletions: int = 0
    out_of_scope_files: List[str] = Field(default_factory=list)
    raw_diff: str = ""
    is_clean: bool = True
    error: Optional[str] = None


class GitDiffInspector:
    """
    Inspects local Git diffs and measures the exact Blast Radius of changes.
    """

    def __init__(self, repo_path: Optional[Path] = None):
        self.repo_path = repo_path or Path.cwd()
        self.last_error: Optional[str] = None

    def is_git_repo(self) -> bool:
        git_dir = self.repo_path / ".git"
        return git_dir.exists()

    def _run_git_diff(self, staged_only: bool, base_ref: Optional[str]) -> str:
        cmd = ["git", "-C", str(self.repo_path), "-c", "core.quotepath=false", "diff"]
        if staged_only:
            cmd.append("--staged")
        elif base_ref:
            cmd.append(base_ref)
        else:
            # Include both staged and unstaged (against HEAD if exists)
            cmd.append("HEAD")

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            if res.returncode == 0:
                self.last_error = None
                return res.stdout or ""
            # Diff command failed
            # Keep fallback to unstaged-only `git diff` only when there is no base_ref
            # and the repository has no commits.
            if not base_ref and not staged_only and self.get_head() is None:
                res2 = subprocess.run(
                    ["git", "-C", str(self.repo_path), "-c", "core.quotepath=false", "diff"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                )
                if res2.returncode == 0:
                    self.last_error = None
                    return res2.stdout or ""
                self.last_error = f"git diff failed (exit code {res2.returncode}): {res2.stderr or ''}".strip()
                return f"# [ERROR: {self.last_error}]\n"
            self.last_error = f"git diff failed (exit code {res.returncode}): {res.stderr or ''}".strip()
            return f"# [ERROR: {self.last_error}]\n"
        except (subprocess.SubprocessError, OSError) as e:
            self.last_error = f"git diff error: {e}"
            return f"# [ERROR: {self.last_error}]\n"

    def _synthetic_file_diff(self, uf: str) -> Optional[str]:
        if uf in [".gitignore", ".guard/session.json"] or uf.startswith(".guard/"):
            return None
        uf_path = self.repo_path / uf
        if not uf_path.is_file():
            return None
        try:
            content = uf_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
            synth = [
                f"diff --git a/{uf} b/{uf}",
                "new file mode 100644",
                "--- /dev/null",
                f"+++ b/{uf}",
                f"@@ -0,0 +1,{max(1, len(lines))} @@",
            ]
            for line in lines:
                synth.append(f"+{line}")
            return "\n".join(synth)
        except OSError as e:
            self.last_error = f"untracked file {uf} could not be read: {e}"
            synth = [
                f"diff --git a/{uf} b/{uf}",
                "new file mode 100644",
                "--- /dev/null",
                f"+++ b/{uf}",
                "@@ -0,0 +1,1 @@",
                f"+# [ERROR: unreadable untracked file: {e}]",
            ]
            return "\n".join(synth)

    def _collect_untracked_diffs(self) -> List[str]:
        # Append synthetic diffs for untracked files (so rules engine can inspect secrets/NPE)
        untracked = self.get_untracked_files()
        synthetic_diffs = []
        for uf in untracked:
            synth = self._synthetic_file_diff(uf)
            if synth is not None:
                synthetic_diffs.append(synth)
        return synthetic_diffs

    def get_diff(self, staged_only: bool = False, base_ref: Optional[str] = None) -> str:
        """
        Extract raw diff from Git, including synthetic diffs for untracked files.
        Always returns a valid string (never None).
        Safely decodes UTF-8 to prevent charmap/UnicodeDecodeError on Windows.
        """
        self.last_error = None
        if not self.is_git_repo():
            return ""

        diff_output = self._run_git_diff(staged_only=staged_only, base_ref=base_ref)
        synthetic_diffs = self._collect_untracked_diffs()

        if synthetic_diffs:
            if diff_output:
                diff_output += "\n" + "\n".join(synthetic_diffs)
            else:
                diff_output = "\n".join(synthetic_diffs)

        return diff_output or ""

    def _porcelain_entries(self) -> List[tuple]:
        """
        (XY status, path) for every changed file. `-z` gives raw, unquoted paths (spaces, unicode)
        and reports renames as `new NUL old`; `-uall` lists files inside new directories.
        """
        if not self.is_git_repo():
            return []
        try:
            res = subprocess.run(
                ["git", "-C", str(self.repo_path), "status", "--porcelain", "-z", "-uall"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            if res.returncode != 0:
                self.last_error = f"git status failed (exit code {res.returncode}): {res.stderr or ''}".strip()
                return []
        except (subprocess.SubprocessError, OSError) as e:
            self.last_error = f"git status error: {e}"
            return []
        parts = (res.stdout or "").split("\0")
        entries = []
        i = 0
        while i < len(parts):
            item = parts[i]
            i += 1
            if len(item) < 4:
                continue
            xy, path = item[:2], item[3:]
            if "R" in xy or "C" in xy:
                i += 1  # skip the original path of a rename/copy
            entries.append((xy, path))
        return entries

    def get_untracked_files(self) -> List[str]:
        return [path for xy, path in self._porcelain_entries() if xy == "??"]

    def get_working_files(self) -> List[str]:
        """
        Returns all files currently touched in the working directory (staged, modified, or untracked).
        """
        from guard.core.untracked_names import is_guard_dir
        # only guard's own .guard/ directory is left out: .guardian/ is the user's
        return [
            path for _, path in self._porcelain_entries()
            if not is_guard_dir(path) and path != ".gitignore"
        ]

    def create_baseline_snapshot(self) -> Optional[str]:
        """
        Commit object of the current dirty tracked state, without touching the working tree or
        index (`git stash create`). Pinned under refs/guard/baseline so gc cannot prune it.
        """
        try:
            res = subprocess.run(
                ["git", "-C", str(self.repo_path), "stash", "create", "guard pre-task baseline"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
            )
            sha = (res.stdout or "").strip()
            if not sha:
                if res.returncode != 0:
                    self.last_error = f"git stash create failed (exit code {res.returncode}): {res.stderr or ''}".strip()
                return None
            res_ref = subprocess.run(
                ["git", "-C", str(self.repo_path), "update-ref", "refs/guard/baseline", sha],
                capture_output=True, check=False,
            )
            if res_ref.returncode != 0:
                self.last_error = f"git update-ref failed (exit code {res_ref.returncode})"
                return None
            return sha
        except (subprocess.SubprocessError, OSError) as e:
            self.last_error = f"create_baseline_snapshot error: {e}"
            return None

    def snapshot_worktree(self) -> Optional[str]:
        """
        Commit object (parent HEAD) of the whole working tree, untracked files included and
        ignored ones (.guard/) left out, built in a throwaway index: the user's index, working
        tree and refs are not touched. None without a HEAD commit.
        """
        head = self.get_head()
        if not head:
            return None
        fd, index = tempfile.mkstemp(prefix="guard-index-")
        os.close(fd)
        env = {**os.environ, "GIT_INDEX_FILE": index}
        git = ["git", "-C", str(self.repo_path)]
        try:
            for args in (["read-tree", head], ["add", "-A"]):
                if subprocess.run(git + args, env=env, capture_output=True, check=False).returncode != 0:
                    return None
            tree = subprocess.run(git + ["write-tree"], env=env, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", check=False).stdout.strip()
            ident = {"GIT_AUTHOR_NAME": "guard", "GIT_AUTHOR_EMAIL": "guard@localhost",
                     "GIT_COMMITTER_NAME": "guard", "GIT_COMMITTER_EMAIL": "guard@localhost"}
            res = subprocess.run(git + ["commit-tree", tree, "-p", head, "-m", "guard review snapshot"],
                                 env={**os.environ, **ident}, capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", check=False)
            return res.stdout.strip() or None
        except OSError:
            return None
        finally:
            Path(index).unlink(missing_ok=True)

    def get_head(self) -> Optional[str]:
        try:
            res = subprocess.run(
                ["git", "-C", str(self.repo_path), "rev-parse", "--verify", "-q", "HEAD"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
            )
            return res.stdout.strip() or None
        except (subprocess.SubprocessError, OSError):
            return None

    def parse_diff(self, raw_diff: Optional[str], expected_files: Optional[List[str]] = None) -> DiffSummary:
        """
        Parse raw git diff string into structured FileDiffStat and detect out-of-scope changes.
        """
        diff_text = raw_diff or ""
        error_msg = None
        for line in diff_text.splitlines():
            if line.startswith("# [ERROR:"):
                error_msg = line.removeprefix("# [ERROR:").removesuffix("]").strip()
                break
        if not error_msg and self.last_error:
            error_msg = self.last_error

        if not diff_text.strip():
            return DiffSummary(files=[], raw_diff="", is_clean=not bool(error_msg), error=error_msg)

        files_map: Dict[str, FileDiffStat] = {}
        current_file: Optional[str] = None

        for d in walk_diff(diff_text):
            if d.kind == "file":
                current_file = d.path or None
                if current_file:
                    files_map[current_file] = FileDiffStat(path=current_file, status="modified")
            elif not current_file:
                continue
            elif d.raw.startswith("new file mode"):
                files_map[current_file].status = "added"
            elif d.raw.startswith("deleted file mode"):
                files_map[current_file].status = "deleted"
            elif d.kind == "+":
                files_map[current_file].insertions += 1
            elif d.kind == "-":
                files_map[current_file].deletions += 1

        stats_list = list(files_map.values())
        tot_ins = sum(s.insertions for s in stats_list)
        tot_del = sum(s.deletions for s in stats_list)

        out_of_scope: List[str] = []
        if expected_files is not None:
            for stat in stats_list:
                if not self._is_expected(stat.path, expected_files):
                    stat.is_out_of_scope = True
                    out_of_scope.append(stat.path)

        return DiffSummary(
            files=stats_list,
            total_insertions=tot_ins,
            total_deletions=tot_del,
            out_of_scope_files=out_of_scope,
            raw_diff=diff_text,
            is_clean=len(stats_list) == 0 and not bool(error_msg),
            error=error_msg,
        )

    def _is_expected(self, file_path: str, expected_files: List[str]) -> bool:
        """
        Match on path boundaries only: exact path, bare filename, directory prefix, or glob.
        (Suffix matching would let `a.ts` cover `src/data.ts`.)
        """
        fp_norm = file_path.replace("\\", "/").lower()
        # System & Guard files are always allowed
        if fp_norm in [".gitignore", ".guard/session.json"] or fp_norm.startswith(".guard/"):
            return True
        basename = fp_norm.rsplit("/", 1)[-1]
        for exp in expected_files:
            exp_norm = exp.replace("\\", "/").lower()
            if exp_norm.startswith("./"):
                exp_norm = exp_norm[2:]
            if not exp_norm:
                continue
            # Literal match first, so paths like `app/[id]/page.tsx` still match themselves
            if fp_norm == exp_norm or fp_norm.startswith(exp_norm.rstrip("/") + "/"):
                return True
            if "/" not in exp_norm and basename == exp_norm:
                return True
            if any(ch in exp_norm for ch in "*?[") and glob_to_regex(exp_norm).match(fp_norm):
                return True
        return False


def glob_to_regex(pattern: str) -> "re.Pattern[str]":
    """Path glob: `*`/`?` stay inside one directory, `**` spans directories, `[...]` is a class."""
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[" and "]" in pattern[i + 1:]:
            j = pattern.index("]", i + 1)
            out.append("[" + pattern[i + 1:j].replace("\\", "\\\\") + "]")
            i = j + 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("".join(out) + r"(?:/.*)?$")
