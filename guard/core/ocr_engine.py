"""
Alibaba Open Code Review (OCR) Engine & Git Diff Inspector.
Provides:
1. Deterministic Git Diff Parsing (added/modified/deleted files, +/- line counts)
2. Blast Radius & Out-of-Scope File Audit
3. Built-in Multi-Language OCR Rulebook Runner (Secrets, NPE, Memory Leaks, SQLi, XSS, Sync I/O)
4. Alibaba OCR CLI review (`ocr review`, LLM-based) of the task's changes
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field


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


class RuleViolation(BaseModel):
    rule_id: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    file_path: str
    line_number: Optional[int] = None
    message: str
    snippet: str = ""


class GitDiffInspector:
    """
    Inspects local Git diffs and measures the exact Blast Radius of changes.
    """

    def __init__(self, repo_path: Optional[Path] = None):
        self.repo_path = repo_path or Path.cwd()

    def is_git_repo(self) -> bool:
        git_dir = self.repo_path / ".git"
        return git_dir.exists()

    def get_diff(self, staged_only: bool = False, base_ref: Optional[str] = None) -> str:
        """
        Extract raw diff from Git, including synthetic diffs for untracked files.
        Always returns a valid string (never None).
        Safely decodes UTF-8 to prevent charmap/UnicodeDecodeError on Windows.
        """
        if not self.is_git_repo():
            return ""

        cmd = ["git", "-C", str(self.repo_path), "-c", "core.quotepath=false", "diff"]
        if staged_only:
            cmd.append("--staged")
        elif base_ref:
            cmd.append(base_ref)
        else:
            # Include both staged and unstaged (against HEAD if exists)
            cmd.append("HEAD")

        diff_output = ""
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            if res.returncode == 0 and res.stdout:
                diff_output = res.stdout
            else:
                res2 = subprocess.run(
                    ["git", "-C", str(self.repo_path), "-c", "core.quotepath=false", "diff"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                )
                diff_output = res2.stdout or ""
        except Exception:
            diff_output = ""

        diff_output = diff_output or ""

        # Append synthetic diffs for untracked files (so rules engine can inspect secrets/NPE)
        untracked = self.get_untracked_files()
        synthetic_diffs = []
        for uf in untracked:
            if uf in [".gitignore", ".guard/session.json"] or uf.startswith(".guard/"):
                continue
            uf_path = self.repo_path / uf
            if uf_path.is_file():
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
                    for l in lines:
                        synth.append(f"+{l}")
                    synthetic_diffs.append("\n".join(synth))
                except Exception:
                    pass

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
        except Exception:
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
                return None
            subprocess.run(
                ["git", "-C", str(self.repo_path), "update-ref", "refs/guard/baseline", sha],
                capture_output=True, check=False,
            )
            return sha
        except Exception:
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
            tree = subprocess.run(git + ["write-tree"], env=env, capture_output=True, text=True, check=False).stdout.strip()
            ident = {"GIT_AUTHOR_NAME": "guard", "GIT_AUTHOR_EMAIL": "guard@localhost",
                     "GIT_COMMITTER_NAME": "guard", "GIT_COMMITTER_EMAIL": "guard@localhost"}
            res = subprocess.run(git + ["commit-tree", tree, "-p", head, "-m", "guard review snapshot"],
                                 env={**os.environ, **ident}, capture_output=True, text=True, check=False)
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
        except Exception:
            return None

    def parse_diff(self, raw_diff: Optional[str], expected_files: Optional[List[str]] = None) -> DiffSummary:
        """
        Parse raw git diff string into structured FileDiffStat and detect out-of-scope changes.
        """
        diff_text = raw_diff or ""
        if not diff_text.strip():
            return DiffSummary(files=[], raw_diff="", is_clean=True)

        files_map: Dict[str, FileDiffStat] = {}
        current_file: Optional[str] = None
        current_status = "modified"

        for line in diff_text.splitlines():
            if line.startswith("diff --git"):
                match = re.search(r"diff --git a/(.*) b/(.*)", line)
                if match:
                    current_file = match.group(2)
                    current_status = "modified"
                    files_map[current_file] = FileDiffStat(path=current_file, status=current_status)
            elif line.startswith("new file mode") and current_file:
                files_map[current_file].status = "added"
            elif line.startswith("deleted file mode") and current_file:
                files_map[current_file].status = "deleted"
            elif line.startswith("+") and not line.startswith("+++") and current_file:
                files_map[current_file].insertions += 1
            elif line.startswith("-") and not line.startswith("---") and current_file:
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
            is_clean=len(stats_list) == 0,
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


def _unsafe_html_sinks(code: str) -> int:
    """
    Count innerHTML / outerHTML assignments on one line whose value is not provably safe.
    Safe values: an empty literal, or a value that is exactly one DOMPurify.sanitize(...) call.
    """
    code = re.sub(r"\s//.*$", "", code)  # drop trailing line comment
    unsafe = 0
    for m in re.finditer(r"\b(?:inner|outer)HTML\s*\+?=(?!=)", code):
        rhs = code[m.end():]
        # value runs until the first `;` that is not inside a string or parentheses
        depth, quote, end = 0, "", len(rhs)
        for k, ch in enumerate(rhs):
            if quote:
                if ch == quote and rhs[k - 1] != "\\":
                    quote = ""
            elif ch in "'\"`":
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == ";" and depth <= 0:
                end = k
                break
        value = rhs[:end].strip()
        if re.fullmatch(r"(['\"`])\1", value):
            continue
        call = re.match(r"DOMPurify\.sanitize\(", value)
        if call:
            depth = 0
            for k, ch in enumerate(value[call.end() - 1:], start=call.end() - 1):
                depth += ch == "("
                depth -= ch == ")"
                if depth == 0:
                    if not value[k + 1:].strip():
                        break
                    unsafe += 1
                    break
            continue
        unsafe += 1
    return unsafe


class OCRRulebookRunner:
    """
    Multi-language deterministic static rules engine matching Alibaba OCR patterns.
    Operates at 0 cost, 0 latency across 5 Quality Pillars.
    """

    # Pillar: Security - Hardcoded Secrets
    SECRET_REGEX = re.compile(
        r"""(?i)(api[_-]?key|secret|token|password|auth[_-]?token|private[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-\.]{12,})["']"""
    )
    # Pillar: Security - SQL Injection string concatenation
    SQLI_REGEX = re.compile(
        r"""(?i)(select\b.+?\bfrom\b|insert\s+into\b|update\b.+?\bset\b|delete\s+from\b).+?["']\s*\+\s*[a-zA-Z_]"""
    )
    # Pillar: Security - Cross-Site Scripting (XSS)
    XSS_REGEX = re.compile(
        r"""(?i)(dangerouslySetInnerHTML\s*=|(?:inner|outer)HTML\s*\+?=(?!=)|\bv-html\s*=)"""
    )
    # Explicit, reviewable suppression: `// guard-allow SEC-003: <reason>` on the same line
    SUPPRESS_REGEX = re.compile(r"guard-allow\s+([A-Z]+-\d+)\s*:\s*(\S.*)")
    # Pillar: Memory Safety - Dangling Listener without remover in component
    DANGLING_LISTENER = re.compile(
        r"""addEventListener\s*\(["'](resize|scroll|mousemove|keydown)["']"""
    )
    # Pillar: Stability - Deep property dereference without optional chaining
    NULL_DEREF = re.compile(
        r"""(?i)(data|res|response|user|item)\.([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)"""
    )
    # Pillar: Performance - Blocking synchronous I/O on async event loop
    BLOCKING_SYNC_IO = re.compile(
        r"""\b(readFileSync|writeFileSync|execSync|spawnSync)\b"""
    )

    def scan_diff(self, raw_diff: Optional[str]) -> List[RuleViolation]:
        diff_text = raw_diff or ""
        violations: List[RuleViolation] = []
        current_file = "unknown"
        line_num = 0

        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()
                line_num = 0
                continue
            if line.startswith("@@"):
                match = re.search(r"\+(\d+)", line)
                if match:
                    line_num = int(match.group(1)) - 1
                continue

            if line.startswith("+") and not line.startswith("+++"):
                line_num += 1
                added_code = line[1:].strip()

                cf_lower = current_file.replace("\\", "/").lower()
                is_doc_file = any(cf_lower.endswith(ext) for ext in [".md", ".markdown", ".txt", ".rst"])
                is_test_file = "tests/" in cf_lower or "test_" in cf_lower
                is_js_ts = any(cf_lower.endswith(ext) for ext in [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"])

                # Rule 1: Hardcoded Secrets (Security - Always scanned on ALL files)
                if self.SECRET_REGEX.search(added_code):
                    # Exclude sample dummy tokens in test files or docs
                    if not (is_test_file and "sk_live_9988776655" in added_code):
                        violations.append(RuleViolation(
                            rule_id="SEC-001",
                            severity="CRITICAL",
                            file_path=current_file,
                            line_number=line_num,
                            message="Potential hardcoded secret or API key detected in code addition.",
                            snippet=added_code[:80],
                        ))

                # Rules 2-6 only apply to actual application source code (not doc markdown files)
                if is_doc_file:
                    continue

                # Rule 2: SQL Injection concatenation (Security)
                if self.SQLI_REGEX.search(added_code) and not is_test_file:
                    violations.append(RuleViolation(
                        rule_id="SEC-002",
                        severity="CRITICAL",
                        file_path=current_file,
                        line_number=line_num,
                        message="SQL string concatenation detected. Use parameterized queries/ORM.",
                        snippet=added_code[:80],
                    ))

                # Rule 3: Cross-Site Scripting (XSS) (Security)
                # A comment mentioning "sanitize" no longer exempts the line; only a provably safe
                # value or an explicit `guard-allow SEC-003: reason` marker does (reported as LOW).
                if self.XSS_REGEX.search(added_code) and not is_test_file and (
                    re.search(r"dangerouslySetInnerHTML|\bv-html", added_code, re.IGNORECASE)
                    or _unsafe_html_sinks(added_code) > 0
                ):
                    suppress = self.SUPPRESS_REGEX.search(added_code)
                    if suppress and suppress.group(1) == "SEC-003":
                        violations.append(RuleViolation(
                            rule_id="SEC-003",
                            severity="LOW",
                            file_path=current_file,
                            line_number=line_num,
                            message=f"innerHTML sink suppressed by author: {suppress.group(2).strip()[:120]}",
                            snippet=added_code[:80],
                        ))
                    else:
                        violations.append(RuleViolation(
                            rule_id="SEC-003",
                            severity="HIGH",
                            file_path=current_file,
                            line_number=line_num,
                            message="Raw HTML injection detected (dangerouslySetInnerHTML / innerHTML / v-html). Use textContent, DOMPurify.sanitize(), or mark `// guard-allow SEC-003: <reason>`.",
                            snippet=added_code[:80],
                        ))

                # Rule 4: Memory leak / Dangling Event Listener (Memory Safety)
                if self.DANGLING_LISTENER.search(added_code) and "removeEventListener" not in diff_text and not is_test_file:
                    violations.append(RuleViolation(
                        rule_id="PERF-001",
                        severity="HIGH",
                        file_path=current_file,
                        line_number=line_num,
                        message="Global window/document event listener added without cleanup remover.",
                        snippet=added_code[:80],
                    ))

                # Rule 5: Blocking Synchronous I/O on Event Loop (Performance - Only in JS/TS environments)
                if is_js_ts and self.BLOCKING_SYNC_IO.search(added_code) and not is_test_file:
                    violations.append(RuleViolation(
                        rule_id="PERF-002",
                        severity="MEDIUM",
                        file_path=current_file,
                        line_number=line_num,
                        message="Blocking synchronous I/O detected on thread. Prefer async/await non-blocking operations.",
                        snippet=added_code[:80],
                    ))

                # Rule 6: Deep property dereference without optional chaining (Stability)
                if self.NULL_DEREF.search(added_code) and "?." not in added_code and not is_test_file:
                    violations.append(RuleViolation(
                        rule_id="STAB-001",
                        severity="MEDIUM",
                        file_path=current_file,
                        line_number=line_num,
                        message="Deep object access without optional chaining (?.) may cause Null Pointer / TypeError.",
                        snippet=added_code[:80],
                    ))

        return violations


OCR_SEVERITY = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "LOW"}
# Terminal statuses OCR reports as a successful review (its IDE extension treats completed_with_errors,
# partial and failed as failures, and so does guard, together with any status it does not know)
OCR_SUCCESS = {"success", "complete", "completed_with_warnings", "skipped"}
OCR_REQUEST_TIMEOUT_S = 10 * 365 * 24 * 3600


def _complete(data: dict, returncode: int = 0) -> bool:
    """
    A successful status, exit code 0 and coverage evidence that every file OCR selected was reviewed
    (completed, reused or waived) and none failed: a warning status can still list failed files.
    A result without readable coverage (manifest.coverage) is not accepted as a review.
    """
    manifest = data.get("manifest")
    coverage = manifest.get("coverage") if isinstance(manifest, dict) else None
    status = data.get("status")
    if status == "skipped" and returncode == 0:  # OCR reviewed nothing on purpose; reported as skipped
        return True
    if not isinstance(coverage, dict):
        return False
    # "selected" and "completed" must be present: a missing list is no evidence, not an empty one
    if not all(isinstance(coverage.get(k), list) for k in ("selected", "completed")):
        return False
    lists = {k: coverage.get(k) or [] for k in ("selected", "completed", "reused", "waived", "failed")}
    if not lists["selected"]:  # a review of a non-empty diff selected nothing
        return False

    def valid_item(i):  # every coverage entry must say which item it is
        return isinstance(i, dict) and isinstance(i.get("item_id") or i.get("path"), str)

    if not all(isinstance(v, list) and all(valid_item(i) for i in v) for v in lists.values()):
        return False

    def ids(items):
        return {i.get("item_id") or i.get("path") for i in items}

    reviewed = ids(lists["completed"]) | ids(lists["reused"]) | ids(lists["waived"])
    return (returncode == 0 and isinstance(status, str) and status in OCR_SUCCESS
            and not lists["failed"] and ids(lists["selected"]) <= reviewed)


def run_ocr_review(
    repo_path: Path,
    base_ref: Optional[str],
    background: str,
    skip_files: Optional[List[str]] = None,
    binary: str = "ocr",
    concurrency: int = 0,
) -> Tuple[str, List[RuleViolation]]:
    """
    Review the task's changes with Alibaba OCR (`ocr review`, an LLM review) and return
    (status line, violations). The range is base_ref..snapshot of the working tree, so mid-task
    commits, unstaged and untracked files are all reviewed. OCR not running is an OCR-RUN HIGH
    violation, never a silent pass. There is no time limit: AI review takes as long as it takes, it
    ends when OCR finishes or reports the provider's error, and only the user stops it (Ctrl+C). Findings on `skip_files` (pre-existing changes) are dropped.
    """
    def failed(reason: str) -> Tuple[str, List[RuleViolation]]:
        reason = reason.rstrip(". ")
        return f"did not run: {reason}", [RuleViolation(
            rule_id="OCR-RUN", severity="HIGH", file_path="(ocr)",
            message=f"Alibaba OCR review did not run: {reason}. Fix the cause above (for a provider or configuration error: guard config sync, then ocr llm test) and run guard post --full again.",
        )]

    ocr_bin = shutil.which(binary)
    if not ocr_bin:
        return failed(f"'{binary}' not found on PATH (npm install -g @alibaba-group/open-code-review)")
    inspector = GitDiffInspector(repo_path)
    snapshot = inspector.snapshot_worktree()
    # Without the exact base..current range OCR would review only its default diff and miss the
    # task's commits: that is not a review of the task. Only a repository without any commit yet
    # (everything uncommitted) is fully covered by OCR's workspace mode.
    if base_ref and not snapshot:
        return failed("the working tree could not be snapshotted, so base..current changes cannot be reviewed")
    if not base_ref and inspector.get_head():
        return failed("no base commit was recorded at pre, so the task's commits cannot be reviewed")
    # OCR diffs from the merge-base: after a rebase or reset past the base it would review another change set
    if base_ref and snapshot and subprocess.run(
        ["git", "-C", str(repo_path), "merge-base", "--is-ancestor", base_ref, snapshot], capture_output=True, check=False,
    ).returncode != 0:
        return failed("the base commit recorded at pre is no longer an ancestor of the working tree (history was rewritten)")
    guard_dir = repo_path / ".guard"
    guard_dir.mkdir(parents=True, exist_ok=True)
    # Each run writes its own file (concurrent posts never read each other's result); the last one
    # is kept as .guard/ocr-review.json for inspection
    fd, name = tempfile.mkstemp(dir=guard_dir, prefix="ocr-review-", suffix=".json")
    os.close(fd)
    out_file = Path(name)
    try:
        return _run_ocr(ocr_bin, repo_path, out_file, base_ref, snapshot, background, skip_files, concurrency, failed)
    finally:
        if out_file.exists():
            os.replace(out_file, guard_dir / "ocr-review.json")


def _run_ocr(ocr_bin, repo_path, out_file, base_ref, snapshot, background, skip_files, concurrency, failed):
    # --timeout 0: OCR's own per-group limit (15 min by default) is off. Its per-request HTTP limit
    # cannot be switched off (0 means its 300 s default), so it is set to ten years: no limit in practice.
    cmd = [ocr_bin, "review", "--repo", str(repo_path), "--format", "json", "--audience", "agent",
           "--color", "never", "-o", str(out_file), "--background", background, "--timeout", "0"]
    env = {**os.environ, "OCR_LLM_TIMEOUT": str(OCR_REQUEST_TIMEOUT_S)}  # never a shorter value from the environment
    ranged = bool(base_ref and snapshot)
    if ranged:
        cmd += ["--from", base_ref, "--to", snapshot]
    if concurrency > 0:
        cmd += ["--concurrency", str(concurrency)]

    data: dict = {}
    for attempt in range(2):
        # A partial review (the provider failed on some files) is resumed once: only failed items rerun
        sid = data.get("session_id") if attempt else None
        resume = ["--resume", sid] if isinstance(sid, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", sid) else []
        # OCR refuses --resume without --from/--to ("workspace resume is not supported"), so only a
        # ranged review is resumed; an unresumable partial review stays a blocking OCR-RUN
        if attempt and not (ranged and resume):
            break
        out_file.unlink(missing_ok=True)
        try:
            # The result goes to out_file; stdout is not kept, stderr only for the failure reason
            res = subprocess.run(cmd + resume, cwd=str(repo_path), env=env, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
        except OSError as e:
            return failed(str(e))
        try:
            data = json.loads(out_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            tail = (res.stderr or "").strip()[-300:]
            return failed(f"exit code {res.returncode}, no JSON result ({tail or 'no output'})")
        # "comments" must be present: a list of findings, or null (OCR writes null when there are none)
        if not isinstance(data, dict) or "comments" not in data or not isinstance(data["comments"] or [], list):
            return failed("OCR returned a result guard cannot read (unexpected JSON shape)")
        if _complete(data, res.returncode):
            break
    skip = set(skip_files or [])
    violations = []
    dropped = 0
    for c in data.get("comments") or []:
        line_no = c.get("start_line") if isinstance(c, dict) else None
        if (not isinstance(c, dict) or not isinstance(c.get("path"), (str, type(None)))
                or not (line_no is None or (isinstance(line_no, int) and not isinstance(line_no, bool)))):
            return failed("OCR returned a finding guard cannot read (unexpected JSON shape)")
        if c.get("path") in skip:  # dirty before pre and not touched by this task since
            dropped += 1
            continue
        raw = str(c.get("severity") or "").lower()
        message = str(c.get("content") or "").strip()[:600]
        if raw not in OCR_SEVERITY:  # a finding without a known severity is not assumed harmless
            message = f"(OCR gave no known severity: {raw or 'none'}) {message}"
        violations.append(RuleViolation(
            rule_id=f"OCR-{str(c.get('category') or 'finding').upper()}",
            severity=OCR_SEVERITY.get(raw, "HIGH"),
            file_path=c.get("path") or "(unknown)",
            line_number=c.get("start_line"),
            message=message,
            snippet=str(c.get("existing_code") or "")[:120],
        ))
    status = data.get("status")
    if not _complete(data, res.returncode):  # partial, failed, with errors or unknown: blocks, but findings are still reported
        line, run_violation = failed(str(data.get("message") or f"status {status}"))
        return line, run_violation + violations
    if status == "skipped":
        return "complete: OCR reported status skipped (it reviewed no file)", violations
    llm = data.get("llm") if isinstance(data.get("llm"), dict) else {}
    note = f"; {dropped} finding(s) dropped: on files dirty before pre and unchanged by this task" if dropped else ""
    # Coverage is the evidence of a finished review; failed tool calls while exploring are only shown
    tool_calls = data.get("tool_calls") if isinstance(data.get("tool_calls"), dict) else {}
    if isinstance(tool_calls.get("failure"), int) and tool_calls["failure"] > 0:
        note += f"; {tool_calls['failure']} of {tool_calls.get('total', '?')} OCR tool call(s) failed while exploring"
    return f"complete: {len(violations)} finding(s) (model {llm.get('model', '?')}, status {status}){note}", violations
