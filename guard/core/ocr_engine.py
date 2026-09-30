"""
Alibaba OCR CLI review (`ocr review`, LLM-based) of the task's changes, and its cache of files already
reviewed. The Git diff inspector lives in guard.core.diff_inspector and the deterministic rulebook in
guard.core.rulebook; their names stay importable from here.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

from guard.core.diff_inspector import DiffSummary, FileDiffStat, GitDiffInspector, glob_to_regex  # noqa: F401  (moved; importers keep this path)
from guard.core.rulebook import OCRRulebookRunner, RuleViolation, _unsafe_html_sinks  # noqa: F401  (moved; importers keep this path)


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
    on_snapshot=None,
    cache_key: Optional[str] = None,
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
    if on_snapshot:  # the reviewed tree is fixed now: work that writes files (a build) may start
        on_snapshot()
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
    # Files unchanged since an earlier complete review (same content, LLM, OCR version and base) are
    # not reviewed again: their cached findings are merged and OCR is told to leave them out
    fps = _reviewed_fingerprints(repo_path, base_ref, snapshot, skip_files) if cache_key and base_ref and snapshot else {}
    cache = _load_cache(guard_dir, cache_key) if fps else {}
    reused = {path: cache[path] for path, fp in fps.items()
              if isinstance(cache.get(path), dict) and cache[path].get("fp") == fp and "," not in path}
    cached = [RuleViolation(**v) for entry in reused.values() for v in entry.get("findings") or [] if isinstance(v, dict)]
    if fps and len(reused) == len(fps):
        return (f"complete: {len(cached)} finding(s); all {len(reused)} file(s) reused from earlier reviews "
                "(unchanged since)"), cached
    fd, name = tempfile.mkstemp(dir=guard_dir, prefix="ocr-review-", suffix=".json")
    os.close(fd)
    out_file = Path(name)
    try:
        line, violations = _run_ocr(ocr_bin, repo_path, out_file, base_ref, snapshot, background, skip_files,
                                    concurrency, failed, exclude=sorted(reused))
        if fps and line.startswith("complete") and not any(v.rule_id == "OCR-RUN" for v in violations):
            covered = _covered_paths(out_file)
            fresh = {path: {"fp": fps[path], "findings": [v.model_dump() for v in violations if v.file_path == path]}
                     for path in fps if path in covered and path not in reused}
            _save_cache(guard_dir, cache_key, {**reused, **fresh})  # files no longer in the task are dropped
        if reused:
            line += f"; {len(reused)} file(s) reused from earlier reviews (unchanged since)"
        return line, cached + violations
    finally:
        if out_file.exists():
            os.replace(out_file, guard_dir / "ocr-review.json")


OCR_CACHE = "ocr-cache.json"


def _reviewed_fingerprints(repo_path: Path, base_ref: str, snapshot: str, skip_files) -> dict:
    """{path: blob id at the snapshot, or "deleted"} for every file the review covers."""
    git = ["git", "-C", str(repo_path)]
    names = subprocess.run(git + ["diff", "--name-only", "-z", base_ref, snapshot], capture_output=True, check=False)
    if names.returncode != 0:
        return {}
    skip = set(skip_files or [])
    paths = [n.decode("utf-8", "surrogateescape") for n in names.stdout.split(b"\0") if n]
    paths = [path for path in paths if path not in skip]
    tree = subprocess.run(git + ["ls-tree", "-r", "-z", snapshot], capture_output=True, check=False)
    blobs = {}
    for entry in tree.stdout.split(b"\0"):
        meta, _, name = entry.partition(b"\t")
        if name:
            blobs[name.decode("utf-8", "surrogateescape")] = meta.split()[-1].decode("ascii", "replace")
    return {path: blobs.get(path, "deleted") for path in paths}


def _covered_paths(out_file: Path) -> set:
    """Paths OCR's coverage says it reviewed (completed, reused or waived); nothing when unreadable."""
    try:
        coverage = json.loads(out_file.read_text(encoding="utf-8")).get("manifest", {}).get("coverage", {})
    except (OSError, ValueError, AttributeError):
        return set()
    return {i["path"] for k in ("completed", "reused", "waived") for i in coverage.get(k) or []
            if isinstance(i, dict) and isinstance(i.get("path"), str)}


def _load_cache(guard_dir: Path, key: Optional[str]) -> dict:
    try:
        data = json.loads((guard_dir / OCR_CACHE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or data.get("key") != key or not isinstance(data.get("files"), dict):
        return {}  # another LLM, OCR version or base: nothing is reused
    return data["files"]


def _save_cache(guard_dir: Path, key: Optional[str], files: dict) -> None:
    try:
        tmp = guard_dir / (OCR_CACHE + ".tmp")
        tmp.write_text(json.dumps({"key": key, "files": files}), encoding="utf-8")
        os.replace(tmp, guard_dir / OCR_CACHE)
    except OSError:
        pass  # only means the next review covers these files again


def _run_ocr(ocr_bin, repo_path, out_file, base_ref, snapshot, background, skip_files, concurrency, failed, exclude=()):
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
    if exclude:  # files whose earlier review is reused: anchored, literal gitignore patterns
        from guard.core.untracked_names import pattern
        cmd += ["--exclude", ",".join(pattern(path) for path in exclude)]

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
