"""
Alibaba OCR's delegation mode answered by the agent CLI: the fallback when OCR through the agent
bridge does not run. `ocr delegate` lists the files OCR would review and its rules for each; guard
sends each rule group's diff with those rules to the agent in one prompt (its tools stay off) and
reads the findings back in OCR's comment shape. A file not reviewed is never a full review.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from guard.core.cli_llm import CLILLMError
from guard.core.diff_inspector import GitDiffInspector
from guard.core.ocr_bridge import _first_object
from guard.core.ocr_engine import ocr_comment_violation, ocr_failed
from guard.core.rulebook import RuleViolation

MAX_PROMPT_CHARS = 150_000  # diff text per prompt; files are packed into prompts up to this size
CONTEXT_LINES = 20  # unchanged lines around each change: the agent cannot open files itself
COMMAND_TIMEOUT_S = 300  # `ocr delegate` and `git diff` read the repository only

RULES = """You review a code change for a code review program, using the review rules and the
background below. Report only real problems in the changed lines or caused by them. Answer with exactly
one JSON object and nothing else:
{"comments": [{"path": "<file path as shown in the diff>", "start_line": <line number in the new file>,
"severity": "critical|high|medium|low", "category": "<one word: bug, security, performance, maintainability...>",
"content": "<the problem and how to fix it>"}]}
Answer {"comments": []} when there is nothing to report."""


def _run(cmd: List[str], repo_path: Path) -> str:
    res = subprocess.run(cmd, cwd=str(repo_path), capture_output=True, text=True, encoding="utf-8",
                         errors="replace", timeout=COMMAND_TIMEOUT_S, check=False)
    if res.returncode != 0:
        raise ValueError(f"{' '.join(cmd[1:3])} exited with {res.returncode}: {' '.join((res.stderr or res.stdout).split())[:300]}")
    return res.stdout


def _ocr_json(cmd: List[str], repo_path: Path) -> dict:
    data = json.loads(_run(cmd, repo_path) or "null")
    if not isinstance(data, dict):
        raise ValueError(f"{' '.join(cmd[1:3])} returned no JSON object")
    return data


def _prompts(groups: List[Tuple[str, List[str]]], diffs: dict) -> Tuple[List[Tuple[str, List[str]]], List[str]]:
    """
    (rule, files) per prompt, each with at most MAX_PROMPT_CHARS of diff, and the files that cannot be
    sent: no diff (nothing the agent could review) or a diff too large for one prompt.
    """
    prompts, unsent = [], []
    for rule, files in groups:
        batch, size = [], 0
        for path in files:
            n = len(diffs[path].strip())
            if not n or n > MAX_PROMPT_CHARS:
                unsent.append(path)
                continue
            if batch and size + n > MAX_PROMPT_CHARS:
                prompts.append((rule, batch))
                batch, size = [], 0
            batch.append(path)
            size += n
        if batch:
            prompts.append((rule, batch))
    return prompts, unsent


def run_delegate_review(
    repo_path: Path,
    base_ref: Optional[str],
    background: str,
    skip_files: Optional[List[str]],
    binary: str,
    ask: Callable[[str, str], str],
) -> Tuple[str, List[RuleViolation]]:
    """
    Review base_ref..snapshot of the working tree with OCR's rules, `ask(system, conversation)`
    answering one prompt per rule group (or part of one). Returns (status line, violations) like
    run_ocr_review: a file that was not reviewed makes it an OCR-RUN failure with the findings so far.
    """
    ocr_bin = shutil.which(binary)
    if not ocr_bin:
        return ocr_failed(f"'{binary}' not found on PATH (npm install -g @alibaba-group/open-code-review)")
    snapshot = GitDiffInspector(repo_path).snapshot_worktree()
    if not (base_ref and snapshot):
        return ocr_failed("the delegation mode needs the base commit recorded at pre and a snapshot of the working tree")
    span = ["--repo", str(repo_path), "--from", base_ref, "--to", snapshot, "--format", "json", "--color", "never"]
    skip = set(skip_files or [])
    try:
        listed = _ocr_json([ocr_bin, "delegate", "preview", *span], repo_path).get("reviewable_files")
        if not isinstance(listed, list) or not all(isinstance(f, dict) and isinstance(f.get("path"), str) for f in listed):
            raise ValueError("delegate preview gave no readable list of reviewable files")
        paths = [f["path"] for f in listed if f["path"] not in skip]
        if not paths:
            return "complete: 0 finding(s); OCR's delegation mode listed no file to review", []
        found_groups = _ocr_json([ocr_bin, "delegate", "rule", *span, *paths], repo_path).get("groups")
        if not isinstance(found_groups, list) or not all(
                isinstance(g, dict) and isinstance(g.get("rule"), str) and isinstance(g.get("files"), list) for g in found_groups):
            raise ValueError("delegate rule gave no readable rule groups")
        groups = [(g["rule"], [p for p in g["files"] if p in paths]) for g in found_groups]
        grouped = {p for _, files in groups for p in files}
        groups.append(("", [p for p in paths if p not in grouped]))  # a file without a rule is still reviewed
        # --no-prefix: the diff names files as OCR does (src/a.js, not b/src/a.js), the paths findings must carry
        diffs = {p: _run(["git", "diff", "--no-prefix", f"-U{CONTEXT_LINES}", base_ref, snapshot, "--", p], repo_path)
                 for p in paths}
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        return ocr_failed(f"OCR's delegation mode did not run: {e}")

    prompts, missed = _prompts([g for g in groups if g[1]], diffs)
    violations: List[RuleViolation] = []
    errors = []
    for rule, files in prompts:
        system = f"{RULES}\n\nReview rules:\n{rule or '(none for these files: use general good practice)'}\n\nBackground:\n{background}"
        try:
            data = _first_object(ask(system, "\n".join(diffs[p] for p in files)))
            comments = data.get("comments") if isinstance(data, dict) else None
            if not isinstance(comments, list) or not all(isinstance(c, dict) for c in comments):
                raise ValueError("the answer is not a JSON object with a list of comments")
        except (CLILLMError, ValueError) as e:  # an agent failure or an unreadable answer: these files were not reviewed
            errors.append(str(e)[:200])
            missed += files
            continue
        for c in comments:
            line, path = c.get("start_line"), c.get("path")
            if isinstance(path, str) and path not in files and path[:2] in ("a/", "b/"):
                path = path[2:]  # Git's usual a/ b/ prefixes, from a model used to them
            c = {**c, "start_line": line if isinstance(line, int) and not isinstance(line, bool) else None,
                 "path": path if isinstance(path, str) else None}
            if c["path"] in files:  # only the files this prompt reviewed
                violations.append(ocr_comment_violation(c))
    done = f"{len(paths) - len(missed)} of {len(paths)} file(s) in {len(prompts)} prompt(s)"
    if missed:
        reason = f"OCR's delegation mode reviewed {done}; not reviewed: {', '.join(missed[:5])}"
        reason += f" ({errors[-1]})" if errors else f" (no diff, or a diff over {MAX_PROMPT_CHARS} characters)"
        line, run = ocr_failed(reason)
        return line, run + violations
    return f"complete: {len(violations)} finding(s); OCR's delegation mode, {done}", violations
