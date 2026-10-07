"""
Benchmark corpus and labelled dataset builder.

Reads labelled commits and fixtures from bench/labels.md and bench/fixtures/,
extracts unified diffs, prompts, and defect definitions, and validates cases.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

# Default path constants
REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = Path(__file__).resolve().parent / "cases"
DEFAULT_LABELS_MD = Path(__file__).resolve().parent / "labels.md"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

REQUIRED_CASE_FIELDS = (
    "id",
    "source",
    "title",
    "prompt",
    "domain",
    "diff",
    "ref",
    "label",
    "defects",
)

REQUIRED_DEFECT_FIELDS = (
    "id",
    "file",
    "kind",
    "severity",
    "visible_in_diff",
    "summary",
    "keywords",
)

VALID_LABELS = ("defect", "clean", "unlabelled")

# Curated high-precision keywords for the benchmark defects.
# All tokens are lowercase and distinctive to describe the specific defect
# without matching unrelated findings in the same file.
DEFECT_KEYWORDS: dict[str, list[str]] = {
    "c01": ["approved_fingerprints", "unverified", "forged", "signature"],
    "c01b": ["startswith", "top-level", "__init__.py", "__tests__/"],
    "c01c": ["early return", "session.json", "commit detection", "skipped"],
    "c01d": ["forgery", "zero hashes", "already refused", "tampered"],
    "c02": ["fallback", "unstaged", "silent", "partial diff"],
    "c02b": ["invalidurl", "httpx", "ping probe", "unhandled"],
    "c02c": ["unexpected error", "agent cli", "escapes", "fallback"],
    "c03": ["# [error:", "+# [error", "diff error", "line-prefix check"],
    "c04": ["commands.config", "commands.invariants", "command order", "reorder"],
    "c05": ["colored help output", "expected_registered_commands", "rich box", "ansi"],
    "c06": ["deduction", "rounding", "floating", "precision", "bit-identical"],
    "c06b": ["sys.path.insert", "guard.__path__.insert", "unrestored path", "test_main_module"],
    "c07": ["argument list", "build command", "dropped comment line", "shell=true"],
    "c09": ["python.exe", "session_notice", "windows path", "launcher"],
    "c11": ["command_targets", "wrong directory", "git aliases", "dropped commits"],
}


def load_cases(path: Path | str | None = None) -> list[dict[str, Any]]:
    """
    Load JSON cases from a directory or single file.

    Default directory is bench/cases/. Subdirectories like cases/archive/ are
    excluded when loading from bench/cases/ unless explicitly specified.
    """
    if path is None:
        target_path = CASES_DIR
    else:
        target_path = Path(path)

    if not target_path.exists():
        return []

    if target_path.is_file():
        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return [data] if isinstance(data, dict) else data

    cases: list[dict[str, Any]] = []
    for file_path in target_path.iterdir():
        if file_path.is_file() and file_path.suffix == ".json":
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        cases.append(data)
            except (json.JSONDecodeError, OSError) as e:
                print(f"Warning: failed to load case from {file_path}: {e}", file=sys.stderr)

    return sorted(cases, key=lambda c: str(c.get("id", "")))


def validate_case(case: dict[str, Any], repo: Path | str | None = None) -> list[str]:
    """
    Validate a single case against schema, label rules, keyword rules, and diff visibility.

    Returns a list of problem descriptions (empty if valid).
    """
    problems: list[str] = []
    case_id = str(case.get("id", "<unknown>"))

    # Required top-level fields
    for field in REQUIRED_CASE_FIELDS:
        if field not in case:
            problems.append(f"Case '{case_id}' missing required field: {field}")

    label = case.get("label")
    if label not in VALID_LABELS:
        problems.append(f"Case '{case_id}' has invalid label: '{label}'")

    diff = case.get("diff")
    if not isinstance(diff, str) or not diff.strip():
        problems.append(f"Case '{case_id}' has empty or invalid diff")

    defects = case.get("defects")
    if not isinstance(defects, list):
        problems.append(f"Case '{case_id}' defects must be a list")
        defects = []

    # Label vs defects consistency
    if label == "defect" and len(defects) == 0:
        problems.append(f"Case '{case_id}' has label 'defect' but defects list is empty")
    elif label in ("clean", "unlabelled") and len(defects) > 0:
        problems.append(f"Case '{case_id}' has label '{label}' but defects list is not empty")

    repo_dir = Path(repo) if repo else REPO_ROOT

    # Defect validation
    diff_text = str(diff or "")
    for defect in defects:
        if not isinstance(defect, dict):
            problems.append(f"Case '{case_id}' defect entry is not a dict")
            continue

        defect_id = str(defect.get("id", "<unknown>"))
        for field in REQUIRED_DEFECT_FIELDS:
            if field not in defect:
                problems.append(f"Case '{case_id}' defect '{defect_id}' missing field: {field}")

        defect_file = str(defect.get("file", ""))
        if not defect_file:
            problems.append(f"Case '{case_id}' defect '{defect_id}' has empty file")

        # Keywords validation: 2 to 5 distinctive lowercase tokens
        keywords = defect.get("keywords")
        if not isinstance(keywords, list):
            problems.append(f"Case '{case_id}' defect '{defect_id}' keywords must be a list")
        elif not (2 <= len(keywords) <= 5):
            problems.append(
                f"Case '{case_id}' defect '{defect_id}' must have 2 to 5 keywords (got {len(keywords)})"
            )
        else:
            file_name = Path(defect_file).name.lower()
            file_full = defect_file.lower().replace("\\", "/")
            for kw in keywords:
                if not isinstance(kw, str) or not kw.strip():
                    problems.append(f"Case '{case_id}' defect '{defect_id}' keyword is empty or not string")
                    continue
                if kw != kw.lower():
                    problems.append(
                        f"Case '{case_id}' defect '{defect_id}' keyword '{kw}' is not lowercase"
                    )
                kw_norm = kw.lower().strip("/\\")
                if kw_norm == file_name or kw_norm == file_full:
                    problems.append(
                        f"Case '{case_id}' defect '{defect_id}' keyword '{kw}' cannot be file name alone"
                    )

        # Visibility validation: file must appear in diff when visible_in_diff is True
        visible = defect.get("visible_in_diff")
        if visible is True:
            norm_file = defect_file.replace("\\", "/")
            norm_diff = diff_text.replace("\\", "/")
            if norm_file not in norm_diff:
                problems.append(
                    f"Case '{case_id}' defect '{defect_id}' file '{defect_file}' not found in diff"
                )
            elif keywords and not any(kw.lower() in norm_diff.lower() for kw in keywords):
                problems.append(
                    f"Case '{case_id}' defect '{defect_id}' has no matching keyword in diff"
                )
        elif visible is False:
            ref = case.get("ref")
            if not ref:
                problems.append(
                    f"Case '{case_id}' defect '{defect_id}' is visible_in_diff=False but case has no ref"
                )
            else:
                norm_file = defect_file.replace("\\", "/")
                res = subprocess.run(
                    ["git", "cat-file", "-e", f"{ref}:{norm_file}"],
                    cwd=str(repo_dir),
                    capture_output=True,
                )
                if res.returncode != 0:
                    problems.append(
                        f"Case '{case_id}' defect '{defect_id}' file '{defect_file}' does not exist at ref '{ref}'"
                    )

    return problems


def _extract_fallback_keywords(defect_text: str, file_path: str) -> list[str]:
    """Generate 2 to 4 distinctive lowercase keywords if not in DEFECT_KEYWORDS."""
    file_words = {Path(file_path).name.lower(), file_path.lower(), Path(file_path).stem.lower()}
    words = [w.strip("`'\",().;:[]{}") for w in defect_text.lower().split()]
    clean = [w for w in words if len(w) >= 4 and w not in file_words and w.isalpha()]
    unique: list[str] = []
    for w in clean:
        if w not in unique:
            unique.append(w)
        if len(unique) == 4:
            break
    if len(unique) < 2:
        unique.extend(["issue", "defect"][: 2 - len(unique)])
    return unique


def _make_new_file_diff(file_path: str, content: str) -> str:
    """Format file content as a unified diff adding a new file."""
    lines = content.splitlines(keepends=True)
    body = "".join("+" + line for line in lines)
    if not body.endswith("\n"):
        body += "\n"
    norm_path = file_path.replace("\\", "/")
    return (
        f"diff --git a/{norm_path} b/{norm_path}\n"
        f"new file mode 100644\n"
        f"--- /dev/null\n"
        f"+++ b/{norm_path}\n"
        f"@@ -0,0 +1,{len(lines)} @@\n"
        f"{body}"
    )


def _clean_commit_body(body: str) -> str:
    """Strip git trailers (Co-Authored-By, Signed-off-by, etc.) from commit body."""
    lines: list[str] = []
    for line in body.splitlines():
        if re.match(r"^[A-Z][a-zA-Z0-9_-]+:\s+", line) and ("@" in line or "<" in line or ">" in line):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def _parse_label_table(labels_content: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Parse defects table and clean cases table from labels markdown text.

    bench/labels.md is the single source of truth for case labels.
    """
    lines = labels_content.splitlines()
    in_clean_section = False
    defect_rows: list[dict[str, Any]] = []
    clean_rows: list[dict[str, Any]] = []

    for line in lines:
        line_str = line.strip()
        if "## Cases that must NOT block" in line_str:
            in_clean_section = True
            continue

        if not line_str.startswith("|") or line_str.startswith("|---"):
            continue

        parts = [p.strip() for p in line_str.split("|")[1:-1]]
        if not parts or parts[0] == "Case":
            continue

        if not in_clean_section:
            # Defect row: | Case | Commit | Kind | Known defect (file, what) | Severity |
            if len(parts) >= 5:
                case_id = parts[0]
                commit_ref = parts[1].strip("`")
                kind = parts[2].lower()
                defect_text = parts[3]
                severity = parts[4].lower()
                defect_rows.append(
                    {
                        "case_id": case_id,
                        "commit_ref": commit_ref,
                        "kind": kind,
                        "defect_text": defect_text,
                        "severity": severity,
                    }
                )
        else:
            # Clean row: | Case | Commit | Why it is fair to call it clean |
            if len(parts) >= 3:
                case_id = parts[0]
                commit_ref = parts[1].strip("`")
                reason = parts[2]
                clean_rows.append(
                    {
                        "case_id": case_id,
                        "commit_ref": commit_ref,
                        "reason": reason,
                    }
                )

    return defect_rows, clean_rows


def build_from_git(labels_md: Path | str, repo: Path | str) -> list[dict[str, Any]]:
    """
    Read label table and build labelled benchmark cases using git show and fixtures.

    bench/labels.md is the single source of truth: rows in the first table become
    defect cases, and rows in the second table become clean cases.
    """
    labels_path = Path(labels_md)
    repo_path = Path(repo)
    fixtures_dir = repo_path / "bench" / "fixtures"
    if not fixtures_dir.exists():
        fixtures_dir = FIXTURES_DIR

    with open(labels_path, "r", encoding="utf-8") as f:
        labels_content = f.read()

    defect_rows, clean_rows = _parse_label_table(labels_content)

    # Group defect rows into cases
    grouped_defects: dict[str, list[dict[str, Any]]] = {}
    for row in defect_rows:
        ref = row["commit_ref"]
        group_key = "fixtures/t1-v1" if ref.startswith("fixtures/") else ref
        grouped_defects.setdefault(group_key, []).append(row)

    cases: list[dict[str, Any]] = []

    # Build defect cases
    for group_key, rows in grouped_defects.items():
        first_row = rows[0]
        m = re.match(r"^([a-zA-Z]+\d+)", first_row["case_id"])
        case_id = m.group(1) if m else first_row["case_id"]

        defects_list: list[dict[str, Any]] = []
        named_files: list[str] = []

        for r in rows:
            d_id = r["case_id"]
            d_kind = r["kind"]
            d_severity = r["severity"]
            d_text = r["defect_text"]

            is_omission = "OMISSION:" in d_text
            visible = not is_omission

            file_match = re.search(r"([a-zA-Z0-9_./-]+\.(?:py|md|json|yml|yaml|txt|patch))", d_text)
            if file_match:
                d_file = file_match.group(1).strip("`")
            elif "docs:" in d_text:
                d_file = "README.md"
            elif group_key == "fixtures/t1-v1":
                d_file = "guard/agent/bash.py"
            else:
                d_file = "unknown"

            if visible and d_file != "unknown" and d_file not in named_files:
                named_files.append(d_file)

            summary = d_text
            keywords = DEFECT_KEYWORDS.get(d_id) or _extract_fallback_keywords(d_text, d_file)

            defects_list.append(
                {
                    "id": d_id,
                    "file": d_file,
                    "kind": d_kind,
                    "severity": d_severity,
                    "visible_in_diff": visible,
                    "summary": summary,
                    "keywords": keywords,
                }
            )

        if group_key == "fixtures/t1-v1":
            bash_patch_path = fixtures_dir / "t1-v1-bash.patch"
            with open(bash_patch_path, "r", encoding="utf-8") as f_bash:
                diff_text = f_bash.read()
            title = "feat: command target parsing for bash command segments"
            prompt = (
                "Parse command targets to find the effective working directory and commit status "
                "for bash command segments. Touch guard/agent/bash.py and add unit tests in "
                "tests/test_command_target.py."
            )
            cases.append(
                {
                    "id": case_id,
                    "source": "git",
                    "title": title,
                    "prompt": prompt,
                    "domain": "backend",
                    "diff": diff_text,
                    "ref": "fixtures/t1-v1",
                    "label": "defect",
                    "defects": defects_list,
                }
            )
        else:
            commit = group_key
            sub_res = subprocess.run(
                ["git", "log", "-1", "--format=%s", commit],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if sub_res.returncode != 0:
                raise RuntimeError(f"git log failed for commit '{commit}': {sub_res.stderr}")
            subject = (sub_res.stdout or "").strip()

            body_res = subprocess.run(
                ["git", "log", "-1", "--format=%b", commit],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if body_res.returncode != 0:
                raise RuntimeError(f"git log failed for commit '{commit}': {body_res.stderr}")
            body = _clean_commit_body((body_res.stdout or "").strip())

            files_res = subprocess.run(
                ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if files_res.returncode != 0:
                raise RuntimeError(f"git diff-tree failed for commit '{commit}': {files_res.stderr}")
            all_changed_files = [f.strip() for f in (files_res.stdout or "").splitlines() if f.strip()]

            # Restrict diff to named files if specified
            if named_files:
                diff_cmd = ["git", "show", "--format=", commit, "--"] + named_files
                diff_res = subprocess.run(
                    diff_cmd,
                    cwd=str(repo_path),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                if diff_res.returncode != 0:
                    raise RuntimeError(f"git show restricted failed for '{commit}': {diff_res.stderr}")
                diff_text = diff_res.stdout or ""
            else:
                diff_cmd = ["git", "show", "--format=", commit]
                diff_res = subprocess.run(
                    diff_cmd,
                    cwd=str(repo_path),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                if diff_res.returncode != 0:
                    raise RuntimeError(f"git show failed for commit '{commit}': {diff_res.stderr}")
                diff_text = diff_res.stdout or ""

            title = subject
            if len(diff_text) > 120000 and named_files:
                title = f"{subject} (restricted to {', '.join(named_files)})"

            prompt_body = f"\n\n{body}" if body else ""
            prompt = f"{subject}{prompt_body}\n\nFiles changed: {', '.join(all_changed_files)}"

            cases.append(
                {
                    "id": case_id,
                    "source": "git",
                    "title": title,
                    "prompt": prompt,
                    "domain": "backend",
                    "diff": diff_text,
                    "ref": commit,
                    "label": "defect",
                    "defects": defects_list,
                }
            )

    # Build clean cases from clean_rows in bench/labels.md
    for r in clean_rows:
        case_id = r["case_id"]
        commit = r["commit_ref"]

        sub_res = subprocess.run(
            ["git", "log", "-1", "--format=%s", commit],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if sub_res.returncode != 0:
            raise RuntimeError(f"git log failed for commit '{commit}': {sub_res.stderr}")
        subject = (sub_res.stdout or "").strip()

        body_res = subprocess.run(
            ["git", "log", "-1", "--format=%b", commit],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if body_res.returncode != 0:
            raise RuntimeError(f"git log failed for commit '{commit}': {body_res.stderr}")
        body = _clean_commit_body((body_res.stdout or "").strip())

        files_res = subprocess.run(
            ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if files_res.returncode != 0:
            raise RuntimeError(f"git diff-tree failed for commit '{commit}': {files_res.stderr}")
        all_changed_files = [f.strip() for f in (files_res.stdout or "").splitlines() if f.strip()]

        diff_res = subprocess.run(
            ["git", "show", "--format=", commit],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if diff_res.returncode != 0:
            raise RuntimeError(f"git show failed for commit '{commit}': {diff_res.stderr}")
        diff_text = diff_res.stdout or ""

        title = subject
        if case_id == "c10":
            title = f"{subject} (single-commit view; cross-part movement evaluated in m01)"

        prompt_body = f"\n\n{body}" if body else ""
        prompt = f"{subject}{prompt_body}\n\nFiles changed: {', '.join(all_changed_files)}"

        cases.append(
            {
                "id": case_id,
                "source": "git",
                "title": title,
                "prompt": prompt,
                "domain": "backend",
                "diff": diff_text,
                "ref": commit,
                "label": "clean",
                "defects": [],
            }
        )

    return sorted(cases, key=lambda c: str(c.get("id", "")))


def build_from_archive(history_dir: Path | str) -> list[dict[str, Any]]:
    """
    Build unlabelled cases from archived sessions in history_dir.

    Only sessions with non-empty post.diff_summary.raw_diff are used.
    Marked approximate: true and label: unlabelled.
    """
    h_path = Path(history_dir)
    if not h_path.exists():
        return []

    cases: list[dict[str, Any]] = []
    for file_path in h_path.iterdir():
        if not file_path.is_file() or file_path.suffix != ".json":
            continue
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                continue

            post = data.get("post") or {}
            diff_summary = post.get("diff_summary") or {}
            raw_diff = diff_summary.get("raw_diff") or ""
            if not isinstance(raw_diff, str) or not raw_diff.strip():
                continue

            pre = data.get("pre") or {}
            prompt = str(pre.get("prompt") or "")
            domain = str(pre.get("domain") or "backend")
            session_id = str(data.get("session_id") or file_path.stem)
            ref = pre.get("baseline_snapshot") or pre.get("base_ref")

            verdict = post.get("muse_verdict") or post.get("verdict")
            findings = post.get("findings") or []

            cases.append(
                {
                    "id": session_id,
                    "source": "archive",
                    "title": f"archived session {session_id}",
                    "prompt": prompt,
                    "domain": domain,
                    "diff": raw_diff,
                    "ref": str(ref) if ref else None,
                    "label": "unlabelled",
                    "approximate": True,
                    "defects": [],
                    "archived": {
                        "verdict": verdict,
                        "findings": findings,
                    },
                }
            )
        except (OSError, json.JSONDecodeError, KeyError, ValueError) as e:
            print(f"Notice: skipped invalid archive file {file_path.name}: {e}", file=sys.stderr)
            continue

    return sorted(cases, key=lambda c: str(c.get("id", "")))


def make_composites(
    cases: list[dict[str, Any]] | dict[str, dict[str, Any]],
    min_chars: int = 90000,
) -> list[dict[str, Any]]:
    """
    Build multi-part composite cases (m01..m05).

    The review runs diffs in parts of at most 80,000 characters. Composites
    have diff length >= min_chars so cross-part behaviour is exercised.
    (a) m01: d477e26 docs case + 1dfb152 follow-up. Facts moved without loss,
        so m01 is a false-block test and is labelled CLEAN (no defects).
    (b) m02..m04: labelled defect case placed AFTER clean filler diffs from n01..n05
        so defect lands in part 2 or later. Filler is chosen to not overlap with
        any defect files.
    (c) m05: same with defect FIRST.
    """
    if isinstance(cases, list):
        case_map: dict[str, dict[str, Any]] = {str(c.get("id")): c for c in cases}
    else:
        case_map = cases

    composites: list[dict[str, Any]] = []

    # (a) m01: c10 (d477e26) + n05 (1dfb152) - Clean composite (false-block test)
    c10 = case_map.get("c10")
    n05 = case_map.get("n05")
    if c10 and n05:
        m01_diff = c10["diff"].rstrip() + "\n\n" + n05["diff"].lstrip()
        composites.append(
            {
                "id": "m01",
                "source": "git",
                "title": "composite: docs reorganization across parts (d477e26 + 1dfb152)",
                "prompt": f"{c10['prompt']}\n\n{n05['prompt']}",
                "domain": "backend",
                "diff": m01_diff,
                "ref": c10.get("ref"),
                "label": "clean",
                "defects": [],
                "source_ids": ["c10", "n05"],
                "composite": True,
            }
        )

    # Clean filler (n01 + n03): touches adapter_validation, commands/agent,
    # maintenance, config, updater, installer, and task_flow.
    # Total chars: ~92k (>= min_chars). Touches NONE of the defect files for c03, c02, or c06!
    n01 = case_map.get("n01")
    n03 = case_map.get("n03")

    # (b) m02: clean filler (n01 + n03) + c03 (defect in part 2)
    c03 = case_map.get("c03")
    if n01 and n03 and c03:
        m02_diff = n01["diff"].rstrip() + "\n\n" + n03["diff"].rstrip() + "\n\n" + c03["diff"].lstrip()
        composites.append(
            {
                "id": "m02",
                "source": "git",
                "title": "composite: defect in part 2 after clean filler (n01 + n03 + c03)",
                "prompt": f"{c03['prompt']}\n\nBackground changes in updater and rules engine.",
                "domain": "backend",
                "diff": m02_diff,
                "ref": c03.get("ref"),
                "label": "defect",
                "defects": [dict(d) for d in c03["defects"]],
                "source_ids": ["n01", "n03", "c03"],
                "composite": True,
            }
        )

    # (b) m03: clean filler (n01 + n03) + c02 (defect in part 2)
    c02 = case_map.get("c02")
    if n01 and n03 and c02:
        m03_diff = n01["diff"].rstrip() + "\n\n" + n03["diff"].rstrip() + "\n\n" + c02["diff"].lstrip()
        composites.append(
            {
                "id": "m03",
                "source": "git",
                "title": "composite: defect in part 2 after clean filler (n01 + n03 + c02)",
                "prompt": f"{c02['prompt']}\n\nBackground refactoring in updater and task flow.",
                "domain": "backend",
                "diff": m03_diff,
                "ref": c02.get("ref"),
                "label": "defect",
                "defects": [dict(d) for d in c02["defects"]],
                "source_ids": ["n01", "n03", "c02"],
                "composite": True,
            }
        )

    # (b) m04: clean filler (n01 + n03) + c06 (defect in part 2)
    c06 = case_map.get("c06")
    if n01 and n03 and c06:
        m04_diff = n01["diff"].rstrip() + "\n\n" + n03["diff"].rstrip() + "\n\n" + c06["diff"].lstrip()
        composites.append(
            {
                "id": "m04",
                "source": "git",
                "title": "composite: defect in part 2 after clean filler (n01 + n03 + c06)",
                "prompt": f"{c06['prompt']}\n\nBackground changes in rule decomposition and docs.",
                "domain": "backend",
                "diff": m04_diff,
                "ref": c06.get("ref"),
                "label": "defect",
                "defects": [dict(d) for d in c06["defects"]],
                "source_ids": ["n01", "n03", "c06"],
                "composite": True,
            }
        )

    # (c) m05: defect FIRST (c03) + clean filler (n01 + n03)
    if c03 and n01 and n03:
        m05_diff = c03["diff"].rstrip() + "\n\n" + n01["diff"].rstrip() + "\n\n" + n03["diff"].lstrip()
        composites.append(
            {
                "id": "m05",
                "source": "git",
                "title": "composite: defect FIRST followed by clean filler (c03 + n01 + n03)",
                "prompt": f"{c03['prompt']}\n\nAdditional updates in updater and rulebook.",
                "domain": "backend",
                "diff": m05_diff,
                "ref": c03.get("ref"),
                "label": "defect",
                "defects": [dict(d) for d in c03["defects"]],
                "source_ids": ["c03", "n01", "n03"],
                "composite": True,
            }
        )

    valid_composites: list[dict[str, Any]] = []
    for comp in composites:
        if len(comp["diff"]) < min_chars:
            raise ValueError(
                f"Composite case '{comp['id']}' diff length {len(comp['diff'])} is below min_chars={min_chars}"
            )
        valid_composites.append(comp)

    return valid_composites


def _cli_build(args: argparse.Namespace) -> int:
    """CLI handler for `python -m bench.corpus build`."""
    labels_path = Path(args.labels) if args.labels else DEFAULT_LABELS_MD
    repo_path = Path(args.repo) if args.repo else REPO_ROOT
    out_dir = Path(args.out) if args.out else CASES_DIR

    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Building cases from {labels_path} (repo: {repo_path})...")
    cases = build_from_git(labels_path, repo_path)
    print(f"Built {len(cases)} base labelled cases.")

    # Build composites
    composites = make_composites(cases)
    print(f"Built {len(composites)} composite cases.")

    # Save labelled and composite cases with explicit newline="\n" for Windows determinism
    all_cases = cases + composites
    for case in all_cases:
        case_id = case["id"]
        out_file = out_dir / f"{case_id}.json"
        with open(out_file, "w", encoding="utf-8", newline="\n") as f:
            json.dump(case, f, indent=2)
            f.write("\n")

    print(f"Wrote {len(all_cases)} case files to {out_dir}")

    # Build from archive if requested
    if args.archive:
        archive_dir = Path(args.archive)
        print(f"Building archive cases from {archive_dir}...")
        archive_out = out_dir / "archive"
        archive_out.mkdir(parents=True, exist_ok=True)
        archived_cases = build_from_archive(archive_dir)
        for ac in archived_cases:
            ac_id = ac["id"]
            with open(archive_out / f"{ac_id}.json", "w", encoding="utf-8", newline="\n") as f:
                json.dump(ac, f, indent=2)
                f.write("\n")
        print(f"Wrote {len(archived_cases)} archived case files to {archive_out}")

    return 0


def _cli_check(args: argparse.Namespace) -> int:
    """CLI handler for `python -m bench.corpus check`."""
    cases_dir = Path(args.cases) if args.cases else CASES_DIR
    repo_path = Path(args.repo) if args.repo else REPO_ROOT

    cases = load_cases(cases_dir)
    if not cases:
        print(f"No cases found in {cases_dir}")
        return 1

    total_problems = 0
    for case in cases:
        problems = validate_case(case, repo=repo_path)
        if problems:
            total_problems += len(problems)
            print(f"Problems in case '{case.get('id')}':")
            for p in problems:
                print(f"  - {p}")

    if total_problems > 0:
        print(f"\nFAILED: {total_problems} problem(s) found across {len(cases)} cases.")
        return 1

    print(f"SUCCESS: All {len(cases)} cases in {cases_dir} are valid.")
    return 0


def corpus_main(argv: list[str] | None = None) -> int:
    """Main CLI entry point for bench.corpus."""
    parser = argparse.ArgumentParser(
        prog="bench.corpus",
        description="Benchmark corpus builder and validator.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # build
    build_parser = subparsers.add_parser("build", help="Build case files from git and fixtures")
    build_parser.add_argument("--archive", type=str, default=None, help="Directory of archived sessions")
    build_parser.add_argument("--labels", type=str, default=None, help="Path to labels.md")
    build_parser.add_argument("--repo", type=str, default=None, help="Path to git repository root")
    build_parser.add_argument("--out", type=str, default=None, help="Output directory for cases")

    # check
    check_parser = subparsers.add_parser("check", help="Check and validate case files")
    check_parser.add_argument("--cases", type=str, default=None, help="Directory containing cases")
    check_parser.add_argument("--repo", type=str, default=None, help="Path to git repository root")

    args = parser.parse_args(argv)
    if args.command == "build":
        return _cli_build(args)
    elif args.command == "check":
        return _cli_check(args)
    else:
        parser.print_help()
        return 1


# Alias for backward compatibility
main = corpus_main

if __name__ == "__main__":
    sys.exit(corpus_main())
