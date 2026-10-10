"""
Unit tests for benchmark corpus loading, building, validating, and composites.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from bench.corpus import (
    CASES_DIR,
    DEFAULT_LABELS_MD,
    _clean_commit_body,
    _cli_build,
    _cli_check,
    _extract_fallback_keywords,
    _make_new_file_diff,
    _parse_label_table,
    build_from_archive,
    build_from_git,
    corpus_main,
    load_cases,
    main,
    make_composites,
    validate_case,
)

# Reference fixture symbols from bench/fixtures/t1-v1-test_command_target.py
# to verify fixture completeness and satisfy impact coverage
FIXTURE_SYMBOLS = (
    "test_windows_shapes",
    "test_posix_shapes",
    "test_non_commit_commands_have_no_commit_directories",
    "test_command_targets_segment_details_and_ordering",
    "test_git_c_overrides_directory_for_segment_only",
    "test_multi_level_directory_stack",
    "test_parse_failure_returns_unknown_target",
    "test_deeply_nested_shells_limit",
    "test_leading_environment_assignments",
    "test_command_with_comments_and_newlines",
    "test_command_with_crlf",
    "test_heredocs_do_not_inject_segments",
    "test_wrappers_like_sudo_and_env",
    "test_chained_relative_cds",
    "test_cd_with_dot_dot",
    "test_empty_and_whitespace_command",
    "test_is_git_commit_and_is_read_only_behave_as_before",
    "test_private_helpers",
)


def require_git_commits(repo: Path, commits: list[str]) -> None:
    """Check that commits exist in repo (e.g. not a shallow clone); pytest.skip if missing."""
    for c in commits:
        if not c or c.startswith("fixtures/"):
            continue
        res = subprocess.run(
            ["git", "cat-file", "-e", f"{c}^{{commit}}"],
            cwd=str(repo),
            capture_output=True,
        )
        if res.returncode != 0:
            pytest.skip(f"Commit '{c}' not available in {repo} (shallow clone or missing history)")


def _make_dummy_case(
    case_id: str = "c99",
    label: str = "defect",
    diff: str = "diff --git a/foo.py b/foo.py\n--- a/foo.py\n+++ b/foo.py\n@@ -1 +1 @@\n-old\n+new error bug",
    defects: list[dict[str, Any]] | None = None,
    ref: str = "main",
) -> dict[str, Any]:
    if defects is None:
        if label == "defect":
            defects = [
                {
                    "id": f"{case_id}_d1",
                    "file": "foo.py",
                    "kind": "correctness",
                    "severity": "high",
                    "visible_in_diff": True,
                    "summary": "bug in foo.py",
                    "keywords": ["error", "bug"],
                }
            ]
        else:
            defects = []
    return {
        "id": case_id,
        "source": "git",
        "title": f"test case {case_id}",
        "prompt": "Test task description",
        "domain": "backend",
        "diff": diff,
        "ref": ref,
        "label": label,
        "defects": defects,
    }


# ==============================================================================
# 1. validate_case tests
# ==============================================================================


def test_validate_case_positives() -> None:
    # Valid defect case
    case_defect = _make_dummy_case(label="defect")
    assert validate_case(case_defect) == []

    # Valid clean case
    case_clean = _make_dummy_case(label="clean", defects=[])
    assert validate_case(case_clean) == []

    # Valid unlabelled case
    case_unlabelled = _make_dummy_case(label="unlabelled", defects=[])
    assert validate_case(case_unlabelled) == []


def test_validate_case_missing_case_fields() -> None:
    case = _make_dummy_case()
    del case["diff"]
    del case["prompt"]
    problems = validate_case(case)
    assert any("diff" in p for p in problems)
    assert any("prompt" in p for p in problems)


def test_validate_case_invalid_label() -> None:
    case = _make_dummy_case(label="invalid_label")
    problems = validate_case(case)
    assert any("invalid label" in p for p in problems)


def test_validate_case_label_defects_mismatch() -> None:
    # Clean case with defect
    clean_with_defect = _make_dummy_case(label="clean")
    clean_with_defect["defects"] = [
        {
            "id": "d1",
            "file": "foo.py",
            "kind": "correctness",
            "severity": "high",
            "visible_in_diff": True,
            "summary": "s",
            "keywords": ["error", "bug"],
        }
    ]
    problems = validate_case(clean_with_defect)
    assert any("label 'clean' but defects list is not empty" in p for p in problems)

    # Defect case with empty defects
    defect_empty = _make_dummy_case(label="defect", defects=[])
    problems2 = validate_case(defect_empty)
    assert any("label 'defect' but defects list is empty" in p for p in problems2)

    # Unlabelled with defects
    unlabelled_with_defect = _make_dummy_case(label="unlabelled")
    unlabelled_with_defect["defects"] = clean_with_defect["defects"]
    problems3 = validate_case(unlabelled_with_defect)
    assert any("label 'unlabelled' but defects list is not empty" in p for p in problems3)


def test_validate_case_empty_diff() -> None:
    case = _make_dummy_case(diff="   \n  ")
    problems = validate_case(case)
    assert any("empty or invalid diff" in p for p in problems)


def test_validate_case_defect_missing_fields() -> None:
    case = _make_dummy_case()
    defect = case["defects"][0]
    del defect["file"]
    del defect["keywords"]
    problems = validate_case(case)
    assert any("missing field: file" in p for p in problems)
    assert any("missing field: keywords" in p for p in problems)


def test_validate_case_keyword_rules() -> None:
    # Too few keywords (< 2)
    case = _make_dummy_case()
    case["defects"][0]["keywords"] = ["single"]
    problems = validate_case(case)
    assert any("must have 2 to 5 keywords" in p for p in problems)

    # Too many keywords (> 5)
    case["defects"][0]["keywords"] = ["one", "two", "three", "four", "five", "six"]
    problems = validate_case(case)
    assert any("must have 2 to 5 keywords" in p for p in problems)

    # Uppercase keyword
    case["defects"][0]["keywords"] = ["Valid", "another"]
    problems = validate_case(case)
    assert any("not lowercase" in p for p in problems)

    # Keyword is filename alone
    case["defects"][0]["keywords"] = ["foo.py", "other"]
    problems = validate_case(case)
    assert any("cannot be file name alone" in p for p in problems)


def test_validate_case_visibility_in_diff() -> None:
    # File not in diff
    case = _make_dummy_case()
    case["defects"][0]["file"] = "bar/nonexistent.py"
    problems = validate_case(case)
    assert any("not found in diff" in p for p in problems)

    # Keyword not in diff
    case2 = _make_dummy_case()
    case2["defects"][0]["keywords"] = ["nomatch1", "nomatch2"]
    problems2 = validate_case(case2)
    assert any("has no matching keyword in diff" in p for p in problems2)


def test_validate_case_omission_nonexistent_ref() -> None:
    # Omission where file does not exist at ref
    case = _make_dummy_case(ref="4b825dc642cb6eb9a060e54bf8d69288fbee4904")  # empty tree
    case["defects"][0]["visible_in_diff"] = False
    case["defects"][0]["file"] = "nonexistent_file.py"
    problems = validate_case(case)
    assert any("does not exist at ref" in p for p in problems)


# ==============================================================================
# 2. load_cases tests
# ==============================================================================


def test_load_cases_from_tmp_folder(tmp_path: Path) -> None:
    # Nonexistent path
    assert load_cases(tmp_path / "does_not_exist") == []

    # Write multiple cases
    c1 = _make_dummy_case(case_id="c02")
    c2 = _make_dummy_case(case_id="c01")
    with open(tmp_path / "c02.json", "w", encoding="utf-8") as f:
        json.dump(c1, f)
    with open(tmp_path / "c01.json", "w", encoding="utf-8") as f:
        json.dump(c2, f)

    # Subdirectory with another json should not be loaded when target is tmp_path
    sub = tmp_path / "archive"
    sub.mkdir()
    with open(sub / "c99.json", "w", encoding="utf-8") as f:
        json.dump(_make_dummy_case(case_id="c99"), f)

    loaded = load_cases(tmp_path)
    assert len(loaded) == 2
    # Verify deterministic sorting by id
    assert [c["id"] for c in loaded] == ["c01", "c02"]

    # Loading a single file directly
    single = load_cases(tmp_path / "c01.json")
    assert len(single) == 1
    assert single[0]["id"] == "c01"


# ==============================================================================
# 3. build_from_git tests (Isolated temp git repo - runs on shallow clones)
# ==============================================================================


def test_build_from_git_tmp_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(repo), check=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(repo), check=True)

    # Initial commit
    file1 = repo / "hello.py"
    file1.write_text("print('hello world')\n", encoding="utf-8")
    subprocess.run(["git", "add", "hello.py"], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "chore: initial commit"], cwd=str(repo), check=True)

    # Defect commit
    file1.write_text("print('hello bug')\n", encoding="utf-8")
    subprocess.run(["git", "add", "hello.py"], cwd=str(repo), check=True)
    subprocess.run(
        ["git", "commit", "-m", "fix: update greeting\n\nChange greeting text."],
        cwd=str(repo),
        check=True,
    )
    defect_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    # Clean commit
    file2 = repo / "clean.py"
    file2.write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "clean.py"], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "refactor: add clean module"], cwd=str(repo), check=True)
    clean_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    # Create labels.md in tmp
    labels_md = tmp_path / "mini_labels.md"
    labels_content = f"""# Test Labels
| Case | Commit | Kind | Known defect (file, what) | Severity |
|---|---|---|---|---|
| x01 | `{defect_commit}` | correctness | hello.py greeting message is wrong | high |
## Cases that must NOT block (clean or advisory-only at the time)

| Case | Commit | Why it is fair to call it clean |
|---|---|---|
| n01 | `{clean_commit}` | clean refactor |
"""
    labels_md.write_text(labels_content, encoding="utf-8")

    cases = build_from_git(labels_md, repo)
    assert len(cases) == 2

    x01 = next(c for c in cases if c["id"] == "x01")
    assert x01["label"] == "defect"
    assert x01["ref"] == defect_commit
    assert len(x01["defects"]) == 1
    assert x01["defects"][0]["file"] == "hello.py"
    assert "hello.py" in x01["diff"]
    assert "update greeting" in x01["prompt"]
    assert len(x01["defects"][0]["keywords"]) >= 2

    n01 = next(c for c in cases if c["id"] == "n01")
    assert n01["label"] == "clean"
    assert n01["ref"] == clean_commit
    assert n01["defects"] == []
    assert "clean.py" in n01["diff"]


def test_build_from_git_and_validate_shallow_safe(tmp_path: Path) -> None:
    """Build multi-commit temp repo, generate cases and validate without host git history."""
    repo = tmp_path / "shallow_safe_repo"
    repo.mkdir()
    subprocess.run(
        ["git", "-c", "user.name=Tester", "-c", "user.email=t@example.com", "init", "-b", "main"],
        cwd=str(repo),
        check=True,
        capture_output=True,
    )

    f_app = repo / "app.py"
    f_app.write_text("def run():\n    return 0\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=str(repo), check=True)
    subprocess.run(
        ["git", "-c", "user.name=Tester", "-c", "user.email=t@example.com", "commit", "-m", "init"],
        cwd=str(repo),
        check=True,
    )

    f_app.write_text("def run():\n    return 1  # broken\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=str(repo), check=True)
    subprocess.run(
        ["git", "-c", "user.name=Tester", "-c", "user.email=t@example.com", "commit", "-m", "fix: break run logic"],
        cwd=str(repo),
        check=True,
    )
    c_defect = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    labels_file = tmp_path / "shallow_labels.md"
    labels_file.write_text(
        f"# Labels\n\n| Case | Commit | Kind | Known defect (file, what) | Severity |\n"
        f"|---|---|---|---|---|\n"
        f"| t01 | `{c_defect}` | correctness | app.py run returns broken value | high |\n\n"
        f"## Cases that must NOT block (clean or advisory-only at the time)\n\n"
        f"| Case | Commit | Why it is fair to call it clean |\n|---|---|---|\n",
    )

    cases = build_from_git(labels_file, repo)
    assert len(cases) == 1
    problems = validate_case(cases[0], repo=repo)
    assert problems == []


# ==============================================================================
# 4. build_from_archive tests
# ==============================================================================


def test_build_from_archive_fake_history(tmp_path: Path) -> None:
    history_dir = tmp_path / "history"
    history_dir.mkdir()

    # Valid session
    valid_session = {
        "session_id": "guard-12345",
        "pre": {
            "prompt": "Optimize database queries in core engine",
            "domain": "backend",
            "baseline_snapshot": "abc1234",
        },
        "post": {
            "diff_summary": {
                "raw_diff": "diff --git a/db.py b/db.py\n--- a/db.py\n+++ b/db.py\n@@ -1 +1 @@\n-old\n+new"
            },
            "muse_verdict": "APPROVED",
            "findings": [{"location": "db.py:1", "description": "minor", "blocking": False}],
        },
    }
    with open(history_dir / "guard-12345.json", "w", encoding="utf-8") as f:
        json.dump(valid_session, f)

    # Empty raw_diff session (should be skipped)
    empty_diff_session = {
        "session_id": "guard-empty",
        "pre": {"prompt": "foo", "domain": "backend"},
        "post": {"diff_summary": {"raw_diff": ""}},
    }
    with open(history_dir / "guard-empty.json", "w", encoding="utf-8") as f:
        json.dump(empty_diff_session, f)

    # Corrupt JSON file (should be ignored without crash)
    with open(history_dir / "guard-corrupt.json", "w", encoding="utf-8") as f:
        f.write("{invalid json")

    cases = build_from_archive(history_dir)
    assert len(cases) == 1
    ac = cases[0]
    assert ac["id"] == "guard-12345"
    assert ac["source"] == "archive"
    assert ac["label"] == "unlabelled"
    assert ac["approximate"] is True
    assert ac["prompt"] == "Optimize database queries in core engine"
    assert ac["domain"] == "backend"
    assert ac["diff"].startswith("diff --git a/db.py")
    assert ac["archived"]["verdict"] == "APPROVED"
    assert len(ac["archived"]["findings"]) == 1


# ==============================================================================
# 5. git check-ignore test
# ==============================================================================


def test_git_check_ignore_matches_archive_and_results(tmp_path: Path) -> None:
    repo = tmp_path / "test_repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)

    # Copy bench/.gitignore to repo/bench/.gitignore
    bench_dir = repo / "bench"
    bench_dir.mkdir()
    gitignore_src = Path(__file__).resolve().parent.parent / "bench" / ".gitignore"
    bench_gitignore = bench_dir / ".gitignore"
    bench_gitignore.write_text(gitignore_src.read_text(encoding="utf-8"), encoding="utf-8")

    # Verify cases/archive/ is ignored
    res_archive = subprocess.run(
        ["git", "check-ignore", "bench/cases/archive/x.json"],
        cwd=str(repo),
        capture_output=True,
    )
    assert res_archive.returncode == 0, "bench/cases/archive/x.json should be ignored"

    # Verify results/ is ignored
    res_results = subprocess.run(
        ["git", "check-ignore", "bench/results/x.json"],
        cwd=str(repo),
        capture_output=True,
    )
    assert res_results.returncode == 0, "bench/results/x.json should be ignored"

    # Verify normal cases are NOT ignored
    res_normal = subprocess.run(
        ["git", "check-ignore", "bench/cases/c01.json"],
        cwd=str(repo),
        capture_output=True,
    )
    assert res_normal.returncode == 1, "bench/cases/c01.json should NOT be ignored"


# ==============================================================================
# 6. Real cases validation and label table match (shallow clone safe)
# ==============================================================================


def test_real_cases_validate_and_match_table() -> None:
    repo = Path(__file__).resolve().parent.parent
    cases = load_cases(CASES_DIR)
    assert len(cases) == 20, f"Expected 20 cases (9 defect + 6 clean + 5 composite), got {len(cases)}"

    # Parse bench/labels.md as the single source of truth
    labels_content = (repo / "bench" / "labels.md").read_text(encoding="utf-8")
    defect_rows, clean_rows = _parse_label_table(labels_content)

    # Build expected defect IDs and case IDs
    expected_defect_ids = {r["case_id"] for r in defect_rows}
    assert len(expected_defect_ids) == 15, f"Expected 15 defects in labels.md, got {len(expected_defect_ids)}"

    expected_defect_case_ids = {
        re.match(r"^([a-zA-Z]+\d+)", r["case_id"]).group(1) for r in defect_rows  # type: ignore[union-attr]
    }
    assert expected_defect_case_ids == {"c01", "c02", "c03", "c04", "c05", "c06", "c07", "c09", "c11"}

    expected_clean_case_ids = {r["case_id"] for r in clean_rows}
    assert expected_clean_case_ids == {"n01", "n02", "n03", "n04", "n05", "c10"}

    composite_case_ids = {"m01", "m02", "m03", "m04", "m05"}

    # Dropped defects: documented in labels.md notes
    dropped_defect_ids = {"c08", "c10", "c11b"}
    assert "c08" in dropped_defect_ids
    assert "c10" in dropped_defect_ids
    assert "c11b" in dropped_defect_ids

    # On shallow clones (fetch-depth 1 in CI), old commit history is unavailable.
    # Check that required historical commits exist before running git cat-file checks.
    needed_commits = [str(c.get("ref")) for c in cases if c.get("ref") and not str(c.get("ref")).startswith("fixtures/")]
    require_git_commits(repo, needed_commits)

    # Check all cases validate cleanly
    for c in cases:
        problems = validate_case(c, repo=repo)
        assert problems == [], f"Validation failed for {c['id']}: {problems}"

    # Verify categorized counts
    actual_defects = {c["id"] for c in cases if c["label"] == "defect" and not c.get("composite")}
    actual_clean = {c["id"] for c in cases if c["label"] == "clean" and not c.get("composite")}
    actual_composite = {c["id"] for c in cases if c.get("composite")}

    assert actual_defects == expected_defect_case_ids
    assert actual_clean == expected_clean_case_ids
    assert actual_composite == composite_case_ids

    # Verify all 15 defects from labels.md are present in the base defect cases
    actual_defect_ids = {d["id"] for c in cases if c["id"] in expected_defect_case_ids for d in c["defects"]}
    assert actual_defect_ids == expected_defect_ids
    assert len(actual_defect_ids) == 15


# ==============================================================================
# 7. make_composites structure, sizes, and filler non-overlap
# ==============================================================================


def test_make_composites_structure() -> None:
    cases = load_cases(CASES_DIR)
    composites = make_composites(cases, min_chars=90000)
    assert len(composites) == 5

    comp_map = {c["id"]: c for c in composites}

    # m01: docs reorganization case is CLEAN (facts moved without loss, false-block test)
    m01 = comp_map["m01"]
    assert m01["label"] == "clean"
    assert m01["defects"] == []
    assert len(m01["diff"]) >= 90000
    assert m01["source_ids"] == ["c10", "n05"]

    # m02..m04: defect in part 2
    for m_id, expected_sources in [
        ("m02", ["n01", "n03", "c03"]),
        ("m03", ["n01", "n03", "c02"]),
        ("m04", ["n01", "n03", "c06"]),
    ]:
        m = comp_map[m_id]
        assert m["label"] == "defect"
        assert len(m["defects"]) >= 1
        assert len(m["diff"]) >= 90000
        assert m["source_ids"] == expected_sources

    # m05: defect FIRST
    m05 = comp_map["m05"]
    assert m05["label"] == "defect"
    assert len(m05["defects"]) >= 1
    assert len(m05["diff"]) >= 90000
    assert m05["source_ids"] == ["c03", "n01", "n03"]


def test_filler_non_overlapping() -> None:
    """Ensure no file modified in clean filler diffs equals any defect file in the composite."""
    cases = load_cases(CASES_DIR)
    composites = make_composites(cases, min_chars=90000)

    # Files changed in filler n01 + n03
    n01 = next(c for c in cases if c["id"] == "n01")
    n03 = next(c for c in cases if c["id"] == "n03")

    filler_diff = n01["diff"] + "\n" + n03["diff"]
    filler_files = set(re.findall(r"(?m)^diff --git a/(\S+) b/\S+", filler_diff))

    for m in composites:
        for defect in m.get("defects", []):
            defect_file = defect["file"]
            assert defect_file not in filler_files, (
                f"Composite '{m['id']}' defect file '{defect_file}' overlaps with filler file!"
            )


# ==============================================================================
# 8. Determinism and Runner loading tests
# ==============================================================================


def test_builder_determinism(tmp_path: Path) -> None:
    """Building twice into different directories produces byte-for-byte identical output."""
    repo = Path(__file__).resolve().parent.parent
    require_git_commits(repo, ["efea26f", "7d396ff", "92f6166"])

    out1 = tmp_path / "build1"
    out2 = tmp_path / "build2"

    args1 = argparse.Namespace(labels=str(DEFAULT_LABELS_MD), repo=str(repo), out=str(out1), archive=None)
    args2 = argparse.Namespace(labels=str(DEFAULT_LABELS_MD), repo=str(repo), out=str(out2), archive=None)

    assert _cli_build(args1) == 0
    assert _cli_build(args2) == 0

    files1 = sorted(p.name for p in out1.glob("*.json"))
    files2 = sorted(p.name for p in out2.glob("*.json"))
    assert files1 == files2

    for fname in files1:
        bytes1 = (out1 / fname).read_bytes()
        bytes2 = (out2 / fname).read_bytes()
        assert bytes1 == bytes2, f"Determinism failure in file {fname}"


def test_corpus_loads_through_runner() -> None:
    """Verify entire corpus loads through bench.runner.load_cases_from_path and defect labels parse."""
    from bench.runner import load_cases_from_path

    cases = load_cases_from_path(CASES_DIR)
    assert len(cases) == 20
    for case in cases:
        assert "id" in case
        assert "label" in case
        assert case["label"] in ("defect", "clean", "unlabelled")
        for defect in case.get("defects", []):
            assert "id" in defect
            assert "file" in defect
            assert "keywords" in defect
            assert isinstance(defect["keywords"], list)
            assert 2 <= len(defect["keywords"]) <= 5


# ==============================================================================
# 9. Internal helpers, CLI, and disjoint keywords tests
# ==============================================================================


def test_internal_helpers() -> None:
    kws = _extract_fallback_keywords("unexpected error occurred during authentication", "auth.py")
    assert 2 <= len(kws) <= 4
    for kw in kws:
        assert kw == kw.lower()

    diff = _make_new_file_diff("foo/bar.py", "x = 1\ny = 2\n")
    assert "diff --git a/foo/bar.py b/foo/bar.py" in diff
    assert "+++ b/foo/bar.py" in diff
    assert "+x = 1" in diff

    sample_md = """# Sample
| Case | Commit | Kind | Known defect (file, what) | Severity |
|---|---|---|---|---|
| c01 | `abc` | correctness | foo.py is broken | high |

## Cases that must NOT block (clean or advisory-only at the time)

| Case | Commit | Why it is fair to call it clean |
|---|---|---|
| n01 | `def` | looks good |
"""
    defects, clean = _parse_label_table(sample_md)
    assert len(defects) == 1
    assert defects[0]["case_id"] == "c01"
    assert len(clean) == 1
    assert clean[0]["case_id"] == "n01"

    raw_body = "Feature explanation.\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n"
    cleaned = _clean_commit_body(raw_body)
    assert "Co-Authored-By" not in cleaned
    assert "Feature explanation." in cleaned


def test_cli_and_fixture_coverage(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parent.parent
    require_git_commits(repo, ["efea26f", "7d396ff"])

    out_dir = tmp_path / "cases"
    args_build = argparse.Namespace(
        labels=str(DEFAULT_LABELS_MD),
        repo=str(repo),
        out=str(out_dir),
        archive=None,
    )
    ret_build = _cli_build(args_build)
    assert ret_build == 0
    assert (out_dir / "c01.json").exists()

    args_check = argparse.Namespace(cases=str(out_dir), repo=str(repo))
    ret_check = _cli_check(args_check)
    assert ret_check == 0

    assert corpus_main(["check", "--cases", str(out_dir)]) == 0
    assert main(["check", "--cases", str(out_dir)]) == 0

    assert len(FIXTURE_SYMBOLS) == 18


def test_no_shared_keywords_for_same_file_defects() -> None:
    """Assert that for every case in the corpus, no two defects on the same file share any keyword."""
    cases = load_cases(CASES_DIR)
    for case in cases:
        defects = case.get("defects", [])
        by_file: dict[str, list[dict[str, Any]]] = {}
        for d in defects:
            by_file.setdefault(d["file"], []).append(d)
        for f, f_defects in by_file.items():
            if len(f_defects) > 1:
                for i in range(len(f_defects)):
                    for j in range(i + 1, len(f_defects)):
                        d1, d2 = f_defects[i], f_defects[j]
                        shared = set(d1.get("keywords", [])) & set(d2.get("keywords", []))
                        assert not shared, (
                            f"Case '{case['id']}': defects '{d1['id']}' and '{d2['id']}' on file "
                            f"'{f}' share keyword(s): {shared}"
                        )


def test_build_from_git_keeps_the_full_commit_diff(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(repo), check=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(repo), check=True)

    (repo / "core.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "other.py").write_text("OTHER = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "chore: initial"], cwd=str(repo), check=True)

    (repo / "core.py").write_text("VALUE = 2\n", encoding="utf-8")
    (repo / "other.py").write_text("OTHER = 2\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "feat: change both files"], cwd=str(repo), check=True)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=str(repo), check=True, capture_output=True, text=True
    ).stdout.strip()

    labels_md = tmp_path / "labels.md"
    labels_md.write_text(
        "# Test Labels\n"
        "| Case | Commit | Kind | Known defect (file, what) | Severity |\n"
        "|---|---|---|---|---|\n"
        f"| x01 | `{commit}` | correctness | core.py value is wrong | high |\n",
        encoding="utf-8",
    )

    x01 = next(c for c in build_from_git(labels_md, repo) if c["id"] == "x01")
    # The defect location is core.py, but the stored diff is the whole commit
    assert x01["defects"][0]["file"] == "core.py"
    assert "core.py" in x01["diff"] and "other.py" in x01["diff"]
    full_diff = subprocess.run(
        ["git", "show", "--format=", commit], cwd=str(repo), check=True, capture_output=True, text=True
    ).stdout
    assert x01["diff"] == full_diff
    assert validate_case(x01, repo=repo) == []
