"""Tests for diff partitioning, batching, and part manifest generation."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

from guard.core.diff_partition import (
    REVIEW_BATCH_CHARS,
    REVIEW_MAX_BATCHES,
    DiffPartition,
    _extract_filename,
    _part_file_stats,
    part_manifest,
    partition_diff,
)


def _load_old_reviewer_from_pinned():
    """Load LLMReviewerEngine from the pinned commit 7f67d12."""
    check = subprocess.run(
        ["git", "cat-file", "-e", "7f67d12"],
        capture_output=True,
    )
    if check.returncode != 0:
        pytest.skip("commit 7f67d12 not found in git")

    out = subprocess.check_output(
        ["git", "show", "7f67d12:guard/core/llm_reviewer.py"],
        text=True,
    )
    spec = importlib.util.spec_from_loader("old_llm_reviewer_pinned", loader=None)
    if spec is None:
        pytest.skip("failed to create module spec for old reviewer")
    mod = importlib.util.module_from_spec(spec)
    exec(out, mod.__dict__)
    return mod


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_constants_defined():
    """Verify REVIEW_BATCH_CHARS and REVIEW_MAX_BATCHES constants."""
    assert REVIEW_BATCH_CHARS == 80000
    assert REVIEW_MAX_BATCHES == 6


# ---------------------------------------------------------------------------
# Layer 1: Golden Fixtures Equivalence (Always runs)
# ---------------------------------------------------------------------------


def test_golden_fixtures_equivalence():
    """Golden fixtures test loaded from tracked JSON, always runs even in CI."""
    fixtures_path = Path(__file__).parent / "fixtures" / "diff_partition" / "golden_cases.json"
    assert fixtures_path.exists(), f"Missing golden cases fixture: {fixtures_path}"

    with open(fixtures_path, encoding="utf-8") as f:
        cases = json.load(f)

    assert len(cases) >= 7
    for case in cases:
        name = case["name"]
        raw_diff = case["raw_diff"]
        expected_parts = case["expected_parts"]

        partition = partition_diff(raw_diff)
        assert partition.parts == expected_parts, f"Mismatch in golden fixture case: {name}"


# ---------------------------------------------------------------------------
# Layer 2: Live Comparison with pinned commit 7f67d12
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case_builder",
    [
        lambda: ("", "empty"),
        lambda: (
            "diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n@@ -1,1 +1,2 @@\n+x = 1\n",
            "one_file",
        ),
        lambda: (
            "diff --git a/assets/img.png b/assets/img.png\n"
            "new file mode 100644\n"
            "diff --git a/yarn.lock b/yarn.lock\n"
            "+lock\n"
            "diff --git a/app.py b/app.py\n"
            "+code\n",
            "asset_and_lockfile",
        ),
        lambda: (
            "diff --git a/old.py b/old.py\n"
            "deleted file mode 100644\n"
            "--- a/old.py\n"
            "+++ /dev/null\n"
            "@@ -1,3 +0,0 @@\n"
            "-a\n-b\n-c\n"
            "diff --git a/new.py b/new.py\n"
            "+new code\n",
            "deleted_file",
        ),
        lambda: (
            "diff --git a/oversized.py b/oversized.py\n@@ -0,0 +1,4000 @@\n"
            + "".join(f"+line_{i} = 'text'\n" for i in range(4000)),
            "oversized_single_file",
        ),
        lambda: (
            "".join(
                f"diff --git a/mod_{i:02d}.py b/mod_{i:02d}.py\n"
                f"--- /dev/null\n+++ b/mod_{i:02d}.py\n@@ -0,0 +1,30 @@\n"
                + "+val = 'x' * 80\n" * 30
                for i in range(80)
            ),
            "eighty_files_many_parts",
        ),
        lambda: (
            "".join(
                f"diff --git a/big_{i}.py b/big_{i}.py\n@@ -0,0 +1,1000 @@\n"
                + "+code = 1234567890\n" * 2500
                for i in range(8)
            ),
            "over_batch_limit",
        ),
    ],
)
def test_live_comparison_with_pinned_commit(case_builder):
    """Compare partition_diff directly against old method from pinned commit 7f67d12."""
    old_mod = _load_old_reviewer_from_pinned()
    old_engine = old_mod.LLMReviewerEngine()
    diff_summary_cls = old_mod.DiffSummary

    raw_diff, case_name = case_builder()
    old_parts = old_engine._prepare_diff_batches(diff_summary_cls(raw_diff=raw_diff) if raw_diff else None)
    new_partition = partition_diff(raw_diff)

    assert new_partition.parts == old_parts, f"Mismatch in live comparison for {case_name}"


def test_live_comparison_over_history_diffs():
    """Run equivalence test over repo .guard/history/*.json diffs if the folder exists."""
    history_dir = Path(".guard/history")
    if not history_dir.exists():
        pytest.skip(".guard/history does not exist in worktree")

    history_files = list(history_dir.glob("*.json"))
    if not history_files:
        pytest.skip("no history session files found in .guard/history")

    old_mod = _load_old_reviewer_from_pinned()
    old_engine = old_mod.LLMReviewerEngine()
    diff_summary_cls = old_mod.DiffSummary

    checked = 0
    for hf in history_files:
        try:
            with open(hf, encoding="utf-8") as f:
                data = json.load(f)
            raw_diff = (
                data.get("post", {}).get("diff_summary", {}).get("raw_diff")
                or data.get("diff_summary", {}).get("raw_diff")
            )
            if raw_diff is not None:
                old_parts = old_engine._prepare_diff_batches(diff_summary_cls(raw_diff=raw_diff))
                new_partition = partition_diff(raw_diff)
                assert new_partition.parts == old_parts
                checked += 1
        except Exception:
            continue

    if checked == 0:
        pytest.skip("no raw_diff entries found in .guard/history/*.json")


# ---------------------------------------------------------------------------
# Metadata and Field Tests for DiffPartition
# ---------------------------------------------------------------------------


def test_extract_filename_helper():
    """Verify internal _extract_filename on various git header formats."""
    assert _extract_filename("a/src/foo.py b/src/foo.py") == "src/foo.py"
    assert _extract_filename('"a/path with space.txt" "b/path with space.txt"') == "path with space.txt"
    assert _extract_filename("a/bar.py") == "bar.py"


def test_part_file_stats_helper():
    """Verify internal _part_file_stats extracts accurate line counts."""
    part = (
        "diff --git a/a.py b/a.py\n+x = 1\n+y = 2\n-z = 3\n"
        "diff --git a/b.py b/b.py\n[file deleted: 4 lines removed; content omitted]\n"
    )
    stats = _part_file_stats(part)
    assert stats == [("a.py", 2, 1), ("b.py", 0, 4)]


def test_partition_diff_captures_skipped_files():
    """Assets, lockfiles, and images are recorded in skipped_files."""
    diff = (
        "diff --git a/assets/icon.svg b/assets/icon.svg\n+svg\n"
        "diff --git a/package-lock.json b/package-lock.json\n+lock\n"
        "diff --git a/models/weights.onnx b/models/weights.onnx\n+onnx\n"
        "diff --git a/src/app.py b/src/app.py\n+print('hello')\n"
    )
    p = partition_diff(diff)
    assert p.skipped_files == ["assets/icon.svg", "package-lock.json", "models/weights.onnx"]
    assert len(p.parts) == 1
    assert "src/app.py" in p.parts[0]
    assert "package-lock.json" not in p.parts[0]


def test_partition_diff_captures_omitted_deleted_files():
    """Deleted files are summarized and captured in omitted_deleted."""
    diff = (
        "diff --git a/old.py b/old.py\n"
        "deleted file mode 100644\n"
        "--- a/old.py\n"
        "+++ /dev/null\n"
        "@@ -1,4 +0,0 @@\n"
        "-line1\n-line2\n-line3\n-line4\n"
        "diff --git a/kept.py b/kept.py\n"
        "+print('kept')\n"
    )
    p = partition_diff(diff)
    assert p.omitted_deleted == ["old.py"]
    assert "[file deleted: 4 lines removed; content omitted]" in p.parts[0]


def test_partition_diff_cut_parts_and_sentinel():
    """Diff exceeding max_batches sets cut_parts and appends sentinel."""
    # 8 files of ~80 characters each, with batch_chars=100 and max_batches=3
    # Each file takes ~80 chars, so each file forms 1 batch (2 files would be ~160 > 100)
    diff = "".join(f"diff --git a/f{i}.py b/f{i}.py\n" + "+x = 12345678901234567890\n" * 2 for i in range(8))
    p = partition_diff(diff, batch_chars=100, max_batches=3)
    assert p.cut_parts == 5
    assert len(p.parts) == 4  # 3 code parts + 1 sentinel
    assert "5 more diff parts were NOT reviewed (limit 3)" in p.parts[-1]
    assert len(p.files_per_part) == 4
    assert p.files_per_part[-1] == []


def test_partition_diff_files_per_part_split_file():
    """A file split across parts appears in each part's file list."""
    diff = (
        "diff --git a/split.py b/split.py\n"
        + "".join(f"+line_{i} = {i}\n" for i in range(60))
    )
    # With max_batches=10, all parts are reviewed without cut parts
    p = partition_diff(diff, batch_chars=200, max_batches=10)
    assert len(p.parts) > 1
    assert p.cut_parts == 0
    for part_files in p.files_per_part:
        assert part_files == ["split.py"]


def test_partition_diff_only_skipped_files():
    """When only skipped files change, returns sentinel and tracks skipped."""
    diff = "diff --git a/yarn.lock b/yarn.lock\n+lock_line\n"
    p = partition_diff(diff)
    assert p.parts == ["No code diff (only lockfiles/assets changed)"]
    assert p.skipped_files == ["yarn.lock"]
    assert p.cut_parts == 0
    assert p.files_per_part == [[]]


def test_partition_diff_empty_input():
    """Empty raw_diff returns No diff."""
    p = partition_diff("")
    assert p.parts == ["No diff"]
    assert p.skipped_files == []
    assert p.omitted_deleted == []
    assert p.cut_parts == 0
    assert p.files_per_part == [[]]


# ---------------------------------------------------------------------------
# Tests for part_manifest
# ---------------------------------------------------------------------------


def test_part_manifest_single_part_returns_empty():
    """For a diff with one part, part_manifest returns empty string."""
    diff = "diff --git a/a.py b/a.py\n+x = 1\n"
    p = partition_diff(diff)
    assert len(p.parts) == 1
    assert part_manifest(p, 1) == ""
    assert part_manifest(p, 0) == ""


def test_part_manifest_multi_part_content_and_indices():
    """Part manifest correctly lists other parts with +/- line counts."""
    diff = (
        "diff --git a/src/a.py b/src/a.py\n"
        + "+line\n" * 12 + "-line\n" * 3
        + "diff --git a/docs/x.md b/docs/x.md\n"
        + "+line\n" * 8 + "-line\n" * 40
        + "diff --git a/tests/test_a.py b/tests/test_a.py\n"
        + "+line\n" * 50
    )
    # Force 3 parts with small batch_chars
    p = partition_diff(diff, batch_chars=180, max_batches=5)
    assert len(p.parts) >= 2

    # Manifest for part 1 should list part 2 (and 3 if present), but not part 1
    m1 = part_manifest(p, 1)
    assert "Other parts of this same diff" in m1
    assert "part 1/" not in m1  # part 1 is current, not in other parts
    assert "part 2/" in m1

    # Calling with 0 is treated as part 1
    assert part_manifest(p, 0) == m1

    # Manifest for part 2 should list part 1
    m2 = part_manifest(p, 2)
    assert "part 1/" in m2
    assert "part 2/" not in m2


def test_part_manifest_capping_and_more_files_marker():
    """Manifest exceeding max_chars is capped and ends with '... and N more files'."""
    part1 = "diff --git a/a.py b/a.py\n+x = 1\n"
    part2 = "".join(f"diff --git a/f{i}.py b/f{i}.py\n+x = 1\n" for i in range(30))
    p = partition_diff(part1 + part2, batch_chars=250, max_batches=5)
    assert len(p.parts) >= 2

    # Capped at small limit
    capped = part_manifest(p, 1, max_chars=150)
    assert len(capped) <= 150
    assert "... and" in capped and "more files" in capped

    # Default 1500 limit is respected
    default_capped = part_manifest(p, 1)
    assert len(default_capped) <= 1500


def test_part_manifest_on_hand_constructed_partition():
    """part_manifest functions correctly on manually constructed DiffPartition."""
    p = DiffPartition(
        parts=[
            "diff --git a/a.py b/a.py\n+a = 1\n",
            "diff --git a/b.py b/b.py\n+b = 2\n-b = 1\n",
            "diff --git a/c.py b/c.py\n[file deleted: 5 lines removed; content omitted]\n",
        ],
        skipped_files=[],
        omitted_deleted=["c.py"],
        cut_parts=0,
        files_per_part=[["a.py"], ["b.py"], ["c.py"]],
    )
    m = part_manifest(p, 1)
    assert "part 2/3: b.py (+1 -1)" in m
    assert "part 3/3: c.py (+0 -5)" in m
    assert "a.py" not in m
