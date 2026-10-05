"""Tests for review coverage notes generator."""

from __future__ import annotations

from guard.core.diff_partition import DiffPartition
from guard.core.review_coverage import _format_file_list, build_coverage_notes


def test_format_file_list_helper():
    """Verify internal _format_file_list formatting and truncation."""
    assert _format_file_list(["a.py", "b.py"]) == "a.py, b.py"
    many = [f"f{i}.py" for i in range(12)]
    assert _format_file_list(many, max_shown=10) == ", ".join(many[:10]) + ", +2 more"


def test_coverage_notes_nothing_to_report():
    """Clean diff partition with no unreviewed items returns empty list."""
    partition = DiffPartition(
        parts=["diff --git a/a.py b/a.py\n+x = 1\n"],
        skipped_files=[],
        omitted_deleted=[],
        cut_parts=0,
        files_per_part=[["a.py"]],
    )
    notes = build_coverage_notes(partition, unreviewed=())
    assert notes == []


def test_coverage_notes_cut_parts():
    """Cut parts produces 'N diff part(s) were NOT reviewed (limit L).'"""
    partition = DiffPartition(
        parts=["part1", "part2", "[1 more diff parts were NOT reviewed]"],
        skipped_files=[],
        omitted_deleted=[],
        cut_parts=1,
        files_per_part=[["a.py"], ["b.py"], []],
        max_batches=2,
    )
    notes = build_coverage_notes(partition)
    assert len(notes) == 1
    assert notes[0] == "1 diff part(s) were NOT reviewed (limit 2)."


def test_coverage_notes_skipped_files_under_limit():
    """Skipped files under 10 are listed directly."""
    partition = DiffPartition(
        parts=["part1"],
        skipped_files=["logo.png", "yarn.lock"],
        omitted_deleted=[],
        cut_parts=0,
        files_per_part=[["a.py"]],
    )
    notes = build_coverage_notes(partition)
    assert len(notes) == 1
    assert notes[0] == "Not shown to the reviewer (assets, lockfiles, images): logo.png, yarn.lock."


def test_coverage_notes_skipped_files_over_limit():
    """Skipped files over 10 are formatted as 'first 10, then +N more'."""
    many_files = [f"asset_{i}.png" for i in range(14)]
    partition = DiffPartition(
        parts=["part1"],
        skipped_files=many_files,
        omitted_deleted=[],
        cut_parts=0,
        files_per_part=[["a.py"]],
    )
    notes = build_coverage_notes(partition)
    assert len(notes) == 1
    expected = (
        "Not shown to the reviewer (assets, lockfiles, images): "
        + ", ".join(many_files[:10])
        + ", +4 more."
    )
    assert notes[0] == expected


def test_coverage_notes_deleted_files_omitted():
    """Deleted files with omitted content are listed."""
    partition = DiffPartition(
        parts=["part1"],
        skipped_files=[],
        omitted_deleted=["old_helper.py", "legacy.js"],
        cut_parts=0,
        files_per_part=[["a.py"]],
    )
    notes = build_coverage_notes(partition)
    assert len(notes) == 1
    assert notes[0] == "Content omitted for deleted file(s): old_helper.py, legacy.js."


def test_coverage_notes_deleted_files_omitted_over_limit():
    """Deleted files over 10 are formatted with '+N more'."""
    many_deleted = [f"old_{i}.py" for i in range(12)]
    partition = DiffPartition(
        parts=["part1"],
        skipped_files=[],
        omitted_deleted=many_deleted,
        cut_parts=0,
        files_per_part=[["a.py"]],
    )
    notes = build_coverage_notes(partition)
    assert len(notes) == 1
    expected = "Content omitted for deleted file(s): " + ", ".join(many_deleted[:10]) + ", +2 more."
    assert notes[0] == expected


def test_coverage_notes_unreviewed_items():
    """Reviewer unreviewed list items are prefixed with 'Reviewer did not trace: '."""
    partition = DiffPartition(
        parts=["part1"],
        skipped_files=[],
        omitted_deleted=[],
        cut_parts=0,
        files_per_part=[["a.py"]],
    )
    unreviewed = ["oauth token expiry handling", "database migration rollback"]
    notes = build_coverage_notes(partition, unreviewed=unreviewed)
    assert len(notes) == 2
    assert notes[0] == "Reviewer did not trace: oauth token expiry handling."
    assert notes[1] == "Reviewer did not trace: database migration rollback."


def test_coverage_notes_stable_order_multiple_rules():
    """When multiple rules trigger, notes are in the stable order."""
    partition = DiffPartition(
        parts=["part1", "sentinel"],
        skipped_files=["icon.png"],
        omitted_deleted=["deprecated.py"],
        cut_parts=3,
        files_per_part=[["a.py"], []],
        max_batches=6,
    )
    unreviewed = ["background worker lifecycle"]
    notes = build_coverage_notes(partition, unreviewed=unreviewed)

    assert len(notes) == 4
    # Order check: 1. cut parts, 2. skipped files, 3. deleted files, 4. unreviewed
    assert "3 diff part(s) were NOT reviewed" in notes[0]
    assert "Not shown to the reviewer (assets, lockfiles, images): icon.png." in notes[1]
    assert "Content omitted for deleted file(s): deprecated.py." in notes[2]
    assert "Reviewer did not trace: background worker lifecycle." in notes[3]
