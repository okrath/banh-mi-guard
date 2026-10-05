"""Post-task review coverage notes generator.

Builds coverage notes for unreviewed aspects: parts cut by batch limits,
files filtered out before review (assets/lockfiles/binaries), deleted files
with omitted content, and items unreviewed by the model.
"""

from __future__ import annotations

from collections.abc import Sequence

from guard.core.diff_partition import REVIEW_MAX_BATCHES, DiffPartition


def _format_file_list(files: list[str], max_shown: int = 10) -> str:
    """Format file list with 'first 10, then +N more' pattern."""
    if len(files) <= max_shown:
        return ", ".join(files)
    shown = ", ".join(files[:max_shown])
    remaining = len(files) - max_shown
    return f"{shown}, +{remaining} more"


def build_coverage_notes(
    partition: DiffPartition,
    unreviewed: Sequence[str] = (),
) -> list[str]:
    """Return post-report coverage notes for unreviewed limits and skipped content.

    Stable order:
    1. Cut diff parts (limit exceeded)
    2. Skipped files (assets, lockfiles, images, tokenizer.json)
    3. Deleted files with omitted content
    4. Reviewer-reported unreviewed topics
    """
    notes: list[str] = []

    # 1. Cut parts
    if partition.cut_parts > 0:
        limit = getattr(partition, "max_batches", REVIEW_MAX_BATCHES)
        notes.append(f"{partition.cut_parts} diff part(s) were NOT reviewed (limit {limit}).")

    # 2. Skipped files
    if partition.skipped_files:
        files_text = _format_file_list(partition.skipped_files, max_shown=10)
        notes.append(f"Not shown to the reviewer (assets, lockfiles, images): {files_text}.")

    # 3. Deleted files with omitted content
    if partition.omitted_deleted:
        files_text = _format_file_list(partition.omitted_deleted, max_shown=10)
        notes.append(f"Content omitted for deleted file(s): {files_text}.")

    # 4. Reviewer's own unreviewed list
    for item in unreviewed:
        item_str = str(item).strip()
        if not item_str:
            continue
        if item_str.startswith("Reviewer did not trace: "):
            note = item_str
        else:
            note = f"Reviewer did not trace: {item_str}"
        if not note.endswith((".", "!", "?")):
            note += "."
        notes.append(note)

    return notes
