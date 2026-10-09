"""Diff partitioning and batching for multi-part LLM review.

Splits git diffs on file boundaries into parts of at most REVIEW_BATCH_CHARS characters,
capturing skipped asset/binary files, omitted content of deleted files, and cut-off parts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from guard.core.unified_diff import GIT_HEADER, chunk_paths, parse_git_header, split_file_chunks, walk_diff

REVIEW_BATCH_CHARS = 80000
REVIEW_MAX_BATCHES = 6


def _extract_filename(first_line: str) -> str:
    """Extract file path from the diff header line following 'diff --git '."""
    parsed = parse_git_header(GIT_HEADER + first_line.strip())
    if parsed:
        return parsed[1]
    line = first_line.strip()
    return line[2:] if line.startswith("a/") else line


def _file_chunks(raw_diff: str) -> list[tuple[str, str]]:
    """(file name, chunk) per file of a diff; text before the first file (an error note) is a chunk of its own."""
    head, chunks = split_file_chunks(raw_diff)
    out = [(head.strip().splitlines()[0], head)] if head.strip() else []
    return out + [(chunk_paths(c)[1] or _extract_filename(c.splitlines()[0][len(GIT_HEADER):]), c) for c in chunks]


@dataclass
class DiffPartition:
    parts: list[str]
    skipped_files: list[str]
    omitted_deleted: list[str]
    cut_parts: int
    files_per_part: list[list[str]]
    max_batches: int = REVIEW_MAX_BATCHES


def partition_diff(
    raw_diff: str,
    batch_chars: int = REVIEW_BATCH_CHARS,
    max_batches: int = REVIEW_MAX_BATCHES,
) -> DiffPartition:
    """Split raw git diff into reviewable parts respecting size limits."""
    if not raw_diff:
        return DiffPartition(
            parts=["No diff"],
            skipped_files=[],
            omitted_deleted=[],
            cut_parts=0,
            files_per_part=[[]],
            max_batches=max_batches,
        )

    code_chunks: list[str] = []
    chunk_files: list[str] = []
    skipped_files: list[str] = []
    omitted_deleted: list[str] = []

    for fname, chunk in _file_chunks(raw_diff):
        first_line = chunk.splitlines()[0]
        if any(k in first_line for k in ["assets/", ".lock", "-lock.", ".svg", ".png", ".onnx", "tokenizer.json"]):
            skipped_files.append(fname)
            continue
        if "\ndeleted file mode" in chunk.split("@@", 1)[0]:
            omitted_deleted.append(fname)
            head = chunk.split("\n@@", 1)[0]
            removed = sum(1 for d in walk_diff(chunk) if d.kind == "-")
            chunk = f"{head}\n[file deleted: {removed} lines removed; content omitted]\n"
        prefix = f"{chunk.splitlines()[0]}\n[continued: next part of this file's diff]\n"
        code_chunks.append(chunk[:batch_chars])
        chunk_files.append(fname)
        step = max(1, batch_chars - len(prefix))
        for k in range(batch_chars, len(chunk), step):
            code_chunks.append(prefix + chunk[k:k + step])
            chunk_files.append(fname)

    if not code_chunks:
        return DiffPartition(
            parts=["No code diff (only lockfiles/assets changed)"],
            skipped_files=skipped_files,
            omitted_deleted=omitted_deleted,
            cut_parts=0,
            files_per_part=[[]],
            max_batches=max_batches,
        )

    batches: list[str] = []
    files_batches: list[list[str]] = []
    current = ""
    current_files: list[str] = []

    for chunk, fn in zip(code_chunks, chunk_files, strict=True):
        if current and len(current) + len(chunk) > batch_chars:
            batches.append(current)
            files_batches.append(current_files)
            current = ""
            current_files = []
        current += chunk
        if fn not in current_files:
            current_files.append(fn)

    batches.append(current)
    files_batches.append(current_files)

    if len(batches) > max_batches:
        cut_parts = len(batches) - max_batches
        parts = batches[:max_batches] + [
            f"[{cut_parts} more diff parts were NOT reviewed (limit {max_batches}); treat them as unreviewed]"
        ]
        files_per_part = files_batches[:max_batches] + [[]]
    else:
        cut_parts = 0
        parts = batches
        files_per_part = files_batches

    return DiffPartition(
        parts=parts,
        skipped_files=skipped_files,
        omitted_deleted=omitted_deleted,
        cut_parts=cut_parts,
        files_per_part=files_per_part,
        max_batches=max_batches,
    )


def _part_file_stats(part_text: str) -> list[tuple[str, int, int]]:
    """Extract (file_path, insertions, deletions) for each file in a diff part."""
    file_map: dict[str, list[int]] = {}
    for fname, chunk in _file_chunks(part_text):
        if "[file deleted:" in chunk:
            m = re.search(r"\[file deleted:\s*(\d+)\s*lines removed", chunk)
            del_count = int(m.group(1)) if m else 0
            ins = 0
        else:
            kinds = [d.kind for d in walk_diff(chunk)]
            ins, del_count = kinds.count("+"), kinds.count("-")
        if fname not in file_map:
            file_map[fname] = [ins, del_count]
        else:
            file_map[fname][0] += ins
            file_map[fname][1] += del_count
    return [(fn, counts[0], counts[1]) for fn, counts in file_map.items()]


def part_manifest(p: DiffPartition, i: int, max_chars: int = 1500) -> str:
    """Return manifest text listing other parts and their touched files with +/- counts.

    i is 1-based part index (1..N). If 0 is passed, it is treated as part 1.
    For a diff with one part, returns "".
    """
    reviewable_parts = [
        part for part in p.parts
        if not (part.startswith("[") and "more diff parts were NOT reviewed" in part)
    ]
    if len(reviewable_parts) <= 1:
        return ""

    total_parts = len(reviewable_parts)
    if i <= 0:
        current_idx = 1
    elif i > total_parts:
        current_idx = total_parts
    else:
        current_idx = i

    other_parts_stats: list[tuple[int, list[tuple[str, int, int]]]] = []
    for part_num, part_text in enumerate(reviewable_parts, 1):
        if part_num == current_idx:
            continue
        stats = _part_file_stats(part_text)
        if stats:
            other_parts_stats.append((part_num, stats))

    if not other_parts_stats:
        return ""

    total_other_files = sum(len(stats) for _, stats in other_parts_stats)
    prefix = "Other parts of this same diff (judge only this part, but content may have moved to them): "

    parts_strs: list[str] = []
    for part_num, stats in other_parts_stats:
        files_str = ", ".join(f"{fn} (+{ins} -{dels})" for fn, ins, dels in stats)
        parts_strs.append(f"part {part_num}/{total_parts}: {files_str}")
    full_manifest = prefix + "; ".join(parts_strs)
    if len(full_manifest) <= max_chars:
        return full_manifest

    # Capped at max_chars, ending with '... and N more files'
    out = prefix
    files_included = 0
    current_part_num = None
    first_file_in_part = True

    for part_num, stats in other_parts_stats:
        part_prefix = (
            f"part {part_num}/{total_parts}: "
            if current_part_num is None
            else f"; part {part_num}/{total_parts}: "
        )
        temp_out = out + part_prefix
        current_part_num = part_num
        first_file_in_part = True

        for fn, ins, dels in stats:
            file_str = f"{fn} (+{ins} -{dels})"
            sep = "" if first_file_in_part else ", "
            candidate = sep + file_str
            remaining = total_other_files - (files_included + 1)
            suffix = f", ... and {remaining} more files" if remaining > 0 else ""

            if len(temp_out + candidate + suffix) <= max_chars:
                temp_out += candidate
                files_included += 1
                first_file_in_part = False
                out = temp_out
            else:
                remaining = total_other_files - files_included
                suffix = f", ... and {remaining} more files" if files_included > 0 else f"... and {remaining} more files"
                final_str = out + suffix
                if len(final_str) > max_chars:
                    final_str = final_str[:max_chars]
                return final_str

    return out[:max_chars]
