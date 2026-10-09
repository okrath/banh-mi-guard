"""
Review ensemble runner for banh-mi-guard.

Runs a panel of independent review lenses concurrently over diff parts on daemon
threads, merges results in lens-then-part order, checks locations against diff hunks,
deduplicates findings with provenance tracking, and enforces fail-closed semantics.
"""

from __future__ import annotations

import difflib
import math
import queue
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from guard.core.findings import Finding
from guard.core.review_lenses import LENSES, Lens
from guard.core.unified_diff import parse_hunk_header, walk_diff

SEVERITY_ORDER: Dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


@dataclass
class EnsembleResult:
    """The outcome of running an ensemble of review lenses over diff parts."""

    findings: List[Finding]
    usable: int
    failed: List[str]
    calls: int
    chars_sent: int
    provenance: Dict[str, List[str]]


@dataclass
class FileDiffInfo:
    """Parsed git diff information for a single file."""

    is_deleted: bool = False
    old_ranges: List[Tuple[int, int]] = field(default_factory=list)
    new_ranges: List[Tuple[int, int]] = field(default_factory=list)


def _normalize_path(path: str) -> str:
    """Normalize a file path for comparison."""
    p = path.strip().replace("\\", "/")
    if p.startswith("./"):
        p = p[2:]
    return p.lower()


def _normalize_description(text: str) -> str:
    """Normalize finding description for comparison without importing private helpers."""
    cleaned = re.sub(r"[`'\"“”‘’]", "", text)
    return " ".join(cleaned.lower().split())


def _lens_rank(lens_key: str) -> int:
    """Determine ranking priority for a lens in LENSES order."""
    for idx, base_lens in enumerate(LENSES):
        if base_lens.key == lens_key:
            return idx
    return 9999


def _parse_location(location: str) -> Tuple[str, Optional[int]]:
    """Parse a finding location string into (file_path, line_number)."""
    parts = location.strip().split(":", 1)
    file_path = parts[0].strip().replace("\\", "/")
    line_num: Optional[int] = None
    if len(parts) > 1:
        m = re.match(r"^(\d+)", parts[1].strip())
        if m:
            line_num = int(m.group(1))
    return file_path, line_num


def _parse_diff(parts: Sequence[str]) -> Dict[str, FileDiffInfo]:
    """
    Parse diff parts into FileDiffInfo for each touched file.

    Removed SQL or Lua comments inside a hunk are content, never file headers.
    """
    files: Dict[str, FileDiffInfo] = {}

    def get_or_create(p: str) -> FileDiffInfo:
        norm = _normalize_path(p)
        if norm not in files:
            files[norm] = FileDiffInfo()
        return files[norm]

    for part in parts:
        current_files: List[str] = []
        for d in walk_diff(part):
            if d.kind == "file":
                current_files = [p for p in dict.fromkeys((d.old_path, d.path)) if p]
            elif d.kind == "header":
                fp = d.old_path if d.raw.startswith("--- ") else d.path
                if fp and fp not in current_files:
                    current_files.append(fp)
            elif d.kind == "hunk" and current_files:
                old_start, old_count, new_start, new_count = parse_hunk_header(d.raw) or (0, 0, 0, 0)
                old_end = old_start + old_count - 1 if old_count > 0 else old_start
                new_end = new_start + new_count - 1 if new_count > 0 else new_start
                for fp in current_files:
                    info = get_or_create(fp)
                    info.old_ranges.append((old_start, old_end))
                    info.new_ranges.append((new_start, new_end))
                continue
            for fp in current_files:
                get_or_create(fp).is_deleted |= d.deleted or d.raw.startswith("[file deleted:")

    return files


def _find_file_info(location_file: str, diff_files: Dict[str, FileDiffInfo]) -> Optional[FileDiffInfo]:
    """Find matching FileDiffInfo for a location file path."""
    norm = _normalize_path(location_file)
    if not norm:
        return None
    if norm in diff_files:
        return diff_files[norm]
    if norm.startswith(("a/", "b/")) and norm[2:] in diff_files:
        return diff_files[norm[2:]]
    suffix = "/" + norm
    for k, v in diff_files.items():
        if k.endswith(suffix):
            return v
    return None


def _is_location_verified(location: str, diff_files: Dict[str, FileDiffInfo]) -> bool:
    """
    Check if a location is verified against the diff.

    Verified when it names a file in the diff and the line (if given) is inside
    a hunk range on either side. A deleted file counts as verified for any line.
    """
    if not location.strip():
        return False
    file_path, line_num = _parse_location(location)
    info = _find_file_info(file_path, diff_files)
    if info is None:
        return False
    if info.is_deleted:
        return True
    if line_num is None:
        return True
    in_new = any(start <= line_num <= end for start, end in info.new_ranges)
    in_old = any(start <= line_num <= end for start, end in info.old_ranges)
    return in_new or in_old


def _is_same_file(file1: str, file2: str) -> bool:
    """Check if two file paths resolve to the same file in diff context."""
    clean1 = _normalize_path(file1)
    clean2 = _normalize_path(file2)
    if not clean1 or not clean2:
        return False
    if clean1 == clean2:
        return True
    return clean1.endswith("/" + clean2) or clean2.endswith("/" + clean1)


def _can_merge(
    rep_item: Tuple[Finding, Lens, List[Tuple[Lens, int]], int],
    cand_item: Tuple[Finding, Lens, int, int],
) -> bool:
    """
    Determine if candidate B should merge into representative A:
    1. NEVER merge if candidate's (lens.key, part_idx) is already present in cluster_members.
    2. Same file and same kind required.
    3. Across lenses: two blocking findings merge ONLY when normalized description
       similarity ratio is >= 0.6. Proximity within 3 lines merges only when at least
       one copy is NOT blocking.
    """
    rep_f, _, cluster_members, _ = rep_item
    cand_f, cand_lens, cand_part, _ = cand_item

    # 1. Never merge if candidate came from the same lens and same part as any member in this cluster
    if any(cl_lens.key == cand_lens.key and cl_part == cand_part for cl_lens, cl_part in cluster_members):
        return False

    # 2. Same file and same kind
    file_rep, line_rep = _parse_location(rep_f.location)
    file_cand, line_cand = _parse_location(cand_f.location)
    if not _is_same_file(file_rep, file_cand):
        return False
    if rep_f.kind.strip().lower() != cand_f.kind.strip().lower():
        return False

    # 3. Match rules
    line_match = line_rep is not None and line_cand is not None and abs(line_rep - line_cand) <= 3
    norm_rep = _normalize_description(rep_f.description)
    norm_cand = _normalize_description(cand_f.description)
    desc_match = difflib.SequenceMatcher(None, norm_rep, norm_cand).ratio() >= 0.6

    if rep_f.blocking and cand_f.blocking:
        # Two blocking findings merge ONLY when descriptions match closely
        return desc_match

    # At least one copy is not blocking: proximity or description similarity merges
    return line_match or desc_match


def _candidate_rank(
    finding: Finding,
    lens: Lens,
    original_idx: int,
) -> Tuple[int, int, int, int]:
    """
    Sorting key for deduplication candidate priority:
    Among two blocking copies, earliest lens in LENSES order wins whatever the severity.
    Severity ranking applies only when neither is blocking.
    """
    lens_rank = _lens_rank(lens.key)
    if finding.blocking:
        return (0, lens_rank, 0, original_idx)
    sev_rank = SEVERITY_ORDER.get(finding.severity.strip().lower(), 99)
    return (1, sev_rank, lens_rank, original_idx)


def _output_sort_key(item: Tuple[Finding, int]) -> Tuple[int, str, int, int, str]:
    """Sort output findings by severity, then file, then line, then lens order index, then id."""
    f, order_idx = item
    sev = SEVERITY_ORDER.get(f.severity.strip().lower(), 99)
    file_path, line_num = _parse_location(f.location)
    return (sev, _normalize_path(file_path), line_num if line_num is not None else 0, order_idx, f.id)


def _combine_system_prompt(base_prompt: str, lens_instruction: str) -> str:
    """
    Combine base system prompt (including focus) and lens instruction.
    For the correctness lens (empty lens_instruction), returns base_prompt without stripping.
    """
    if not lens_instruction:
        return base_prompt
    base = base_prompt.strip()
    lens = lens_instruction.strip()
    if base:
        return f"{base}\n\n{lens}"
    return lens


def _build_part_prompt(header: str, part: str, part_index: int, total_parts: int) -> str:
    """Format the review prompt for a single diff part exactly as the single reviewer does."""
    part_indicator = (
        f"Diff part {part_index}/{total_parts} (other parts are reviewed separately; judge only this part):\n"
        if total_parts > 1
        else ""
    )
    diff_block = f"Git Diff:\n```\n{part}\n```\n"
    if header:
        return f"{header}\n{part_indicator}{diff_block}"
    return f"{part_indicator}{diff_block}"


def run_ensemble(
    lenses: Sequence[Lens],
    call: Callable[[str, str], str],
    header: str,
    parts: Sequence[str],
    parse: Callable[[str], Optional[List[Finding]]],
    *,
    max_calls: int,
    format_reminder: str,
    system_prompt: str,
    stage_timeout_s: float = 900.0,
) -> Optional[EnsembleResult]:
    """
    Run an opt-in panel of independent review lenses over diff parts on daemon threads.

    Returns the union of evidence-checked findings, or None if the worst-case
    call budget exceeds max_calls or too few lenses produce a parseable answer.
    """
    if not lenses or not parts:
        return None

    # Pre-check: worst case is 2 calls per (lens, part) with format retry
    worst_case_calls = 2 * len(lenses) * len(parts)
    if worst_case_calls > max_calls:
        return None

    counter_lock = threading.Lock()
    cancelled = threading.Event()
    semaphore = threading.Semaphore(3)
    calls_made = 0
    chars_sent = 0

    def make_call(system: str, prompt: str) -> str:
        nonlocal calls_made, chars_sent
        if cancelled.is_set():
            raise RuntimeError("ensemble stage cancelled")
        with counter_lock:
            if cancelled.is_set():
                raise RuntimeError("ensemble stage cancelled")
            calls_made += 1
            chars_sent += len(system) + len(prompt)
        return call(system, prompt)

    result_queue: queue.Queue[
        Tuple[Lens, Optional[List[List[Finding]]], List[List[Finding]]]
    ] = queue.Queue()

    def lens_worker(lens_obj: Lens) -> None:
        try:
            with semaphore:
                if cancelled.is_set():
                    result_queue.put((lens_obj, None, []))
                    return

                combined_system = _combine_system_prompt(system_prompt, lens_obj.instruction)
                completed_findings: List[List[Finding]] = []

                for i, part in enumerate(parts, start=1):
                    if cancelled.is_set():
                        break

                    prompt_text = _build_part_prompt(header, part, i, len(parts))
                    parsed_findings: Optional[List[Finding]] = None

                    for attempt in range(2):
                        if cancelled.is_set():
                            break
                        used_prompt = prompt_text if attempt == 0 else prompt_text + format_reminder
                        try:
                            response = make_call(combined_system, used_prompt)
                        except Exception:
                            break

                        parsed = parse(response)
                        if parsed is not None:
                            parsed_findings = parsed
                            break

                    if parsed_findings is None:
                        break

                    completed_findings.append(parsed_findings)

                if len(completed_findings) == len(parts):
                    result_queue.put((lens_obj, completed_findings, []))
                else:
                    result_queue.put((lens_obj, None, completed_findings))
        except Exception:
            result_queue.put((lens_obj, None, []))

    for lens in lenses:
        worker_thread = threading.Thread(target=lens_worker, args=(lens,), daemon=True)
        worker_thread.start()

    deadline = time.monotonic() + stage_timeout_s
    lens_results: Dict[str, List[List[Finding]]] = {}
    partial_results: Dict[str, List[List[Finding]]] = {}
    failed_keys: set[str] = set()
    completed_lens_keys: set[str] = set()

    for _ in range(len(lenses)):
        remaining = max(0.0, deadline - time.monotonic())
        if remaining <= 0:
            break
        try:
            res_lens, completed_parts, partial_parts = result_queue.get(timeout=remaining)
            completed_lens_keys.add(res_lens.key)
            if completed_parts is not None:
                lens_results[res_lens.key] = completed_parts
            else:
                failed_keys.add(res_lens.key)
                if partial_parts:
                    partial_results[res_lens.key] = partial_parts
        except queue.Empty:
            break

    # Record timed-out lenses that did not complete before deadline
    for lens in lenses:
        if lens.key not in completed_lens_keys:
            failed_keys.add(lens.key)

    if len(completed_lens_keys) < len(lenses):
        cancelled.set()

    with counter_lock:
        final_calls = calls_made
        final_chars = chars_sent

    usable = len(lens_results)

    # Fail closed: must produce a parseable answer for EVERY part from ceil(len(lenses)/2) lenses
    quorum = math.ceil(len(lenses) / 2)
    if usable < quorum:
        cancelled.set()
        return None

    # Merge candidates in lens order, then part order (never completion order)
    raw_candidates: List[Tuple[Finding, Lens, int, int]] = []
    candidate_idx = 0
    for lens in lenses:
        if lens.key in lens_results:
            parts_findings = lens_results[lens.key]
            for part_idx, part_findings in enumerate(parts_findings):
                for f in part_findings:
                    raw_candidates.append((f.model_copy(), lens, part_idx, candidate_idx))
                    candidate_idx += 1
        elif lens.key in partial_results:
            parts_findings = partial_results[lens.key]
            for part_idx, part_findings in enumerate(parts_findings):
                for f in part_findings:
                    f_copy = f.model_copy()
                    f_copy.description = f"{f_copy.description} [from a lens that failed on a later part]"
                    raw_candidates.append((f_copy, lens, part_idx, candidate_idx))
                    candidate_idx += 1

    # Pairwise deduplication against kept representative (non-transitive)
    sorted_candidates = sorted(
        raw_candidates,
        key=lambda item: _candidate_rank(item[0], item[1], item[3]),
    )

    representatives: List[Tuple[Finding, Lens, List[Tuple[Lens, int]], int]] = []
    for cand_item in sorted_candidates:
        cand_f, cand_lens, cand_part, cand_order = cand_item
        matched = False
        for rep_item in representatives:
            if _can_merge(rep_item, cand_item):
                rep_item[2].append((cand_lens, cand_part))
                matched = True
                break
        if not matched:
            representatives.append((cand_f.model_copy(), cand_lens, [(cand_lens, cand_part)], cand_order))

    # Location check and provenance applied AFTER dedupe
    diff_info = _parse_diff(parts)
    deduped_findings_with_order: List[Tuple[Finding, int]] = []
    provenance: Dict[str, List[str]] = {}

    for kept_finding, winner_lens, cluster_members, rep_order in representatives:
        if not _is_location_verified(kept_finding.location, diff_info):
            if " [location not verified in the diff]" not in kept_finding.description:
                kept_finding.description = f"{kept_finding.description} [location not verified in the diff]"

        unique_lenses: List[Lens] = []
        seen_keys: set[str] = set()
        for cl_lens, _ in cluster_members:
            if cl_lens.key not in seen_keys:
                seen_keys.add(cl_lens.key)
                unique_lenses.append(cl_lens)

        sorted_cluster_lenses = sorted(
            unique_lenses,
            key=lambda lens_item: _lens_rank(lens_item.key),
        )
        provenance[kept_finding.id] = [lens_item.key for lens_item in sorted_cluster_lenses]

        other_lens_names = [
            lens_item.name
            for lens_item in sorted_cluster_lenses
            if lens_item.key != winner_lens.key
        ]
        if other_lens_names:
            kept_finding.description = (
                f"{kept_finding.description} [also found by: {', '.join(other_lens_names)}]"
            )

        deduped_findings_with_order.append((kept_finding, rep_order))

    final_findings = [
        f for f, _ in sorted(deduped_findings_with_order, key=_output_sort_key)
    ]

    return EnsembleResult(
        findings=final_findings,
        usable=usable,
        failed=[lens.key for lens in lenses if lens.key in failed_keys],
        calls=final_calls,
        chars_sent=final_chars,
        provenance=provenance,
    )
