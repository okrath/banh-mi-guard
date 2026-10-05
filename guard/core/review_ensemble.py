"""
Review ensemble runner for banh-mi-guard.

Runs a panel of independent review lenses concurrently over diff parts,
merges results in lens-then-part order, checks locations against diff hunks,
deduplicates findings with provenance tracking, and enforces fail-closed semantics.
"""

from __future__ import annotations

import concurrent.futures
import difflib
import math
import re
import threading
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from guard.core.findings import Finding
from guard.core.review_lenses import LENSES, Lens

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


def _lens_rank(lens_key: str, lenses: Sequence[Lens]) -> int:
    """Determine ranking priority for a lens in LENSES order."""
    for idx, base_lens in enumerate(LENSES):
        if base_lens.key == lens_key:
            return idx
    for idx, extra_lens in enumerate(lenses):
        if extra_lens.key == lens_key:
            return 1000 + idx
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

    Matches diff headers at column 0 and avoids misidentifying body lines
    (such as removed SQL or Lua comments) as diff headers.
    """
    files: Dict[str, FileDiffInfo] = {}
    current_files: List[str] = []
    in_hunk = False

    def get_or_create(p: str) -> FileDiffInfo:
        norm = _normalize_path(p)
        if norm not in files:
            files[norm] = FileDiffInfo()
        return files[norm]

    for part in parts:
        in_hunk = False
        current_files = []
        for raw_line in part.splitlines():
            line = raw_line[:2000]

            # diff --git a/... b/... (starts at column 0)
            if line.startswith("diff --git a/"):
                in_hunk = False
                after = line[len("diff --git a/"):]
                if " b/" in after:
                    p_old, p_new = after.split(" b/", 1)
                    current_files = [p_old.strip(), p_new.strip()]
                    for fp in current_files:
                        get_or_create(fp)
                continue

            # Outside hunks: match file headers
            if not in_hunk:
                if line.startswith("--- a/"):
                    fp = line[len("--- a/"):].strip()
                    if fp not in current_files:
                        current_files.append(fp)
                    get_or_create(fp)
                    continue
                if line.startswith("--- /dev/null"):
                    continue
                if line.startswith("+++ b/"):
                    fp = line[len("+++ b/"):].strip()
                    if fp not in current_files:
                        current_files.append(fp)
                    get_or_create(fp)
                    continue
                if line.startswith("+++ /dev/null"):
                    for fp in current_files:
                        get_or_create(fp).is_deleted = True
                    continue
                if line.startswith("deleted file mode") or line.startswith("[file deleted:"):
                    for fp in current_files:
                        get_or_create(fp).is_deleted = True
                    continue

            # Hunk header: @@ -old_start,old_count +new_start,new_count @@
            if line.startswith("@@ "):
                in_hunk = True
                m = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
                if m and current_files:
                    old_start = int(m.group(1))
                    old_count = int(m.group(2)) if m.group(2) is not None else 1
                    new_start = int(m.group(3))
                    new_count = int(m.group(4)) if m.group(4) is not None else 1

                    old_end = old_start + old_count - 1 if old_count > 0 else old_start
                    new_end = new_start + new_count - 1 if new_count > 0 else new_start

                    for fp in current_files:
                        info = get_or_create(fp)
                        info.old_ranges.append((old_start, old_end))
                        info.new_ranges.append((new_start, new_end))
                continue

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


def _strip_annotations(desc: str) -> str:
    """Remove location and provenance annotations before description comparison."""
    cleaned = re.sub(r"\s*\[location not verified in the diff\]", "", desc)
    cleaned = re.sub(r"\s*\[also found by: [^\]]+\]", "", cleaned)
    return cleaned.strip()


def _is_same_finding(f1: Finding, f2: Finding) -> bool:
    """
    Two findings are the same only when they have the same file AND same kind
    AND (lines within 3 OR normalized sequence matcher ratio >= 0.6).
    """
    file1, _ = _parse_location(f1.location)
    file2, _ = _parse_location(f2.location)
    clean1 = _normalize_path(file1)
    clean2 = _normalize_path(file2)
    if not clean1 or not clean2:
        return False
    if clean1 != clean2 and not clean1.endswith("/" + clean2) and not clean2.endswith("/" + clean1):
        return False
    if f1.kind.strip().lower() != f2.kind.strip().lower():
        return False

    _, line1 = _parse_location(f1.location)
    _, line2 = _parse_location(f2.location)
    line_match = line1 is not None and line2 is not None and abs(line1 - line2) <= 3

    norm1 = _normalize_description(_strip_annotations(f1.description))
    norm2 = _normalize_description(_strip_annotations(f2.description))
    ratio = difflib.SequenceMatcher(None, norm1, norm2).ratio()
    desc_match = ratio >= 0.6

    return line_match or desc_match


def _candidate_rank(
    finding: Finding,
    lens: Lens,
    original_idx: int,
    lenses: Sequence[Lens],
) -> Tuple[int, int, int, int]:
    """
    Sorting key for deduplication candidate priority:
    1. Blocking copies first (0 < 1)
    2. Highest severity (critical 0 < high 1 < medium 2 < low 3)
    3. Earliest lens in LENSES order
    4. Original index
    """
    blocking_rank = 0 if finding.blocking else 1
    sev_rank = SEVERITY_ORDER.get(finding.severity.strip().lower(), 99)
    lens_rank = _lens_rank(lens.key, lenses)
    return (blocking_rank, sev_rank, lens_rank, original_idx)


def _output_sort_key(f: Finding) -> Tuple[int, str, int, str]:
    """Sort output findings by severity, then file, then line, then id."""
    sev = SEVERITY_ORDER.get(f.severity.strip().lower(), 99)
    file_path, line_num = _parse_location(f.location)
    return (sev, _normalize_path(file_path), line_num if line_num is not None else 0, f.id)


def _combine_system_prompt(base_prompt: str, lens_instruction: str) -> str:
    """Combine base system prompt (including focus) and lens instruction."""
    base = base_prompt.strip()
    lens = lens_instruction.strip()
    if base and lens:
        return f"{base}\n\n{lens}"
    if base:
        return base
    return lens


def _build_part_prompt(header: str, part: str, part_index: int, total_parts: int) -> str:
    """Format the review prompt for a single diff part."""
    part_indicator = (
        f"Diff part {part_index}/{total_parts} (other parts are reviewed separately; judge only this part):\n"
        if total_parts > 1
        else ""
    )
    diff_block = part if "Git Diff:\n```" in part else f"Git Diff:\n```\n{part}\n```\n"
    if header.strip():
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
    system_prompt: str = "",
    stage_timeout_s: float = 900.0,
) -> Optional[EnsembleResult]:
    """
    Run an opt-in panel of independent review lenses over diff parts.

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
    calls_made = 0
    chars_sent = 0

    def make_call(system: str, prompt: str) -> str:
        nonlocal calls_made, chars_sent
        if cancelled.is_set():
            raise RuntimeError("ensemble stage cancelled")
        with counter_lock:
            if cancelled.is_set():
                raise RuntimeError("ensemble stage cancelled")
            if calls_made >= max_calls:
                raise RuntimeError("max_calls exceeded")
            calls_made += 1
            chars_sent += len(system) + len(prompt)
        return call(system, prompt)

    def evaluate_lens(lens: Lens) -> Tuple[Lens, Optional[List[List[Finding]]]]:
        combined_system = _combine_system_prompt(system_prompt, lens.instruction)
        findings_per_part: List[List[Finding]] = []

        for i, part in enumerate(parts, start=1):
            if cancelled.is_set():
                return lens, None

            prompt_text = _build_part_prompt(header, part, i, len(parts))
            parsed_findings: Optional[List[Finding]] = None

            for attempt in range(2):
                if cancelled.is_set():
                    return lens, None
                used_prompt = prompt_text if attempt == 0 else prompt_text + format_reminder
                try:
                    response = make_call(combined_system, used_prompt)
                except Exception:
                    return lens, None

                parsed = parse(response)
                if parsed is not None:
                    parsed_findings = parsed
                    break

            if parsed_findings is None:
                return lens, None

            findings_per_part.append(parsed_findings)

        return lens, findings_per_part

    max_workers = min(3, max(1, len(lenses)))
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
    failed_keys: set[str] = set()
    lens_part_findings: Dict[str, List[List[Finding]]] = {}
    not_done: set[concurrent.futures.Future[Tuple[Lens, Optional[List[List[Finding]]]]]] = set()

    try:
        future_to_lens = {executor.submit(evaluate_lens, lens): lens for lens in lenses}
        done, not_done = concurrent.futures.wait(future_to_lens.keys(), timeout=stage_timeout_s)

        for f in not_done:
            timed_out_lens = future_to_lens[f]
            failed_keys.add(timed_out_lens.key)

        if not_done:
            cancelled.set()
            executor.shutdown(wait=False, cancel_futures=True)

        for f in done:
            completed_lens = future_to_lens[f]
            try:
                _, part_results = f.result()
                if part_results is None:
                    failed_keys.add(completed_lens.key)
                else:
                    lens_part_findings[completed_lens.key] = part_results
            except Exception:
                failed_keys.add(completed_lens.key)
    finally:
        if not not_done:
            executor.shutdown(wait=True)

    with counter_lock:
        final_calls = calls_made
        final_chars = chars_sent

    failed = [lens.key for lens in lenses if lens.key in failed_keys]
    usable = len(lens_part_findings)

    # Fail closed: must produce a parseable answer for EVERY part from ceil(len(lenses)/2) lenses
    quorum = math.ceil(len(lenses) / 2)
    if usable < quorum:
        return None

    # Merge candidates in lens order, then part order (never completion order)
    raw_candidates: List[Tuple[Finding, Lens, int]] = []
    candidate_idx = 0
    for lens in lenses:
        if lens.key in lens_part_findings:
            parts_findings = lens_part_findings[lens.key]
            for part_findings in parts_findings:
                for f in part_findings:
                    raw_candidates.append((f.model_copy(), lens, candidate_idx))
                    candidate_idx += 1

    # Location check: annotate unverified locations without changing blocking value
    diff_info = _parse_diff(parts)
    for f, _, _ in raw_candidates:
        if not _is_location_verified(f.location, diff_info):
            if " [location not verified in the diff]" not in f.description:
                f.description = f"{f.description} [location not verified in the diff]"

    # Pairwise deduplication against kept representative (non-transitive)
    sorted_candidates = sorted(
        raw_candidates,
        key=lambda item: _candidate_rank(item[0], item[1], item[2], lenses),
    )

    representatives: List[Tuple[Finding, Lens, List[Lens]]] = []
    for cand_finding, cand_lens, _ in sorted_candidates:
        matched = False
        for rep_finding, _rep_lens, cluster_lenses in representatives:
            if _is_same_finding(rep_finding, cand_finding):
                if not any(cl.key == cand_lens.key for cl in cluster_lenses):
                    cluster_lenses.append(cand_lens)
                matched = True
                break
        if not matched:
            representatives.append((cand_finding.model_copy(), cand_lens, [cand_lens]))

    deduped_findings: List[Finding] = []
    provenance: Dict[str, List[str]] = {}

    for kept_finding, winner_lens, cluster_lenses in representatives:
        sorted_cluster_lenses = sorted(
            cluster_lenses,
            key=lambda lens_item: _lens_rank(lens_item.key, lenses),
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

        deduped_findings.append(kept_finding)

    final_findings = sorted(deduped_findings, key=_output_sort_key)

    return EnsembleResult(
        findings=final_findings,
        usable=usable,
        failed=failed,
        calls=final_calls,
        chars_sent=final_chars,
        provenance=provenance,
    )
