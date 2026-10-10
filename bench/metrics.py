"""
Benchmark metrics: pure evaluation and comparison functions.
"""

from __future__ import annotations

from typing import Any, List, Optional, Set

from guard.core.findings import BLOCKING_KINDS
from guard.core.unified_diff import walk_diff

# For backwards compatibility with callers importing ItemList
ItemList = list


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").strip().lower()


def _extract_location_file(location: str) -> str:
    """Extract file path from finding location, handling Windows drive letters and line numbers."""
    loc = location.strip()
    if not loc:
        return ""
    # Windows drive letter e.g. C:\repo\x.py:3 or C:/repo/x.py:3
    if len(loc) >= 2 and loc[1] == ":" and loc[0].isalpha():
        drive = loc[:2]
        rest = loc[2:]
        if ":" in rest:
            file_part, _ = rest.rsplit(":", 1)
            return drive + file_part
        return loc
    # Standard path:line
    if ":" in loc:
        file_part, _ = loc.rsplit(":", 1)
        return file_part
    return loc


def _extract_diff_files(raw_diff: str) -> set[str]:
    """Extract touched target file paths from a unified diff."""
    return {d.path for d in walk_diff(raw_diff or "") if d.kind == "file" and d.path}


def _path_suffix_match(p1: str, p2: str) -> bool:
    """Return True if p1 equals p2, or one is a path-boundary suffix of the other."""
    norm1 = _normalize_path(p1)
    norm2 = _normalize_path(p2)
    if not norm1 or not norm2:
        return False
    if norm1 == norm2:
        return True
    if norm1.endswith("/" + norm2) or norm2.endswith("/" + norm1):
        return True
    return False


def _matches_location(finding_loc: str, defect_file: str, case_files: Optional[set[str]] = None) -> bool:
    """
    Match finding location to defect file.
    A location with no directory part matches only when exactly one file of the case's diff
    has that basename; with a directory part it must equal the defect path or be a suffix on a '/' boundary.
    """
    f_file = _normalize_path(_extract_location_file(finding_loc))
    d_file = _normalize_path(defect_file)
    if not f_file or not d_file:
        return False

    has_dir = "/" in f_file
    if not has_dir:
        # Bare basename (e.g. events.py)
        if case_files:
            matching = [
                cf for cf in case_files
                if _normalize_path(cf) == f_file or _normalize_path(cf).endswith("/" + f_file)
            ]
            if len(matching) == 1:
                norm_match = _normalize_path(matching[0])
                return norm_match == d_file or norm_match.endswith("/" + d_file) or d_file.endswith("/" + norm_match)
            return False
        d_base = d_file.rsplit("/", 1)[-1]
        return d_base == f_file
    else:
        # Directory part present: must equal or be a suffix on '/' boundary
        return _path_suffix_match(f_file, d_file)

def _get_finding_id(f: dict) -> str:
    if f.get("id"):
        return str(f["id"])
    try:
        from guard.core.findings import finding_id

        kind = str(f.get("kind", "other"))
        loc = str(f.get("location", ""))
        desc = str(f.get("description", ""))
        return finding_id(kind, loc, desc)
    except Exception:
        return str(f.get("location", "unknown"))


def match_defects(
    findings: list[dict],
    defects: list[dict],
    *,
    case_files: Optional[set[str]] = None,
) -> dict:
    """
    Match findings to known defects.

    finding dict: {"location": "path:line", "description": str, "blocking": bool, "severity": str}
    -> {"caught": [defect ids], "missed": [defect ids], "extra_blocking": [finding ids],
        "caught_blocking": [defect ids], "caught_advisory": [defect ids]}
    """
    caught_defect_ids: List[str] = []
    caught_blocking_defect_ids: List[str] = []
    caught_advisory_defect_ids: List[str] = []
    missed_defect_ids: List[str] = []
    matched_finding_indices: Set[int] = set()

    for d in defects:
        d_id = str(d.get("id", ""))
        d_file = str(d.get("file", "")).strip()
        keywords = [str(k).lower() for k in d.get("keywords", []) if str(k).strip()]

        matching_findings = []
        for idx, f in enumerate(findings):
            f_loc = str(f.get("location", ""))
            desc = str(f.get("description", "")).lower()

            if _matches_location(f_loc, d_file, case_files) and keywords and any(kw in desc for kw in keywords):
                matching_findings.append(f)
                matched_finding_indices.add(idx)

        if matching_findings:
            caught_defect_ids.append(d_id)
            if any(f.get("blocking", False) for f in matching_findings):
                caught_blocking_defect_ids.append(d_id)
            else:
                caught_advisory_defect_ids.append(d_id)
        else:
            missed_defect_ids.append(d_id)

    extra_blocking_ids: List[str] = []
    for idx, f in enumerate(findings):
        if idx not in matched_finding_indices and f.get("blocking", False):
            extra_blocking_ids.append(_get_finding_id(f))

    return {
        "caught": caught_defect_ids,
        "missed": missed_defect_ids,
        "extra_blocking": extra_blocking_ids,
        "caught_blocking": caught_blocking_defect_ids,
        "caught_advisory": caught_advisory_defect_ids,
    }


# Severities the gate can block on; BLOCKING_KINDS are the kinds it blocks for (findings.classify).
GATE_SEVERITIES = ("critical", "high")


def _gate_eligible(defect: dict) -> bool:
    """A labelled defect the gate is able to block: critical or high, correctness or security."""
    return defect.get("severity") in GATE_SEVERITIES and defect.get("kind") in BLOCKING_KINDS


def case_outcome(
    case: dict | Any,
    verdict: Any,
    findings: list[dict],
    *,
    calls: int = 0,
    chars_sent: int = 0,
    seconds: float = 0.0,
    llm_error: Optional[str] = None,
) -> dict:
    """
    Score a single case run outcome.

    verdict "APPROVED"/"REVISE"/"no-llm";
    for a defect case: caught_blocking, caught_advisory, missed;
    for a clean case: false_block (REVISE or any blocking finding), advisory_count
    """
    case_id = str(case.get("id", "") if isinstance(case, dict) else getattr(case, "id", ""))
    label = str(case.get("label", "unlabelled") if isinstance(case, dict) else getattr(case, "label", "unlabelled"))
    raw_defects = case.get("defects", []) if isinstance(case, dict) else getattr(case, "defects", [])
    defects = list(raw_defects) if raw_defects else []

    # Store verdict string value (from enum or str)
    verdict_str = verdict.value if hasattr(verdict, "value") else str(verdict)
    no_llm = verdict_str == "no-llm" or bool(llm_error)
    blocking_finding_ids = [_get_finding_id(f) for f in findings if f.get("blocking", False)]
    advisory_count = sum(1 for f in findings if not f.get("blocking", False))
    blocking_count = sum(1 for f in findings if f.get("blocking", False))

    diff_text = case.get("diff", "") if isinstance(case, dict) else getattr(case, "diff", "")
    case_files = _extract_diff_files(diff_text)
    if not case_files and defects:
        case_files = {str(d.get("file", "")) for d in defects if d.get("file")}

    outcome: dict = {
        "case_id": case_id,
        "label": label,
        "verdict": verdict_str,
        "no_llm": no_llm,
        "llm_error": llm_error,
        "calls": calls,
        "chars_sent": chars_sent,
        "seconds": round(seconds, 4),
        "blocking_count": blocking_count,
        "advisory_count": advisory_count,
        "blocking_finding_ids": blocking_finding_ids,
        "invalid": (label == "invalid" or verdict_str == "invalid"),
    }

    if label == "defect":
        matched = match_defects(findings, defects, case_files=case_files)
        # Key defects by (case_id, defect_id) tuples
        outcome.update(
            {
                "caught_blocking": [(case_id, d_id) for d_id in matched["caught_blocking"]],
                "caught_advisory": [(case_id, d_id) for d_id in matched["caught_advisory"]],
                "caught": [(case_id, d_id) for d_id in matched["caught"]],
                "missed": [(case_id, d_id) for d_id in matched["missed"]],
                "extra_blocking": matched["extra_blocking"],
                "defects_total": len(defects),
                "gate_eligible_total": sum(1 for d in defects if _gate_eligible(d)),
                "gate_eligible_caught_blocking": sum(
                    1
                    for d in defects
                    if _gate_eligible(d) and str(d.get("id", "")) in matched["caught_blocking"]
                ),
                "false_block": False,
            }
        )
    else:  # clean, unlabelled, approximate, invalid
        # Clean-case false block is REVISE or any blocking finding
        is_false_block = (verdict_str == "REVISE") or bool(blocking_finding_ids)
        outcome.update(
            {
                "caught_blocking": [],
                "caught_advisory": [],
                "caught": [],
                "missed": [],
                "extra_blocking": list(blocking_finding_ids),
                "defects_total": 0,
                "false_block": is_false_block,
            }
        )
    return outcome


def summarise(outcomes: list[dict]) -> dict:
    """
    Summarise a collection of case outcomes.

    recall_blocking, recall_any, defects_total, false_blocks, clean_total, calls, chars_sent,
    seconds, per-case rows; plus stability for repeated runs of one case (the share of repeats
    that agree on the verdict, on the set of caught defects and on the ids of the blocking findings)
    """
    by_case: dict[str, list[dict]] = {}
    for o in outcomes:
        cid = o.get("case_id", "unknown")
        by_case.setdefault(cid, []).append(o)

    defects_total = 0
    caught_blocking = 0
    caught_any = 0
    gate_eligible_total = 0
    gate_eligible_caught_blocking = 0
    clean_total = 0
    false_blocks = 0
    no_llm_count = 0
    skipped_count = 0
    invalid_count = 0
    total_calls = 0
    total_chars = 0
    total_seconds = 0.0

    per_case_rows: list[dict] = []
    case_stabilities: list[float] = []

    for cid, runs in by_case.items():
        first = runs[0]
        label = first.get("label", "unlabelled")

        if all(r.get("invalid") or r.get("verdict") == "invalid" or r.get("label") == "invalid" for r in runs):
            invalid_count += 1
            per_case_rows.append(
                {
                    "case_id": cid,
                    "label": "invalid",
                    "verdict": "invalid",
                    "repeats": len(runs),
                    "defects": 0,
                    "caught_blocking": [],
                    "caught_any": [],
                    "missed": [],
                    "false_block": False,
                    "stability": 1.0,
                    "calls": 0,
                    "chars_sent": 0,
                    "seconds": 0.0,
                    "no_llm": False,
                    "skipped": False,
                    "invalid": True,
                }
            )
            continue

        if all(r.get("skipped") or r.get("verdict") == "skipped (budget)" for r in runs):
            skipped_count += 1
            case_calls = sum(r.get("calls", 0) for r in runs)
            case_chars = sum(r.get("chars_sent", 0) for r in runs)
            case_seconds = sum(r.get("seconds", 0.0) for r in runs)
            total_calls += case_calls
            total_chars += case_chars
            total_seconds += case_seconds
            per_case_rows.append(
                {
                    "case_id": cid,
                    "label": label,
                    "verdict": "skipped (budget)",
                    "repeats": len(runs),
                    "defects": first.get("defects_total", 0),
                    "caught_blocking": [],
                    "caught_any": [],
                    "missed": [],
                    "false_block": False,
                    "stability": 1.0,
                    "calls": case_calls,
                    "chars_sent": case_chars,
                    "seconds": round(case_seconds, 2),
                    "no_llm": False,
                    "skipped": True,
                    "invalid": False,
                }
            )
            continue

        case_calls = sum(r.get("calls", 0) for r in runs)
        case_chars = sum(r.get("chars_sent", 0) for r in runs)
        case_seconds = sum(r.get("seconds", 0.0) for r in runs)
        total_calls += case_calls
        total_chars += case_chars
        total_seconds += case_seconds

        # Stability: share of repeats that agree on verdict, caught defects, and blocking finding IDs
        sig_counts: dict[tuple, int] = {}
        for r in runs:
            sig = (
                r.get("verdict"),
                frozenset(
                    tuple(x) if isinstance(x, (list, tuple)) else (cid, str(x))
                    for x in r.get("caught", [])
                ),
                frozenset(r.get("blocking_finding_ids", [])),
            )
            sig_counts[sig] = sig_counts.get(sig, 0) + 1
        case_stability = max(sig_counts.values()) / len(runs) if runs else 1.0
        case_stabilities.append(case_stability)

        for r in runs:
            if r.get("invalid") or r.get("verdict") == "invalid":
                invalid_count += 1
                continue
            if r.get("no_llm"):
                no_llm_count += 1
                continue
            if r.get("skipped") or r.get("verdict") == "skipped (budget)":
                skipped_count += 1
                continue

            if label == "defect":
                defects_total += r.get("defects_total", 0)
                caught_blocking += len(r.get("caught_blocking", []))
                caught_any += len(r.get("caught", []))
                gate_eligible_total += r.get("gate_eligible_total", 0)
                gate_eligible_caught_blocking += r.get("gate_eligible_caught_blocking", 0)
            elif label == "clean":
                clean_total += 1
                if r.get("false_block"):
                    false_blocks += 1

        all_caught_blocking = sorted(
            {
                tuple(x) if isinstance(x, (list, tuple)) else (cid, str(x))
                for r in runs for x in r.get("caught_blocking", [])
            }
        )
        all_caught_any = sorted(
            {
                tuple(x) if isinstance(x, (list, tuple)) else (cid, str(x))
                for r in runs for x in r.get("caught", [])
            }
        )
        missed_sets = [
            {
                tuple(x) if isinstance(x, (list, tuple)) else (cid, str(x))
                for x in r.get("missed", [])
            }
            for r in runs
        ]
        all_missed = sorted(set.intersection(*missed_sets)) if missed_sets else []

        any_false_block = any(r.get("false_block", False) for r in runs)
        verdicts = [r.get("verdict", "") for r in runs]
        verdict_summary = verdicts[0] if len(set(verdicts)) == 1 else ", ".join(verdicts)

        per_case_rows.append(
            {
                "case_id": cid,
                "label": label,
                "verdict": verdict_summary,
                "repeats": len(runs),
                "defects": first.get("defects_total", 0),
                "caught_blocking": all_caught_blocking,
                "caught_any": all_caught_any,
                "missed": all_missed,
                "false_block": any_false_block,
                "stability": round(case_stability, 4),
                "calls": case_calls,
                "chars_sent": case_chars,
                "seconds": round(case_seconds, 2),
                "no_llm": any(r.get("no_llm", False) for r in runs),
                "skipped": False,
                "invalid": False,
            }
        )

    recall_blocking = (caught_blocking / defects_total) if defects_total > 0 else 0.0
    recall_any = (caught_any / defects_total) if defects_total > 0 else 0.0
    recall_gate_eligible = (gate_eligible_caught_blocking / gate_eligible_total) if gate_eligible_total > 0 else 0.0
    overall_stability = sum(case_stabilities) / len(case_stabilities) if case_stabilities else 1.0

    return {
        "recall_blocking": round(recall_blocking, 4),
        "recall_any": round(recall_any, 4),
        "recall_gate_eligible": round(recall_gate_eligible, 4),
        "gate_eligible_total": gate_eligible_total,
        "gate_eligible_caught_blocking": gate_eligible_caught_blocking,
        "defects_total": defects_total,
        "caught_blocking": caught_blocking,
        "caught_any": caught_any,
        "false_blocks": false_blocks,
        "clean_total": clean_total,
        "no_llm_count": no_llm_count,
        "skipped_count": skipped_count,
        "invalid_count": invalid_count,
        "calls": total_calls,
        "chars_sent": total_chars,
        "seconds": round(total_seconds, 2),
        "stability": round(overall_stability, 4),
        "per_case_rows": per_case_rows,
        "rows": per_case_rows,
    }


def _normalize_case_defect(item: Any, default_case_id: str) -> tuple[str, str]:
    """Normalize defect representation to a (case_id, defect_id) tuple."""
    if isinstance(item, (tuple, list)) and len(item) == 2:
        return (str(item[0]), str(item[1]))
    if isinstance(item, str):
        if ":" in item:
            parts = item.split(":", 1)
            return (parts[0], parts[1])
        return (default_case_id, item)
    return (default_case_id, str(item))


def _extract_caught_defects(s: dict) -> Set[tuple[str, str]]:
    """Extract set of (case_id, defect_id) tuples from summary or raw dict."""
    res: Set[tuple[str, str]] = set()
    rows = s.get("per_case_rows", s.get("rows", []))
    if rows:
        for row in rows:
            cid = str(row.get("case_id", ""))
            for key in ("caught_blocking", "caught_any", "caught"):
                val = row.get(key)
                if isinstance(val, (set, list, tuple)):
                    for item in val:
                        res.add(_normalize_case_defect(item, cid))
                    break
        return res

    for key in ("caught_blocking", "caught_defects", "caught"):
        val = s.get(key)
        if isinstance(val, (set, list, tuple)):
            for item in val:
                res.add(_normalize_case_defect(item, "case"))
            return res
    return res


def _extract_false_block_cases(s: dict) -> Set[str]:
    val = s.get("false_block_cases")
    if isinstance(val, (set, list, tuple)):
        return {str(x) for x in val}
    rows = s.get("per_case_rows", s.get("rows", []))
    res: Set[str] = set()
    for row in rows:
        if row.get("false_block"):
            res.add(str(row.get("case_id", "")))
    return res


def _to_int(val: Any) -> int:
    if val is None:
        return 0
    if isinstance(val, (list, set, tuple)):
        return len(val)
    try:
        return int(val)
    except (ValueError, TypeError):
        return 0


def _is_valid_llm_case_row(row: dict) -> bool:
    """True if row is labelled (defect/clean) and ran with an LLM (not no-llm, skipped, or invalid)."""
    label = str(row.get("label", "")).lower()
    if label not in ("defect", "clean"):
        return False
    if row.get("no_llm") or row.get("verdict") == "no-llm" or bool(row.get("llm_error")):
        return False
    if row.get("skipped") or row.get("verdict") == "skipped (budget)":
        return False
    if row.get("invalid") or row.get("verdict") == "invalid":
        return False
    return True


def _repeat_count(s: dict) -> Optional[int]:
    """Repeats a result was measured with: the summary's own count, else the largest per-case count, else unknown."""
    top = _to_int(s.get("repeats"))
    if top > 0:
        return top
    rows = s.get("per_case_rows", s.get("rows", []))
    per_row = [_to_int(r.get("repeats")) for r in rows if isinstance(r, dict)]
    per_row = [n for n in per_row if n > 0]
    return max(per_row) if per_row else None


def compare(baseline: dict, variant: dict, *, opt_in_by_design: bool = False) -> dict:
    """
    Judge variant against baseline using the decision rule in plan.md.

    gained, lost, new_false_blocks, call_ratio, adopt: bool.
    Only considers cases that are labelled AND ran with an LLM in BOTH runs.
    Keyed by (case_id, defect_id).
    With opt_in_by_design (the panel), adopt is ALWAYS False and recommendation is reported.
    The checks compare totals and unions over repeats, so results measured with different repeat counts
    are not comparable: the verdict is then "inconclusive" and adopt is False.
    """
    b_repeats = _repeat_count(baseline)
    v_repeats = _repeat_count(variant)
    # Doubt is inconclusive: differing counts, or a count known for only one side (older result files).
    inconclusive = (b_repeats is None) != (v_repeats is None) or b_repeats != v_repeats
    baseline_calls = _to_int(baseline.get("calls", 0))
    variant_calls = _to_int(variant.get("calls", 0))
    call_ratio = variant_calls / max(baseline_calls, 1)

    b_rows_list = baseline.get("per_case_rows", baseline.get("rows", []))
    v_rows_list = variant.get("per_case_rows", variant.get("rows", []))
    b_rows = {str(r.get("case_id", "")): r for r in b_rows_list}
    v_rows = {str(r.get("case_id", "")): r for r in v_rows_list}

    if b_rows and v_rows:
        # Consider ONLY cases that are labelled AND ran with an LLM in BOTH runs
        valid_cids = {
            cid for cid in b_rows
            if cid in v_rows
            and _is_valid_llm_case_row(b_rows[cid])
            and _is_valid_llm_case_row(v_rows[cid])
        }

        b_caught: Set[tuple[str, str]] = set()
        v_caught: Set[tuple[str, str]] = set()
        b_fb_cases: Set[str] = set()
        v_fb_cases: Set[str] = set()

        for cid in valid_cids:
            b_r = b_rows[cid]
            v_r = v_rows[cid]
            lbl = b_r.get("label")
            if lbl == "defect":
                for item in b_r.get("caught_blocking", b_r.get("caught", [])):
                    b_caught.add(_normalize_case_defect(item, cid))
                for item in v_r.get("caught_blocking", v_r.get("caught", [])):
                    v_caught.add(_normalize_case_defect(item, cid))
            elif lbl == "clean":
                if b_r.get("false_block"):
                    b_fb_cases.add(cid)
                if v_r.get("false_block"):
                    v_fb_cases.add(cid)

        gained = sorted(v_caught - b_caught)
        lost = sorted(b_caught - v_caught)
        new_fb = sorted(v_fb_cases - b_fb_cases)
        fb_removed = len(b_fb_cases - v_fb_cases)
    else:
        # Fallback for simple crafted dicts without per-case rows (e.g. unit tests):
        b_caught_set = _extract_caught_defects(baseline)
        v_caught_set = _extract_caught_defects(variant)
        gained = sorted(v_caught_set - b_caught_set)
        lost = sorted(b_caught_set - v_caught_set)

        b_fb_set = _extract_false_block_cases(baseline)
        v_fb_set = _extract_false_block_cases(variant)
        b_fb_count = _to_int(baseline.get("false_blocks", len(b_fb_set)))
        v_fb_count = _to_int(variant.get("false_blocks", len(v_fb_set)))

        if b_fb_set or v_fb_set:
            new_fb = sorted(v_fb_set - b_fb_set)
            fb_removed = len(b_fb_set - v_fb_set)
        else:
            new_fb_count = max(0, v_fb_count - b_fb_count)
            fb_removed = max(0, b_fb_count - v_fb_count)
            new_fb = [f"fb_{i+1}" for i in range(new_fb_count)]

    # Decision rule:
    # (a) catches at least one more known defect or removes at least one false block
    clause_a = bool(len(gained) > 0 or fb_removed > 0)
    # (b) loses no defect baseline caught
    clause_b = bool(len(lost) == 0)
    # (c) raises no new false block
    clause_c = bool(len(new_fb) == 0)
    # (d) costs at most 2x baseline calls (skipped if opt_in_by_design)
    clause_d = bool(call_ratio <= 2.0)

    b_recall = float(baseline.get("recall_blocking", baseline.get("recall_any", 0.0)))
    v_recall = float(variant.get("recall_blocking", variant.get("recall_any", 0.0)))
    b_gate = baseline.get("recall_gate_eligible")
    v_gate = variant.get("recall_gate_eligible")
    extra_calls = variant_calls - baseline_calls

    if extra_calls > 0:
        recall_gained_per_extra_call = round(max(0.0, v_recall - b_recall) / extra_calls, 6)
    else:
        recall_gained_per_extra_call = 0.0

    if inconclusive:
        adopt = False
        recommendation = f"inconclusive: repeats differ or unknown (baseline {b_repeats}, variant {v_repeats}); rerun with the same --repeats"
    elif opt_in_by_design:
        # The panel is opt-in by design: adopt must ALWAYS be False
        adopt = False
        if clause_a and clause_b and clause_c:
            recommendation = (
                f"keep as opt-in (panel gained {len(gained)} defect(s) "
                f"at {recall_gained_per_extra_call:.4f} recall/call, 0 lost, 0 new false blocks)"
            )
        elif not clause_a:
            recommendation = "remove (panel showed no gain over baseline)"
        else:
            recommendation = (
                f"do not adopt (panel regression: {len(lost)} lost defect(s), "
                f"{len(new_fb)} new false block(s))"
            )
    else:
        adopt = bool(clause_a and clause_b and clause_c and clause_d)
        recommendation = "adopt (default-on)" if adopt else "do not adopt"

    result: dict = {
        "gained": list(gained),
        "lost": list(lost),
        "new_false_blocks": list(new_fb),
        "call_ratio": round(call_ratio, 3),
        "adopt": adopt,
        "recommendation": recommendation,
        "clause_a": clause_a,
        "clause_b": clause_b,
        "clause_c": clause_c,
        "clause_d": clause_d,
        "inconclusive": inconclusive,
    }
    if opt_in_by_design or extra_calls > 0:
        result["recall_gained_per_extra_call"] = recall_gained_per_extra_call
    result["recall_gate_eligible"] = {
        "baseline": None if b_gate is None else float(b_gate),
        "variant": None if v_gate is None else float(v_gate),
    }

    return result


def _fmt_gate_recall(value: Any) -> str:
    return "n/a" if value is None else f"{float(value):.1%}"


def to_markdown(summary: dict, compare: Optional[dict] = None) -> str:
    """Format benchmark summary and comparison into a Markdown report."""
    lines: List[str] = [
        "# Benchmark Results",
        "",
        "## Summary",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Recall (blocking) | {summary.get('recall_blocking', 0.0):.1%} |",
        f"| Recall (gate-eligible) | {_fmt_gate_recall(summary.get('recall_gate_eligible'))} "
        f"({summary.get('gate_eligible_caught_blocking', 0)} / {summary.get('gate_eligible_total', 0)}) |",
        f"| Recall (any) | {summary.get('recall_any', 0.0):.1%} |",
        f"| Defects Total | {summary.get('defects_total', 0)} |",
        f"| Caught (blocking) | {summary.get('caught_blocking', 0)} |",
        f"| Caught (any) | {summary.get('caught_any', 0)} |",
        f"| False Blocks | {summary.get('false_blocks', 0)} / {summary.get('clean_total', 0)} clean |",
        f"| No-LLM Cases | {summary.get('no_llm_count', 0)} |",
        f"| Stability | {summary.get('stability', 1.0):.1%} |",
        f"| Total Calls | {summary.get('calls', 0)} |",
        f"| Characters Sent | {summary.get('chars_sent', 0):,} |",
        f"| Total Time | {summary.get('seconds', 0.0):.1f}s |",
    ]

    if summary.get("skipped_count", 0) > 0:
        lines.append(f"| Skipped (Budget) | {summary.get('skipped_count', 0)} |")
    if summary.get("invalid_count", 0) > 0:
        lines.append(f"| Invalid Case Files | {summary.get('invalid_count', 0)} |")

    if compare:
        lines.extend([
            "",
            "## Comparison vs Baseline",
            "| Check | Result | Detail |",
            "| --- | --- | --- |",
            f"| (a) Gained / Removed False Block | {'PASS' if compare.get('clause_a', bool(compare.get('gained') or compare.get('adopt'))) else 'FAIL'} | Gained: {len(compare.get('gained', []))} |",
            f"| (b) No Lost Defects | {'PASS' if compare.get('clause_b', not compare.get('lost')) else 'FAIL'} | Lost: {len(compare.get('lost', []))} |",
            f"| (c) No New False Blocks | {'PASS' if compare.get('clause_c', not compare.get('new_false_blocks')) else 'FAIL'} | New FB: {len(compare.get('new_false_blocks', []))} |",
            f"| (d) Cost Ratio <= 2.0x | {'PASS' if compare.get('clause_d', compare.get('call_ratio', 0) <= 2.0) else 'FAIL'} | {compare.get('call_ratio', 0):.2f}x |",
            f"| **Adopt (Default-On)** | **{'YES' if compare.get('adopt') else 'NO'}** | |",
        ])
        if "recommendation" in compare:
            lines.append(f"| Recommendation | **{compare['recommendation']}** | |")
        if "recall_gate_eligible" in compare:
            gate = compare["recall_gate_eligible"]
            lines.append(
                f"| Recall (gate-eligible) baseline -> variant | "
                f"{_fmt_gate_recall(gate.get('baseline'))} -> {_fmt_gate_recall(gate.get('variant'))} | |"
            )
        if "recall_gained_per_extra_call" in compare:
            lines.append(f"| Recall Gain / Extra Call | {compare['recall_gained_per_extra_call']:.6f} | |")

    rows = summary.get("per_case_rows", summary.get("rows", []))
    if rows:
        lines.extend([
            "",
            "## Per-Case Breakdown",
            "| Case | Label | Verdict | Defects | Caught | Missed | FB | Calls | Stability |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ])
        for r in rows:
            cid = r.get("case_id", "")
            lbl = r.get("label", "")
            vrd = r.get("verdict", "")
            tot = r.get("defects", 0)
            cgt = len(r.get("caught_blocking", []))
            msd = len(r.get("missed", []))
            fb = "YES" if r.get("false_block") else "no"
            cls = r.get("calls", 0)
            stb = f"{r.get('stability', 1.0):.0%}"
            lines.append(f"| {cid} | {lbl} | {vrd} | {tot} | {cgt} | {msd} | {fb} | {cls} | {stb} |")

    lines.append("")
    return "\n".join(lines)
