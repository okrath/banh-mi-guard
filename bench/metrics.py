"""
Benchmark metrics: pure evaluation and comparison functions.
"""

from __future__ import annotations

from typing import Any, List, Optional, Set


class ItemList(list):
    """A list that also compares equal to its length when compared to an int."""

    def __eq__(self, other: object) -> bool:
        if isinstance(other, int):
            return len(self) == other
        return super().__eq__(other)


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").strip().lower()


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


def match_defects(findings: list[dict], defects: list[dict]) -> dict:
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
            f_file = f_loc.split(":", 1)[0].strip() if ":" in f_loc else f_loc.strip()
            desc = str(f.get("description", "")).lower()

            if _path_suffix_match(f_file, d_file) and keywords and any(kw in desc for kw in keywords):
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


def case_outcome(
    case: dict | Any,
    verdict: str,
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

    no_llm = verdict == "no-llm" or bool(llm_error)
    blocking_finding_ids = [_get_finding_id(f) for f in findings if f.get("blocking", False)]
    advisory_count = sum(1 for f in findings if not f.get("blocking", False))
    blocking_count = sum(1 for f in findings if f.get("blocking", False))

    outcome: dict = {
        "case_id": case_id,
        "label": label,
        "verdict": verdict,
        "no_llm": no_llm,
        "llm_error": llm_error,
        "calls": calls,
        "chars_sent": chars_sent,
        "seconds": round(seconds, 4),
        "blocking_count": blocking_count,
        "advisory_count": advisory_count,
        "blocking_finding_ids": blocking_finding_ids,
    }

    if label == "defect":
        matched = match_defects(findings, defects)
        outcome.update(
            {
                "caught_blocking": matched["caught_blocking"],
                "caught_advisory": matched["caught_advisory"],
                "caught": matched["caught"],
                "missed": matched["missed"],
                "extra_blocking": matched["extra_blocking"],
                "defects_total": len(defects),
                "false_block": False,
            }
        )
    else:  # clean, unlabelled, approximate
        is_false_block = verdict == "REVISE" or bool(blocking_finding_ids)
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
    clean_total = 0
    false_blocks = 0
    no_llm_count = 0
    skipped_count = 0
    total_calls = 0
    total_chars = 0
    total_seconds = 0.0

    per_case_rows: list[dict] = []
    case_stabilities: list[float] = []

    for cid, runs in by_case.items():
        if all(r.get("skipped") or r.get("verdict") == "skipped (budget)" for r in runs):
            skipped_count += 1
            first = runs[0]
            per_case_rows.append(
                {
                    "case_id": cid,
                    "label": first.get("label", "unlabelled"),
                    "verdict": "skipped (budget)",
                    "repeats": len(runs),
                    "defects": first.get("defects_total", 0),
                    "caught_blocking": [],
                    "caught_any": [],
                    "missed": [],
                    "false_block": False,
                    "stability": 1.0,
                    "calls": 0,
                    "chars_sent": 0,
                    "seconds": 0.0,
                    "no_llm": False,
                    "skipped": True,
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
                frozenset(r.get("caught", [])),
                frozenset(r.get("blocking_finding_ids", [])),
            )
            sig_counts[sig] = sig_counts.get(sig, 0) + 1
        case_stability = max(sig_counts.values()) / len(runs) if runs else 1.0
        case_stabilities.append(case_stability)

        first = runs[0]
        label = first.get("label", "unlabelled")

        for r in runs:
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
            elif label == "clean":
                clean_total += 1
                if r.get("false_block"):
                    false_blocks += 1

        all_caught_blocking = sorted(set().union(*(r.get("caught_blocking", []) for r in runs)))
        all_caught_any = sorted(set().union(*(r.get("caught", []) for r in runs)))
        missed_sets = [set(r.get("missed", [])) for r in runs]
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
            }
        )

    recall_blocking = (caught_blocking / defects_total) if defects_total > 0 else 0.0
    recall_any = (caught_any / defects_total) if defects_total > 0 else 0.0
    overall_stability = sum(case_stabilities) / len(case_stabilities) if case_stabilities else 1.0

    return {
        "recall_blocking": round(recall_blocking, 4),
        "recall_any": round(recall_any, 4),
        "defects_total": defects_total,
        "caught_blocking": caught_blocking,
        "caught_any": caught_any,
        "false_blocks": false_blocks,
        "clean_total": clean_total,
        "no_llm_count": no_llm_count,
        "skipped_count": skipped_count,
        "calls": total_calls,
        "chars_sent": total_chars,
        "seconds": round(total_seconds, 2),
        "stability": round(overall_stability, 4),
        "per_case_rows": per_case_rows,
        "rows": per_case_rows,
    }


def _extract_caught_defects(s: dict) -> Set[str]:
    for key in ("caught_blocking", "caught_defects", "caught"):
        val = s.get(key)
        if isinstance(val, (set, list, tuple)):
            return {str(x) for x in val}
    rows = s.get("per_case_rows", s.get("rows", []))
    res: Set[str] = set()
    for row in rows:
        for key in ("caught_blocking", "caught_any", "caught"):
            val = row.get(key)
            if isinstance(val, (set, list, tuple)):
                res.update(str(x) for x in val)
                break
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


def compare(baseline: dict, variant: dict, *, opt_in_by_design: bool = False) -> dict:
    """
    Judge variant against baseline using the decision rule in plan.md.

    gained, lost, new_false_blocks, call_ratio, adopt: bool.
    call_ratio divides by max(baseline calls, 1), never by zero.
    With opt_in_by_design (the panel) clause (d) is not applied;
    the result reports recall gained per extra call instead.
    """
    baseline_calls = _to_int(baseline.get("calls", 0))
    variant_calls = _to_int(variant.get("calls", 0))
    call_ratio = variant_calls / max(baseline_calls, 1)

    b_caught_set = _extract_caught_defects(baseline)
    v_caught_set = _extract_caught_defects(variant)

    if b_caught_set or v_caught_set:
        gained = sorted(v_caught_set - b_caught_set)
        lost = sorted(b_caught_set - v_caught_set)
    else:
        b_count = _to_int(baseline.get("caught_blocking", baseline.get("caught", 0)))
        v_count = _to_int(variant.get("caught_blocking", variant.get("caught", 0)))
        gained_count = max(0, v_count - b_count)
        lost_count = max(0, b_count - v_count)
        gained = [f"defect_{i+1}" for i in range(gained_count)]
        lost = [f"defect_{i+1}" for i in range(lost_count)]

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

    if opt_in_by_design:
        adopt = bool(clause_a and clause_b and clause_c)
    else:
        adopt = bool(clause_a and clause_b and clause_c and clause_d)

    b_recall = float(baseline.get("recall_blocking", baseline.get("recall_any", 0.0)))
    v_recall = float(variant.get("recall_blocking", variant.get("recall_any", 0.0)))
    extra_calls = variant_calls - baseline_calls

    if extra_calls > 0:
        recall_gained_per_extra_call = round(max(0.0, v_recall - b_recall) / extra_calls, 6)
    else:
        recall_gained_per_extra_call = 0.0

    result: dict = {
        "gained": ItemList(gained),
        "lost": ItemList(lost),
        "new_false_blocks": ItemList(new_fb),
        "call_ratio": round(call_ratio, 3),
        "adopt": adopt,
        "clause_a": clause_a,
        "clause_b": clause_b,
        "clause_c": clause_c,
        "clause_d": clause_d,
    }
    if opt_in_by_design or extra_calls > 0:
        result["recall_gained_per_extra_call"] = recall_gained_per_extra_call

    return result

def to_markdown(summary: dict, compare: Optional[dict] = None) -> str:
    """Format benchmark summary and comparison into a Markdown report."""
    lines: List[str] = [
        "# Benchmark Results",
        "",
        "## Summary",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Recall (blocking) | {summary.get('recall_blocking', 0.0):.1%} |",
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
