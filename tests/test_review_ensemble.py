"""
Tests for the review ensemble and review lenses.
"""

from __future__ import annotations

import queue
import subprocess
import sys
import threading
import time
from typing import List, Optional

from guard.core.findings import Finding, parse_findings
from guard.core.review_ensemble import (
    EnsembleResult,
    _can_merge,
    _candidate_rank,
    _collect_candidates,
    _collect_lens_results,
    _combine_system_prompt,
    _dedupe_candidates,
    _finalize_representatives,
    _is_location_verified,
    _parse_diff,
    _review_lens_parts,
    run_ensemble,
)
from guard.core.review_lenses import (
    ADVERSARY_INSTRUCTION,
    CONTRACTS_INSTRUCTION,
    LENSES,
    REQUIREMENTS_INSTRUCTION,
    TESTS_INSTRUCTION,
    build_lens,
    build_lenses,
)

SAMPLE_DIFF = """diff --git a/src/auth.py b/src/auth.py
--- a/src/auth.py
+++ b/src/auth.py
@@ -10,10 +10,12 @@ def login(user, password):
+    check_rate_limit(user)
"""

MULTI_HUNK_DIFF = """diff --git a/src/auth.py b/src/auth.py
--- a/src/auth.py
+++ b/src/auth.py
@@ -20,10 +20,3 @@ def old_auth():
-    check_token()
-    check_role()
-    check_permission()
+    check_all()
diff --git a/src/legacy.py b/src/legacy.py
deleted file mode 100644
--- a/src/legacy.py
+++ /dev/null
@@ -1,20 +0,0 @@
-def dead(): pass
"""

FORMAT_REMINDER = (
    "\nYour previous answer could not be parsed. Answer again with SCORE and FINDINGS lines."
)


def _make_parse(task_text: str = ""):
    def _parse(text: str) -> Optional[List[Finding]]:
        return parse_findings(text, task_text)

    return _parse


def test_lens_definitions_and_helpers():
    """Verify lens definitions, keys, order, and builder helpers."""
    assert len(LENSES) == 5
    expected_keys = ("correctness", "requirements", "contracts", "tests", "adversary")
    assert tuple(lens.key for lens in LENSES) == expected_keys
    assert tuple(lens.name for lens in LENSES) == expected_keys

    # Correctness has empty instruction
    assert LENSES[0].instruction == ""
    assert LENSES[1].instruction == REQUIREMENTS_INSTRUCTION
    assert LENSES[2].instruction == CONTRACTS_INSTRUCTION
    assert LENSES[3].instruction == TESTS_INSTRUCTION
    assert LENSES[4].instruction == ADVERSARY_INSTRUCTION

    # build_lens appends extra and output contract
    lens = build_lens(
        LENSES[3],
        output_contract="MANDATORY FORMAT: FINDINGS line format",
        extra="CHECKLIST: check for mutated globals",
    )
    assert TESTS_INSTRUCTION in lens.instruction
    assert "CHECKLIST: check for mutated globals" in lens.instruction
    assert "MANDATORY FORMAT: FINDINGS line format" in lens.instruction

    # build_lenses builds full panel with contract and extras
    all_lenses = build_lenses(
        output_contract="OUTPUT CONTRACT",
        extra={"tests": "EXTRA TEST", "adversary": "EXTRA THREAT"},
    )
    assert len(all_lenses) == 5
    assert "OUTPUT CONTRACT" in all_lenses[0].instruction
    assert "EXTRA TEST" in all_lenses[3].instruction
    assert "EXTRA THREAT" in all_lenses[4].instruction


def test_location_verification_rule():
    """Test the diff hunk location verification rule: inside hunks or deleted file."""
    diff_info = _parse_diff([MULTI_HUNK_DIFF])
    # Inside removed hunk range (lines 20-29) -> verified
    assert _is_location_verified("src/auth.py:25", diff_info) is True
    # Inside deleted file (any line) -> verified
    assert _is_location_verified("src/legacy.py:100", diff_info) is True
    # Outside hunk ranges (line 999) -> unverified
    assert _is_location_verified("src/auth.py:999", diff_info) is False
    # File not in diff -> unverified
    assert _is_location_verified("src/other.py:10", diff_info) is False


def test_rule_carrying_helpers():
    """
    Test only the private helpers that carry specific review rules:
    - Rule 1 (_can_merge): candidates from the same lens and part never merge;
      across lenses, blocking findings merge only when description similarity >= 0.6.
    - Rule 2 (_candidate_rank): among blocking copies, earliest lens in LENSES order
      wins regardless of severity; severity ranking applies when neither is blocking.
    - Rule 3 (_is_location_verified): verified inside hunk ranges or on deleted files.
    - Rule 4 (_combine_system_prompt): correctness lens preserves base prompt unstripped;
      lenses with instructions append after a blank line.
    """
    f1 = Finding(id="1", severity="high", kind="correctness", location="a.py:1", description="leak")
    f2 = Finding(id="2", severity="high", kind="correctness", location="a.py:1", description="leak")
    f_crit = Finding(id="3", severity="critical", kind="correctness", location="a.py:1", description="leak", blocking=True)
    f_high = Finding(id="4", severity="high", kind="correctness", location="a.py:1", description="leak", blocking=True)

    # Rule 1: same lens same part cannot merge; different lens can merge
    assert _can_merge((f1, LENSES[0], [(LENSES[0], 0)], 0), (f2, LENSES[0], 0, 1)) is False
    assert _can_merge((f1, LENSES[0], [(LENSES[0], 0)], 0), (f2, LENSES[1], 0, 1)) is True

    # Rule 2: earliest lens wins among blocking copies regardless of severity
    assert _candidate_rank(f_high, LENSES[0], 0) < _candidate_rank(f_crit, LENSES[1], 1)

    # Rule 3: location verification
    diff_info = _parse_diff([MULTI_HUNK_DIFF])
    assert _is_location_verified("src/auth.py:25", diff_info) is True
    assert _is_location_verified("src/legacy.py:100", diff_info) is True

    # Rule 4: system prompt combination
    assert _combine_system_prompt("  base  \n", "") == "  base  \n"
    assert _combine_system_prompt("base", "lens") == "base\n\nlens"

def test_ensemble_union_different_defects():
    """Union of two lenses that each find a different defect."""
    lens1 = LENSES[0]  # correctness
    lens2 = LENSES[1]  # requirements

    response_1 = (
        "SCORE: 7.0\nSUMMARY: correctness check\nFINDINGS:\n"
        "- high | correctness | src/auth.py:12 | - | Null pointer in login\n"
    )
    response_2 = (
        "SCORE: 7.0\nSUMMARY: requirements check\nFINDINGS:\n"
        "- medium | requirement | src/auth.py:15 | - | Missing rate limit audit log\n"
    )

    def scripted_call(system: str, prompt: str) -> str:
        if "Requirements" in system:
            return response_2
        return response_1

    result = run_ensemble(
        lenses=[lens1, lens2],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert isinstance(result, EnsembleResult)
    assert result.usable == 2
    assert result.failed == []
    assert len(result.findings) == 2

    # Verify both findings are present in the union
    descriptions = [f.description for f in result.findings]
    assert any("Null pointer in login" in d for d in descriptions)
    assert any("Missing rate limit audit log" in d for d in descriptions)

    # Provenance tracks finding id -> lens keys
    for f in result.findings:
        if "Null pointer" in f.description:
            assert result.provenance[f.id] == ["correctness"]
        if "Missing rate limit" in f.description:
            assert result.provenance[f.id] == ["requirements"]


def test_ensemble_same_lens_same_part_never_merged():
    """
    NEVER merge two candidates that came from the SAME lens (and the same part):
    one reviewer reported them separately on purpose.
    Two high|security findings in the same file 2 lines apart with different descriptions
    must both survive and appear in the output.
    """
    lens = LENSES[0]  # single correctness lens

    # Same lens reports two security findings 2 lines apart (lines 12 and 14)
    response = (
        "SCORE: 3.0\nSUMMARY: vulnerabilities\nFINDINGS:\n"
        "- high | security | src/auth.py:12 | - | SQL injection in user query\n"
        "- high | security | src/auth.py:14 | - | Insecure password hashing\n"
    )

    result = run_ensemble(
        lenses=[lens],
        call=lambda sys, p: response,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert len(result.findings) == 2
    descs = [f.description for f in result.findings]
    assert any("SQL injection in user query" in d for d in descs)
    assert any("Insecure password hashing" in d for d in descs)


def test_ensemble_multipart_same_lens_same_part_never_merged_into_cluster():
    """
    On a multi-part diff, findings from the same lens on the same part never merge
    into the same cluster, even when merging into a representative from another lens.
    """
    lens0 = LENSES[0]
    lens1 = LENSES[1]

    part1 = "diff --git a/src/auth.py b/src/auth.py\n@@ -10,5 +10,5 @@\n+part1\n"
    part2 = "diff --git a/src/auth.py b/src/auth.py\n@@ -10,5 +10,5 @@\n+part2\n"

    # Lens 0 on part 1 reports finding A (lines within 3 of B and C)
    resp_l0_p1 = "SCORE: 5.0\nSUMMARY: p1\nFINDINGS:\n- medium | correctness | src/auth.py:10 | - | Leak issue A\n"
    resp_l0_p2 = "SCORE: 9.0\nSUMMARY: p2\nFINDINGS:\nNone\n"

    # Lens 1 on part 2 reports finding B and finding C (both on part 2)
    resp_l1_p1 = "SCORE: 9.0\nSUMMARY: p1\nFINDINGS:\nNone\n"
    resp_l1_p2 = (
        "SCORE: 5.0\nSUMMARY: p2\nFINDINGS:\n"
        "- medium | correctness | src/auth.py:11 | - | Leak issue B\n"
        "- medium | correctness | src/auth.py:12 | - | Leak issue C\n"
    )

    def scripted_call(system: str, prompt: str) -> str:
        if "Requirements" in system:
            if "Diff part 2/2" in prompt:
                return resp_l1_p2
            return resp_l1_p1
        if "Diff part 2/2" in prompt:
            return resp_l0_p2
        return resp_l0_p1

    result = run_ensemble(
        lenses=[lens0, lens1],
        call=scripted_call,
        header="Header",
        parts=[part1, part2],
        parse=_make_parse(),
        max_calls=12,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    # Finding B merges into A, but Finding C CANNOT merge into A because Lens 1 on Part 2 is already in A!
    # Therefore, exactly 2 findings survive (A+B merged, and C survives separately)
    assert len(result.findings) == 2


def test_ensemble_across_lenses_two_blocking_merge_only_on_description_similarity():
    """
    Across lenses, two BLOCKING findings merge only when normalised-description ratio is >= 0.6.
    Proximity alone (within 3 lines) may NOT merge two blocking findings.
    Lens 0 reports SQL injection at line 12, lens 1 reports hard-coded password at line 13:
    both are blocking and security -> both survive.
    """
    lens0 = LENSES[0]
    lens1 = LENSES[1]

    resp0 = (
        "SCORE: 4.0\nSUMMARY: audit 0\nFINDINGS:\n"
        "- high | security | src/auth.py:12 | - | SQL injection vulnerability in login\n"
    )
    resp1 = (
        "SCORE: 4.0\nSUMMARY: audit 1\nFINDINGS:\n"
        "- high | security | src/auth.py:13 | - | Hard-coded database password in login\n"
    )

    def scripted_call(system: str, prompt: str) -> str:
        if "Requirements" in system:
            return resp1
        return resp0

    result = run_ensemble(
        lenses=[lens0, lens1],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    # Both blocking findings must survive because proximity alone does not merge blocking findings
    assert len(result.findings) == 2
    descs = [f.description for f in result.findings]
    assert any("SQL injection" in d for d in descs)
    assert any("Hard-coded database password" in d for d in descs)


def test_ensemble_earliest_lens_wins_among_two_blocking_copies_regardless_of_severity():
    """
    Among two BLOCKING copies, earliest lens in LENSES order wins whatever the severity
    (treat blocking copies as equal candidates; severity ranking applies only when neither is blocking).
    Lens 0 says high, lens 1 says critical for the same finding: lens 0's id and text are kept.
    """
    lens0 = LENSES[0]  # correctness (earlier in LENSES)
    lens1 = LENSES[1]  # requirements (later in LENSES)

    resp0 = (
        "SCORE: 5.0\nSUMMARY: 0\nFINDINGS:\n"
        "- high | correctness | src/auth.py:12 | - | Resource leak in database connection\n"
    )
    resp1 = (
        "SCORE: 5.0\nSUMMARY: 1\nFINDINGS:\n"
        "- critical | correctness | src/auth.py:12 | - | Resource leak in database connection pool\n"
    )

    orig0 = parse_findings(resp0, "")
    assert orig0 is not None and len(orig0) == 1
    expected_id = orig0[0].id
    expected_desc = orig0[0].description

    def scripted_call(system: str, prompt: str) -> str:
        if "Requirements" in system:
            return resp1
        return resp0

    result = run_ensemble(
        lenses=[lens0, lens1],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert len(result.findings) == 1
    kept = result.findings[0]
    # Lens 0's ID and base wording are kept even though Lens 1 reported critical vs high
    assert kept.id == expected_id
    assert expected_desc in kept.description
    assert "[also found by: requirements]" in kept.description


def test_ensemble_merged_blocking_keeps_original_id_kind_text():
    """A merged blocking finding keeps its original id, kind, severity, and text."""
    lens1 = LENSES[0]  # correctness (earlier in LENSES)
    lens2 = LENSES[1]  # requirements

    # Lens 1 has a blocking critical finding
    resp_1 = (
        "SCORE: 5.0\nSUMMARY: leak\nFINDINGS:\n"
        "- critical | correctness | src/auth.py:12 | - | Connection leak on failed authentication\n"
    )
    # Lens 2 has non-blocking low finding for same issue (ratio >= 0.6)
    resp_2 = (
        "SCORE: 5.0\nSUMMARY: leak\nFINDINGS:\n"
        "- low | correctness | src/auth.py:12 | - | Connection leak on failed authentication flow\n"
    )

    orig_parsed = parse_findings(resp_1, "")
    assert orig_parsed is not None and len(orig_parsed) == 1
    orig_id = orig_parsed[0].id
    orig_desc = orig_parsed[0].description

    def scripted_call(system: str, prompt: str) -> str:
        if "Requirements" in system:
            return resp_2
        return resp_1

    result = run_ensemble(
        lenses=[lens1, lens2],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert len(result.findings) == 1
    f = result.findings[0]

    # Kept finding retains original id, kind, severity, blocking status
    assert f.id == orig_id
    assert f.kind == "correctness"
    assert f.severity == "critical"
    assert f.blocking is True
    # Base text is unchanged, provenance suffix appended
    assert f.description == f"{orig_desc} [also found by: requirements]"


def test_ensemble_earlier_lens_shorter_description_wins():
    """
    Verify that the earlier lens in LENSES order wins, NOT the longest description.
    Earlier lens has a shorter description, later lens has a much longer description:
    the earlier lens's shorter copy is kept.
    """
    lens0 = LENSES[0]  # earlier lens
    lens1 = LENSES[1]  # later lens

    short_desc = "Brief leak"
    long_desc = "Much longer and extremely detailed description of the memory leak in auth session logic"

    resp0 = f"SCORE: 5.0\nSUMMARY: 0\nFINDINGS:\n- high | correctness | src/auth.py:12 | - | {short_desc}\n"
    resp1 = f"SCORE: 5.0\nSUMMARY: 1\nFINDINGS:\n- medium | correctness | src/auth.py:12 | - | {long_desc}\n"

    def scripted_call(system: str, prompt: str) -> str:
        if "Requirements" in system:
            return resp1
        return resp0

    result = run_ensemble(
        lenses=[lens0, lens1],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert len(result.findings) == 1
    # Shorter description from earlier lens was kept, NOT the longer one
    assert short_desc in result.findings[0].description
    assert long_desc not in result.findings[0].description


def test_ensemble_correctness_prompt_reproduction():
    """
    The prompt for the correctness lens must reproduce the single reviewer's prompt exactly:
    base system prompt is unstripped, and part prompt always has the Git Diff fence.
    """
    lens = LENSES[0]  # correctness
    captured_sys: List[str] = []
    captured_prompt: List[str] = []

    base_sys = "  You are the Lead Architect.  \n"  # contains leading/trailing whitespace
    part = "diff --git a/a.py b/a.py\nGit Diff:\n```\n+code\n```\n"

    def scripted_call(system: str, prompt: str) -> str:
        captured_sys.append(system)
        captured_prompt.append(prompt)
        return "SCORE: 9.0\nSUMMARY: ok\nFINDINGS:\nNone\n"

    run_ensemble(
        lenses=[lens],
        call=scripted_call,
        header="Header",
        parts=[part],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt=base_sys,
    )

    assert len(captured_sys) == 1
    # System prompt is NOT stripped for correctness lens
    assert captured_sys[0] == base_sys
    # Prompt wraps with standard Git Diff fence without special-case skipping
    assert "Git Diff:\n```\n" in captured_prompt[0]


def test_ensemble_same_defect_merged_with_provenance():
    """The same defect found by two lenses is merged once with provenance."""
    lens1 = LENSES[0]  # correctness
    lens2 = LENSES[1]  # requirements

    response_1 = (
        "SCORE: 6.0\nSUMMARY: check 1\nFINDINGS:\n"
        "- high | correctness | src/auth.py:12 | - | Potential memory leak in auth session\n"
    )
    response_2 = (
        "SCORE: 6.0\nSUMMARY: check 2\nFINDINGS:\n"
        "- high | correctness | src/auth.py:12 | - | Potential memory leak in auth session\n"
    )

    def scripted_call(system: str, prompt: str) -> str:
        if "Requirements" in system:
            return response_2
        return response_1

    result = run_ensemble(
        lenses=[lens1, lens2],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert len(result.findings) == 1
    merged = result.findings[0]

    # Kept finding is from earliest lens in LENSES (correctness)
    assert "Potential memory leak in auth session" in merged.description
    assert "[also found by: requirements]" in merged.description
    assert result.provenance[merged.id] == ["correctness", "requirements"]


def test_ensemble_non_transitive_merge_preserves_distinct_findings():
    """
    Dedupe is pairwise against the kept representative (non-transitive).
    Finding A matches B, B matches C, but A and C are distinct (>3 lines and low similarity).
    A and C must both be preserved.
    """
    lens1 = LENSES[0]
    lens2 = LENSES[1]
    lens3 = LENSES[2]

    resp_a = "SCORE: 5.0\nSUMMARY: A\nFINDINGS:\n- high | correctness | src/auth.py:10 | - | Buffer overflow in parsing\n"
    resp_b = "SCORE: 5.0\nSUMMARY: B\nFINDINGS:\n- high | correctness | src/auth.py:12 | - | Buffer overflow in parsing\n"
    resp_c = "SCORE: 5.0\nSUMMARY: C\nFINDINGS:\n- high | correctness | src/auth.py:15 | - | Integer underflow in arithmetic\n"

    def scripted_call(system: str, prompt: str) -> str:
        if "Requirements" in system:
            return resp_b
        if "Contracts" in system:
            return resp_c
        return resp_a

    result = run_ensemble(
        lenses=[lens1, lens2, lens3],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=12,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert len(result.findings) == 2
    descs = [f.description for f in result.findings]
    assert any("Buffer overflow" in d for d in descs)
    assert any("Integer underflow" in d for d in descs)


def test_ensemble_raising_lens_recorded_and_rest_used():
    """A lens that raises is recorded in failed and the rest are used."""
    lens1 = LENSES[0]  # raises
    lens2 = LENSES[1]  # succeeds
    lens3 = LENSES[2]  # succeeds

    resp_2 = (
        "SCORE: 8.0\nSUMMARY: ok\nFINDINGS:\n"
        "- high | requirement | src/auth.py:12 | - | Req issue\n"
    )
    resp_3 = (
        "SCORE: 8.0\nSUMMARY: ok\nFINDINGS:\n"
        "- low | maintainability | src/auth.py:14 | - | Contract issue\n"
    )

    def scripted_call(system: str, prompt: str) -> str:
        if "Requirements" in system:
            return resp_2
        if "Contracts" in system:
            return resp_3
        raise RuntimeError("LLM connection timed out")

    result = run_ensemble(
        lenses=[lens1, lens2, lens3],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=12,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert result.usable == 2
    assert result.failed == ["correctness"]
    assert len(result.findings) == 2


def test_ensemble_too_few_usable_lenses_returns_none():
    """When fewer than ceil(N/2) lenses succeed, fail closed and return None."""
    lens1 = LENSES[0]
    lens2 = LENSES[1]
    lens3 = LENSES[2]

    def scripted_call(system: str, prompt: str) -> str:
        if "Contracts" in system:
            return "SCORE: 8.0\nSUMMARY: ok\nFINDINGS:\nNone\n"
        raise ConnectionError("Network down")

    result = run_ensemble(
        lenses=[lens1, lens2, lens3],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=12,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is None


def test_ensemble_max_calls_exceeded_returns_none_zero_calls():
    """When 2 * len(lenses) * len(parts) > max_calls, return None with zero calls."""
    calls_made = 0

    def scripted_call(system: str, prompt: str) -> str:
        nonlocal calls_made
        calls_made += 1
        return "SCORE: 10.0\nSUMMARY: ok\nFINDINGS:\nNone\n"

    result = run_ensemble(
        lenses=[LENSES[0], LENSES[1], LENSES[2]],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=5,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is None
    assert calls_made == 0


def test_ensemble_unverifiable_location_annotated_keeps_blocking():
    """An unverifiable location is annotated and its blocking value is kept."""
    lens1 = LENSES[0]

    response = (
        "SCORE: 4.0\nSUMMARY: bad\nFINDINGS:\n"
        "- critical | correctness | src/auth.py:999 | - | Hardcoded secret in config\n"
    )

    result = run_ensemble(
        lenses=[lens1],
        call=lambda sys, p: response,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert len(result.findings) == 1
    f = result.findings[0]
    assert "[location not verified in the diff]" in f.description
    assert f.blocking is True


def test_ensemble_old_side_lines_and_deleted_file_verified():
    """Old-side lines of a removed block and lines of a deleted file count as verified."""
    lens1 = LENSES[0]

    response = (
        "SCORE: 5.0\nSUMMARY: audit\nFINDINGS:\n"
        "- high | correctness | src/auth.py:25 | - | Removed authorization check without replacement\n"
        "- high | correctness | src/legacy.py:100 | - | Deleted legacy module references\n"
    )

    result = run_ensemble(
        lenses=[lens1],
        call=lambda sys, p: response,
        header="Header",
        parts=[MULTI_HUNK_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert len(result.findings) == 2
    for f in result.findings:
        assert "[location not verified in the diff]" not in f.description


def test_ensemble_diff_parser_ignores_comment_body_lines():
    """Hunk body lines starting with SQL/Lua comments are not treated as diff headers."""
    sql_diff = (
        "diff --git a/schema.sql b/schema.sql\n"
        "--- a/schema.sql\n"
        "+++ b/schema.sql\n"
        "@@ -1,5 +1,5 @@\n"
        "--- Removed SQL comment\n"
        "+-- New SQL comment\n"
        " [file deleted: fake note in body]\n"
    )
    diff_info = _parse_diff([sql_diff])
    assert "schema.sql" in diff_info
    assert diff_info["schema.sql"].is_deleted is False


def test_ensemble_different_kinds_same_place_not_merged():
    """Two findings with different kinds in the same place are NOT merged."""
    lens1 = LENSES[0]
    lens2 = LENSES[1]

    resp_1 = (
        "SCORE: 6.0\nSUMMARY: ok\nFINDINGS:\n"
        "- high | correctness | src/auth.py:12 | - | Null check omitted\n"
    )
    resp_2 = (
        "SCORE: 6.0\nSUMMARY: ok\nFINDINGS:\n"
        "- high | security | src/auth.py:12 | - | Timing attack vulnerability\n"
    )

    def scripted_call(system: str, prompt: str) -> str:
        if "Requirements" in system:
            return resp_2
        return resp_1

    result = run_ensemble(
        lenses=[lens1, lens2],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert len(result.findings) == 2
    kinds = {f.kind for f in result.findings}
    assert kinds == {"correctness", "security"}


def test_ensemble_output_order_independent_of_completion_order():
    """Output order is independent of completion order (varying sleeps in call)."""
    lens1 = LENSES[0]  # correctness
    lens2 = LENSES[1]  # requirements

    resp_auth = (
        "SCORE: 6.0\nSUMMARY: ok\nFINDINGS:\n"
        "- high | correctness | src/auth.py:12 | - | Auth defect\n"
    )
    resp_config = (
        "SCORE: 6.0\nSUMMARY: ok\nFINDINGS:\n"
        "- high | requirement | src/config.py:12 | - | Config defect\n"
    )

    diff = (
        "diff --git a/src/auth.py b/src/auth.py\n"
        "@@ -10,5 +10,5 @@\n+auth\n"
        "diff --git a/src/config.py b/src/config.py\n"
        "@@ -10,5 +10,5 @@\n+config\n"
    )

    def call_run1(system: str, prompt: str) -> str:
        if "Requirements" in system:
            return resp_config
        time.sleep(0.04)
        return resp_auth

    res1 = run_ensemble(
        lenses=[lens1, lens2],
        call=call_run1,
        header="Header",
        parts=[diff],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    def call_run2(system: str, prompt: str) -> str:
        if "Requirements" in system:
            time.sleep(0.04)
            return resp_config
        return resp_auth

    res2 = run_ensemble(
        lenses=[lens1, lens2],
        call=call_run2,
        header="Header",
        parts=[diff],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert res1 is not None and res2 is not None
    assert [f.id for f in res1.findings] == [f.id for f in res2.findings]


def test_ensemble_merge_order_preserves_lens_priority_over_completion_order():
    """When lens 2 finishes first, duplicate merge still selects lens 1's copy."""
    lens1 = LENSES[0]  # correctness
    lens2 = LENSES[1]  # requirements

    resp_1 = "SCORE: 6.0\nSUMMARY: 1\nFINDINGS:\n- high | correctness | src/auth.py:12 | - | Lens 1 wording of issue\n"
    resp_2 = "SCORE: 6.0\nSUMMARY: 2\nFINDINGS:\n- high | correctness | src/auth.py:12 | - | Lens 2 wording of issue\n"

    def scripted_call(system: str, prompt: str) -> str:
        if "Requirements" in system:
            return resp_2
        time.sleep(0.04)
        return resp_1

    result = run_ensemble(
        lenses=[lens1, lens2],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert len(result.findings) == 1
    assert "Lens 1 wording of issue" in result.findings[0].description
    assert "[also found by: requirements]" in result.findings[0].description


def test_ensemble_equal_sort_keys_order_preserved():
    """Non-duplicates with equal sort keys (same file, line, severity) preserve lens order."""
    lens1 = LENSES[0]  # correctness
    lens2 = LENSES[1]  # requirements

    resp_1 = (
        "SCORE: 5.0\nSUMMARY: 1\nFINDINGS:\n"
        "- critical | correctness | src/auth.py:12 | - | Null pointer dereference\n"
    )
    resp_2 = (
        "SCORE: 5.0\nSUMMARY: 2\nFINDINGS:\n"
        "- critical | security | src/auth.py:12 | - | Secret token leak\n"
    )

    def scripted_call(system: str, prompt: str) -> str:
        if "Requirements" in system:
            return resp_2
        time.sleep(0.04)
        return resp_1

    result = run_ensemble(
        lenses=[lens1, lens2],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert len(result.findings) == 2
    assert result.findings[0].kind == "correctness"
    assert result.findings[1].kind == "security"


def test_ensemble_chars_sent_and_calls_exact():
    """chars_sent and calls are exact."""
    lens1 = LENSES[0]

    resp = "SCORE: 9.0\nSUMMARY: ok\nFINDINGS:\nNone\n"
    system_text = "Review System Prompt"
    recorded_lengths: List[int] = []

    def scripted_call(system: str, prompt: str) -> str:
        recorded_lengths.append(len(system) + len(prompt))
        return resp

    result = run_ensemble(
        lenses=[lens1],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt=system_text,
    )

    assert result is not None
    assert result.calls == 1
    assert result.chars_sent == sum(recorded_lengths)
    assert result.chars_sent > 0


def test_ensemble_n1_correctness_one_call_per_part():
    """N=1 with only the correctness lens makes exactly one call per part."""
    lens1 = LENSES[0]  # correctness
    call_count = 0

    def scripted_call(system: str, prompt: str) -> str:
        nonlocal call_count
        call_count += 1
        return "SCORE: 9.0\nSUMMARY: ok\nFINDINGS:\nNone\n"

    part1 = "diff --git a/a.py b/a.py\n@@ -1,5 +1,5 @@\n+1\n"
    part2 = "diff --git a/b.py b/b.py\n@@ -1,5 +1,5 @@\n+2\n"

    result = run_ensemble(
        lenses=[lens1],
        call=scripted_call,
        header="Header",
        parts=[part1, part2],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert result.calls == 2
    assert call_count == 2
    assert result.usable == 1


def test_ensemble_retry_on_unparseable_output():
    """When parse returns None, asks once more with format_reminder appended."""
    lens1 = LENSES[0]
    call_prompts: List[str] = []

    good_resp = (
        "SCORE: 8.0\nSUMMARY: ok\nFINDINGS:\n"
        "- low | style | src/auth.py:12 | - | Line too long\n"
    )

    def scripted_call(system: str, prompt: str) -> str:
        call_prompts.append(prompt)
        if len(call_prompts) == 1:
            return "Sure, here are some thoughts on your code: looks fine!"
        return good_resp

    result = run_ensemble(
        lenses=[lens1],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert result.calls == 2
    assert len(call_prompts) == 2
    assert FORMAT_REMINDER in call_prompts[1]
    assert len(result.findings) == 1


def test_ensemble_retry_exhaustion_fails_lens():
    """When both initial attempt and retry fail to parse, the lens fails."""
    lens1 = LENSES[0]
    lens2 = LENSES[1]

    def scripted_call(system: str, prompt: str) -> str:
        if "Requirements" in system:
            return "SCORE: 8.0\nSUMMARY: ok\nFINDINGS:\nNone\n"
        return "I am an unparseable response"

    result = run_ensemble(
        lenses=[lens1, lens2],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert result.usable == 1
    assert "correctness" in result.failed


def test_ensemble_prompt_focus_lens_order_pinned():
    """A test pins the order: base prompt, focus, lens instruction."""
    base_prompt_body = "You are the Senior Lead Architect safety gate."
    focus_directive = "Review Directive: CRITICAL FOCUS ON SECURITY"
    combined_base = f"{base_prompt_body}\n{focus_directive}"

    adversary_lens = LENSES[4]
    captured_systems: List[str] = []

    def scripted_call(system: str, prompt: str) -> str:
        captured_systems.append(system)
        return "SCORE: 9.0\nSUMMARY: ok\nFINDINGS:\nNone\n"

    run_ensemble(
        lenses=[adversary_lens],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt=combined_base,
    )

    assert len(captured_systems) == 1
    system_text = captured_systems[0]

    idx_base = system_text.index(base_prompt_body)
    idx_focus = system_text.index(focus_directive)
    idx_lens = system_text.index(ADVERSARY_INSTRUCTION)

    assert idx_base < idx_focus < idx_lens


def test_ensemble_stage_timeout_handles_hung_lens():
    """
    A lens still running at expiry is recorded in failed, and cancelled flag stops extra calls.
    Multi-part diff: verifies that a hung thread does NOT make extra calls on subsequent parts.
    """
    lens1 = LENSES[0]  # fast
    lens2 = LENSES[1]  # hung on part 1
    lens2_call_count = 0

    part1 = "diff --git a/a.py b/a.py\n@@ -1,5 +1,5 @@\n+1\n"
    part2 = "diff --git a/b.py b/b.py\n@@ -1,5 +1,5 @@\n+2\n"

    def scripted_call(system: str, prompt: str) -> str:
        nonlocal lens2_call_count
        if "Requirements" in system:
            lens2_call_count += 1
            time.sleep(0.5)
            return "SCORE: 8.0\nSUMMARY: ok\nFINDINGS:\nNone\n"
        return "SCORE: 8.0\nSUMMARY: ok\nFINDINGS:\nNone\n"

    result = run_ensemble(
        lenses=[lens1, lens2],
        call=scripted_call,
        header="Header",
        parts=[part1, part2],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
        stage_timeout_s=0.2,
    )

    assert result is not None
    assert result.usable == 1
    assert "requirements" in result.failed
    # Lens 1 finished both parts (2 calls).
    assert result.calls >= 2
    time.sleep(0.55)  # wait for thread 2 sleep to finish
    # Confirm lens 2 never made a second call on part 2 after timeout cancelled the stage
    assert lens2_call_count == 1


def test_ensemble_daemon_threads_do_not_block_process_exit():
    """
    Subprocess test: running run_ensemble with a call sleeping 8s and stage_timeout_s=0.5
    must exit in under 3s because daemon threads are abandoned without joining at interpreter exit.
    """
    code = """
import time
from guard.core.findings import parse_findings
from guard.core.review_ensemble import run_ensemble
from guard.core.review_lenses import LENSES

def slow_call(sys, p):
    if "Requirements" in sys:
        time.sleep(8.0)
    return "SCORE: 9.0\\nSUMMARY: ok\\nFINDINGS:\\nNone\\n"

part = "diff --git a/a.py b/a.py\\n@@ -1,5 +1,5 @@\\n+1\\n"
res = run_ensemble(
    lenses=[LENSES[0], LENSES[1]],
    call=slow_call,
    header="Header",
    parts=[part],
    parse=lambda t: parse_findings(t, ""),
    max_calls=10,
    format_reminder="reminder",
    system_prompt="",
    stage_timeout_s=0.5,
)
assert res is not None
"""
    start_t = time.perf_counter()
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=5)
    elapsed = time.perf_counter() - start_t

    assert proc.returncode == 0, f"Process failed with stderr: {proc.stderr}"
    assert elapsed < 3.0, f"Process took {elapsed:.2f}s, expected < 3.0s"


def test_ensemble_partial_lens_findings_preserved_when_quorum_met():
    """
    When a lens succeeds on part 1 but fails on part 2, its part 1 findings
    are preserved with annotation '[from a lens that failed on a later part]'
    as long as fail-closed quorum is met by other lenses.
    """
    lens0 = LENSES[0]  # succeeds on both parts
    lens1 = LENSES[1]  # succeeds on part 1, raises on part 2
    lens2 = LENSES[2]  # succeeds on both parts (2 usable lenses >= ceil(3/2) = 2)

    part1 = "diff --git a/a.py b/a.py\n@@ -1,5 +1,5 @@\n+1\n"
    part2 = "diff --git a/b.py b/b.py\n@@ -1,5 +1,5 @@\n+2\n"

    resp_lens1_part1 = (
        "SCORE: 6.0\nSUMMARY: p1\nFINDINGS:\n"
        "- high | requirement | a.py:1 | - | Missing auth check on endpoint A\n"
    )

    def scripted_call(system: str, prompt: str) -> str:
        if "Requirements" in system:
            if "Diff part 2/2" in prompt:
                raise RuntimeError("Failed on part 2")
            return resp_lens1_part1
        return "SCORE: 9.0\nSUMMARY: ok\nFINDINGS:\nNone\n"

    result = run_ensemble(
        lenses=[lens0, lens1, lens2],
        call=scripted_call,
        header="Header",
        parts=[part1, part2],
        parse=_make_parse(),
        max_calls=16,
        format_reminder=FORMAT_REMINDER,
        system_prompt="",
    )

    assert result is not None
    assert result.usable == 2
    assert "requirements" in result.failed
    # Lens 1's finding on part 1 is preserved with annotation
    assert len(result.findings) == 1
    f = result.findings[0]
    assert "Missing auth check on endpoint A" in f.description
    assert "[from a lens that failed on a later part]" in f.description


def _finding(fid: str, location: str, description: str, severity: str = "high") -> Finding:
    return Finding(id=fid, severity=severity, kind="correctness", location=location, description=description)


def test_review_lens_parts_retries_bad_format_then_succeeds():
    """A part whose first answer is unparseable is asked again with the format reminder appended."""
    prompts: List[str] = []
    systems: List[str] = []
    responses = iter(
        [
            "Looks fine to me.",
            "SCORE: 7.0\nSUMMARY: ok\nFINDINGS:\n"
            "- high | correctness | src/auth.py:12 | - | Null pointer in login\n",
        ]
    )

    def make_call(system: str, prompt: str) -> str:
        systems.append(system)
        prompts.append(prompt)
        return next(responses)

    completed = _review_lens_parts(
        LENSES[1], [SAMPLE_DIFF], "Header", "BASE", FORMAT_REMINDER, _make_parse(), make_call, threading.Event()
    )

    assert [[f.location for f in part] for part in completed] == [["src/auth.py:12"]]
    assert len(prompts) == 2
    assert not prompts[0].endswith(FORMAT_REMINDER)
    assert prompts[1].endswith(FORMAT_REMINDER)
    assert REQUIREMENTS_INSTRUCTION in systems[0]


def test_review_lens_parts_failed_part_stops_the_lens():
    """A part that fails both attempts ends the lens; later parts are never sent to the model."""
    prompts: List[str] = []
    parts = [
        "diff --git a/a.py b/a.py\n@@ -1,5 +1,5 @@\n+1\n",
        "diff --git a/b.py b/b.py\n@@ -1,5 +1,5 @@\n+2\n",
        "diff --git a/c.py b/c.py\n@@ -1,5 +1,5 @@\n+3\n",
    ]

    def make_call(system: str, prompt: str) -> str:
        prompts.append(prompt)
        if "b.py" in prompt:
            return "no usable format"
        return "SCORE: 8.0\nSUMMARY: ok\nFINDINGS:\nNone\n"

    completed = _review_lens_parts(
        LENSES[0], parts, "Header", "", FORMAT_REMINDER, _make_parse(), make_call, threading.Event()
    )

    assert completed == [[]]
    assert len(prompts) == 3  # part 1 once, part 2 twice (retry), part 3 never
    assert not any("c.py" in prompt for prompt in prompts)


def test_review_lens_parts_cancelled_stage_makes_no_calls():
    """A lens started after the stage was cancelled returns nothing and calls the model zero times."""
    cancelled = threading.Event()
    cancelled.set()
    calls: List[str] = []

    def make_call(system: str, prompt: str) -> str:
        calls.append(prompt)
        return ""

    completed = _review_lens_parts(
        LENSES[0], [SAMPLE_DIFF], "Header", "", FORMAT_REMINDER, _make_parse(), make_call, cancelled
    )

    assert completed == []
    assert calls == []


def test_collect_lens_results_expired_deadline_marks_every_lens_failed():
    """Past the stage deadline no outcome is read, so every lens counts as failed."""
    lenses = LENSES[:3]
    result_queue: queue.Queue = queue.Queue()
    result_queue.put((lenses[0], [[]], []))

    lens_results, partial_results, failed_keys, completed_keys = _collect_lens_results(
        lenses, result_queue, time.monotonic() - 1.0
    )

    assert lens_results == {}
    assert partial_results == {}
    assert failed_keys == {lens.key for lens in lenses}
    assert completed_keys == set()


def test_collect_lens_results_splits_complete_partial_and_silent_lenses():
    """Complete lenses fill lens_results, partial lenses keep their parts, silent lenses are failed."""
    lenses = LENSES[:3]
    result_queue: queue.Queue = queue.Queue()
    result_queue.put((lenses[0], [[_finding("a1", "src/auth.py:12", "Null pointer")]], []))
    result_queue.put((lenses[1], None, [[_finding("b1", "src/auth.py:13", "Leaks token")]]))

    lens_results, partial_results, failed_keys, completed_keys = _collect_lens_results(
        lenses, result_queue, time.monotonic() + 0.1
    )

    assert set(lens_results) == {"correctness"}
    assert set(partial_results) == {"requirements"}
    assert failed_keys == {"requirements", "contracts"}
    assert completed_keys == {"correctness", "requirements"}


def test_collect_candidates_orders_by_lens_then_part_and_tags_partial_lens():
    """Candidates follow lens order then part order, and partial-lens findings get the failure note."""
    lenses = [LENSES[0], LENSES[1], LENSES[2]]
    a1 = _finding("a1", "src/auth.py:12", "Null pointer")
    a2 = _finding("a2", "src/auth.py:14", "Unchecked role")
    b1 = _finding("b1", "src/auth.py:13", "Leaks token")
    c1 = _finding("c1", "src/auth.py:15", "Contract drift")

    raw = _collect_candidates(
        lenses,
        lens_results={"contracts": [[c1]], "correctness": [[a1], [a2]]},
        partial_results={"requirements": [[b1]]},
    )

    assert [(f.id, lens.key, part, idx) for f, lens, part, idx in raw] == [
        ("a1", "correctness", 0, 0),
        ("a2", "correctness", 1, 1),
        ("b1", "requirements", 0, 2),
        ("c1", "contracts", 0, 3),
    ]
    assert raw[2][0].description == "Leaks token [from a lens that failed on a later part]"
    assert b1.description == "Leaks token"


def test_dedupe_candidates_merges_same_defect_across_lenses_and_keeps_distinct_ones():
    """The same defect reported by two lenses becomes one representative listing both lenses."""
    same_a = _finding("s1", "src/auth.py:12", "Null pointer in login")
    same_b = _finding("s2", "src/auth.py:12", "Null pointer in login")
    other = _finding("o1", "src/auth.py:60", "Missing rate limit audit log")
    raw = [
        (same_a, LENSES[0], 0, 0),
        (other, LENSES[1], 0, 1),
        (same_b, LENSES[1], 0, 2),
    ]

    representatives = _dedupe_candidates(raw)

    assert [rep[0].id for rep in representatives] == ["s1", "o1"]
    _, winner, members, _ = representatives[0]
    assert winner.key == "correctness"
    assert sorted(lens.key for lens, _ in members) == ["correctness", "requirements"]
    assert representatives[1][2] == [(LENSES[1], 0)]


def test_finalize_representatives_flags_unverified_location_and_records_provenance():
    """Findings outside the diff are flagged, provenance lists lenses in priority order, output is severity-sorted."""
    verified = _finding("v1", "src/auth.py:12", "Null pointer in login", severity="medium")
    unverified = _finding("u1", "src/auth.py:999", "Stale cache", severity="high")
    representatives = [
        (verified, LENSES[0], [(LENSES[1], 0), (LENSES[0], 0)], 0),
        (unverified, LENSES[1], [(LENSES[1], 0)], 1),
    ]

    findings, provenance = _finalize_representatives(representatives, [SAMPLE_DIFF])

    assert [f.id for f in findings] == ["u1", "v1"]
    assert findings[0].description == "Stale cache [location not verified in the diff]"
    assert findings[1].description == "Null pointer in login [also found by: requirements]"
    assert provenance == {"v1": ["correctness", "requirements"], "u1": ["requirements"]}
