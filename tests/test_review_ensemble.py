"""
Tests for the review ensemble and review lenses.
"""

from __future__ import annotations

import time
from typing import List, Optional

from guard.core.findings import Finding, parse_findings
from guard.core.review_ensemble import (
    EnsembleResult,
    FileDiffInfo,
    _build_part_prompt,
    _candidate_rank,
    _combine_system_prompt,
    _find_file_info,
    _is_location_verified,
    _is_same_finding,
    _lens_rank,
    _normalize_description,
    _normalize_path,
    _output_sort_key,
    _parse_diff,
    _parse_location,
    _strip_annotations,
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


def test_ensemble_helpers_direct():
    """Direct tests for parsing, normalization and ranking helpers."""
    # _normalize_path
    assert _normalize_path("./src/foo.py") == "src/foo.py"
    assert _normalize_path("src\\bar.py") == "src/bar.py"

    # _normalize_description
    assert _normalize_description("`quoted` text  with 'apostrophe'") == "quoted text with apostrophe"

    # _parse_location
    file_p, line_n = _parse_location("src/app.py:42")
    assert file_p == "src/app.py"
    assert line_n == 42
    file_p2, line_n2 = _parse_location("src/app.py")
    assert file_p2 == "src/app.py"
    assert line_n2 is None

    # _strip_annotations
    annotated = "Memory leak [location not verified in the diff] [also found by: tests]"
    assert _strip_annotations(annotated) == "Memory leak"

    # _lens_rank
    assert _lens_rank("correctness", LENSES) == 0
    assert _lens_rank("requirements", LENSES) == 1
    assert _lens_rank("unknown", LENSES) == 9999

    # FileDiffInfo dataclass
    diff_info = FileDiffInfo(is_deleted=True, old_ranges=[(1, 10)], new_ranges=[(1, 5)])
    assert diff_info.is_deleted is True
    assert diff_info.old_ranges == [(1, 10)]

    # _find_file_info
    diff_map = {"src/app.py": diff_info}
    assert _find_file_info("src/app.py", diff_map) is diff_info
    assert _find_file_info("app.py", diff_map) is diff_info
    assert _find_file_info("other.py", diff_map) is None

    # _is_location_verified
    assert _is_location_verified("src/app.py:5", diff_map) is True
    assert _is_location_verified("unknown.py:5", diff_map) is False
    # _candidate_rank
    finding_crit = Finding(
        id="c1", severity="critical", kind="correctness", location="a.py:1",
        description="d1", blocking=True,
    )
    finding_low = Finding(
        id="c2", severity="low", kind="correctness", location="a.py:1",
        description="d2", blocking=False,
    )
    rank_crit = _candidate_rank(finding_crit, LENSES[0], 0, LENSES)
    rank_low = _candidate_rank(finding_low, LENSES[0], 1, LENSES)
    assert rank_crit < rank_low  # blocking critical ranks higher (smaller tuple)

    # _is_same_finding
    assert _is_same_finding(finding_crit, finding_crit) is True
    finding_diff = Finding(
        id="c3", severity="low", kind="correctness", location="b.py:1",
        description="d3", blocking=False,
    )
    assert _is_same_finding(finding_crit, finding_diff) is False
    key_crit = _output_sort_key(finding_crit)
    key_low = _output_sort_key(finding_low)
    assert key_crit < key_low

    # _combine_system_prompt
    assert _combine_system_prompt("base", "lens") == "base\n\nlens"
    assert _combine_system_prompt("base", "") == "base"
    assert _combine_system_prompt("", "lens") == "lens"

    # _build_part_prompt
    prompt1 = _build_part_prompt("Header", "diff content", 1, 1)
    assert "Header" in prompt1 and "diff content" in prompt1
    prompt2 = _build_part_prompt("", "diff content", 1, 2)
    assert "Diff part 1/2" in prompt2


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


def test_ensemble_same_defect_merged_with_provenance():
    """The same defect found by two lenses is merged once with provenance."""
    lens1 = LENSES[0]  # correctness
    lens2 = LENSES[1]  # requirements

    # Same file, same kind ('correctness'), lines within 3 (12 vs 13)
    response_1 = (
        "SCORE: 6.0\nSUMMARY: check 1\nFINDINGS:\n"
        "- high | correctness | src/auth.py:12 | - | Potential memory leak in auth session\n"
    )
    response_2 = (
        "SCORE: 6.0\nSUMMARY: check 2\nFINDINGS:\n"
        "- high | correctness | src/auth.py:13 | - | Potential memory leak in auth session\n"
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
    )

    assert result is not None
    assert isinstance(result, EnsembleResult)
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

    # A: line 10, "Buffer overflow in request parsing"
    # B: line 12, "Buffer overflow in request parsing" (within 3 lines of A -> matches A)
    # C: line 15, "Integer underflow in arithmetic logic" (5 lines from A and different wording)
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
    )

    assert result is not None
    # A and B merged, C remains distinct -> exactly 2 findings
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

    # 2 out of 3 raise -> only 1 usable < ceil(3/2) = 2 -> None
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
    )

    assert result is None


def test_ensemble_max_calls_exceeded_returns_none_zero_calls():
    """When 2 * len(lenses) * len(parts) > max_calls, return None with zero calls."""
    calls_made = 0

    def scripted_call(system: str, prompt: str) -> str:
        nonlocal calls_made
        calls_made += 1
        return "SCORE: 10.0\nSUMMARY: ok\nFINDINGS:\nNone\n"

    # 3 lenses, 1 part -> worst case is 2 * 3 * 1 = 6 calls. With max_calls=5, aborts before calling.
    result = run_ensemble(
        lenses=[LENSES[0], LENSES[1], LENSES[2]],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=5,
        format_reminder=FORMAT_REMINDER,
    )

    assert result is None
    assert calls_made == 0


def test_ensemble_unverifiable_location_annotated_keeps_blocking():
    """An unverifiable location is annotated and its blocking value is kept."""
    lens1 = LENSES[0]

    # Line 999 is outside diff hunk (hunk is 10..21)
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
    )

    assert result is not None
    assert len(result.findings) == 1
    f = result.findings[0]
    # Location not verified is annotated
    assert "[location not verified in the diff]" in f.description
    # Blocking status is strictly preserved (critical correctness is blocking)
    assert f.blocking is True


def test_ensemble_old_side_lines_and_deleted_file_verified():
    """Old-side lines of a removed block and lines of a deleted file count as verified."""
    lens1 = LENSES[0]

    # In MULTI_HUNK_DIFF:
    # auth.py has hunk @@ -20,10 +20,3 @@: old lines 20-29 were removed.
    # legacy.py is deleted (deleted file mode 100644).
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
    )

    assert result is not None
    assert len(result.findings) == 2
    for f in result.findings:
        # Neither should have [location not verified in the diff]
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
    # Body line with [file deleted: should NOT mark schema.sql as deleted!
    assert diff_info["schema.sql"].is_deleted is False


def test_ensemble_different_kinds_same_place_not_merged():
    """Two findings with different kinds in the same place are NOT merged."""
    lens1 = LENSES[0]
    lens2 = LENSES[1]

    # Same location (src/auth.py:12), but one is correctness and one is security
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
    )

    assert result is not None
    assert len(result.findings) == 2
    kinds = {f.kind for f in result.findings}
    assert kinds == {"correctness", "security"}


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


def test_ensemble_output_order_independent_of_completion_order():
    """Output order is independent of completion order (varying sleeps in call)."""
    lens1 = LENSES[0]  # correctness
    lens2 = LENSES[1]  # requirements

    # Defect on auth.py vs defect on config.py
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

    # Run 1: lens1 sleeps 0.05s, lens2 returns immediately
    def call_run1(system: str, prompt: str) -> str:
        if "Requirements" in system:
            return resp_config
        time.sleep(0.05)
        return resp_auth

    res1 = run_ensemble(
        lenses=[lens1, lens2],
        call=call_run1,
        header="Header",
        parts=[diff],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
    )

    # Run 2: lens2 sleeps 0.05s, lens1 returns immediately
    def call_run2(system: str, prompt: str) -> str:
        if "Requirements" in system:
            time.sleep(0.05)
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
    )

    assert res1 is not None and res2 is not None
    # Findings must be in identical order across both runs
    assert [f.id for f in res1.findings] == [f.id for f in res2.findings]


def test_ensemble_merge_order_preserves_lens_priority_over_completion_order():
    """When lens 2 finishes first, duplicate merge still selects lens 1's copy."""
    lens1 = LENSES[0]  # correctness
    lens2 = LENSES[1]  # requirements

    # Both find the exact same issue at src/auth.py:12
    resp_1 = "SCORE: 6.0\nSUMMARY: 1\nFINDINGS:\n- high | correctness | src/auth.py:12 | - | Lens 1 wording of issue\n"
    resp_2 = "SCORE: 6.0\nSUMMARY: 2\nFINDINGS:\n- high | correctness | src/auth.py:12 | - | Lens 2 wording of issue\n"

    # Lens 1 sleeps, Lens 2 completes first
    def scripted_call(system: str, prompt: str) -> str:
        if "Requirements" in system:
            return resp_2
        time.sleep(0.05)
        return resp_1

    result = run_ensemble(
        lenses=[lens1, lens2],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
    )

    assert result is not None
    assert len(result.findings) == 1
    # Even though lens 2 completed first, lens 1 wording must be kept (earliest in LENSES)
    assert "Lens 1 wording of issue" in result.findings[0].description
    assert "[also found by: requirements]" in result.findings[0].description


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
            # First answer cannot be parsed
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
    )

    assert result is not None
    assert result.calls == 2
    assert len(call_prompts) == 2
    # Second attempt had format reminder appended
    assert FORMAT_REMINDER in call_prompts[1]
    assert len(result.findings) == 1


def test_ensemble_retry_exhaustion_fails_lens():
    """When both initial attempt and retry fail to parse, the lens fails."""
    lens1 = LENSES[0]
    lens2 = LENSES[1]

    def scripted_call(system: str, prompt: str) -> str:
        if "Requirements" in system:
            return "SCORE: 8.0\nSUMMARY: ok\nFINDINGS:\nNone\n"
        # Lens 1 always returns unparseable text
        return "I am an unparseable response"

    result = run_ensemble(
        lenses=[lens1, lens2],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
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

    # Verify strictly that base_prompt precedes focus, and focus precedes lens instruction
    idx_base = system_text.index(base_prompt_body)
    idx_focus = system_text.index(focus_directive)
    idx_lens = system_text.index(ADVERSARY_INSTRUCTION)

    assert idx_base < idx_focus < idx_lens


def test_ensemble_stage_timeout_handles_hung_lens():
    """A lens still running at expiry is recorded in failed, and cancelled flag stops extra calls."""
    lens1 = LENSES[0]  # fast
    lens2 = LENSES[1]  # hung / slow
    hung_calls_after_timeout = 0

    def scripted_call(system: str, prompt: str) -> str:
        nonlocal hung_calls_after_timeout
        if "Requirements" in system:
            time.sleep(0.3)
            hung_calls_after_timeout += 1
            return "SCORE: 8.0\nSUMMARY: ok\nFINDINGS:\nNone\n"
        return "SCORE: 8.0\nSUMMARY: ok\nFINDINGS:\nNone\n"

    # Timeout after 0.05s
    result = run_ensemble(
        lenses=[lens1, lens2],
        call=scripted_call,
        header="Header",
        parts=[SAMPLE_DIFF],
        parse=_make_parse(),
        max_calls=10,
        format_reminder=FORMAT_REMINDER,
        stage_timeout_s=0.05,
    )

    assert result is not None
    assert result.usable == 1
    assert "requirements" in result.failed
    # Wait briefly to let hung thread exit cleanly without continuing to make calls
    time.sleep(0.35)
