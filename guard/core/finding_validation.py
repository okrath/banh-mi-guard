"""
Cross-part finding validation: validates blocking findings against the full diff.

Note on diff partitioning:
The reviewer passes the full raw diff to validate_findings. Because review part
boundaries are not present in a raw diff, cross-part validation within the same file
cannot be reliably distinguished from adjacent author-controlled edits. Therefore,
validation strictly enforces cross-file verification paired with provenance:
a finding is only refuted by evidence that the author could not have fabricated,
specifically:
  (a) an unchanged context line in a file other than the finding's own file, or
  (b) an added (+) line in another file whose exact text was moved verbatim from
      a removed (-) line in the finding's file (the content already existed at the base commit).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Literal, Optional

from guard.core.findings import Finding
from guard.core.rulebook import OCRRulebookRunner

STOP_WORDS = {
    "about", "above", "after", "again", "against", "all", "also", "always",
    "been", "before", "being", "below", "between", "both", "could", "does",
    "doing", "down", "during", "each", "from", "further", "have", "having",
    "here", "into", "just", "more", "most", "only", "other", "over", "same",
    "should", "some", "such", "than", "that", "their", "them", "then", "there",
    "these", "they", "this", "those", "through", "under", "until", "very",
    "were", "what", "when", "where", "which", "while", "will", "with", "would",
    "true", "false", "none", "null", "self", "return", "import", "class",
}

COMMENT_PREFIXES = (
    "#",
    "//",
    "/*",
    "*",
    "--",
    "<!--",
    '"""',
    "'''",
    ";",
)

# Token prefixes for well-known credentials that might appear without standard assignment keywords.
# Key-assignment patterns (api_key = "...", token: "...", etc.) are defined centrally in OCRRulebookRunner.SECRET_REGEX.
_KNOWN_TOKEN_PREFIX_PATTERNS = [
    re.compile(r"\b(?:sk-[a-zA-Z0-9_-]{16,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16}|xox[baprs]-[a-zA-Z0-9_-]{10,})\b"),
    re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"),
]

VALIDATION_SYSTEM_PROMPT = """You are a code review validator checking whether a finding raised on a diff is disproven by other parts of the diff.

Your task is to judge whether the diff context refutes, confirms, or leaves unsure the finding.
Refute only when a line in the context shows the claim is false (the content was moved to another file, the missing check exists, the claimed removal is re-added); otherwise answer confirmed or unsure.

You must answer in exactly this format:
VERDICT: confirmed|refuted|unsure
EVIDENCE: <one verbatim line from the context, copied exactly, or none>
REASON: <one sentence>"""


@dataclass
class Validation:
    finding_id: str
    verdict: Literal["confirmed", "refuted", "unsure"]
    evidence: str = ""  # verbatim quote from the diff, empty when none
    evidence_verified: bool = False  # the quote literally appears in the diff (whitespace-normalised)
    reason: str = ""  # why guard kept or changed the finding; empty for pure confirmations
    cross_part_verified: bool = False  # verified from a different part or different file than finding


# Internal types:
# DiffLine: (line_type, content, raw_line, file_path)
# DiffHunk: (file_path, full_text, old_start, old_count, new_start, new_count)
_DiffLineTuple = tuple[str, str, str, str]
_DiffHunkTuple = tuple[str, str, int, int, int, int]


def _norm_path(path: str) -> str:
    p = path.replace("\\", "/").strip()
    if p.startswith("a/") or p.startswith("b/"):
        p = p[2:]
    return p.lower()


def resolve_finding_file(location: str, diff_files: set[str]) -> Optional[str]:
    """
    Normalise finding.location and resolve it to exactly ONE file present in the diff.
    Strips backticks, quotes, leading ./, :line, :line-range, #L3, ' line 3', ' (L3)', and trailing prose.
    If the location does not resolve to exactly one file in diff_files, returns None (fail-safe).
    """
    if not location or not location.strip():
        return None

    # Remove quotes and backticks anywhere in the string:
    s = location.replace("`", "").replace("'", "").replace('"', "").strip()
    if s.startswith("./") or s.startswith(".\\"):
        s = s[2:]

    # Take candidate path before first colon, hash, parenthesis, or whitespace
    candidate = re.split(r"[:#(\s]", s)[0].strip()
    candidate_norm = _norm_path(candidate)
    if not candidate_norm:
        return None

    # Check 1: Exact match in diff_files
    if candidate_norm in diff_files:
        return candidate_norm

    # Check 2: Path suffix on a '/' boundary (e.g. 'auth.py' matches 'src/auth.py')
    matches = [f for f in diff_files if f.endswith("/" + candidate_norm)]
    if len(matches) == 1:
        return matches[0]

    return None


def _is_comment_or_docstring_line(line: str) -> bool:
    """
    Reject lines whose first non-blank characters (after any diff marker)
    are #, //, /*, *, --, <!--, \"\"\", ''', or ;
    """
    s = line.strip()
    if s.startswith(("+", " ")) or (s.startswith("-") and not s.startswith("--")):
        s = s[1:].strip()
    return any(s.startswith(prefix) for prefix in COMMENT_PREFIXES)


def _matches_secret_pattern(line: str) -> bool:
    """Check if the line matches the shared rulebook secret regex or well-known token prefixes."""
    if OCRRulebookRunner.SECRET_REGEX.search(line):
        return True
    for pattern in _KNOWN_TOKEN_PREFIX_PATTERNS:
        if pattern.search(line):
            return True
    return False


def _flush_hunk(
    diff_hunks: list[_DiffHunkTuple],
    current_file: str,
    current_file_headers: list[str],
    current_hunk_header: str,
    current_hunk_lines: list[str],
    current_old_start: int,
    current_old_count: int,
    current_new_start: int,
    current_new_count: int,
) -> None:
    """Append completed hunk to diff_hunks if header and file are valid."""
    if current_hunk_header and current_file:
        full_text = "\n".join(current_file_headers) + "\n" + current_hunk_header + "\n" + "\n".join(current_hunk_lines)
        diff_hunks.append(
            (
                current_file,
                full_text.strip(),
                current_old_start,
                current_old_count,
                current_new_start,
                current_new_count,
            )
        )


def _parse_diff(full_diff: str) -> tuple[list[_DiffLineTuple], list[_DiffHunkTuple]]:
    """Parse unified diff into lines and hunks with file headers and line numbering."""
    diff_lines: list[_DiffLineTuple] = []
    diff_hunks: list[_DiffHunkTuple] = []

    current_file = ""
    in_hunk = False

    current_file_headers: list[str] = []
    current_hunk_header = ""
    current_hunk_lines: list[str] = []
    current_old_start = 0
    current_old_count = 0
    current_new_start = 0
    current_new_count = 0

    for line in full_diff.splitlines():
        # Check diff --git header: ends previous file/hunk
        git_m = re.match(r"^diff --git a/(.*?)\s+b/(.*)", line)
        if git_m:
            _flush_hunk(
                diff_hunks, current_file, current_file_headers, current_hunk_header,
                current_hunk_lines, current_old_start, current_old_count,
                current_new_start, current_new_count,
            )
            current_hunk_lines = []
            current_hunk_header = ""
            current_file = _norm_path(git_m.group(2))
            current_file_headers = [line]
            in_hunk = False
            continue

        # Check hunk header: ends previous hunk, starts new hunk
        hunk_m = re.match(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@", line)
        if hunk_m:
            _flush_hunk(
                diff_hunks, current_file, current_file_headers, current_hunk_header,
                current_hunk_lines, current_old_start, current_old_count,
                current_new_start, current_new_count,
            )
            current_hunk_lines = []
            current_hunk_header = line
            current_old_start = int(hunk_m.group(1))
            current_old_count = int(hunk_m.group(2)) if hunk_m.group(2) else 1
            current_new_start = int(hunk_m.group(3))
            current_new_count = int(hunk_m.group(4)) if hunk_m.group(4) else 1
            in_hunk = True
            continue

        # Check --- / +++ file headers: only outside hunks
        if not in_hunk:
            if line.startswith("--- "):
                current_file_headers.append(line)
                continue
            if line.startswith("+++ "):
                current_file_headers.append(line)
                plus_m = re.match(r"^\+\+\+\s+(?:b/)?(.*)", line)
                if plus_m and not current_file:
                    current_file = _norm_path(plus_m.group(1))
                continue

        # Content lines inside hunks
        if in_hunk:
            if line.startswith("+"):
                diff_lines.append(("+", line[1:].strip(), line, current_file))
                current_hunk_lines.append(line)
            elif line.startswith("-"):
                diff_lines.append(("-", line[1:].strip(), line, current_file))
                current_hunk_lines.append(line)
            elif line.startswith(" "):
                diff_lines.append((" ", line[1:].strip(), line, current_file))
                current_hunk_lines.append(line)
            elif line.startswith("\\"):
                current_hunk_lines.append(line)
            else:
                # Line does not start with '+', '-', ' ' or '\\': ends the current hunk
                _flush_hunk(
                    diff_hunks, current_file, current_file_headers, current_hunk_header,
                    current_hunk_lines, current_old_start, current_old_count,
                    current_new_start, current_new_count,
                )
                current_hunk_lines = []
                current_hunk_header = ""
                in_hunk = False
        else:
            if current_file:
                current_file_headers.append(line)

    _flush_hunk(
        diff_hunks, current_file, current_file_headers, current_hunk_header,
        current_hunk_lines, current_old_start, current_old_count,
        current_new_start, current_new_count,
    )
    return diff_lines, diff_hunks


def select_for_validation(findings: list[Finding]) -> list[Finding]:
    """Select blocking findings for validation in their original order."""
    return [f for f in findings if f.blocking]


def relevant_context(finding: Finding, full_diff: str, max_chars: int = 12000) -> str:
    """
    From the whole diff, take hunks relevant to the finding, trimmed to max_chars:
    1. Finding's own file hunks are placed FIRST to defeat context padding attacks.
    2. Each hunk is capped at 2,500 characters so no single hunk can starve the context.
    3. Other hunks sharing at least two distinctive identifiers are ranked by overlap.
    4. Loop uses continue (not break) so smaller qualifying hunks still fit.
    """
    _, diff_hunks = _parse_diff(full_diff)
    diff_files = {h[0] for h in diff_hunks}
    finding_file = resolve_finding_file(finding.location, diff_files)

    # Separate own-file hunks from other hunks, capping each hunk text at 2500 characters
    own_file_hunks: list[str] = []
    other_hunks: list[tuple[int, int, str]] = []

    query_text = f"{finding.description} {finding.location}"
    query_tokens = {
        tok.lower()
        for tok in re.findall(r"[a-zA-Z0-9_]{4,}", query_text)
        if tok.lower() not in STOP_WORDS
    }

    for idx, (h_file, h_text, _, _, _, _) in enumerate(diff_hunks):
        capped_text = h_text[:2500].rstrip() + "\n... [diff hunk trimmed for length]" if len(h_text) > 2500 else h_text
        if finding_file and h_file == finding_file:
            own_file_hunks.append(capped_text)
        else:
            hunk_tokens = {
                tok.lower()
                for tok in re.findall(r"[a-zA-Z0-9_]{4,}", capped_text)
                if tok.lower() not in STOP_WORDS
            }
            overlap = len(query_tokens.intersection(hunk_tokens))
            if overlap >= 2:
                other_hunks.append((overlap, idx, capped_text))

    # Sort other hunks descending by overlap (stable)
    other_hunks.sort(key=lambda item: (-item[0], item[1]))

    # Prioritize finding's own file hunks first, then qualifying other hunks
    candidate_hunks: list[str] = list(own_file_hunks) + [h[2] for h in other_hunks]

    selected_texts: list[str] = []
    current_len = 0
    for text in candidate_hunks:
        text_clean = text.strip()
        if not text_clean:
            continue
        add_len = len(text_clean) + (2 if selected_texts else 0)
        if current_len + add_len <= max_chars:
            selected_texts.append(text_clean)
            current_len += add_len
        elif not selected_texts:
            selected_texts.append(text_clean[:max_chars])
            current_len = max_chars
        # continue (do not break) so smaller subsequent hunks can still fit

    if selected_texts:
        return "\n\n".join(selected_texts)

    # Fallback to finding's file, or full_diff capped
    if finding_file:
        file_lines: list[str] = []
        capturing = False
        for line in full_diff.splitlines():
            if line.startswith("diff --git ") or line.startswith("--- "):
                if finding_file in line.lower():
                    capturing = True
                elif capturing and line.startswith("diff --git "):
                    break
            if capturing:
                file_lines.append(line)
        if file_lines:
            return "\n".join(file_lines)[:max_chars]

    return full_diff[:max_chars]


def build_validation_prompt(
    finding: Finding, context: str, task_text: str
) -> tuple[str, str]:
    """
    Build (system, prompt) for validation.
    All instructions live in system; prompt carries only data.
    """
    prompt_data = f"""Task:
{task_text}

Finding:
- Severity: {finding.severity}
- Kind: {finding.kind}
- Location: {finding.location}
- Description: {finding.description}

Diff Context:
```
{context}
```"""
    return VALIDATION_SYSTEM_PROMPT, prompt_data


def parse_validation(text: str, finding_id: str) -> Optional[Validation]:
    """
    Parse validation LLM response into Validation dataclass.
    Ambiguous answers (more than one VERDICT, EVIDENCE, or REASON line) fail safe and return None.
    Supports markdown bold and bullet formatting.
    """
    if not text or not text.strip():
        return None

    verdict_matches = list(re.finditer(r"(?im)^[ \t*#-]*\**VERDICT\**:[ \t*]*(confirmed|refuted|unsure)\b", text))
    if len(verdict_matches) != 1:
        return None  # Missing, or more than one VERDICT line -> ambiguous -> fail safe!

    verdict = verdict_matches[0].group(1).lower()

    evidence_matches = list(re.finditer(r"(?im)^[ \t*#-]*\**EVIDENCE\**:[ \t*]*(.*)$", text))
    if len(evidence_matches) > 1:
        return None  # More than one EVIDENCE line -> ambiguous -> fail safe!

    evidence = ""
    if len(evidence_matches) == 1:
        raw_evidence = evidence_matches[0].group(1).strip()
        raw_evidence = re.sub(r"\**$", "", raw_evidence).strip()
        if raw_evidence.lower() not in ("none", "<none>", "none.", "n/a", "no evidence", '""', "''"):
            evidence = raw_evidence

    reason_matches = list(re.finditer(r"(?im)^[ \t*#-]*\**REASON\**:[ \t*]*(.*)$", text))
    if len(reason_matches) > 1:
        return None  # More than one REASON line -> ambiguous -> fail safe!

    reason = ""
    if len(reason_matches) == 1:
        raw_reason = reason_matches[0].group(1).strip()
        reason = re.sub(r"\**$", "", raw_reason).strip()

    return Validation(
        finding_id=finding_id,
        verdict=verdict,  # type: ignore
        evidence=evidence,
        evidence_verified=False,
        reason=reason,
    )


def _check_evidence_in_diff(
    evidence: str, finding: Finding, full_diff: str
) -> tuple[bool, bool]:
    """
    Verify if evidence appears in full_diff as a whole line, satisfying PROVENANCE:
    The quote must be a line the agent could not have invented, specifically:
      (a) an unchanged context line (' ') of a file other than the finding's own file, OR
      (b) an added (+) line in another file whose exact text was moved verbatim from a
          removed (-) line in the finding's file (the content was moved from existing code).
    A (+) line with no matching (-) line is never evidence.
    A (-) line alone is never evidence.
    Returns (evidence_verified, cross_part_verified).
    """
    if not evidence or not evidence.strip():
        return False, False

    ev_trimmed = evidence.strip()
    if "\n" in ev_trimmed:
        return False, False

    diff_lines, diff_hunks = _parse_diff(full_diff)
    if not diff_lines:
        return False, False

    diff_files = {h[0] for h in diff_hunks}
    finding_file = resolve_finding_file(finding.location, diff_files)

    # If finding location does not resolve to exactly one file in the diff, fail safe!
    if not finding_file:
        return False, False

    matching_plus_files: set[str] = set()
    matching_minus_files: set[str] = set()
    matching_context_files: set[str] = set()

    for line_type, line_content, _, file_path in diff_lines:
        if line_content == ev_trimmed:
            if line_type == "+":
                matching_plus_files.add(file_path)
            elif line_type == "-":
                matching_minus_files.add(file_path)
            elif line_type == " ":
                matching_context_files.add(file_path)

    # 1. evidence_verified: must literally exist as an added or context line
    if not matching_plus_files and not matching_context_files:
        return False, False

    # 2. PROVENANCE check for cross_part_verified:
    # (a) Unchanged context line in another file:
    context_in_other = any(f != finding_file for f in matching_context_files)
    # (b) Moved code: added in another file AND removed from the finding's file:
    moved_from_finding_file = any(f != finding_file for f in matching_plus_files) and (finding_file in matching_minus_files)

    if context_in_other or moved_from_finding_file:
        return True, True

    # If the quote matches added lines only without provenance or in the same file:
    return True, False


def apply_validations(
    findings: list[Finding],
    validations: list[Validation],
) -> list[Finding]:
    """
    Apply validations to findings. Only blocking findings can be demoted.
    A finding is demoted when ALL 6 conditions hold:
    1. verdict is 'refuted' and evidence_verified is true;
    2. quote is 12 to 160 characters after trimming;
    3. finding kind is NOT 'security';
    4. quote has valid cross-file provenance (cross_part_verified is true);
    5. quote is not a comment or docstring line;
    6. quote does not match a secret pattern.
    Two findings with the same ID do not share one validation result: each copy
    consumes exactly one validation result from the queue.
    Fails safe: on any error, doubt, or missing evidence, findings stay untouched.
    """
    val_queue_by_id: dict[str, list[Validation]] = {}
    for v in validations:
        val_queue_by_id.setdefault(v.finding_id, []).append(v)

    updated_findings: list[Finding] = []

    for finding in findings:
        v_list = val_queue_by_id.get(finding.id)
        if not v_list:
            updated_findings.append(finding)
            continue

        v = v_list.pop(0)  # consume one validation result for this finding copy

        # Only blocking findings can be demoted
        if not finding.blocking:
            updated_findings.append(finding)
            continue

        # Condition 1: verdict is refuted and evidence_verified is true
        if v.verdict != "refuted" or not v.evidence_verified:
            updated_findings.append(finding)
            continue

        quote_trimmed = v.evidence.strip()

        # Condition 2: single line of 12 to 160 characters
        if "\n" in quote_trimmed or len(quote_trimmed) < 12 or len(quote_trimmed) > 160:
            updated_findings.append(finding)
            continue

        # Condition 3: finding kind is NOT security
        if finding.kind.strip().lower() == "security":
            updated_findings.append(finding)
            continue

        # Condition 4: cross-file provenance verified
        if not v.cross_part_verified:
            updated_findings.append(finding)
            continue

        # Condition 5: not a comment, docstring or string-literal line
        if _is_comment_or_docstring_line(v.evidence):
            updated_findings.append(finding)
            continue

        # Condition 6: does not match a secret pattern
        if _matches_secret_pattern(v.evidence):
            updated_findings.append(finding)
            continue

        # All 6 conditions passed -> demote
        quote_for_annotation = quote_trimmed[:160]
        suffix = f' [contested: validation refuted this finding - evidence: "{quote_for_annotation}"]'
        demoted = finding.model_copy(
            update={
                "blocking": False,
                "why_blocking": "",
                "description": finding.description + suffix,
            }
        )
        updated_findings.append(demoted)

    return updated_findings


def validate_findings(
    findings: list[Finding],
    full_diff: str,
    task_text: str,
    call: Callable[[str, str], str],
    *,
    max_validations: int = 5,
) -> tuple[list[Finding], list[Validation]]:
    """
    Validate at most max_validations blocking findings against full_diff using call.
    Returns (updated_findings, validations).
    Deterministic and fails safe.
    Clamps max_validations to max(0, n).
    """
    effective_max = max(0, max_validations)
    to_validate = select_for_validation(findings)[:effective_max]
    validations: list[Validation] = []

    for finding in to_validate:
        try:
            context = relevant_context(finding, full_diff)
            system_prompt, prompt_data = build_validation_prompt(finding, context, task_text)
            response = call(system_prompt, prompt_data)
            val = parse_validation(response, finding.id)
            if val is None:
                val = Validation(
                    finding_id=finding.id,
                    verdict="unsure",
                    evidence="",
                    evidence_verified=False,
                    cross_part_verified=False,
                    reason="Unparseable validation response",
                )
            elif val.evidence:
                verified, cross_part = _check_evidence_in_diff(val.evidence, finding, full_diff)
                val.evidence_verified = verified
                val.cross_part_verified = cross_part
            else:
                val.evidence_verified = False
                val.cross_part_verified = False
        except Exception as exc:
            val = Validation(
                finding_id=finding.id,
                verdict="unsure",
                evidence="",
                evidence_verified=False,
                cross_part_verified=False,
                reason=f"Validation call failed: {exc}",
            )

        validations.append(val)

    updated_findings = apply_validations(findings, validations)
    return updated_findings, validations
