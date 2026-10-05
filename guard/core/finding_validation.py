"""
Cross-part finding validation: validates blocking findings against the full diff.
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
# DiffLine: (line_type, content, raw_line, file_path, part_id, hunk_id)
# DiffHunk: (file_path, part_id, hunk_id, full_text, old_start, old_count, new_start, new_count)
_DiffLineTuple = tuple[str, str, str, str, int, int]
_DiffHunkTuple = tuple[str, int, int, str, int, int, int, int]


def _norm_path(path: str) -> str:
    p = path.replace("\\", "/").strip()
    if p.startswith("a/") or p.startswith("b/"):
        p = p[2:]
    return p.lower()


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


def _parse_diff(full_diff: str) -> tuple[list[_DiffLineTuple], list[_DiffHunkTuple]]:
    """Parse unified diff into lines and hunks with file, part, and line numbering."""
    diff_lines: list[_DiffLineTuple] = []
    diff_hunks: list[_DiffHunkTuple] = []

    current_part = 1
    current_file = ""
    current_hunk_id = 0
    in_hunk = False

    current_file_headers: list[str] = []
    current_hunk_header = ""
    current_hunk_lines: list[str] = []
    current_old_start = 0
    current_old_count = 0
    current_new_start = 0
    current_new_count = 0

    def _flush_hunk() -> None:
        nonlocal in_hunk, current_hunk_header, current_hunk_lines
        if current_hunk_header and current_file:
            full_text = "\n".join(current_file_headers) + "\n" + current_hunk_header + "\n" + "\n".join(current_hunk_lines)
            diff_hunks.append(
                (
                    current_file,
                    current_part,
                    current_hunk_id,
                    full_text.strip(),
                    current_old_start,
                    current_old_count,
                    current_new_start,
                    current_new_count,
                )
            )
        current_hunk_lines = []
        current_hunk_header = ""
        in_hunk = False

    for line in full_diff.splitlines():
        # Check if line is a part marker:
        is_part_marker = (
            line.strip() == "[continued: next part of this file's diff]"
            or bool(re.match(r"^(?:---\s*|===\s*)?diff\s+part\s+(\d+)\b", line.strip(), re.IGNORECASE))
        )

        # Inside a hunk: any line that is not a diff content marker (+, -, space, \)
        # or that is an unquoted part marker ends the hunk.
        if in_hunk:
            if not line or line[0] not in ("+", "-", " ", "\\") or (is_part_marker and not line.startswith("+")):
                _flush_hunk()

        # Outside hunks: check part boundaries
        if not in_hunk:
            if line.strip() == "[continued: next part of this file's diff]":
                current_part += 1
                continue
            part_m = re.match(r"^(?:---\s*|===\s*)?diff\s+part\s+(\d+)\b", line.strip(), re.IGNORECASE)
            if part_m:
                current_part = int(part_m.group(1))
                continue

        # Check diff --git header: ends any previous hunk/file
        git_m = re.match(r"^diff --git a/(.*?)\s+b/(.*)", line)
        if git_m:
            _flush_hunk()
            current_file = _norm_path(git_m.group(2))
            current_hunk_id = 0
            current_file_headers = [line]
            in_hunk = False
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

        # Check hunk header
        hunk_m = re.match(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@", line)
        if hunk_m:
            _flush_hunk()
            current_hunk_id += 1
            current_hunk_header = line
            current_old_start = int(hunk_m.group(1))
            current_old_count = int(hunk_m.group(2)) if hunk_m.group(2) else 1
            current_new_start = int(hunk_m.group(3))
            current_new_count = int(hunk_m.group(4)) if hunk_m.group(4) else 1
            in_hunk = True
            continue

        # Content lines inside hunks
        if in_hunk:
            if line.startswith("+"):
                diff_lines.append(("+", line[1:].strip(), line, current_file, current_part, current_hunk_id))
                current_hunk_lines.append(line)
            elif line.startswith("-"):
                diff_lines.append(("-", line[1:].strip(), line, current_file, current_part, current_hunk_id))
                current_hunk_lines.append(line)
            elif line.startswith(" "):
                diff_lines.append((" ", line[1:].strip(), line, current_file, current_part, current_hunk_id))
                current_hunk_lines.append(line)
            else:
                current_hunk_lines.append(line)
        else:
            if current_file:
                current_file_headers.append(line)

    _flush_hunk()
    return diff_lines, diff_hunks


def select_for_validation(findings: list[Finding]) -> list[Finding]:
    """Select blocking findings for validation in their original order."""
    return [f for f in findings if f.blocking]


def relevant_context(finding: Finding, full_diff: str, max_chars: int = 12000) -> str:
    """
    From the whole diff, take every hunk (from every file) that shares at least
    two distinctive identifiers with the finding's description or location file name,
    most overlapping first, trimmed to max_chars.
    If nothing matches, falls back to the finding's own file diff only.
    """
    _, diff_hunks = _parse_diff(full_diff)

    finding_file = _norm_path(finding.location.split(":", 1)[0]) if finding.location else ""
    query_text = f"{finding.description} {finding.location}"
    query_tokens = {
        tok.lower()
        for tok in re.findall(r"[a-zA-Z0-9_]{4,}", query_text)
        if tok.lower() not in STOP_WORDS
    }

    scored_hunks: list[tuple[int, int, str]] = []
    for idx, hunk in enumerate(diff_hunks):
        hunk_text = hunk[3]
        hunk_tokens = {
            tok.lower()
            for tok in re.findall(r"[a-zA-Z0-9_]{4,}", hunk_text)
            if tok.lower() not in STOP_WORDS
        }
        overlap = len(query_tokens.intersection(hunk_tokens))
        if overlap >= 2:
            scored_hunks.append((overlap, idx, hunk_text))

    # Sort descending by overlap, then ascending by original index (stable)
    scored_hunks.sort(key=lambda item: (-item[0], item[1]))

    if scored_hunks:
        selected_texts: list[str] = []
        current_len = 0
        for _, _, hunk_text in scored_hunks:
            text = hunk_text.strip()
            if not text:
                continue
            add_len = len(text) + (1 if selected_texts else 0)
            if current_len + add_len <= max_chars:
                selected_texts.append(text)
                current_len += add_len
            elif not selected_texts:
                selected_texts.append(text[:max_chars])
                break
            else:
                break
        return "\n\n".join(selected_texts)

    # Fallback to finding's own file diff only
    if finding_file:
        file_hunk_texts = [h[3].strip() for h in diff_hunks if h[0] == finding_file and h[3].strip()]
        if file_hunk_texts:
            return "\n\n".join(file_hunk_texts)[:max_chars]

        # Linear scan for file in raw diff if parser had no hunks
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
    """Parse validation LLM response into Validation dataclass."""
    if not text or not text.strip():
        return None

    verdict_m = re.search(r"(?im)^\s*VERDICT:\s*(confirmed|refuted|unsure)\b", text)
    if not verdict_m:
        return None
    verdict = verdict_m.group(1).lower()

    evidence_m = re.search(r"(?im)^\s*EVIDENCE:\s*(.*)$", text)
    evidence = ""
    if evidence_m:
        raw_evidence = evidence_m.group(1).strip()
        if raw_evidence.lower() not in ("none", "<none>", "none.", "n/a", "no evidence", '""', "''"):
            evidence = raw_evidence

    reason_m = re.search(r"(?im)^\s*REASON:\s*(.*)$", text)
    reason = reason_m.group(1).strip() if reason_m else ""

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
    Verify if evidence appears in full_diff as a whole line (+ or context, never -).
    Also checks Condition 4: whether it comes from a different part or file than the finding.
    Returns (verified, cross_part_verified).
    """
    if not evidence or not evidence.strip():
        return False, False

    ev_trimmed = evidence.strip()
    if "\n" in ev_trimmed:
        return False, False

    if ev_trimmed.startswith("+") and len(ev_trimmed) > 1 and (ev_trimmed[1].isspace() or ev_trimmed[1] not in "+"):
        ev_clean = ev_trimmed[1:].strip()
    else:
        ev_clean = ev_trimmed

    diff_lines, diff_hunks = _parse_diff(full_diff)
    if not diff_lines:
        return False, False

    # Parse finding location
    finding_file = _norm_path(finding.location.split(":", 1)[0]) if finding.location else ""
    if not finding_file:
        # Finding has no file location: cannot safely determine cross-part/cross-file context. Fail safe!
        has_any = any(
            (dl[1] == ev_clean or dl[1] == ev_trimmed or dl[2].strip() == ev_trimmed) and dl[0] in ("+", " ")
            for dl in diff_lines
        )
        return has_any, False

    finding_line: Optional[int] = None
    if finding.location and ":" in finding.location:
        line_m = re.search(r":(\d+)", finding.location)
        if line_m:
            finding_line = int(line_m.group(1))

    # Identify finding part (checking both old-side and new-side line ranges: start <= line < start + count)
    finding_part = 1
    for h_file, h_part, _, _, h_old_s, h_old_c, h_new_s, h_new_c in diff_hunks:
        if h_file == finding_file:
            if finding_line is not None:
                in_new = h_new_s <= finding_line < h_new_s + max(1, h_new_c)
                in_old = h_old_s <= finding_line < h_old_s + max(1, h_old_c)
                if in_new or in_old:
                    finding_part = h_part
                    break
            else:
                finding_part = h_part
                break

    has_valid_line = False
    cross_part_verified = False

    for dline_type, dline_content, dline_raw, dline_file, dline_part, _ in diff_lines:
        if dline_content == ev_clean or dline_content == ev_trimmed or dline_raw.strip() == ev_trimmed:
            if dline_type in ("+", " "):
                has_valid_line = True
                if dline_file != finding_file:
                    cross_part_verified = True
                else:
                    # Same file: must come from a DIFFERENT part in a multi-part diff
                    file_parts = {h[1] for h in diff_hunks if h[0] == finding_file}
                    if len(file_parts) > 1 and dline_part != finding_part:
                        cross_part_verified = True

    return has_valid_line, cross_part_verified


def apply_validations(
    findings: list[Finding],
    validations: list[Validation],
) -> list[Finding]:
    """
    Apply validations to findings. Only blocking findings can be demoted.
    A finding is demoted when ALL 6 conditions hold:
    1. verdict is 'refuted' and evidence_verified is true (+ or context line, never -);
    2. quote is 12 to 160 characters after trimming;
    3. finding kind is NOT 'security';
    4. quote comes from a different part or file than the finding (cross_part_verified);
    5. quote is not a comment, docstring, or string literal;
    6. quote does not match a secret pattern.
    Fails safe: on any error, doubt, or missing evidence, findings stay untouched.
    """
    val_map = {v.finding_id: v for v in validations}
    updated_findings: list[Finding] = []

    for finding in findings:
        if finding.id not in val_map:
            updated_findings.append(finding)
            continue

        v = val_map[finding.id]

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

        # Condition 4: different part of diff or different file
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
    """
    to_validate = select_for_validation(findings)[:max_validations]
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
