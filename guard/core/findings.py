"""
Findings model, classification, and parsing from LLM review output.
"""

from __future__ import annotations

import re
from typing import List, Optional

from pydantic import BaseModel

SEVERITIES = ("critical", "high", "medium", "low")
KINDS = ("correctness", "security", "requirement", "maintainability", "style", "documentation", "other")
BLOCKING_KINDS = {"correctness", "security"}


def _norm(text: str) -> str:
    return " ".join(re.sub(r"[`'\"“”‘’]", "", text).lower().split())


def finding_id(kind: str, location: str, description: str) -> str:
    """Stable id of a finding across rounds: its kind, file and the start of its wording."""
    import hashlib
    file_part = location.split(":", 1)[0].strip().lower()
    return hashlib.sha1(f"{kind}|{file_part}|{_norm(description)[:60]}".encode("utf-8")).hexdigest()[:8]


class Finding(BaseModel):
    id: str
    severity: str
    kind: str
    location: str = ""
    requirement: str = ""  # a verbatim quote from the task, when the finding says the task asked for it
    description: str
    blocking: bool = False
    why_blocking: str = ""


def classify(finding: "Finding", task_text: str) -> "Finding":
    """
    The verdict rule, applied by guard and not by the model: a finding blocks when it is
    critical/high and about correctness or security, or when the requirement it quotes is really in
    the task. Everything else is advisory.
    """
    # Word for word (case and punctuation aside), at least two whole words: never a fragment of a word
    quote = " ".join(re.findall(r"\w+", finding.requirement.lower()))
    task = " ".join(re.findall(r"\w+", task_text.lower()))
    if finding.severity in ("critical", "high") and finding.kind in BLOCKING_KINDS:
        finding.blocking, finding.why_blocking = True, f"{finding.severity} {finding.kind}"
    elif len(quote.split()) >= 2 and f" {quote} " in f" {task} ":
        finding.blocking, finding.why_blocking = True, "violates a stated requirement"
    return finding


_NEXT_SECTION_RE = re.compile(
    r"(?:\r?\n)[ \t]*(?:\*{1,2}|#{1,6}[ \t]*)?(?:[A-Z]{3,}|(?i:threat[ \t]*model|unreviewed|technical|ergonomics|remediation|invariants|summary|score))[ \t]*(?::[ \t]*(?:\*{1,2})?|\*{1,2}:)",
)


def _is_finding_line(line: str) -> bool:
    """`severity | kind | ...` with a known severity and kind: the shape of a finding wherever it stands."""
    parts = [x.strip().lower() for x in line.strip().lstrip("-*•").split("|")]
    return len(parts) >= 5 and parts[0] in SEVERITIES and parts[1] in KINDS


def parse_findings(text: str, task_text: str) -> Optional[List[Finding]]:
    """
    `FINDINGS:` lines -> classified findings. None when the section is missing or any line is malformed
    (too few fields, an unknown severity or kind): a finding guard cannot read is never dropped or
    demoted into an approval.
    """
    findings_matches = list(re.finditer(r"(?m)^(?:\*{1,2}|#{1,6}[ \t]*)?FINDINGS(?:\s*:[ \t]*(?:\*{1,2})?|\*{1,2}[ \t]*:)", text))
    if len(findings_matches) != 1:
        return None
    start_pos = findings_matches[0].end()
    rest = text[start_pos:]
    end_match = _NEXT_SECTION_RE.search(rest)
    block = rest[:end_match.start()] if end_match else rest
    if end_match and any(_is_finding_line(line) for line in rest[end_match.start():].splitlines()):
        return None  # a line inside the block looked like a header: the block was cut, never drop what follows
    out: List[Finding] = []
    for line in block.splitlines():
        line = line.strip().lstrip("-*•").strip()
        if not line or line.lower() == "none":
            continue
        parts = [x.strip() for x in line.split("|")]
        if len(parts) < 5 or parts[0].lower() not in SEVERITIES or parts[1].lower() not in KINDS:
            return None
        severity, kind, location, requirement = parts[0].lower(), parts[1].lower(), parts[2], parts[3]
        description = " | ".join(parts[4:])
        requirement = "" if requirement in ("-", "none", "None", "") else requirement
        out.append(classify(Finding(
            id=finding_id(kind, location, description), severity=severity, kind=kind,
            location=location, requirement=requirement, description=description,
        ), task_text))
    return out


def _parse_invariant_proposals(text: str) -> List[dict]:
    """`INVARIANTS:` lines -> [{"id", "description", "checks"}]; malformed lines are dropped."""
    m = re.search(r"INVARIANTS:\s*(.+?)(?=\n[A-Z]+:|\Z)", text, re.DOTALL)
    if not m:
        return []
    out = []
    for line in m.group(1).strip().splitlines():
        line = re.sub(r"^[\s*\-\d.)]+", "", line).strip().strip("`")
        if not line or line.lower() == "none":
            continue
        parts = [x.strip().strip("`") for x in line.split(" | ")]
        if len(parts) == 2:
            out.append({"id": parts[0], "description": parts[1], "checks": []})
        elif len(parts) >= 5 and parts[3].lower() in ("forbid", "require"):
            # `\_` is a markdown escape; in a regex it means `_`, so dropping it keeps the meaning
            regex = " | ".join(parts[4:]).replace("\\_", "_")
            # Models often markdown-escape paths (`project\_invariants.py`); a glob never needs that
            files = re.sub(r"\\([_*\[\]])", r"\1", parts[2])
            out.append({"id": parts[0], "description": parts[1],
                        "checks": [{"files": files, parts[3].lower(): regex}]})
    return out


def _resolved_script(output: str) -> Optional[str]:
    """Script line echoed by pnpm/yarn (`$ tsc && vite build`) or npm (`> tsc && vite build`)."""
    for line in (output or "").splitlines():
        m = re.match(r"^\s*[$>]\s+(?!\S+@\S+\s)(\S.*)$", line)
        if m:
            return m.group(1).strip()
    return None
