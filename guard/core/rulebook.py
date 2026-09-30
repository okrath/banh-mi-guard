"""
The deterministic rulebook every guard post runs on the diff: secrets, SQL built from strings, HTML
sinks, global listeners, blocking I/O and deep property access.
"""

from __future__ import annotations

import re
from typing import List, Optional

from pydantic import BaseModel


class RuleViolation(BaseModel):
    rule_id: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    file_path: str
    line_number: Optional[int] = None
    message: str
    snippet: str = ""


def _unsafe_html_sinks(code: str) -> int:
    """
    Count innerHTML / outerHTML assignments on one line whose value is not provably safe.
    Safe values: an empty literal, or a value that is exactly one DOMPurify.sanitize(...) call.
    """
    code = re.sub(r"\s//.*$", "", code)  # drop trailing line comment
    unsafe = 0
    for m in re.finditer(r"\b(?:inner|outer)HTML\s*\+?=(?!=)", code):
        rhs = code[m.end():]
        # value runs until the first `;` that is not inside a string or parentheses
        depth, quote, end = 0, "", len(rhs)
        for k, ch in enumerate(rhs):
            if quote:
                if ch == quote and rhs[k - 1] != "\\":
                    quote = ""
            elif ch in "'\"`":
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == ";" and depth <= 0:
                end = k
                break
        value = rhs[:end].strip()
        if re.fullmatch(r"(['\"`])\1", value):
            continue
        call = re.match(r"DOMPurify\.sanitize\(", value)
        if call:
            # the call's own closing parenthesis, not one inside a string argument (`sanitize(")") + x`)
            depth, quote, closed = 0, "", None
            for k in range(call.end() - 1, len(value)):
                ch = value[k]
                if quote:
                    if ch == quote and value[k - 1] != "\\":
                        quote = ""
                elif ch in "'\"`":
                    quote = ch
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        closed = k
                        break
            # safe only when the sanitize call closes and nothing follows it
            if closed is None or value[closed + 1:].strip():
                unsafe += 1
            continue
        unsafe += 1
    return unsafe


class OCRRulebookRunner:
    """
    Multi-language deterministic static rules engine matching Alibaba OCR patterns.
    Operates at 0 cost, 0 latency across 5 Quality Pillars.
    """

    # Pillar: Security - Hardcoded Secrets
    SECRET_REGEX = re.compile(
        r"""(?i)(api[_-]?key|secret|token|password|auth[_-]?token|private[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-\.]{12,})["']"""
    )
    # Pillar: Security - SQL Injection string concatenation
    SQLI_REGEX = re.compile(
        r"""(?i)(select\b.+?\bfrom\b|insert\s+into\b|update\b.+?\bset\b|delete\s+from\b).+?["']\s*\+\s*[a-zA-Z_]"""
    )
    # Pillar: Security - Cross-Site Scripting (XSS)
    XSS_REGEX = re.compile(
        r"""(?i)(dangerouslySetInnerHTML\s*=|(?:inner|outer)HTML\s*\+?=(?!=)|\bv-html\s*=)"""
    )
    # Explicit, reviewable suppression: `// guard-allow SEC-003: <reason>` on the same line
    SUPPRESS_REGEX = re.compile(r"guard-allow\s+([A-Z]+-\d+)\s*:\s*(\S.*)")
    # Pillar: Memory Safety - Dangling Listener without remover in component
    DANGLING_LISTENER = re.compile(
        r"""addEventListener\s*\(["'](resize|scroll|mousemove|keydown)["']"""
    )
    # Pillar: Stability - Deep property dereference without optional chaining
    NULL_DEREF = re.compile(
        r"""(?i)(data|res|response|user|item)\.([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)"""
    )
    # Pillar: Performance - Blocking synchronous I/O on async event loop
    BLOCKING_SYNC_IO = re.compile(
        r"""\b(readFileSync|writeFileSync|execSync|spawnSync)\b"""
    )

    def scan_diff(self, raw_diff: Optional[str]) -> List[RuleViolation]:
        diff_text = raw_diff or ""
        violations: List[RuleViolation] = []
        current_file = "unknown"
        line_num = 0

        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()
                line_num = 0
                continue
            if line.startswith("@@"):
                match = re.search(r"\+(\d+)", line)
                if match:
                    line_num = int(match.group(1)) - 1
                continue

            if line.startswith("+") and not line.startswith("+++"):
                line_num += 1
                added_code = line[1:].strip()

                cf_lower = current_file.replace("\\", "/").lower()
                is_doc_file = any(cf_lower.endswith(ext) for ext in [".md", ".markdown", ".txt", ".rst"])
                is_test_file = "tests/" in cf_lower or "test_" in cf_lower
                is_js_ts = any(cf_lower.endswith(ext) for ext in [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"])

                # Rule 1: Hardcoded Secrets (Security - Always scanned on ALL files)
                if self.SECRET_REGEX.search(added_code):
                    # Exclude sample dummy tokens in test files or docs
                    if not (is_test_file and "sk_live_9988776655" in added_code):
                        violations.append(RuleViolation(
                            rule_id="SEC-001",
                            severity="CRITICAL",
                            file_path=current_file,
                            line_number=line_num,
                            message="Potential hardcoded secret or API key detected in code addition.",
                            snippet=added_code[:80],
                        ))

                # Rules 2-6 only apply to actual application source code (not doc markdown files)
                if is_doc_file:
                    continue

                # Rule 2: SQL Injection concatenation (Security)
                if self.SQLI_REGEX.search(added_code) and not is_test_file:
                    violations.append(RuleViolation(
                        rule_id="SEC-002",
                        severity="CRITICAL",
                        file_path=current_file,
                        line_number=line_num,
                        message="SQL string concatenation detected. Use parameterized queries/ORM.",
                        snippet=added_code[:80],
                    ))

                # Rule 3: Cross-Site Scripting (XSS) (Security)
                # A comment mentioning "sanitize" no longer exempts the line; only a provably safe
                # value or an explicit `guard-allow SEC-003: reason` marker does (reported as LOW).
                if self.XSS_REGEX.search(added_code) and not is_test_file and (
                    re.search(r"dangerouslySetInnerHTML|\bv-html", added_code, re.IGNORECASE)
                    or _unsafe_html_sinks(added_code) > 0
                ):
                    suppress = self.SUPPRESS_REGEX.search(added_code)
                    if suppress and suppress.group(1) == "SEC-003":
                        violations.append(RuleViolation(
                            rule_id="SEC-003",
                            severity="LOW",
                            file_path=current_file,
                            line_number=line_num,
                            message=f"innerHTML sink suppressed by author: {suppress.group(2).strip()[:120]}",
                            snippet=added_code[:80],
                        ))
                    else:
                        violations.append(RuleViolation(
                            rule_id="SEC-003",
                            severity="HIGH",
                            file_path=current_file,
                            line_number=line_num,
                            message="Raw HTML injection detected (dangerouslySetInnerHTML / innerHTML / v-html). Use textContent, DOMPurify.sanitize(), or mark `// guard-allow SEC-003: <reason>`.",
                            snippet=added_code[:80],
                        ))

                # Rule 4: Memory leak / Dangling Event Listener (Memory Safety)
                if self.DANGLING_LISTENER.search(added_code) and "removeEventListener" not in diff_text and not is_test_file:
                    violations.append(RuleViolation(
                        rule_id="PERF-001",
                        severity="HIGH",
                        file_path=current_file,
                        line_number=line_num,
                        message="Global window/document event listener added without cleanup remover.",
                        snippet=added_code[:80],
                    ))

                # Rule 5: Blocking Synchronous I/O on Event Loop (Performance - Only in JS/TS environments)
                if is_js_ts and self.BLOCKING_SYNC_IO.search(added_code) and not is_test_file:
                    violations.append(RuleViolation(
                        rule_id="PERF-002",
                        severity="MEDIUM",
                        file_path=current_file,
                        line_number=line_num,
                        message="Blocking synchronous I/O detected on thread. Prefer async/await non-blocking operations.",
                        snippet=added_code[:80],
                    ))

                # Rule 6: Deep property dereference without optional chaining (Stability)
                if self.NULL_DEREF.search(added_code) and "?." not in added_code and not is_test_file:
                    violations.append(RuleViolation(
                        rule_id="STAB-001",
                        severity="MEDIUM",
                        file_path=current_file,
                        line_number=line_num,
                        message="Deep object access without optional chaining (?.) may cause Null Pointer / TypeError.",
                        snippet=added_code[:80],
                    ))

        return violations
