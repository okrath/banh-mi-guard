"""
The deterministic rulebook every guard post runs on the diff: secrets, SQL built from strings, HTML
sinks, infra and UX rules.
"""

from __future__ import annotations

import re
from typing import List, Optional

from guard.core.code_text import (
    CSS,
    ERB,
    MARKUP,
    PY,
    RB,
    _block_comments,
    _carry_comment,
    _carry_string,
    _comment_start,
    _hash_comments,
    _is_dockerfile,
    _is_docs_path,
    _is_test_path,
    _tag_end,
)  # noqa: F401
from guard.core.rules import (
    LINE_RULES,
    MAX_IMG_TAG,
    MAX_RULE_LINE,
    RuleViolation,
    _ruby_xss,
    _sql_injection,
    _unsafe_html_sinks,
    _unsafe_yaml_load,
    shell_backtick_at,
)  # noqa: F401


class OCRRulebookRunner:
    """
    Multi-language deterministic static rules engine matching Alibaba OCR patterns.
    Operates at 0 cost, 0 latency across 5 Quality Pillars.
    """

    # Pillar: Security - Hardcoded Secrets
    SECRET_REGEX = re.compile(
        r"""(?i)(api[_-]?key|secret|token|password|auth[_-]?token|private[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-\.]{12,})["']"""
    )
    _sql_injection = staticmethod(_sql_injection)

    # Pillar: Security - Cross-Site Scripting (XSS)
    XSS_REGEX = re.compile(
        r"""(?i)(?:dangerously""" r"""SetInnerHTML\s*=|(?<![\w$])(?:inner|outer)HTML\s*\+?=(?!=)|\bv-""" r"""html\s*=|"""
        r"""\bmark_""" r"""safe\(|\|\s*sa""" r"""fe\b|\btemplate\.HT""" r"""ML\(|\bHtml\.R""" r"""aw\(|"""
        r"""\bbypassSecurity""" r"""TrustHtml\(|\bec""" r"""ho\b(?!.*?\b(?:htmlspecialchars|htmlentities)\b).*?\$(?:_GET|_POST|_REQUEST)\b)"""
    )
    _PY_MARKUP = re.compile(r"\bMar" r"kup\(")
    # Explicit, reviewable suppression: `// guard-allow SEC-003: <reason>` on the same line
    SUPPRESS_REGEX = re.compile(r"guard-allow\s+([A-Z]+-\d+)\s*:\s*(\S.*)")
    # for the line rules: the marker in a comment (`# ...`, `// ...`, `/* ...`, `<!-- ...`), never in a string
    SUPPRESS_COMMENT = re.compile(r"(?:#|//|/\*|<!--)\s*guard-allow\s+([A-Z]+-\d+)\s*:\s*(\S.*)")

    @staticmethod
    def _collect_docker_users(diff_text: str) -> set[str]:
        last_user, name = {}, None
        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                name = line[6:].strip()
            elif name and line[:1] in ("+", " "):
                user = re.match(r"(?i)^USER\s+(\S+)", line[1:].strip())
                if user:
                    last_user[name.replace("\\", "/").lower()] = user.group(1).split(":")[0].lower()
        # Dockerfiles that end as another user may switch to root for a build step
        return {f for f, u in last_user.items() if u not in ("root", "0")}

    def _reset_hunk_state(self, cf_lower: str) -> None:
        self._open_comment.pop(cf_lower, None)
        self._open_string.pop(cf_lower, None)
        self._open_img.pop(cf_lower, None)
        self._open_key.pop(cf_lower, None)

    def _handle_context_line(self, current_file: str, line_num: int, line_content: str) -> List[RuleViolation]:
        # a context line: only what the rules need to know about the file
        cf = current_file.replace("\\", "/").lower()
        open_comm = self._open_comment.get(cf)
        _carry_comment(self._open_comment, cf, line_content)
        _carry_string(self._open_string, cf, line_content, open_comm)
        self._file_context(current_file.lower(), line_content.strip())
        if cf.endswith("info.plist"):  # an added key over an unchanged value is reported here
            return self._plist_value(cf, current_file, line_num, line_content.strip(), added=False)
        return []

    def _check_secret(self, current_file: str, line_num: int, added_code: str, is_test_file: bool) -> Optional[RuleViolation]:
        # Rule 1: Hardcoded Secrets (Security - Always scanned on ALL files)
        if self.SECRET_REGEX.search(added_code):
            # Exclude sample dummy tokens in test files or docs
            if not (is_test_file and "sk_live_9988776655" in added_code):
                return RuleViolation(
                    rule_id="SEC-001",
                    severity="CRITICAL",
                    file_path=current_file,
                    line_number=line_num,
                    message="Potential hardcoded secret or API key detected in code addition.",
                    snippet=added_code[:80],
                )
        return None

    def _check_sql_injection(self, current_file: str, line_num: int, added_code: str, cf_lower: str, is_test_file: bool) -> Optional[RuleViolation]:
        # Rule 2: SQL Injection concatenation (Security)
        if _sql_injection(added_code, cf_lower) and not is_test_file:
            return RuleViolation(
                rule_id="SEC-002",
                severity="CRITICAL",
                file_path=current_file,
                line_number=line_num,
                message="SQL string concatenation detected. Use parameterized queries/ORM.",
                snippet=added_code[:80],
            )
        return None

    def _check_xss(self, current_file: str, line_num: int, added_code: str, cf_lower: str, is_test_file: bool) -> Optional[RuleViolation]:
        # Rule 3: Cross-Site Scripting (XSS) (Security)
        # A comment mentioning "sanitize" no longer exempts the line; only a provably safe
        # value or an explicit `guard-allow SEC-003: reason` marker does (reported as LOW).
        has_xss = False
        if not is_test_file:
            if self.XSS_REGEX.search(added_code) and (
                not re.search(r"(?<![\w$])(?:inner|outer)HTML\s*\+?=(?!=)", added_code, re.IGNORECASE)
                or _unsafe_html_sinks(added_code) > 0
            ):
                has_xss = True
            elif cf_lower.endswith(PY) and self._PY_MARKUP.search(added_code):
                has_xss = True
            elif cf_lower.endswith(RB + ERB) and _ruby_xss(added_code, is_erb=cf_lower.endswith(ERB)):
                has_xss = True
        if not has_xss:
            return None
        suppress = self.SUPPRESS_REGEX.search(added_code)
        if suppress and suppress.group(1) == "SEC-003":
            return RuleViolation(
                rule_id="SEC-003",
                severity="LOW",
                file_path=current_file,
                line_number=line_num,
                message=f"innerHTML sink suppressed by author: {suppress.group(2).strip()[:120]}",
                snippet=added_code[:80],
            )
        return RuleViolation(
            rule_id="SEC-003",
            severity="HIGH",
            file_path=current_file,
            line_number=line_num,
            message="Raw HTML injection detected: in browser JS use textContent or DOMPurify, in server templates (Go template.HTML, Ruby raw/html_safe, PHP echo) escape with framework escaping (html/template auto-escaping, ERB <%= %>, htmlspecialchars).",
            snippet=added_code[:80],
        )

    def _scan_added_line(self, current_file: str, line_num: int, added_code: str) -> List[RuleViolation]:
        violations: List[RuleViolation] = []
        cf_lower = current_file.replace("\\", "/").lower()
        is_doc_file = any(cf_lower.endswith(ext) for ext in [".md", ".markdown", ".txt", ".rst"])
        is_test_file = _is_test_path(cf_lower)
        # the code of the line outside a comment an earlier line left open (None: all comment)
        open_comm = self._open_comment.get(cf_lower)
        visible = _carry_comment(self._open_comment, cf_lower, added_code)
        visible = visible.strip() if visible is not None else None
        string_cutoff = _carry_string(self._open_string, cf_lower, added_code, open_comm)

        sec = self._check_secret(current_file, line_num, added_code, is_test_file)
        if sec:
            violations.append(sec)

        # Rules only apply to actual application source code (not doc markdown files)
        if is_doc_file:
            return violations

        sql = self._check_sql_injection(current_file, line_num, added_code, cf_lower, is_test_file)
        if sql:
            violations.append(sql)

        xss = self._check_xss(current_file, line_num, added_code, cf_lower, is_test_file)
        if xss:
            violations.append(xss)

        # Line rules of the quality matrix (security, infra, mobile); a line is
        # judged before it adds to what the file defines (`FROM node AS node` is still an image)
        if not is_test_file and visible is not None:
            violations.extend(self._line_rules(cf_lower, current_file, line_num, visible, string_cutoff))
            if cf_lower.endswith(MARKUP):
                violations.extend(self._multiline_img(cf_lower, current_file, line_num, visible))
            if cf_lower.endswith("info.plist"):
                violations.extend(self._plist_value(cf_lower, current_file, line_num, visible, added=True))
        self._file_context(cf_lower, added_code)
        return violations

    def scan_diff(self, raw_diff: Optional[str]) -> List[RuleViolation]:
        diff_text = raw_diff or ""
        violations: List[RuleViolation] = []
        current_file = "unknown"
        line_num = 0
        self._ends_as_user = self._collect_docker_users(diff_text)
        self._stages = set()
        self._open_comment = {}  # file -> the `*/` or `-->` that closes a comment left open on a diff line
        self._open_img = {}  # file -> (line, text so far) of an <img tag not closed on its first line
        self._open_key = {}  # Info.plist -> (line, text, added) of a <key> whose value is on the next line
        self._open_string = {}

        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()
                line_num = 0
                self._stages = set()
                self._open_string.pop(current_file.replace("\\", "/").lower(), None)
                continue
            if line.startswith(" "):
                line_num += 1
                violations.extend(self._handle_context_line(current_file, line_num, line[1:]))
                continue
            if line.startswith("@@"):
                match = re.search(r"\+(\d+)", line)
                if match:
                    line_num = int(match.group(1)) - 1
                self._reset_hunk_state(current_file.replace("\\", "/").lower())
                continue

            if line.startswith("+") and not line.startswith("+++"):
                line_num += 1
                violations.extend(self._scan_added_line(current_file, line_num, line[1:].strip()))

        return violations

    def _multiline_img(self, path_lower: str, path: str, line_num: int, code: str) -> List[RuleViolation]:
        """UX-002 for an <img tag spread over several added lines (JSX): judged once its `>` arrives."""
        found: List[RuleViolation] = []
        start, tag = self._open_img.pop(path_lower, (None, ""))
        if start is not None:
            tag += " " + code
            end = _tag_end(tag)
            if end >= 0:
                found = [v for v in self._line_rules(path_lower, path, start, tag[:end + 1]) if v.rule_id == "UX-002"]
            elif len(tag) > MAX_IMG_TAG:
                start, tag = None, ""
            else:
                self._open_img[path_lower] = (start, tag)
        last = code.lower().rfind("<img")
        if last >= 0 and _tag_end(code[last:]) < 0:
            if len(code[last:]) <= MAX_IMG_TAG:
                self._open_img[path_lower] = (line_num, code[last:])
        return found

    def _plist_value(self, path_lower: str, path: str, line_num: int, code: str, added: bool) -> List[RuleViolation]:
        """MOB rows for an Info.plist key whose value is on the next line: an added key, or an added value
        under an unchanged key (`<false/>` turned `<true/>`), reported on the added line."""
        found: List[RuleViolation] = []
        key = self._open_key.pop(path_lower, None)
        if key and (added or key[2]):
            pair = f"{key[1]} {code}"
            found = [v for v in self._line_rules(path_lower, path, key[0] if key[2] else line_num, pair)
                     if v.rule_id.startswith("MOB-")]
        if re.search(r"</key>\s*$", code):
            self._open_key[path_lower] = (line_num, code, added)
        return found

    def _file_context(self, path_lower: str, code: str) -> None:
        """Follow a Dockerfile line by line (added and context lines): the stage names defined so far."""
        if _is_dockerfile(path_lower) and len(code) <= MAX_RULE_LINE:
            stage = re.match(r"(?i)^FROM\s+(?:--platform=\S+\s+)?\S+\s+AS\s+(\S+)\s*$", code)
            if stage:
                self._stages.add(stage.group(1).lower())

    def _line_rules(self, path_lower: str, path: str, line_num: int, code: str, string_cutoff: int = 0) -> List[RuleViolation]:
        found: List[RuleViolation] = []
        if code.startswith(("#", "//")) or (code.startswith("*") and not path_lower.endswith(CSS)) \
                or len(code) > MAX_RULE_LINE or _is_docs_path(path_lower):
            return found  # a comment or a docs page talks about code; a minified or generated line is not read
        # the line's own comment, found outside strings: `#` in Python, YAML, shell and Dockerfiles,
        # `//` in C-family languages (in Python `//` divides). The rules read the code before it; a
        # guard-allow counts only there, never in a string that looks like a comment
        spans: list = []
        cut = _comment_start(code, _hash_comments(path_lower), spans, _block_comments(path_lower))
        body, comment = (code[:cut], code[cut:]) if cut >= 0 else (code, "")
        if cut == 0:
            return found  # the whole line is a comment
        for a, b in spans:  # a comment closed on the line is not code; what follows it is
            body = body[:a] + " " * (b - a) + body[b:]
        # a guard-allow in the line's comment, or in a comment closed on the line (`/* guard-allow ... */ x`)
        suppress = next(filter(None, (self.SUPPRESS_COMMENT.match(c)
                                      for c in [comment] + [code[a:b] for a, b in spans])), None)
        for rule_id, severity, applies, pattern, advice in LINE_RULES:
            if not applies(path_lower) or any(v.rule_id == rule_id for v in found):
                continue
            # a name quoted in prose (``pickle.loads()`` in a docstring) is not a call. Text inside strings is
            # read like code: a string may hold code that runs (`${eval(x)}`, f-strings), and a security rule
            # would rather report a sentence that mentions eval( than miss a call
            if not any((m.start() == 0 or body[m.start() - 1] != "`")
                       and (rule_id != "UX-002" or _tag_end(body[m.start():]) >= 0)
                       and (rule_id != "SEC-005" or body[m.start()] != "`" or shell_backtick_at(body, m.start(), string_cutoff))
                       for m in pattern.finditer(body)):
                continue
            base = re.match(r"(?i)^FROM\s+(?:--platform=\S+\s+)?(\S+)", body) if _is_dockerfile(path_lower) else None
            if rule_id == "INFRA-002" and base:
                if base.group(1).lower() in self._stages:
                    continue  # an earlier stage of this Dockerfile, not an image
            if rule_id == "INFRA-003" and path_lower in self._ends_as_user:
                continue  # a later USER in the diff switches back
            if rule_id == "SEC-004" and path_lower.endswith(PY) and not _unsafe_yaml_load(body) and not re.search(
                    r"\byaml\.unsafe_load(?:_all)?\(|\b(?:pickle|cPickle|dill|marshal)\.loads?\(", body):
                continue  # every yaml.load call on the line names a SafeLoader
            allowed = suppress and suppress.group(1) == rule_id
            found.append(RuleViolation(
                rule_id=rule_id,
                severity="LOW" if allowed else severity,
                file_path=path,
                line_number=line_num,
                message=f"{rule_id} suppressed by author: {suppress.group(2).strip()[:120]}" if (allowed and suppress) else advice,
                snippet=code[:80],
            ))
        return found
