"""
Rule definitions, line rules, and syntax sinks for quality and security checks.
"""

from __future__ import annotations

import re
from typing import Optional

from pydantic import BaseModel

from guard.core.code_text import (
    CODE,
    CSS,
    JS,
    MARKUP,
    PY,
    YAML,
    _call_arguments,
    _is_dockerfile,
    _mask_strings,
)


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


def _unsafe_yaml_load(code: str) -> bool:
    """A yaml.load( call whose own arguments name no SafeLoader (as code, not inside a string)."""
    return any(not re.search(r"\bC?SafeLoader\b", _mask_strings(_call_arguments(code, m.end() - 1)))
               for m in re.finditer(r"\byaml\.load(?:_all)?\(", code))


SUPPRESS_COMMENT = re.compile(r"(?:#|//|/\*|<!--)\s*guard-allow\s+([A-Z]+-\d+)\s*:\s*(\S.*)")


# Line rules, checked on each added line of a matching file (never docs or tests): (rule, severity,
# which files, pattern, what to do instead). Each is narrow on purpose: a line that matches is
# nearly always the problem, and `guard-allow <RULE>: <reason>` on the line keeps it as a LOW note.
LINE_RULES = [
    ("SEC-004", "HIGH", lambda f: f.endswith(PY),
     re.compile(r"\byaml\.(?:unsafe_)?load(?:_all)?\(|\b(?:pickle|cPickle|dill|marshal)\.loads?\("),
     "Deserializing data this way can run code (yaml.load without SafeLoader, pickle/marshal): use "
     "yaml.safe_load or JSON for anything that is not your own trusted file."),
    ("SEC-005", "HIGH", lambda f: f.endswith(PY),
     re.compile(r"\bsubprocess\.\w+\(.*\bshell\s*=\s*True|\bos\.(?:system|popen)\(|(?<![\w.])(?<!def )(?:eval|exec)\("),
     "A string is run as a shell command or as code: pass subprocess an argument list without "
     "shell=True, and parse values instead of eval/exec."),
    ("SEC-005", "HIGH", lambda f: f.endswith(JS),
     re.compile(r"(?:(?<![\w.$])|(?<=\bwindow\.)|(?<=\bglobalThis\.)|(?<=\bself\.))eval\(|\bnew\s+Function\("),
     "eval / new Function runs a string as code: parse the value (JSON.parse) or call the function directly."),
    ("SEC-006", "HIGH", lambda f: f.endswith(CODE) or f.endswith(YAML) or _is_dockerfile(f),
     re.compile(r"(?i)\b(?:requests|httpx|session|client|urllib3?|aiohttp|http|ssl|get|post|put|patch|delete|request)\b.*\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false\b|InsecureSkipVerify\s*:\s*true\b|"
                r"NODE_TLS_REJECT_UNAUTHORIZED[\"']?(?:\s*[:=]\s*|\s+)[\"']?0\b|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)\b"),
     "TLS certificate checking is turned off, so any server can pretend to be this one: trust the right "
     "CA bundle instead."),
    ("SEC-007", "MEDIUM", lambda f: f.endswith(CODE) or f.endswith(YAML),
     re.compile(r"Access-Control-Allow-Origin[\"']?\s*[:,=]\s*[\"']\*[\"']|allow_origins\s*=\s*\[\s*[\"']\*[\"']|"
                r"\borigin\s*:\s*[\"']\*[\"']"),
     "CORS is open to every origin: list the origins that may call this API."),
    ("SEC-008", "MEDIUM", lambda f: f.endswith(JS),
     re.compile(r"(?i)localStorage(?:\.setItem\(\s*|\[\s*(?=[^\]]*\]\s*=(?!=))|\.(?=[\w$]+\s*=(?!=)))"
                r"[\"'`]?[^\"'`\]=]*(?:token|jwt|secret|passw(?:or)?d|api[_-]?key|\bsession(?:[_-]?(?:id|key))?\b)"),
     "A credential goes into localStorage, which every script on the page can read: prefer an HttpOnly cookie."),
    ("INFRA-001", "HIGH", lambda f: f.endswith(YAML),
     re.compile(r"^\s*(?:privileged|allowPrivilegeEscalation|hostNetwork|hostPID|hostIPC)\s*:\s*true\b"),
     "The container gets host-level privileges: drop them, or grant only the capability it needs."),
    ("INFRA-002", "MEDIUM", _is_dockerfile,
     re.compile(r"(?i)^FROM\s+(?:--platform=\S+\s+)?(?!scratch\b)(?:[\w.-]+:\d+/)?[^\s:@$]+(?::latest)?(?:\s+AS\s+\S+)?\s*$"),
     "The base image has no pinned tag or digest (or is :latest): builds change under you; pin a version."),
    ("INFRA-002", "MEDIUM", lambda f: f.endswith(YAML),
     re.compile(r"^\s*-?\s*image\s*:\s*[\"']?(?!/)(?![^\s\"']*\.(?:png|jpe?g|gif|svg|webp|avif|ico)\b)(?:[\w.-]+:\d+/)?[^\s:\"'@${}]+(?::latest)?[\"']?\s*$"),
     "The image has no pinned tag or digest (or is :latest): deployments change under you; pin a version."),
    ("INFRA-003", "MEDIUM", _is_dockerfile,
     re.compile(r"(?i)^USER\s+(?:root|0)(?::\S+)?\s*$"),
     "The container runs as root: add a user and switch to it."),
    ("MOB-001", "HIGH", lambda f: f.endswith("androidmanifest.xml") and "/debug/" not in f,
     re.compile(r"android:(?:debuggable|usesCleartextTraffic)\s*=\s*[\"']true[\"']"),
     "The app ships debuggable, or allows plain-HTTP traffic (usesCleartextTraffic): turn it off, or allow "
     "only the hosts that need it in a network security config."),
    ("UX-001", "LOW", lambda f: f.endswith(CSS) or f.endswith(MARKUP),
     re.compile(r"(?i)^(?!.*:not\(\s*:focus-visible\s*\)).*?\boutline\s*:\s*[\"']?(?:none|0)(?![\w.])"),
     "The keyboard focus ring is removed, so keyboard users cannot see where they are: style :focus-visible "
     "instead of removing the outline."),
    ("UX-002", "MEDIUM", lambda f: f.endswith(MARKUP),
     re.compile(r"(?i)<img\b(?=(?:(?!<img\b).)*>)(?!(?:(?!<img\b).)*(?:\balt\s*=|\[alt\]|\{alt\}))(?!(?:(?!<img\b).)*\{\s*\.\.\.)"),
     "An image has no alt text, so screen readers announce nothing useful: add alt (alt=\"\" for decoration)."),
    ("MOB-002", "MEDIUM", lambda f: f.endswith("androidmanifest.xml"),
     re.compile(r"android:allowBackup\s*=\s*[\"']true[\"']"),
     "App data goes into device backups (android:allowBackup): turn it off unless backups are intended."),
]


MAX_RULE_LINE = 2000
MAX_IMG_TAG = 2000
