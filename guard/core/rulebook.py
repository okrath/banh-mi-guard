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


PY = (".py",)
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte")
CODE = PY + JS + (".go", ".rb", ".php", ".java", ".kt", ".cs", ".rs", ".swift", ".dart")
YAML = (".yaml", ".yml")
CSS = (".css", ".scss", ".sass", ".less")
MARKUP = (".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte")


def _is_test_path(path: str) -> bool:
    """A test file: in a tests/, test/ or __tests__/ folder, or named test_*, *_test.*, *.test.* or *.spec.*."""
    parts = path.split("/")
    name = parts[-1]
    return any(p in ("tests", "test", "__tests__") for p in parts[:-1]) or name.startswith("test_") or \
        bool(re.search(r"(?:_test|\.test|\.spec)\.[a-z0-9]+$", name))


def _scan(code: str, start: int = 0):
    """(index, character, in_string) for each character from `start`, following ' " ` strings and escapes."""
    quote, escaped = "", False
    for k in range(start, len(code)):
        ch = code[k]
        if quote:
            yield k, ch, True
            if ch == quote and not escaped:
                quote = ""
            escaped = ch == "\\" and not escaped
        elif ch in "'\"`":
            quote = ch
            yield k, ch, True
        else:
            yield k, ch, False


def _call_arguments(code: str, open_paren: int) -> str:
    """The text between a call's parenthesis at `open_paren` and the one that closes it (strings skipped)."""
    depth = 0
    for k, ch, in_string in _scan(code, open_paren):
        if in_string:
            continue
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0:
            return code[open_paren + 1:k]
    return code[open_paren + 1:]  # not closed on this line: the rest of it


def _comment_start(code: str, hash_comments: bool, spans: Optional[list] = None, blocks: tuple = ()) -> int:
    """
    Where the line's comment begins, outside any string (`#` or `//` by language, or a block comment
    not closed on the line); -1 for none. A block comment closed on the line (`/* note */ run(x)`) is not the
    end of the code: the scan goes on after it, and its (start, end) goes into `spans` when given.
    """
    closed_until = 0
    for k, ch, in_string in _scan(code):
        if in_string or k < closed_until:
            continue
        for opening, closing in blocks:
            if code.startswith(opening, k):
                end = code.find(closing, k + len(opening))
                if end < 0:
                    return k
                closed_until = end + len(closing)
                if spans is not None:
                    spans.append((k, closed_until))
        if k < closed_until:
            continue
        if (hash_comments and ch == "#") or (not hash_comments and code.startswith("//", k)):
            return k
    return -1


def _hash_comments(path_lower: str) -> bool:
    """`#` starts a comment in Python, YAML, shell and Dockerfiles; elsewhere `//` does (in Python `//` divides)."""
    return path_lower.endswith(PY + YAML + (".sh", ".rb", ".toml")) or _is_dockerfile(path_lower)


def _block_comments(path_lower: str) -> tuple:
    """Block comment pairs (opening, closing) allowed in the file type."""
    if _hash_comments(path_lower):
        return ()
    if path_lower.endswith((".html", ".htm", ".xml", ".svg")):
        return (("<!--", "-->"),)
    if path_lower.endswith((".jsx", ".tsx", ".vue", ".svelte")):
        return (("/*", "*/"), ("<!--", "-->"))
    if path_lower.endswith(CODE) or path_lower.endswith(CSS):
        return (("/*", "*/"),)
    return ()

def _carry_comment(open_comments: dict, path_lower: str, code: str) -> Optional[str]:
    """
    The line without the part inside a block comment an earlier line left open (None when all of it
    is), noting in `open_comments` whether this line leaves one open for the next.
    """
    blocks = _block_comments(path_lower)
    closing = open_comments.pop(path_lower, None)
    if closing:
        end = code.find(closing)
        if end < 0:
            open_comments[path_lower] = closing
            return None
        code = code[end + len(closing):]
    cut = _comment_start(code, _hash_comments(path_lower), blocks=blocks)
    for opening, closer in blocks:
        if cut >= 0 and code.startswith(opening, cut):
            open_comments[path_lower] = closer
    return code


def _tag_end(tag: str) -> int:
    """Where a tag closes: its first `>` outside `{...}` and quotes that is not part of `=>`; -1 when it goes on."""
    depth, quote = 0, ""
    for k, ch in enumerate(tag):
        if quote:
            if ch == quote and tag[k - 1:k] != "\\":
                quote = ""
            continue
        if depth <= 0 and ch in "'\"":
            quote = ch
            continue
        depth += (ch == "{") - (ch == "}")
        if ch == ">" and depth <= 0 and tag[k - 1:k] != "=":
            return k
    return -1


def _mask_strings(code: str) -> str:
    """The line with the inside of every string blanked, except `${...}` in template strings: what remains is code."""
    chars, quote, depth, inner, escaped = list(code), "", 0, "", False
    for k, ch, in_string in _scan(code):
        if not in_string:
            quote, depth, inner, escaped = "", 0, "", False
            continue
        if not quote:
            quote = ch
        if quote == "`" and code.startswith("${", k) and not depth:
            depth = 1
            continue
        if depth:
            if inner:
                if ch == inner and not escaped:
                    inner = ""
                else:
                    chars[k] = " "
                escaped = ch == "\\" and not escaped
            elif ch in "'\"":
                inner, escaped = ch, False
            elif ch == "{" and code[k - 1] != "$":
                depth += 1
            elif ch == "}":
                depth -= 1
            continue
        if ch not in "'\"`":
            chars[k] = " "
    return "".join(chars)


def _is_docs_path(path: str) -> bool:
    """A documentation page or example: in a docs/ or doc/ folder."""
    return any(p in ("docs", "doc") for p in path.split("/")[:-1])


def _unsafe_yaml_load(code: str) -> bool:
    """A yaml.load( call whose own arguments name no SafeLoader (as code, not inside a string)."""
    return any(not re.search(r"\bC?SafeLoader\b", _mask_strings(_call_arguments(code, m.end() - 1)))
               for m in re.finditer(r"\byaml\.load(?:_all)?\(", code))


def _is_dockerfile(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")


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


MAX_RULE_LINE = 2000  # longer lines are minified or generated: the line rules skip them
MAX_IMG_TAG = 2000  # an <img tag still open after this much text is dropped, not rescanned line by line
# A Kubernetes workload whose `kind:` line is added here: the change brings the whole manifest
WORKLOAD_KIND = re.compile(r"^\s*kind\s*:\s*(Deployment|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob|Pod)\s*$")
LONG_RUNNING = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}


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
    # for the line rules: the marker in a comment (`# ...`, `// ...`, `/* ...`, `<!-- ...`), never in a string
    SUPPRESS_COMMENT = re.compile(r"(?:#|//|/\*|<!--)\s*guard-allow\s+([A-Z]+-\d+)\s*:\s*(\S.*)")
    # Pillar: Memory Safety - Dangling Listener without remover in component
    DANGLING_LISTENER = re.compile(
        r"""addEventListener\s*\(["'](resize|scroll|mousemove|keydown)["']"""
    )
    # Pillar: Stability - Deep property dereference without optional chaining
    NULL_DEREF = re.compile(
        r"""(?i)(data|res|response|user|item)\.([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)"""
    )
    # Pillar: Memory Safety - An interval that keeps running (and holding what it closes over)
    DANGLING_INTERVAL = re.compile(r"\bsetInterval\s*\(")
    # Pillar: Performance - Blocking synchronous I/O on async event loop
    BLOCKING_SYNC_IO = re.compile(
        r"""\b(readFileSync|writeFileSync|execSync|spawnSync)\b"""
    )

    def scan_diff(self, raw_diff: Optional[str]) -> List[RuleViolation]:
        diff_text = raw_diff or ""
        violations: List[RuleViolation] = []
        current_file = "unknown"
        line_num = 0
        # per file, from its added and context lines: whether it clears an interval anywhere
        cleared, name, last_user, open_comments = set(), None, {}, {}
        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                name = line[6:].strip()
            elif name and line.startswith("@@"):
                open_comments.pop(name.replace("\\", "/").lower(), None)  # lines between hunks are unseen
            elif name and line[:1] in ("+", " "):
                code = line[1:]
                visible = _carry_comment(open_comments, name.replace("\\", "/").lower(), code)
                if len(line) > MAX_RULE_LINE:
                    continue
                spans: list = []
                p_lower = name.replace("\\", "/").lower()
                cut = _comment_start(visible or "", _hash_comments(p_lower), spans, _block_comments(p_lower))
                body = (visible or "")[:cut] if cut >= 0 else (visible or "")
                for a, b in spans:
                    body = body[:a] + " " * (b - a) + body[b:]
                if visible and re.search(r"\bclearInterval\s*\(", _mask_strings(body)):
                    cleared.add(name)  # a real call, not the word in a string or a comment
                user = re.match(r"(?i)^USER\s+(\S+)", code.strip())
                if user:
                    last_user[name.replace("\\", "/").lower()] = user.group(1).split(":")[0].lower()
        # Dockerfiles that end as another user may switch to root for a build step
        self._ends_as_user = {f for f, u in last_user.items() if u not in ("root", "0")}
        self._stages = set()
        self._open_comment = {}  # file -> the `*/` or `-->` that closes a comment left open on a diff line
        self._open_img = {}  # file -> (line, text so far) of an <img tag not closed on its first line

        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()
                line_num = 0
                self._stages = set()
                continue
            if line.startswith(" "):  # a context line: only what the rules need to know about the file
                line_num += 1
                _carry_comment(self._open_comment, current_file.replace("\\", "/").lower(), line[1:])
                self._file_context(current_file.lower(), line[1:].strip())
                continue
            if line.startswith("@@"):
                match = re.search(r"\+(\d+)", line)
                if match:
                    line_num = int(match.group(1)) - 1
                self._open_comment.pop(current_file.replace("\\", "/").lower(), None)
                self._open_img.pop(current_file.replace("\\", "/").lower(), None)
                continue

            if line.startswith("+") and not line.startswith("+++"):
                line_num += 1
                added_code = line[1:].strip()

                cf_lower = current_file.replace("\\", "/").lower()
                is_doc_file = any(cf_lower.endswith(ext) for ext in [".md", ".markdown", ".txt", ".rst"])
                is_test_file = _is_test_path(cf_lower)
                is_js_ts = any(cf_lower.endswith(ext) for ext in [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"])
                # the code of the line outside a comment an earlier line left open (None: all comment)
                visible = _carry_comment(self._open_comment, cf_lower, added_code)
                visible = visible.strip() if visible is not None else None

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

                # Rule 4b: an interval started with no clearInterval anywhere in the change (Memory Safety)
                spans = []
                cut = _comment_start(visible or "", _hash_comments(cf_lower), spans, _block_comments(cf_lower))
                interval_code = (visible or "")[:cut] if cut >= 0 else (visible or "")
                for a, b in spans:
                    interval_code = interval_code[:a] + " " * (b - a) + interval_code[b:]
                interval_code = _mask_strings(interval_code)
                if cf_lower.endswith(JS) and self.DANGLING_INTERVAL.search(interval_code) and current_file not in cleared \
                        and not is_test_file and not _is_docs_path(cf_lower) and len(added_code) <= MAX_RULE_LINE:
                    violations.append(RuleViolation(
                        rule_id="PERF-003",
                        severity="MEDIUM",
                        file_path=current_file,
                        line_number=line_num,
                        message="setInterval started with no clearInterval in the same file: it keeps running, and "
                                "keeps what it uses alive, after its component or page is gone.",
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

                # Rules 7+: the line rules of the quality matrix (security, infra, mobile); a line is
                # judged before it adds to what the file defines (`FROM node AS node` is still an image)
                if not is_test_file and visible is not None:
                    violations.extend(self._line_rules(cf_lower, current_file, line_num, visible))
                    if cf_lower.endswith(MARKUP):
                        violations.extend(self._multiline_img(cf_lower, current_file, line_num, visible))
                self._file_context(cf_lower, added_code)

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

        violations.extend(self._workload_rules(diff_text))
        return violations

    def _workload_rules(self, diff_text: str) -> List[RuleViolation]:
        """
        A Kubernetes workload added by this change (its `kind:` line is added) with containers but no
        resource limits (INFRA-004), or, when it runs for good, no liveness or readiness probe (INFRA-005).
        Each YAML document (`---`) is judged on its own lines; a limit outside the lines of an edited one
        cannot be seen, so only workloads whose `kind:` line is added are judged.
        """
        found: List[RuleViolation] = []
        docs: List[dict] = []
        name, line_num = None, 0

        def new_doc():
            docs.append({"file": name, "kinds": set(), "at": None, "lines": [], "allow": {}})

        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                name, line_num = line[6:].strip(), 0
                new_doc()
            elif line.startswith("@@"):
                m = re.search(r"\+(\d+)", line)
                line_num = int(m.group(1)) - 1 if m else 0
            elif name and name.lower().endswith(YAML) and line[:1] in ("+", " ") and not line.startswith("+++"):
                line_num += 1
                code = line[1:]
                if code.strip() == "---":
                    new_doc()
                    continue
                doc = docs[-1]
                doc["lines"].append(code)
                containers = re.match(r"^\s*containers\s*:", code)
                if containers and doc["at"] is None:
                    doc["at"] = line_num
                if line.startswith("+"):
                    kind = WORKLOAD_KIND.match(code)
                    if kind:
                        doc["kinds"].add(kind.group(1))
                    if kind or containers:
                        p_lower = name.replace("\\", "/").lower()
                        cut = _comment_start(code, _hash_comments(p_lower), blocks=_block_comments(p_lower))
                        allow = self.SUPPRESS_COMMENT.match(code[cut:]) if cut >= 0 else None
                        if allow:
                            doc["allow"][allow.group(1)] = allow.group(2).strip()[:120]
        for doc in docs:
            f = doc["file"]
            path = f.replace("\\", "/").lower()
            if not doc["kinds"] or doc["at"] is None or _is_test_path(path) or _is_docs_path(path):
                continue
            text = "\n".join(doc["lines"])
            if "{{" in text:
                continue  # a template (Helm): its values decide the limits and probes
            missing = []  # `limits:` / `livenessProbe:` in block or flow style (`resources: {limits: ...}`)
            if not re.search(r"(?:^|[\s{,])limits\s*:", text, re.M):
                missing.append(("INFRA-004", "MEDIUM", "Containers without resources.limits: one of them can take "
                                "the node's memory and CPU, and it gets killed at random. Set requests and limits."))
            if doc["kinds"] & LONG_RUNNING and not re.search(r"(?:^|[\s{,])(?:liveness|readiness)Probe\s*:", text, re.M):
                missing.append(("INFRA-005", "LOW", "A long-running workload without a liveness or readiness probe: "
                                "traffic reaches pods that are not ready, and a hung one is never restarted."))
            for rule_id, severity, advice in missing:
                reason = doc["allow"].get(rule_id)
                found.append(RuleViolation(
                    rule_id=rule_id, severity="LOW" if reason else severity, file_path=f, line_number=doc["at"],
                    message=f"{rule_id} suppressed by author: {reason}" if reason else advice,
                    snippet="containers:",
                ))
        return found

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

    def _file_context(self, path_lower: str, code: str) -> None:
        """Follow a Dockerfile line by line (added and context lines): the stage names defined so far."""
        if _is_dockerfile(path_lower) and len(code) <= MAX_RULE_LINE:
            stage = re.match(r"(?i)^FROM\s+(?:--platform=\S+\s+)?\S+\s+AS\s+(\S+)\s*$", code)
            if stage:
                self._stages.add(stage.group(1).lower())

    def _line_rules(self, path_lower: str, path: str, line_num: int, code: str) -> List[RuleViolation]:
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
                       for m in pattern.finditer(body)):
                continue
            base = re.match(r"(?i)^FROM\s+(?:--platform=\S+\s+)?(\S+)", body) if _is_dockerfile(path_lower) else None
            if rule_id == "INFRA-002" and base:
                if base.group(1).lower() in self._stages:
                    continue  # an earlier stage of this Dockerfile, not an image
            if rule_id == "INFRA-003" and path_lower in self._ends_as_user:
                continue  # a later USER in the diff switches back
            if rule_id == "SEC-004" and not _unsafe_yaml_load(body) and not re.search(
                    r"\byaml\.unsafe_load(?:_all)?\(|\b(?:pickle|cPickle|dill|marshal)\.loads?\(", body):
                continue  # every yaml.load call on the line names a SafeLoader
            allowed = suppress and suppress.group(1) == rule_id
            found.append(RuleViolation(
                rule_id=rule_id,
                severity="LOW" if allowed else severity,
                file_path=path,
                line_number=line_num,
                message=f"{rule_id} suppressed by author: {suppress.group(2).strip()[:120]}" if allowed else advice,
                snippet=code[:80],
            ))
        return found
