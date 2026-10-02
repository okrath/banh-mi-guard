"""
Rule definitions, line rules, and syntax sinks for quality and security checks.
"""

from __future__ import annotations

import re
from typing import Optional

from pydantic import BaseModel

from guard.core.code_text import (
    CODE,
    CS,
    CSS,
    DART,
    GO,
    JAVA,
    JS,
    KT,
    MARKUP,
    PHP,
    PY,
    RB,
    RS,
    SWIFT,
    YAML,
    _call_arguments,
    _is_dockerfile,
    _mask_strings,
    _scan,
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


_SQL_KW = re.compile(
    r"(?i)(?:"
    r"sel" r"ect\s+(?:distinct\s+)?(?!(?:an|a|the|your)\s+[a-zA-Z]+\s+from\b).+?\s+from\s+(?!the\s)[a-zA-Z0-9_\"`\[\].*]+"
    r"|^\s*sel" r"ect\s+(?:distinct\s+)?(?!(?:an|a|the|your)\s+[a-zA-Z]+\s+from\b).+?\s+from\s*$"
    r"|del" r"ete\s+from\s+(?!the\s)[a-zA-Z0-9_\"`\[\].*]+"
    r"|^\s*del" r"ete\s+from\s*$"
    r"|upd" r"ate\s+[a-zA-Z0-9_\"`\[\].]+\s+set\s+[a-zA-Z0-9_\"`\[\].]+\s*="
    r"|^\s*upd" r"ate\s+[a-zA-Z0-9_\"`\[\].]+\s+set\s*$"
    r"|^\s*upd" r"ate\s*$"
    r"|ins" r"ert\s+into\s+(?!the\s)[a-zA-Z0-9_\"`\[\].]+"
    r"|^\s*ins" r"ert\s+into\s*$"
    r")"
)
_UPDATE_ONLY = re.compile(r"^\s*upd" r"ate\s*$", re.IGNORECASE)
_SET_KW = re.compile(r"\bset\b", re.IGNORECASE)
_SELECT_ONLY = re.compile(r"^\s*sel" r"ect\s*$", re.IGNORECASE)
_FROM_KW = re.compile(r"\bfrom\b", re.IGNORECASE)
_FROM_OR_WHERE = re.compile(r"^\s*(?:from\s+[a-zA-Z0-9_\"`\[\].*]+|where\s+[a-zA-Z0-9_\"`\[\].*]+)", re.IGNORECASE)
_SELECT_OR_DELETE_START = re.compile(r"^\s*(?:sel" r"ect|del" r"ete)\b", re.IGNORECASE)

_FMT_CALL = re.compile(
    r"\b(?:fmt\.Sprintf|String\.format|string\.Format|String\.Format|format!)\s*\(\s*$"
)

_FMT_PLACEHOLDER = re.compile(r"%[sdv]|(?:\{\w*\})")

def _extract_literals(code: str) -> list[tuple[int, int, str, str]]:
    """Yields (start, end, quote_char, content) where start is opening quote idx, end is closing quote idx."""
    literals = []
    start = -1
    quote = ""
    escaped = False
    for k, ch, in_string in _scan(code):
        if not in_string:
            continue
        if start == -1:
            start = k
            quote = ch
            escaped = False
        else:
            if ch == quote and not escaped:
                literals.append((start, k, quote, code[start + 1:k]))
                start = -1
                quote = ""
                escaped = False
            else:
                escaped = ch == "\\" and not escaped
    return literals


_EXEMPT_TAGS = {"sql", "SQL", "$queryRaw", "$executeRaw", "$queryRawTyped"}


def _tagged_template(code: str, start: int) -> bool:
    """A JS template literal right after a tag: only known parameterizing tags are exempt."""
    before = code[:start].rstrip()
    word = re.search(r"[\w$.]+$", before)
    return bool(word) and word.group().split(".")[-1] in _EXEMPT_TAGS


def shell_backtick_at(code: str, k: int, string_cutoff: int = 0) -> bool:
    """A backtick at `k` that opens a literal outside any other string (a PHP/Ruby shell command)."""
    if k < string_cutoff:
        return False
    return any(string_cutoff + start == k and quote == "`"
               for start, _end, quote, _c in _extract_literals(code[string_cutoff:]))


def _sql_injection(code: str, path_lower: str) -> bool:
    """True when a SQL literal is built from a variable in the file's language."""
    literals = _extract_literals(code)
    for idx, (start, end, quote, content) in enumerate(literals):
        is_sql = bool(_SQL_KW.search(content))
        if not is_sql:
            if _SELECT_ONLY.search(content):
                is_sql = any(_FROM_KW.search(oc) for os, oe, _oq, oc in literals if (os, oe) != (start, end))
            elif _FROM_OR_WHERE.search(content):
                is_sql = any(_SELECT_OR_DELETE_START.search(oc) for os, oe, _oq, oc in literals if (os, oe) != (start, end))
        elif _UPDATE_ONLY.search(content):
            if not any(_SET_KW.search(other_c) for os, oe, _oq, other_c in literals if (os, oe) != (start, end)):
                is_sql = False
        if not is_sql:
            continue
        # 1. Interpolation inside the literal
        if path_lower.endswith(PY):
            if re.search(r"(?<!\w)(?:f|rf|fr)$", code[:start], re.IGNORECASE) and re.search(r"\{\s*[a-zA-Z_]", content):
                return True
        elif path_lower.endswith(JS):
            if quote == "`" and "${" in content and not _tagged_template(code, start):
                return True
        elif path_lower.endswith(CS):
            if re.search(r"(?<!\w)(?:\$|\$@|@\$)$", code[:start]) and re.search(r"\{\s*[a-zA-Z_]", content):
                return True
        elif path_lower.endswith(RB):
            if quote == '"' and "#{" in content:
                return True
        elif path_lower.endswith(PHP):
            if quote == '"' and re.search(r"(?:\$[a-zA-Z_]|\{\$)", content):
                return True
        elif path_lower.endswith(KT + DART):
            if re.search(r"(?:\$[a-zA-Z_]|\$\{)", content):
                return True
        elif path_lower.endswith(SWIFT):
            if r"\(" in content:
                return True

        # 2. Concatenation right after closing quote or right before opening quote
        is_php = path_lower.endswith(PHP)
        curr_end = end
        next_idx = idx + 1
        while next_idx < len(literals):
            next_start, next_literal_end, _, _ = literals[next_idx]
            between = code[curr_end + 1:next_start].strip()
            if is_php and between == ".":
                curr_end = next_literal_end
                next_idx += 1
            elif not is_php and re.match(r"^\+(?!\+|=)\s*[rRuUbB]*$", between):
                curr_end = next_literal_end
                next_idx += 1
            else:
                break

        after = code[curr_end + 1:].lstrip()
        before = code[:start]

        if is_php:
            if re.match(r"^\.(?!\.|=)\s*([a-zA-Z_$]|\()", after):
                return True
            if re.search(r"(?:\b\w+|[)\]])\s*(?<![\.\->:])\.\s*$", before):
                return True
        else:
            if re.match(r"^\+(?!\+|=)\s*([a-zA-Z_$]|\()", after):
                return True
            if re.search(r"(?:\b\w+|[)\]])\s*(?<!\+)\+\s*$", before):
                return True
        # 3. Python formatting right after closing quote
        if path_lower.endswith(PY):
            if re.match(r"^%\s*([a-zA-Z_]|\()", after):
                return True
            if re.match(r"^\.for" r"mat\s*\(", after):
                return True

        # 4. Go/Java/Kotlin/C#/Rust formatters
        if path_lower.endswith(GO + JAVA + KT + CS + RS):
            if _FMT_CALL.search(before) and _FMT_PLACEHOLDER.search(content):
                return True

    return False


_RUBY_HTML_SAFE = re.compile(r"\.html_" r"safe\b(?!\?)")
_RUBY_RAW = re.compile(r"\braw\s*\(")
_ERB_RAW = re.compile(r"<%=\s*raw\s+(?!\()")
_ERB_DOUBLE_EQUAL = re.compile(r"<%==")


def _ruby_xss(code: str, is_erb: bool = False) -> bool:
    """Ruby/ERB XSS sinks: .html_safe or raw( not preceded by ., ::, or ->; in .erb also <%= raw and <%==."""
    if _RUBY_HTML_SAFE.search(code):
        return True
    for m in _RUBY_RAW.finditer(code):
        prefix = code[:m.start()].rstrip()
        if not prefix.endswith((".", "::", "->")) and prefix != "def" and not prefix.endswith((" def", "\tdef")):
            return True
    if is_erb:
        if _ERB_RAW.search(code):
            return True
        if _ERB_DOUBLE_EQUAL.search(code):
            return True
    return False

def _backward_chain(s: str, end: int) -> str:
    """Walk backward across identifiers, dots, whitespace, and balanced () pairs."""
    i = end - 1
    while i >= 0 and s[i].isspace():
        i -= 1
    while i >= 0:
        if s[i] == ")":
            depth = 1
            i -= 1
            while i >= 0 and depth > 0:
                if s[i] == ")":
                    depth += 1
                elif s[i] == "(":
                    depth -= 1
                i -= 1
        elif s[i].isalnum() or s[i] in "_?.!":
            i -= 1
        elif s[i].isspace():
            j = i
            while j >= 0 and s[j].isspace():
                j -= 1
            if j >= 0 and (s[j].isalnum() or s[j] in "_?.!)"):
                i = j
            else:
                break
        else:
            break
    return s[i + 1:end].strip()


class _Sec008Matcher:
    """Receiver-aware SEC-008 write matcher for Java/Kotlin and Swift."""
    def __init__(self, write_pattern: re.Pattern, method_call: str, exempt_names: tuple[str, ...], allow_block: bool = False):
        self._pattern = write_pattern
        self._method = method_call.lower()
        self._exempt_re = re.compile(
            r"^(?:(?:this|self)\.|with\s*\(\s*(?:(?:this|self)\.)?)?(?:"
            + "|".join(re.escape(n) for n in exempt_names)
            + r")\b",
            re.IGNORECASE,
        )
        self._allow_block = allow_block

    def finditer(self, body: str):
        for m in self._pattern.finditer(body):
            sub = body[m.start():m.end()]
            pos = sub.lower().find(self._method)
            if pos < 0:
                yield m
                continue
            call_idx = m.start() + pos
            dot_idx = call_idx - 1
            while dot_idx >= 0 and body[dot_idx].isspace():
                dot_idx -= 1
            if dot_idx >= 0 and body[dot_idx] in ".?":
                dot_pos = dot_idx
                if body[dot_pos] == "." and dot_pos > 0 and body[dot_pos - 1] == "?":
                    dot_pos -= 1
                chain = _backward_chain(body, dot_pos)
                if self._exempt_re.match(chain):
                    continue
            elif self._allow_block:
                depth = 0
                brace_idx = -1
                for i in range(call_idx - 1, -1, -1):
                    if body[i] == "}":
                        depth += 1
                    elif body[i] == "{":
                        if depth > 0:
                            depth -= 1
                        else:
                            brace_idx = i
                            break
                if brace_idx != -1:
                    chain = _backward_chain(body, brace_idx)
                    if self._exempt_re.match(chain):
                        continue
            yield m

SUPPRESS_COMMENT = re.compile(r"(?:#|//|/\*|<!--)\s*guard-allow\s+([A-Z]+-\d+)\s*:\s*(\S.*)")


# Line rules, checked on each added line of a matching file (never docs or tests): (rule, severity,
# which files, pattern, what to do instead). Each is narrow on purpose: a line that matches is
# nearly always the problem, and `guard-allow <RULE>: <reason>` on the line keeps it as a LOW note.
LINE_RULES = [
    ("SEC-004", "HIGH", lambda f: f.endswith(PY),
     re.compile(r"\byaml\.(?:unsafe_)?load(?:_all)?\(|\b(?:pickle|cPickle|dill|marshal)\.loads?\("),
     "Deserializing data this way can run code (yaml.load without SafeLoader, pickle/marshal): use "
     "yaml.safe_load or JSON for anything that is not your own trusted file."),
    ("SEC-004", "HIGH", lambda f: f.endswith(JAVA + KT),
     re.compile(r"(?<!\bimport\s)(?<!\bimport\s\s)(?<!:\s)(?<!:\s\s)(?<!:)(?<!<\s)(?<!<)(?<!\bclass\s)(?<!\binterface\s)\bObjectInputStream\s*\(|\b(?:enable|activate)DefaultTyping\("),
     "ObjectInputStream and Jackson default typing allow arbitrary code execution during deserialization."),
    ("SEC-004", "HIGH", lambda f: f.endswith(PHP),
     re.compile(r"(?i)(?<!\bfunction\s)(?<!\bfunction\s\s)(?<!\bfunction\s\s\s)(?<!\bfunction\t)(?<!\bfunction&)(?<!\bfunction\s&)(?<!\bfunction\s&\s)\bunserialize\s*\((?!.*['\"]allowed_classes['\"]\s*=>\s*false\b)"),
     "unserialize() on untrusted data can lead to object injection: use json_decode."),
    ("SEC-004", "HIGH", lambda f: f.endswith(RB),
     re.compile(r"\b(?:Mar" r"shal\.load|YA" r"ML\.(?:unsafe_)?load|Psy" r"ch\.(?:unsafe_)?load)\("),
     "Marshal.load and YAML.load can run code on untrusted input: use YAML.safe_load or JSON.parse."),
    ("SEC-004", "HIGH", lambda f: f.endswith(CS),
     re.compile(r"\b(?:BinaryFormatter|NetDataContractSerializer|LosFormatter)\b"),
     "BinaryFormatter and related formatters are inherently unsafe for untrusted input: use System.Text.Json."),
    ("SEC-005", "HIGH", lambda f: f.endswith(PY),
     re.compile(r"\bsubprocess\.\w+\(.*\bshell\s*=\s*True|\bos\.(?:system|popen)\(|(?<![\w.])(?<!def )(?:eval|exec)\("),
     "A string is run as a shell command or as code: pass subprocess an argument list without "
     "shell=True, and parse values instead of eval/exec."),
    ("SEC-005", "HIGH", lambda f: f.endswith(JS),
     re.compile(r"(?:(?<![\w.$])|(?<=\bwindow\.)|(?<=\bglobalThis\.)|(?<=\bself\.))eval\(|\bnew\s+Function\("),
     "eval / new Function runs a string as code: parse the value (JSON.parse) or call the function directly."),
    ("SEC-005", "HIGH", lambda f: f.endswith(GO),
     re.compile(r"""\bexec\.(?:Command\s*\(\s*|CommandContext\s*\(\s*[^,]+,\s*)["'](?:sh|bash|cmd(?:\.exe)?|/bin/(?:sh|bash))["']\s*,\s*["'][-/][cC]["']"""),
     "Running a shell with exec.Command allows command injection: pass arguments directly without a shell."),
    ("SEC-005", "HIGH", lambda f: f.endswith(JAVA + KT),
     re.compile(r"""(?:\bRuntime\.getRuntime\(\)\.exec|\bProcessBuilder)\s*\(.*?(?:["'](?:sh|bash|cmd(?:\.exe)?|/bin/(?:sh|bash))["']\s*,\s*["'][-/][cC]["'])"""),
     "Executing a command via shell can allow command injection: pass arguments directly without sh/bash/cmd."),
    ("SEC-005", "HIGH", lambda f: f.endswith(PHP),
     re.compile(r"""(?<!->)(?<!::)(?<![\w.$])(?<!->\s)(?<!::\s)(?<!\.\s)(?<!\$\s)(?<!\bfunction\s)(?:system|exec|shell_exec|passthru|popen|proc_open|eval)\s*\(|`[^`\r\n]+`"""),
     "Running a shell command or eval runs a string as code: avoid shell execution or validate arguments."),
    ("SEC-005", "HIGH", lambda f: f.endswith(RB),
     re.compile(r"""(?<!->)(?<!::)(?<![\w.$])(?<!->\s)(?<!::\s)(?<!\.\s)(?<!\$\s)(?<!\bdef\s)(?<!\bdef\s\s)(?<!\bdef\t)(?:system|exec|eval)(?:\s*\(|\s+["'])|"""
                r"""\b(?:Kernel\s*(?:\.|::)\s*(?:system|exec)|IO\s*(?:\.|::)\s*popen)\s*(?:\(|\s+["'])|"""
                r"""%x[({[]|`[^`\r\n]+`"""),
     "Running a shell command or eval runs a string as code: avoid shell execution or pass argument arrays."),
    ("SEC-005", "HIGH", lambda f: f.endswith(CS),
     re.compile(r"""(?:\b(?:Process\.Start|new\s+ProcessStartInfo)\s*\(.*?(?:["'](?:cmd(?:\.exe)?|powershell(?:\.exe)?|sh|bash|/bin/(?:sh|bash))["'])|"""
                r"""\bFileName\s*=\s*["'](?:cmd(?:\.exe)?|powershell(?:\.exe)?|sh|bash|/bin/(?:sh|bash))["'])"""),
     "Starting a shell with Process.Start can allow command injection: run target executables directly without cmd/bash."),
    ("SEC-005", "HIGH", lambda f: f.endswith(RS),
     re.compile(r"""\bCommand::new\s*\(\s*["'](?:sh|bash|cmd(?:\.exe)?|/(?:usr/)?bin/(?:sh|bash))["']\s*\)|"""
                r"""\.\s*arg(?:s\s*\(\s*\[|\s*\()\s*["'](?:-c|/c|/C)["']"""),
     "Spawning a shell with Command::new allows command injection: pass executable and arguments directly."),
    ("SEC-005", "HIGH", lambda f: f.endswith(SWIFT),
     re.compile(r"""\blaunchPath\s*=\s*["'](?:/(?:usr/)?bin/)?(?:sh|bash|zsh)["']|"""
                r"""\bexecutableURL\s*=\s*URL\s*\(\s*fileURLWithPath:\s*["'](?:/(?:usr/)?bin/)?(?:sh|bash|zsh)["']"""),
     "Running a shell via Process can allow command injection: run target executables directly."),
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
     re.compile(r"(?i)(?:(?:localStorage|sessionStorage)(?:\.setItem\(\s*|\[\s*(?=[^\]]*\]\s*=(?!=))|\.(?=[\w$]+\s*=(?!=)))|AsyncStorage\.setItem\(\s*)"
                r"[\"'`]?[^\"'`\]=]*(?:token|jwt|secret|passw(?:or)?d|api[_-]?key|\bsession(?:[_-]?(?:id|key))?\b)"),
     "A credential goes into client storage (localStorage/sessionStorage/AsyncStorage): prefer an HttpOnly cookie."),
    ("SEC-008", "MEDIUM", lambda f: f.endswith(JAVA + KT),
     _Sec008Matcher(
         re.compile(r"(?i)\bputString\(\s*[\"'][^\"']*(?:token|jwt|secret|passw(?:or)?d|api[_-]?key|\bsession(?:[_-]?(?:id|key))?\b)"),
         "putString(",
         ("EncryptedSharedPreferences", "encryptedPrefs", "securePrefs"),
         allow_block=True,
     ),
     "A credential is saved in SharedPreferences in plaintext: store sensitive tokens in EncryptedSharedPreferences or KeyStore."),
    ("SEC-008", "MEDIUM", lambda f: f.endswith(SWIFT),
     _Sec008Matcher(
         re.compile(r"(?i)(?:\bUserDefaults\b[^;]*?\.set\(|\.set\([^;)]*forKey:\s*[\"'][^\"']*)"
                    r"(?:token|jwt|secret|passw(?:or)?d|api[_-]?key|\bsession(?:[_-]?(?:id|key))?\b)"),
         "set(",
         ("Keychain", "KeychainWrapper", "SecureStore"),
         allow_block=False,
     ),
     "A credential is saved in UserDefaults in plaintext: store credentials in the iOS Keychain."),
    ("SEC-008", "MEDIUM", lambda f: f.endswith(DART),
     re.compile(r"(?i)\bsetString\(\s*[\"'][^\"']*(?:token|jwt|secret|passw(?:or)?d|api[_-]?key|\bsession(?:[_-]?(?:id|key))?\b)"),
     "A credential is saved in SharedPreferences in plaintext: use flutter_secure_storage for sensitive credentials."),
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
    # iOS Info.plist: the value usually sits on the line after its key; the scan joins the two lines
    ("MOB-001", "HIGH", lambda f: f.endswith("info.plist"),
     re.compile(r"<key>\s*NSAllowsArbitraryLoads\s*</key>\s*<true\s*/>"),
     "App Transport Security is off (NSAllowsArbitraryLoads): the app may load plain-HTTP content; allow only "
     "the hosts that need it with NSExceptionDomains."),
    ("MOB-002", "MEDIUM", lambda f: f.endswith("info.plist"),
     re.compile(r"<key>\s*UIFileSharingEnabled\s*</key>\s*<true\s*/>"),
     "The app's Documents folder is shared through Finder/iTunes (UIFileSharingEnabled): turn it off unless "
     "users are meant to see those files."),
]


MAX_RULE_LINE = 2000
MAX_IMG_TAG = 2000
