"""
Registering an agent guard does not know yet: investigate it on this machine and have the configured
LLM propose an adapter (phase 2's data shape) from that and from what it knows of the agent, which
`validate_adapter` checks before the user sees a diff. Whether it works is then tried for real
(`guard agent test`); when guard cannot make it work, the user is told what happened and gets a
prefilled GitHub issue, instead of guard reading documentation from the web on its own.

Everything sent to the LLM is read-only and size-capped, and never free text: config files go as
structure only (key names, sections, numbers and booleans; every text value replaced) and the agent
as its version number, so no value of any shape leaves the machine. The LLM only describes the
harness (config path, event names, payload fields, how an answer is read); guard fills in the
command, and gate logic never comes from it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

MAX_FILE = 64_000  # a config file larger than this is listed, not read
MAX_FILES_TEXT = 60_000  # all config text sent, together
MAX_LISTED = 80
CONFIG_EXTS = (".json", ".jsonc", ".toml", ".yaml", ".yml")
SKIP_PARTS = {"sessions", "logs", "cache", "node_modules", "chats", "projects", "worktrees", "history"}

# `0.156.1`, `2.1.0-beta.3`, `v1.7`: two or three numbers, never part of a longer dotted run (an IP address)
VERSION = re.compile(r"(?<![\d.])\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]{1,20})?(?![\d.])")
TEXT = "<text>"  # a config value, whatever it held: the LLM needs a file's structure, never its values


# A key is sent only when it reads as a name: letters and underscores (`hooks`, `preToolUse`, `timeout`).
# Anything with a digit, dash, dot, @ or slash may be data (a token, a path, an e-mail) and is replaced.
PLAIN_KEY = re.compile(r"[A-Za-z][A-Za-z_]{0,39}")


def _key(key: str, taken: Dict[str, Any]) -> str:
    """A key name as it is when it is a plain name; any other key (a token, a path, an e-mail) is replaced."""
    if PLAIN_KEY.fullmatch(key):
        return key
    n = sum(1 for k in taken if k.startswith("<key"))
    return f"<key{n + 1}>"


def _structure_value(value: Any) -> Any:
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for k, v in value.items():
            out[_key(str(k), out)] = _structure_value(v)
        return out
    if isinstance(value, list):
        return [_structure_value(v) for v in value]
    return TEXT if isinstance(value, str) else value  # numbers, booleans and null tell no secrets


def structure(text: str) -> str:
    """
    A config file with every text value replaced: plain key names, sections, numbers and booleans stay,
    so the LLM sees the file's shape (where hooks go, what an entry holds) and none of its contents;
    a key that is itself data (a folder path, a URL) is replaced too.
    """
    try:
        return json.dumps(_structure_value(json.loads(text)), indent=1, ensure_ascii=False)
    except ValueError:
        pass
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        m = re.match(r"""^(\s*-?\s*)["']?([\w.\-]+)["']?(\s*[=:])\s*(.*)$""", line)
        if not stripped:
            out.append(line)
        elif re.fullmatch(r"\[{1,2}[^\]]*\]{1,2}", stripped):
            # a TOML section header: each part stays only as a plain name (`[projects."E:\\work"]` names a folder)
            double = stripped.startswith("[[")
            inner = stripped[2:-2] if double else stripped[1:-1]
            parts = [p if PLAIN_KEY.fullmatch(p) else "<key>" for p in re.findall(r"\"[^\"]*\"|'[^']*'|[^.]+", inner)]
            joined = ".".join(parts)
            out.append(line[:len(line) - len(line.lstrip())] + (f"[[{joined}]]" if double else f"[{joined}]"))
        elif m:
            key = m.group(2) if PLAIN_KEY.fullmatch(m.group(2)) else "<key>"
            value = m.group(4).strip()
            kept = value if re.fullmatch(r"-?\d+(\.\d+)?|true|false|null|\{|\[", value, re.I) else TEXT
            head = f"{m.group(1)}{key}{m.group(3)}"
            out.append(f"{head} {kept}" if value else head)
        else:
            out.append(re.match(r"^\s*-?\s*", line).group(0) + TEXT)  # a list item, comment or continuation
    return "\n".join(out)


@dataclass
class Investigation:
    name: str
    binary: Optional[str] = None
    version: str = ""
    listing: List[str] = field(default_factory=list)  # config files found (home-relative)
    files: Dict[str, str] = field(default_factory=dict)  # home-relative path -> its structure, every text value replaced
    notes: List[str] = field(default_factory=list)

    def found(self) -> bool:
        return bool(self.binary or self.listing)


def _config_dirs(name: str) -> List[Path]:
    home = Path(os.path.expanduser("~"))
    dirs = [home / f".{name}", home / ".config" / name]
    for env in ("APPDATA", "LOCALAPPDATA"):
        if os.environ.get(env):
            dirs.append(Path(os.environ[env]) / name)
    from guard.agent.adapter_validation import _inside_home
    # checked where it really is (links resolved): a folder that leads into a repository is skipped
    return [d for d in dirs if d.is_dir() and _inside_home(str(d / "config"))]


def _config_files(base: Path, depth: int = 2) -> List[Path]:
    """Config-like files at most `depth` levels down, never walking into data folders (worktrees, node_modules, …)."""
    found: List[Path] = []
    try:
        entries = sorted(os.scandir(base), key=lambda e: e.name)
    except OSError:
        return found  # unreadable, or a link to nowhere
    for entry in entries:
        try:
            if entry.is_dir(follow_symlinks=False):
                if depth > 1 and entry.name.lower() not in SKIP_PARTS and not entry.name.startswith("."):
                    found.extend(_config_files(Path(entry.path), depth - 1))
            elif (entry.is_file(follow_symlinks=False) and entry.name.lower().endswith(CONFIG_EXTS)
                  and ".tmp" not in entry.name and ".bak" not in entry.name):
                found.append(Path(entry.path))
        except OSError:
            continue
    return found


def _shown(path: Path, base: Path, home: Path) -> str:
    """A config file as the LLM and the issue see it: `~/…`, or `%APPDATA%/…` for a folder outside home; never a full path."""
    if path.is_relative_to(home):
        return "~/" + path.relative_to(home).as_posix()
    for env in ("APPDATA", "LOCALAPPDATA"):
        root = os.environ.get(env)
        if root and path.is_relative_to(Path(root)):
            return f"%{env}%/" + path.relative_to(Path(root)).as_posix()
    return f"<{base.name}>/" + path.relative_to(base).as_posix()


VERSION_BYTES = 4096


def _first_bytes(command: List[str], timeout: float = 10.0) -> str:
    """
    At most VERSION_BYTES of what a command prints within `timeout`. The read runs in a thread guard
    stops waiting for: a launcher's child that keeps the pipe open (and prints nothing) never holds
    guard, and the whole process tree is ended afterwards.
    """
    import threading
    proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            start_new_session=os.name != "nt")  # its own process group, ended as one
    got: List[bytes] = []

    def read() -> None:  # chunk by chunk, so what arrived before the timeout is kept
        while proc.stdout and sum(map(len, got)) < VERSION_BYTES:
            chunk = proc.stdout.read1(VERSION_BYTES - sum(map(len, got)))
            if not chunk:
                return
            got.append(chunk)

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    reader.join(timeout)
    if os.name == "nt":
        # safe even after it exited: Popen keeps the process handle open until `proc` is freed, and
        # Windows never gives a PID to another process while a handle to its old one is open
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, check=False)
    else:
        import signal
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
    try:
        proc.kill()
        proc.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return b"".join(got)[:VERSION_BYTES].decode("utf-8", errors="replace")


def investigate(name: str) -> Investigation:
    """What this machine says about the agent: its binary, its version number, the structure of its config files."""
    from guard.agent.adapter import NAME
    if not NAME.match(name):  # the name becomes part of the folders read: never `..` or a path
        raise ValueError("an agent name is lower-case letters, digits and dashes")
    inv = Investigation(name=name)
    inv.binary = shutil.which(name)
    if inv.binary:
        try:
            output = _first_bytes([inv.binary, "--version"])
            # only the version number leaves the machine: free text is never sent, so nothing in it can leak
            # the first line's version only, and only when it names one: anything ambiguous is left out
            first = output.strip().splitlines()[:1]
            versions = set(VERSION.findall(first[0])) if first else set()
            inv.version = versions.pop() if len(versions) == 1 else ""
        except (OSError, subprocess.SubprocessError) as e:
            inv.notes.append(f"`{name} --version` did not run: {type(e).__name__}")
    home = Path(os.path.expanduser("~"))
    sent = 0
    for base in _config_dirs(name):
        for path in _config_files(base):
            shown = _shown(path, base, home)
            if len(inv.listing) >= MAX_LISTED:
                inv.notes.append(f"more than {MAX_LISTED} config files: the first {MAX_LISTED} are listed")
                return inv
            inv.listing.append(shown)
            try:
                size = path.stat().st_size
                if size > MAX_FILE or sent + size > MAX_FILES_TEXT:
                    continue  # listed, not read
                text = structure(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            inv.files[shown] = text
            sent += size
    return inv


def _json_in(text: str) -> Any:
    """The first JSON value in an LLM answer (it may add a sentence or a code fence around it)."""
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch in "[{":
            try:
                return decoder.raw_decode(text[i:])[0]
            except ValueError:
                continue
    raise ValueError("the answer holds no JSON")


def _evidence(inv: Investigation) -> str:
    parts = [f"Agent: {inv.name}", f"Binary on PATH: {'yes' if inv.binary else 'no'}"]  # never its path: it names the user
    if inv.version:
        parts.append(f"Version: {inv.version}")
    parts.append("Config files found:\n" + ("\n".join(f"- {p}" for p in inv.listing) or "- none"))
    for path, text in inv.files.items():
        parts.append(f"--- {path} (structure only: every text value replaced)\n{text}")
    return "\n\n".join(parts)


ADAPTER_RULES = """\
An adapter maps an agent harness's hooks onto guard's fixed contract `guard agent-event <event>`.
Guard's events: prompt (user submitted a prompt), before-edit (before a file edit or a shell command),
after-bash (after a shell command), stop (the agent is about to finish its turn), before-commit.
Answer with ONE JSON object:
- name: "{name}"; title: the agent's name for people.
- config: the global (user-level, never per-project) hook config file, starting with "~/" (or with
  "%APPDATA%/" or "%LOCALAPPDATA%/" when the listing shows it there).
- detect: the agent's config folder, written the same way.
- hooks: [{{"harness_event": <the harness's own event name>, "event": <guard event>, "matcher"?: <tool
  filter the harness supports, if it needs one>}}], one per harness event guard should hear.
- fields: where the harness's JSON payload puts each field, as dotted paths:
  {{"cwd": [...], "prompt": [...], "tool": [...], "file_paths": [...], "command": [...], "call_id": [...], "loop": [...]}}.
- can_block: the guard events whose hook can really stop the action.
- output: per decision (allow, notify, block), per harness event (names joined by "|", "*" for the rest),
  what the command prints: {{"stdout": <text or JSON the harness reads>, "stderr": <text>, "exit": <code>}};
  "{{reason}}" and "{{harness_event}}" are filled in by guard.
- entry: the JSON of ONE hook entry as the config file holds it. What runs is guard's: "command" is exactly
  "{{command_line}}" (one command string), or "{{program}}" with "args": "{{args}}" (a list); "{{matcher}}"
  may fill the harness's filter. Every other value is a plain word or a number (e.g. "type": "command", "timeout": 30).
- defaults: top-level keys a new config file needs besides "hooks" (e.g. {{"version": 1}}), if any.
Base it on the evidence (its version and the structure of its config files) and on what you know of this
agent's documented hook system. If it has no hook system that can run a command, or you do not know it well
enough to name its events and payload fields, answer {{"no_hooks": "<why>"}}: guessing is worse than saying so.
The built-in Claude Code adapter, as an example of the shape:
{example}"""


# Text kept in an adapter sent for a fix: names without digits (event names, matchers such as
# `Edit|Write`, dotted field paths, `*`) and guard's own placeholders. A digit, or anything else, may
# be a secret someone typed into the record (`sk_live_abc123`): it is replaced.
ADAPTER_WORD = re.compile(r"[A-Za-z_*][A-Za-z_.|*\-]{0,79}|\{(?:reason|harness_event|command_line|program|args|matcher)\}")
ADAPTER_PATH = re.compile(r"~/\.[A-Za-z_\-]+(?:/[A-Za-z_.\-]+)*")  # config and detect: `~/.cursor/hooks.json`
ADAPTER_FREE_TEXT = {"title", "limits"}  # a person's words: never sent


PLACEHOLDER = re.compile(r"\{(?:reason|harness_event|command_line|program|args|matcher)\}")
PROTOCOL_WORDS = {"block", "deny", "allow", "ask", "continue", "command", "process"}  # answer and entry words


def _adapter_summary(adapter: Any) -> Any:
    """
    An adapter as the LLM sees it for a fix, by schema: event names, matchers, guard's own payload
    paths, placeholders and a few protocol words stay; every other value (a title, answer text, an
    unknown field path) is replaced, even when it reads as a plain word: it may be what someone typed.
    """
    from guard.agent.adapter import BUILT_IN, NAME
    from guard.agent.events import DEFAULT_FIELDS, EVENTS
    known_paths = {p for paths in DEFAULT_FIELDS.values() for p in paths} | {
        p for a in BUILT_IN.values() for paths in (a.get("fields") or {}).values() for p in paths}

    def key_of(k: Any, out: Dict[str, Any]) -> str:  # keys are event names too (`preToolUse|beforeShellExecution`, `*`)
        return str(k) if ADAPTER_WORD.fullmatch(str(k)) else f"<key{sum(1 for x in out if x.startswith('<key')) + 1}>"

    def value(v: Any) -> Any:  # answers, entry templates, defaults
        if isinstance(v, dict):
            out: Dict[str, Any] = {}
            for k, item in v.items():
                out[key_of(k, out)] = value(item)
            return out
        if isinstance(v, list):
            return [value(item) for item in v]
        if isinstance(v, str):
            return v if PLACEHOLDER.fullmatch(v) or v in PROTOCOL_WORDS else TEXT
        return v

    def hook(h: Any) -> Any:
        if not isinstance(h, dict):
            return TEXT
        out: Dict[str, Any] = {}
        for k, v in h.items():
            if k == "harness_event":
                out[k] = v if isinstance(v, str) and ADAPTER_WORD.fullmatch(v) else TEXT
            elif k == "event":
                out[k] = v if v in EVENTS else TEXT
            elif k == "matcher":
                out[k] = v if isinstance(v, str) and ADAPTER_WORD.fullmatch(v) else TEXT
            else:
                out[key_of(k, out)] = value(v)
        return out

    if not isinstance(adapter, dict):
        return TEXT
    out: Dict[str, Any] = {}
    for k, v in adapter.items():
        if k in ADAPTER_FREE_TEXT:
            out[k] = TEXT
        elif k == "name":
            out[k] = v if isinstance(v, str) and NAME.fullmatch(v) else TEXT
        elif k in ("config", "detect"):
            out[k] = v if isinstance(v, str) and ADAPTER_PATH.fullmatch(v) else TEXT
        elif k == "can_block":
            out[k] = [e if e in EVENTS else TEXT for e in v] if isinstance(v, list) else TEXT
        elif k == "hooks":
            out[k] = [hook(h) for h in v] if isinstance(v, list) else TEXT
        elif k == "fields":
            out[k] = ({f: ([p if isinstance(p, str) and p in known_paths else TEXT for p in paths] if isinstance(paths, list) else TEXT)
                       for f, paths in v.items() if f in DEFAULT_FIELDS} if isinstance(v, dict) else TEXT)
        else:
            out[key_of(k, out)] = value(v)
    return out


def propose(cfg, inv: Investigation, previous: Optional[dict] = None,
            problems: Optional[List[str]] = None, log: str = "") -> dict:
    """The LLM's adapter for this agent (or {"no_hooks": ...}); `previous` and `problems` ask for a fix."""
    from guard.agent.adapter import CLAUDE_CODE
    from guard.core.llm_client import call_llm
    parts = [_evidence(inv)]
    if previous is not None:  # a record anyone can edit: its free text stays on the machine
        parts.append("The current adapter:\n" + json.dumps(_adapter_summary(previous), indent=1))
    if log:
        parts.append("Events guard received from this agent (most recent last):\n" + log)
    if problems:
        parts.append("Fix these problems:\n" + "\n".join(f"- {p}" for p in problems))
    example = {k: v for k, v in CLAUDE_CODE.items() if k != "entry"}
    system = ADAPTER_RULES.format(name=inv.name, example=json.dumps(example, indent=1))
    answer = call_llm(cfg, "\n\n".join(parts), system_prompt=system, max_tokens=4000, temperature=0.0)
    proposal = _json_in(answer)
    if not isinstance(proposal, dict):
        raise ValueError("the answer is not a JSON object")
    return proposal


def event_summary(lines: List[str]) -> str:
    """
    What `agent fix` tells the LLM about the events guard received: the harness event, the tool name
    and the decision, when each is a plain word (letters and `_.-`, no digit: a key or token has
    digits); anything else in a log line (paths, commands, error text) never leaves the machine.
    """
    word = re.compile(r"[A-Za-z][A-Za-z_.-]{0,39}")
    out = []
    for line in lines:
        if " EVENT " in line:
            rest = line.split(" EVENT ", 1)[1].split()
            harness = rest[0] if rest and word.fullmatch(rest[0]) else "?"
            tool = next((t[5:] for t in rest if t.startswith("tool=") and word.fullmatch(t[5:])), "")
            action = rest[-1] if rest and rest[-1] in ("allow", "notify", "block") else "?"
            out.append(f"{harness}{' tool=' + tool if tool else ''} -> {action}")
        elif " UNREADABLE " in line or " ERROR " in line:
            kind = "UNREADABLE" if " UNREADABLE " in line else "ERROR"
            name = line.split(f" {kind} ", 1)[1].split(":", 1)[0].strip()
            out.append(f"{kind} {name if word.fullmatch(name) else '?'}")
    return "\n".join(out)


ISSUES_URL = "https://github.com/okrath/banh-mi-guard/issues/new"


def issue_url(name: str, problem: str, inv: Optional[Investigation] = None) -> str:
    """
    A prefilled issue asking for support of this agent. It holds what the user can read in it before
    sending: the agent's name, guard's version, the OS, the config file names and the problem; never a
    config's contents. Guard only prints it: the user opens it and decides whether to send it.
    """
    import platform
    from urllib.parse import urlencode

    from guard import __version__
    lines = [
        f"Agent: {name}", f"guard: {__version__}", f"OS: {platform.system()} {platform.release()}",
        # without an investigation (a failed `guard agent test`) guard does not know: it never guesses "no"
        "Binary on PATH: " + ("unknown" if inv is None else "yes" if inv.binary else "no"),
        "Config files: " + ("unknown" if inv is None else ", ".join(inv.listing[:20]) or "none found"),
        "", f"What happened: {problem}", "", "Where the agent documents its hooks (if you know): ",
    ]
    return ISSUES_URL + "?" + urlencode({"title": f"Support agent: {name}", "body": "\n".join(lines)})
