"""
Agent adapters: how an agent harness calls `guard agent-event` and how guard answers it.

An adapter is data (the same shape phase 5 generates for user-registered agents): the harness
config file, the hook entries guard adds there, the payload field paths, and the output style per
harness event. Installing one writes ~/.guard/agents/<name>.json (what `agent-event --agent` reads)
and merges guard's own hook entries into the harness config, after the user saw the diff.
Guard only ever touches its own entries: they are the ones whose arguments call `agent-event`.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import shlex
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from guard.agent.events import EVENTS as _EVENTS
from guard.agent.events import READ_TOOLS, Decision

MARKER = "agent-event"  # guard's entries are the ones that run `guard agent-event <event> --agent <name>`

# Claude Code: https://code.claude.com/docs/en/hooks (checked 2026-09-28). Hooks from the user
# settings file run for every project; edits are picked up without a restart.
CLAUDE_CODE: Dict[str, Any] = {
    "name": "claude-code",
    "session_id": "session_id (documented: code.claude.com hooks reference, every hook payload)",
    "title": "Claude Code",
    "detect": "~/.claude",
    "config": "~/.claude/settings.json",
    "hooks": [
        {"harness_event": "UserPromptSubmit", "event": "prompt"},
        {"harness_event": "PreToolUse", "matcher": "Edit|Write|MultiEdit|NotebookEdit|Bash|PowerShell", "event": "before-edit"},
        {"harness_event": "PostToolUse", "matcher": "Bash|PowerShell", "event": "after-bash"},
        {"harness_event": "Stop", "event": "stop"},
    ],
    # Fields where Claude Code puts them (guard's defaults already cover these; kept explicit)
    "fields": {
        "cwd": ["cwd"], "prompt": ["prompt"], "tool": ["tool_name"],
        "file_paths": ["tool_input.file_path", "tool_input.notebook_path"],
        "command": ["tool_input.command"], "call_id": ["tool_use_id"], "loop": ["stop_hook_active"],
    },
    "can_block": ["prompt", "before-edit", "stop"],
    # What guard prints per decision and harness event: the first key naming the event (`A|B`), else
    # `*`. `{reason}` and `{harness_event}` are filled in; a JSON object goes to stdout as JSON.
    "output": {
        "allow": {"*": {"exit": 0}},
        "notify": {
            "PreToolUse|PostToolUse|UserPromptSubmit": {
                "stdout": {"hookSpecificOutput": {"hookEventName": "{harness_event}", "additionalContext": "{reason}"}}},
            "*": {"stdout": {"systemMessage": "{reason}"}},  # shown to the user
        },
        "block": {
            # a stop is prevented with a JSON decision on exit 0: Claude reads the reason as what is left
            "Stop|SubagentStop|PostToolUse": {"stdout": {"decision": "block", "reason": "{reason}"}},
            "*": {"stderr": "{reason}", "exit": 2},  # a tool call or prompt: exit 2, stderr reaches Claude
        },
    },
}
from guard.agent.builtins import ADAPTERS as _SHIPPED  # noqa: E402  # circular dependency between adapter and builtins
from guard.agent.builtins import (  # noqa: E402  # circular dependency between adapter and builtins
    EXTENSION_MARKER,
    EXTENSION_SOURCES,
)

BUILT_IN = {"claude-code": CLAUDE_CODE, **_SHIPPED}  # the popular agents, each checked against its own source


def protection(adapter: Dict[str, Any]) -> str:
    """What this agent's hooks really enforce, from what its harness can refuse (never more)."""
    blocks = set(adapter.get("can_block") or [])
    refused = []
    if "before-edit" in blocks:  # shell commands arrive there too, so a `git commit` is checked with them
        refused.append("edits before guard pre or outside the scope, commits without an approval")
    if "stop" in blocks:
        refused.append("a stop with unapproved edits")
    text = ("refuses " + " and ".join(refused)) if refused else "reports edits, refuses nothing"
    if adapter.get("protection_note"):
        text += f" ({adapter['protection_note']})"
    if "stop" not in blocks:
        text += " (a stop is not refused: the Git pre-commit hook remains the backstop)"
    return text


def _record_name(name: str) -> str:
    """An agent's name as part of a file name under ~/.guard/agents: never a path (`..`, `/`)."""
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise AdapterError(f"{name!r} is not an agent name (lowercase letters, digits and -)")
    return name


def test_record_path(name: str) -> Path:
    """What the last `guard agent test <name>` saw (doctor shows it)."""
    return adapters_dir() / f"{_record_name(name)}.test.json"


def config_fingerprint(path: Path) -> Optional[str]:
    """
    Which config file a test saw and what it held: its path and a hash of its content ("missing" when
    there is none). None when it cannot be read: no evidence, so it never matches an earlier test.
    """
    import hashlib
    try:
        content = hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        content = "missing"
    except OSError:
        return None
    return f"{path.resolve()}:{content}"


def switched_path(name: str) -> Path:
    """The settings guard switched on for this agent (ZCode's hooks.enabled): `guard agent remove` switches them back."""
    return adapters_dir() / f"{_record_name(name)}.switched.json"


def extension_path(adapter: Dict[str, Any]) -> Path:
    return Path(user_path(adapter["install"]))


def extension_text(adapter: Dict[str, Any], command: Optional[List[str]] = None) -> str:
    """The one file guard installs for an in-process agent (omp, pi, opencode), with guard's command in it."""
    return (EXTENSION_SOURCES[adapter["source"]]
            .replace("__GUARD__", json.dumps(command or guard_command()))
            .replace("__AGENT__", json.dumps(adapter["name"]))
            .replace("__READ_TOOLS__", json.dumps(sorted(READ_TOOLS))))


def extension_is_guards(adapter: Dict[str, Any]) -> bool:
    """The file there starts with guard's marker (a file of someone else's is not guard's)."""
    try:
        with open(extension_path(adapter), encoding="utf-8") as f:
            return f.readline().rstrip("\r\n") == EXTENSION_MARKER
    except (OSError, UnicodeDecodeError):
        return False


def extension_state(adapter: Dict[str, Any]) -> str:
    """
    "current": guard's file exactly as this guard writes it (the only state that counts as installed:
    an older file may call a guard that is gone, and then allows everything); "stale": guard's marker,
    but not this guard's file (guard moved, another version, or edited), which `guard agent add`
    rewrites; "foreign": not guard's; "missing".
    """
    try:
        text = extension_path(adapter).read_text(encoding="utf-8")
    except FileNotFoundError:
        return "missing"
    except (OSError, UnicodeDecodeError):
        return "foreign"  # unreadable, or not text guard wrote
    if text.split("\n", 1)[0].rstrip("\r") != EXTENSION_MARKER:
        return "foreign"
    try:
        return "current" if text == extension_text(adapter) else "stale"
    except (KeyError, AdapterError):
        return "stale"


def extension_installed(adapter: Dict[str, Any]) -> bool:
    return extension_state(adapter) == "current"


class AdapterError(ValueError):
    """The harness config cannot be changed safely (unreadable, not an object): nothing was written."""


def adapters_dir() -> Path:
    from guard.core.repo_setup import guard_home
    return guard_home() / "agents"


def load_adapter(name: str) -> Optional[Dict[str, Any]]:
    """
    A built-in adapter comes from this guard version (a record written by an older version never
    answers with stale output rules); any other from ~/.guard/agents/<name>.json; else None.
    """
    if name in BUILT_IN:
        return BUILT_IN[name]
    if not isinstance(name, str) or not NAME.fullmatch(name):
        return None  # never a path outside ~/.guard/agents
    path = adapters_dir() / f"{name}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return BUILT_IN.get(name)


USER_ROOTS = ("APPDATA", "LOCALAPPDATA")  # Windows' per-user folders, written `%APPDATA%/…` as discovery shows them


def user_path(raw: str) -> str:
    """`~/…` or `%APPDATA%/…` / `%LOCALAPPDATA%/…` made absolute; anything else as it is."""
    for env in USER_ROOTS:
        tag = f"%{env}%"
        if raw[len(tag):len(tag) + 1] in ("/", "\\") and raw.startswith(tag) and os.environ.get(env):
            return os.environ[env] + raw[len(tag):]
    return os.path.expanduser(raw)


def config_path(adapter: Dict[str, Any]) -> Path:
    """The file guard writes for this agent: its hook config, or guard's own extension file."""
    if adapter.get("kind") == "extension":
        return extension_path(adapter)
    return Path(user_path(adapter["config"]))


def guard_command() -> List[str]:
    """
    How the harness starts guard: the guard executable found now (absolute, so a harness with a
    different PATH still finds it), else this Python running the guard module.
    """
    found = shutil.which("guard")
    return [str(Path(found).resolve())] if found else [sys.executable, "-m", "guard.cli"]


SHELL_SAFE = re.compile(r"[\w\-.:/\\]+(?:~\d+[\w\-.:/\\]*)*")  # `~1` only as in an 8.3 short name (PROGRA~1)
SHELL_SPECIAL = set('"%$`^&|<>;()!\n\r')  # an apostrophe is plain text inside double quotes


def command_line(command: List[str]) -> str:
    """
    One command string, for harnesses that run a shell line instead of a program and its arguments.
    On Windows the shell may be cmd or PowerShell, and they read a quoted program differently
    (PowerShell needs `& "…"`, where cmd sees `&` as a command separator): so no part is quoted. A
    part that is not plain (a space, an apostrophe) is replaced by its 8.3 short name, which both
    read alike; a part with no plain short name, or with characters a shell interprets, is refused.
    """
    if os.name != "nt":
        return shlex.join(command)
    parts = []
    for part in command:
        if not SHELL_SAFE.fullmatch(part) and not SHELL_SPECIAL.intersection(part.replace("'", "")):
            part = _short_path(part) or part
        if not SHELL_SAFE.fullmatch(part):
            raise AdapterError(f"{part!r} is not a plain path both cmd and PowerShell run as it is; "
                               "install guard in a path without spaces or special characters")
        parts.append(part)
    return " ".join(parts)


def _short_path(path: str) -> Optional[str]:
    """The Windows 8.3 short name of an existing path (no spaces), or None when there is none."""
    try:
        import ctypes
        buffer = ctypes.create_unicode_buffer(1024)
        size = ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, 1024)
        return buffer.value if 0 < size < 1024 else None
    except (AttributeError, OSError):
        return None


def _entry(adapter: Dict[str, Any], hook: Dict[str, Any], command: List[str]) -> Any:
    args = command[1:] + [MARKER, hook["event"], "--agent", adapter["name"]]
    template = hook.get("entry", adapter.get("entry"))  # a hook may need its own shape (Antigravity)
    if template is None:  # Claude Code's shape
        entry: Dict[str, Any] = {}
        if hook.get("matcher"):
            entry["matcher"] = hook["matcher"]
        # exec form (command + args): no shell, no quoting problems on Windows
        entry["hooks"] = [{"type": "command", "command": command[0], "args": args}]
        return entry
    # The adapter's own shape: guard fills in what runs, the template only says where it goes
    values = {"{matcher}": hook.get("matcher"), "{program}": command[0], "{args}": args}
    if "{command_line}" in json.dumps(template):  # built only for a shell line: the exec form never needs quoting
        values["{command_line}"] = command_line([command[0]] + args)

    def fill(value: Any) -> Any:
        if isinstance(value, str) and value in values:
            return values[value]
        if isinstance(value, dict):
            return {k: fill(v) for k, v in value.items() if not (v == "{matcher}" and not hook.get("matcher"))}
        if isinstance(value, list):
            return [fill(v) for v in value]
        return value
    return fill(template)


def _is_guard_program(words: List[str]) -> bool:
    """The command starts guard: the guard executable, or Python running `-m guard.cli` (guard_command())."""
    if not words:
        return False
    program = Path(words[0].strip('"\'')).name.lower()
    if program in ("guard", "guard.exe"):
        return True
    # the module form only with a Python launcher (python, python3.11, pythonw.exe, py.exe)
    return bool(re.fullmatch(r"(python[\d.]*t?w?|py)(\.exe)?", program)) and words[1:3] == ["-m", "guard.cli"]


def _is_guard_hook(hook: Any, agent: Optional[str] = None, event: Optional[str] = None) -> bool:
    """
    Guard's handler, as guard writes it: guard itself runs with `agent-event <event> --agent <name>`.
    Someone else's program with the same words (`node audit.js agent-event stop …`) is not guard's.
    With `agent`, only the entries of that adapter (two adapters may share one config file); with
    `event`, only the entry for that guard event.
    """
    if not isinstance(hook, dict):
        return False
    if "args" in hook and not isinstance(hook["args"], list):
        return False
    if hook.get("args"):
        words = [str(hook.get("command", ""))] + [str(a) for a in hook["args"]]
    else:
        try:
            words = shlex.split(str(hook.get("command", "")), posix=os.name != "nt")
        except ValueError:
            return False
    if not _is_guard_program(words):
        return False
    # exactly what guard writes: the command ends in `agent-event <event> --agent <name>`, nothing after
    tail = words[-4:]
    if len(tail) == 4 and tail[0] == MARKER and tail[1] in _EVENTS and tail[2] == "--agent" and NAME.fullmatch(tail[3]):
        return (agent is None or tail[3] == agent) and (event is None or tail[1] == event)
    return False


def _without_guard(hooks: Dict[str, Any], agent: Optional[str] = None) -> Dict[str, Any]:
    """The hooks section with guard's entries (of `agent`, when given) taken out; everything else as it was."""
    out: Dict[str, Any] = {}
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            out[event] = entries
            continue
        kept = []
        for entry in entries:
            if _is_guard_hook(entry, agent):  # a flat entry (a command string or program and args) of guard's
                continue
            inner = entry.get("hooks") if isinstance(entry, dict) else None
            if isinstance(inner, list) and any(_is_guard_hook(h, agent) for h in inner):
                rest = [h for h in inner if not _is_guard_hook(h, agent)]
                if rest:  # someone else's hook shares the entry: keep it without guard's
                    kept.append({**entry, "hooks": rest})
                continue
            kept.append(entry)
        if kept:
            out[event] = kept
    return out


def hooks_path(adapter: Optional[Dict[str, Any]]) -> List[str]:
    """Where the config holds its hooks: `hooks` (Claude Code, Cursor, …) or deeper (ZCode's `hooks.events`)."""
    return str((adapter or {}).get("hooks_path") or "hooks").split(".")


def _at(data: Any, path: List[str]) -> Any:
    for part in path:
        if not isinstance(data, dict):
            return None
        data = data.get(part)
    return data


def _absent_at(data: Any, path: List[str]) -> bool:
    """Nothing at `path` (a key set to null is there: it is the user's value)."""
    for part in path:
        if not isinstance(data, dict) or part not in data:
            return True
        data = data[part]
    return False


def _set_at(data: Dict[str, Any], path: List[str], value: Any) -> Dict[str, Any]:
    """A copy of `data` with `value` at `path` (objects on the way are copied, never changed in place)."""
    out = dict(data)
    if len(path) == 1:
        out[path[0]] = value
        return out
    inner = out.get(path[0])
    out[path[0]] = _set_at(inner if isinstance(inner, dict) else {}, path[1:], value)
    return out


def _drop_at(data: Dict[str, Any], path: List[str]) -> Dict[str, Any]:
    """A copy of `data` without the key at `path`; objects left empty on the way go too."""
    out = dict(data)
    if len(path) == 1:
        out.pop(path[0], None)
        return out
    inner = out.get(path[0])
    if isinstance(inner, dict):
        rest = _drop_at(inner, path[1:])
        if rest:
            out[path[0]] = rest
        else:
            out.pop(path[0], None)
    return out


def read_config(path: Path, adapter: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise AdapterError(f"{path} cannot be read as JSON ({e}); fix it first, guard does not overwrite it") from e
    if not isinstance(data, dict):
        raise AdapterError(f"{path} is not a JSON object; guard does not overwrite it")
    where = hooks_path(adapter)
    for i in range(1, len(where) + 1):  # every object on the way to the hooks must be one
        value = _at(data, where[:i])
        if value is not None and not isinstance(value, dict):
            raise AdapterError(f"{path}: `{'.'.join(where[:i])}` is not an object; guard does not overwrite it")
    return data


def _held_parent(settings: Dict[str, Any], path: List[str], whole: bool = False) -> Optional[str]:
    """
    The first folder-like key on `path` (with `whole`, `path` itself too) the config holds as something
    other than an object (null, text), if any.
    """
    data: Any = settings
    for i, part in enumerate(path if whole else path[:-1]):
        if not isinstance(data, dict) or part not in data:
            return None
        data = data[part]
        if not isinstance(data, dict):
            return ".".join(path[:i + 1])
    return None


def with_guard(settings: Dict[str, Any], adapter: Dict[str, Any], command: Optional[List[str]] = None) -> Dict[str, Any]:
    """Settings with guard's entries replaced by the adapter's current ones (idempotent)."""
    command = command or guard_command()
    where = hooks_path(adapter)
    defaults = adapter.get("defaults") or {}
    for path, whole in [(where, True)] + [(k.split("."), False) for k in (defaults if isinstance(defaults, dict) else {})]:
        held = _held_parent(settings, path, whole)
        if held:  # e.g. `"hooks": null`: that value is the user's, and remove could not give it back
            raise AdapterError(f"`{held}` in the config is {json.dumps(_at(settings, held.split('.')))}, not an object: "
                               "guard does not replace it; set it to {} or remove it, then add again")
    current = _at(settings, where)
    hooks = _without_guard(current if isinstance(current, dict) else {}, adapter["name"])  # another adapter's stay
    for hook in adapter["hooks"]:
        if not isinstance(hooks.get(hook["harness_event"]), list):  # an event set to null holds no hook yet
            hooks[hook["harness_event"]] = []
        hooks[hook["harness_event"]].append(_entry(adapter, hook, command))
    out = _set_at(settings, where, hooks)
    # `defaults`: keys a config needs before its hooks run (Cursor's `version`, ZCode's `hooks.enabled`),
    # set only where the key is absent: a value the user chose is never overridden
    for key, value in (defaults.items() if isinstance(defaults, dict) else ()):
        if _absent_at(out, key.split(".")):
            out = _set_at(out, key.split("."), value)
    return out


def without_guard(settings: Dict[str, Any], agent: Optional[str] = None,
                  adapter: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    where = hooks_path(adapter)
    current = _at(settings, where)
    if not isinstance(current, dict):
        return dict(settings)
    hooks = _without_guard(current, agent)
    return _set_at(settings, where, hooks) if hooks else _drop_at(settings, where)


def switched_on(adapter: Dict[str, Any], before: Dict[str, Any]) -> List[str]:
    """The `defaults` guard turns on because the config has none (ZCode's hooks.enabled)."""
    defaults = adapter.get("defaults") or {}
    return [k for k, v in (defaults.items() if isinstance(defaults, dict) else ()) if v is True
            and _absent_at(before, k.split("."))]


def others_under(adapter: Dict[str, Any], settings: Dict[str, Any]) -> int:
    """How many hook entries in the config are not guard's (a switch guard turns on runs them too)."""
    current = _at(settings, hooks_path(adapter))
    if not isinstance(current, dict):
        return 0
    return sum(len(v) for v in _without_guard(current, adapter.get("name")).values() if isinstance(v, list))


def installed(adapter: Dict[str, Any]) -> bool:
    if adapter.get("kind") == "extension":
        return extension_installed(adapter)
    try:
        hooks = _at(read_config(config_path(adapter), adapter), hooks_path(adapter)) or {}
    except AdapterError:
        return False
    name = adapter.get("name")
    records = adapter.get("hooks")
    if not isinstance(name, str) or not isinstance(records, list) or not records or not all(
            isinstance(k, dict) and isinstance(k.get("harness_event"), str) and isinstance(k.get("event"), str)
            for k in records):
        return False  # a malformed record (no name, hooks: [{}]) runs nothing: `guard agent list` shows it
    def holds(value: Any, text: str) -> bool:  # the matcher, wherever the entry's shape puts it
        if isinstance(value, dict):
            return any(holds(v, text) for v in value.values())
        if isinstance(value, list):
            return any(holds(v, text) for v in value)
        return value == text

    def guards(entry: Any, record: Dict[str, Any]) -> bool:
        event = record["event"]
        if record.get("matcher") and not holds(entry, record["matcher"]):
            return False  # the user changed or removed the matcher: the tools it named are not covered
        return _is_guard_hook(entry, name, event) or (isinstance(entry, dict) and isinstance(entry.get("hooks"), list)
                                                      and any(_is_guard_hook(h, name, event) for h in entry["hooks"]))
    def entries(event: str) -> list:  # an event set to null or anything but a list holds no hook
        value = hooks.get(event) if isinstance(hooks, dict) else None
        return value if isinstance(value, list) else []
    try:
        config = read_config(config_path(adapter), adapter)
    except AdapterError:
        return False
    defaults = adapter.get("defaults") or {}
    if not isinstance(defaults, dict):
        return False  # an edited record: `guard agent list` shows it, `guard agent fix` rebuilds it
    for key, value in defaults.items():
        if value is True and _at(config, key.split(".")) is not True:
            return False  # the user switched the hooks off (ZCode's hooks.enabled): nothing runs
    return all(any(guards(e, k) for e in entries(k["harness_event"])) for k in records)


def dump(settings: Dict[str, Any]) -> str:
    return json.dumps(settings, indent=2, ensure_ascii=False) + "\n"


def adapter_diff(before: Dict[str, Any], after: Dict[str, Any]) -> str:
    """The change between two adapter records, as the user reviews it."""
    return "".join(difflib.unified_diff(dump(before).splitlines(keepends=True), dump(after).splitlines(keepends=True),
                                        "adapter (current)", "adapter (proposed)"))


def diff(path: Path, before: Dict[str, Any], after: Dict[str, Any]) -> str:
    old = dump(before).splitlines(keepends=True) if before or path.exists() else []
    return "".join(difflib.unified_diff(old, dump(after).splitlines(keepends=True), str(path), str(path)))


def write_config(path: Path, settings: Dict[str, Any]) -> Optional[Path]:
    """
    Write the harness config atomically. The first time guard changes an existing file, the
    original is kept as <file>.guard.bak (never overwritten later). Returns the backup path.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = path.with_name(path.name + ".guard.bak")
    made = None
    if path.exists() and not backup.exists():
        shutil.copy2(path, backup)
        made = backup
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="." + path.name + ".", suffix=".guard-tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(dump(settings))
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return made


def save_adapter(adapter: Dict[str, Any]) -> Path:
    path = adapters_dir() / f"{adapter['name']}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(adapter, indent=2) + "\n", encoding="utf-8")
    return path


def harness_event(adapter: Optional[Dict[str, Any]], event: str, payload: Dict[str, Any]) -> str:
    """The harness's name for this call: its own field, else the adapter's mapping."""
    name = payload.get("hook_event_name")
    if isinstance(name, str) and name:
        return name
    for hook in (adapter or {}).get("hooks", []):
        if hook.get("event") == event:
            return hook["harness_event"]
    return ""


def render(output: Optional[Dict[str, Any]], harness: str, decision: Decision) -> Tuple[str, str, int]:
    """
    (stdout, stderr, exit code) from the adapter's output rules. Without rules (no adapter), guard's
    own JSON: a block exits 2 with the reason on stderr. Values are filled in as text, never parsed.
    """
    reason = decision.reason
    rules = (output or {}).get(decision.action) if isinstance(output, dict) else None
    if not isinstance(rules, dict):
        out = json.dumps({"decision": decision.action, "reason": reason}) + "\n"
        return (out, reason + "\n", 2) if decision.action == "block" else (out, "", 0)
    rule = next((r for key, r in rules.items() if key != "*" and harness in key.split("|")), rules.get("*")) or {}

    def fill(value: Any) -> Any:
        if isinstance(value, str):
            return value.replace("{harness_event}", harness).replace("{reason}", reason)
        if isinstance(value, dict):
            return {k: fill(v) for k, v in value.items()}
        if isinstance(value, list):
            return [fill(v) for v in value]
        return value

    stdout = fill(rule.get("stdout", ""))
    stdout = json.dumps(stdout) + "\n" if isinstance(stdout, (dict, list)) else (stdout + "\n" if stdout else "")
    stderr = fill(rule.get("stderr", ""))
    return stdout, (stderr + "\n" if stderr else ""), int(rule.get("exit", 0))


NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}\Z")


