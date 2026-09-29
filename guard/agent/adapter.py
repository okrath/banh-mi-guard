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
from guard.agent.builtins import ADAPTERS as _SHIPPED, EXTENSION_MARKER, EXTENSION_SOURCES  # noqa: E402

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


def test_record_path(name: str) -> Path:
    """What the last `guard agent test <name>` saw (doctor shows it)."""
    return adapters_dir() / f"{name}.test.json"


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


def with_guard(settings: Dict[str, Any], adapter: Dict[str, Any], command: Optional[List[str]] = None) -> Dict[str, Any]:
    """Settings with guard's entries replaced by the adapter's current ones (idempotent)."""
    command = command or guard_command()
    where = hooks_path(adapter)
    current = _at(settings, where)
    hooks = _without_guard(current if isinstance(current, dict) else {}, adapter["name"])  # another adapter's stay
    for hook in adapter["hooks"]:
        if not isinstance(hooks.get(hook["harness_event"]), list):  # an event set to null holds no hook yet
            hooks[hook["harness_event"]] = []
        hooks[hook["harness_event"]].append(_entry(adapter, hook, command))
    out = _set_at(settings, where, hooks)
    # `defaults`: keys a config needs before its hooks run (Cursor's `version`, ZCode's `hooks.enabled`),
    # set only where the key is absent: a value the user chose is never overridden
    defaults = adapter.get("defaults") or {}
    for key, value in (defaults.items() if isinstance(defaults, dict) else ()):
        if _at(out, key.split(".")) is None:
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
WORD = re.compile(r"^[A-Za-z][\w.-]{0,39}\Z")  # a harness event name, or a literal in an entry template
RULE_KEYS = {"stdout", "stderr", "exit"}
# Not a reason to refuse: guard prints the entries for the user to add to a TOML or YAML config
NOT_JSON = "config: guard only edits JSON configs (other formats: add the entries by hand)"


def _inside_home(raw: str) -> bool:
    """
    A user-level path: `~/…` or absolute, inside a dot folder of the home folder (`~/.cursor/…`,
    `~/.config/…`) and never inside a Git repository: a relative path would follow the current
    directory, and `~/work/project/.cursor/hooks.json` is a project's file, not the user's.
    """
    raw = user_path(raw)
    if not (raw.startswith("~/") or raw.startswith("~\\") or Path(raw).is_absolute()):
        return False
    try:
        home = Path(os.path.expanduser("~")).resolve()
        path = Path(os.path.expanduser(raw)).resolve()
        # Windows' own per-user settings folders count wherever a redirected profile puts them
        app_data = [Path(os.environ[e]).resolve() for e in USER_ROOTS if os.environ.get(e)]
    except OSError:
        return False
    if not any(path.is_relative_to(a) and path != a for a in app_data):  # otherwise a dot folder of home
        if not path.is_relative_to(home):
            return False
        rel = path.relative_to(home)
        if not rel.parts or not rel.parts[0].startswith("."):
            return False
    # every folder above the file, the root and what holds it included: a home folder (or an
    # %APPDATA% moved into a checkout) kept in Git makes every file below it a repository's file
    return not any((folder / ".git").exists() for folder in path.parents)


def _is_number(v: Any) -> bool:
    import math
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


# The only keys an entry template may hold, and what each may be: what runs is always guard's own
# command, filled in by guard. Any other key (`exec`, `script`, …) is refused, whatever a harness
# does with it, so no unknown field can ever carry a command.
ENTRY_KEYS = {
    "type": lambda v: isinstance(v, str) and bool(WORD.match(v)),
    "command": lambda v: v in ("{command_line}", "{program}"),
    "args": lambda v: v == "{args}",
    "matcher": lambda v: v == "{matcher}",
    "timeout": _is_number,
    "loop_limit": _is_number,
    "failClosed": lambda v: isinstance(v, bool),
    "enabled": lambda v: v is True,  # `false` would install a hook the harness never runs
}
# Keys a config may need before its hooks run (Cursor's `version`, ZCode's `hooks.enabled`), and where
# hooks may live: both closed lists, so a proposal can never point guard at another part of a config
DEFAULT_KEYS = {"version": _is_number, "hooks.enabled": lambda v: v is True}
HOOKS_PATHS = ("hooks", "hooks.events")


def _entry_problem(value: Any, where: str) -> Optional[str]:
    """
    Why an entry template is refused, or None: an object built only from ENTRY_KEYS, where `command`
    is "{command_line}", or "{program}" with `"args": "{args}"` beside it; a nested `hooks` list
    holds entries of the same kind (Claude Code's shape).
    """
    if not isinstance(value, dict):
        return f"{where}: one JSON object (a hook entry)"
    for k, v in value.items():
        at = f"{where}.{k}"
        if k == "hooks":
            if not isinstance(v, list) or not v:
                return f"{at}: a list of hook entries"
            problem = next((p for i, e in enumerate(v) if (p := _entry_problem(e, f"{at}[{i}]"))), None)
            if problem:
                return problem
        elif k not in ENTRY_KEYS:
            return f"{at}: not a hook entry key guard accepts ({', '.join(sorted(ENTRY_KEYS))}, hooks)"
        elif not ENTRY_KEYS[k](v):
            return f"{at}: {str(v)[:60]!r} is not allowed here"
    if value.get("command") == "{program}" and value.get("args") != "{args}":
        return f'{where}.command: "{{program}}" needs "args": "{{args}}" beside it'
    if "args" in value and value.get("command") != "{program}":
        return f'{where}.args: "{{args}}" goes beside "command": "{{program}}"'
    return None


def _runs_guard(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    return value.get("command") in ("{command_line}", "{program}") or any(
        _runs_guard(e) for e in value.get("hooks") or [] if isinstance(value.get("hooks"), list))


def _defaults_problem(value: Any) -> Optional[str]:
    if not isinstance(value, dict):
        return "defaults: an object of top-level keys"
    for k, v in value.items():
        if k not in DEFAULT_KEYS or not DEFAULT_KEYS[k](v):
            return f"defaults.{k}: not a top-level key guard accepts ({', '.join(DEFAULT_KEYS)})"
    return None


def _block_problems(hooks: List[Any], can_block: Any, block: Any) -> List[str]:
    """
    Every harness event of a guard event in can_block has a block rule (its own, or `*`) that the
    harness reads as a refusal (see _refuses). Without one, guard's refusal would reach the harness
    as silence, or as `{"decision": "allow"}`, which it reads as allowed.
    """
    refusing = {e for e in can_block if isinstance(e, str)} if isinstance(can_block, list) else set()
    rules = block if isinstance(block, dict) else {}
    problems = []
    for hook in hooks:
        if not isinstance(hook, dict) or not isinstance(hook.get("event"), str) or hook["event"] not in refusing \
                or not isinstance(hook.get("harness_event"), str):
            continue
        harness = hook["harness_event"]
        rule = next((r for k, r in rules.items() if k != "*" and harness in str(k).split("|")), rules.get("*"))
        if not _refuses(rule):
            problems.append(f"output.block: nothing refuses {harness} (can_block has {hook['event']}): give it a "
                            'non-zero exit, or stdout saying "block"/"deny" (or `"continue": false`), and no "allow"')
    return sorted(set(problems))


REFUSAL_WORDS = {"block", "deny"}
ALLOWING_WORDS = {"allow", "approve", "accept"}
REFUSAL_KEYS = {"followup_message"}  # Cursor keeps a stop going by giving the agent a follow-up


def _refuses(rule: Any) -> bool:
    """
    A block rule the harness reads as a refusal: a non-zero exit, or stdout holding "block"/"deny",
    `"continue": false` or a follow-up message, with no allowing word anywhere in it.
    """
    if not isinstance(rule, dict):
        return False
    pairs: List[Any] = []

    def walk(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                walk(v, str(k))
        elif isinstance(value, list):
            for v in value:
                walk(v, key)
        else:
            pairs.append((key, value))

    walk(rule.get("stdout"))
    words = {str(v).strip().lower() for _, v in pairs if isinstance(v, str)}
    if words & ALLOWING_WORDS or any(k == "continue" and v is True for k, v in pairs):
        return False
    exit_code = rule.get("exit", 0)
    if isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code != 0:
        return True
    return (bool(words & REFUSAL_WORDS) or any(k == "continue" and v is False for k, v in pairs)
            or any(k in REFUSAL_KEYS for k, _ in pairs))


def _rule_ok(rule: Any) -> bool:
    return (isinstance(rule, dict) and set(rule) <= RULE_KEYS
            and isinstance(rule.get("exit", 0), int) and not isinstance(rule.get("exit", 0), bool)
            and 0 <= rule.get("exit", 0) <= 255
            and isinstance(rule.get("stderr", ""), str) and isinstance(rule.get("stdout", ""), (str, dict, list))
            and len(json.dumps(rule)) <= 2000)


def validate_adapter(adapter: Any) -> List[str]:
    """
    Why a proposed adapter cannot be installed (empty: it can). An adapter is data only: it maps a
    harness's events, fields and answers onto guard's; it never decides what runs or what is allowed.
    """
    from guard.agent.events import DEFAULT_FIELDS
    if not isinstance(adapter, dict):
        return ["the adapter is not a JSON object"]
    errors: List[str] = []
    for key in ("kind", "install", "source", "protection_note"):  # only an adapter shipped with guard installs a file
        if key in adapter:
            errors.append(f"{key}: only built-in adapters use it")
    name = adapter.get("name")
    if not isinstance(name, str) or not NAME.match(name):
        errors.append("name: lower-case letters, digits and dashes, up to 40")
    elif name in BUILT_IN:
        errors.append(f"name: {name} is built in")
    if not isinstance(adapter.get("title"), str) or not 0 < len(adapter["title"]) <= 60:
        errors.append("title: a short text")
    config = adapter.get("config")
    if not isinstance(config, str) or not _inside_home(config):
        errors.append("config: a path inside your home folder")
    elif not config.endswith(".json"):
        errors.append(NOT_JSON)
    if "detect" in adapter and (not isinstance(adapter["detect"], str) or not _inside_home(adapter["detect"])):
        errors.append("detect: a path inside your home folder")

    hooks = adapter.get("hooks")
    if not isinstance(hooks, list) or not hooks:
        errors.append("hooks: a non-empty list")
        hooks = []
    for i, hook in enumerate(hooks):
        if not isinstance(hook, dict) or not isinstance(hook.get("harness_event"), str) or not WORD.match(hook["harness_event"]):
            errors.append(f"hooks[{i}].harness_event: the harness's event name")
        elif not isinstance(hook.get("event"), str) or hook["event"] not in _EVENTS:
            errors.append(f"hooks[{i}].event: one of {', '.join(_EVENTS)}")
        elif "matcher" in hook and (not isinstance(hook["matcher"], str) or len(hook["matcher"]) > 200):
            errors.append(f"hooks[{i}].matcher: a short text")
        elif "entry" in hook:  # this hook's own shape: held to the same rules as the adapter's
            problem = _entry_problem(hook["entry"], f"hooks[{i}].entry")
            if problem or not _runs_guard(hook["entry"]):
                errors.append(problem or f'hooks[{i}].entry: needs "command": "{{command_line}}" or "{{program}}"')
    if adapter.get("hooks_path", "hooks") not in HOOKS_PATHS:
        errors.append(f"hooks_path: one of {', '.join(HOOKS_PATHS)}")
    # only text values reach the sets below: a list or object in the proposal is an error, not a crash
    events = {h["event"] for h in hooks if isinstance(h, dict) and isinstance(h.get("event"), str)}
    can_block = adapter.get("can_block", [])
    if not isinstance(can_block, list) or not all(isinstance(e, str) for e in can_block) or not set(can_block) <= events:
        errors.append("can_block: events the adapter hooks")

    fields = adapter.get("fields", {})
    if not isinstance(fields, dict) or any(
        k not in DEFAULT_FIELDS or not isinstance(v, list) or not all(isinstance(p, str) and len(p) <= 100 for p in v)
        for k, v in fields.items()
    ):
        errors.append(f"fields: lists of payload paths for {', '.join(DEFAULT_FIELDS)}")

    output = adapter.get("output")
    if not isinstance(output, dict) or not output or not set(output) <= {"allow", "notify", "block"}:
        errors.append("output: rules for allow, notify and block")
    else:
        for action, rules in output.items():
            if not isinstance(rules, dict) or not all(isinstance(k, str) and _rule_ok(r) for k, r in rules.items()):
                errors.append(f"output.{action}: harness events mapped to {{stdout, stderr, exit}}")
        errors.extend(_block_problems(hooks, can_block, output.get("block")))

    if "entry" not in adapter:  # only a built-in adapter may use Claude Code's shape by default
        errors.append("entry: the JSON of one hook entry as the config file holds it")
    else:
        problem = _entry_problem(adapter["entry"], "entry")
        if problem:
            errors.append(problem)
        elif not _runs_guard(adapter["entry"]):
            errors.append('entry: needs "command": "{command_line}", or "command": "{program}" with "args": "{args}"')
    limits = adapter.get("limits", [])
    if not isinstance(limits, list) or len(limits) > 5 or not all(
            isinstance(t, str) and len(t) <= 300 and t.isprintable() for t in limits):
        errors.append("limits: up to 5 short printable sentences")  # shown before the diff: never markup or escapes
    if "defaults" in adapter:
        problem = _defaults_problem(adapter["defaults"])
        if problem:
            errors.append(problem)
        elif "hooks.enabled" in adapter["defaults"] and adapter.get("hooks_path") != "hooks.events":
            errors.append("defaults.hooks.enabled: only with hooks_path hooks.events (it would sit among the event lists)")
    return errors
