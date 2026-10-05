"""
Whether an adapter record is safe to install: a user-level config path, entry templates that can only run
guard, block rules the harness reads as a refusal, and well-formed values.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, List, Optional

from guard.agent.adapter import BUILT_IN, NAME, USER_ROOTS, user_path
from guard.agent.events import EVENTS as _EVENTS

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
