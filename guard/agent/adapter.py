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
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from guard.agent.events import EVENTS as _EVENTS
from guard.agent.events import Decision

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
BUILT_IN = {"claude-code": CLAUDE_CODE}


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


def config_path(adapter: Dict[str, Any]) -> Path:
    return Path(os.path.expanduser(adapter["config"]))


def guard_command() -> List[str]:
    """
    How the harness starts guard: the guard executable found now (absolute, so a harness with a
    different PATH still finds it), else this Python running the guard module.
    """
    found = shutil.which("guard")
    return [str(Path(found).resolve())] if found else [sys.executable, "-m", "guard.cli"]


def _entry(adapter: Dict[str, Any], hook: Dict[str, Any], command: List[str]) -> Dict[str, Any]:
    entry: Dict[str, Any] = {}
    if hook.get("matcher"):
        entry["matcher"] = hook["matcher"]
    # exec form (command + args): no shell, no quoting problems on Windows
    entry["hooks"] = [{"type": "command", "command": command[0],
                       "args": command[1:] + [MARKER, hook["event"], "--agent", adapter["name"]]}]
    return entry


def _is_guard_hook(hook: Any) -> bool:
    """Guard's handler, as guard writes it: its arguments end in `agent-event <event> --agent <name>`."""
    if not isinstance(hook, dict):
        return False
    words = [str(a) for a in hook.get("args") or []] or str(hook.get("command", "")).split()
    for i, word in enumerate(words):
        if word == MARKER and i + 3 < len(words) and words[i + 2] == "--agent" and words[i + 1] in _EVENTS:
            return True
    return False


def _without_guard(hooks: Dict[str, Any]) -> Dict[str, Any]:
    """The hooks section with guard's entries taken out; everything else exactly as it was."""
    out: Dict[str, Any] = {}
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            out[event] = entries
            continue
        kept = []
        for entry in entries:
            inner = entry.get("hooks") if isinstance(entry, dict) else None
            if isinstance(inner, list) and any(_is_guard_hook(h) for h in inner):
                rest = [h for h in inner if not _is_guard_hook(h)]
                if rest:  # someone else's hook shares the entry: keep it without guard's
                    kept.append({**entry, "hooks": rest})
                continue
            kept.append(entry)
        if kept:
            out[event] = kept
    return out


def read_config(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise AdapterError(f"{path} cannot be read as JSON ({e}); fix it first, guard does not overwrite it") from e
    if not isinstance(data, dict):
        raise AdapterError(f"{path} is not a JSON object; guard does not overwrite it")
    if "hooks" in data and not isinstance(data["hooks"], dict):
        raise AdapterError(f"{path}: `hooks` is not an object; guard does not overwrite it")
    return data


def with_guard(settings: Dict[str, Any], adapter: Dict[str, Any], command: Optional[List[str]] = None) -> Dict[str, Any]:
    """Settings with guard's entries replaced by the adapter's current ones (idempotent)."""
    command = command or guard_command()
    hooks = _without_guard(settings.get("hooks") or {})
    for hook in adapter["hooks"]:
        hooks.setdefault(hook["harness_event"], []).append(_entry(adapter, hook, command))
    return {**settings, "hooks": hooks}


def without_guard(settings: Dict[str, Any]) -> Dict[str, Any]:
    hooks = _without_guard(settings.get("hooks") or {})
    out = {k: v for k, v in settings.items() if k != "hooks"}
    if hooks:
        out["hooks"] = hooks
    return out


def installed(adapter: Dict[str, Any]) -> bool:
    try:
        hooks = read_config(config_path(adapter)).get("hooks") or {}
    except AdapterError:
        return False
    return all(any(_is_guard_hook(h) for e in hooks.get(k["harness_event"], []) if isinstance(e, dict)
                   for h in e.get("hooks") or []) for k in adapter["hooks"])


def dump(settings: Dict[str, Any]) -> str:
    return json.dumps(settings, indent=2, ensure_ascii=False) + "\n"


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
