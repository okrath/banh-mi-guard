"""
Adapters guard ships for the popular agents, each checked against the agent's own source, local
install or docs (sources and dates in each comment; the research is in the repository's plan
reports). What could not be checked end to end is named in the adapter's `limits`, which
`guard agent add` shows before the diff.
"""

from __future__ import annotations

from typing import Any, Dict

# Guard's answer rules shared by harnesses that clone Claude Code's contract
_CLAUDE_LIKE_BLOCK = {"stdout": {"decision": "block", "reason": "{reason}"}}

# OpenAI Codex CLI: openai/codex main (codex-rs/hooks, codex-rs/config/src/hook_config.rs), checked
# 2026-09-28 against codex-cli 0.156.1. Hooks are on by default; `~/.codex/hooks.json` is JSON (never
# config.toml). The decision is read from stdout JSON only: exit codes do not block.
CODEX: Dict[str, Any] = {
    "name": "codex",
    "title": "OpenAI Codex CLI",
    "detect": "~/.codex",
    "config": "~/.codex/hooks.json",
    "hooks": [
        {"harness_event": "UserPromptSubmit", "event": "prompt"},
        {"harness_event": "PreToolUse", "matcher": "Bash|apply_patch", "event": "before-edit"},
        {"harness_event": "PostToolUse", "matcher": "Bash|apply_patch", "event": "after-bash"},
        {"harness_event": "Stop", "event": "stop"},
    ],
    # 600 s: a stop may wait for a running guard post (up to 540 s) before it answers
    "entry": {"matcher": "{matcher}", "hooks": [{"type": "command", "command": "{command_line}", "timeout": 600}]},
    "can_block": ["prompt", "before-edit", "stop"],
    "protection_note": "an apply_patch edit outside the scope is reported right after it, not refused before",
    "output": {
        "allow": {"*": {"exit": 0}},
        "notify": {
            "PreToolUse|PostToolUse|UserPromptSubmit": {
                "stdout": {"hookSpecificOutput": {"hookEventName": "{harness_event}", "additionalContext": "{reason}"}}},
            "*": {"stdout": {"systemMessage": "{reason}"}},
        },
        "block": {"*": _CLAUDE_LIKE_BLOCK},
    },
    "limits": [
        "Codex edits files through apply_patch, which names no file before the edit: an edit outside the "
        "scope is reported right after it, not blocked before it.",
        "Codex asks you to trust a new hook once (its hook review screen, or /hooks).",
    ],
}

# Cursor (IDE and cursor-agent CLI): the installed cursor-agent 2026.09.15 bundle and
# cursor.com/docs/agent/hooks, checked 2026-09-28. Flat entries, `version: 1` required; shell commands
# and tool calls are separate events; a stop is refused with `followup_message`, and `loop_count`
# (a number) says how often that already happened.
CURSOR: Dict[str, Any] = {
    "name": "cursor",
    "title": "Cursor",
    "detect": "~/.cursor",
    "config": "~/.cursor/hooks.json",
    "defaults": {"version": 1},
    "hooks": [
        {"harness_event": "beforeSubmitPrompt", "event": "prompt"},
        {"harness_event": "preToolUse", "matcher": "Write|Delete", "event": "before-edit"},
        {"harness_event": "beforeShellExecution", "event": "before-edit"},
        {"harness_event": "postToolUse", "event": "after-bash"},
        {"harness_event": "afterShellExecution", "event": "after-bash"},
        {"harness_event": "stop", "event": "stop"},
    ],
    "entry": {"type": "command", "command": "{command_line}", "matcher": "{matcher}", "timeout": 600},
    # no loop field: Cursor's loop_count counts refused stops per conversation, not per turn (a second
    # stop later in the same conversation would pass); Cursor's own loop_limit (5) bounds a refused stop
    "fields": {"command": ["command", "tool_input.command"]},
    "protection_note": "Cursor asks a refused stop again at most 5 times per conversation, then lets it stop",
    "can_block": ["prompt", "before-edit", "stop"],
    "output": {
        "allow": {"*": {"exit": 0}},
        "notify": {
            "preToolUse|postToolUse|afterShellExecution|beforeSubmitPrompt": {"stdout": {"additional_context": "{reason}"}},
            "*": {"stdout": {"user_message": "{reason}"}},
        },
        "block": {
            "preToolUse|beforeShellExecution": {"stdout": {"permission": "deny", "user_message": "{reason}",
                                                           "agent_message": "{reason}"}},
            "beforeSubmitPrompt": {"stdout": {"continue": False, "user_message": "{reason}"}},
            "stop": {"stdout": {"followup_message": "{reason}"}},
            "*": {"stdout": {"additional_context": "{reason}"}},
        },
    },
    "limits": ["A refused stop is asked again at most 5 times per conversation (Cursor's own loop_limit).",
               "cursor-agent (the CLI) does not send beforeSubmitPrompt: the reminder to run guard pre appears "
               "only in the Cursor app; edits and stops are guarded in both."],
}

# Grok Build (xai-org/grok-build, crates/codegen/xai-grok-hooks) and docs.x.ai/build/features/hooks,
# checked 2026-09-28. Every *.json in ~/.grok/hooks is a hook file: guard owns guard.json there.
# Claude tool names in a matcher also match Grok's own; user-level hooks need no trust step.
GROK: Dict[str, Any] = {
    "name": "grok",
    "title": "Grok Build (xAI)",
    "detect": "~/.grok",
    "config": "~/.grok/hooks/guard.json",
    "hooks": [
        {"harness_event": "UserPromptSubmit", "event": "prompt"},
        {"harness_event": "PreToolUse", "matcher": "Edit|Write|MultiEdit|NotebookEdit|Bash|PowerShell", "event": "before-edit"},
        {"harness_event": "PostToolUse", "matcher": "Bash|PowerShell", "event": "after-bash"},
        {"harness_event": "Stop", "event": "stop"},
    ],
    "entry": {"matcher": "{matcher}", "hooks": [{"type": "command", "command": "{command_line}", "timeout": 600}]},
    "fields": {"loop": ["stopHookActive", "stop_hook_active"], "tool": ["tool_name", "toolName"],
               "command": ["tool_input.command", "toolInput.command"], "file_paths": ["tool_input.file_path", "toolInput.file_path"],
               "call_id": ["tool_use_id", "toolUseId"]},
    "can_block": ["prompt", "before-edit", "stop"],
    "output": {
        "allow": {"*": {"exit": 0}},
        "notify": {"PostToolUse|post_tool_use": {"stdout": {"additionalContext": "{reason}"}}, "*": {"stderr": "{reason}"}},
        # exit 2 refuses on every gate whatever the event is called (`PreToolUse` or `pre_tool_use`)
        "block": {"*": {"stdout": {"decision": "deny", "reason": "{reason}"}, "stderr": "{reason}", "exit": 2}},
    },
    "limits": [],
}

# Gemini CLI: geminicli.com/docs/hooks (reference, writing-hooks) and the v0.26.0 release discussion,
# checked 2026-09-28 (docs only: no gemini binary on the machine it was checked on). AfterAgent is
# the stop; exit 2 with the reason on stderr blocks on every event.
GEMINI: Dict[str, Any] = {
    "name": "gemini",
    "title": "Gemini CLI",
    "detect": "~/.gemini",
    "config": "~/.gemini/settings.json",
    "hooks": [
        {"harness_event": "BeforeAgent", "event": "prompt"},
        {"harness_event": "BeforeTool", "matcher": "run_shell_command|write_file|replace", "event": "before-edit"},
        {"harness_event": "AfterTool", "matcher": "run_shell_command", "event": "after-bash"},
        {"harness_event": "AfterAgent", "event": "stop"},
    ],
    "entry": {"matcher": "{matcher}", "hooks": [{"type": "command", "command": "{command_line}", "timeout": 600000}]},
    "can_block": ["prompt", "before-edit", "stop"],
    "output": {
        "allow": {"*": {"exit": 0}},
        "notify": {
            "BeforeTool|AfterTool|BeforeAgent": {"stdout": {"hookSpecificOutput": {"additionalContext": "{reason}"}}},
            "*": {"stdout": {"systemMessage": "{reason}"}},
        },
        "block": {"*": {"stderr": "{reason}", "exit": 2}},
    },
    "limits": ["Checked against Gemini CLI's documentation only: run guard agent test gemini after adding it."],
}

# Google Antigravity: antigravity.google/docs/hooks, atamel.dev (2026-07-16) and a hooks.json already
# present on the machine it was checked on, 2026-09-28. One global file for the app, IDE and CLI;
# PreInvocation/Stop take a bare handler, PreToolUse/PostToolUse a matcher group. Its stop signal
# (`fullyIdle`) is not a count of refused stops, so a refused stop could loop: the stop stays a reminder.
ANTIGRAVITY: Dict[str, Any] = {
    "name": "antigravity",
    "title": "Google Antigravity",
    "detect": "~/.gemini/config",
    "config": "~/.gemini/config/hooks.json",
    "hooks": [
        {"harness_event": "PreInvocation", "event": "prompt", "entry": {"type": "command", "command": "{command_line}"}},
        {"harness_event": "PreToolUse", "matcher": ".*", "event": "before-edit"},
        {"harness_event": "PostToolUse", "matcher": ".*", "event": "after-bash"},
        {"harness_event": "Stop", "event": "stop", "entry": {"type": "command", "command": "{command_line}"}},
    ],
    "entry": {"matcher": "{matcher}", "hooks": [{"type": "command", "command": "{command_line}"}]},
    # argument names from its Windsurf lineage (TargetFile, CommandLine), not verified live: when they do
    # not match, a tool names no file and is measured after it runs instead (a wrong name never blocks)
    "fields": {"cwd": ["cwd", "workspacePaths.0"], "tool": ["toolCall.name"], "file_paths": ["toolCall.args.TargetFile"],
               "command": ["toolCall.args.CommandLine"], "call_id": ["stepIdx"]},
    # an edit outside the task is refused (PreToolUse `decision: deny`); a refused stop is left out (see limits)
    "can_block": ["before-edit"],
    "protection_note": "an edit is refused only when Antigravity names its file the way guard reads it (not verified live)",
    "output": {
        "allow": {"*": {"exit": 0}},
        # no notification field of Antigravity's is verified: the reason goes to stderr, which a hook's
        # log keeps, on exit 0, which never refuses anything
        "notify": {"*": {"stderr": "{reason}", "exit": 0}},
        "block": {"PreToolUse": {"stdout": {"decision": "deny", "reason": "{reason}"}}, "*": {"exit": 0}},
    },
    "limits": [
        "Antigravity's stop cannot be refused safely yet: guard reports unapproved edits, the Git pre-commit "
        "hook still blocks the commit.",
        "Antigravity's tool arguments were not verified live: an edit guard cannot read before it runs is "
        "measured right after it.",
    ],
}

# ZCode (zai-org/ZCode, apps/zcode-cli packages contracts/core/adapters), checked 2026-09-28 against
# the install on the machine it was checked on. Hooks live at hooks.events in ~/.zcode/cli/config.json
# and run only with hooks.enabled; type "process" runs guard directly (no shell).
ZCODE: Dict[str, Any] = {
    "name": "zcode",
    "title": "ZCode (Z.ai)",
    "detect": "~/.zcode",
    "config": "~/.zcode/cli/config.json",
    "hooks_path": "hooks.events",
    "defaults": {"hooks.enabled": True},
    "hooks": [
        {"harness_event": "UserPromptSubmit", "event": "prompt"},
        {"harness_event": "PreToolUse", "matcher": "Edit|Write|Bash", "event": "before-edit"},
        {"harness_event": "PostToolUse", "matcher": "Bash", "event": "after-bash"},
        {"harness_event": "Stop", "event": "stop"},
    ],
    "entry": {"matcher": "{matcher}", "hooks": [{"type": "process", "command": "{program}", "args": "{args}"}]},
    "fields": {"tool": ["toolName"], "command": ["toolInput.command"], "file_paths": ["toolInput.file_path"],
               "call_id": ["toolCallId"], "loop": ["stopHookActive"]},
    "can_block": ["prompt", "before-edit", "stop"],
    "output": {
        "allow": {"*": {"exit": 0}},
        "notify": {"*": {"stdout": {"hookSpecificOutput": {"hookEventName": "{harness_event}", "additionalContext": "{reason}"}}}},
        "block": {"*": _CLAUDE_LIKE_BLOCK},
    },
    "limits": [],
}

# In-process agents run no command per event: guard installs one file of its own that calls
# `guard agent-event <event> --agent <name>` with guard's field names and reads guard's JSON answer
# (no output rules: `render` prints {"decision", "reason"}). The first line marks the file as guard's.
EXTENSION_MARKER = "// guard-hook: written by guard (guard agent add); guard agent remove takes it out"

_CALL_GUARD = r"""
import { spawn } from "node:child_process";

const GUARD = __GUARD__;  // guard's own command, filled in by guard
const AGENT = __AGENT__;
const READS = __READ_TOOLS__;  // guard's read-only tools: never refused because guard could not answer

// Asks guard. When guard cannot answer (missing, crashed, unreadable, past 600 s) the answer is
// {failed}: an edit is then refused and anything else goes on with a warning (see `failure`)
function callGuard(event, payload) {
  return new Promise((resolve) => {
    let out = "";
    let child;
    try {
      child = spawn(GUARD[0], [...GUARD.slice(1), "agent-event", event, "--agent", AGENT],
                    { stdio: ["pipe", "pipe", "ignore"], windowsHide: true });
    } catch (e) { resolve({ failed: `guard did not start: ${e?.message ?? e}` }); return; }
    // a stop may wait for a running guard post (up to 540 s): past 600 s guard is given up on
    const timer = setTimeout(() => { try { child.kill(); } catch {} resolve({ failed: "guard did not answer in 600 s" }); },
                             600000);
    child.stdout.on("data", (d) => { out += d; });
    child.stdin.on("error", () => {});  // guard gone before reading: reported by close, never an error here
    child.on("error", (e) => { clearTimeout(timer); resolve({ failed: `guard did not start: ${e?.message ?? e}` }); });
    child.on("close", () => {
      clearTimeout(timer);
      try {
        const r = JSON.parse(out);
        resolve(r && typeof r === "object" ? r : { failed: "guard's answer is not an object" });
      } catch { resolve({ failed: "guard's answer is not JSON" }); }
    });
    child.stdin.end(JSON.stringify({ event, ...payload }));
  });
}

// what the user is told when guard could not answer
const failure = (r) => (r.failed ? `guard could not check this (${r.failed}): run \`guard doctor\`` : undefined);
const reads = (tool) => READS.includes(String(tool ?? "").toLowerCase());

const text = (v) => (typeof v === "string" ? v : undefined);
"""

# pi (earendil-works/pi, packages/coding-agent src/core/extensions/types.ts) and omp (can1357/oh-my-pi,
# docs/extensions.md, docs/skills/authoring-hooks.md), checked 2026-09-28: `tool_call` can block with
# {block, reason}; omp's `session_stop` refuses a stop with {decision: "block", reason}; pi has no
# event that can refuse a stop.
_PI_EXTENSION = EXTENSION_MARKER + _CALL_GUARD + r"""
export default function (pi) {
  pi.on("before_agent_start", async (event, ctx) => {
    const r = await callGuard("prompt", { cwd: ctx.cwd, prompt: text(event.prompt) });
    if (r.failed) ctx.ui?.notify?.(failure(r), "warning");
    if (r.decision === "notify" && r.reason) ctx.ui?.notify?.(r.reason, "warning");
  });

  pi.on("tool_call", async (event, ctx) => {
    const input = event.input ?? {};
    const r = await callGuard("before-edit", {
      cwd: ctx.cwd, tool: event.toolName, file_path: text(input.path), command: text(input.command),
      call_id: event.toolCallId,
    });
    if (r.failed && !reads(event.toolName)) return { block: true, reason: failure(r) };
    if (r.failed) ctx.ui?.notify?.(failure(r), "warning");
    if (r.decision === "block") return { block: true, reason: r.reason };
    if (r.decision === "notify" && r.reason) ctx.ui?.notify?.(r.reason, "warning");
  });

  pi.on("tool_result", async (event, ctx) => {
    const input = event.input ?? {};
    const r = await callGuard("after-bash", {
      cwd: ctx.cwd, tool: event.toolName, command: text(input.command), call_id: event.toolCallId,
    });
    if (r.failed) ctx.ui?.notify?.(failure(r), "warning");
    if (r.decision === "notify" && r.reason) ctx.ui?.notify?.(r.reason, "warning");
  });
__STOP__}
"""

_OMP_STOP = r"""
  // omp keeps a refusal in force until guard allows the stop: after one refusal the next stop says
  // so (loop), as Claude Code's stop_hook_active does, and guard lets it through instead of looping
  let refusedStop = false;
  pi.on("session_stop", async (_event, ctx) => {
    const r = await callGuard("stop", { cwd: ctx.cwd, loop: refusedStop });
    if (r.failed) ctx.ui?.notify?.(failure(r), "warning");  // a stop is never held by guard's own failure
    if (r.decision === "block" && !refusedStop) {
      refusedStop = true;
      return { decision: "block", reason: r.reason || "guard: finish the guard post first" };
    }
    refusedStop = false;
  });
"""

# opencode (sst/opencode dev, packages/plugin/src/index.ts), checked 2026-09-28: a plugin blocks a
# tool call by throwing in `tool.execute.before`; there is no hook that can refuse a stop.
_OPENCODE_PLUGIN = EXTENSION_MARKER + _CALL_GUARD + r"""
export const GuardHook = async ({ directory, worktree }) => {
  const cwd = worktree || directory;
  return {
    "tool.execute.before": async (input, output) => {
      const args = output?.args ?? {};
      const r = await callGuard("before-edit", {
        cwd, tool: input.tool, file_path: text(args.path) ?? text(args.filePath), command: text(args.command),
        call_id: input.callID,
      });
      if (r.failed && !reads(input.tool)) throw new Error(failure(r));
      if (r.decision === "block") throw new Error(r.reason || "Blocked by guard");
    },
    // the tool's output is what the agent reads next: guard's warning goes at its end
    "tool.execute.after": async (input, output) => {
      const r = await callGuard("after-bash", { cwd, tool: input.tool, call_id: input.callID });
      const note = failure(r) ?? (r.decision === "notify" ? r.reason : undefined);
      if (note && output && typeof output.output === "string") output.output += `\n\n${note}`;
    },
  };
};

export default { id: "guard-hook", server: GuardHook };
"""

OMP: Dict[str, Any] = {
    "name": "omp", "title": "Oh My Pi (omp)", "kind": "extension",
    "detect": "~/.omp", "install": "~/.omp/agent/extensions/guard-hook.ts", "source": "pi-omp",
    "hooks": [{"harness_event": "before_agent_start", "event": "prompt"},
              {"harness_event": "tool_call", "event": "before-edit"},
              {"harness_event": "tool_result", "event": "after-bash"},
              {"harness_event": "session_stop", "event": "stop"}],
    "can_block": ["before-edit", "stop"],
    "limits": ["omp loads extensions at start: restart omp after adding guard."],
}
PI: Dict[str, Any] = {
    "name": "pi", "title": "pi (earendil-works)", "kind": "extension",
    "detect": "~/.pi", "install": "~/.pi/agent/extensions/guard-hook.ts", "source": "pi",
    "hooks": [{"harness_event": "before_agent_start", "event": "prompt"},
              {"harness_event": "tool_call", "event": "before-edit"},
              {"harness_event": "tool_result", "event": "after-bash"}],
    "can_block": ["before-edit"],
    "limits": ["pi has no event that can refuse a stop: guard blocks edits outside the task, and the Git "
               "pre-commit hook still blocks an unapproved commit.",
               "pi loads extensions at start: restart pi after adding guard."],
}
OPENCODE: Dict[str, Any] = {
    "name": "opencode", "title": "opencode", "kind": "extension",
    "detect": "~/.config/opencode", "install": "~/.config/opencode/plugins/guard-hook.js", "source": "opencode",
    "hooks": [{"harness_event": "tool.execute.before", "event": "before-edit"},
              {"harness_event": "tool.execute.after", "event": "after-bash"}],
    "can_block": ["before-edit"],
    "limits": ["opencode has no plugin hook that can refuse a stop or a prompt: guard blocks edits outside the "
               "task, and the Git pre-commit hook still blocks an unapproved commit.",
               "opencode loads plugins at start: restart opencode after adding guard."],
}


# How each extension is written: guard's command and the agent's name are filled in by guard
EXTENSION_SOURCES: Dict[str, str] = {
    "pi": _PI_EXTENSION.replace("__STOP__", ""),
    "pi-omp": _PI_EXTENSION.replace("__STOP__", _OMP_STOP),
    "opencode": _OPENCODE_PLUGIN,
}

ADAPTERS: Dict[str, Dict[str, Any]] = {a["name"]: a for a in (
    CODEX, CURSOR, GROK, GEMINI, ANTIGRAVITY, ZCODE, OMP, PI, OPENCODE)}
