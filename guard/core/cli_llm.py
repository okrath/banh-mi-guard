"""
The LLM through the user's own agent CLI (`claude`, `codex`): no API key and no gateway, the user's
subscription answers. Guard sends one plain-text prompt and reads one text answer.

What the nested CLI may do is kept to answering: Claude runs with its built-in tools off, no MCP
server of the user's (`--strict-mcp-config`) and no saved session; Codex runs read-only, without the
user's config (so none of its MCP servers) and without keeping a session. Both run in an empty
temporary folder outside any repository, so guard's own hooks see no session there. The review text
goes on stdin and the rules in a file the CLI reads as its system prompt, never on the command line:
on Windows `claude` is a `.cmd` shim, and cmd.exe would cut an argument at a newline and run what
follows a `|`. No environment switch turns guard's hooks off: an agent could set one for its own
commands.

`probe` tests a CLI without a review prompt: its own sign-in status and its model list.

Alibaba OCR cannot use this: it only calls an HTTP endpoint, with tool calls. `guard config` says so.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

# the fence and its rule are shared with the API path; re-exported for callers of this module
from guard.core.llm_client import UNTRUSTED_CLOSE, UNTRUSTED_OPEN, UNTRUSTED_RULE, fence_untrusted  # noqa: F401

# How each CLI answers one prompt without tools (flags checked 2026-09-29: claude 2.1.284, codex 0.156.1;
# 2026-10-03: omp 18.4.3). agy is not here: headless it asks for tools that only
# --dangerously-skip-permissions would allow, which no prompt carrying repository text may get
AGENTS: Dict[str, Dict[str, str]] = {
    "claude": {"title": "Claude Code", "binary": "claude"},
    "codex": {"title": "OpenAI Codex CLI", "binary": "codex"},
    "omp": {"title": "Oh My Pi (omp)", "binary": "omp"},
}
# omp ignores a system prompt in print mode (checked live): its rules go first in the prompt instead
RULES_IN_PROMPT = {"omp"}


SESSION_VARS = {"CLAUDE_CODE_MESSAGING_SOCKET", "CLAUDE_CODE_MESSAGING_TOKEN", "CLAUDE_CODE_SESSION_ID", "CLAUDECODE"}
# what a CLI needs to start, find its sign-in and reach its API; nothing else of guard's environment
# (a project's tokens, cloud keys) is handed to a process that reads repository text
CHILD_ENV = {"PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "HOME", "USERPROFILE", "HOMEDRIVE",
             "HOMEPATH", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "TEMP", "TMP", "TMPDIR", "LANG",
             "LC_ALL", "TERM", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR", "USER",
             "USERNAME", "LOGNAME", "SHELL", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "SSL_CERT_FILE",
             "NODE_EXTRA_CA_CERTS"}
# each CLI's own sign-in and API settings: one CLI never sees the other's credentials
AGENT_ENV = {
    "claude": {"ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
               "CLAUDE_CONFIG_DIR"},
    "codex": {"CODEX_HOME", "OPENAI_API_KEY", "OPENAI_BASE_URL"},
    "omp": set(),  # omp keeps its sign-in in its own home folder
}


def _child_env(agent: str) -> Dict[str, str]:
    """What this CLI needs to start and sign in, and never the session markers of the agent running guard."""
    allowed = CHILD_ENV | AGENT_ENV.get(agent, set())
    return {k: v for k, v in os.environ.items() if k.upper() in allowed and k not in SESSION_VARS}


class CLILLMError(Exception):
    pass


def find(agent: str) -> Optional[str]:
    """The CLI's executable on PATH, or None."""
    spec = AGENTS.get(agent)
    return shutil.which(spec["binary"]) if spec else None


def _quiet(agent: str, cmd: List[str], text: str = "", timeout: float = 60) -> subprocess.CompletedProcess:
    """A short command of the CLI's own (status, model list), in guard's empty folder, with the CLI's environment."""
    env = _child_env(agent)
    with tempfile.TemporaryDirectory(prefix="guard-llm-", ignore_cleanup_errors=True) as work:
        return _run(cmd, text, work, timeout, env)


def _models(agent: str, binary: str, timeout: float = 60) -> List[str]:
    """
    The models the CLI offers, as it names them, read from the CLI itself: codex prints its model
    catalog locally; claude answers `/model` (the aliases it accepts; measured 2026-09-29 with claude
    2.1.284: no model turn, no cost; another version may answer it through the model, which the user
    accepts for a connection test).
    """
    if agent == "omp":
        res = _quiet(agent, [binary, "models", "--json"], "", timeout)
        if res.returncode != 0:
            return []
        try:
            catalog = json.loads(res.stdout).get("models") or []
        except (ValueError, AttributeError):
            return []
        return [m["selector"] for m in catalog
                if isinstance(m, dict) and m.get("kind", "chat") == "chat" and isinstance(m.get("selector"), str)]
    if agent == "claude":
        res = _quiet(agent, [binary, "-p", "--output-format", "json", "--tools", "", "--strict-mcp-config",
                      "--no-session-persistence"], "/model", timeout)
        if res.returncode != 0:
            return []  # a failed command lists nothing, whatever it printed
        try:
            data = json.loads(res.stdout)
            text = str(data.get("result") or "") if isinstance(data, dict) else ""
        except (ValueError, AttributeError):
            return []
        # "… Available: sonnet, opus, haiku, …, default, or a full model ID." (or "Available models:", "Models:")
        m = re.search(r"(?im)^.*?\b(?:available(?:\s+models)?|models)\s*:\s*(.+)$", text)
        listed = re.split(r",?\s+or\s+", m.group(1), maxsplit=1)[0] if m else ""
        return [m.strip(" .`") for m in listed.split(",") if m.strip(" .`") and m.strip(" .`") != "default"]
    res = _quiet(agent, [binary, "debug", "models"], "", timeout)
    if res.returncode != 0:
        return []
    try:
        catalog = json.loads(res.stdout).get("models") or []
    except (ValueError, AttributeError):
        return []
    shown = [m for m in catalog if isinstance(m, dict) and m.get("visibility") == "list" and isinstance(m.get("slug"), str)]
    def _prio(item: dict) -> int:
        p = item.get("priority")
        return p if isinstance(p, int) else 99

    return [m["slug"] for m in sorted(shown, key=_prio)]


def probe(agent: str, timeout: Optional[float] = None) -> tuple:
    """
    (ready, what to tell the user, the models it offers), with no review prompt: the CLI's own sign-in
    status (`claude auth status`, `codex login status`) and its model list. Ready means both answered;
    each command gets `timeout` (60 s when none is set).
    """
    timeout = timeout or 60
    binary = find(agent)
    if not binary:
        return False, f"`{AGENTS.get(agent, {}).get('binary', agent)}` is not on PATH", []
    if agent == "omp":  # no sign-in status command: a model list read from omp is what it can answer with
        try:
            models = _models(agent, binary, timeout)
        except (OSError, subprocess.SubprocessError) as e:
            return False, f"omp did not run: {type(e).__name__}: {e}", []
        if not models:
            return False, "omp lists no models: run `omp login`", []
        shown = ", ".join(models[:8]) + (", …" if len(models) > 8 else "")
        return True, f"omp is ready; models: {shown}", models
    status = [binary, "auth", "status"] if agent == "claude" else [binary, "login", "status"]
    try:
        res = _quiet(agent, status, "", timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"{agent} did not run: {type(e).__name__}: {e}", []
    if agent == "claude":
        try:
            signed_in = bool(json.loads(res.stdout).get("loggedIn"))
        except (ValueError, AttributeError):
            signed_in = False
    else:
        said = " ".join((res.stdout + res.stderr).lower().split())
        # "Logged in using ChatGPT"; "Not logged in" also holds the words, so it is refused first
        signed_in = res.returncode == 0 and "not logged in" not in said and said.startswith("logged in")
    if not signed_in:
        return False, f"{agent} is not signed in: run `{AGENTS[agent]['binary']} {'auth login' if agent == 'claude' else 'login'}`", []
    try:
        models = _models(agent, binary, timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"{agent} is signed in, but its model list did not come ({type(e).__name__})", []
    if not models:
        return False, f"{agent} is signed in, but its model list could not be read", []
    shown = ", ".join(models[:8]) + (", …" if len(models) > 8 else "")
    return True, f"{agent} is signed in; models: {shown}", models


def installed() -> List[str]:
    return [a for a in AGENTS if find(a)]


def _command(agent: str, binary: str, model: str, answer_file: Path, system_file: Optional[Path] = None) -> List[str]:
    """
    Only fixed flags, a model name and guard's own file paths: no text of the prompt is ever an
    argument. The review rules (`system_file`) go through the CLI's system channel, apart from the
    repository text on stdin, so that text cannot pass itself off as the rules.
    """
    if agent == "omp":  # no tools at all, nothing kept; the answer is the last JSON line's assistant message
        return [binary, "-p", "--no-tools", "--no-session", "--mode", "json"] + (["--model", model] if model else [])
    if agent == "claude":
        cmd = [binary, "-p", "--output-format", "json", "--tools", "", "--strict-mcp-config", "--no-session-persistence"]
        cmd += ["--system-prompt-file", str(system_file)] if system_file else []
        return cmd + (["--model", model] if model else [])
    # codex: no shell tool at all (the prompt holds repository text, which may ask it to read the
    # machine), read-only, without the user's config and its MCP servers, outside Git, nothing kept;
    # the final answer is written to a file of guard's
    cmd = [binary, "exec", "--disable", "shell_tool", "--disable", "unified_exec", "--sandbox", "read-only",
           "--ignore-user-config", "--skip-git-repo-check", "--ephemeral", "-o", str(answer_file)]
    # the rules replace codex's own agent instructions: it has no tool to use them for here
    cmd += ["-c", f"model_instructions_file={json.dumps(system_file.as_posix())}"] if system_file else []
    return cmd + (["-m", model] if model else []) + ["-"]


def _end_tree(proc: subprocess.Popen) -> None:
    """Stop the CLI and what it started (a .cmd shim runs node under cmd.exe; npm's codex runs a binary)."""
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, check=False, timeout=30)
        except (OSError, subprocess.SubprocessError):
            pass
    else:  # the CLI runs in its own session (see _run): its group is everything it started
        import signal
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=30)  # never communicate() here: a grandchild may keep the pipes open
    except subprocess.TimeoutExpired:
        pass


def _run(cmd: List[str], text: str, cwd: str, timeout: Optional[float], env: Dict[str, str]) -> subprocess.CompletedProcess:
    """
    subprocess.run, but a timeout, or Ctrl+C, ends the CLI's whole process tree, so no review keeps
    running (and spending) after guard gave up on it.
    """
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace", cwd=cwd, env=env,
                            start_new_session=os.name != "nt")
    try:
        out, err = proc.communicate(text, timeout=timeout)
    except BaseException:
        _end_tree(proc)
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def call(agent: str, prompt: str, system_prompt: Optional[str] = None, model: str = "",
         timeout: Optional[float] = None) -> str:
    """The CLI's answer to one prompt, as text; a CLI that cannot be run or read raises CLILLMError."""
    binary = find(agent)
    if not binary:
        raise CLILLMError(f"`{AGENTS.get(agent, {}).get('binary', agent)}` is not on PATH")
    if model and not all(c.isalnum() or c in "-._:/[]" for c in model):
        raise CLILLMError(f"model name {model!r} is not a plain name")  # it is the one value on the command line
    # what came from the repository is marked as data (a closing marker inside it cannot end the
    # data early), and the rules are never part of it
    text, framed_system = fence_untrusted(prompt, system_prompt)
    if agent in RULES_IN_PROMPT and framed_system:  # ahead of the marked data, which cannot pass itself off as them
        text, framed_system = f"{framed_system}\n\n{text}", None
    with tempfile.TemporaryDirectory(prefix="guard-llm-", ignore_cleanup_errors=True) as work:
        answer_file = Path(work) / "answer.txt"
        system_file = None
        if framed_system:
            system_file = Path(work) / "rules.txt"
            system_file.write_text(framed_system, encoding="utf-8")
        # only what the CLI needs (CHILD_ENV), never attached to the session of the agent that runs
        # guard (its messaging socket and id)
        env = _child_env(agent)
        try:
            res = _run(_command(agent, binary, model, answer_file, system_file), text, work, timeout, env)
        except subprocess.TimeoutExpired as e:
            raise CLILLMError(f"{agent} did not answer within {timeout:.0f} s") from e
        except (OSError, subprocess.SubprocessError) as e:
            raise CLILLMError(f"{agent} did not run: {type(e).__name__}: {e}") from e
        if res.returncode != 0:
            said = (_omp_error(res.stdout) if agent == "omp" else "") or " ".join((res.stderr or res.stdout).split())[:300]
            raise CLILLMError(f"{agent} exited with {res.returncode}: {said}")
        if agent == "omp":
            return _omp_answer(res.stdout)
        if agent == "claude":
            try:
                data = json.loads(res.stdout)
            except ValueError as e:
                raise CLILLMError(f"claude's answer is not JSON: {' '.join(res.stdout.split())[:200]}") from e
            if not isinstance(data, dict) or data.get("is_error") or not isinstance(data.get("result"), str):
                shown = (data.get("result") or data.get("subtype")) if isinstance(data, dict) else data
                raise CLILLMError(f"claude answered with an error: {str(shown)[:300]}")
            return data["result"].strip()
        answer = answer_file.read_text(encoding="utf-8", errors="replace").strip() if answer_file.is_file() else ""
        if not answer:
            raise CLILLMError("codex wrote no final answer")
        return answer


def _omp_messages(stdout: str) -> list:
    """
    The conversation in omp's JSON output: the last line that is a JSON object holding `messages`;
    other lines (events, progress, stray text) are skipped.
    """
    for line in reversed(stdout.splitlines()):
        try:
            data = json.loads(line)
        except ValueError:
            continue
        if isinstance(data, dict) and isinstance(data.get("messages"), list):
            return data["messages"]
    return []


def _omp_error(stdout: str) -> str:
    """The error omp's model gave in its last assistant message (the output itself starts with session events)."""
    for message in reversed(_omp_messages(stdout)):
        if isinstance(message, dict) and message.get("role") == "assistant":
            error = message.get("errorMessage")
            return f"{message.get('model') or 'the model'} failed: {' '.join(str(error).split())[:300]}" if error else ""
    return ""


def _omp_answer(stdout: str) -> str:
    """The text of the last assistant message in omp's JSON output."""
    for message in reversed(_omp_messages(stdout)):
        if isinstance(message, dict) and message.get("role") == "assistant":
            parts = message.get("content")
            text = parts if isinstance(parts, str) else "".join(
                p.get("text", "") for p in parts or [] if isinstance(p, dict) and p.get("type") == "text")
            if text.strip():
                return text.strip()
    raise CLILLMError(f"omp's answer has no assistant text: {' '.join(stdout.split())[-200:]}")
