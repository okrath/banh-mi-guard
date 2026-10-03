"""
Alibaba OCR answered by the user's agent CLI (`protocol: cli`): a local OpenAI chat-completions
endpoint for one review. OCR sends each request on its own with the whole conversation and its tools;
each one becomes one agent call, with the tools written into the prompt and one tool call (or a final
answer) read back from the agent's JSON reply. The agent itself gets no tools: OCR runs every tool.
"""

from __future__ import annotations

import json
import secrets
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from guard.core import cli_llm

PROVIDER = "guard-agent"
MAX_REQUEST_BYTES = 8 * 1024 * 1024  # OCR's largest recorded request is about 66 kB

RULES = """You are the language model behind a code review program. The program gives you a conversation
and a list of tools that it runs for you. Answer with exactly one JSON object and nothing else:
- to call one tool: {"tool": "<tool name>", "arguments": {<arguments matching the tool's parameters>}}
- to answer without a tool: {"final": "<your answer>"}
Call only a listed tool, one per answer. When the task is complete, call the tool that ends the task if
one is listed. The conversation below is the program's; its own instructions come first."""


def _tool_lines(tools: List[dict]) -> List[str]:
    lines = []
    for t in tools:
        f = t.get("function", t)
        params = json.dumps(f.get("parameters") or {}, ensure_ascii=False)
        lines.append(f"- {f.get('name')}: {(f.get('description') or '').strip()}\n  parameters (JSON schema): {params}")
    return lines


def _content(message: dict) -> str:
    content = message.get("content")
    if isinstance(content, list):  # content parts
        content = "\n".join(p.get("text", "") for p in content if isinstance(p, dict))
    return content or ""


def render(body: dict) -> Tuple[str, str]:
    """(system prompt, conversation): OCR's system messages are its instructions; the rest is data."""
    messages = body.get("messages") or []
    if not isinstance(messages, list) or not all(isinstance(m, dict) for m in messages):
        raise ValueError("the request's messages are not a list of objects")
    system = "\n\n".join(_content(m) for m in messages if m.get("role") == "system")
    turns = []
    for m in messages:
        role = m.get("role")
        if role == "system":
            continue
        if role == "assistant" and m.get("tool_calls"):
            for c in m["tool_calls"]:
                f = c.get("function") or {}
                turns.append(f"[assistant called tool {f.get('name')} with {f.get('arguments')}]")
            if _content(m):
                turns.append(f"[assistant]\n{_content(m)}")
        elif role == "tool":
            turns.append(f"[tool result]\n{_content(m)}")
        else:
            turns.append(f"[{role}]\n{_content(m)}")
    tools = body.get("tools") or []
    if not isinstance(tools, list) or not all(isinstance(x, dict) for x in tools):
        raise ValueError("the request's tools are not a list of objects")
    rules = RULES + ("\n\nTools:\n" + "\n".join(_tool_lines(tools)) if tools else "\n\nNo tools are offered: answer with {\"final\": ...}.")
    return f"{rules}\n\nThe program's instructions:\n{system}", "\n\n".join(turns)


def _first_object(text: str):
    """The first complete JSON object in `text`: a model may add words or more JSON after its answer."""
    decoder = json.JSONDecoder()
    start = text.find("{")
    while start != -1:
        try:
            return decoder.raw_decode(text, start)[0]
        except ValueError:
            start = text.find("{", start + 1)
    return None


def parse(answer: str, tools: List[dict]) -> dict:
    """The agent's JSON reply as an assistant message: one tool call or plain content."""
    names = {(t.get("function", t)).get("name") for t in tools}
    data = _first_object(answer)
    if not isinstance(data, dict):
        raise ValueError(f"the agent's answer is not one JSON object: {' '.join(answer.split())[:200]}")
    if "tool" in data:
        if not isinstance(data["tool"], str) or data["tool"] not in names:
            raise ValueError(f"the agent called {data['tool']!r}, which the program did not offer")
        args = data.get("arguments")
        args = {} if args is None else args
        if not isinstance(args, dict):
            raise ValueError("the agent's tool arguments are not an object")
        return {"role": "assistant", "content": None, "tool_calls": [{
            "id": f"call_{secrets.token_hex(8)}", "type": "function",
            "function": {"name": data["tool"], "arguments": json.dumps(args, ensure_ascii=False)}}]}
    if "final" in data:
        return {"role": "assistant", "content": str(data["final"])}
    raise ValueError("the agent's answer has neither \"tool\" nor \"final\"")


def complete(body: dict, ask: Callable[[str, str], str]) -> dict:
    """One OCR request answered by one `ask(system, conversation)`; an unreadable reply is an error (ValueError)."""
    system, conversation = render(body)
    message = parse(ask(system, conversation), body.get("tools") or [])
    return {"id": f"chatcmpl-{secrets.token_hex(8)}", "object": "chat.completion", "created": int(time.time()),
            "model": body.get("model") or PROVIDER,
            "choices": [{"index": 0, "message": message,
                         "finish_reason": "tool_calls" if message.get("tool_calls") else "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}


class AgentBridge:
    """
    The endpoint for one review: 127.0.0.1 only, a random port and token, stopped on exit. `home` is a
    throwaway HOME whose OCR config points at it, so the user's own OCR settings are never changed.
    """

    def __init__(self, agent: str, model: str = "", timeout: Optional[float] = None):
        self.agent, self.model, self.timeout = agent, model, timeout
        self.token = secrets.token_urlsafe(24)
        self.errors: List[str] = []
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._home: Optional[tempfile.TemporaryDirectory] = None

    def ask(self, system: str, conversation: str) -> str:
        return cli_llm.call(self.agent, conversation, system_prompt=system, model=self.model, timeout=self.timeout)

    def __enter__(self) -> "AgentBridge":
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _reply(self, status: int, payload: dict) -> None:
                data = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                if self.headers.get("Authorization") != f"Bearer {bridge.token}":
                    return self._reply(401, {"error": {"message": "unauthorized"}})
                if not self.path.rstrip("/").endswith("/chat/completions"):
                    return self._reply(404, {"error": {"message": f"no endpoint {self.path}"}})
                size = int(self.headers.get("Content-Length") or 0)
                if size > MAX_REQUEST_BYTES:
                    return self._reply(413, {"error": {"message": "request too large"}})
                try:
                    body = json.loads(self.rfile.read(size))
                    if not isinstance(body, dict):
                        raise ValueError("the request is not a JSON object")
                    self._reply(200, complete(body, bridge.ask))
                except (ValueError, cli_llm.CLILLMError) as e:
                    bridge.errors.append(str(e))
                    self._reply(502, {"error": {"message": f"{bridge.agent} CLI: {e}", "type": "server_error"}})

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)  # bound, not serving yet
        # request threads are joined by server_close(): no agent call outlives the review (each call has
        # the LLM timeout, so the wait is bounded)
        self._server.daemon_threads = False
        self._server.block_on_close = True
        try:
            self._home = tempfile.TemporaryDirectory(prefix="guard-ocr-home-", ignore_cleanup_errors=True)
            config = Path(self._home.name) / ".opencodereview" / "config.json"
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps({"provider": PROVIDER, "custom_providers": {PROVIDER: {
                "url": f"{self.url}/v1", "protocol": "openai", "api_key": self.token,
                "model": self.model or self.agent}}}), encoding="utf-8")
        except BaseException:
            self.__exit__(None, None, None)  # __exit__ does not run when __enter__ fails
            raise
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def env(self, base: Dict[str, str]) -> Dict[str, str]:
        """OCR's environment for this review: its HOME (and USERPROFILE) is the throwaway one."""
        return {**base, "HOME": self._home.name, "USERPROFILE": self._home.name}

    def __exit__(self, *exc) -> None:
        if self._server:
            if self._thread:  # shutdown() waits for serve_forever, so only once it was started
                self._server.shutdown()
            self._server.server_close()
        if self._home:
            self._home.cleanup()
