"""
The gate logic behind `guard agent-event`: what an agent may do before `guard pre`, inside and
outside the scope, when it stops, and when it commits.
"""

import json
import os
import subprocess
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from guard.agent.events import AgentEvent, _pid_alive, decide, load_state, normalise
from guard.cli import app, execute_post_task, execute_pre_task
from guard.core.session import SessionManager, SessionStatus


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    (repo / "src").mkdir(parents=True)
    for cmd in (["git", "init"], ["git", "config", "user.email", "t@t"], ["git", "config", "user.name", "t"],
                ["git", "config", "core.hooksPath", ".git/hooks"]):
        subprocess.run(cmd, cwd=repo, check=True, capture_output=True)
    (repo / "package.json").write_text('{"name": "fe", "scripts": {"build": "node -e \\"process.exit(0)\\""}}', encoding="utf-8")
    (repo / "src" / "chat.ts").write_text("export const a = 1;\n", encoding="utf-8")
    (repo / "src" / "other.ts").write_text("export const b = 1;\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)
    return repo


def edit(repo, path, tool="Edit"):
    return decide(AgentEvent(event="before-edit", cwd=str(repo), tool=tool, file_paths=[str(repo / path)]))


def bash(repo, command, call_id="c1"):
    return decide(AgentEvent(event="before-edit", cwd=str(repo), tool="Bash", command=command, call_id=call_id))


def after_bash(repo, call_id="c1"):
    return decide(AgentEvent(event="after-bash", cwd=str(repo), tool="Bash", call_id=call_id))


def stop(repo, loop=False):
    return decide(AgentEvent(event="stop", cwd=str(repo), loop=loop))


def test_edits_need_guard_pre_and_stay_in_scope(tmp_path):
    repo = make_repo(tmp_path)
    blocked = edit(repo, "src/chat.ts")
    assert blocked.action == "block" and "guard pre" in blocked.reason
    assert edit(repo, "src/chat.ts", tool="Read").action == "allow"  # readers are never blocked
    assert edit(repo, str(tmp_path / "outside.txt")).action == "allow"  # not this repository's file

    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    assert edit(repo, "src/chat.ts").action == "allow"
    outside = edit(repo, "src/other.ts")
    assert outside.action == "block" and "--scope src/other.ts" in outside.reason


def test_edits_git_ignores_are_not_guarded(tmp_path):
    from guard.core.untracked import decide as record
    repo = make_repo(tmp_path)
    (repo / "plans").mkdir()
    (repo / "plans" / "plan.md").write_text("# plan\n", encoding="utf-8")
    record(repo, "plans", "ignore")  # the user's choice: never part of the repository
    assert edit(repo, "plans/plan.md").action == "allow"  # no session needed: it never reaches a commit
    assert edit(repo, "plans/new-phase.md").action == "allow"  # new files in it too
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    assert edit(repo, "plans/plan.md").action == "allow"  # and it is not "outside the scope"
    assert edit(repo, "src/other.ts").action == "block"  # the repository's own files stay guarded


def test_the_users_prompt_is_recorded_and_reaches_the_gate(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    hint = decide(AgentEvent(event="prompt", cwd=str(repo), prompt="Make chat retry once on 503"))
    assert hint.action == "notify" and "guard pre" in hint.reason
    assert load_state(repo)["user_prompt"] == "Make chat retry once on 503"

    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    pre = SessionManager(repo).load_local_session().pre
    assert pre.user_prompt == "Make chat retry once on 503"
    assert "user_prompt" not in load_state(repo)  # consumed: never reused for a later task

    seen = {}
    from guard.core import llm_reviewer
    original = llm_reviewer.LLMReviewerEngine.review

    def spy(self, **kwargs):
        seen["prompt"] = kwargs["prompt"]
        return original(self, **kwargs)

    monkeypatch.setattr(llm_reviewer.LLMReviewerEngine, "review", spy)
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    execute_post_task(repo_path=repo)
    assert "Make chat retry once on 503" in seen["prompt"] and "user's own message" in seen["prompt"]


def test_read_only_bash_passes_and_other_commands_are_measured(tmp_path):
    repo = make_repo(tmp_path)
    assert bash(repo, "git status && ls").action == "allow"
    assert after_bash(repo).action == "allow"  # nothing was fingerprinted

    assert bash(repo, "python -c 'print(1)'", call_id="c2").action == "allow"  # runs; measured afterwards
    assert after_bash(repo, "c2").action == "allow"  # it changed nothing

    assert bash(repo, "node build.js", call_id="c3").action == "allow"
    (repo / "src" / "chat.ts").write_text("export const a = 9;\n", encoding="utf-8")  # what the command did
    told = after_bash(repo, "c3")
    assert told.action == "notify" and "src/chat.ts" in told.reason and "before any guard session" in told.reason
    assert (repo / "src" / "chat.ts").read_text(encoding="utf-8") == "export const a = 9;\n"  # never reverted

    assert stop(repo).action == "block"  # changed without a session: the agent must say so
    assert stop(repo, loop=True).action == "allow"  # the harness's loop guard always wins

    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, allow_dirty=True) is True
    assert SessionManager(repo).load_local_session().pre.pre_edit_changes == ["src/chat.ts"]


def test_bash_outside_scope_is_reported_after_pre(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    bash(repo, "node gen.js", call_id="c9")
    (repo / "src" / "other.ts").write_text("export const b = 2;\n", encoding="utf-8")
    told = after_bash(repo, "c9")
    assert told.action == "notify" and "src/other.ts" in told.reason and "outside the declared scope" in told.reason


def test_stop_and_commit_need_an_approved_post(tmp_path, fake_ocr_review):
    repo = make_repo(tmp_path)
    assert stop(repo).action == "allow"  # a chat without edits
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    assert stop(repo).action == "block"

    commit = "git add -A && git commit -m 'fix chat'"
    assert bash(repo, commit).action == "block"  # not approved yet
    assert execute_post_task(repo_path=repo) is True  # gate approved, OCR not run
    assert stop(repo).action == "allow"
    # the approval is enough: OCR is optional and the user is asked about it before the commit
    assert bash(repo, commit).action == "allow"

    (repo / "src" / "chat.ts").write_text("export const a = 3;\n", encoding="utf-8")  # edited after approval
    assert bash(repo, commit).action == "block"
    assert stop(repo).action == "block"


def test_a_quote_in_a_heredoc_message_does_not_hide_a_commit(tmp_path):
    from guard.agent.bash import is_git_commit
    repo = make_repo(tmp_path)
    message = "git add -A && git commit -q -F - <<'EOF'\nfeat: merges guard's hook entries\nEOF\ngit log --oneline -1"
    assert bash(repo, message).action == "block"  # no approval: the gate sees the commit
    assert is_git_commit("git commit -m \"it's", repo)  # cannot be parsed: a commit shape counts (fail closed)
    assert not is_git_commit("cat <<'EOF' > notes.md\ndon't commit this\nEOF", repo)  # text in a heredoc is text
    # a heredoc-looking comment or string does not swallow the real command after it
    for hidden in ("# <<EOF\ngit commit -m x", "echo \"<<EOF\"\ngit commit -m x", "echo a#b; git commit -m x"):
        assert is_git_commit(hidden, repo), hidden
    assert not is_git_commit("git status # commit later", repo)  # a real comment is not a command
    assert is_git_commit("echo \\<<EOF\ngit commit -m x", repo)  # an escaped `<` is not a heredoc
    assert not is_git_commit("cat <<'END HERE'\nnot a commit\nEND HERE\necho ok", repo)  # quoted delimiter
    # a body line shaped like a commit still counts: a body read wrongly must never hide one (fail closed)
    assert is_git_commit("cat <<'END HERE'\ngit commit -m x\nEND HERE", repo)
    assert not is_git_commit("grep x <<< \"git commit\"", repo)  # a here-string is not a heredoc
    # a misread heredoc can never hide a commit: every line is also scanned as the shell sees it
    assert is_git_commit("cat <<EOF-1\nx\nEOF-1\ngit commit -m y", repo)  # delimiter with a dash
    assert is_git_commit("git \\\ncommit -m \"guard's", repo)  # a line continuation, then an open quote
    assert is_git_commit("git -C /x commit -m y", repo) and is_git_commit("git -c user.name=a commit", repo)
    for wrapped in ("sudo git commit -m \"guard's", "git --git-dir /tmp commit -m \"guard's"):  # cannot be parsed
        assert is_git_commit(wrapped, repo), wrapped
    # ... without false alarms for reading commands or comments
    for reading in ("git log --grep commit", "git log --oneline | grep commit", "echo \"x\" # git commit\nls 'a"):
        assert not is_git_commit(reading, repo), reading


def test_a_command_with_a_heredoc_is_measured_not_trusted():
    from guard.agent.bash import is_read_only
    assert not is_read_only("cat <<EOF\nx\nEOF")  # its effect is measured after it ran


def test_concurrent_posts_keep_each_others_marker(tmp_path):
    import os

    from guard.agent.events import POST_MARKER, post_running
    repo = make_repo(tmp_path)
    marker = repo / ".guard" / POST_MARKER
    with post_running(repo):
        assert json.loads(marker.read_text(encoding="utf-8"))["pid"] == os.getpid()
        marker.write_text(json.dumps({"pid": os.getpid() + 1}), encoding="utf-8")  # a second post started meanwhile
    assert marker.exists()  # the first post leaves the second one's marker alone


def test_a_prompt_in_utf8_survives_a_cp1252_console(tmp_path):
    import os
    import sys
    repo = make_repo(tmp_path)
    prompt = "đã chọn c, sửa tiếp đi"
    env = {**os.environ, "PYTHONIOENCODING": "cp1252"}  # what a Windows console gives the hook
    payload = json.dumps({"cwd": str(repo), "hook_event_name": "UserPromptSubmit", "prompt": prompt}, ensure_ascii=False)
    res = subprocess.run([sys.executable, "-m", "guard.cli", "agent-event", "prompt", "--agent", "claude-code"],
                         input=payload.encode("utf-8"), capture_output=True, env=env)
    assert res.returncode == 0, res.stderr
    assert load_state(repo)["user_prompt"] == prompt


def test_stop_waits_for_a_running_post_and_a_marker_never_allows_it(tmp_path, monkeypatch):
    import sys
    import time

    import guard.agent.events as events
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    marker = repo / ".guard" / events.POST_MARKER

    # a post that ends: the stop waits for it, then decides on the session (still unapproved here)
    short = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(3)"])
    marker.write_text(json.dumps({"pid": short.pid}), encoding="utf-8")
    started = time.monotonic()
    assert stop(repo).action == "block" and time.monotonic() - started >= 1.5
    short.wait()

    # a marker an agent wrote for a process of its own: it only delays, it never lets the stop through
    monkeypatch.setattr(events, "POST_WAIT_S", 1)
    forged = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        marker.write_text(json.dumps({"pid": forged.pid}), encoding="utf-8")
        still = stop(repo)
        # still running when the wait ends: blocked, and never told to start a second post
        assert still.action == "block" and "still running" in still.reason and "Run `guard post`" not in still.reason
    finally:
        forged.kill()
        forged.wait()
    marker.unlink()
    # an oversized or non-regular marker is never read (a FIFO or /dev/zero link would hang the hook)
    marker.write_text(json.dumps({"pid": forged.pid, "pad": "x" * 5000}), encoding="utf-8")
    assert not events._post_in_progress(repo)
    marker.unlink()
    marker.mkdir()
    assert not events._post_in_progress(repo)
    marker.rmdir()
    assert execute_post_task(repo_path=repo) is True and not marker.exists()  # post removes its own marker
    assert stop(repo).action == "allow"

    # waited for a post that approved: the stop goes through, with a note to read the report
    monkeypatch.setattr(events, "POST_WAIT_S", 30)
    short = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
    marker.write_text(json.dumps({"pid": short.pid}), encoding="utf-8")
    told = stop(repo)
    short.wait()
    assert told.action == "notify" and "has finished" in told.reason


def test_cli_contract_block_exits_2_and_bad_payload_is_allowed(tmp_path):
    repo = make_repo(tmp_path)
    payload = {"tool_name": "Write", "tool_input": {"file_path": str(repo / "src" / "chat.ts")}, "cwd": str(repo)}
    result = CliRunner().invoke(app, ["agent-event", "before-edit"], input=json.dumps(payload))
    assert result.exit_code == 2 and '"decision": "block"' in result.output

    broken = CliRunner().invoke(app, ["agent-event", "before-edit"], input="{not json")
    assert broken.exit_code == 0 and '"decision": "allow"' in broken.output

    assert CliRunner().invoke(app, ["agent-event", "nonsense"], input="{}").exit_code == 1


def test_normalise_reads_common_harness_fields():
    ev = normalise("before-edit", {"cwd": "/w", "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "t1"})
    assert (ev.tool, ev.command, ev.call_id, ev.file_paths) == ("Bash", "ls", "t1", [])
    ev = normalise("stop", {"stop_hook_active": True})
    assert ev.loop is True


def test_a_dedicated_commit_hook_is_always_gated(tmp_path):
    repo = make_repo(tmp_path)
    no_command = decide(AgentEvent(event="before-commit", cwd=str(repo)))
    assert no_command.action == "block" and "approved" in no_command.reason


def test_cli_uses_the_adapter_field_mapping_and_logs_odd_payloads(tmp_path, monkeypatch):
    from guard.core.repo_setup import guard_home
    repo = make_repo(tmp_path)
    agents = guard_home() / "agents"
    agents.mkdir(parents=True, exist_ok=True)
    (agents / "mytool.json").write_text(json.dumps({"fields": {"file_paths": ["args.target"], "tool": ["kind"]}}), encoding="utf-8")
    payload = {"kind": "Write", "args": {"target": str(repo / "src" / "chat.ts")}, "cwd": str(repo)}
    result = CliRunner().invoke(app, ["agent-event", "before-edit", "--agent", "mytool"], input=json.dumps(payload))
    assert result.exit_code == 2  # found the file through the adapter's own field names

    odd = CliRunner().invoke(app, ["agent-event", "stop"], input="[1, 2]")
    assert odd.exit_code == 0
    assert "payload is a JSON list" in (guard_home() / "agent-events.log").read_text(encoding="utf-8")


def test_unknown_tools_that_name_a_file_are_treated_as_edits(tmp_path):
    repo = make_repo(tmp_path)
    assert edit(repo, "src/chat.ts", tool="apply_patch").action == "block"  # a writer guard has never heard of
    assert edit(repo, "src/chat.ts", tool="Grep").action == "allow"
    assert decide(AgentEvent(event="before-edit", cwd=str(repo), tool="TodoList")).action == "allow"  # names no file


def test_commit_checks_the_staged_content_not_only_the_working_tree(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    subprocess.run(["git", "add", "src/chat.ts"], cwd=repo, check=True, capture_output=True)  # stage v2
    (repo / "src" / "chat.ts").write_text("export const a = 3;\n", encoding="utf-8")  # then edit to v3
    assert execute_post_task(repo_path=repo, full=True) is True  # approves the working tree (v3)
    staged_old = bash(repo, "git commit -m x")
    assert staged_old.action == "block" and "src/chat.ts" in staged_old.reason  # the commit would contain v2
    subprocess.run(["git", "add", "src/chat.ts"], cwd=repo, check=True, capture_output=True)
    assert bash(repo, "git commit -m x").action == "allow"


def test_stop_ignores_pre_existing_changes_the_task_did_not_touch(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "src" / "other.ts").write_text("export const b = 5;\n", encoding="utf-8")  # the user's own work
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, allow_dirty=True) is True
    assert stop(repo).action == "allow"  # the task has not edited anything yet
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    assert stop(repo).action == "block"


def test_parallel_hook_calls_keep_every_fingerprint(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    from guard.agent.events import load_state
    repo = make_repo(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: bash(repo, "node build.js", call_id=f"c{i}"), range(16)))
    assert len(load_state(repo)["bash"]) == 16


def test_guard_failure_is_allowed_but_the_agent_is_told(tmp_path, monkeypatch):
    import guard.agent.events as events
    repo = make_repo(tmp_path)
    monkeypatch.setattr(events, "decide", lambda ev: (_ for _ in ()).throw(RuntimeError("boom")))
    payload = {"tool_name": "Write", "tool_input": {"file_path": str(repo / "src" / "chat.ts")}, "cwd": str(repo)}
    result = CliRunner().invoke(app, ["agent-event", "before-edit"], input=json.dumps(payload))
    assert result.exit_code == 0 and '"decision": "notify"' in result.output and "could not check" in result.output


def test_a_session_without_scope_does_not_allow_edits(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Refactor things", repo_path=repo) is True  # no file named, no --scope
    blocked = edit(repo, "src/chat.ts")
    assert blocked.action == "block" and "declares no scope" in blocked.reason and "--scope src/chat.ts" in blocked.reason


def test_a_commit_that_slipped_past_is_reported_right_after(tmp_path):
    repo = make_repo(tmp_path)
    assert bash(repo, "./release.sh", call_id="r1").action == "allow"  # an unknown script, measured
    (repo / "src" / "chat.ts").write_text("export const a = 5;\n", encoding="utf-8")
    subprocess.run(["git", "commit", "-qam", "sneaky"], cwd=repo, check=True, capture_output=True)  # what it did
    told = after_bash(repo, "r1")
    assert told.action == "notify" and "made a commit" in told.reason


def test_loop_flag_only_counts_when_true():
    assert normalise("stop", {"stop_hook_active": "false"}).loop is False
    assert normalise("stop", {"stop_hook_active": "true"}).loop is True
    assert normalise("stop", {"stop_hook_active": 0}).loop is False


def test_a_new_prompt_wins_over_the_restarted_sessions_prompt(tmp_path):
    repo = make_repo(tmp_path)
    decide(AgentEvent(event="prompt", cwd=str(repo), prompt="first request"))
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    decide(AgentEvent(event="prompt", cwd=str(repo), prompt="actually, also retry twice"))
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, force=True) is True
    assert SessionManager(repo).load_local_session().pre.user_prompt == "actually, also retry twice"


def test_oversized_payload_is_allowed_and_logged(tmp_path, monkeypatch):
    import guard.commands.agent as agent_cmds
    from guard.core.repo_setup import guard_home
    monkeypatch.setattr(agent_cmds, "MAX_EVENT_BYTES", 100)
    result = CliRunner().invoke(app, ["agent-event", "before-edit"], input=json.dumps({"x": "y" * 500}))
    assert result.exit_code == 0 and '"decision": "allow"' in result.output
    assert "larger than 100" in (guard_home() / "agent-events.log").read_text(encoding="utf-8")


def test_tools_guard_cannot_classify_are_measured(tmp_path):
    repo = make_repo(tmp_path)
    ev = AgentEvent(event="before-edit", cwd=str(repo), tool="Task", call_id="t1")  # a subagent can edit
    assert decide(ev).action == "allow"
    (repo / "src" / "chat.ts").write_text("export const a = 7;\n", encoding="utf-8")  # what the subagent did
    told = decide(AgentEvent(event="after-bash", cwd=str(repo), tool="Task", call_id="t1"))
    assert told.action == "notify" and "src/chat.ts" in told.reason


def test_ignored_files_inside_the_repo_are_gated_too(tmp_path):
    repo = make_repo(tmp_path)
    (repo / ".gitignore").write_text("out/\n", encoding="utf-8")
    assert edit(repo, "out/bundle.js").action == "block"
    # guard's state is written only by guard commands
    assert edit(repo, ".guard/notes.txt").action == "block"


def test_pre_keeps_fingerprints_of_commands_still_running(tmp_path):
    repo = make_repo(tmp_path)
    bash(repo, "node long-job.js", call_id="long")
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    assert "long" in load_state(repo).get("bash", {})


@pytest.mark.skipif(os.name == "nt", reason="POSIX-only test for reaping unreaped child processes")
def test_posix_zombie_process_is_not_reported_alive():
    import sys
    import time

    import guard.agent.events as events
    child = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(0)"])
    time.sleep(0.5)
    assert events._pid_alive(child.pid) is False


def test_pid_alive_rejects_non_positive_and_non_int():
    assert _pid_alive(0) is False
    assert _pid_alive(-1) is False
    assert _pid_alive("12") is False


# --- two agent sessions in one working tree -------------------------------------------------------

def ev(repo, event, session, **kw):
    return decide(AgentEvent(event=event, cwd=str(repo), agent_session=session, agent="claude-code", **kw))


def owned_pre(repo, prompt="Fix src/chat.ts", session="sess-A"):
    """Agent session A runs `guard pre` through its Bash tool: the hook takes the claim first."""
    ev(repo, "before-edit", session, tool="Bash", command=f'guard pre "{prompt}" --scope src/chat.ts', call_id="pre")
    assert execute_pre_task(prompt, repo_path=repo) is True
    ev(repo, "after-bash", session, tool="Bash", call_id="pre")
    return SessionManager(repo).load_local_session()


def test_normalise_reads_the_agent_session_id():
    assert normalise("stop", {"session_id": "abc"}).agent_session == "abc"
    assert normalise("stop", {"conversation_id": "c1"}).agent_session == "c1"
    assert normalise("stop", {"sessionId": "s1"}).agent_session == "s1"
    assert normalise("stop", {}).agent_session is None


def test_pre_takes_the_claim_and_the_owners_own_prompt(tmp_path):
    repo = make_repo(tmp_path)
    ev(repo, "prompt", "sess-A", prompt="A: fix the chat")
    ev(repo, "prompt", "sess-B", prompt="B: only plan the next phase")  # typed later, in another session
    session = owned_pre(repo)
    assert session.pre.owner == {"agent": "claude-code", "session": "claude-code:sess-A"}
    assert session.pre.user_prompt == "A: fix the chat"  # never the last prompt typed into any agent
    assert "B: only plan" in json.dumps(load_state(repo)["sessions"]["claude-code:sess-B"])  # B's stays B's
    assert "* **Owner:** `claude-code session sess-A`" in (repo / ".guard" / "PRE_TASK_NOTE.md").read_text(encoding="utf-8")


def test_a_pre_run_by_hand_has_no_owner_and_behaves_as_today(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    session = SessionManager(repo).load_local_session()
    assert session.pre.owner is None
    assert ev(repo, "before-edit", "sess-B", tool="Edit", file_paths=[str(repo / "src/other.ts")]).action == "block"
    assert "outside the declared scope" in ev(repo, "before-edit", "sess-B", tool="Edit",
                                             file_paths=[str(repo / "src/other.ts")]).reason


def test_another_session_cannot_restart_the_owners_task(tmp_path):
    repo = make_repo(tmp_path)
    owned_pre(repo)
    ev(repo, "before-edit", "sess-B", tool="Bash", command='guard pre --force "B task" --scope src/other.ts', call_id="b")
    assert execute_pre_task("B task", repo_path=repo, scope=["src/other.ts"], force=True) is False
    assert SessionManager(repo).load_local_session().pre.owner["session"] == "claude-code:sess-A"
    ev(repo, "before-edit", "sess-A", tool="Bash", command='guard pre --force "Fix src/chat.ts"', call_id="a")
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, force=True) is True  # the owner may
    assert SessionManager(repo).load_local_session().pre.owner["session"] == "claude-code:sess-A"


def test_another_sessions_edit_is_blocked_with_the_worktree_hint(tmp_path):
    from guard.core.untracked import decide as record
    repo = make_repo(tmp_path)
    owned_pre(repo)
    blocked = ev(repo, "before-edit", "sess-B", tool="Edit", file_paths=[str(repo / "src/chat.ts")])
    assert blocked.action == "block" and "git worktree add" in blocked.reason and "Fix src/chat.ts" in blocked.reason
    assert "claude-code session sess-A" in blocked.reason
    (repo / "plans").mkdir()
    record(repo, "plans", "ignore")
    assert ev(repo, "before-edit", "sess-B", tool="Write", file_paths=[str(repo / "plans/p.md")]).action == "allow"
    assert ev(repo, "before-edit", "sess-A", tool="Edit", file_paths=[str(repo / "src/chat.ts")]).action == "allow"


def test_another_session_never_waits_or_stops_for_the_owners_edits(tmp_path, monkeypatch):
    import guard.agent.events as events
    repo = make_repo(tmp_path)
    owned_pre(repo)
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")  # the owner's edit
    monkeypatch.setattr(events, "_post_in_progress", lambda r: True)  # the owner's post is running
    monkeypatch.setattr(events, "POST_WAIT_S", 5)  # a wait would show as a slow test, never a hang
    started = time.monotonic()
    assert ev(repo, "stop", "sess-B").action == "allow"  # no block
    assert time.monotonic() - started < 2  # and no wait for the owner's post
    monkeypatch.setattr(events, "POST_WAIT_S", 0)
    assert ev(repo, "stop", "sess-A").action == "block"  # the owner is gated as before


def test_another_sessions_own_command_changes_are_reported_and_stop_it(tmp_path):
    repo = make_repo(tmp_path)
    owned_pre(repo)
    ev(repo, "before-edit", "sess-B", tool="Bash", command="node gen.js", call_id="b1")
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")  # inside the owner's scope
    assert ev(repo, "after-bash", "sess-B", tool="Bash", call_id="b1").action == "allow"
    ev(repo, "before-edit", "sess-B", tool="Bash", command="node gen.js", call_id="b2")
    (repo / "src" / "other.ts").write_text("export const b = 2;\n", encoding="utf-8")  # B's own change
    reported = ev(repo, "after-bash", "sess-B", tool="Bash", call_id="b2")
    assert reported.action == "notify" and reported.reason.startswith("Guard: that command changed src/other.ts while")
    stopped = ev(repo, "stop", "sess-B")
    assert stopped.action == "block" and "src/other.ts" in stopped.reason
    subprocess.run(["git", "checkout", "--", "src/other.ts"], cwd=repo, check=True)
    assert ev(repo, "stop", "sess-B").action == "allow"  # undone: nothing of its own is left


def test_another_session_cannot_commit_and_gets_no_pre_hint(tmp_path):
    repo = make_repo(tmp_path)
    owned_pre(repo)
    commit = ev(repo, "before-commit", "sess-B")
    assert commit.action == "block" and "not yours to commit" in commit.reason
    assert ev(repo, "prompt", "sess-B", prompt="B: what is next?").action == "allow"  # no "run guard pre" hint
    state = load_state(repo)
    assert state["sessions"]["claude-code:sess-B"]["user_prompt"] == "B: what is next?" and "user_prompt" not in state


def test_the_post_report_names_the_owner(tmp_path, fake_ocr_review):
    repo = make_repo(tmp_path)
    owned_pre(repo)
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    execute_post_task(repo_path=repo)
    assert "* **Owner:** `claude-code session sess-A`" in (repo / ".guard" / "POST_TASK_REPORT.md").read_text(encoding="utf-8")


def test_two_pres_started_together_give_no_owner_rather_than_the_wrong_one(tmp_path):
    repo = make_repo(tmp_path)
    ev(repo, "before-edit", "sess-A", tool="Bash", command='guard pre "A task" --scope src/chat.ts', call_id="a")
    ev(repo, "before-edit", "sess-B", tool="Bash", command='guard pre "B task" --scope src/other.ts', call_id="b")
    assert execute_pre_task("A task", repo_path=repo, scope=["src/chat.ts"]) is True
    assert SessionManager(repo).load_local_session().pre.owner is None  # ambiguous: shared behaviour, as before


def test_a_non_owners_changes_after_the_owners_task_still_stop_it(tmp_path, fake_ocr_review):
    repo = make_repo(tmp_path)
    owned_pre(repo)
    s = SessionManager(repo)
    session = s.load_local_session()
    session.status = SessionStatus.COMPLETED  # the owner's task is approved, the tree no longer held
    s._save(session)
    ev(repo, "before-edit", "sess-B", tool="Bash", command="node gen.js", call_id="b1")
    (repo / "src" / "other.ts").write_text("export const b = 2;\n", encoding="utf-8")
    ev(repo, "after-bash", "sess-B", tool="Bash", call_id="b1")
    stopped = ev(repo, "stop", "sess-B")
    assert stopped.action == "block" and "src/other.ts" in stopped.reason


def test_only_a_guard_pre_command_takes_a_claim():
    from guard.agent.events import GUARD_PRE
    for command in ('guard pre "x" --scope a', "cd app && guard pre x", "PYTHONPATH=. guard pre x",
                    "/usr/local/bin/guard pre x", "C:\\tools\\guard.exe pre x", "(guard pre x)"):
        assert GUARD_PRE.search(command), command
    for command in ("grep guard pre docs/", "echo guard pre", "git log --grep 'guard pre'", "guard post"):
        assert not GUARD_PRE.search(command), command


def test_a_pre_keeps_another_sessions_claim_and_old_claims_expire(tmp_path, monkeypatch):
    import guard.agent.events as events
    repo = make_repo(tmp_path)
    ev(repo, "before-edit", "sess-old", tool="Bash", command="guard pre old", call_id="o")
    monkeypatch.setattr(events.time, "time", lambda real=events.time.time: real() + 120)  # two minutes later
    ev(repo, "before-edit", "sess-A", tool="Bash", command='guard pre "Fix src/chat.ts"', call_id="a")
    assert sorted(load_state(repo)["claims"]) == ["claude-code:sess-A"]  # the expired one is gone
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    assert SessionManager(repo).load_local_session().pre.owner["session"] == "claude-code:sess-A"
    ev(repo, "before-edit", "sess-B", tool="Bash", command="guard pre --force B", call_id="b")
    assert "claude-code:sess-B" in load_state(repo)["claims"]  # B's claim reaches its own pre, which is refused
    assert execute_pre_task("B", repo_path=repo, force=True) is False


def test_two_agents_with_the_same_session_id_are_not_one_session(tmp_path):
    repo = make_repo(tmp_path)
    owned_pre(repo, session="same-id")  # claude-code's session
    other = decide(AgentEvent(event="before-edit", cwd=str(repo), agent_session="same-id", agent="codex",
                              tool="Edit", file_paths=[str(repo / "src/chat.ts")]))
    assert other.action == "block" and "git worktree add" in other.reason
