"""
The agent hook checks the repository an event acts in, not only the harness's cwd: a commit run in a
linked worktree (`git -C <wt> commit`, `Set-Location <wt>; git commit`), edits of worktree files, shell
commands that change a worktree, the guard pre claim, the prompt notice and stop.

Every case has the cwd repository hold an unsigned COMPLETED session (the state that used to block every
worktree commit) and a linked worktree next to it.
"""

import os
import subprocess
from pathlib import Path

import pytest
from test_agent_events import make_repo

from guard.agent.events import AgentEvent, Decision, decide, load_state
from guard.cli import execute_post_task, execute_pre_task
from guard.core.session import SessionManager

GIT = "git"  # kept apart so the commands below read as data, not as commands this file runs


def ev(cwd: Path, event: str, **kw) -> Decision:
    return decide(AgentEvent(event=event, cwd=str(cwd), agent="claude-code", **kw))


def names(reason: str, repo: Path) -> bool:
    return os.path.normcase(str(repo.resolve())) in os.path.normcase(reason)


def approve(repo: Path, text: str = "export const a = 2;\n") -> None:
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, scope=["src/chat.ts"]) is True
    (repo / "src" / "chat.ts").write_text(text, encoding="utf-8")
    assert execute_post_task(repo_path=repo, full=True) is True


def unsign(repo: Path) -> None:
    mgr = SessionManager(repo)
    session = mgr.load_local_session()
    assert session is not None and session.post is not None
    session.post.approval_signature = None
    mgr._save(session)


@pytest.fixture
def main_and_wt(tmp_path, fake_ocr_review):
    main = make_repo(tmp_path)
    approve(main)
    unsign(main)  # an older or tampered approval: commits in main stay blocked
    wt = tmp_path / "wt"
    subprocess.run([GIT, "worktree", "add", "-b", "feature", str(wt)], cwd=main, check=True, capture_output=True)
    return main, wt


# Every shape with every path spelling the shell accepts: Windows-style paths only where the shell
# reads a backslash literally (PowerShell), POSIX-style paths everywhere
def commit_shapes(wt: Path):
    styles = list(dict.fromkeys([str(wt), wt.as_posix()]))
    shapes = []
    for p in styles:
        shapes += [("PowerShell", f"Set-Location '{p}'; {GIT} commit -m x"),
                   ("PowerShell", f"{GIT} -C '{p}' commit -m x")]
    shapes += [("Bash", f"{GIT} -C '{wt.as_posix()}' commit -m x"), ("Bash", f"cd '{wt.as_posix()}' && {GIT} commit -m x")]
    return shapes


def test_commits_in_an_approved_worktree_are_allowed_from_the_main_cwd(main_and_wt):
    main, wt = main_and_wt
    approve(wt)
    for tool, command in commit_shapes(wt):
        assert ev(main, "before-edit", tool=tool, command=command).action == "allow", command


def test_a_re_post_in_the_worktree_is_what_the_commit_is_checked_against(main_and_wt):
    main, wt = main_and_wt
    approve(wt)
    (wt / "src" / "chat.ts").write_text("export const a = 3;\n", encoding="utf-8")
    command = f"{GIT} -C '{wt.as_posix()}' commit -m x"
    changed = ev(main, "before-edit", tool="Bash", command=command)
    assert changed.action == "block" and "src/chat.ts" in changed.reason and names(changed.reason, wt)
    assert execute_post_task(repo_path=wt, full=True) is True
    assert ev(main, "before-edit", tool="Bash", command=command).action == "allow"


def test_an_unsigned_worktree_approval_blocks_and_names_the_worktree(main_and_wt):
    main, wt = main_and_wt
    approve(wt)
    unsign(wt)
    for tool, command in commit_shapes(wt):
        blocked = ev(main, "before-edit", tool=tool, command=command)
        assert blocked.action == "block" and "valid signature" in blocked.reason and names(blocked.reason, wt), command


def test_commits_the_target_of_which_is_not_certain_are_checked_against_the_cwd(main_and_wt):
    main, wt = main_and_wt
    approve(wt)
    for command in (f"{GIT} commit -m x", f"cd $dir; {GIT} commit -m x"):
        blocked = ev(main, "before-edit", tool="Bash", command=command)
        # the cwd's own unsigned approval decides; a message about the cwd keeps its usual form
        assert blocked.action == "block" and blocked.reason.startswith("Guard: this approval is missing a valid signature")
    assert ev(main, "before-commit").action == "block"  # a dedicated commit hook names no command


def test_edit_tools_are_checked_against_the_worktree_session(main_and_wt):
    main, wt = main_and_wt
    for path in (wt / "src" / "chat.ts", Path((wt / "src" / "chat.ts").as_posix())):
        no_pre = ev(main, "before-edit", tool="Edit", file_paths=[str(path)])
        assert no_pre.action == "block" and "guard pre" in no_pre.reason and names(no_pre.reason, wt)
    assert execute_pre_task("Fix src/chat.ts", repo_path=wt, scope=["src/chat.ts"]) is True
    assert ev(main, "before-edit", tool="Edit", file_paths=[str(wt / "src" / "chat.ts")]).action == "allow"
    outside = ev(main, "before-edit", tool="Edit", file_paths=[str(wt / "src" / "other.ts")])
    assert outside.action == "block" and "outside the declared scope" in outside.reason and names(outside.reason, wt)


def test_a_shell_edit_in_the_worktree_is_measured_there(main_and_wt):
    main, wt = main_and_wt
    assert execute_pre_task("Fix src/chat.ts", repo_path=wt, scope=["src/chat.ts"]) is True
    command = f"Set-Location '{wt}'; Add-Content src/other.ts '// x'"
    assert ev(main, "before-edit", tool="PowerShell", command=command, call_id="c1").action == "allow"
    assert "c1" in load_state(wt)["bash"]  # the worktree's own state holds the fingerprint
    (wt / "src" / "other.ts").write_text("export const b = 2;\n", encoding="utf-8")  # what the command did
    told = ev(main, "after-bash", tool="PowerShell", command=command, call_id="c1")
    assert told.action == "notify" and "src/other.ts" in told.reason and "outside the declared scope" in told.reason
    assert names(told.reason, wt)


def test_a_shell_command_naming_a_repository_guard_never_worked_in_writes_nothing_there(main_and_wt, tmp_path):
    main, _ = main_and_wt
    plain = tmp_path / "plain"
    plain.mkdir()
    subprocess.run([GIT, "init"], cwd=plain, check=True, capture_output=True)
    assert ev(main, "before-edit", tool="Bash", command=f"cp README.md '{plain.as_posix()}'", call_id="c1").action == "allow"
    assert not (plain / ".guard").exists()
    assert ev(main, "after-bash", tool="Bash", call_id="c1").action in ("allow", "notify")
    assert not (plain / ".guard").exists()


def test_a_deleted_worktree_the_session_worked_in_is_skipped(main_and_wt):
    main, wt = main_and_wt
    subprocess.run([GIT, "checkout", "--", "src/chat.ts"], cwd=main, check=True, capture_output=True)
    assert execute_pre_task("Fix src/chat.ts", repo_path=wt, scope=["src/chat.ts"]) is True
    ev(main, "before-edit", agent_session="sess-A", tool="Edit", file_paths=[str(wt / "src" / "chat.ts")])
    (wt / "src" / "chat.ts").write_text("export const a = 5;\n", encoding="utf-8")
    subprocess.run([GIT, "worktree", "remove", "--force", str(wt)], cwd=main, check=True, capture_output=True)
    assert ev(main, "stop", agent_session="sess-A").action == "allow"
    assert ev(main, "prompt", agent_session="sess-A", prompt="next").action == "notify"


def test_guard_pre_in_the_worktree_gets_the_claim_and_the_users_prompt(main_and_wt):
    main, wt = main_and_wt
    ev(main, "prompt", agent_session="sess-A", prompt="Fix the chat in the worktree")
    command = f"cd '{wt.as_posix()}' && guard pre \"Fix src/chat.ts\" --scope src/chat.ts"
    ev(main, "before-edit", agent_session="sess-A", tool="Bash", command=command, call_id="pre")
    assert execute_pre_task("Fix src/chat.ts", repo_path=wt, scope=["src/chat.ts"]) is True
    session = SessionManager(wt).load_local_session()
    assert session is not None and session.pre is not None
    assert session.pre.owner == {"agent": "claude-code", "session": "claude-code:sess-A"}
    assert session.pre.user_prompt == "Fix the chat in the worktree"


def test_prompt_notice_and_stop_cover_the_worktree_the_session_worked_in(main_and_wt):
    main, wt = main_and_wt
    subprocess.run([GIT, "checkout", "--", "src/chat.ts"], cwd=main, check=True, capture_output=True)  # main: nothing to stop for
    assert ev(main, "stop", agent_session="sess-A").action == "allow"
    hint = ev(main, "prompt", agent_session="sess-A", prompt="next")
    assert hint.action == "notify"  # main's session is completed and nothing else is known yet
    assert execute_pre_task("Fix src/chat.ts", repo_path=wt, scope=["src/chat.ts"]) is True
    assert ev(main, "before-edit", agent_session="sess-A", tool="Edit",
              file_paths=[str(wt / "src" / "chat.ts")]).action == "allow"
    assert ev(main, "prompt", agent_session="sess-A", prompt="go on").action == "allow"  # its worktree task is open
    (wt / "src" / "chat.ts").write_text("export const a = 5;\n", encoding="utf-8")
    stopped = ev(main, "stop", agent_session="sess-A")
    assert stopped.action == "block" and "guard post" in stopped.reason and names(stopped.reason, wt)
    assert execute_post_task(repo_path=wt, full=True) is True
    assert ev(main, "stop", agent_session="sess-A").action == "allow"
