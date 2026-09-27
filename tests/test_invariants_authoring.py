"""
guard.invariants.json authoring: init from agent docs, check command, creation on hook install,
rules learned from the LLM review, and protection against removing or relaxing invariants.
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from guard.cli import app, execute_post_task, execute_pre_task
from guard.core.project_invariants import import_from_agent_docs, init_invariants_file
from guard.core.session import SessionManager
from guard.hooks.installer import HookInstaller

AGENT_MD = """# Project

## ⚙️ CÁC BẤT BIẾN KỸ THUẬT CỐT LÕI (CORE INVARIANTS)

1. **Không giới hạn Timeout khi Chat với AI:**
   * Tuyệt đối không dùng `AbortSignal.timeout(...)` trong luồng chat AI.
2. **Khóa Đại Cương:**
   * Chỉ ẩn `update_project_synopsis`.

## Other section
1. Not an invariant
"""


def git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "t@t")
    git(repo, "config", "user.name", "t")
    git(repo, "config", "core.hooksPath", ".git/hooks")
    (repo / "package.json").write_text('{"name": "fe", "scripts": {"build": "node -e \\"process.exit(0)\\""}}', encoding="utf-8")
    (repo / "src").mkdir()
    (repo / "src" / "chat.ts").write_text("export function send() { return fetch('/api'); }\n", encoding="utf-8")
    (repo / "AGENT.md").write_text(AGENT_MD, encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "init")
    return repo


def enable_llm(repo: Path):
    (repo / ".guard").mkdir(exist_ok=True)
    (repo / ".guard" / "config.json").write_text(json.dumps(
        {"llm": {"protocol": "openai", "base_url": "http://127.0.0.1:9/v1", "api_key": "k", "model": "m"}}), encoding="utf-8")


def commit_invariants(repo: Path, items):
    (repo / "guard.invariants.json").write_text(json.dumps({"invariants": items}), encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "invariants")


def test_init_imports_agent_doc_invariants_and_never_overwrites(tmp_path):
    repo = make_repo(tmp_path)
    items = import_from_agent_docs(repo)
    assert [i["id"] for i in items] == ["INV-01", "INV-02"]
    assert items[0]["description"].startswith("Không giới hạn Timeout khi Chat với AI.")
    assert "update_project_synopsis" in items[1]["description"]  # underscores survive
    assert all(i["checks"] == [] for i in items)

    path, created, imported = init_invariants_file(repo)
    assert created and imported == 2 and path.is_file()
    path.write_text('{"invariants": []}', encoding="utf-8")
    assert init_invariants_file(repo)[1] is False
    assert path.read_text(encoding="utf-8") == '{"invariants": []}'


def test_check_command_exit_codes(tmp_path):
    repo = make_repo(tmp_path)
    runner = CliRunner()
    assert runner.invoke(app, ["invariants", "check", "--repo", str(repo)]).exit_code == 2  # missing

    commit_invariants(repo, [{"id": "A", "description": "send exported",
                              "checks": [{"files": "src/chat.ts", "require": "export function send"}]}])
    assert runner.invoke(app, ["invariants", "check", "--repo", str(repo)]).exit_code == 0

    commit_invariants(repo, [{"id": "B", "description": "no fetch",
                              "checks": [{"files": "src/chat.ts", "forbid": r"fetch\("}]}])
    assert runner.invoke(app, ["invariants", "check", "--repo", str(repo)]).exit_code == 1

    (repo / "guard.invariants.json").write_text("{broken", encoding="utf-8")
    assert runner.invoke(app, ["invariants", "check", "--repo", str(repo)]).exit_code == 2


def test_hook_install_creates_local_invariants_only(tmp_path):
    repo = make_repo(tmp_path)
    ok, msgs = HookInstaller(repo).install("git")
    assert ok
    data = json.loads((repo / ".guard" / "invariants.json").read_text(encoding="utf-8"))
    assert [i["id"] for i in data["invariants"]] == ["INV-01", "INV-02"]
    assert not (repo / "guard.invariants.json").exists()
    status = subprocess.run(["git", "status", "--porcelain", "-uall"], cwd=repo, capture_output=True, text=True).stdout
    assert status == ""  # nothing shows up in the repository


def test_llm_discovered_invariants_are_validated_then_written(tmp_path):
    repo = make_repo(tmp_path)
    commit_invariants(repo, [{"id": "SEND-01", "description": "send exported",
                              "checks": [{"files": "src/chat.ts", "require": "export function send"}]}])
    enable_llm(repo)
    assert execute_pre_task("Tweak src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export function send() { return fetch('/api/v2'); }\n", encoding="utf-8")

    reply = (
        "SCORE: 9\nSUMMARY: ok\nFINDINGS: None\nINVARIANTS:\n"
        "- API-01 | chat calls go through /api | src/chat.ts | require | fetch\\('/api\n"
        "- API-02 | never uses axios | src/chat.ts | require | axios\n"
        "- SEND-01 | duplicate id | src/chat.ts | require | send\n"
        "- UX-01 | Esc stops generation\n"
    )
    with patch("guard.core.llm_reviewer.call_llm", return_value=reply):
        assert execute_post_task(repo_path=repo) is True

    post = SessionManager(repo).load_local_session().post
    assert post.learned_invariants == ["API-01", "UX-01"]
    assert any(r.startswith("API-02: check does not pass") for r in post.rejected_invariant_proposals)
    assert any(r.startswith("SEND-01: already present") for r in post.rejected_invariant_proposals)
    # Learned rules go to the local file; the repository's own rulebook is untouched
    shared = json.loads((repo / "guard.invariants.json").read_text(encoding="utf-8"))["invariants"]
    assert [i["id"] for i in shared] == ["SEND-01"]
    written = {i["id"]: i for i in json.loads((repo / ".guard" / "invariants.json").read_text(encoding="utf-8"))["invariants"]}
    assert written["API-01"]["origin"].startswith("llm:") and written["UX-01"]["checks"] == []

    # The learned additions are part of the approval: committing them passes the hook
    assert execute_post_task(repo_path=repo, hook=True) is True


def test_removing_an_invariant_silently_blocks(tmp_path):
    repo = make_repo(tmp_path)
    commit_invariants(repo, [
        {"id": "KEEP", "description": "send exported", "checks": [{"files": "src/chat.ts", "require": "export function send"}]},
        {"id": "GONE", "description": "uses fetch", "checks": [{"files": "src/chat.ts", "require": "fetch"}]},
    ])
    assert execute_pre_task("Tweak src/chat.ts", repo_path=repo) is True
    (repo / "guard.invariants.json").write_text(json.dumps({"invariants": [
        {"id": "KEEP", "description": "send exported", "checks": [{"files": "src/chat.ts", "require": "export function"}]},
    ]}), encoding="utf-8")
    assert execute_post_task(repo_path=repo) is False
    post = SessionManager(repo).load_local_session().post
    weakened = [v for v in post.rule_violations if v.rule_id == "INV-WEAKENED"]
    assert {v.severity for v in weakened} == {"CRITICAL"}
    assert any("`GONE` was removed" in v.message for v in weakened)
    assert any("`KEEP` checks were changed" in v.message for v in weakened)
    assert "guard.invariants.json" not in post.out_of_scope_files


def test_declared_rulebook_edit_is_reviewed_not_hard_blocked(tmp_path):
    repo = make_repo(tmp_path)
    commit_invariants(repo, [{"id": "GONE", "description": "uses fetch", "checks": [{"files": "src/chat.ts", "require": "fetch"}]}])
    assert execute_pre_task("Retire rule GONE", repo_path=repo, scope=["guard.invariants.json"]) is True
    (repo / "guard.invariants.json").write_text(json.dumps({"invariants": []}), encoding="utf-8")
    (repo / "src" / "chat.ts").write_text("export function send() { return 1; }\n", encoding="utf-8")  # the rule's target changes too
    execute_post_task(repo_path=repo)
    post = SessionManager(repo).load_local_session().post
    assert [v.severity for v in post.rule_violations if v.rule_id == "INV-WEAKENED"] == ["MEDIUM"]
    # The locked rule is judged by the task's explicit decision: retired, not a hard failure
    check = [c for c in post.invariant_result.checks if c.id == "GONE"][0]
    assert check.status == "retired" and check.passed
    assert post.invariant_result.all_passed


def test_undeclared_rulebook_edit_still_blocks_on_the_locked_rule(tmp_path):
    repo = make_repo(tmp_path)
    commit_invariants(repo, [{"id": "GONE", "description": "uses fetch", "checks": [{"files": "src/chat.ts", "require": "fetch"}]}])
    assert execute_pre_task("Tweak src/chat.ts", repo_path=repo) is True
    (repo / "guard.invariants.json").write_text(json.dumps({"invariants": []}), encoding="utf-8")
    (repo / "src" / "chat.ts").write_text("export function send() { return 1; }\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo) is False
    check = [c for c in SessionManager(repo).load_local_session().post.invariant_result.checks if c.id == "GONE"][0]
    assert check.status == "failed"


def test_appending_a_learned_rule_keeps_existing_entries_byte_identical(tmp_path):
    from guard.core.project_invariants import append_learned_invariants, dump_invariants
    repo = make_repo(tmp_path)
    original = dump_invariants({"invariants": [
        {"id": "SEND-01", "description": "send exported", "checks": [{"files": "src/chat.ts", "require": "export function send"}]},
    ]})
    (repo / "guard.invariants.json").write_text(original, encoding="utf-8", newline="\n")
    added, _ = append_learned_invariants(repo, [{"id": "UX-01", "description": "Esc stops generation"}], "s1")
    assert added == ["UX-01"]
    after = (repo / "guard.invariants.json").read_text(encoding="utf-8")
    assert after.startswith(original.rsplit("\n  ]", 1)[0])  # old block untouched, new one appended
    assert "$comment" not in after  # no header injected into a file that had none


def test_markdown_escapes_are_removed_from_proposed_globs_and_regexes():
    from guard.core.llm_reviewer import _parse_invariant_proposals
    text = "INVARIANTS:\n- X-1 | d | guard/core/project\\_invariants.py | require | def \\_model\\_fingerprint\n"
    check = _parse_invariant_proposals(text)[0]["checks"][0]
    assert check == {"files": "guard/core/project_invariants.py", "require": "def _model_fingerprint"}
