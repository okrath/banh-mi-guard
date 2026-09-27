"""
Tests that the gates cannot be satisfied by ritual: retroactive scope, template invariants,
comment-based rule bypass, silent LLM fallback, and hooks blocking unrelated repositories.
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from guard.cli import execute_post_task, execute_pre_task
from guard.core.config import GuardConfig, LLMConfig
from guard.core.invariant_eval import DomainType, evaluate_invariants
from guard.core.llm_reviewer import LLMReviewerEngine
from guard.core.ocr_engine import GitDiffInspector, OCRRulebookRunner, RuleViolation
from guard.core.session import SessionManager


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    for cmd in (["git", "init"], ["git", "config", "user.email", "t@t"], ["git", "config", "user.name", "t"],
                ["git", "config", "core.hooksPath", ".git/hooks"]):
        subprocess.run(cmd, cwd=repo, check=True, capture_output=True)
    (repo / "package.json").write_text('{"name": "fe", "scripts": {"build": "node -e \\"process.exit(0)\\""}}', encoding="utf-8")
    (repo / "src").mkdir()
    (repo / "src" / "chat.ts").write_text("export function send() { return fetch('/api'); }\n", encoding="utf-8")
    (repo / "src" / "other.ts").write_text("export const x = 1;\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)
    return repo


def write_invariants(repo: Path):
    (repo / "guard.invariants.json").write_text(json.dumps({"invariants": [
        {"id": "CHAT-01", "description": "Chat requests never time out",
         "checks": [{"files": "src/**/*.ts", "forbid": r"AbortSignal\.timeout"}]},
        {"id": "CHAT-02", "description": "send() stays exported",
         "checks": [{"files": "src/chat.ts", "require": r"export function send"}]},
        {"id": "UX-01", "description": "Message renders within 1ms"},
    ]}), encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "invariants"], cwd=repo, check=True, capture_output=True)


def test_pre_refuses_dirty_tree_unless_allowed(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "src" / "chat.ts").write_text("// edited before pre\n", encoding="utf-8")
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is False
    assert SessionManager(repo).load_local_session() is None

    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, allow_dirty=True) is True
    pre = SessionManager(repo).load_local_session().pre
    assert "src/chat.ts" in pre.baseline_dirty
    # Dirty files are baseline, never silently promoted to declared scope
    assert pre.expected_files == ["src/chat.ts"]


def test_pre_cannot_be_rerun_to_widen_scope(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "other.ts").write_text("export const x = 2;\n", encoding="utf-8")
    assert execute_pre_task("Fix src/chat.ts src/other.ts", repo_path=repo) is False
    assert SessionManager(repo).load_local_session().pre.expected_files == ["src/chat.ts"]

    assert execute_post_task(repo_path=repo) is False
    post = SessionManager(repo).load_local_session().post
    assert post.out_of_scope_files == ["src/other.ts"]


def test_preexisting_untouched_files_are_not_attributed(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "src" / "other.ts").write_text("export const x = 3;\n", encoding="utf-8")
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, allow_dirty=True) is True
    (repo / "src" / "chat.ts").write_text("export function send() { return fetch('/v2'); }\n", encoding="utf-8")
    execute_post_task(repo_path=repo)
    post = SessionManager(repo).load_local_session().post
    assert post.preexisting_files == ["src/other.ts"]
    assert post.out_of_scope_files == []
    assert any(v.rule_id == "SCOPE-003" for v in post.rule_violations)


def test_undeclared_scope_is_reported_not_punished(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Review the repo and fix bugs", repo_path=repo) is True
    (repo / "src" / "other.ts").write_text("export const x = 2;\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo) is True
    post = SessionManager(repo).load_local_session().post
    assert post.scope_declared is False
    assert post.out_of_scope_files == []


def test_deleted_files_are_flagged(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Clean up", repo_path=repo, scope=["src/**"]) is True
    (repo / "src" / "other.ts").unlink()
    execute_post_task(repo_path=repo)
    post = SessionManager(repo).load_local_session().post
    assert post.deleted_files == ["src/other.ts"]
    assert any(v.rule_id == "SCOPE-002" for v in post.rule_violations)


def test_project_invariants_replace_templates_and_are_really_checked(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "index.html").write_text("<div id=app></div>\n", encoding="utf-8")  # a web frontend
    write_invariants(repo)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    pre = SessionManager(repo).load_local_session().pre
    assert pre.domain == DomainType.FRONTEND
    assert [i.id for i in pre.locked_invariants] == ["CHAT-01", "CHAT-02", "UX-01"]
    assert pre.baseline_invariant_status == {"CHAT-01": "passed", "CHAT-02": "passed"}

    (repo / "src" / "chat.ts").write_text(
        "export function send() { return fetch('/api', { signal: AbortSignal.timeout(5000) }); }\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo) is False
    checks = {c.id: c for c in SessionManager(repo).load_local_session().post.invariant_result.checks}
    assert checks["CHAT-01"].status == "failed" and "src/chat.ts:1" in checks["CHAT-01"].notes
    assert checks["CHAT-02"].status == "passed"
    assert checks["UX-01"].status == "unverified"


def test_template_invariants_without_heuristic_are_unverified():
    res = evaluate_invariants(
        [{"id": "INFRA-INV-02", "description": "Do not bind database ports to 0.0.0.0/0."}], git_diff="+x", files_changed=[])
    assert res.checks[0].status == "unverified"
    assert res.unverified_count == 1
    assert res.engine_mode == "deterministic_rules"


def test_scope_matching_respects_path_boundaries():
    g = GitDiffInspector()
    assert g._is_expected("src/data.ts", ["a.ts"]) is False
    assert g._is_expected("src/a.ts", ["a.ts"]) is True
    assert g._is_expected("srcx/y.ts", ["src"]) is False
    assert g._is_expected("src/ui/x.css", ["src/**/*.css"]) is True
    assert g._is_expected("src/x.css", ["src/**/*.css"]) is True


def test_sanitize_comment_no_longer_bypasses_xss_rule():
    diff = (
        "+++ b/src/x.ts\n@@ -0,0 +1,4 @@\n"
        "+el.innerHTML = html; // sanitize: safe template\n"
        "+el.innerHTML = '';\n"
        "+el.innerHTML = DOMPurify.sanitize(h);\n"
        "+el.innerHTML = t; // guard-allow SEC-003: built only from escapeHtml output\n"
    )
    found = [(v.line_number, v.severity) for v in OCRRulebookRunner().scan_diff(diff) if v.rule_id == "SEC-003"]
    assert found == [(1, "HIGH"), (4, "LOW")]


def test_failed_llm_call_is_reported_not_disguised():
    cfg = GuardConfig(llm=LLMConfig(base_url="http://127.0.0.1:9/v1", api_key="k", model="m"))
    with patch("guard.core.llm_reviewer.call_llm", side_effect=TimeoutError("read timeout")):
        verdict = LLMReviewerEngine(config=cfg).review(prompt="p", domain=DomainType.FRONTEND)
    assert verdict.review_mode == "heuristic"
    assert "TimeoutError" in verdict.llm_error
    assert "LLM GATE" not in verdict.summary
    assert "did NOT run" in verdict.summary


def test_hook_mode_skips_repositories_without_session(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "src" / "other.ts").write_text("export const x = 9;\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo, hook=True) is True
    assert SessionManager(repo).load_local_session() is None


def git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def test_allow_dirty_after_revise_cannot_launder_edits(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "other.ts").write_text("export const x = 2;\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo) is False  # out of scope -> REVISE (NEEDS_FIX)

    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, allow_dirty=True) is False
    assert execute_pre_task("Fix src/chat.ts src/other.ts", repo_path=repo, allow_dirty=True, force=True) is True
    pre = SessionManager(repo).load_local_session().pre
    assert pre.baseline_dirty == {}  # inherited, the task's own edit is not baseline
    assert pre.late_scope == ["src/other.ts"]
    assert pre.restarts and pre.restarts[0]["status"] == "needs_fix"

    assert execute_post_task(repo_path=repo) is False
    post = SessionManager(repo).load_local_session().post
    assert any(v.rule_id == "SCOPE-004" for v in post.rule_violations)


def test_stash_restart_pop_is_still_audited(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "other.ts").write_text("export const x = 2;\n", encoding="utf-8")
    git(repo, "stash")
    assert execute_pre_task("Fix src/", repo_path=repo, force=True) is True
    git(repo, "stash", "pop")
    assert execute_post_task(repo_path=repo) is False
    assert SessionManager(repo).load_local_session().post.out_of_scope_files == ["src/other.ts"]


def test_mid_task_commit_is_still_audited(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "other.ts").write_text("export const x = 2;\n", encoding="utf-8")
    git(repo, "commit", "--no-verify", "-am", "sneak")  # an agent bypassing the hook
    assert execute_post_task(repo_path=repo) is False
    assert SessionManager(repo).load_local_session().post.out_of_scope_files == ["src/other.ts"]


def test_renamed_and_spaced_paths_are_tracked(tmp_path):
    repo = make_repo(tmp_path)
    git(repo, "mv", "src/other.ts", "src/renamed.ts")
    (repo / "src" / "a b ố.ts").write_text("el.innerHTML = t;\n", encoding="utf-8")
    working = GitDiffInspector(repo).get_working_files()
    assert "src/renamed.ts" in working and "src/a b ố.ts" in working
    assert not any("->" in f or f.startswith('"') for f in working)

    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, allow_dirty=True) is False  # untracked, undecided
    from guard.core.untracked import decide
    decide(repo, "src/a b ố.ts", "include")
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, allow_dirty=True) is True
    (repo / "src" / "new dir").mkdir()
    (repo / "src" / "new dir" / "x y.ts").write_text("el.innerHTML = t;\n", encoding="utf-8")
    execute_post_task(repo_path=repo)
    post = SessionManager(repo).load_local_session().post
    assert "src/new dir/x y.ts" in post.out_of_scope_files
    assert any(v.rule_id == "SEC-003" and v.file_path == "src/new dir/x y.ts" for v in post.rule_violations)


def test_malformed_invariants_file_fails_pre_cleanly(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "guard.invariants.json").write_text("{not json", encoding="utf-8")
    git(repo, "add", "."); git(repo, "commit", "-m", "bad")
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is False

    (repo / "guard.invariants.json").write_text(json.dumps({"invariants": [
        {"id": "X", "description": "d", "checks": [{"files": "src/*.ts", "forbid": "("}]}]}), encoding="utf-8")
    git(repo, "commit", "-am", "bad regex")
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    assert SessionManager(repo).load_local_session().pre.baseline_invariant_status == {"X": "failed"}


def test_invariant_failing_before_task_warns_but_does_not_block(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "guard.invariants.json").write_text(json.dumps({"invariants": [
        {"id": "LEGACY", "description": "no fetch", "checks": [{"files": "src/*.ts", "forbid": r"fetch\("}]}]}), encoding="utf-8")
    git(repo, "add", "."); git(repo, "commit", "-m", "inv")
    assert execute_pre_task("Fix src/other.ts", repo_path=repo) is True
    (repo / "src" / "other.ts").write_text("export const x = 5;\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo) is True
    check = SessionManager(repo).load_local_session().post.invariant_result.checks[0]
    assert check.status == "baseline_failed"


def test_hook_approval_covers_only_the_approved_changes(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/other.ts", repo_path=repo) is True
    (repo / "src" / "other.ts").write_text("export const x = 5;\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo) is True
    # Committing exactly the approved change passes without re-running the gate
    assert execute_post_task(repo_path=repo, hook=True) is True

    # Work edited after the approval (or unrelated to it) is not covered
    (repo / "src" / "chat.ts").write_text("// later unrelated work\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo, hook=True) is False
    (repo / "src" / "chat.ts").write_text("export function send() { return fetch('/api'); }\n", encoding="utf-8")
    (repo / "src" / "other.ts").write_text("export const x = 6;\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo, hook=True) is False


def test_reset_archives_and_closes_a_rejected_session(tmp_path):
    from typer.testing import CliRunner
    from guard.cli import app

    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "other.ts").write_text("export const x = 2;\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo) is False
    session_id = SessionManager(repo).load_local_session().session_id

    result = CliRunner().invoke(app, ["reset", "--repo", str(repo)])
    assert result.exit_code == 0
    assert SessionManager(repo).load_local_session() is None
    assert (repo / ".guard" / "history" / f"{session_id}.json").is_file()
    assert execute_post_task(repo_path=repo, hook=True) is True  # no session any more


def test_new_pre_archives_the_finished_session_it_replaces(tmp_path):
    import subprocess

    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export function send() { return fetch('/api/v2'); }\n", encoding="utf-8")
    execute_post_task(repo_path=repo)
    finished = SessionManager(repo).load_local_session()
    subprocess.run(["git", "-C", str(repo), "commit", "-qam", "work"], check=True)

    assert execute_pre_task("Fix src/other.ts", repo_path=repo, force=True) is True
    archived = repo / ".guard" / "history" / f"{finished.session_id}.json"
    assert archived.is_file()
    assert json.loads(archived.read_text(encoding="utf-8"))["status"] == finished.status.value


def test_archives_never_overwrite_each_other(tmp_path):
    repo = make_repo(tmp_path)
    mgr = SessionManager(repo)
    with patch("guard.core.session.time.time", return_value=1790000000):  # two sessions in the same second
        for prompt in ("Fix src/chat.ts", "Fix src/other.ts"):
            mgr.start_pre_session(prompt=prompt, expected_files=[], contracts=[], invariants=[])
        mgr.archive_and_clear()
    prompts = {json.loads(p.read_text(encoding="utf-8"))["pre"]["prompt"] for p in (repo / ".guard" / "history").glob("*.json")}
    assert prompts == {"Fix src/chat.ts", "Fix src/other.ts"}


def test_ocr_that_fails_or_finds_a_high_issue_blocks_post(tmp_path, fake_ocr_review):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export function send() { return fetch('/api/v2'); }\n", encoding="utf-8")

    fake_ocr_review.return_value = ("did not run: timed out after 900s", [
        RuleViolation(rule_id="OCR-RUN", severity="HIGH", file_path="(ocr)", message="Alibaba OCR review did not run")])
    assert execute_post_task(repo_path=repo, full=True) is False
    report = (repo / ".guard" / "POST_TASK_REPORT.md").read_text(encoding="utf-8")
    assert "**Alibaba OCR Review:** `did not run: timed out" in report and "nothing to commit until the gate approves" in report
    assert fake_ocr_review.call_args.kwargs["background"] == "Fix src/chat.ts"

    for severity in ("HIGH", "CRITICAL"):
        assert execute_pre_task("Fix src/chat.ts", repo_path=repo, force=True) is True
        fake_ocr_review.return_value = ("complete: 1 finding(s)", [
            RuleViolation(rule_id="OCR-BUG", severity=severity, file_path="src/chat.ts", message="wrong endpoint")])
        assert execute_post_task(repo_path=repo, full=True) is False, severity

    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, force=True) is True
    fake_ocr_review.return_value = ("complete: 0 finding(s)", [])
    assert execute_post_task(repo_path=repo, full=True) is True
    assert "Commit mode not set" in (repo / ".guard" / "POST_TASK_REPORT.md").read_text(encoding="utf-8")


def test_ocr_skips_only_dirty_files_the_task_left_untouched(tmp_path, fake_ocr_review):
    repo = make_repo(tmp_path)
    (repo / "src" / "chat.ts").write_text("export function send() { return fetch('/api/dirty'); }\n", encoding="utf-8")
    (repo / "src" / "other.ts").write_text("export const x = 2;\n", encoding="utf-8")  # unrelated, stays as is
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, allow_dirty=True) is True
    (repo / "src" / "chat.ts").write_text("export function send() { return fetch('/api/v2'); }\n", encoding="utf-8")
    execute_post_task(repo_path=repo, full=True)
    assert fake_ocr_review.call_args.kwargs["skip_files"] == ["src/other.ts"]  # chat.ts: dirty, but edited by the task


def test_a_dirty_file_the_task_edits_is_not_dropped_from_untracked_checks(tmp_path):
    from guard.core.untracked import decide, undecided
    repo = make_repo(tmp_path)
    (repo / "notes.md").write_text("mine\n", encoding="utf-8")  # untracked before pre
    decide(repo, "notes.md", "include")
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, allow_dirty=True) is True
    assert undecided(repo) == []


def test_plain_post_does_not_run_ocr_and_says_so(tmp_path, fake_ocr_review):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export function send() { return fetch('/api/v2'); }\n", encoding="utf-8")
    assert execute_post_task(repo_path=repo) is True
    fake_ocr_review.assert_not_called()
    assert "**Alibaba OCR Review:** `not run (optional: guard post --full adds it)`" in (
        repo / ".guard" / "POST_TASK_REPORT.md").read_text(encoding="utf-8")


def test_prompt_globs_do_not_widen_scope(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task(r"Fix src\chat.ts but do not edit *.css", repo_path=repo) is True
    assert SessionManager(repo).load_local_session().pre.expected_files == ["src/chat.ts"]
    g = GitDiffInspector()
    assert g._is_expected("src/deep/x.ts", ["src/*.ts"]) is False
    assert g._is_expected("app/[id]/page.tsx", ["app/[id]/page.tsx"]) is True


def test_allow_dirty_reviews_only_the_task_edits(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "src" / "other.ts").write_text("el.innerHTML = legacy;\n", encoding="utf-8")  # pre-existing sink
    (repo / "src" / "chat.ts").write_text("export function send() { return 1; }\n", encoding="utf-8")
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, allow_dirty=True) is True
    pre = SessionManager(repo).load_local_session().pre
    assert pre.baseline_snapshot

    # The task edits an already-dirty file further; only that new line is the task's
    (repo / "src" / "chat.ts").write_text("export function send() { return 1; }\nel.innerHTML = fresh;\n", encoding="utf-8")
    execute_post_task(repo_path=repo)
    post = SessionManager(repo).load_local_session().post
    sec = [v for v in post.rule_violations if v.rule_id == "SEC-003"]
    assert [v.file_path for v in sec] == ["src/chat.ts"]  # legacy sink in other.ts is not blamed on the task
    assert "src/other.ts" in post.preexisting_files
    scope3 = [v for v in post.rule_violations if v.rule_id == "SCOPE-003"][0]
    assert scope3.severity == "MEDIUM"


def test_large_diff_is_reviewed_in_parts_not_truncated():
    from guard.core.ocr_engine import DiffSummary
    big = "".join(f"diff --git a/src/f{i}.ts b/src/f{i}.ts\n+++ b/src/f{i}.ts\n" + "+x\n" * 20000 for i in range(3))
    cfg = GuardConfig(llm=LLMConfig(base_url="http://127.0.0.1:9/v1", api_key="k", model="m"))
    replies = iter([
        "SCORE: 9\nSUMMARY: ok\nFINDINGS: None",
        "SCORE: 5\nSUMMARY: bad\nFINDINGS:\n- high | correctness | src/f1.ts:1 | - | breaks f1",
        "SCORE: 8\nSUMMARY: ok\nFINDINGS: None",
    ])
    prompts = []

    def fake_call(**kw):
        prompts.append(kw["prompt"])
        return next(replies)

    with patch("guard.core.llm_reviewer.call_llm", side_effect=fake_call):
        verdict = LLMReviewerEngine(config=cfg).review(
            prompt="p", domain=DomainType.FRONTEND, diff_summary=DiffSummary(raw_diff=big))
    assert len(prompts) == 3 and all("TRUNCATED" not in p for p in prompts)
    assert "Diff part 2/3" in prompts[1]
    assert verdict.verdict.value == "REVISE" and verdict.score == 5.0
    assert verdict.review_mode == "llm_deep"


def test_new_invariants_file_is_self_checked_on_post(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Add guard.invariants.json", repo_path=repo) is True
    (repo / "guard.invariants.json").write_text(json.dumps({"invariants": [
        {"id": "OK", "description": "send exported", "checks": [{"files": "src/chat.ts", "require": "export function send"}]},
        {"id": "BROKEN", "description": "typo", "checks": [{"files": "src/chat.ts", "require": "export function sned"}]},
    ]}), encoding="utf-8")
    assert execute_post_task(repo_path=repo) is False
    checks = {c.id: c.status for c in SessionManager(repo).load_local_session().post.invariant_result.checks}
    assert checks["OK (new guard.invariants.json, self-check)"] == "passed"
    assert checks["BROKEN (new guard.invariants.json, self-check)"] == "failed"


def test_escape_heuristic_ignores_identifiers_named_escape():
    inv = [{"id": "FE-INV-02", "description": "Keep Escape and Enter keyboard navigation working."}]
    ident = evaluate_invariants(inv, "-function formatInline(escapedText: string) {\n-  return escapeHtml(x);\n", [])
    assert ident.checks[0].status == "passed"
    for removed in ["-  if (e.key === 'Escape') close();", "-  window.addEventListener('keydown', onKey);"]:
        assert evaluate_invariants(inv, removed, []).checks[0].status == "failed"


def test_removed_symbols_still_referenced_are_reported(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "src" / "icons.ts").write_text(
        "export function icon(n: string) {\n  switch (n) {\n    case 'edit':\n      return 'e';\n    case 'gone':\n      return 'g';\n  }\n}\n", encoding="utf-8")
    (repo / "src" / "style.css").write_text(".btn-live { color: red; }\n.btn-dead { color: blue; }\n", encoding="utf-8")
    (repo / "src" / "use.ts").write_text("icon('edit'); el.className = 'btn-live';\n", encoding="utf-8")
    git(repo, "add", "."); git(repo, "commit", "-m", "base")
    assert execute_pre_task("Remove dead icons and css", repo_path=repo, scope=["src"]) is True

    (repo / "src" / "icons.ts").write_text(
        "export function icon(n: string) {\n  switch (n) {\n  }\n}\n", encoding="utf-8")  # removes 'edit' (used) and 'gone' (dead)
    (repo / "src" / "style.css").write_text(".btn-live { color: red; }\n", encoding="utf-8")  # removes .btn-dead only
    execute_post_task(repo_path=repo)
    post = SessionManager(repo).load_local_session().post
    dead_refs = [v.message for v in post.rule_violations if v.rule_id == "DEAD-REF"]
    assert len(dead_refs) == 1 and "`edit`" in dead_refs[0] and "src/use.ts:1" in dead_refs[0]


def test_restart_keeps_the_rules_locked_at_the_first_pre(tmp_path):
    repo = make_repo(tmp_path)
    write_invariants(repo)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    # The task edits the rulebook to drop a rule, then restarts to re-lock from the edited file
    (repo / "guard.invariants.json").write_text(json.dumps({"invariants": [
        {"id": "CHAT-02", "description": "send() stays exported",
         "checks": [{"files": "src/chat.ts", "require": "export function send"}]}]}), encoding="utf-8")
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, force=True) is True
    locked = [i.id for i in SessionManager(repo).load_local_session().pre.locked_invariants]
    assert locked == ["CHAT-01", "CHAT-02", "UX-01"]


def test_build_info_names_the_script_that_ran():
    from guard.core.llm_reviewer import _resolved_script
    assert _resolved_script("vite v6\n$ tsc && vite build\n") == "tsc && vite build"
    assert _resolved_script("\n> fe@0.1.0 build\n> tsc -b && vite build\n") == "tsc -b && vite build"
    assert _resolved_script("no script echo here") is None
