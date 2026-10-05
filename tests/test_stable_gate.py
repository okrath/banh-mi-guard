"""
The LLM gate's verdict is computed from structured findings, remembers earlier rounds, and stops
after its round budget so the user decides.
"""

import subprocess
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from guard.agent.events import AgentEvent, decide
from guard.cli import app, execute_post_task, execute_pre_task
from guard.core.config import GuardConfig, LLMConfig
from guard.core.invariant_eval import DomainType
from guard.core.llm_reviewer import Finding, LLMReviewerEngine, LLMReviewVerdict, ReviewVerdict, parse_findings
from guard.core.ocr_engine import RuleViolation
from guard.core.session import SessionManager, SessionStatus

TASK = "Fix src/chat.ts: retries must stop after three attempts"


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    (repo / "src").mkdir(parents=True)
    for cmd in (["git", "init"], ["git", "config", "user.email", "t@t"], ["git", "config", "user.name", "t"],
                ["git", "config", "core.hooksPath", ".git/hooks"]):
        subprocess.run(cmd, cwd=repo, check=True, capture_output=True)
    (repo / "package.json").write_text('{"name": "fe", "scripts": {"build": "node -e \\"process.exit(0)\\""}}', encoding="utf-8")
    (repo / "src" / "chat.ts").write_text("export const a = 1;\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)
    return repo


def test_guard_not_the_model_decides_what_blocks():
    text = (
        "SCORE: 6\nSUMMARY: s\nFINDINGS:\n"
        "- medium | maintainability | src/chat.ts:3 | - | could be clearer\n"
        "- high | correctness | src/chat.ts:9 | - | retries never stop\n"
        "- low | requirement | src/chat.ts:1 | retries must stop after three attempts | stops after four\n"
        "- medium | requirement | src/chat.ts:2 | retries must be exponential | not exponential\n"
        "- high | style | src/chat.ts:4 | - | naming\n"
    )
    findings = parse_findings(text, TASK)
    blocking = {f.description: f.why_blocking for f in findings if f.blocking}
    assert blocking == {"retries never stop": "high correctness", "stops after four": "violates a stated requirement"}
    # a quoted "requirement" that is not in the task, and a high style nit, are advisory
    assert {f.description for f in findings if not f.blocking} == {"could be clearer", "not exponential", "naming"}


def test_advisory_findings_approve_and_the_ledger_reaches_the_next_prompt():
    cfg = GuardConfig(llm=LLMConfig(base_url="http://127.0.0.1:9/v1", api_key="k", model="m"))
    prompts = []

    def fake_call(**kw):
        prompts.append(kw["prompt"] + kw.get("system_prompt", ""))
        return "SCORE: 7\nSUMMARY: fine\nFINDINGS:\n- medium | maintainability | a.ts:1 | - | tidy this"

    ledger = [{"id": "abc12345", "round": 1, "status": "deferred", "note": "phase 9", "severity": "medium",
               "kind": "maintainability", "location": "a.ts:1", "description": "tidy this"}]
    with patch("guard.core.llm_reviewer.call_llm", side_effect=fake_call):
        verdict = LLMReviewerEngine(config=cfg).review(prompt=TASK, domain=DomainType.BACKEND, ledger=ledger)
    assert verdict.verdict == ReviewVerdict.APPROVED and verdict.remediation_steps == []
    assert "[abc12345] round 1, deferred (phase 9)" in prompts[0]  # the reviewer sees what was decided
    assert "You do not decide the verdict" in prompts[0]


def test_an_unstructured_revise_is_no_llm_review():
    cfg = GuardConfig(llm=LLMConfig(base_url="http://127.0.0.1:9/v1", api_key="k", model="m"))
    answers = iter(["SCORE: 3\nVERDICT: REVISE\nSUMMARY: bad", "SCORE: 3\nVERDICT: REVISE\nSUMMARY: bad\nREMEDIATION: - fix it"])
    with patch("guard.core.llm_reviewer.call_llm", side_effect=lambda **kw: next(answers)) as llm:
        verdict = LLMReviewerEngine(config=cfg).review(prompt=TASK, domain=DomainType.BACKEND)
    # asked again, then reported as no LLM review: it neither blocks nor counts as an LLM approval
    assert llm.call_count == 2 and verdict.review_mode != "llm_deep" and verdict.llm_error


def _revise(desc="retries never stop"):
    f = Finding(id="f" + str(abs(hash(desc)) % 10 ** 7), severity="high", kind="correctness", location="src/chat.ts:1",
                description=desc, blocking=True, why_blocking="high correctness")
    return LLMReviewVerdict(verdict=ReviewVerdict.REVISE, score=4, summary="s", findings=[f], review_mode="llm_deep")


def test_the_third_revise_hands_the_decision_to_the_user(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    with patch("guard.task_flow.LLMReviewerEngine.review", return_value=_revise()):
        for _ in range(2):
            assert execute_post_task(repo_path=repo) is False
        assert SessionManager(repo).load_local_session().status == SessionStatus.NEEDS_FIX
        assert execute_pre_task("Fix src/chat.ts", repo_path=repo, force=True) is True  # a restart keeps the count
        assert execute_post_task(repo_path=repo) is False
    session = SessionManager(repo).load_local_session()
    assert session.status == SessionStatus.NEEDS_USER and session.llm_revise_rounds == 3
    assert len(session.findings_ledger) == 1 and session.findings_ledger[0]["status"] == "open"  # same finding, one entry
    assert "needs_user" in (repo / ".guard" / "POST_TASK_REPORT.md").read_text(encoding="utf-8")

    commit = decide(AgentEvent(event="before-edit", cwd=str(repo), tool="Bash", command="git commit -m x"))
    assert commit.action == "block" and "guard accept" in commit.reason
    assert decide(AgentEvent(event="stop", cwd=str(repo))).action == "allow"  # stopping to ask is right

    # neither another round, a restart nor a reset takes the decision away from the user
    with patch("guard.task_flow.LLMReviewerEngine.review") as review:
        assert execute_post_task(repo_path=repo) is False
    assert review.call_count == 0
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo, force=True) is False
    assert CliRunner().invoke(app, ["reset", "--repo", str(repo)]).exit_code == 1
    with patch("sys.stdin.isatty", return_value=True, create=True), patch("sys.stdout.isatty", return_value=True, create=True):
        assert CliRunner().invoke(app, ["reset", "--repo", str(repo)]).exit_code == 1  # even in a terminal: guard accept
    assert SessionManager(repo).load_local_session().status == SessionStatus.NEEDS_USER


def test_an_unreadable_findings_list_never_approves():
    cfg = GuardConfig(llm=LLMConfig(base_url="http://127.0.0.1:9/v1", api_key="k", model="m"))
    for reply in ("SCORE: 9\nVERDICT: APPROVED\nSUMMARY: ok",  # no FINDINGS at all
                  "SCORE: 9\nSUMMARY: ok\nFINDINGS:\n- severe | correctness | a.ts:1 | - | data loss",  # unknown severity
                  "SCORE: 9\nSUMMARY: ok\nFINDINGS:\n- high | bug | a.ts:1 | - | data loss",  # unknown kind
                  "SCORE: 9\nSUMMARY: ok\nFINDINGS:\n- high correctness: data loss"):  # too few fields
        with patch("guard.core.llm_reviewer.call_llm", return_value=reply) as llm:
            verdict = LLMReviewerEngine(config=cfg).review(prompt=TASK, domain=DomainType.BACKEND)
        assert verdict.review_mode != "llm_deep" and verdict.llm_error, reply  # reported as no LLM review
        assert llm.call_count == 2  # asked again with the format reminder first


def test_a_requirement_quote_matches_whole_words_of_the_task():
    def blocks(quote):
        return parse_findings(f"FINDINGS:\n- low | requirement | a.ts:1 | {quote} | d", "Keep it offline. Retries: max three")[0].blocking
    assert blocks("keep it offline") and blocks("retries max")  # case and punctuation aside
    assert not blocks("offline")  # one word is not a requirement
    assert not blocks("ep it offl")  # fragments of words are not a quote


def test_an_approval_keeps_every_advisory_and_deferral_as_follow_ups(tmp_path):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    first = _revise()
    first.findings.append(Finding(id="adv00001", severity="low", kind="style", description="rename a"))
    with patch("guard.task_flow.LLMReviewerEngine.review", return_value=first):
        execute_post_task(repo_path=repo)
    fid = first.findings[0].id
    assert CliRunner().invoke(app, ["finding", fid, "--defer", "tracked in phase 9", "--repo", str(repo)]).exit_code == 0
    approved = LLMReviewVerdict(verdict=ReviewVerdict.APPROVED, score=8, summary="ok", findings=[], review_mode="llm_deep")
    with patch("guard.task_flow.LLMReviewerEngine.review", return_value=approved):
        assert execute_post_task(repo_path=repo) is True
    followups = SessionManager(repo).load_local_session().post.followups
    assert sorted(f["id"] for f in followups) == sorted([fid, "adv00001"])

    # an approval by the heuristic gate alone (LLM not answering) keeps them too
    heuristic = approved.model_copy(update={"review_mode": "heuristic"})
    with patch("guard.task_flow.LLMReviewerEngine.review", return_value=heuristic):
        assert execute_post_task(repo_path=repo) is True
    followups = SessionManager(repo).load_local_session().post.followups
    assert sorted(f["id"] for f in followups) == sorted([fid, "adv00001"])
    assert "Follow-ups of this task" in (repo / ".guard" / "POST_TASK_REPORT.md").read_text(encoding="utf-8")


def test_guard_accept_is_the_users_and_approves_only_what_was_reviewed(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    first = _revise()
    first.findings.append(Finding(id="adv00001", severity="low", kind="style", description="rename a"))
    with patch("guard.task_flow.LLMReviewerEngine.review", return_value=first):
        execute_post_task(repo_path=repo)  # the advisory is raised only in the first round
    with patch("guard.task_flow.LLMReviewerEngine.review", return_value=_revise()):
        for _ in range(2):
            execute_post_task(repo_path=repo)
    monkeypatch.chdir(repo)
    assert CliRunner().invoke(app, ["accept"]).exit_code == 1  # no terminal: an agent cannot accept

    import guard.cli as cli
    import guard.commands.review as review_cmds

    def accept(answer):
        import pytest
        # a local patch: monkeypatch.undo() would also undo conftest's HOME / GUARD_HOME isolation
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(review_cmds.Prompt, "ask", lambda *a, **k: answer)
            mp.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
            mp.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
            try:
                review_cmds.accept_cmd(repo=str(repo))
                return 0
            except cli.typer.Exit as e:
                return e.exit_code

    (repo / "src" / "chat.ts").write_text("export const a = 3;\n", encoding="utf-8")  # edited after the review
    assert accept("a") == 1
    assert accept("actually no") == 0  # only an explicit "a" approves
    assert SessionManager(repo).load_local_session().status == SessionStatus.NEEDS_USER
    mgr = SessionManager(repo)
    s = mgr.load_local_session()
    s.post.build_check = s.post.build_check.model_copy(update={"passed": False}) if s.post.build_check else None
    s.post.out_of_scope_files = ["other.ts"]
    mgr._save(s)
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    assert accept("a") == 1  # a failed deterministic gate is never accepted
    s.post.out_of_scope_files = []
    s.post.build_check = s.post.build_check.model_copy(update={"passed": True}) if s.post.build_check else None
    s.post.rule_violations = [RuleViolation(rule_id="OCR-SEC", severity="HIGH", file_path="src/chat.ts", message="leak")]
    mgr._save(s)
    assert accept("a") == 1  # nor an Alibaba OCR high finding
    s.post.rule_violations = []
    mgr._save(s)
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")  # back to what was reviewed
    assert accept("c") == 0
    session = SessionManager(repo).load_local_session()
    assert session.revise_budget == 6 and session.status == SessionStatus.NEEDS_FIX
    assert "needs_user" not in (repo / ".guard" / "POST_TASK_REPORT.md").read_text(encoding="utf-8")  # report follows

    with patch("guard.task_flow.LLMReviewerEngine.review", return_value=_revise()):
        for _ in range(3):
            execute_post_task(repo_path=repo)
    assert accept("a") == 0
    session = SessionManager(repo).load_local_session()
    assert session.status == SessionStatus.COMPLETED and session.post.accepted_by_user
    assert session.post.approved_fingerprints == session.post.reviewed_fingerprints
    assert sorted((f["id"], f["status"]) for f in session.post.followups) == sorted(
        [(_revise().findings[0].id, "open"), ("adv00001", "not raised again")])  # earlier advisories are kept
    assert "Approved by the user" in (repo / ".guard" / "POST_TASK_REPORT.md").read_text(encoding="utf-8")


def test_a_deferral_is_recorded_for_the_next_review(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    with patch("guard.task_flow.LLMReviewerEngine.review", return_value=_revise()):
        execute_post_task(repo_path=repo)
    fid = SessionManager(repo).load_local_session().findings_ledger[0]["id"]
    monkeypatch.chdir(repo)
    assert CliRunner().invoke(app, ["finding", fid]).exit_code == 1  # a reason is required
    assert CliRunner().invoke(app, ["finding", fid, "--defer", "handled in phase 9"]).exit_code == 0
    entry = SessionManager(repo).load_local_session().findings_ledger[0]
    assert (entry["status"], entry["note"]) == ("deferred", "handled in phase 9")
