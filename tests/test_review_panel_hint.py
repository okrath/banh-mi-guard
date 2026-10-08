"""
After a plain review approves a large or security-sensitive diff, the Commit line tells the agent to ask the user
one question: this approval, a review panel of three reviewers, a full OCR review, or both.
"""

from __future__ import annotations

from pathlib import Path

from test_review_report import edited_repo, fake_reviewer, post

from guard.core.llm_reviewer import LLMReviewVerdict, ReviewVerdict
from guard.core.session import PostTaskRecord, SessionManager
from guard.reporters.markdown import commit_instruction


def record(repo: Path) -> PostTaskRecord:
    session = SessionManager(repo).load_local_session()
    assert session is not None and session.post is not None
    return session.post


def commit_line(repo: Path) -> str:
    return (repo / ".guard" / "POST_TASK_REPORT.md").read_text(encoding="utf-8").split("**Commit:**")[1]


def test_a_small_plain_change_keeps_the_usual_question(tmp_path, monkeypatch):
    repo = edited_repo(tmp_path)
    fake_reviewer(monkeypatch)
    assert post(repo).exit_code == 0
    assert record(repo).panel_hint == {}
    line = commit_line(repo)
    assert "full review with Alibaba OCR first" in line and "--reviewers" not in line


def test_a_large_change_asks_one_question_with_the_panel_command(tmp_path, monkeypatch):
    repo = edited_repo(tmp_path)
    (repo / "src" / "chat.ts").write_text("".join(f"export const a{i} = {i};\n" for i in range(450)), encoding="utf-8")
    fake_reviewer(monkeypatch)
    assert post(repo).exit_code == 0
    hint = record(repo).panel_hint
    assert any("changed lines" in r for r in hint["reasons"])
    assert hint["command"] == "guard post --reviewers 3 --max-llm-calls 6" and hint["calls"] == 6
    line = commit_line(repo)
    assert "ask the user one question" in line and "`guard post --reviewers 3 --max-llm-calls 6`" in line
    assert "`guard post --full`" in line and "`guard post --reviewers 3 --max-llm-calls 6 --full`" in line


def test_a_diff_in_several_parts_counts_its_parts_and_the_calls_they_need(tmp_path, monkeypatch):
    repo = edited_repo(tmp_path)
    for name in ("big1.ts", "big2.ts"):  # each close to one review part: two parts
        (repo / "src" / name).write_text("// x\n" + ("export const s = '" + "y" * 60000 + "';\n"), encoding="utf-8")
    fake_reviewer(monkeypatch)
    assert post(repo).exit_code == 0
    hint = record(repo).panel_hint
    assert "2 review parts" in hint["reasons"] and hint["command"].endswith("--max-llm-calls 12")


def test_a_security_sensitive_change_is_offered_the_panel(tmp_path, monkeypatch):
    repo = edited_repo(tmp_path)
    (repo / "src" / "auth").mkdir()
    (repo / "src" / "auth" / "session.ts").write_text("export const token = 'x';\n", encoding="utf-8")
    fake_reviewer(monkeypatch)
    assert post(repo).exit_code == 0
    assert any(r.startswith("security-sensitive: ") for r in record(repo).panel_hint["reasons"])


def test_no_offer_when_the_gate_rejects_or_a_panel_already_ran(tmp_path, monkeypatch):
    repo = edited_repo(tmp_path)
    (repo / "src" / "chat.ts").write_text("".join(f"export const a{i} = {i};\n" for i in range(450)), encoding="utf-8")
    calls = fake_reviewer(monkeypatch)
    assert post(repo, "--reviewers", "3", "--max-llm-calls", "18").exit_code == 0
    assert record(repo).panel_hint == {}
    assert calls[0]["options"].reviewers == 3 and calls[0]["options"].max_llm_calls == 18  # the flag reaches the review

    def rejects(self, **kwargs):
        return LLMReviewVerdict(verdict=ReviewVerdict.REVISE, score=4.0, summary="No.", review_mode="llm_deep")
    monkeypatch.setattr("guard.core.llm_reviewer.LLMReviewerEngine.review", rejects)
    (repo / "src" / "chat.ts").write_text("export const a = 3;\n" * 450, encoding="utf-8")
    assert post(repo).exit_code == 1
    assert record(repo).panel_hint == {}


def test_after_a_full_ocr_review_only_the_panel_is_offered():
    hint = {"reasons": ["450 changed lines"], "calls": 6, "command": "guard post --reviewers 3 --max-llm-calls 6"}
    line = commit_instruction(PostTaskRecord(all_passed=True, muse_verdict="APPROVED", commit_mode="auto",
                                             ocr_status="complete: 0 finding(s)", panel_hint=hint))
    assert "deeper review by a review panel of three LLM reviewers" in line and "Alibaba OCR" not in line
    assert "write the commit message yourself" in line
