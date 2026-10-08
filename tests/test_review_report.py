"""
Review flags, configuration and report: options resolution through `guard post` and `guard config review`,
the options reaching the reviewer, and the coverage / validation / heuristic lines of both reports.
No test calls a model: the reviewer is replaced by a scripted fake.
"""

from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console
from typer.testing import CliRunner

import guard.core.config as guard_config
from guard.cli import app
from guard.commands import config as config_cmd
from guard.core import llm_reviewer
from guard.core.config import GuardConfig, load_global_config, save_config
from guard.core.invariant_eval import DomainType
from guard.core.llm_reviewer import LLMReviewVerdict, ReviewVerdict
from guard.core.ocr_engine import DiffSummary, FileDiffStat
from guard.core.review_options import ReviewOptions
from guard.core.session import BuildCheckResult, GuardSession, PostTaskRecord, PreTaskRecord, SessionManager
from guard.reporters import terminal
from guard.reporters.markdown import generate_post_task_markdown
from guard.task_flow import execute_post_task, execute_pre_task, review_options_line

runner = CliRunner()
NOTE = "2 part(s) were cut by the review limit and not reviewed."


# --- helpers -------------------------------------------------------------------------------------------------

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


def edited_repo(tmp_path: Path) -> Path:
    """A repository with a guard session and one edited file, ready for guard post."""
    repo = make_repo(tmp_path)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is True
    (repo / "src" / "chat.ts").write_text("export const a = 2;\n", encoding="utf-8")
    return repo


def write_local_config(repo: Path, review: dict) -> None:
    (repo / ".guard").mkdir(exist_ok=True)
    (repo / ".guard" / "config.json").write_text(json.dumps({"review": review}), encoding="utf-8")


def fake_reviewer(monkeypatch, **verdict_fields):
    """Replace the reviewer; returns the list of keyword arguments each review() call received."""
    calls: list = []

    def review(self, **kwargs):
        calls.append(kwargs)
        return LLMReviewVerdict(
            verdict=ReviewVerdict.APPROVED, score=9.0, summary="Fine.", review_mode="llm_deep", **verdict_fields,
        )

    monkeypatch.setattr(llm_reviewer.LLMReviewerEngine, "review", review)
    return calls


def post(repo: Path, *flags: str):
    return runner.invoke(app, ["post", "--repo", str(repo), *flags])


# --- options resolution through guard post ------------------------------------------------------------------

def test_flags_reach_the_reviewer_and_are_recorded_with_their_sources(tmp_path, monkeypatch):
    repo = edited_repo(tmp_path)
    write_local_config(repo, {"reviewers": 2, "test_checklist": True})
    calls = fake_reviewer(monkeypatch)

    result = post(repo, "--reviewers", "4", "--validate", "--threat-frame", "auto")

    assert result.exit_code == 0, result.output
    opts = calls[0]["options"]
    assert isinstance(opts, ReviewOptions)
    assert (opts.reviewers, opts.validate_findings, opts.threat_frame, opts.test_checklist) == (4, True, "auto", True)
    assert "Review options: " in result.output and "reviewers=4 (cli)" in result.output
    assert "validate_findings=on (cli)" in result.output and "test_checklist=on (config)" in result.output
    assert "threat_frame=auto (cli)" in result.output and "LLM calls" in result.output
    record = SessionManager(repo).load_local_session().post
    assert record.review_options["options"]["reviewers"] == 4
    assert record.review_options["sources"]["reviewers"] == "cli"
    assert record.review_options["sources"]["test_checklist"] == "config"
    assert record.review_options["sources"]["part_manifest"] == "default"


def test_flags_not_passed_leave_the_config_alone_and_defaults_print_nothing(tmp_path, monkeypatch):
    repo = edited_repo(tmp_path)
    calls = fake_reviewer(monkeypatch)

    result = post(repo)

    assert result.exit_code == 0, result.output
    assert calls[0]["options"] == ReviewOptions()
    assert "Review options:" not in result.output

    write_local_config(repo, {"reviewers": 3})
    (repo / "src" / "chat.ts").write_text("export const a = 3;\n", encoding="utf-8")
    result = post(repo, "--no-validate")  # a flag set to its default still counts as passed
    assert calls[1]["options"].reviewers == 3 and calls[1]["options"].validate_findings is False
    assert "reviewers=3 (config)" in result.output


def test_environment_variables_change_nothing(tmp_path, monkeypatch):
    repo = edited_repo(tmp_path)
    calls = fake_reviewer(monkeypatch)
    for name in ("GUARD_REVIEW_REVIEWERS", "GUARD_REVIEWERS", "GUARD_REVIEW_VALIDATE_FINDINGS", "GUARD_VALIDATE_FINDINGS",
                 "GUARD_REVIEW_THREAT_FRAME", "GUARD_REVIEW_MAX_LLM_CALLS"):
        monkeypatch.setenv(name, "5" if "REVIEWERS" in name or "CALLS" in name else "on")

    result = post(repo)

    assert result.exit_code == 0, result.output
    assert calls[0]["options"] == ReviewOptions()


@pytest.mark.parametrize("flags", [("--reviewers", "0"), ("--reviewers", "6"), ("--reviewers", "two")])
def test_a_reviewer_count_outside_1_to_5_is_refused_before_any_review(tmp_path, monkeypatch, flags):
    repo = edited_repo(tmp_path)
    calls = fake_reviewer(monkeypatch)

    result = post(repo, *flags)

    assert result.exit_code != 0 and calls == []


def test_an_invalid_threat_frame_or_config_value_refuses_the_post_and_names_the_allowed_values(tmp_path, monkeypatch):
    repo = edited_repo(tmp_path)
    calls = fake_reviewer(monkeypatch)

    result = post(repo, "--threat-frame", "loud")
    assert result.exit_code == 1 and "threat_frame" in result.output and "off" in result.output and "auto" in result.output

    write_local_config(repo, {"reviewers": 9})
    result = post(repo)
    assert result.exit_code == 1 and "reviewers" in result.output and "1 and 5" in result.output
    assert calls == []


def test_review_options_line_lists_every_difference_with_cost_and_weakness():
    assert review_options_line(ReviewOptions(), {}) == ""
    opts = ReviewOptions(reviewers=3, validate_findings=True, coverage_notes=False, max_llm_calls=4)
    sources = {"reviewers": "cli", "validate_findings": "config", "coverage_notes": "config", "max_llm_calls": "config"}

    line = review_options_line(opts, sources, parts=2)

    assert line.startswith("Review options: ")
    assert "reviewers=3 (cli)" in line and "validate_findings=on (config)" in line
    assert "coverage_notes=off (config, weaker than default)" in line
    assert "max_llm_calls=4 (config, weaker than default)" in line
    assert line.endswith(f"; up to {opts.cost_hint(2)} LLM calls")
    stronger = review_options_line(ReviewOptions(max_llm_calls=30), {"max_llm_calls": "cli"})
    assert "weaker" not in stronger and "up to" not in stronger  # no extra calls: no cost hint


# --- guard config review ------------------------------------------------------------------------------------

@pytest.fixture
def user_config(tmp_path, monkeypatch):
    """The machine-wide config in a throwaway file; the working directory has no local config."""
    path = tmp_path / "home" / "config.json"
    monkeypatch.setattr(guard_config, "get_global_config_path", lambda: path)
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    return path


def set_tty(monkeypatch, value: bool) -> None:
    """The command's view of the terminal (the runner swaps sys.stdin and sys.stdout while it runs)."""
    stream = SimpleNamespace(isatty=lambda: value)
    monkeypatch.setattr(config_cmd, "sys", SimpleNamespace(stdin=stream, stdout=stream))


def test_config_review_shows_effective_options_and_sources(user_config):
    user_config.parent.mkdir(parents=True)
    user_config.write_text(json.dumps({"review": {"reviewers": 3}}), encoding="utf-8")

    result = runner.invoke(app, ["config", "review"])

    assert result.exit_code == 0, result.output
    assert "reviewers = 3  (config)" in result.output
    assert "validate_findings = False  (default)" in result.output
    assert "coverage_notes = True  (default)" in result.output


def test_config_review_write_is_refused_without_a_terminal_and_changes_nothing(user_config, monkeypatch):
    set_tty(monkeypatch, False)

    result = runner.invoke(app, ["config", "review", "reviewers", "3"])

    assert result.exit_code == 1 and "interactive terminal" in result.output
    assert not user_config.exists()


def test_config_review_write_in_a_terminal_is_validated_and_kept(user_config, monkeypatch):
    set_tty(monkeypatch, True)

    ok = runner.invoke(app, ["config", "review", "reviewers", "3"])
    assert ok.exit_code == 0, ok.output
    assert runner.invoke(app, ["config", "review", "validate_findings", "yes"]).exit_code == 0
    assert load_global_config().review == {"reviewers": 3, "validate_findings": True}

    bad = runner.invoke(app, ["config", "review", "reviewers", "9"])
    assert bad.exit_code == 1 and "1 and 5" in bad.output
    bad = runner.invoke(app, ["config", "review", "threat_frame", "loud"])
    assert bad.exit_code == 1 and "off" in bad.output and "auto" in bad.output
    unknown = runner.invoke(app, ["config", "review", "turbo", "on"])
    assert unknown.exit_code == 1 and "Unknown review option" in unknown.output and "reviewers" in unknown.output
    assert runner.invoke(app, ["config", "review", "reviewers"]).exit_code == 1  # a key without a value
    assert load_global_config().review == {"reviewers": 3, "validate_findings": True}  # nothing invalid was saved


def test_review_settings_survive_a_save_and_load_round_trip(user_config):
    cfg = GuardConfig(review={"reviewers": 2, "threat_frame": "auto"})
    save_config(cfg)
    reloaded = load_global_config()
    reloaded.commit_mode = "auto"  # what `guard config commit` does
    save_config(reloaded)

    assert json.loads(user_config.read_text(encoding="utf-8"))["review"] == {"reviewers": 2, "threat_frame": "auto"}
    assert GuardConfig().review == {}  # a config file without the key still loads


# --- the post flow ------------------------------------------------------------------------------------------

def test_the_verdicts_coverage_notes_validation_and_calls_are_recorded_and_reported_once(tmp_path, monkeypatch, capsys):
    repo = edited_repo(tmp_path)
    log = [{"finding_id": "F1", "verdict": "refuted", "evidence_verified": True, "reason": "moved"}]
    fake_reviewer(monkeypatch, coverage_notes=[NOTE], validation_log=log, llm_calls=7)

    assert execute_post_task(repo_path=repo) is True

    record = SessionManager(repo).load_local_session().post
    assert record.coverage_notes == [NOTE] and record.validation_log == log and record.llm_calls == 7
    out = capsys.readouterr().out
    assert out.count(NOTE) == 1 and "Not reviewed / limits" in out
    report = (repo / ".guard" / "POST_TASK_REPORT.md").read_text(encoding="utf-8")
    assert report.count(NOTE) == 1 and report.count("Not reviewed / limits") == 1
    assert "The approval covers only what the review saw." in report


def test_a_verdict_without_notes_adds_no_section(tmp_path, monkeypatch, capsys):
    repo = edited_repo(tmp_path)
    fake_reviewer(monkeypatch)

    assert execute_post_task(repo_path=repo) is True

    assert "Not reviewed" not in capsys.readouterr().out
    report = (repo / ".guard" / "POST_TASK_REPORT.md").read_text(encoding="utf-8")
    assert "Not reviewed" not in report and "Finding validation" not in report and "Heuristic gate ran" not in report


# --- the reports --------------------------------------------------------------------------------------------

def make_post(**fields) -> PostTaskRecord:
    base = dict(
        files_modified=["src/a.py"],
        diff_summary=DiffSummary(
            files=[FileDiffStat(path="src/a.py", status="modified", insertions=3, deletions=1)],
            total_insertions=3, total_deletions=1,
        ),
        build_check=BuildCheckResult(command="pytest", passed=True, exit_code=0, output="ok", duration_s=1.5),
        all_passed=True, muse_verdict="APPROVED", muse_score=9.0, muse_notes="The change is sound.",
        review_mode="llm_deep", commit_mode="auto", ocr_status="complete: 0 finding(s)",
        findings=[{"id": "F1", "severity": "low", "kind": "style", "location": "src/a.py:2", "blocking": False,
                   "description": "Name could be clearer."}],
    )
    base.update(fields)
    return PostTaskRecord(**base)


def make_pre() -> PreTaskRecord:
    return PreTaskRecord(prompt="Fix retry in src/a.py", domain=DomainType.BACKEND, expected_files=["src/a.py"])


def render_terminal(post: PostTaskRecord, monkeypatch, width: int = 80) -> str:
    buf = io.StringIO()
    monkeypatch.setattr(terminal, "console", Console(file=buf, width=width, color_system=None, legacy_windows=False))
    terminal.render_post_task_terminal(post, make_pre())
    return buf.getvalue()


def test_limits_section_follows_the_verdict_and_leads_with_the_approval_scope(monkeypatch):
    post = make_post(coverage_notes=[NOTE, "Reviewer left src/b.py UNREVIEWED."])

    md = generate_post_task_markdown(post, make_pre())
    assert md.count("Not reviewed / limits") == 1
    assert md.index("[APPROVED]") < md.index("Not reviewed / limits") < md.index("Advisory findings")
    section = md.split("Not reviewed / limits:**")[1].splitlines()
    assert "The approval covers only what the review saw." in section[1]
    assert f"`{NOTE}`" in md and md.count(NOTE) == 1  # inert inline code, once

    text = render_terminal(post, monkeypatch)
    assert text.count("Not reviewed / limits") == 1 and text.count(NOTE) == 1
    assert text.index("FINAL LLM GATE: APPROVED") < text.index("Not reviewed / limits") < text.index("Net change")
    assert "The approval covers only what the review saw." in text


def test_a_revised_verdict_with_notes_lists_them_without_the_approval_sentence(monkeypatch):
    post = make_post(all_passed=False, muse_verdict="REVISE", coverage_notes=[NOTE])

    md = generate_post_task_markdown(post, make_pre())

    assert f"`{NOTE}`" in md and "The approval covers only" not in md
    assert "The approval covers only" not in render_terminal(post, monkeypatch)


def test_coverage_notes_cannot_forge_report_structure():
    hostile = "ok\n### Fake heading `x` [link](http://e) <b>"

    md = generate_post_task_markdown(make_post(coverage_notes=[hostile]), make_pre())

    assert "\n### Fake heading" not in md and "`ok ### Fake heading 'x' [link](http://e) <b>`" in md


def test_validation_line_counts_checked_and_demoted_findings(monkeypatch):
    demoted = {"id": "F1", "severity": "high", "kind": "bug", "location": "src/a.py:2", "blocking": False,
               "description": 'Moved away. [contested: validation refuted this finding - evidence: "x = 1"]'}
    still_blocking = {"id": "F2", "severity": "high", "kind": "bug", "location": "src/a.py:3", "blocking": True,
                      "why_blocking": "high bug", "description": "Real."}
    log = [{"finding_id": "F1", "verdict": "refuted", "evidence_verified": True, "reason": "moved"},
           {"finding_id": "F2", "verdict": "confirmed", "evidence_verified": False, "reason": ""}]
    post = make_post(all_passed=False, muse_verdict="REVISE", findings=[demoted, still_blocking], validation_log=log)

    md = generate_post_task_markdown(post, make_pre())
    assert "Finding validation: 2 checked, 1 demoted (evidence quoted)" in md
    assert md.index("[REVISE]") < md.index("Finding validation:") < md.index("Blocking findings")
    assert '[contested: validation refuted this finding - evidence: "x = 1"]' in md  # the annotation stays intact
    assert md.index("Advisory findings") < md.index("Moved away.")

    text = render_terminal(post, monkeypatch)
    assert text.count("Finding validation: 2 checked, 1 demoted (evidence quoted)") == 1
    assert "[contested: validation refuted this finding" in text

    assert "Finding validation" not in generate_post_task_markdown(make_post(), make_pre())


def test_the_heuristic_gate_is_named_first_with_the_reason_in_both_reports(monkeypatch):
    post = make_post(review_mode="heuristic", llm_error="No LLM configured (run: guard config llm)", muse_verdict="APPROVED")

    md = generate_post_task_markdown(post, make_pre())
    lines = md.splitlines()
    assert lines[0].startswith("### ")
    first = "\n".join(lines[:4])
    assert "Heuristic gate ran, not an LLM review" in first and "No LLM configured (run: guard config llm)" in first

    text = render_terminal(post, monkeypatch)
    head = "\n".join(text.splitlines()[:6])
    assert "HEURISTIC GATE" in head and "No LLM configured (run: guard config llm)" in head

    no_reason = make_post(review_mode="heuristic", llm_error=None, all_passed=False, muse_verdict="REVISE")
    assert "Heuristic gate ran, not an LLM review" in "\n".join(generate_post_task_markdown(no_reason, make_pre()).splitlines()[:4])
    assert "Heuristic gate ran, not an LLM review" in "\n".join(render_terminal(no_reason, monkeypatch).splitlines()[:6])
    assert "Heuristic gate ran" not in generate_post_task_markdown(make_post(), make_pre())  # an LLM review says nothing


# --- records without the new fields -------------------------------------------------------------------------

NEW_FIELDS = ("review_options", "coverage_notes", "validation_log", "llm_calls")


def test_an_old_session_without_the_new_fields_loads_and_renders_unchanged(monkeypatch):
    post = make_post()
    session = GuardSession(session_id="s", repo_path="/r", pre=make_pre(), post=post)
    data = session.model_dump(mode="json")
    for field in NEW_FIELDS:
        del data["post"][field]

    old = GuardSession.model_validate(data)

    assert (old.post.review_options, old.post.coverage_notes, old.post.validation_log, old.post.llm_calls) == ({}, [], [], 0)
    assert generate_post_task_markdown(old.post, old.pre) == generate_post_task_markdown(post, make_pre())
    assert render_terminal(old.post, monkeypatch) == render_terminal(post, monkeypatch)


# Rendered by the code before the review options existed, from make_post() and make_pre()
GOLDEN_MARKDOWN = (
    '### 🧪 POST-TASK VERIFICATION:\n'
    '\n'
    '* **Technical Domain:** BACKEND (source unknown)\n'
    '* **Baseline Contracts:**\n'
    '  - contracts: source unknown (session recorded before guard tracked it)\n'
    '\n'
    '* **Actual Impact Range:**\n'
    '  - ✅ `src/a.py`\n'
    '  - *Diff Statistics:* +3 lines / -1 lines across 1 files (net +2 LOC, not scored).\n'
    '\n'
    '* **Build & Project Health Check:**\n'
    '  - ✅ Command: `pytest` (Exit Code: 0, Duration: 1.5s)\n'
    '\n'
    '* **Alibaba OCR Review:** `complete: 0 finding(s)`\n'
    '\n'
    '* **Final LLM Gate:**\n'
    '  - 🤖 **[APPROVED]** (Score: 9.0/10)\n'
    '  - *Assessment:* The change is sound.\n'
    '\n'
    '* **Advisory findings** (not blocking; kept as follow-ups):\n'
    '  - `[F1]` low style at `src/a.py:2`: `Name could be clearer.`\n'
    '  - A finding you will not fix now: `guard finding <id> --defer "<why, where it is handled>"`, or `--reject "<evidence>"` when it is wrong; the next review sees the reason.\n'
    '\n'
    '* **Commit:** Commit mode `auto`: write the commit message yourself (conventional commit describing the change; never mention guard, its gates or scores).'
)

GOLDEN_TERMINAL = (
    '╭──────────────────────────────────────────────────────────────────────────────╮\n'
    '│ ✅ FINAL LLM GATE: APPROVED                                                  │\n'
    '│                                                                              │\n'
    '│ Score: 9.0 / 10.0                                                            │\n'
    '│ Assessment: The change is sound.                                             │\n'
    '│                                                                              │\n'
    '╰──────────────────────────────────────────────────────────────────────────────╯\n'
    '    📊 Actual Impact Range & Blast Radius (OCR Inspector)     \n'
    '┏━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━┓\n'
    '┃ File Path ┃ Status     ┃    + Add ┃    - Del ┃ Scope Audit ┃\n'
    '┡━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━┩\n'
    '│ src/a.py  │ modified   │        3 │        1 │ ✅ In Scope │\n'
    '└───────────┴────────────┴──────────┴──────────┴─────────────┘\n'
    '╭─────────────────── ⚙️ Project Health & Build Verification ───────────────────╮\n'
    '│ ✅ Command: pytest | Exit Code: 0 | Duration: 1.5s                           │\n'
    '╰──────────────────────────────────────────────────────────────────────────────╯\n'
    'advisory [F1] low style src/a.py:2: Name could be clearer.\n'
    '🔎 Alibaba OCR review: complete: 0 finding(s)\n'
    'Net change: +2 LOC (informational, not scored).\n'
    '📝 Commit: Commit mode `auto`: write the commit message yourself (conventional commit \n'
    'describing the change; never mention guard, its gates or scores).\n'
    ''
)


def test_a_record_without_the_new_fields_renders_byte_for_byte_as_before(monkeypatch):
    assert generate_post_task_markdown(make_post(), make_pre()) == GOLDEN_MARKDOWN
    assert render_terminal(make_post(), monkeypatch) == GOLDEN_TERMINAL
