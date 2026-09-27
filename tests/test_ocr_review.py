"""
Alibaba OCR review run by `guard post --full`: the reviewed range, the result contract (status,
coverage, findings) and how a review that did not complete blocks.
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from guard.core.ocr_engine import GitDiffInspector, run_ocr_review


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def _task_repo(tmp_path):
    """Base commit, a mid-task commit, an unstaged edit, an untracked file and guard's own folder."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.name", "t")  # commits never depend on the machine's Git identity
    _git(repo, "config", "user.email", "t@t")
    (repo / ".gitignore").write_text(".guard/\n", encoding="utf-8")
    (repo / "a.py").write_text("a = 1\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "b.py").write_text("b = 1\n", encoding="utf-8")
    _git(repo, "add", "b.py")
    _git(repo, "commit", "-m", "mid-task")
    (repo / "a.py").write_text("a = 2\n", encoding="utf-8")
    (repo / "c.py").write_text("c = 1\n", encoding="utf-8")
    (repo / ".guard").mkdir()
    (repo / ".guard" / "session.json").write_text("{}", encoding="utf-8")
    return repo, base


def test_worktree_snapshot_covers_the_whole_task_and_touches_nothing(tmp_path):
    repo, base = _task_repo(tmp_path)
    status_before = _git(repo, "status", "--porcelain")
    snap = GitDiffInspector(repo).snapshot_worktree()
    changed = set(_git(repo, "diff", "--name-only", base, snap).splitlines())
    assert changed == {"a.py", "b.py", "c.py"}  # mid-task commit, unstaged and untracked; never .guard/
    assert _git(repo, "status", "--porcelain") == status_before  # index and working tree untouched
    assert _git(repo, "show", f"{snap}:a.py") == "a = 2"


real_run = subprocess.run


def _fake_ocr(result, calls):
    def run(cmd, **kwargs):
        if cmd[0] == "git":  # the working-tree snapshot is real
            return real_run(cmd, **kwargs)
        calls.append(cmd)
        out = Path(cmd[cmd.index("-o") + 1])
        answer = result.pop(0) if isinstance(result, list) else result  # a list: one answer per run
        if answer is not None and "manifest" not in answer and not answer.pop("_no_manifest", False):
            task_files = [{"item_id": p, "path": p} for p in ("a.py", "b.py", "c.py")]  # the task's changed files
            answer = {**answer, "manifest": {"coverage": {"selected": task_files, "completed": task_files}}}
        if answer is not None:
            out.write_text(json.dumps(answer), encoding="utf-8")
        ok = answer and answer.get("status") in ("success", "complete", "completed_with_warnings", "skipped")
        return subprocess.CompletedProcess(cmd, 0 if ok else 1, "", "boom")
    return run


def test_ocr_review_maps_findings_and_reviews_base_to_snapshot(tmp_path):
    repo, base = _task_repo(tmp_path)
    result = {"status": "complete", "llm": {"model": "muse"}, "comments": [
        {"path": "a.py", "content": "wrong value", "start_line": 1, "category": "bug", "severity": "high"},
        {"path": "c.py", "content": "naming", "start_line": 1, "category": "style", "severity": "low"},
        {"path": "old.py", "content": "not this task", "severity": "critical"},
    ]}
    calls = []
    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
         patch("guard.core.ocr_engine.subprocess.run", side_effect=_fake_ocr(result, calls)):
        status, violations = run_ocr_review(repo, base, "Fix a.py", skip_files=["old.py"])
    cmd = calls[0]
    assert cmd[cmd.index("--from") + 1] == base and "--to" in cmd and "Fix a.py" in cmd
    assert cmd[cmd.index("--timeout") + 1] == "0"  # AI review has no time limit
    snapshot = cmd[cmd.index("--to") + 1]  # a commit of the working tree on top of HEAD: the whole task range
    assert _git(repo, "show", f"{snapshot}:a.py") == "a = 2" and _git(repo, "show", f"{snapshot}:c.py") == "c = 1"
    assert _git(repo, "rev-parse", f"{snapshot}^") == _git(repo, "rev-parse", "HEAD")
    assert status.startswith("complete: 2 finding(s)")
    assert "1 finding(s) dropped: on files dirty before pre and unchanged by this task" in status  # never silent
    assert [(v.rule_id, v.severity, v.file_path) for v in violations] == [("OCR-BUG", "HIGH", "a.py"), ("OCR-STYLE", "LOW", "c.py")]


def test_failed_tool_calls_are_shown_but_do_not_fail_a_covered_review(tmp_path):
    repo, base = _task_repo(tmp_path)
    answer = {"status": "complete", "comments": [], "tool_calls": {"total": 12, "failure": 2}}
    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
         patch("guard.core.ocr_engine.subprocess.run", side_effect=_fake_ocr(answer, [])):
        line, violations = run_ocr_review(repo, base, "task")
    assert line.startswith("complete") and violations == []
    assert "2 of 12 OCR tool call(s) failed while exploring" in line


def test_ocr_that_does_not_run_is_a_high_violation(tmp_path):
    repo, base = _task_repo(tmp_path)
    with patch("guard.core.ocr_engine.shutil.which", return_value=None):
        status, violations = run_ocr_review(repo, base, "task")
    assert status.startswith("did not run") and [(v.rule_id, v.severity) for v in violations] == [("OCR-RUN", "HIGH")]

    failed = {"status": "failed", "message": "Review failed: 2 of 2 selected item(s) failed."}
    for result in (failed, None):  # a failed review, and no JSON result at all
        with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
             patch("guard.core.ocr_engine.subprocess.run", side_effect=_fake_ocr(result, [])):
            status, violations = run_ocr_review(repo, base, "task")
        assert status.startswith("did not run") and violations[0].rule_id == "OCR-RUN"


def test_partial_ocr_review_is_resumed_once(tmp_path):
    repo, base = _task_repo(tmp_path)
    partial = {"status": "partial", "comments": [], "session_id": "s-1", "message": "8 of 11 selected item(s) failed."}
    done = {"status": "complete", "comments": []}
    calls = []
    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
         patch("guard.core.ocr_engine.subprocess.run", side_effect=_fake_ocr([partial, done], calls)):
        status, violations = run_ocr_review(repo, base, "task", concurrency=2)
    assert status.startswith("complete") and violations == []
    assert "--resume" not in calls[0] and calls[1][calls[1].index("--resume") + 1] == "s-1"
    assert calls[0][calls[0].index("--concurrency") + 1] == "2"

    calls = []
    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
         patch("guard.core.ocr_engine.subprocess.run", side_effect=_fake_ocr([dict(partial), dict(partial)], calls)):
        status, violations = run_ocr_review(repo, base, "task")
    assert len(calls) == 2 and status == "did not run: 8 of 11 selected item(s) failed"


def test_ocr_never_reviews_without_the_task_range(tmp_path):
    repo, base = _task_repo(tmp_path)
    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
         patch("guard.core.ocr_engine.subprocess.run", side_effect=AssertionError("OCR must not start")), \
         patch.object(GitDiffInspector, "snapshot_worktree", return_value=None):
        status, violations = run_ocr_review(repo, base, "task")
    assert status.startswith("did not run: the working tree could not be snapshotted") and violations[0].rule_id == "OCR-RUN"

    def git_only(cmd, **kwargs):  # the snapshot may run git; OCR itself must never start
        assert cmd[0] == "git", "OCR must not start"
        return real_run(cmd, **kwargs)

    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
         patch("guard.core.ocr_engine.subprocess.run", side_effect=git_only):
        status, violations = run_ocr_review(repo, None, "task")  # commits exist, but no base was recorded
    assert status.startswith("did not run: no base commit") and violations[0].severity == "HIGH"


def test_partial_review_blocks_but_still_reports_its_findings(tmp_path):
    repo, base = _task_repo(tmp_path)
    partial = {"status": "partial", "message": "2 of 11 selected item(s) failed.",
               "comments": [{"path": "a.py", "content": "off by one", "category": "bug", "severity": "medium"}]}
    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
         patch("guard.core.ocr_engine.subprocess.run", side_effect=_fake_ocr([partial, dict(partial)], [])):
        status, violations = run_ocr_review(repo, base, "task")
    assert status.startswith("did not run") and [v.rule_id for v in violations] == ["OCR-RUN", "OCR-BUG"]


def test_finding_without_known_severity_blocks_and_result_is_kept(tmp_path):
    repo, base = _task_repo(tmp_path)
    result = {"status": "complete", "comments": [{"path": "a.py", "content": "suspicious", "category": "bug"}]}
    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
         patch("guard.core.ocr_engine.subprocess.run", side_effect=_fake_ocr(result, [])):
        _, violations = run_ocr_review(repo, base, "task")
    assert violations[0].severity == "HIGH" and "no known severity" in violations[0].message
    kept = json.loads((repo / ".guard" / "ocr-review.json").read_text(encoding="utf-8"))
    assert kept["comments"] == result["comments"]
    assert not list((repo / ".guard").glob("ocr-review-*.json"))  # the per-run file was moved, not left behind


@pytest.mark.parametrize("status, ok", [
    ("success", True), ("complete", True), ("completed_with_warnings", True), ("skipped", True),
    ("completed_with_errors", False), ("failed", False), ("something-new", False),
])
def test_ocr_status_contract(tmp_path, status, ok):
    repo, base = _task_repo(tmp_path)
    answer = {"status": status, "comments": []}
    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
         patch("guard.core.ocr_engine.subprocess.run", side_effect=_fake_ocr([dict(answer), dict(answer)], [])):
        line, violations = run_ocr_review(repo, base, "task")
    assert line.startswith("complete") is ok
    if status == "skipped":
        assert "status skipped" in line  # the report names OCR's own status, not a guessed reason
    assert (violations == []) is ok


def test_unreadable_ocr_result_is_a_failure(tmp_path):
    repo, base = _task_repo(tmp_path)
    for answer in ({"status": "complete", "comments": "oops"}, {"status": "complete", "comments": ["oops"]}):
        with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
             patch("guard.core.ocr_engine.subprocess.run", side_effect=_fake_ocr(answer, [])):
            line, violations = run_ocr_review(repo, base, "task")
        assert line.startswith("did not run: OCR returned") and violations[0].rule_id == "OCR-RUN"


def test_warning_status_with_unreviewed_files_is_incomplete_and_timeout_is_forced(tmp_path, monkeypatch):
    repo, base = _task_repo(tmp_path)
    monkeypatch.setenv("OCR_LLM_TIMEOUT", "300")  # a short limit from the environment is not kept
    answer = {"status": "completed_with_warnings", "comments": [],
              "manifest": {"coverage": {"failed": [{"path": "a.py", "reason": "provider"}]}}}
    envs = []

    def run(cmd, **kwargs):
        if cmd[0] == "git":
            return real_run(cmd, **kwargs)
        envs.append(kwargs["env"]["OCR_LLM_TIMEOUT"])
        Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps(answer), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
         patch("guard.core.ocr_engine.subprocess.run", side_effect=run):
        line, violations = run_ocr_review(repo, base, "task")
    assert line.startswith("did not run") and violations[0].rule_id == "OCR-RUN"
    assert envs and all(v == str(10 * 365 * 24 * 3600) for v in envs)  # exactly ten years, the environment's 300 ignored


def test_complete_status_with_failing_exit_code_is_a_failure(tmp_path):
    repo, base = _task_repo(tmp_path)

    def run(cmd, **kwargs):
        if cmd[0] == "git":
            return real_run(cmd, **kwargs)
        Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps({"status": "complete", "comments": []}), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 2, "", "")

    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
         patch("guard.core.ocr_engine.subprocess.run", side_effect=run):
        line, violations = run_ocr_review(repo, base, "task")
    assert line.startswith("did not run") and violations[0].rule_id == "OCR-RUN"


def test_odd_ocr_json_never_crashes_the_post(tmp_path):
    repo, base = _task_repo(tmp_path)
    blocked = [
        {"status": ["complete"], "comments": []},  # status of the wrong type
        {"status": "complete", "comments": [], "manifest": {"coverage": {"failed": "x"}}},  # unreadable coverage
        {"status": "complete", "comments": [{"path": ["a.py"], "content": "x", "severity": "low"}]},  # path type
        {"status": "complete", "comments": [{"path": "a.py", "start_line": "3", "severity": "low"}]},  # line type
    ]
    for answer in blocked:
        with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
             patch("guard.core.ocr_engine.subprocess.run", side_effect=_fake_ocr([dict(answer), dict(answer)], [])):
            line, violations = run_ocr_review(repo, base, "task")
        assert line.startswith("did not run") and violations[0].rule_id == "OCR-RUN", answer

    tolerated = {"status": "complete", "comments": [], "llm": "m"}  # only the model name is unreadable
    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
         patch("guard.core.ocr_engine.subprocess.run", side_effect=_fake_ocr(tolerated, [])):
        line, violations = run_ocr_review(repo, base, "task")
    assert line.startswith("complete: 0 finding(s) (model ?") and violations == []


def test_success_without_coverage_evidence_is_not_a_review(tmp_path):
    repo, base = _task_repo(tmp_path)
    unproven = [
        {"status": "complete", "comments": [], "_no_manifest": True},
        {"status": "complete", "comments": [],
         "manifest": {"coverage": {"selected": [{"item_id": "a"}, {"item_id": "b"}], "completed": [{"item_id": "a"}]}}},
        {"status": "complete", "comments": [], "manifest": {"coverage": {}}},  # no evidence at all
        {"status": "complete", "comments": [], "manifest": {"coverage": {"completed": []}}},  # nothing selected
        {"status": "complete", "comments": [], "manifest": {"coverage": {"selected": [], "completed": []}}},
    ]
    for answer in unproven:
        with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
             patch("guard.core.ocr_engine.subprocess.run", side_effect=_fake_ocr([dict(answer), dict(answer)], [])):
            line, violations = run_ocr_review(repo, base, "task")
        assert line.startswith("did not run") and violations[0].rule_id == "OCR-RUN"


def test_coverage_entries_without_an_identity_are_not_a_review(tmp_path):
    repo, base = _task_repo(tmp_path)
    answer = {"status": "complete", "comments": [],
              "manifest": {"coverage": {"selected": [{}], "completed": [{}]}}}  # both "match" only as None
    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
         patch("guard.core.ocr_engine.subprocess.run", side_effect=_fake_ocr([dict(answer), dict(answer)], [])):
        line, violations = run_ocr_review(repo, base, "task")
    assert line.startswith("did not run") and violations[0].rule_id == "OCR-RUN"


def test_skipped_needs_no_coverage_and_output_is_not_buffered(tmp_path):
    repo, base = _task_repo(tmp_path)
    seen = []

    def run(cmd, **kwargs):
        if cmd[0] == "git":
            return real_run(cmd, **kwargs)
        seen.append(kwargs)
        Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps({"status": "skipped", "comments": []}), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, None, "")

    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
         patch("guard.core.ocr_engine.subprocess.run", side_effect=run):
        line, violations = run_ocr_review(repo, base, "task")
    assert line == "complete: OCR reported status skipped (it reviewed no file)" and violations == []
    assert seen[0]["stdout"] is subprocess.DEVNULL and "capture_output" not in seen[0]


def test_rewritten_history_is_not_reviewed_as_the_task(tmp_path):
    repo, base = _task_repo(tmp_path)
    _git(repo, "checkout", "-q", "--orphan", "rewritten")  # the recorded base is no longer an ancestor
    _git(repo, "commit", "-qm", "rewritten history")
    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"):
        line, violations = run_ocr_review(repo, base, "task")
    assert line.startswith("did not run: the base commit recorded at pre is no longer an ancestor")
    assert violations[0].rule_id == "OCR-RUN"


def test_unusable_resume_id_is_not_passed_to_ocr(tmp_path):
    repo, base = _task_repo(tmp_path)
    partial = {"status": "partial", "comments": [], "session_id": ["not", "an", "id"], "message": "1 of 2 failed."}
    calls = []
    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
         patch("guard.core.ocr_engine.subprocess.run", side_effect=_fake_ocr([dict(partial), dict(partial)], calls)):
        line, violations = run_ocr_review(repo, base, "task")
    assert len(calls) == 1 and line.startswith("did not run") and violations[0].rule_id == "OCR-RUN"


def test_result_without_a_comments_field_is_not_accepted(tmp_path):
    repo, base = _task_repo(tmp_path)
    for answer in ({"status": "complete"}, {"status": "complete", "comments": {"a": 1}}):
        with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
             patch("guard.core.ocr_engine.subprocess.run", side_effect=_fake_ocr(answer, [])):
            line, violations = run_ocr_review(repo, base, "task")
        assert line.startswith("did not run: OCR returned") and violations[0].rule_id == "OCR-RUN"
    with patch("guard.core.ocr_engine.shutil.which", return_value="ocr"), \
         patch("guard.core.ocr_engine.subprocess.run", side_effect=_fake_ocr({"status": "complete", "comments": None}, [])):
        line, violations = run_ocr_review(repo, base, "task")  # null: OCR's way of saying no findings
    assert line.startswith("complete: 0 finding(s)") and violations == []
