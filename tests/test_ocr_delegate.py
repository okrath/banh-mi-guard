"""OCR's delegation mode answered by the agent CLI: the fallback when OCR through the agent bridge does not run."""

import subprocess
from types import SimpleNamespace

import pytest

from guard.core import ocr_delegate
from guard.core.cli_llm import CLILLMError
from guard.core.ocr_delegate import run_delegate_review


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A base commit, then a.js changed and b.py and notes.txt added; OCR lists the three and groups two."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.name", "t")
    _git(repo, "config", "user.email", "t@t")
    (repo / "a.js").write_text("const a = 1;\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "a.js").write_text("const a = user.name;\n", encoding="utf-8")
    (repo / "b.py").write_text("b = None.x\n", encoding="utf-8")
    (repo / "notes.txt").write_text("todo\n", encoding="utf-8")
    calls = []

    def fake_ocr(cmd, repo_path):
        calls.append(cmd)
        if cmd[2] == "preview":
            return {"reviewable_files": [{"path": "a.js"}, {"path": "b.py"}, {"path": "notes.txt"}]}
        return {"groups": [{"rule": "JS rules", "files": ["a.js"]}, {"rule": "Python rules", "files": ["b.py"]}]}

    monkeypatch.setattr(ocr_delegate.shutil, "which", lambda b: f"/bin/{b}")
    monkeypatch.setattr(ocr_delegate, "_ocr_json", fake_ocr)
    return SimpleNamespace(path=repo, base=base, ocr=calls)


def test_each_rule_group_is_one_prompt_and_its_findings_come_back(repo):
    prompts = []

    def ask(system, conversation):
        prompts.append((system, conversation))
        if "a.js" in conversation:
            return 'Sure: {"comments": [{"path": "a.js", "start_line": 1, "severity": "high", "category": "bug", "content": "user may be undefined"}]} done'
        return '{"comments": []}'

    status, found = run_delegate_review(repo.path, repo.base, "Read the user name", None, "ocr", ask)
    assert status == "complete: 1 finding(s); OCR's delegation mode, 3 of 3 file(s) in 3 prompt(s)"
    assert [(v.rule_id, v.severity, v.file_path, v.line_number) for v in found] == [("OCR-BUG", "HIGH", "a.js", 1)]
    systems = [s for s, _ in prompts]
    assert "JS rules" in systems[0] and "Python rules" in systems[1] and "(none for these files" in systems[2]
    assert all("Read the user name" in s for s in systems)
    assert "+const a = user.name;" in prompts[0][1] and "JS rules" not in prompts[0][1]  # the diff is the data
    assert "notes.txt" in prompts[2][1]  # a file without a rule group is still reviewed
    rule_cmd = repo.ocr[1]
    assert rule_cmd[1:3] == ["delegate", "rule"] and rule_cmd[-3:] == ["a.js", "b.py", "notes.txt"]
    assert rule_cmd[rule_cmd.index("--from") + 1] == repo.base


def test_files_dirty_before_pre_are_left_out(repo):
    seen = []
    status, _ = run_delegate_review(repo.path, repo.base, "", ["b.py"], "ocr",
                                    lambda s, c: seen.append(c) or '{"comments": [{"path": "b.py", "severity": "low"}]}')
    assert status.startswith("complete: 0 finding(s)") and "2 of 2 file(s)" in status
    assert not any("b = None.x" in c for c in seen)


def test_a_failed_or_unreadable_answer_is_never_a_full_review(repo):
    def ask(system, conversation):
        if "b.py" in conversation:
            raise CLILLMError("codex exited with 1: rate limited")
        if "a.js" in conversation:
            return "I think it looks fine."
        return '{"comments": [{"path": "notes.txt", "start_line": "one", "severity": "low", "category": "style", "content": "x"}]}'

    status, found = run_delegate_review(repo.path, repo.base, "", None, "ocr", ask)
    assert status.startswith("did not run: OCR's delegation mode reviewed 1 of 3 file(s) in 3 prompt(s); not reviewed: a.js, b.py")
    assert "codex exited with 1: rate limited" in status
    assert [(v.rule_id, v.line_number) for v in found] == [("OCR-RUN", None), ("OCR-STYLE", None)]


def test_a_diff_too_large_for_a_prompt_is_not_reviewed_and_files_are_packed(repo, monkeypatch):
    monkeypatch.setattr(ocr_delegate, "_ocr_json", lambda cmd, p: (
        {"reviewable_files": [{"path": "a.js"}, {"path": "b.py"}, {"path": "notes.txt"}]} if cmd[2] == "preview"
        else {"groups": [{"rule": "all", "files": ["a.js", "b.py", "notes.txt"]}]}))
    from guard.core.diff_inspector import GitDiffInspector
    (repo.path / "notes.txt").write_text("x" * 2000 + "\n", encoding="utf-8")
    snap = GitDiffInspector(repo.path).snapshot_worktree()
    sizes = [len(_git(repo.path, "diff", "-U20", repo.base, snap, "--", p)) for p in ("a.js", "b.py")]
    monkeypatch.setattr(ocr_delegate, "MAX_PROMPT_CHARS", max(sizes) + 10)
    assert sum(sizes) > max(sizes) + 10
    prompts = []
    status, found = run_delegate_review(repo.path, repo.base, "", None, "ocr",
                                        lambda s, c: prompts.append(c) or '{"comments": []}')
    assert len(prompts) == 2  # a.js and b.py do not fit in one prompt together
    assert status.startswith("did not run") and "not reviewed: notes.txt" in status and "characters" in status
    assert [v.rule_id for v in found] == ["OCR-RUN"]


def test_ocr_failing_is_an_ocr_failure(repo, monkeypatch):
    def broken(cmd, p):
        raise ValueError("delegate preview exited with 1: not a git repository")

    monkeypatch.setattr(ocr_delegate, "_ocr_json", broken)
    status, found = run_delegate_review(repo.path, repo.base, "", None, "ocr", lambda s, c: pytest.fail("no prompt"))
    assert status == "did not run: OCR's delegation mode did not run: delegate preview exited with 1: not a git repository"
    assert [v.rule_id for v in found] == ["OCR-RUN"]


@pytest.mark.parametrize("preview, rules", [
    ({}, None),  # no file list is not an empty one
    ({"reviewable_files": [{"name": "a.js"}]}, None),
    ({"reviewable_files": [{"path": "a.js"}]}, {}),  # no rule groups: OCR's rules would not be applied
    ({"reviewable_files": [{"path": "a.js"}]}, {"groups": [{"files": ["a.js"]}]}),
])
def test_unreadable_delegation_output_is_a_failure_not_an_empty_review(repo, monkeypatch, preview, rules):
    monkeypatch.setattr(ocr_delegate, "_ocr_json", lambda cmd, p: preview if cmd[2] == "preview" else rules)
    status, found = run_delegate_review(repo.path, repo.base, "", None, "ocr", lambda s, c: pytest.fail("no prompt"))
    assert status.startswith("did not run: OCR's delegation mode did not run: delegate")
    assert [v.rule_id for v in found] == ["OCR-RUN"]


def test_a_listed_file_without_a_diff_is_not_reviewed(repo, monkeypatch):
    monkeypatch.setattr(ocr_delegate, "_ocr_json", lambda cmd, p: (
        {"reviewable_files": [{"path": "a.js"}, {"path": "unchanged.js"}]} if cmd[2] == "preview"
        else {"groups": [{"rule": "JS", "files": ["a.js", "unchanged.js"]}]}))
    status, found = run_delegate_review(repo.path, repo.base, "", None, "ocr", lambda s, c: '{"comments": []}')
    assert status.startswith("did not run") and "not reviewed: unchanged.js (no diff" in status
    assert [v.rule_id for v in found] == ["OCR-RUN"]


def test_a_finding_on_a_file_the_prompt_did_not_carry_is_dropped(repo):
    answer = '{"comments": [{"path": "elsewhere.py", "severity": "high", "category": "bug", "content": "x"}]}'
    status, found = run_delegate_review(repo.path, repo.base, "", None, "ocr", lambda s, c: answer)
    assert status.startswith("complete: 0 finding(s)") and found == []


def test_the_diff_names_files_as_ocr_does_and_a_git_prefix_is_read_too(repo):
    def ask(system, conversation):
        assert "+++ a.js" in conversation or "a.js" not in conversation  # no b/ prefix in what the agent sees
        return '{"comments": [{"path": "b/a.js", "start_line": 1, "severity": "low", "category": "bug", "content": "x"}]}'

    status, found = run_delegate_review(repo.path, repo.base, "", None, "ocr", ask)
    assert [v.file_path for v in found] == ["a.js"]


def test_bridge_failure_falls_back_to_the_delegation_mode(tmp_path, monkeypatch, capsys):
    from guard import task_flow

    seen = {}

    def delegate(repo, base_ref, background, skip_files, binary, ask):
        seen.update(base_ref=base_ref, background=background, skip=skip_files, ask=ask)
        return "complete: 1 finding(s); OCR's delegation mode, 1 of 1 file(s) in 1 prompt(s)", ["finding"]

    monkeypatch.setattr(task_flow, "run_ocr_review", lambda repo, env_for=None, **kw: (
        "did not run: Review failed: 0 finding(s)", ["bridge OCR-RUN"]))
    monkeypatch.setattr(ocr_delegate, "run_delegate_review", delegate)
    config = SimpleNamespace(llm=SimpleNamespace(cli_agent="omp", model="", timeout=60.0))
    review = {"base_ref": "abc", "background": "task", "skip_files": ["x"], "binary": "ocr", "concurrency": 0}
    status, found = task_flow._ocr_through_agent(tmp_path, config, review)
    assert status == ("complete: 1 finding(s); OCR's delegation mode, 1 of 1 file(s) in 1 prompt(s); answered by the omp "
                      "CLI as the fallback after OCR answered by the omp CLI (tool calls written as text) did not run: "
                      "Review failed: 0 finding(s)")
    assert found == ["finding"] and seen["base_ref"] == "abc" and seen["skip"] == ["x"] and callable(seen["ask"])
    assert "Falling back to OCR's delegation mode" in capsys.readouterr().out


def test_both_paths_failing_keep_the_first_failure(tmp_path, monkeypatch):
    from guard import task_flow
    from guard.core.rulebook import RuleViolation

    run = RuleViolation(rule_id="OCR-RUN", severity="HIGH", file_path="(ocr)", message="bridge failed")
    partial = RuleViolation(rule_id="OCR-BUG", severity="HIGH", file_path="a.js", message="late")
    monkeypatch.setattr(task_flow, "run_ocr_review", lambda repo, env_for=None, **kw: ("did not run: bridge", [run]))
    monkeypatch.setattr(ocr_delegate, "run_delegate_review", lambda *a: (
        "did not run: delegation", [RuleViolation(rule_id="OCR-RUN", severity="HIGH", file_path="(ocr)", message="d"), partial]))
    config = SimpleNamespace(llm=SimpleNamespace(cli_agent="codex", model="", timeout=60.0))
    status, found = task_flow._ocr_through_agent(tmp_path, config, {"concurrency": 0})
    assert status.startswith("did not run: delegation; answered by the codex CLI as the fallback after OCR")
    assert found == [run, partial]  # one blocking OCR-RUN, the findings the fallback still made
