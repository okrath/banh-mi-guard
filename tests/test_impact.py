"""Impact range: pre lists symbols, callers, tests and invariants; post reports changes outside it."""

import subprocess
from pathlib import Path
from unittest.mock import patch

from guard.cli import execute_post_task, execute_pre_task
from guard.core import impact as impact_mod
from guard.core.impact import check_impact, definitions, expected_impact
from guard.core.llm_reviewer import LLMReviewerEngine
from guard.core.ocr_engine import GitDiffInspector
from guard.core.session import SessionManager

INVARIANTS = [{"id": "LIB-01", "checks": [{"files": "src/**/*.py", "require": "def helper"}]},
              {"id": "WEB-01", "checks": [{"files": "web/*.css", "forbid": "!important"}]}]


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(repo), check=True, capture_output=True)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "src" / "lib.py").write_text(
        "def helper(x):\n    return x + 1\n\n\ndef unused():\n    return 0\n", encoding="utf-8")
    (repo / "src" / "app.py").write_text("from src.lib import helper\n\nprint(helper(1))\n", encoding="utf-8")
    (repo / "src" / "report.py").write_text("# the nightly audit job lives here\n", encoding="utf-8")
    (repo / "tests" / "test_lib.py").write_text(
        "from src.lib import helper\n\n\ndef test_helper():\n    assert helper(1) == 2\n", encoding="utf-8")
    _git(repo, "init")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "initial")
    return repo


def _diff(repo: Path) -> str:
    _git(repo, "add", "-A")  # new files show in the diff against HEAD
    return GitDiffInspector(repo).get_diff(base_ref="HEAD") or ""


def test_definitions_cover_python_js_css_and_string_keys():
    assert [(n, k) for _, n, k in definitions("a.py", "class A:\n    def run(self):\n        pass\n    def __init__(self): pass\n")] == [
        ("A", "class"), ("run", "def")]
    js = "export const API = 1;\nfunction draw() {}\nclass Box {}\nswitch (k) { case 'edit': break; }\n"
    assert [(n, k) for _, n, k in definitions("a.ts", js)] == [
        ("API", "export"), ("draw", "function"), ("Box", "class")]
    assert [(n, k) for _, n, k in definitions("a.ts", "  case 'edit':\n")] == [("edit", "string-key")]
    assert [n for _, n, _ in definitions("a.css", ".btn, .card {\n  color: red;\n}\n")] == ["btn", "card"]
    assert definitions("README.md", "def not_code():\n") == []


def test_pre_lists_symbols_callers_tests_and_invariants(tmp_path):
    repo = _repo(tmp_path)
    impact = expected_impact(repo, ["src/lib.py"], INVARIANTS)

    by_name = {s.name: s for s in impact.symbols}
    assert set(by_name) == {"helper", "unused"}
    assert by_name["helper"].references == ["src/app.py", "tests/test_lib.py"]  # never its own file
    assert by_name["helper"].tests == ["tests/test_lib.py"]
    assert by_name["unused"].references == [] and by_name["unused"].tests == []
    assert impact.invariants == {"src/lib.py": ["LIB-01"]}
    assert impact.notes == [] and impact.capped_files == []


def test_post_reports_change_outside_the_range_and_untested_symbols(tmp_path):
    repo = _repo(tmp_path)
    expected = expected_impact(repo, ["src/lib.py"], INVARIANTS)
    # helper's body changes (its callers were expected); a new `audit` is named by a file pre never listed
    (repo / "src" / "lib.py").write_text(
        "def helper(x):\n    return x + 2\n\n\ndef unused():\n    return 0\n\n\ndef audit():\n    return 1\n",
        encoding="utf-8")

    violations, summary = check_impact(repo, _diff(repo), expected, ["src/lib.py"])

    outside = [v for v in violations if v.rule_id == "IMPACT-OUTSIDE"]
    untested = [v for v in violations if v.rule_id == "IMPACT-UNTESTED"]
    assert len(outside) == 1 and "`audit`" in outside[0].message and "src/report.py" in outside[0].message
    assert len(untested) == 1 and "`audit`" in untested[0].message and "helper" not in untested[0].message
    assert all(v.severity == "MEDIUM" for v in violations)  # reported, never blocking
    assert "2 symbol(s) added, changed or removed" in summary and "`audit` (src/report.py)" in summary


def test_removed_symbol_is_checked_for_outside_references_but_not_for_tests(tmp_path):
    repo = _repo(tmp_path)
    (repo / "src" / "report.py").write_text("# unused is mentioned here\n", encoding="utf-8")
    _git(repo, "commit", "-am", "mention")
    expected = expected_impact(repo, ["tests/test_lib.py"], [])  # neither lib.py nor report.py is in the range
    (repo / "src" / "lib.py").write_text("def helper(x):\n    return x + 1\n", encoding="utf-8")

    violations, _ = check_impact(repo, _diff(repo), expected, ["tests/test_lib.py"])

    assert [v.rule_id for v in violations] == ["IMPACT-OUTSIDE"]
    assert "Removed def `unused`" in violations[0].message


def test_caps_are_reported_and_capped_symbols_skip_the_outside_check(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    monkeypatch.setattr(impact_mod, "MAX_SYMBOLS_PER_FILE", 1)
    monkeypatch.setattr(impact_mod, "MAX_REFS_PER_SYMBOL", 1)
    expected = expected_impact(repo, ["src/lib.py"], [])

    assert expected.capped_files == ["src/lib.py"]
    assert [s.name for s in expected.symbols] == ["helper"] and expected.symbols[0].capped
    assert len(expected.notes) == 2

    (repo / "src" / "report.py").write_text("# unused\n", encoding="utf-8")
    _git(repo, "commit", "-am", "mention")
    (repo / "src" / "lib.py").write_text("def helper(x):\n    return x + 3\n\n\ndef unused():\n    return 9\n", encoding="utf-8")
    violations, summary = check_impact(repo, _diff(repo), expected, ["src/lib.py"])

    assert not [v for v in violations if v.rule_id == "IMPACT-OUTSIDE"]  # pre could not list its whole range
    assert "skipped where pre's listing was capped: `helper`" in summary
    assert "`src/lib.py` has 2 changed symbols: the first 1 are checked" in summary  # post is bounded too


def test_untracked_new_test_file_counts_as_a_test_reference(tmp_path):
    repo = _repo(tmp_path)
    expected = expected_impact(repo, ["src/lib.py"], [])
    with open(repo / "src" / "lib.py", "a", encoding="utf-8") as f:
        f.write("\n\ndef audit():\n    return 1\n")
    (repo / "tests" / "test_audit.py").write_text("from src.lib import audit\n", encoding="utf-8")  # not added

    violations, _ = check_impact(repo, GitDiffInspector(repo).get_diff(base_ref="HEAD") or "", expected, ["src/lib.py"])

    assert not [v for v in violations if v.rule_id == "IMPACT-UNTESTED"]


def test_summary_and_findings_stay_bounded_on_a_large_diff(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    monkeypatch.setattr(impact_mod, "MAX_REPORTED", 2)
    expected = expected_impact(repo, ["src/lib.py"], [])
    (repo / "src" / "report.py").write_text("# " + " ".join(f"f{i}" for i in range(6)) + "\n", encoding="utf-8")
    _git(repo, "commit", "-am", "mention")
    with open(repo / "src" / "lib.py", "a", encoding="utf-8") as f:
        f.write("".join(f"\n\ndef f{i}():\n    return {i}\n" for i in range(6)))

    violations, summary = check_impact(repo, _diff(repo), expected, ["src/lib.py"])

    assert len([v for v in violations if v.rule_id == "IMPACT-OUTSIDE"]) == 2
    untested = [v for v in violations if v.rule_id == "IMPACT-UNTESTED"]
    assert len(untested) == 1 and untested[0].message.endswith("… and 4 more.")
    assert "`f2`" not in summary and summary.count("… and 4 more") == 2
    assert "6 symbols are referenced outside the range: the first 2 are reported" in summary


def test_removed_definition_does_not_swallow_the_next_file_or_hunk(tmp_path):
    (tmp_path / "b.py").write_text("def kept():\n    return 1\n", encoding="utf-8")
    (tmp_path / "c.py").write_text("x = 0\n\n\ndef other():\n    return 2\n", encoding="utf-8")
    # Deletion-only hunks without context (-U0): a removed definition in a.py, then removed body
    # lines of existing symbols in b.py and in a later hunk of c.py
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,2 +0,0 @@\n-def gone():\n-    return 0\n"
        "diff --git a/b.py b/b.py\n--- a/b.py\n+++ b/b.py\n@@ -3 +2,0 @@\n-    print('bye')\n"
        "diff --git a/c.py b/c.py\n--- a/c.py\n+++ b/c.py\n@@ -2 +1,0 @@\n-def dropped(): pass\n"
        "@@ -7 +5,0 @@\n-    print('end')\n"
    )
    changed, _ = impact_mod.changed_symbols(tmp_path, diff)

    assert ("b.py", "kept", "def", False) in changed
    assert ("c.py", "other", "def", False) in changed
    assert ("a.py", "gone", "def", True) in changed and ("c.py", "dropped", "def", True) in changed


def test_pre_note_shows_cap_warnings_even_without_listed_symbols():
    from guard.core.impact import ImpactRange
    from guard.core.invariant_eval import DomainType
    from guard.core.session import PreTaskRecord
    from guard.reporters.markdown import generate_pre_task_markdown

    pre = PreTaskRecord(prompt="docs", domain=DomainType.BACKEND, expected_files=["docs"],
                        impact=ImpactRange(notes=["45 scoped files: symbols listed for the first 40 only"]))

    assert "⚠️ capped: `45 scoped files" in generate_pre_task_markdown(pre)


def test_repository_names_cannot_break_out_of_the_report_markup():
    from guard.core.impact import ImpactRange, ImpactSymbol
    from guard.reporters.markdown import impact_lines

    impact = ImpactRange(symbols=[ImpactSymbol(file="a`](http://x)`.py", name="f", kind="def", line=1,
                                               references=["b`<img>.py"])])

    text = "\n".join(impact_lines(impact))
    assert "`a'](http://x)'.py`" in text and "`b'<img>.py`" in text  # one inert code span each


def test_js_functions_bound_to_names_are_definitions():
    js = "const draw = () => 1;\nlet load = async (a: T): Promise<R> => a;\nvar old = function () {};\nconst n = 5;\n"
    assert [(n, k) for _, n, k in definitions("a.ts", js)] == [("draw", "function"), ("load", "function"), ("old", "function")]


def test_decorator_change_belongs_to_the_definition_below(tmp_path):
    repo = _repo(tmp_path)
    (repo / "src" / "lib.py").write_text(
        "import functools\n\n\n@functools.cache\ndef helper(x):\n    return x + 1\n\n\ndef unused():\n    return 0\n",
        encoding="utf-8")
    added, _ = impact_mod.changed_symbols(repo, _diff(repo))
    assert [n for _, n, _, _ in added] == ["helper"]

    _git(repo, "commit", "-qm", "cache")
    (repo / "src" / "lib.py").write_text(
        "import functools\n\n\ndef helper(x):\n    return x + 1\n\n\ndef unused():\n    return 0\n", encoding="utf-8")
    removed, _ = impact_mod.changed_symbols(repo, _diff(repo))
    assert [n for _, n, _, _ in removed] == ["helper"]


def test_cap_note_survives_when_no_symbol_changed(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    monkeypatch.setattr(impact_mod, "MAX_FILES", 1)
    (repo / "README.md").write_text("docs\n", encoding="utf-8")
    (repo / "notes.md").write_text("more\n", encoding="utf-8")

    violations, summary = check_impact(repo, _diff(repo), None, [])

    assert violations == [] and "2 changed files: symbols checked in the first 1 only" in summary


def test_session_without_expected_range_skips_only_the_outside_check(tmp_path):
    repo = _repo(tmp_path)
    (repo / "src" / "lib.py").write_text("def helper(x):\n    return x\n\n\ndef audit():\n    return 1\n", encoding="utf-8")

    violations, summary = check_impact(repo, _diff(repo), None, ["src/lib.py"])

    assert {v.rule_id for v in violations} == {"IMPACT-UNTESTED"}
    assert "no expected impact range" in summary


def test_pre_and_post_record_the_range_report_it_and_pass_it_to_the_gate(tmp_path):
    repo = _repo(tmp_path)
    assert execute_pre_task("Add an audit helper to src/lib.py", repo_path=repo) is True

    pre = SessionManager(repo).load_session().pre
    assert {s.name for s in pre.impact.symbols} == {"helper", "unused"}
    note = (repo / ".guard" / "PRE_TASK_NOTE.md").read_text(encoding="utf-8")
    assert "Expected Impact Range (symbols, their callers, covering tests, invariants)" in note
    assert "`helper` (def): `src/app.py`; tests: `tests/test_lib.py`" in note
    assert "not referenced from other files: `unused`" in note

    with open(repo / "src" / "lib.py", "a", encoding="utf-8") as f:
        f.write("\n\ndef audit():\n    return helper(0)\n")
    review = LLMReviewerEngine.review
    with patch.object(LLMReviewerEngine, "review", autospec=True, side_effect=review) as spy:
        execute_post_task(repo_path=repo)

    post = SessionManager(repo).load_session().post
    impact_findings = [v for v in post.rule_violations if v.rule_id.startswith("IMPACT-")]
    assert {v.rule_id for v in impact_findings} == {"IMPACT-OUTSIDE", "IMPACT-UNTESTED"}
    assert all(v.severity == "MEDIUM" for v in impact_findings)
    assert post.impact_summary.startswith("Impact range check")
    assert any(e == post.impact_summary for e in spy.call_args.kwargs["evidence"])
    assert "**Impact Range:**" in (repo / ".guard" / "POST_TASK_REPORT.md").read_text(encoding="utf-8")


def test_restart_keeps_the_first_expected_range(tmp_path):
    repo = _repo(tmp_path)
    assert execute_pre_task("Edit src/lib.py", repo_path=repo) is True
    (repo / "src" / "lib.py").write_text("def helper(x):\n    return x\n\n\ndef later():\n    return 1\n", encoding="utf-8")
    assert execute_pre_task("Edit src/lib.py", repo_path=repo, force=True) is True

    pre = SessionManager(repo).load_session().pre
    assert {s.name for s in pre.impact.symbols} == {"helper", "unused"}  # not re-read from the edited file
