"""
`guard config tests related`: a pytest build runs only the tests of the changed Python files while the gate
would not approve, and the full suite always runs before an approval.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from typer.testing import CliRunner

from guard.cli import app
from guard.core import llm_reviewer
from guard.core.config import load_global_config, save_config
from guard.core.llm_reviewer import LLMReviewVerdict, ReviewVerdict
from guard.core.related_tests import related_tests
from guard.core.session import SessionManager
from guard.task_flow import execute_post_task, execute_pre_task

PASS = "def test_ok():\n    assert True\n"
FAIL = "def test_broken():\n    assert False\n"


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def python_repo(tmp_path: Path, other_test: str = PASS) -> Path:
    """pkg/a.py and pkg/b.py, tests/test_a.py (imports pkg.a) and tests/test_b.py (imports pkg.b)."""
    repo = tmp_path / "py"
    (repo / "pkg").mkdir(parents=True)
    (repo / "tests").mkdir()
    for cmd in (["init"], ["config", "user.email", "t@t"], ["config", "user.name", "t"],
                ["config", "core.hooksPath", ".git/hooks"]):
        git(repo, *cmd)
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "py"\nversion = "0"\n\n[tool.pytest.ini_options]\npythonpath = ["."]\n', encoding="utf-8")
    (repo / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "pkg" / "a.py").write_text("A = 1\n", encoding="utf-8")
    (repo / "pkg" / "b.py").write_text("B = 1\n", encoding="utf-8")
    (repo / "tests" / "test_a.py").write_text("import pkg.a\n\n" + PASS, encoding="utf-8")
    (repo / "tests" / "test_b.py").write_text("from pkg import b\n\n" + other_test, encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "init")
    return repo


def use_related_tests() -> None:
    cfg = load_global_config()
    cfg.tests_scope = "related"
    save_config(cfg)


def llm_approves(monkeypatch) -> None:
    """The LLM approves; a review without the LLM (a failing build decides) runs guard's own heuristics."""
    real = llm_reviewer.LLMReviewerEngine.review

    def review(self, **kwargs):
        if not kwargs.get("use_llm", True):
            return real(self, **kwargs)
        return LLMReviewVerdict(verdict=ReviewVerdict.APPROVED, score=9.0, summary="Fine.", review_mode="llm_deep")
    monkeypatch.setattr(llm_reviewer.LLMReviewerEngine, "review", review)


def change_a(repo: Path) -> None:
    assert execute_pre_task("Change pkg/a.py", repo_path=repo, scope=["pkg/a.py"]) is True
    (repo / "pkg" / "a.py").write_text("A = 2\n", encoding="utf-8")


# --- selection ------------------------------------------------------------------------------------------------

def test_the_tests_that_import_or_are_named_after_a_changed_module_are_selected(tmp_path):
    repo = python_repo(tmp_path)
    (repo / "tests" / "test_from_parent.py").write_text("from pkg import a, b\n\n" + PASS, encoding="utf-8")
    git(repo, "add", ".")
    assert related_tests(repo, ["pkg/a.py"]) == ["tests/test_a.py", "tests/test_from_parent.py"]
    assert related_tests(repo, ["pkg/b.py"]) == ["tests/test_b.py", "tests/test_from_parent.py"]
    assert related_tests(repo, ["tests/test_b.py"]) == ["tests/test_b.py"]  # a changed test runs itself


def test_anything_guard_cannot_map_to_tests_means_the_full_suite(tmp_path):
    repo = python_repo(tmp_path)
    for changed in (["pkg/a.py", "README.md"], ["tests/conftest.py"], ["pyproject.toml"], ["pkg/__init__.py"], []):
        assert related_tests(repo, changed) == [], changed
    (repo / "pkg" / "lonely.py").write_text("X = 1\n", encoding="utf-8")
    assert related_tests(repo, ["pkg/lonely.py"]) == []  # no test reaches it


# --- guard post -----------------------------------------------------------------------------------------------

def test_off_by_default_every_post_runs_the_full_suite(tmp_path, monkeypatch, fake_ocr_review):
    repo = python_repo(tmp_path)
    llm_approves(monkeypatch)
    change_a(repo)
    assert execute_post_task(repo_path=repo) is True
    build = SessionManager(repo).load_local_session().post.build_check  # type: ignore[union-attr]
    assert build is not None and build.command == "pytest" and build.related == []


def test_a_failing_related_test_rejects_without_the_full_suite_and_the_report_says_so(tmp_path, monkeypatch, fake_ocr_review):
    repo = python_repo(tmp_path)
    use_related_tests()
    llm_approves(monkeypatch)
    change_a(repo)
    (repo / "tests" / "test_a.py").write_text("import pkg.a\n\n" + FAIL, encoding="utf-8")

    assert execute_post_task(repo_path=repo) is False
    post = SessionManager(repo).load_local_session().post  # type: ignore[union-attr]
    assert post.build_check.command == "pytest tests/test_a.py" and not post.build_check.passed
    assert post.build_check.related == ["tests/test_a.py"]
    report = (repo / ".guard" / "POST_TASK_REPORT.md").read_text(encoding="utf-8")
    assert "Related tests only (1 file(s)); the full suite runs before any approval." in report


def test_an_approval_always_has_a_full_run_that_can_still_reject(tmp_path, monkeypatch, fake_ocr_review):
    repo = python_repo(tmp_path, other_test=FAIL)  # pkg/b.py's test fails; the related run never sees it
    use_related_tests()
    llm_approves(monkeypatch)
    change_a(repo)

    assert execute_post_task(repo_path=repo) is False
    build = SessionManager(repo).load_local_session().post.build_check  # type: ignore[union-attr]
    assert build.command == "pytest" and not build.passed and build.related == []


def test_a_full_run_that_passes_approves(tmp_path, monkeypatch, fake_ocr_review):
    repo = python_repo(tmp_path)
    use_related_tests()
    llm_approves(monkeypatch)
    change_a(repo)

    assert execute_post_task(repo_path=repo) is True
    build = SessionManager(repo).load_local_session().post.build_check  # type: ignore[union-attr]
    assert build.command == "pytest" and build.passed and build.related == []


# --- guard config tests ---------------------------------------------------------------------------------------

def test_config_tests_sets_the_scope_and_refuses_anything_else():
    runner = CliRunner()
    assert runner.invoke(app, ["config", "tests", "related"]).exit_code == 0
    assert load_global_config().tests_scope == "related"
    refused = runner.invoke(app, ["config", "tests", "some"])
    assert refused.exit_code == 1 and "`full` or `related`" in refused.output
    assert load_global_config().tests_scope == "related"
    assert runner.invoke(app, ["config", "tests", "full"]).exit_code == 0
    assert load_global_config().tests_scope == "full"
