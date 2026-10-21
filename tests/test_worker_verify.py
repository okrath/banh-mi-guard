"""
Unit tests for the worker delivery-verification engine.
"""

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from guard.core.worker_verify import FAIL, WARN, VerifyResult, verify_worker

PASS_COMMAND = "git rev-parse --short HEAD"
FAIL_COMMAND = "git rev-parse refs/heads/no-such-branch"

# Sample lines are assembled from parts: a literal weakened line in this file's diff would
# be flagged by the very engine these tests exercise.
WEAKENING_SAMPLES = [
    ("describe" + ".skip('x', () => {})", "weakened-skip-focus"),
    ("it" + "." + "only('x', () => {})", "weakened-skip-focus"),
    ("py" + "test.mark.skip('later')", "weakened-skip-focus"),
    ("py" + "test.mark.xfail(reason='known bug')", "weakened-skip-focus"),
    ("npm test ||" + " true", "weakened-swallowed-failure"),
    ("npm test --" + "passWith" + "NoTests", "weakened-swallowed-failure"),
    ("// eslint-" + "disable-next-line", "weakened-lint-type-silenced"),
    ("# type" + ": ignore", "weakened-lint-type-silenced"),
    ("const value = input as" + " any", "weakened-any-escape"),
    ("const value:" + " any = 1", "weakened-any-escape"),
]

# A platform-conditional skip is a legitimate test guard, not a weakened test.
SKIPIF_TEST = "\n".join(
    [
        "@" + "py" + "test.mark.skipif(os.name == 'nt', reason='windows only')",
        "def test_platform():",
        "    assert True",
        "",
    ]
)

# What a docs page looks like when it quotes the weakening patterns back at the reader: the
# quoted strings are documentation, not executable checks, so they must not fail the scan.
DOCS_QUOTING_THE_PATTERNS = "\n".join(
    [
        "Do not add `describe" + ".skip(` or `py" + "test.mark.skip(` to a suite.",
        "Do not pipe a test through `npm test ||" + " true`.",
        "No `eslint-" + "disable` and no `@ts-" + "ignore` comments.",
        "No `as" + " any`, no `:" + " any` and no `<" + "any>` escapes.",
    ]
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway repository with one commit; its HEAD is a worker's base."""
    root = tmp_path / "worker"
    root.mkdir()
    git(root, "init", "-q")
    (root / "keep.txt").write_text("base\n", encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    return root


def head(repo: Path) -> str:
    return git(repo, "rev-parse", "HEAD").strip()


def commit_all(repo: Path, message: str) -> None:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


def stage_all(repo: Path) -> None:
    git(repo, "add", "-A")


def codes(result: VerifyResult) -> list[str]:
    return [issue.code for issue in result.issues]


def test_empty_result_passes() -> None:
    result = VerifyResult()
    assert result.passed
    assert result.fails == []
    assert result.warns == []


def test_clean_fix_worker_inside_its_globs_passes(repo: Path) -> None:
    base = head(repo)
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    commit_all(repo, "work")
    result = verify_worker(repo, base=base, own=["src/**"])
    assert result.passed
    assert result.fails == []


def test_edit_outside_ownership_fails(repo: Path) -> None:
    base = head(repo)
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "docs.md").write_text("notes\n", encoding="utf-8")
    result = verify_worker(repo, base=base, own=["src/**"])
    assert codes(result) == ["scope-outside-ownership"]
    assert "docs.md" in result.issues[0].message


def test_ownership_globs_are_case_sensitive(repo: Path) -> None:
    base = head(repo)
    (repo / "Docs").mkdir()
    (repo / "Docs" / "a.md").write_text("x\n", encoding="utf-8")
    result = verify_worker(repo, base=base, own=["docs/*.md"])
    assert codes(result) == ["scope-outside-ownership"]


def test_unknown_role_is_rejected(repo: Path) -> None:
    with pytest.raises(ValueError):
        verify_worker(repo, base=head(repo), role="qa")


def test_test_worker_tracked_edit_fails(repo: Path) -> None:
    base = head(repo)
    (repo / "keep.txt").write_text("changed\n", encoding="utf-8")
    result = verify_worker(repo, base=base, role="test")
    assert codes(result) == ["test-worker-tracked-edits"]


def test_test_worker_commit_fails(repo: Path) -> None:
    base = head(repo)
    (repo / "keep.txt").write_text("changed\n", encoding="utf-8")
    commit_all(repo, "edge case")
    result = verify_worker(repo, base=base, role="test")
    assert "test-worker-tracked-edits" in codes(result)


def test_test_worker_untracked_files_pass(repo: Path) -> None:
    base = head(repo)
    (repo / "evidence.txt").write_text("shot\n", encoding="utf-8")
    result = verify_worker(repo, base=base, role="test")
    assert result.passed


@pytest.mark.parametrize(("sample", "code"), WEAKENING_SAMPLES)
def test_weakening_patterns(repo: Path, sample: str, code: str) -> None:
    base = head(repo)
    (repo / "app.js").write_text(sample + "\n", encoding="utf-8")
    commit_all(repo, "work")
    result = verify_worker(repo, base=base, quick=True)
    assert codes(result) == [code]


def test_pytest_mark_skipif_is_not_a_skip(repo: Path) -> None:
    base = head(repo)
    (repo / "tests").mkdir()
    (repo / "tests" / "test_platform.py").write_text(SKIPIF_TEST, encoding="utf-8")
    commit_all(repo, "a platform test")
    result = verify_worker(repo, base=base, quick=True)
    assert codes(result) == []


def test_docs_patterns_and_skipif_pass_but_a_real_skip_fails(repo: Path) -> None:
    """The smoke reproduction: quoted patterns in docs and a platform skipif must not fail."""
    base = head(repo)
    (repo / "docs").mkdir()
    (repo / "docs" / "notes.md").write_text(DOCS_QUOTING_THE_PATTERNS, encoding="utf-8")
    (repo / "config.yaml").write_text("script: npm test ||" + " true\n", encoding="utf-8")
    (repo / "tests").mkdir()
    test_file = repo / "tests" / "test_platform.py"
    test_file.write_text(SKIPIF_TEST, encoding="utf-8")
    commit_all(repo, "docs and a platform test")
    assert codes(verify_worker(repo, base=base, quick=True)) == []

    test_file.write_text(SKIPIF_TEST + "py" + "test.mark.skip('later')" + "\n", encoding="utf-8")
    commit_all(repo, "an unconditional skip")
    result = verify_worker(repo, base=base, quick=True)
    assert codes(result) == ["weakened-skip-focus"]


def test_deleted_test_file_fails(repo: Path) -> None:
    (repo / "tests").mkdir()
    (repo / "tests" / "test_thing.py").write_text("def test_thing():\n    assert True\n", encoding="utf-8")
    commit_all(repo, "a test")
    base = head(repo)
    (repo / "tests" / "test_thing.py").unlink()
    result = verify_worker(repo, base=base)
    assert "weakened-deleted-test" in codes(result)
    assert not result.passed


def test_deleted_non_test_file_is_no_fail(repo: Path) -> None:
    base = head(repo)
    (repo / "keep.txt").unlink()
    result = verify_worker(repo, base=base)
    assert result.passed


def test_fewer_assertions_warns(repo: Path) -> None:
    (repo / "tests").mkdir()
    (repo / "tests" / "test_x.py").write_text(
        "def test_x():\n    assert a == 1\n    assert b == 2\n", encoding="utf-8"
    )
    commit_all(repo, "a test")
    base = head(repo)
    (repo / "tests" / "test_x.py").write_text("def test_x():\n    assert a == 1\n", encoding="utf-8")
    result = verify_worker(repo, base=base, quick=True)
    assert "fewer-assertions" in codes(result)
    assert result.passed


def test_spec_dropped_from_package_json_fails(repo: Path) -> None:
    (repo / "package.json").write_text(
        json.dumps({"scripts": {"test": "vitest run src/a.test.ts src/b.test.ts"}}), encoding="utf-8"
    )
    commit_all(repo, "tooling")
    base = head(repo)
    (repo / "package.json").write_text(
        json.dumps({"scripts": {"test": "vitest run src/a.test.ts"}}), encoding="utf-8"
    )
    result = verify_worker(repo, base=base)
    assert "weakened-spec-dropped" in codes(result)
    assert "src/b.test.ts" in result.issues[0].message


def test_ci_workflow_change_fails(repo: Path) -> None:
    base = head(repo)
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text("on: push\n", encoding="utf-8")
    commit_all(repo, "ci")
    result = verify_worker(repo, base=base)
    assert "ci-workflow-changed" in codes(result)


def test_ci_workflow_change_inside_own_passes(repo: Path) -> None:
    base = head(repo)
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text("on: push\n", encoding="utf-8")
    commit_all(repo, "ci")
    result = verify_worker(repo, base=base, own=[".github/workflows/*.yml"])
    assert result.passed


def test_empty_own_allows_any_path(repo: Path) -> None:
    base = head(repo)
    (repo / "anywhere.txt").write_text("x\n", encoding="utf-8")
    commit_all(repo, "work")
    assert verify_worker(repo, base=base).passed


def test_star_stays_within_one_segment(repo: Path) -> None:
    base = head(repo)
    (repo / "docs").mkdir()
    (repo / "docs" / "a.md").write_text("x\n", encoding="utf-8")
    commit_all(repo, "work")
    assert verify_worker(repo, base=base, own=["docs/*.md"]).passed

    (repo / "docs" / "sub").mkdir()
    (repo / "docs" / "sub" / "b.md").write_text("y\n", encoding="utf-8")
    result = verify_worker(repo, base=base, own=["docs/*.md"])
    assert codes(result) == ["scope-outside-ownership"]


def test_double_star_covers_nested_paths(repo: Path) -> None:
    base = head(repo)
    (repo / "src" / "deep").mkdir(parents=True)
    (repo / "src" / "deep" / "b.py").write_text("x\n", encoding="utf-8")
    commit_all(repo, "work")
    assert verify_worker(repo, base=base, own=["src/**"]).passed


def test_own_globs_accept_backslashes(repo: Path) -> None:
    base = head(repo)
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    commit_all(repo, "work")
    assert verify_worker(repo, base=base, own=["src\\**"]).passed


def test_quoted_porcelain_paths_are_unquoted(repo: Path) -> None:
    base = head(repo)
    (repo / "docs").mkdir()
    (repo / "docs" / "caf\u00e9.md").write_text("x\n", encoding="utf-8")
    stage_all(repo)
    assert verify_worker(repo, base=base, own=["docs/*.md"]).passed


def test_untracked_files_in_a_new_folder_inside_a_narrow_glob_pass(repo: Path) -> None:
    """Git would collapse a wholly new folder to `apps/`; each file must be checked on its own."""
    base = head(repo)
    models = repo / "apps" / "web" / "public" / "models" / "characters"
    models.mkdir(parents=True)
    (models / "chibi.glb").write_bytes(b"glb")
    (models / "chibi.json").write_text("{}\n", encoding="utf-8")
    assert verify_worker(repo, base=base, own=["apps/web/public/models/characters/**"]).passed


def test_untracked_file_outside_a_narrow_glob_in_a_new_folder_is_flagged(repo: Path) -> None:
    base = head(repo)
    models = repo / "apps" / "web" / "public" / "models" / "characters"
    models.mkdir(parents=True)
    (models / "chibi.glb").write_bytes(b"glb")
    (repo / "apps" / "web" / "public" / "favicon.ico").write_bytes(b"ico")
    result = verify_worker(repo, base=base, own=["apps/web/public/models/characters/**"])
    assert codes(result) == ["scope-outside-ownership"]
    assert "apps/web/public/favicon.ico" in result.issues[0].message
    assert "chibi.glb" not in result.issues[0].message


def test_staged_rename_names_both_paths(repo: Path) -> None:
    base = head(repo)
    git(repo, "mv", "keep.txt", "moved.txt")
    result = verify_worker(repo, base=base, own=["moved.txt"])
    assert codes(result) == ["scope-outside-ownership"]
    assert "keep.txt" in result.issues[0].message


def test_staged_rename_inside_own_passes(repo: Path) -> None:
    base = head(repo)
    git(repo, "mv", "keep.txt", "moved.txt")
    assert verify_worker(repo, base=base, own=["keep.txt", "moved.txt"]).passed


def test_report_missing_fails(repo: Path, tmp_path: Path) -> None:
    result = verify_worker(repo, base=head(repo), report=tmp_path / "nope.md")
    assert codes(result) == ["report-missing"]


def test_report_stale_fails(repo: Path, tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text("done\n", encoding="utf-8")
    old = time.time() - 3600
    os.utime(report, (old, old))
    result = verify_worker(repo, base=head(repo), report=report, since=time.time())
    assert "report-stale" in codes(result)


def test_report_paths_resolve_against_the_worktree(repo: Path, tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text("see keep.txt and notes/absent.png\n", encoding="utf-8")
    result = verify_worker(repo, base=head(repo), report=report)
    assert codes(result) == ["report-missing-paths"]
    assert "notes/absent.png" in result.issues[0].message
    assert "keep.txt" not in result.issues[0].message


def test_report_format_words_are_not_paths(repo: Path, tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text("the .json and .md files are untouched\n", encoding="utf-8")
    result = verify_worker(repo, base=head(repo), report=report)
    assert result.passed


def test_markdown_link_paths_are_recognized(repo: Path, tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text("before/after: [shot](missing.png) and (other.png)\n", encoding="utf-8")
    result = verify_worker(repo, base=head(repo), report=report)
    assert codes(result) == ["report-missing-paths"]
    message = result.issues[0].message
    assert "missing.png" in message
    assert "other.png" in message
    assert "(missing.png" not in message


def test_unchecked_claim_warns_without_checks(repo: Path, tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text("All tests pass.\n", encoding="utf-8")
    result = verify_worker(repo, base=head(repo), report=report)
    assert codes(result) == ["report-unchecked-claim"]
    assert result.passed


def test_claim_with_a_check_command_is_not_warned(repo: Path, tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text("All tests pass.\n", encoding="utf-8")
    result = verify_worker(repo, base=head(repo), report=report, check_commands=[PASS_COMMAND])
    assert codes(result) == []
    assert [check.exit_code for check in result.checks] == [0]


def test_evidence_warns(repo: Path, tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    big = b"x" * 9000
    for name in ("old.png", "tiny.png", "a.png", "b.png"):
        (evidence / name).write_bytes(big if name != "tiny.png" else b"x")
    old = time.time() - 3600
    os.utime(evidence / "old.png", (old, old))
    result = verify_worker(repo, base=head(repo), evidence=evidence, since=time.time())
    assert {"evidence-old", "evidence-tiny", "evidence-duplicate"} <= set(codes(result))
    assert "evidence-empty" not in codes(result)


def test_evidence_empty_warns(repo: Path, tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    result = verify_worker(repo, base=head(repo), evidence=evidence)
    assert codes(result) == ["evidence-empty"]


def test_rerun_passing_command_is_recorded(repo: Path) -> None:
    result = verify_worker(repo, base=head(repo), check_commands=[PASS_COMMAND])
    assert result.passed
    assert [check.command for check in result.checks] == [PASS_COMMAND]
    assert [check.exit_code for check in result.checks] == [0]


def test_rerun_failing_command_fails(repo: Path) -> None:
    result = verify_worker(repo, base=head(repo), check_commands=[FAIL_COMMAND])
    assert codes(result) == ["check-failed"]
    assert result.checks[0].exit_code != 0
    assert f"re-run failed (exit {result.checks[0].exit_code})" in result.issues[0].message


def test_quick_skips_report_evidence_and_checks(repo: Path, tmp_path: Path) -> None:
    result = verify_worker(
        repo,
        base=head(repo),
        report=tmp_path / "nope.md",
        evidence=tmp_path / "no-evidence",
        check_commands=[FAIL_COMMAND],
        quick=True,
    )
    assert result.passed
    assert result.checks == []


def test_to_dict_round_trips(repo: Path, tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text("All tests pass.\n", encoding="utf-8")
    result = verify_worker(repo, base=head(repo), report=report)
    data = result.to_dict()
    assert data["passed"] is True
    assert data["issues"] == [
        {"severity": WARN, "code": "report-unchecked-claim", "message": result.issues[0].message}
    ]
    assert data["checks"] == []


def test_failed_result_is_not_passed(repo: Path) -> None:
    base = head(repo)
    (repo / "nope.txt").write_text("x\n", encoding="utf-8")
    result = verify_worker(repo, base=base, own=["src/**"])
    assert result.passed is False
    assert [issue.severity for issue in result.fails] == [FAIL]
