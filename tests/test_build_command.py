"""The build command guard post runs: set per repository, detected only with evidence, and exit 5 as no tests."""

import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from guard.cli import app
from guard.core.build_command import (
    build_argv,
    build_command,
    collected_no_tests,
    command_problem,
    configured_build_command,
    set_build_command,
)
from guard.core.session import BuildCheckResult, PostTaskRecord
from guard.domains.detector import detect_build_command
from guard.reporters.markdown import _markdown_build_check
from guard.task_flow import _run_build


def git_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    return path


def test_a_monorepo_with_a_root_pyproject_but_no_python_tests_gets_no_python_command(tmp_path):
    repo = git_repo(tmp_path / "mono")
    (repo / "pyproject.toml").write_text("[tool.ruff]\nline-length = 120\n", encoding="utf-8")
    (repo / "lambdas" / "push").mkdir(parents=True)
    (repo / "lambdas" / "push" / "package.json").write_text('{"scripts": {"test": "vitest"}}', encoding="utf-8")
    assert detect_build_command(repo) is None
    assert build_command(repo) == (None, False)


def test_python_test_commands_need_python_tests_in_sight(tmp_path):
    for i, (marker, expected) in enumerate([
        ("tests/test_a.py", "pytest"),
        ("conftest.py", "pytest"),
        ("pytest.ini", "pytest"),
        ("test_root.py", "python -m unittest"),
        ("util_test.py", "python -m unittest"),
    ]):
        repo = tmp_path / f"r{i}"
        (repo / marker).parent.mkdir(parents=True, exist_ok=True)
        (repo / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
        (repo / marker).write_text("", encoding="utf-8")
        assert detect_build_command(repo) == expected, marker
    configured = tmp_path / "cfg"
    configured.mkdir()
    (configured / "pyproject.toml").write_text("[tool.pytest.ini_options]\naddopts = '-q'\n", encoding="utf-8")
    assert detect_build_command(configured) == "pytest"


def test_the_set_command_lives_in_the_git_dir_and_every_worktree_reads_it(tmp_path):
    repo = git_repo(tmp_path / "main")
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q",
                    "--allow-empty", "-m", "init"], check=True)
    path = set_build_command(repo, "pnpm -r test")
    assert path.parent.name == ".git" and not any(p.name == "guard-build.json" for p in repo.iterdir())
    subprocess.run(["git", "-C", str(repo), "worktree", "add", "-q", str(tmp_path / "wt")], check=True)
    assert configured_build_command(tmp_path / "wt") == "pnpm -r test"
    assert build_command(tmp_path / "wt") == ("pnpm -r test", True)
    set_build_command(repo, None)
    assert configured_build_command(repo) is None and not path.exists()


def test_a_command_is_set_only_inside_a_git_repository(tmp_path):
    try:
        set_build_command(tmp_path, "pnpm test")
    except OSError as e:
        assert "not a Git repository" in str(e)
    else:
        raise AssertionError("set outside a Git repository")


def test_a_command_must_run_as_one_argument_list():
    assert "`&&` needs a shell" in command_problem("cd a && pnpm test")
    assert "`|` needs a shell" in command_problem("pnpm test|tee log")
    assert "`&` needs a shell" in command_problem("pnpm test &")
    assert "sets a variable" in command_problem("CI=1 pnpm test")
    assert "cannot be split" in command_problem('pnpm "test')
    assert "more than one line" in command_problem("pnpm test\npnpm lint")
    assert command_problem("  ") == "it is empty"
    # an operator inside quotes is a plain argument
    assert command_problem("pnpm -r --filter './lambdas/**' test") is None
    assert command_problem('npx vitest -t "x;y" --grep "a | b"') is None
    argv = build_argv("pnpm -r --filter './lambdas/**' test")
    assert argv[1:] == ["-r", "--filter", "./lambdas/**", "test"]


def test_only_pytest_and_unittest_read_exit_5_as_no_tests():
    assert collected_no_tests("pytest", 5)
    assert collected_no_tests("pytest tests/test_a.py", 5)
    assert collected_no_tests("python -m unittest", 5)
    assert collected_no_tests("python3 -m pytest -q", 5)
    assert not collected_no_tests("pytest", 1)
    assert not collected_no_tests("pnpm test", 5)
    assert not collected_no_tests("python -m mypy .", 5)
    assert collected_no_tests('"C:/Program Files/Python312/python.exe" -m pytest', 5)  # a quoted interpreter path


def test_a_set_command_runs_without_a_shell_and_no_tests_is_not_a_failure(tmp_path):
    repo = git_repo(tmp_path / "empty")
    python = Path(sys.executable).as_posix()
    set_build_command(repo, f"{python} -m pytest -q -p no:cacheprovider")
    res = _run_build(repo)
    assert res is not None and res.exit_code == 5 and res.no_tests and res.passed and res.configured
    assert "set with `guard config build`" in "\n".join(_markdown_build_check(PostTaskRecord(build_check=res)))
    set_build_command(repo, f'{python} -c "import sys; sys.exit(3)"')
    failed = _run_build(repo)
    assert failed is not None and failed.exit_code == 3 and not failed.passed and not failed.no_tests


def test_the_report_says_nothing_was_tested():
    post = PostTaskRecord(build_check=BuildCheckResult(command="pytest", passed=True, exit_code=5, duration_s=0.1,
                                                       no_tests=True))
    text = "\n".join(_markdown_build_check(post))
    assert "nothing was tested" in text and "guard config build" in text and "✅" not in text
    assert "guard config build" in "\n".join(_markdown_build_check(PostTaskRecord()))


def test_config_build_shows_and_refuses_an_agent(tmp_path):
    repo = git_repo(tmp_path / "r")
    (repo / "go.mod").write_text("module x\n", encoding="utf-8")
    runner = CliRunner()
    shown = runner.invoke(app, ["config", "build", "--repo", str(repo)])
    assert shown.exit_code == 0 and "go test" in shown.output and "detected" in shown.output
    chained = runner.invoke(app, ["config", "build", "cd a && pnpm test", "--repo", str(repo)])
    assert chained.exit_code == 1 and "`&&`" in chained.output
    refused = runner.invoke(app, ["config", "build", "pnpm test", "--repo", str(repo)])  # no terminal: not the user
    assert refused.exit_code == 1 and "interactive terminal" in refused.output
    assert configured_build_command(repo) is None
