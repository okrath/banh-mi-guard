"""
How untracked path names are handled: literal patterns, whitespace, control characters, invalid
UTF-8, exclude-file bytes and line endings, terminal escaping and copy-safe suggestions.
"""

import subprocess

from test_untracked import exclude_text, make_repo  # pytest puts tests/ on sys.path
from typer.testing import CliRunner

from guard.cli import app, execute_pre_task
from guard.core.untracked import MARK, decide, load_decisions, undecided


def test_special_characters_are_ignored_literally(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "a[1].md").write_text("x\n", encoding="utf-8")
    (repo / "a1.md").write_text("y\n", encoding="utf-8")  # would match the name used as a glob
    decide(repo, "a[1].md", "ignore")
    assert undecided(repo) == ["a1.md"]  # only the exact file is ignored


def test_names_with_spaces_and_crlf_exclude_files_survive(tmp_path):
    repo = make_repo(tmp_path)
    (repo / " notes .md").write_text("x\n", encoding="utf-8")  # leading and trailing spaces are part of the name
    common = subprocess.run(["git", "-C", str(repo), "rev-parse", "--git-common-dir"], capture_output=True, text=True).stdout.strip()
    exclude = repo / common / "info" / "exclude"
    exclude.write_bytes(b"# user header\r\n/secret.txt\r\n")  # the user's CRLF file
    decide(repo, " notes .md", "ignore")
    assert undecided(repo) == []
    assert exclude.read_bytes().startswith(b"# user header\r\n/secret.txt\r\n")  # untouched bytes
    decide(repo, " notes .md", "include")
    assert exclude.read_bytes() == b"# user header\r\n/secret.txt\r\n"  # exactly as before
    assert load_decisions(repo) == {" notes .md": "include"}


def test_include_removes_only_that_entrys_pair(tmp_path):
    repo = make_repo(tmp_path)
    for name in ("a.md", "b.md"):
        (repo / name).write_text("x\n", encoding="utf-8")
        decide(repo, name, "ignore")
    decide(repo, "a.md", "include")
    text = exclude_text(repo)
    assert f"{MARK}: b.md\n/b.md" in text and "a.md" not in text


def test_more_control_characters_and_git_launch_failures(tmp_path, monkeypatch, capsys):
    import pytest

    import guard.core.untracked as untracked
    repo = make_repo(tmp_path)
    for bad in ("x\u0085y", "x y"):  # C1 next-line and the Unicode line separator
        with pytest.raises(ValueError, match="control characters"):
            decide(repo, bad, "ignore")
    real = untracked.subprocess.run

    def no_git(cmd, **kw):
        if "ls-files" in cmd:
            raise FileNotFoundError("git")
        return real(cmd, **kw)

    monkeypatch.setattr(untracked.subprocess, "run", no_git)
    assert execute_pre_task("Fix src/chat.ts", repo_path=repo) is False
    monkeypatch.chdir(repo)
    listed = CliRunner().invoke(app, ["untracked"])
    assert listed.exit_code == 1 and "Cannot list untracked paths" in listed.output


def test_terminal_output_escapes_odd_names():
    from guard.core.untracked import shown
    assert shown("plans/") == "plans/"
    assert shown("a\tb") == "a\\tb" and "\\" in shown("bad\udc80name")


def test_rich_markup_in_a_name_prints_as_text(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    (repo / "[red]x.md").write_text("x\n", encoding="utf-8")
    monkeypatch.chdir(repo)
    listed = CliRunner().invoke(app, ["untracked"])
    assert "[red]x.md" in listed.output  # shown literally, not swallowed as a style tag
    done = CliRunner().invoke(app, ["untracked", "[red]x.md", "--ignore"])
    assert done.exit_code == 0 and "[red]x.md" in done.output


def test_suggested_commands_survive_spaces_and_dashes():
    from guard.core.untracked import suggest
    assert suggest("my notes.md") == "guard untracked 'my notes.md' --include   or   guard untracked 'my notes.md' --ignore"
    assert suggest("-draft.md") == "guard untracked './-draft.md' --include   or   guard untracked './-draft.md' --ignore"
    for dangerous in ("$(rm -rf x)", "a`id`b", "it's.md", 'q"x.md', "a;b"):
        assert dangerous not in suggest(dangerous) and "<the path above>" in suggest(dangerous)  # never pasted raw
    assert "|" not in suggest("plans/")  # two commands, not a pipeline


def test_rejected_names_are_shown_literally(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    monkeypatch.chdir(repo)
    result = CliRunner().invoke(app, ["untracked", "[bold]nope[/bold]", "--ignore"])
    assert result.exit_code == 1 and "[bold]nope[/bold]" in result.output


def test_safe_names_must_be_safe_to_the_end_and_listing_errors_are_clean(tmp_path, monkeypatch):
    import pytest

    import guard.core.untracked as untracked
    from guard.core.untracked import suggest
    assert "<the path above>" in suggest("ok.md\n")  # a trailing newline is not a safe name
    repo = make_repo(tmp_path)
    monkeypatch.setattr(untracked, "untracked_entries", lambda r: (_ for _ in ()).throw(RuntimeError("git broke")))
    with pytest.raises(ValueError, match="cannot list untracked paths"):
        decide(repo, "whatever.md", "ignore")


def test_the_lock_file_is_never_opened_through_a_link(tmp_path):
    import os

    import pytest

    from guard.core.untracked import _open_no_follow
    target = tmp_path / "elsewhere"
    target.mkdir()
    link = tmp_path / "lock"
    if os.name == "nt":  # a junction needs no special rights on Windows
        made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True).returncode == 0
    else:
        link.symlink_to(target / "real.lock")
        made = True
    if not made:
        pytest.skip("cannot create a link here")
    with pytest.raises(OSError):
        _open_no_follow(link)
    assert not (target / "real.lock").exists()  # nothing was created behind the link


def test_doctor_shows_error_text_literally(tmp_path, monkeypatch):
    import guard.core.untracked as untracked
    from guard.core.setup_health import setup_health
    repo = make_repo(tmp_path)
    monkeypatch.setattr(untracked, "untracked_entries", lambda r: (_ for _ in ()).throw(RuntimeError("[red]boom")))
    rows = [r for r in setup_health(repo) if r["item"] == "Untracked paths"]
    assert rows and r"\[red]boom" in rows[0]["detail"]  # escaped for the Rich table
