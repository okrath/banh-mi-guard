"""
Tests for the dependency-link check of the main checkout and worker worktrees.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import guard.cli
from guard.core import deps_check
from guard.core.deps_check import check_main_checkout, check_worktree, main_checkout_links, main_checkout_of


def make_link(link: Path, target: Path) -> None:
    """A directory link the way pnpm makes one: a junction on Windows, a symlink elsewhere."""
    link.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


def remove_link(link: Path) -> None:
    """Removes the link itself, never what it points to."""
    if os.name == "nt":
        os.rmdir(link)
    else:
        os.unlink(link)


def make_pkg(folder: Path, name: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0"}), encoding="utf-8")
    return folder


def store_pkg(modules: Path, name: str) -> Path:
    """A package inside pnpm's store of one node_modules folder."""
    return make_pkg(modules / ".pnpm" / f"{name.replace('/', '+')}@1.0.0" / "node_modules" / name, name)


def healthy_repo(root: Path) -> Path:
    """A main checkout with root, app and scoped package links, all into its own store."""
    repo = root / "repo"
    modules = repo / "node_modules"
    make_link(modules / "vite", store_pkg(modules, "vite"))
    make_link(modules / "@vue" / "shared", store_pkg(modules, "@vue/shared"))
    app_modules = repo / "vue3" / "node_modules"
    make_link(app_modules / "vue-tsc", store_pkg(modules, "vue-tsc"))
    return repo


def make_worktree(root: Path, repo: Path) -> Path:
    """A worker worktree sharing the main checkout's node_modules through junctions."""
    wt = root / "wt"
    (wt / "vue3").mkdir(parents=True)
    make_link(wt / "node_modules", repo / "node_modules")
    make_link(wt / "vue3" / "node_modules", repo / "vue3" / "node_modules")
    return wt


@pytest.fixture
def app():
    """guard's app: guard.cli registers deps-check with the other commands."""
    return guard.cli.app


def test_healthy_main_checkout_passes(tmp_path):
    repo = healthy_repo(tmp_path)

    assert check_main_checkout(repo) == []
    assert len(main_checkout_links(repo)) == 3


def test_store_and_shims_are_not_checked(tmp_path):
    repo = healthy_repo(tmp_path)
    elsewhere = make_pkg(tmp_path / "elsewhere" / "tool", "tool")
    make_link(repo / "node_modules" / ".bin" / "tool", elsewhere)
    make_link(repo / "node_modules" / ".pnpm" / "tool", elsewhere)
    make_link(repo / "plans" / "node_modules" / "tool", elsewhere)
    make_link(repo / "docs" / "node_modules" / "tool", elsewhere)

    assert check_main_checkout(repo) == []
    assert len(main_checkout_links(repo)) == 3


def test_dangling_link_fails(tmp_path):
    repo = healthy_repo(tmp_path)
    gone = make_pkg(tmp_path / "gone" / "lodash", "lodash")
    link = repo / "node_modules" / "lodash"
    make_link(link, gone)
    shutil.rmtree(gone)

    assert check_main_checkout(repo) == [f"FAIL main dangling: {link} -> {gone}"]


def test_link_into_another_tree_fails_and_nothing_is_touched(tmp_path):
    repo = healthy_repo(tmp_path)
    worker_store = tmp_path / "wt" / "node_modules"
    target = store_pkg(worker_store, "vite")
    link = repo / "vue3" / "node_modules" / "vite"
    make_link(link, target)

    assert check_main_checkout(repo) == [f"FAIL main points outside the checkout: {link} -> {target}"]
    assert (target / "package.json").is_file()  # read-only: the target and the link stay
    assert os.path.lexists(link) and (link / "package.json").is_file()


def test_scoped_package_pointing_outside_fails(tmp_path):
    repo = healthy_repo(tmp_path)
    target = store_pkg(tmp_path / "other" / "node_modules", "@vitejs/plugin-vue")
    link = repo / "node_modules" / "@vitejs" / "plugin-vue"
    make_link(link, target)

    assert check_main_checkout(repo) == [f"FAIL main points outside the checkout: {link} -> {target}"]
    assert len(main_checkout_links(repo)) == 4


def test_sibling_folder_with_the_repo_name_as_prefix_is_outside(tmp_path):
    repo = healthy_repo(tmp_path)
    target = store_pkg(tmp_path / "repo-copy" / "node_modules", "vite")
    link = repo / "node_modules" / "vite2"
    make_link(link, target)

    assert check_main_checkout(repo) == [f"FAIL main points outside the checkout: {link} -> {target}"]


def test_missing_node_modules_is_healthy(tmp_path):
    repo = tmp_path / "repo"
    (repo / "vue3").mkdir(parents=True)

    assert check_main_checkout(repo) == []
    assert main_checkout_links(repo) == []


@pytest.mark.skipif(os.name == "nt", reason="relative symlinks need Developer Mode on Windows, where pnpm makes junctions")
def test_relative_symlinks_resolve_from_their_folder(tmp_path):
    repo = healthy_repo(tmp_path)
    store_pkg(repo / "node_modules", "pinia")
    os.symlink(os.path.join(".pnpm", "pinia@1.0.0", "node_modules", "pinia"), repo / "node_modules" / "pinia")
    store_pkg(tmp_path / "wt" / "node_modules", "axios")
    link = repo / "node_modules" / "axios"
    os.symlink(os.path.join("..", "..", "wt", "node_modules", ".pnpm", "axios@1.0.0", "node_modules", "axios"), link)
    target = tmp_path / "wt" / "node_modules" / ".pnpm" / "axios@1.0.0" / "node_modules" / "axios"

    assert check_main_checkout(repo) == [f"FAIL main points outside the checkout: {link} -> {target}"]


def test_junction_found_without_os_path_isjunction(tmp_path, monkeypatch):
    repo = healthy_repo(tmp_path)
    monkeypatch.delattr(os.path, "isjunction", raising=False)  # Python 3.10-3.11

    assert len(main_checkout_links(repo)) == 3


def test_healthy_worktree_passes(tmp_path):
    repo = healthy_repo(tmp_path)
    wt = make_worktree(tmp_path, repo)

    assert check_worktree(repo, wt) == []


def test_worktree_junction_outside_the_main_checkout_fails(tmp_path):
    repo = healthy_repo(tmp_path)
    wt = make_worktree(tmp_path, repo)
    own = tmp_path / "own-install" / "node_modules"
    store_pkg(own, "vite")
    remove_link(wt / "vue3" / "node_modules")
    make_link(wt / "vue3" / "node_modules", own)

    assert check_worktree(repo, wt) == [
        f"FAIL worktree junction not into the main checkout: {wt / 'vue3' / 'node_modules'} -> {own}"
    ]
    assert (repo / "vue3" / "node_modules" / "vue-tsc").exists()


def test_dangling_worktree_junction_fails(tmp_path):
    repo = healthy_repo(tmp_path)
    wt = tmp_path / "wt"
    wt.mkdir()
    gone = tmp_path / "gone" / "node_modules"
    gone.mkdir(parents=True)
    make_link(wt / "node_modules", gone)
    gone.rmdir()

    assert check_worktree(repo, wt) == [f"FAIL worktree junction dangling: {wt / 'node_modules'} -> {gone}"]


def test_missing_worktree_fails(tmp_path):
    repo = healthy_repo(tmp_path)
    missing = tmp_path / "no-such-wt"

    assert check_worktree(repo, missing) == [f"FAIL worktree missing: {missing}"]


def test_packages_load_through_the_worktree_junction(tmp_path):
    repo = healthy_repo(tmp_path)
    make_pkg(repo / "vue3" / "node_modules" / "fakepkg", "fakepkg")
    wt = make_worktree(tmp_path, repo)

    assert check_worktree(repo, wt, {"vue3": ["fakepkg"]}) == []


def test_missing_package_fails_to_load(tmp_path):
    repo = healthy_repo(tmp_path)
    make_pkg(repo / "vue3" / "node_modules" / "fakepkg", "fakepkg")
    wt = make_worktree(tmp_path, repo)

    fails = check_worktree(repo, wt, {"vue3": ["fakepkg", "no-such-pkg"], "react": ["react"]})

    assert fails == [
        f"FAIL {wt / 'vue3'} cannot load no-such-pkg",
        f"FAIL {wt} has no react folder",
    ]


def test_missing_node_is_one_fail_line(tmp_path, monkeypatch):
    repo = healthy_repo(tmp_path)
    wt = make_worktree(tmp_path, repo)
    monkeypatch.setattr(deps_check.shutil, "which", lambda name: None)

    fails = check_worktree(repo, wt, {"vue3": ["vite", "vue-tsc"], "admin": ["vite"]})

    assert fails == [f"FAIL node is not on PATH: cannot check that packages load in {wt}"]


def test_node_timeout_is_a_fail_line(tmp_path, monkeypatch):
    repo = healthy_repo(tmp_path)
    wt = make_worktree(tmp_path, repo)

    def hang(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(deps_check.shutil, "which", lambda name: "node")
    monkeypatch.setattr(deps_check.subprocess, "run", hang)

    assert check_worktree(repo, wt, {"vue3": ["vite"]}) == [
        f"FAIL {wt / 'vue3'} cannot load vite (node timed out after {deps_check.NODE_TIMEOUT_S}s)"
    ]


def git(cwd: Path, *args: str) -> None:
    # Without the GIT_* variables a git hook exports, so a run inside a hook cannot reach the outer repository.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, timeout=60, env=env)


def test_main_checkout_of_a_worktree(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    git(repo, "add", "a.txt")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "init")
    wt = tmp_path / "wt"
    git(repo, "worktree", "add", "-q", "-b", "side", str(wt))

    from_worktree, from_main = main_checkout_of(wt), main_checkout_of(repo)
    assert from_worktree is not None and from_worktree.resolve() == repo.resolve()
    assert from_main is not None and from_main.resolve() == repo.resolve()
    assert main_checkout_of(tmp_path / "not-a-repo") is None


def test_main_checkout_of_ignores_a_hook_git_dir(tmp_path, monkeypatch):
    repo, other = tmp_path / "repo", tmp_path / "other"
    for folder in (repo, other):
        folder.mkdir()
        git(folder, "init", "-q")
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))  # what git exports while a hook runs

    found = main_checkout_of(repo)

    assert found is not None and found.resolve() == repo.resolve()


def test_cli_pass(tmp_path, app):
    repo = healthy_repo(tmp_path)
    wt = make_worktree(tmp_path, repo)

    result = CliRunner().invoke(app, ["deps-check", "--repo", str(repo), "--worktree", str(wt)])

    assert result.exit_code == 0, result.output
    assert "main checkout: 3 links checked" in result.output
    assert result.output.strip().endswith("RESULT: PASS")


def test_cli_fail(tmp_path, app):
    repo = healthy_repo(tmp_path)
    target = store_pkg(tmp_path / "wt" / "node_modules", "vite")
    make_link(repo / "node_modules" / "vite2", target)

    result = CliRunner().invoke(app, ["deps-check", "--repo", str(repo)])

    assert result.exit_code == 1
    assert "FAIL main points outside the checkout" in result.output
    assert result.output.strip().endswith("RESULT: FAIL")


def test_cli_json(tmp_path, app):
    repo = healthy_repo(tmp_path)
    make_pkg(repo / "vue3" / "node_modules" / "fakepkg", "fakepkg")
    wt = make_worktree(tmp_path, repo)

    result = CliRunner().invoke(
        app,
        ["deps-check", "--repo", str(repo), "--worktree", str(wt), "--resolve", "vue3=fakepkg,no-such-pkg", "--json"],
    )

    assert result.exit_code == 1
    assert json.loads(result.output) == {
        "result": "FAIL",
        "fails": [f"FAIL {wt / 'vue3'} cannot load no-such-pkg"],
        "checked": 3,
    }


@pytest.mark.parametrize(
    "extra",
    [
        ["--resolve", "vue3"],
        ["--resolve", "=vite"],
        ["--resolve", "vue3="],
    ],
)
def test_cli_malformed_resolve_is_a_usage_error(tmp_path, app, extra):
    repo = healthy_repo(tmp_path)

    result = CliRunner().invoke(app, ["deps-check", "--repo", str(repo), *extra])

    assert result.exit_code == 2


def test_cli_missing_repo_is_a_usage_error(tmp_path, app):
    assert CliRunner().invoke(app, ["deps-check", "--repo", str(tmp_path / "missing")]).exit_code == 2
    assert CliRunner().invoke(app, ["deps-check"]).exit_code == 2
