"""
Checking that the dependency links shared between the main checkout and worker worktrees are healthy.

Workers share the main checkout's `node_modules` through junctions (symlinks outside Windows).
An install run through such a junction makes pnpm rewrite the main checkout's package links
into the worker's worktree: the main checkout keeps working until that worktree is deleted, and
a shim such as `.bin/vite.cmd` survives the damage, so checking it proves nothing. This module
reads every package link instead:

- main checkout: every link in `<repo>/node_modules` and `<repo>/<app>/node_modules` (including
  `@scope/*`) must resolve and stay inside the main checkout;
- worktree: each `node_modules` junction must point into the main checkout, and the packages
  asked for must load from it with Node.

Read-only: links are listed and read, never followed to change or delete anything. Stdlib only
and no guard imports, so the watchdog can run it on every tick.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import List, Mapping, Optional, Sequence

NODE_TIMEOUT_S = 30
GIT_TIMEOUT_S = 15
# Folders of the checkout root that never hold an app with its own node_modules.
SKIPPED_ROOT_DIRS = frozenset({".git", "node_modules", "plans", "docs"})
# pnpm's store and the command shims are not package links.
SKIPPED_MODULE_ENTRIES = frozenset({".pnpm", ".bin"})
# Set by git while a hook runs; inherited, they would point `git -C <worktree>` at another repository.
REPO_ENV_VARS = frozenset({"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_PREFIX"})
RESOLVE_SCRIPT = "require.resolve(process.argv[1] + '/package.json')"


def _is_junction(path: str) -> bool:
    """A Windows junction; Python 3.10-3.11 have no os.path.isjunction, so read the reparse flag."""
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction is not None:
        return isjunction(path)
    try:
        attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _is_link(path: str) -> bool:
    return os.path.islink(path) or _is_junction(path)


def _link_target(link: str) -> Optional[str]:
    """Absolute, normalised target of a link as written (not followed further); None if unreadable."""
    try:
        target = os.readlink(link)
    except (OSError, ValueError):
        return None
    if os.name == "nt":  # junction targets come back in the \\?\ form
        if target.startswith("\\\\?\\UNC\\"):
            target = "\\\\" + target[8:]
        elif target.startswith("\\\\?\\"):
            target = target[4:]
    if not os.path.isabs(target):
        target = os.path.join(os.path.dirname(link), target)
    return os.path.normpath(target)


def _under(path: str, roots: Sequence[str]) -> bool:
    """`path` lies strictly inside one of `roots` (compared as text, the way Windows compares paths)."""
    candidate = os.path.normcase(path)
    for root in roots:
        prefix = os.path.normcase(root).rstrip("\\/") + os.sep
        if candidate.startswith(prefix):
            return True
    return False


def _repo_roots(repo: Path) -> List[str]:
    """The checkout as given and as it really is, so a repo reached through a link still matches."""
    given = os.path.normpath(os.path.abspath(repo))
    real = os.path.realpath(given)
    return [given] if real == given else [given, real]


def _entries(directory: str) -> List[os.DirEntry]:
    try:
        with os.scandir(directory) as it:
            return sorted(it, key=lambda entry: entry.name)
    except OSError:
        return []


def _module_dirs(root: Path) -> List[str]:
    """`<root>/node_modules` and `<root>/<app>/node_modules` that exist (even as a dangling link)."""
    base = os.path.abspath(root)
    candidates = [os.path.join(base, "node_modules")]
    for entry in _entries(base):
        if entry.name not in SKIPPED_ROOT_DIRS and entry.is_dir():
            candidates.append(os.path.join(entry.path, "node_modules"))
    return [path for path in candidates if os.path.lexists(path)]


def _links_in(directory: str) -> List[str]:
    """Package links of one node_modules folder, `@scope/*` included, `.pnpm` and `.bin` skipped."""
    links: List[str] = []
    for entry in _entries(directory):
        if entry.name in SKIPPED_MODULE_ENTRIES:
            continue
        if _is_link(entry.path):
            links.append(entry.path)
        elif entry.name.startswith("@") and entry.is_dir(follow_symlinks=False):
            links.extend(child.path for child in _entries(entry.path) if _is_link(child.path))
    return links


def main_checkout_links(repo: Path) -> List[str]:
    """Every package link the main checkout check reads."""
    return [link for directory in _module_dirs(repo) for link in _links_in(directory)]


def check_main_checkout(repo: Path) -> List[str]:
    """`FAIL ...` lines for main-checkout package links that dangle or leave the checkout."""
    roots = _repo_roots(repo)
    fails: List[str] = []
    for link in main_checkout_links(repo):
        target = _link_target(link)
        if target is None:  # a reparse point that is not a link: nothing to follow
            continue
        if not os.path.exists(target):
            fails.append(f"FAIL main dangling: {link} -> {target}")
        elif not _under(target, roots):
            fails.append(f"FAIL main points outside the checkout: {link} -> {target}")
    return fails


def _load_fail(node: str, app_dir: str, pkg: str) -> Optional[str]:
    """The FAIL line when Node cannot resolve `pkg` from `app_dir`; None when it can."""
    try:
        proc = subprocess.run(
            [node, "-e", RESOLVE_SCRIPT, pkg],
            cwd=app_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=NODE_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return f"FAIL {app_dir} cannot load {pkg} (node timed out after {NODE_TIMEOUT_S}s)"
    except OSError as e:
        return f"FAIL {app_dir} cannot load {pkg} (node could not start: {e})"
    return None if proc.returncode == 0 else f"FAIL {app_dir} cannot load {pkg}"


def check_worktree(
    repo: Path, worktree: Path, resolve: Mapping[str, Sequence[str]] | None = None
) -> List[str]:
    """
    `FAIL ...` lines for one worktree: node_modules junctions that dangle or do not point into
    the main checkout, and packages in `resolve` (app folder -> package names) Node cannot load.
    `resolve=None` checks the junctions only.
    """
    wt = os.path.normpath(os.path.abspath(worktree))
    if not os.path.isdir(wt):
        return [f"FAIL worktree missing: {wt}"]
    roots = _repo_roots(repo)
    fails: List[str] = []
    for nm in _module_dirs(Path(wt)):
        if not _is_link(nm):
            continue
        target = _link_target(nm)
        if target is None:
            continue
        if not os.path.exists(target):
            fails.append(f"FAIL worktree junction dangling: {nm} -> {target}")
        elif not _under(target, roots):
            fails.append(f"FAIL worktree junction not into the main checkout: {nm} -> {target}")

    if not resolve:
        return fails
    node = shutil.which("node")
    if node is None:
        fails.append(f"FAIL node is not on PATH: cannot check that packages load in {wt}")
        return fails
    for app, pkgs in resolve.items():
        app_dir = os.path.join(wt, app)
        if not os.path.isdir(app_dir):
            fails.append(f"FAIL {wt} has no {app} folder")
            continue
        fails.extend(line for pkg in pkgs if (line := _load_fail(node, app_dir, pkg)))
    return fails


def main_checkout_of(worktree: Path) -> Path | None:
    """The main checkout a worktree belongs to (the parent of its common git dir); None on error."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(worktree), "rev-parse", "--path-format=absolute", "--git-common-dir"],
            env={key: value for key, value in os.environ.items() if key not in REPO_ENV_VARS},
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=GIT_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    common = proc.stdout.strip()
    if proc.returncode != 0 or not common:
        return None
    return Path(common).parent
