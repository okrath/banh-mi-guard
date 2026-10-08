"""
The test files related to a change, for `guard config tests related`: only a pytest build is narrowed, and
only when every changed file is Python code guard can map to tests. Anything else returns [] and the full
suite runs. A related run only shortens the rounds that fail: an approval always needs the full suite.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import List

# Files that change how every test runs: any change to them needs the full suite
_WHOLE_SUITE = {"conftest.py", "pyproject.toml", "setup.cfg", "setup.py", "pytest.ini", "tox.ini"}
_SAFE_PATH = re.compile(r"[\w./-]+")  # passed to a shell: anything else falls back to the full suite


def _is_test(path: str) -> bool:
    name = PurePosixPath(path).name
    return name.startswith("test_") and name.endswith(".py") or name.endswith("_test.py")


def _imports(text: str, module: str) -> bool:
    """`import a.b.c`, `from a.b.c import ...` or `from a.b import c`: the test reaches the module."""
    parent, _, leaf = module.rpartition(".")
    pattern = rf"^\s*(?:import\s+{re.escape(module)}\b|from\s+{re.escape(module)}\s+import\b"
    if parent:
        pattern += rf"|from\s+{re.escape(parent)}\s+import\s+[^\n]*\b{re.escape(leaf)}\b"
    return re.search(pattern + ")", text, re.MULTILINE) is not None


def related_tests(repo: Path, changed: List[str]) -> List[str]:
    """
    Repository-relative test files for the changed files: the changed test files that still exist, and the
    tracked test files that import a changed module or are named after it. [] means "run the full suite".
    """
    if not changed or any(not p.endswith(".py") or PurePosixPath(p).name in _WHOLE_SUITE for p in changed):
        return []
    try:
        listed = subprocess.run(["git", "-C", str(repo), "ls-files", "-z", "--", "*.py"], capture_output=True,
                                text=True, encoding="utf-8", errors="replace", check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    tests = [p for p in listed.split("\0") if p and _is_test(p)]
    picked = {p for p in changed if _is_test(p) and (repo / p).is_file()}
    modules = [(PurePosixPath(p).with_suffix("").as_posix().replace("/", "."), PurePosixPath(p).stem)
               for p in changed if not _is_test(p) and PurePosixPath(p).name != "__init__.py"]
    if any(PurePosixPath(p).name == "__init__.py" for p in changed if not _is_test(p)):
        return []  # a package's __init__ is imported through every module of the package
    for test in tests:
        try:
            text = (repo / test).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        if any(stem in PurePosixPath(test).stem or _imports(text, dotted) for dotted, stem in modules):
            picked.add(test)
    selected = sorted(picked)
    return selected if all(_SAFE_PATH.fullmatch(p) for p in selected) else []
