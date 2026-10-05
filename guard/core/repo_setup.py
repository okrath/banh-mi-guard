"""
Zero-touch setup and refresh of the files guard writes outside its own package.

Rule: guard never creates a diff in a user's repository. Inside a repository it writes only
where Git does not track anything (the .git directory and the Git-excluded .guard/ folder).
Repository files (agent docs, hooks kept in the tree such as .husky/, guard.invariants.json)
are only read; when they need a change, the setup check tells the user what to do.

- Setup happens lazily: the first time guard runs inside a Git repository it creates the local
  .guard/invariants.json and, when Git runs hooks from inside .git, makes that hook call guard.
- Refresh happens when the installed guard version changes (e.g. after `guard update self`):
  global hooks, guard hooks inside .git of recorded repositories, and the marked directive
  block in the user's global agent docs (home directory) are rewritten.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from guard import __version__

DIRECTIVE_START = "<!-- === BANH-MI-GUARD DUAL-GATE HOOK: START === -->"
DIRECTIVE_END = "<!-- === BANH-MI-GUARD DUAL-GATE HOOK: END === -->"
HOOK_BLOCK_START = "# >>> BANH-MI-GUARD >>>"
HOOK_BLOCK_END = "# <<< BANH-MI-GUARD <<<"
# One line a user can add to a hook kept in their repository (guard never edits it).
# Skips when guard is not installed, so it never blocks a commit on a machine without guard.
MANUAL_HOOK_LINE = "if command -v guard >/dev/null 2>&1; then guard post --hook || exit 1; fi  # BANH-MI-GUARD"
HOOK_BLOCK = f"""{HOOK_BLOCK_START}
# Added by guard: this repository sets its own core.hooksPath, so the global guard hook does not run here.
if command -v guard >/dev/null 2>&1; then
  guard post --hook || exit 1
fi
{HOOK_BLOCK_END}
"""
# What guard <= 0.10 (laya-ocr-guard) wrote: recognised wherever a guard file is, so an upgrade
# cleans it up instead of treating it as the user's own
LEGACY_MARKER = "LAYA-OCR-GUARD"
LEGACY_COMMENT = "Laya-OCR-Guard"
LEGACY_DIRECTIVE_START = DIRECTIVE_START.replace("BANH-MI-GUARD", LEGACY_MARKER)
LEGACY_DIRECTIVE_END = DIRECTIVE_END.replace("BANH-MI-GUARD", LEGACY_MARKER)
LEGACY_HOOK_BLOCK_START = HOOK_BLOCK_START.replace("BANH-MI-GUARD", LEGACY_MARKER)
LEGACY_HOOK_BLOCK_END = HOOK_BLOCK_END.replace("BANH-MI-GUARD", LEGACY_MARKER)
LEGACY_MANUAL_HOOK_LINE = MANUAL_HOOK_LINE.replace("BANH-MI-GUARD", LEGACY_MARKER)
# The first lines of the files guard 0.1.0 generated whole (hooks, the agent wrapper)
LEGACY_WHOLE_FILES = ("# --- LAYA-OCR-GUARD AUTO-GENERATED HOOK ---", "# --- LAYA-OCR-GUARD COMMIT MSG HOOK ---",
                      "# --- LAYA-OCR-GUARD AGENT HARNESS ---")
GUARD_MARKERS = ("BANH-MI-GUARD", LEGACY_MARKER, LEGACY_COMMENT)


def mentions_guard(text: str) -> bool:
    """A file guard wrote or refers to, by any guard version."""
    return any(m in text for m in GUARD_MARKERS)


def is_legacy_whole_file(text: str) -> bool:
    """A file guard <= 0.10 generated whole: its marker is in the first two lines (shebang, marker)."""
    return any(line.strip() in LEGACY_WHOLE_FILES for line in text.splitlines()[:2])


def has_legacy(text: str) -> bool:
    """Text guard <= 0.10 wrote: a whole file, its hook block, its manual line or its directive markers
    (a plain mention is not enough: the current global hooks name the old marker to skip it)."""
    return is_legacy_whole_file(text) or any(m in text for m in (
        LEGACY_HOOK_BLOCK_START, LEGACY_MANUAL_HOOK_LINE, LEGACY_DIRECTIVE_START))


def strip_legacy_parts(text: str) -> str:
    """A user's hook without the guard block and manual line guard <= 0.10 put into it."""
    text = re.sub(re.escape(LEGACY_HOOK_BLOCK_START) + r".*?" + re.escape(LEGACY_HOOK_BLOCK_END) + r"\n?",
                  "", text, flags=re.DOTALL)
    return "".join(line for line in text.splitlines(keepends=True) if line.strip() != LEGACY_MANUAL_HOOK_LINE)


def replace_legacy_parts(text: str) -> str:
    """The guard block and the manual line of guard <= 0.10 inside a user's hook, in their current form."""
    text = re.sub(re.escape(LEGACY_HOOK_BLOCK_START) + r".*?" + re.escape(LEGACY_HOOK_BLOCK_END) + r"\n?",
                  lambda _m: HOOK_BLOCK, text, flags=re.DOTALL)
    return text.replace(LEGACY_MANUAL_HOOK_LINE, MANUAL_HOOK_LINE)


AGENT_DOC_NAMES = ("CLAUDE.md", "AGENT.md", "AGENTS.md", "GEMINI.md")
GLOBAL_AGENT_DOCS = (
    Path(".claude") / "CLAUDE.md",
    Path(".codex") / "AGENTS.md",
    Path(".gemini") / "GEMINI.md",
    Path(".config") / "opencode" / "AGENTS.md",
)


def guard_home() -> Path:
    """~/.guard, overridable with GUARD_HOME (tests, portable installs)."""
    return Path(os.environ.get("GUARD_HOME") or (Path.home() / ".guard"))


def _registry_file() -> Path:
    return guard_home() / "repos.json"


def _state_file() -> Path:
    return guard_home() / "state.json"


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _git(repo: Path, *args: str) -> Optional[str]:
    try:
        res = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", check=False)
    except OSError:
        return None
    return res.stdout.strip() if res.returncode == 0 else None


def git_root(path: Path) -> Optional[Path]:
    top = _git(path, "rev-parse", "--show-toplevel")
    return Path(top).resolve() if top else None


def _same(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except OSError:
        return False


def effective_hooks_dir(repo: Path) -> Optional[Path]:
    """The directory Git actually runs hooks from (respects local and global core.hooksPath)."""
    rel = _git(repo, "rev-parse", "--git-path", "hooks")
    if not rel:
        return None
    p = Path(rel)
    return (p if p.is_absolute() else repo / p).resolve()


def _write_exec(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    try:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass


def _inside_git_dir(path: Path, repo: Path) -> bool:
    """True when `path` lies in the repository's Git directory (nothing there is ever committed)."""
    common = _git(repo, "rev-parse", "--git-common-dir")
    if not common:
        return False
    git_dir = Path(common)
    git_dir = (git_dir if git_dir.is_absolute() else repo / git_dir).resolve()
    try:
        path.resolve().relative_to(git_dir)
        return True
    except ValueError:
        return False


def _ensure_hook_block(hook: Path) -> Optional[str]:
    """Make `hook` run guard. Returns a message when the file changed."""
    from guard.hooks.templates import GIT_PRE_COMMIT_HOOK

    if not hook.exists():
        _write_exec(hook, GIT_PRE_COMMIT_HOOK)
        return f"created guard pre-commit hook {hook}"
    original = text = hook.read_text(encoding="utf-8", errors="ignore")
    if is_legacy_whole_file(text):
        copy = _backup_legacy(hook, text)
        _write_exec(hook, GIT_PRE_COMMIT_HOOK)
        return f"replaced the old laya-ocr-guard hook {hook} (copy in {copy})"
    if LEGACY_MARKER in text:
        text = replace_legacy_parts(text)  # guard <= 0.10's own block or line, in its current form
    if HOOK_BLOCK_START in text and HOOK_BLOCK_END in text:
        new = re.sub(re.escape(HOOK_BLOCK_START) + r".*?" + re.escape(HOOK_BLOCK_END) + r"\n?",
                     lambda _m: HOOK_BLOCK, text, flags=re.DOTALL)
    elif "BANH-MI-GUARD AUTO-GENERATED HOOK" in text:
        new = GIT_PRE_COMMIT_HOOK  # a whole file guard generated earlier
    elif "BANH-MI-GUARD" in text:
        if text == original:
            return None  # guard is referenced in some other form; leave the author's file alone
        new = text  # only guard's own old manual line changed
    else:
        # Insert right after the shebang so a trailing `exit 0` in the existing hook cannot skip it
        lines = text.splitlines(keepends=True)
        at = 1 if lines and lines[0].startswith("#!") else 0
        new = "".join(lines[:at]) + HOOK_BLOCK + "".join(lines[at:])
    if new == original:
        return None
    _write_exec(hook, new)
    return f"updated guard block in {hook}"


def legacy_backup_path(path: Path) -> Path:
    """`<name>.laya.bak`, or `<name>.laya.2.bak`, ... when it is taken: a copy is never overwritten."""
    backup, n = path.with_name(f"{path.name}.laya.bak"), 2
    while backup.exists():
        backup, n = path.with_name(f"{path.name}.laya.{n}.bak"), n + 1
    return backup


def _backup_legacy(path: Path, text: str) -> str:
    """Never chained by the hooks: only a copy for the user, made before the file is replaced or removed.
    Returns the copy's file name."""
    backup = legacy_backup_path(path)
    backup.write_text(text, encoding="utf-8", newline="\n")
    return backup.name


def legacy_directive_to_current(text: str) -> str:
    """A guard <= 0.10 directive block, both markers present, with the current markers."""
    if LEGACY_DIRECTIVE_START in text and LEGACY_DIRECTIVE_END in text.split(LEGACY_DIRECTIVE_START, 1)[1]:
        return text.replace(LEGACY_DIRECTIVE_START, DIRECTIVE_START, 1).replace(LEGACY_DIRECTIVE_END, DIRECTIVE_END, 1)
    return text


def strip_guard_parts(text: str) -> str:
    """A user's hook without every guard block and manual line in it, current or from guard <= 0.10."""
    text = re.sub(re.escape(HOOK_BLOCK_START) + r".*?" + re.escape(HOOK_BLOCK_END) + r"\n?", "", strip_legacy_parts(text),
                  flags=re.DOTALL)
    return "".join(line for line in text.splitlines(keepends=True) if line.strip() != MANUAL_HOOK_LINE)


def clean_legacy(repo: Path) -> List[str]:
    """
    What guard <= 0.10 left in this repository's Git directory and in .guard/: its whole-file hooks
    (removed when the global hooks serve the repository, replaced otherwise, a .laya.bak copy kept),
    its block in the user's own hook, the 0.1.0 agent wrapper, and its info/exclude comment.
    """
    from guard.hooks.templates import GIT_PRE_COMMIT_HOOK, GIT_PREPARE_COMMIT_MSG_HOOK
    messages: List[str] = []
    common = _git(repo, "rev-parse", "--git-common-dir")
    local = ((Path(common) if Path(common).is_absolute() else repo / common) / "hooks") if common else None
    served_globally = _same(effective_hooks_dir(repo) or Path(), guard_home() / "hooks")
    for name, template in (("pre-commit", GIT_PRE_COMMIT_HOOK), ("prepare-commit-msg", GIT_PREPARE_COMMIT_MSG_HOOK)):
        hook = local / name if local else None
        if hook is None or not hook.is_file():
            continue
        text = hook.read_text(encoding="utf-8", errors="ignore")
        if is_legacy_whole_file(text):
            copy = _backup_legacy(hook, text)
            if served_globally:
                hook.unlink()
                messages.append(f"removed the old laya-ocr-guard hook {hook} (copy in {copy})")
            else:
                _write_exec(hook, template)
                messages.append(f"replaced the old laya-ocr-guard hook {hook} (copy in {copy})")
        elif served_globally and strip_legacy_parts(text) != text:
            # the global hook runs guard itself and chains this hook: guard's old lines go, and no current
            # guard block is added (a guard marker would make the global hook skip the user's commands)
            _write_exec(hook, strip_legacy_parts(text))
            messages.append(f"removed the old laya-ocr-guard lines from {hook}")
        elif LEGACY_MARKER in text and replace_legacy_parts(text) != text:
            _write_exec(hook, replace_legacy_parts(text))
            messages.append(f"updated the old laya-ocr-guard block in {hook}")
    for name in ("pre-commit", "prepare-commit-msg"):
        # the global hooks run <hook>.guard.bak: an old installer may have parked guard <= 0.10's hook there
        chained = local / f"{name}.guard.bak" if local else None
        if chained is None or not chained.is_file():
            continue
        text = chained.read_text(encoding="utf-8", errors="ignore")
        assert local is not None
        if is_legacy_whole_file(text):
            copy = _backup_legacy(local / name, text)
            chained.unlink()
            messages.append(f"removed the old laya-ocr-guard hook {chained} (copy in {copy})")
        elif strip_legacy_parts(text) != text:
            _write_exec(chained, strip_legacy_parts(text))
            messages.append(f"removed the old laya-ocr-guard lines from {chained}")
    wrapper = repo / ".guard" / "bin" / "guard-exec"
    if wrapper.is_file() and LEGACY_MARKER in wrapper.read_text(encoding="utf-8", errors="ignore"):
        wrapper.unlink()
        messages.append(f"removed the old laya-ocr-guard agent wrapper {wrapper}")
    from guard.core.git_exclude import reword_excluded_comments
    if reword_excluded_comments(repo, LEGACY_COMMENT, "Banh-Mi-Guard"):
        messages.append(f"reworded the old laya-ocr-guard comment in {repo}'s info/exclude")
    return messages


def refresh_directive_block(doc: Path) -> Optional[str]:
    """Replace the guard directive block between its markers. Never adds a block."""
    from guard.hooks.templates import AGENT_DIRECTIVES_TEMPLATE

    if not doc.is_file():
        return None
    text = doc.read_text(encoding="utf-8", errors="ignore")
    text = legacy_directive_to_current(text)  # a guard <= 0.10 block is refreshed like a current one
    if DIRECTIVE_START not in text or DIRECTIVE_END not in text:
        if mentions_guard(text):
            return (
                f"WARN {doc}: guard directives without START/END markers were not refreshed. Wrap the guard "
                f"section in `{DIRECTIVE_START}` ... `{DIRECTIVE_END}` (guard then keeps it current), or delete "
                f"it and run `guard hook install --mode agent`."
            )
        return None
    block = f"{DIRECTIVE_START}\n{AGENT_DIRECTIVES_TEMPLATE.strip()}\n{DIRECTIVE_END}"
    new = re.sub(re.escape(DIRECTIVE_START) + r".*?" + re.escape(DIRECTIVE_END),
                 lambda _m: block, text, count=1, flags=re.DOTALL)
    if new == doc.read_text(encoding="utf-8", errors="ignore"):
        return None
    doc.write_text(new, encoding="utf-8", newline="\n")
    return f"refreshed guard directives in {doc}"


def refresh_repo(repo: Path) -> List[str]:
    """
    Make the hook Git runs for this repository call guard, but only when that hook lives inside
    .git (untracked). Hooks kept in the repository tree and agent docs are never edited; the
    setup check reports them instead.
    """
    messages: List[str] = clean_legacy(repo)
    hooks = effective_hooks_dir(repo)
    if hooks and not _same(hooks, guard_home() / "hooks") and _inside_git_dir(hooks, repo):
        msg = _ensure_hook_block(hooks / "pre-commit")
        if msg:
            messages.append(msg)
    return messages


def ensure_repo_setup(start: Path, create_invariants: bool = True) -> List[str]:
    """
    First run in a repository: create guard.invariants.json and make sure the hook Git really
    runs calls guard. Later runs only refresh when the guard version changed.
    """
    repo = git_root(start)
    if repo is None:
        return []  # not a Git repository: only the agent directives apply
    registry: Dict[str, Dict[str, str]] = _read_json(_registry_file(), {})
    key = str(repo)
    known = registry.get(key)
    messages: List[str] = []

    if known is None:
        if create_invariants:
            from guard.core.project_invariants import init_invariants_file
            path, created, imported = init_invariants_file(repo)
            if created:
                messages.append(f"created local {path.relative_to(repo).as_posix()} ({imported} invariant(s) imported "
                                "from agent docs); it is Git-excluded and never part of the repository")
        # Hook inside .git only; also refreshes a guard hook written by an older version
        messages.extend(refresh_repo(repo))
    elif known.get("version") != __version__:
        messages.extend(refresh_repo(repo))

    if known is None or known.get("version") != __version__:
        registry[key] = {"version": __version__}
        _write_json(_registry_file(), registry)
    return messages


def refresh_after_upgrade(force: bool = False) -> List[str]:
    """
    Once per installed version: rewrite global hooks (only if Git's global hooksPath points at
    guard's hooks directory), refresh global agent docs and every registered repository.
    """
    state = _read_json(_state_file(), {})
    if not force and state.get("refreshed_version") == __version__:
        return []
    messages: List[str] = []
    global_dir = guard_home() / "hooks"
    configured = None
    try:
        res = subprocess.run(["git", "config", "--global", "--get", "core.hooksPath"], capture_output=True,
                             text=True, encoding="utf-8", errors="replace", check=False)
        configured = res.stdout.strip() or None
    except OSError:
        pass
    if configured and _same(Path(os.path.expanduser(configured)), global_dir):
        from guard.hooks.templates import GIT_PRE_COMMIT_HOOK, GIT_PREPARE_COMMIT_MSG_HOOK
        for name, content in (("pre-commit", GIT_PRE_COMMIT_HOOK), ("prepare-commit-msg", GIT_PREPARE_COMMIT_MSG_HOOK)):
            hook = global_dir / name
            if not hook.exists() or hook.read_text(encoding="utf-8", errors="ignore") != content:
                _write_exec(hook, content)
                messages.append(f"refreshed global hook {hook}")

    for rel in GLOBAL_AGENT_DOCS:
        msg = refresh_directive_block(Path.home() / rel)
        if msg:
            messages.append(msg)

    registry: Dict[str, Dict[str, str]] = _read_json(_registry_file(), {})
    for key in list(registry):
        repo = Path(key)
        if not (repo / ".git").exists():
            continue
        messages.extend(refresh_repo(repo))
        registry[key] = {"version": __version__}
    if registry:
        _write_json(_registry_file(), registry)

    state["refreshed_version"] = __version__
    _write_json(_state_file(), state)
    return messages


# ---------------------------------------------------------------------------
# Install modes: global (whole machine) or workspace (one folder)
# ---------------------------------------------------------------------------

def _directive_block() -> str:
    from guard.hooks.templates import AGENT_DIRECTIVES_TEMPLATE
    return f"{DIRECTIVE_START}\n{AGENT_DIRECTIVES_TEMPLATE.strip()}\n{DIRECTIVE_END}"


def add_directive_block(doc: Path) -> str:
    """Append the marked guard block (or refresh it). Backs up the original file once."""
    if doc.is_file():
        text = doc.read_text(encoding="utf-8", errors="ignore")
        if DIRECTIVE_START in text and DIRECTIVE_END in text:
            return refresh_directive_block(doc) or f"guard directives already current in {doc}"
        if mentions_guard(text):
            return refresh_directive_block(doc) or f"WARN {doc}: unmarked guard directives"
        backup = doc.with_name(f"{doc.name}.guard.bak")
        if not backup.exists():
            backup.write_text(text, encoding="utf-8", newline="\n")
        new = text.rstrip() + "\n\n" + _directive_block() + "\n"
    else:
        doc.parent.mkdir(parents=True, exist_ok=True)
        new = _directive_block() + "\n"
    doc.write_text(new, encoding="utf-8", newline="\n")
    return f"added guard directives to {doc}"


def remove_directive_block(doc: Path) -> Optional[str]:
    """Remove the marked guard block; delete the file when nothing else is left in it."""
    if not doc.is_file():
        return None
    text = doc.read_text(encoding="utf-8", errors="ignore")
    text = legacy_directive_to_current(text)
    if DIRECTIVE_START not in text or DIRECTIVE_END not in text:
        return None
    new = re.sub(r"\n*" + re.escape(DIRECTIVE_START) + r".*?" + re.escape(DIRECTIVE_END) + r"\n?",
                 "\n", text, count=1, flags=re.DOTALL).strip()
    if new:
        doc.write_text(new + "\n", encoding="utf-8", newline="\n")
        return f"removed guard directives from {doc}"
    doc.unlink()
    return f"deleted {doc} (it only contained guard directives)"


def global_agent_docs() -> List[Path]:
    """Global instruction files of the agents whose config directory exists on this machine."""
    docs = []
    for rel in GLOBAL_AGENT_DOCS:
        doc = Path.home() / rel
        if doc.parent.is_dir():
            docs.append(doc)
    return docs


def install_global(cwd: Path) -> Tuple[bool, List[str]]:
    from guard.hooks.installer import HookInstaller

    ok, messages = HookInstaller.install_global_git_hooks()
    docs = global_agent_docs()
    for doc in docs:
        messages.append(add_directive_block(doc))
    if not docs:
        messages.append("WARN no agent config directory found (~/.claude, ~/.codex, ~/.gemini, ~/.config/opencode); "
                        "use `guard install --workspace <dir>` so agents see the guard directives")
    from guard.agent.adapter import protection
    for adapter in _detected_adapters(installed_too=False):
        # Offered, not done: the agent's own config changes only after the user saw the diff
        messages.append(f"WARN {adapter['title']} found: `guard agent add {adapter['name']}` makes it call guard through "
                        f"its hooks ({protection(adapter)})")
    messages.extend(ensure_repo_setup(cwd))
    return ok, messages


def _detected_adapters(installed_too: bool = True) -> List[dict]:
    """
    Adapters whose agent is on this machine: the built-in ones found here and every one the user
    registered (`guard agent add <other agent>`); without `installed_too`, only those not set up yet.
    """
    from guard.agent.adapter import BUILT_IN, adapters_dir, installed, load_adapter
    registered = sorted(p.stem for p in adapters_dir().glob("*.json") if "." not in p.stem) \
        if adapters_dir().is_dir() else []
    found = []
    for name in list(BUILT_IN) + [n for n in registered if n not in BUILT_IN]:
        adapter = load_adapter(name)
        if not isinstance(adapter, dict) or not isinstance(adapter.get("hooks"), list):
            continue  # a broken record: `guard agent list` shows it
        if name not in BUILT_IN:
            from guard.agent.adapter_validation import NOT_JSON, validate_adapter
            if [p for p in validate_adapter(adapter) if p != NOT_JSON]:
                continue  # an invalid record: `guard agent add` refuses it and names the problems
        if _agent_present(adapter) and (installed_too or not installed(adapter)):
            found.append(adapter)
    return found


def _agent_present(adapter: dict) -> bool:
    """The agent is on this machine: its detect folder exists, else its config file does (a shared folder proves nothing)."""
    from guard.agent.adapter import user_path
    if adapter.get("detect"):
        return Path(user_path(str(adapter["detect"]))).is_dir()
    target = Path(user_path(str(adapter.get("config") or adapter.get("install") or "")))
    return target.is_absolute() and target.is_file()


def uninstall_global() -> List[str]:
    from guard.hooks.installer import HookInstaller

    messages: List[str] = []
    configured = None
    try:
        res = subprocess.run(["git", "config", "--global", "--get", "core.hooksPath"], capture_output=True,
                             text=True, encoding="utf-8", errors="replace", check=False)
        configured = res.stdout.strip() or None
    except OSError:
        pass
    if configured and _same(Path(os.path.expanduser(configured)), guard_home() / "hooks"):
        messages.extend(HookInstaller.uninstall_global_git_hooks()[1])
    elif configured:
        messages.append(f"kept global core.hooksPath {configured} (not guard's)")
    for doc in global_agent_docs():
        msg = remove_directive_block(doc)
        if msg:
            messages.append(msg)
    if _registry_file().exists():
        _registry_file().unlink()  # recorded repositories are no longer refreshed
        messages.append("forgot the repositories guard had set up")
    return messages


def _workspace_repos(folder: Path) -> List[Path]:
    from guard.hooks.installer import HookInstaller

    root = git_root(folder)
    if root is not None and _same(root, folder):
        return [folder]
    return HookInstaller(folder).find_child_git_repos()


def install_workspace(folder: Path) -> Tuple[bool, List[str]]:
    """Guard only inside `folder`: directives in its agent docs, hooks in every Git repo below it."""
    from guard.hooks.installer import HookInstaller

    folder = folder.resolve()
    names = ["CLAUDE.md", "AGENT.md"] + (["AGENTS.md"] if (folder / "AGENTS.md").is_file() else [])
    messages = [_add_workspace_doc(folder, folder / name) for name in names]
    repos = _workspace_repos(folder)
    for repo in repos:
        ok, msgs = HookInstaller(repo).install(mode="git")
        messages.extend(f"{repo.name}: {m}" for m in msgs)
        messages.extend(f"{repo.name}: {m}" for m in ensure_repo_setup(repo))
    if not repos:
        messages.append("no Git repository in this workspace: only the agent directives apply")
    return True, messages


def _is_tracked(path: Path) -> bool:
    res = _git(path.parent, "ls-files", "--error-unmatch", path.name)
    return res is not None


def _add_workspace_doc(folder: Path, doc: Path) -> str:
    """
    Add the directive block to a workspace doc without creating a repository diff: a doc that
    Git tracks is left alone, and a doc guard creates inside a repository is Git-excluded.
    """
    root = git_root(folder)
    if root is None:
        return add_directive_block(doc)
    if doc.exists() and _is_tracked(doc):
        return (f"WARN skipped {doc}: it is part of the repository and guard does not edit repository files. "
                "Add the guard directives yourself, or use `guard install` (global agent docs)")
    created = not doc.exists()
    msg = add_directive_block(doc)
    if created:
        _exclude_path(root, doc)
    return msg


def _exclude_path(repo: Path, path: Path) -> None:
    """Add `path` to the repository's info/exclude (works in linked worktrees too)."""
    from guard.core.git_exclude import ensure_excluded
    ensure_excluded(repo, "/" + path.resolve().relative_to(repo.resolve()).as_posix())


def uninstall_workspace(folder: Path) -> List[str]:
    from guard.hooks.installer import HookInstaller

    folder = folder.resolve()
    messages = [m for m in (remove_directive_block(folder / n) for n in ("CLAUDE.md", "AGENT.md", "AGENTS.md")) if m]
    for repo in _workspace_repos(folder):
        _, msgs = HookInstaller(repo).uninstall(mode="git")
        messages.extend(f"{repo.name}: {m}" for m in msgs)
        _forget_repo(repo)  # so a later refresh does not reinstall the hook
    return messages


def _forget_repo(repo: Path) -> None:
    registry = _read_json(_registry_file(), {})
    if registry.pop(str(repo.resolve()), None) is not None:
        _write_json(_registry_file(), registry)


# ---------------------------------------------------------------------------
# Setup health: what is missing and the command that fixes it
# ---------------------------------------------------------------------------


def needs_refresh() -> bool:
    return _read_json(_state_file(), {}).get("refreshed_version") != __version__
