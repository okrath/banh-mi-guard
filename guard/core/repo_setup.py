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
import shutil
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
    text = hook.read_text(encoding="utf-8", errors="ignore")
    if HOOK_BLOCK_START in text and HOOK_BLOCK_END in text:
        new = re.sub(re.escape(HOOK_BLOCK_START) + r".*?" + re.escape(HOOK_BLOCK_END) + r"\n?",
                     lambda _m: HOOK_BLOCK, text, flags=re.DOTALL)
    elif "BANH-MI-GUARD AUTO-GENERATED HOOK" in text:
        new = GIT_PRE_COMMIT_HOOK  # a whole file guard generated earlier
    elif "BANH-MI-GUARD" in text:
        return None  # guard is referenced in some other form; leave the author's file alone
    else:
        # Insert right after the shebang so a trailing `exit 0` in the existing hook cannot skip it
        lines = text.splitlines(keepends=True)
        at = 1 if lines and lines[0].startswith("#!") else 0
        new = "".join(lines[:at]) + HOOK_BLOCK + "".join(lines[at:])
    if new == text:
        return None
    _write_exec(hook, new)
    return f"updated guard block in {hook}"


def refresh_directive_block(doc: Path) -> Optional[str]:
    """Replace the guard directive block between its markers. Never adds a block."""
    from guard.hooks.templates import AGENT_DIRECTIVES_TEMPLATE

    if not doc.is_file():
        return None
    text = doc.read_text(encoding="utf-8", errors="ignore")
    if DIRECTIVE_START not in text or DIRECTIVE_END not in text:
        if "BANH-MI-GUARD" in text:
            return (
                f"WARN {doc}: guard directives without START/END markers were not refreshed. Wrap the guard "
                f"section in `{DIRECTIVE_START}` ... `{DIRECTIVE_END}` (guard then keeps it current), or delete "
                f"it and run `guard hook install --mode agent`."
            )
        return None
    block = f"{DIRECTIVE_START}\n{AGENT_DIRECTIVES_TEMPLATE.strip()}\n{DIRECTIVE_END}"
    new = re.sub(re.escape(DIRECTIVE_START) + r".*?" + re.escape(DIRECTIVE_END),
                 lambda _m: block, text, count=1, flags=re.DOTALL)
    if new == text:
        return None
    doc.write_text(new, encoding="utf-8", newline="\n")
    return f"refreshed guard directives in {doc}"


def refresh_repo(repo: Path) -> List[str]:
    """
    Make the hook Git runs for this repository call guard, but only when that hook lives inside
    .git (untracked). Hooks kept in the repository tree and agent docs are never edited; the
    setup check reports them instead.
    """
    messages: List[str] = []
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
        if "BANH-MI-GUARD" in text:
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
    messages.extend(ensure_repo_setup(cwd))
    return ok, messages


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
    common = _git(repo, "rev-parse", "--git-common-dir")
    if not common:
        return
    git_dir = Path(common) if Path(common).is_absolute() else repo / common
    exclude = git_dir / "info" / "exclude"
    exclude.parent.mkdir(parents=True, exist_ok=True)
    rel = "/" + path.resolve().relative_to(repo.resolve()).as_posix()
    text = exclude.read_text(encoding="utf-8", errors="ignore") if exclude.exists() else ""
    if rel not in [line.strip() for line in text.splitlines()]:
        exclude.write_text(text.rstrip() + ("\n" if text else "") + rel + "\n", encoding="utf-8")


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

def _global_hooks_active() -> bool:
    try:
        res = subprocess.run(["git", "config", "--global", "--get", "core.hooksPath"], capture_output=True,
                             text=True, encoding="utf-8", errors="replace", check=False)
    except OSError:
        return False
    configured = res.stdout.strip()
    return bool(configured) and _same(Path(os.path.expanduser(configured)), guard_home() / "hooks")


def _hook_calls_guard(hook: Path) -> bool:
    return hook.is_file() and "BANH-MI-GUARD" in hook.read_text(encoding="utf-8", errors="ignore")


def _doc_state(doc: Path) -> str:
    """'marked', 'unmarked' (guard text without markers) or 'none'."""
    if not doc.is_file():
        return "none"
    text = doc.read_text(encoding="utf-8", errors="ignore")
    if DIRECTIVE_START in text and DIRECTIVE_END in text:
        return "marked"
    return "unmarked" if "BANH-MI-GUARD" in text else "none"


def _local_agent_docs(cwd: Path) -> List[Path]:
    """Agent docs in cwd and its parents up to the repository root (or cwd alone outside Git)."""
    stop = git_root(cwd)
    docs, current = [], cwd.resolve()
    while True:
        docs.extend(current / n for n in AGENT_DOC_NAMES)
        if stop is None or _same(current, stop) or current.parent == current:
            break
        current = current.parent
    return docs


def setup_health(cwd: Path) -> List[Dict[str, str]]:
    """
    Check an installation made by any guard version. Each entry: level ('missing' | 'warn' | 'ok'),
    item, detail and the fix command, so users of older setups know exactly what to run.
    """
    out: List[Dict[str, str]] = []

    def add(level: str, item: str, detail: str, fix: str = ""):
        out.append({"level": level, "item": item, "detail": detail, "fix": fix})

    repo = git_root(cwd)
    install_fix = "guard install   (or: guard install --workspace <dir>)"

    # 1. Git hooks
    if _global_hooks_active():
        if (guard_home() / "hooks" / "pre-commit").is_file():
            add("ok", "Git hooks", "global hooks check every repository")
        else:
            add("missing", "Git hooks", "global core.hooksPath points at guard but the hook file is missing", "guard hook refresh")
        if repo:
            eff = effective_hooks_dir(repo)
            if eff and not _same(eff, guard_home() / "hooks") and not _hook_calls_guard(eff / "pre-commit"):
                if _inside_git_dir(eff, repo):
                    add("missing", "Repository hook", f"{repo.name} runs hooks from {eff} and its pre-commit does not call guard",
                        "guard hook refresh   (run inside the repository)")
                else:
                    add("missing", "Repository hook",
                        f"{repo.name} keeps its hooks in the repository ({eff}); guard does not edit repository files",
                        f"add this line to {eff / 'pre-commit'}:  {MANUAL_HOOK_LINE}")
    elif repo:
        eff = effective_hooks_dir(repo)
        if eff and _hook_calls_guard(eff / "pre-commit"):
            add("ok", "Git hooks", f"repository hook in {eff}")
        elif eff and not _inside_git_dir(eff, repo):
            add("missing", "Git hooks", f"{repo.name} keeps its hooks in the repository ({eff}); guard does not edit repository files",
                f"add this line to {eff / 'pre-commit'}:  {MANUAL_HOOK_LINE}")
        else:
            add("missing", "Git hooks", f"commits in {repo.name} are not checked by guard", install_fix)
    else:
        add("missing", "Git hooks", "no global guard hooks are installed", install_fix)

    # 2. Agent directives: an agent must be told to run guard, otherwise nothing starts
    global_docs = global_agent_docs()
    local_docs = _local_agent_docs(cwd)
    states = {d: _doc_state(d) for d in global_docs + local_docs}
    marked = [d for d, s in states.items() if s == "marked"]
    current = _directive_block()
    for d, s in states.items():
        in_home = d in global_docs
        if s == "unmarked":
            add("warn", "Agent directives",
                f"{d} has guard directives without START/END markers" + ("" if in_home else " (repository file: guard does not edit it)"),
                "wrap the guard section in guard's START/END markers (README: 'Upgrading from an older version'), "
                "or delete it and run guard install")
        elif s == "marked" and not in_home and current not in d.read_text(encoding="utf-8", errors="ignore"):
            add("warn", "Agent directives", f"{d} carries an older guard directive block (repository file: guard does not edit it)",
                "update it yourself if the team wants the new rules, or remove it and rely on `guard install` (global)")
    if marked:
        add("ok", "Agent directives", ", ".join(str(d) for d in marked))
    elif not any(s == "unmarked" for s in states.values()):
        add("missing", "Agent directives", "no agent instruction file tells the agent to run guard pre/post", install_fix)

    # 3. Project invariants
    if repo:
        from guard.core.project_invariants import InvariantsFileError, load_project_invariants
        try:
            items = load_project_invariants(repo)
        except InvariantsFileError as e:
            add("missing", "Invariants", str(e), "fix the file, then guard invariants check")
        else:
            if items is None:
                add("warn", "Invariants", f"{repo.name} has no project invariants", "guard invariants init   (local, not committed)")
            elif not items:
                add("warn", "Invariants", "the invariants file is empty; generic domain templates are used",
                    "add project rules, then guard invariants check")
            else:
                unchecked = sum(1 for i in items if not i.get("checks"))
                if unchecked == len(items):
                    add("warn", "Invariants", f"all {len(items)} invariants have no checks (UNVERIFIED)",
                        "add {files, forbid|require} checks, then guard invariants check")
                else:
                    add("ok", "Invariants", f"{len(items) - unchecked}/{len(items)} invariants have automated checks")

    # 4. Alibaba OCR: only `guard post --full` runs it
    from guard.core.config import load_config, load_global_config
    ocr_binary = load_config(repo or cwd).ocr.binary_path  # the config guard post uses here
    if shutil.which(ocr_binary):
        add("ok", "Alibaba OCR", f"{ocr_binary} found; guard post --full adds its review")
    else:
        add("warn", "Alibaba OCR", f"'{ocr_binary}' is not on PATH: guard post works, guard post --full (full review) cannot approve",
            "npm install -g @alibaba-group/open-code-review   then: guard config sync")

    # 5. Commit messages: the user decides who writes them (machine-wide)
    cfg = load_global_config()
    if cfg.commit_mode:
        who = "the agent writes them" if cfg.commit_mode == "auto" else "the agent asks you for each one"
        add("ok", "Commit messages", f"mode `{cfg.commit_mode}`: {who}")
    else:
        add("warn", "Commit messages", "not chosen yet: auto (the agent writes them) or ask (the agent asks you for each one)",
            "guard config commit auto   (or: guard config commit ask)")

    # 6. Files left by guard <= 0.10 (the Laya model is no longer used)
    models = guard_home() / "models"
    if models.is_dir():
        size_mb = sum(f.stat().st_size for f in models.rglob("*") if f.is_file()) / (1024 * 1024)
        if size_mb >= 1:
            add("warn", "Old Laya model", f"{models} ({size_mb:.0f} MB) is no longer used since guard 0.11",
                f"delete the folder to free the space: {models}")
    return out


def needs_refresh() -> bool:
    return _read_json(_state_file(), {}).get("refreshed_version") != __version__
