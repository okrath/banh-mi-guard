"""
The setup-health table `guard doctor`, `guard setup` and a new version's first run print: what is
installed, what is missing, and the command that fixes each gap.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

from guard.core.repo_setup import (
    AGENT_DOC_NAMES, DIRECTIVE_END, DIRECTIVE_START, GLOBAL_AGENT_DOCS, LEGACY_COMMENT, MANUAL_HOOK_LINE,
    _detected_adapters, _directive_block, _git, _inside_git_dir, _same, effective_hooks_dir, git_root, global_agent_docs,
    guard_home, has_legacy,
)


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

    # 2b. Agent hooks: the directives ask; the hooks enforce
    from guard.agent.adapter import installed, protection, test_record_path
    for adapter in _detected_adapters():
        name = adapter["name"]
        by_hand = adapter.get("kind") != "extension" and not str(adapter.get("config", "")).endswith(".json")
        if by_hand or not installed(adapter):
            if by_hand:  # guard printed the entries to add; only a test shows they are there
                try:
                    tested = json.loads(test_record_path(name).read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    tested = None
                from guard.agent.adapter import config_fingerprint, config_path
                refuses = "before-edit" in (adapter.get("can_block") or [])
                now = config_fingerprint(config_path(adapter))  # None: unreadable now, so nothing to compare with
                same_file = isinstance(tested, dict) and now is not None and tested.get("config") == now
                unknown = isinstance(tested, dict) and (now is None or not tested.get("config"))
                if isinstance(tested, dict) and tested.get("events") and unknown:
                    add("warn", "Agent hooks", f"{adapter['title']}: hooks added by hand; guard cannot tell whether its "
                        f"config is the one the last test ({str(tested.get('at'))[:10]}) saw", f"guard agent test {name}")
                elif isinstance(tested, dict) and tested.get("events") and not same_file:
                    add("warn", "Agent hooks", f"{adapter['title']}: hooks added by hand; its config changed since the "
                        f"last test ({str(tested.get('at'))[:10]})", f"guard agent test {name}")
                elif isinstance(tested, dict) and tested.get("events") and (tested.get("blocked_edit") or not refuses):
                    # guard cannot read that file to check it now: the last test is the evidence
                    add("ok", "Agent hooks", f"{adapter['title']}: hooks added by hand; the last test "
                        f"({str(tested.get('at'))[:10]}) saw guard's events (run guard agent test {name} after "
                        "changing that file)")
                elif isinstance(tested, dict) and tested.get("events"):
                    add("warn", "Agent hooks", f"{adapter['title']}: hooks added by hand; the last test "
                        f"({str(tested.get('at'))[:10]}) refused no edit", f"guard agent test {name}")
                else:
                    add("warn", "Agent hooks", f"{adapter['title']}: its config is not JSON, so guard's entries are "
                        "added by hand; no test has seen them yet", f"guard agent test {name}")
                continue
            stale = False
            if adapter.get("kind") == "extension":
                from guard.agent.adapter import extension_state
                stale = extension_state(adapter) == "stale"
            add("warn", "Agent hooks", f"{adapter['title']}: guard's file there is not this guard's (guard moved, another "
                "version, or an edit): it may call nothing" if stale else
                f"{adapter['title']}: no hooks, it only reads the directives; nothing stops an edit before guard pre",
                f"guard agent add {name}")
            continue

        if not adapter.get("session_id"):  # its events cannot be told apart by agent session
            add("warn", "Agent sessions", f"{adapter['title']}: no session id, parallel sessions in one working tree "
                "are not separated", "git worktree add ../<folder> -b <branch>   (one worktree per parallel session)")
        try:  # the last `guard agent test`: whether the agent really called guard
            last = json.loads(test_record_path(name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            last = None
        if not isinstance(last, dict):
            last = None  # an edited record (`[]`, a string): as if never tested
        if last is None:
            add("ok", "Agent hooks", f"{adapter['title']}: {protection(adapter)}; not tested yet (guard agent test {name})")
        elif not last.get("events"):
            add("warn", "Agent hooks", f"{adapter['title']}: hooks in place, but the last test ({str(last.get('at'))[:10]}) "
                "saw no event: the agent is not calling guard", f"guard agent fix {name}")
        elif "before-edit" not in (adapter.get("can_block") or []):  # it reports edits after they run
            add("ok", "Agent hooks", f"{adapter['title']}: {protection(adapter)}; last test {str(last.get('at'))[:10]}: "
                "guard's events arrived (this agent cannot refuse an edit, guard reports it right after)")
        elif not last.get("blocked_edit"):  # events arrived, but guard refused no edit during the test
            add("warn", "Agent hooks", f"{adapter['title']}: {protection(adapter)}; the last test "
                f"({str(last.get('at'))[:10]}) refused no edit", f"guard agent test {name}")
        else:
            add("ok", "Agent hooks", f"{adapter['title']}: {protection(adapter)}; last test {str(last.get('at'))[:10]}: "
                "an edit was refused")

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

    # 4. The LLM behind the review gate (and Alibaba OCR, which guard keeps in sync with it)
    from guard.core.config import load_config, load_global_config, ocr_in_sync
    from guard.core.config import LLMProtocol
    llm = load_global_config().llm
    if llm.protocol == LLMProtocol.CLI and not llm.ready:
        add("missing", "LLM", "the review runs through an agent CLI, but none is chosen: guard post falls back to "
            "the heuristic gate", "guard config llm")
    elif llm.protocol == LLMProtocol.CLI:
        from guard.core import cli_llm
        if cli_llm.find(llm.cli_agent):
            add("ok", "LLM", f"the {llm.cli_agent} CLI" + (f" ({llm.model})" if llm.model else "") + " (your subscription; no API key)")
        else:
            add("missing", "LLM", f"the {llm.cli_agent} CLI is chosen but not on PATH: guard post falls back to the "
                "heuristic gate", "guard config llm")
    elif llm.api_key:
        from urllib.parse import urlsplit
        try:
            parts = urlsplit(llm.base_url or "")
            where = f"{parts.scheme}://{parts.hostname or ''}{f':{parts.port}' if parts.port else ''}{parts.path}" if parts.scheme else "(no URL)"
        except ValueError:  # e.g. a non-numeric port: doctor still shows every row
            where = "(invalid URL: check guard config llm)"
        add("ok", "LLM", f"{llm.model} at {where}")  # no user, password or query from the URL
    else:
        add("missing", "LLM", "no LLM configured: guard post falls back to the heuristic gate", "guard config llm")

    # 4b. Alibaba OCR: only `guard post --full` runs it
    ocr_binary = load_config(repo or cwd).ocr.binary_path  # the config guard post uses here
    always = load_global_config().ocr.always
    # Every row for an installed OCR says when it runs, and how to change that
    when = {None: "runs only with guard post --full; it can run on every post (not chosen yet: guard config ocr always|optional)",
            True: "runs on every guard post (guard config ocr optional: only with --full)",
            False: "runs only with guard post --full (guard config ocr always: on every post)"}[always]
    if shutil.which(ocr_binary) and llm.protocol == LLMProtocol.CLI:
        # guard post --full answers OCR through the same CLI (a local endpoint for that review only)
        add("ok", "Alibaba OCR", f"{ocr_binary} found; it runs through the {llm.cli_agent} CLI, like the review gate; {when}")
    elif shutil.which(ocr_binary) and not llm.api_key:
        add("warn", "Alibaba OCR", f"{ocr_binary} found, not synced: there is no LLM to give it yet; {when}", "guard config llm")
    elif shutil.which(ocr_binary) and not ocr_in_sync(llm, ocr_binary):
        add("warn", "Alibaba OCR", f"{ocr_binary} found, but guard has not given it the current LLM; {when}", "guard config sync")
    elif shutil.which(ocr_binary):
        if always is None:  # installed, never chosen: the user should know it can run on every post
            add("warn", "Alibaba OCR", f"{ocr_binary} found; {when}", "guard config ocr always   (or: guard config ocr optional)")
        else:
            add("ok", "Alibaba OCR", f"{ocr_binary} found; {when}")
    else:
        add("warn", "Alibaba OCR", f"'{ocr_binary}' is not on PATH: guard post works, guard post --full (full review) cannot approve; "
            f"once installed it {when}",
            "npm install -g @alibaba-group/open-code-review   then: guard config sync")

    # 5. Commit messages: the user decides who writes them (machine-wide)
    cfg = load_global_config()
    if cfg.commit_mode:
        who = "the agent writes them" if cfg.commit_mode == "auto" else "the agent asks you for each one"
        add("ok", "Commit messages", f"mode `{cfg.commit_mode}`: {who}")
    else:
        add("warn", "Commit messages", "not chosen yet: auto (the agent writes them) or ask (the agent asks you for each one)",
            "guard config commit auto   (or: guard config commit ask)")

    # 6. Untracked paths the user has not decided about stop guard pre
    if repo:
        from guard.core.untracked import RegistryError, undecided
        try:
            pending = undecided(repo)
        except (RuntimeError, RegistryError) as e:
            pending = []
            from rich.markup import escape
            from guard.core.untracked import printable
            add("warn", "Untracked paths", f"cannot list untracked paths: {escape(printable(str(e)))}",
                "git status   (fix the repository, then guard doctor)")
        if pending:
            from guard.core.untracked import shown as show_path
            shown = ", ".join(show_path(p) for p in pending[:5]) + (" …" if len(pending) > 5 else "")
            add("warn", "Untracked paths", f"{len(pending)} untracked path(s) without a decision: {shown}",
                "guard untracked <path> --include   (or --ignore)")

    # 7. Files left by guard <= 0.10 (the Laya model is no longer used)
    models = guard_home() / "models"
    if models.is_dir():
        size_mb = sum(f.stat().st_size for f in models.rglob("*") if f.is_file()) / (1024 * 1024)
        if size_mb >= 1:
            add("warn", "Old Laya model", f"{models} ({size_mb:.0f} MB) is no longer used since guard 0.11",
                f"delete the folder to free the space: {models}")
    for detail, fix in legacy_items(cwd):
        add("warn", "Old laya-ocr-guard files", detail, fix)
    return out


def _legacy_text(path: Path) -> bool:
    try:
        return path.is_file() and has_legacy(path.read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        return False


def legacy_items(cwd: Path) -> List[Tuple[str, str]]:
    """
    What guard <= 0.10 (laya-ocr-guard) left that still runs or still carries its name, with the fix:
    `guard hook refresh` for what guard may clean, the change to make for a repository file.
    """
    items: List[Tuple[str, str]] = []
    refresh = "guard hook refresh"
    repo = git_root(cwd)
    if repo is not None:
        common = _git(repo, "rev-parse", "--git-common-dir")
        local = ((Path(common) if Path(common).is_absolute() else repo / common) / "hooks") if common else None
        hooks = effective_hooks_dir(repo)
        for name in ("pre-commit", "prepare-commit-msg"):
            if local and _legacy_text(local / name):
                items.append((f"{local / name} was written by guard <= 0.10", refresh))
            if local and _legacy_text(local / f"{name}.guard.bak"):  # chained by the global hooks
                items.append((f"{local / (name + '.guard.bak')} holds guard <= 0.10 lines", refresh))
            tracked = hooks / name if hooks and not _inside_git_dir(hooks, repo) and not _same(hooks, guard_home() / "hooks") else None
            if tracked and _legacy_text(tracked):  # a repository file: guard never edits it
                items.append((f"{tracked} (repository file) still calls guard the old way",
                              f"replace its LAYA-OCR-GUARD lines with: {MANUAL_HOOK_LINE}"))
        if _legacy_text(repo / ".guard" / "bin" / "guard-exec"):
            items.append((f"{repo / '.guard' / 'bin' / 'guard-exec'} is the 0.1.0 agent wrapper", refresh))
        from guard.core.git_exclude import exclude_file
        exclude = exclude_file(repo)
        if exclude and exclude.is_file() and LEGACY_COMMENT in exclude.read_text(encoding="utf-8", errors="ignore"):
            items.append((f"{exclude} has the old Laya-OCR-Guard comment", refresh))
    for doc in (Path.home() / rel for rel in GLOBAL_AGENT_DOCS):
        if _legacy_text(doc):
            items.append((f"{doc} has the old LAYA-OCR-GUARD directive block", refresh))
    for doc in _local_agent_docs(cwd):
        if _legacy_text(doc):  # a repository file: guard never edits it
            items.append((f"old guard directive in {doc}",
                          "replace the LAYA-OCR-GUARD section with `guard hook install --mode agent`"))
    try:
        from importlib.metadata import PackageNotFoundError, distribution
        dist = distribution("laya-ocr-guard")
        where = str(getattr(dist, "_path", "") or "")
        tool = "pipx" if "pipx" in where.lower() else "pip"
        items.append(("the old laya-ocr-guard package is still installed (it owns the same `guard` command)",
                      f"{tool} uninstall laya-ocr-guard"))
    except PackageNotFoundError:
        pass
    except Exception:
        pass  # metadata that cannot be read is not a reason to fail the check
    return items
