"""`guard agent` and `guard agent-event`: guard on an agent's own hooks."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import typer
from rich.table import Table

from guard.cli import app, console
from guard.core.config import load_config


# A hook payload is a small JSON object; anything bigger is not read (and the action is allowed, logged)
MAX_EVENT_BYTES = 5_000_000
AGENT_TEST_FLAG = "agent-test.json"  # present while `guard agent test` listens: every event is logged


agent_app = typer.Typer(name="agent", help="🤖 Put guard on an agent's path through its hooks", no_args_is_help=True)
app.add_typer(agent_app, name="agent")


def _adapter_or_exit(name: str) -> dict:
    from guard.agent.adapter import BUILT_IN, load_adapter
    adapter = load_adapter(name)
    if adapter is None:
        console.print(f"[bold red]❌ No adapter named {name!r}.[/bold red] Built in: {', '.join(BUILT_IN)}")
        raise typer.Exit(code=1)
    return adapter


def _unchanged_since_diff(path: Path, shown: dict) -> None:
    """The config is written only as confirmed: if it changed while the diff was on screen, nothing is written."""
    from guard.agent.adapter import AdapterError, read_config
    try:
        now = read_config(path)
    except AdapterError as e:
        now = str(e)
    if now != shown:
        console.print(f"[bold red]❌ {path} changed while you were reading the diff; nothing was written. Run the command again.[/bold red]")
        raise typer.Exit(code=1)


def _forget_switches(name: str, path: Path) -> None:
    """Delete the record of what guard switched on; one left behind would be trusted by a later add, so it is said."""
    from guard.agent.adapter import switched_path
    try:
        switched_path(name).unlink(missing_ok=True)
    except OSError as e:
        console.print(f"[bold red]❌ Guard's hooks are out of {path}, but {switched_path(name)} could not be deleted "
                      f"({e}). Delete it yourself before adding guard again.[/bold red]", highlight=False)
        raise typer.Exit(code=1)


def _file_state(path: Path):
    """A file's bytes, None when there is none (an empty file is not an absent one), False when it cannot be read."""
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        return False


def _file_unchanged(path: Path, shown) -> None:
    """A file is written or deleted only as shown: if it changed while the question was on screen, nothing happens."""
    if _file_state(path) != shown or shown is False:
        console.print(f"[bold red]❌ {path} changed while you were reading; nothing was done. Run the command again.[/bold red]")
        raise typer.Exit(code=1)


def _test_listening() -> bool:
    """`guard agent test` started less than an hour ago (an abandoned test stops logging by itself)."""
    from guard.core.repo_setup import guard_home
    try:
        since = datetime.fromisoformat(json.loads((guard_home() / AGENT_TEST_FLAG).read_text(encoding="utf-8"))["since"])
    except (OSError, ValueError, KeyError, TypeError):
        return False
    return (datetime.now(timezone.utc) - since).total_seconds() < 3600


def _show_diff(text: str) -> None:
    for line in text.splitlines():
        style = "green" if line.startswith("+") and not line.startswith("+++") else (
            "red" if line.startswith("-") and not line.startswith("---") else "dim")
        console.print(line, style=style, markup=False, highlight=False)


def _home_relative(path: Path) -> str:
    """A config file as discovery shows it (`~/…`, `%APPDATA%/…`), never a full path with the user's name."""
    from guard.agent.discover import _shown
    return _shown(path, path.parent, Path.home())


def _cannot_set_up(name: str, problem: str, inv=None) -> None:
    """Tell the user guard could not make this agent work, what they can do, and exit."""
    from guard.agent.discover import issue_url
    console.print(f"[bold yellow]⚠️ Guard could not set up {name}:[/bold yellow] ", end="")
    console.print(problem, markup=False, highlight=False)
    console.print(
        f"What you can do: look in {name}'s documentation for hooks that run a command before an edit or a shell "
        f"command (then [bold]guard agent fix {name} --note \"<what the docs say>\"[/bold]), or ask for support with "
        "this prefilled GitHub issue (read it first; guard sends nothing itself):")
    console.print(issue_url(name, problem, inv), markup=False, highlight=False, soft_wrap=True)
    console.print(f"Until then guard still protects {name} through the agent directive and the Git pre-commit hook.")
    raise typer.Exit(code=1)


def _proposed_adapter(name: str, inv, previous: Optional[dict] = None, log: str = "") -> dict:
    """The LLM's adapter after validation (one retry with the problems named), or exit with what to do next."""
    from guard.agent.adapter_validation import NOT_JSON, validate_adapter
    from guard.agent.discover import propose
    from guard.core.llm_client import LLMClientError
    problems: List[str] = []
    for _ in range(2):
        try:
            proposal = propose(_work_llm(), inv, previous=previous, problems=problems, log=log)
        except (LLMClientError, ValueError) as e:
            console.print(f"[bold red]❌ The LLM gave no usable adapter:[/bold red] {printable_error(e)}", highlight=False)
            console.print("Registering an agent needs a working LLM: check it with [bold]guard config test[/bold] "
                          "(set it up with [bold]guard config llm[/bold]).")
            _cannot_set_up(name, f"the LLM gave no usable adapter ({type(e).__name__})", inv)
        if "no_hooks" in proposal:
            _cannot_set_up(name, f"no hooks guard can use ({str(proposal['no_hooks'])[:300]})", inv)
        proposal["name"] = name  # the adapter is registered under the name the user typed
        problems = [p for p in validate_adapter(proposal) if p != NOT_JSON]
        if not problems:
            return proposal
    _cannot_set_up(name, "the proposed adapter is not safe to install: " + "; ".join(problems), inv)


def _work_llm():
    """The configured LLM without a time limit, as for a review: llm.timeout is only for `guard config test` pings."""
    return load_config(Path.cwd()).llm.model_copy(update={"timeout": None})


def printable_error(e: Exception) -> str:
    return " ".join(str(e).split())[:300]


def _investigate(name: str, need_found: bool = True):
    """
    What this machine says about an agent guard does not know, or exit with what to do next. With
    `need_found` False (fix with a note), an agent nothing points to goes on with the note alone.
    """
    from guard.agent.discover import investigate
    try:
        inv = investigate(name)
    except ValueError as e:
        console.print(f"[bold red]❌ {name!r}: {e}.[/bold red]", highlight=False)
        raise typer.Exit(code=1)
    console.print(f"[cyan]🔎 {name}: binary {inv.binary or 'not on PATH'}; {len(inv.listing)} config file(s) found, "
                  f"{len(inv.files)} read as structure only (no text values).[/cyan]")
    for note in inv.notes:
        console.print(f"[dim]{note}[/dim]", highlight=False)
    if need_found and not inv.found():
        _cannot_set_up(name, "it is not on PATH and has no config folder in your home folder", inv)
    return inv


def _write_text_atomic(path: Path, text: str) -> None:
    import os
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="." + path.name + ".", suffix=".guard-tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _install_extension(adapter: dict, name: str) -> None:
    """omp, pi, opencode: guard writes one file of its own (shown first, confirmed); a file of anyone else's stays."""
    import difflib
    from guard.agent.adapter import (
        AdapterError, adapters_dir, config_path, extension_is_guards, extension_text, save_adapter, _record_name,
    )
    path = config_path(adapter)
    if path.exists() and not extension_is_guards(adapter):
        console.print(f"[bold red]❌ {path} is not guard's file:[/bold red] guard does not replace it. Move it away, then add again.")
        raise typer.Exit(code=1)
    try:
        text = extension_text(adapter)
    except AdapterError as e:
        console.print(f"[bold red]❌ {e}[/bold red]", highlight=False)
        raise typer.Exit(code=1)
    seen = _file_state(path)
    old = seen.decode("utf-8", errors="replace") if isinstance(seen, bytes) else ""
    if old == text:
        save_adapter(adapter)
        console.print(f"[green]✅ {adapter['title']} already loads guard's {path.name} ({path}).[/green]")
        return
    _show_diff("".join(difflib.unified_diff(old.splitlines(keepends=True), text.splitlines(keepends=True), str(path), str(path))))
    if not typer.confirm(f"Write guard's {path.name} to {path}?", default=False):
        console.print("[dim]Nothing changed.[/dim]")
        raise typer.Exit(code=1)
    _file_unchanged(path, seen)  # before anything is saved: never replaces a file put there meanwhile
    record = adapters_dir() / f"{_record_name(name)}.json"
    kept = record.read_bytes() if record.is_file() else None
    save_adapter(adapter)  # the record first, as for a config
    try:
        _write_text_atomic(path, text)
    except OSError as e:  # the file is as it was: so is the record
        if kept is None:
            record.unlink(missing_ok=True)
        else:
            record.write_bytes(kept)
        console.print(f"[bold red]❌ {e}[/bold red]", highlight=False)  # the full error, on this screen only
        _cannot_set_up(name, f"writing {_home_relative(path)} failed ({type(e).__name__})")
    events = ", ".join(sorted({h["event"] for h in adapter["hooks"]}))
    console.print(f"[bold green]✅ {adapter['title']} now calls guard on: {events}.[/bold green] Restart it so it loads the file.")
    console.print(f"Check it with [bold]guard agent test {name}[/bold]; undo with [bold]guard agent remove {name}[/bold].")


def _install_adapter(adapter: dict, name: str) -> None:
    """Show the config diff, confirm, back up and write; a config guard cannot edit gets the entries to add by hand."""
    from guard.agent.adapter import (
        AdapterError, adapters_dir, config_path, diff, dump, guard_command, installed, load_adapter, others_under,
        read_config, save_adapter, switched_on, switched_path, with_guard, write_config, _at, _entry, _record_name,
    )
    _registered_ok(adapter, name)  # every install, including one from a record written earlier
    for limit in adapter.get("limits") or []:  # what guard cannot do for this agent, said before anything is written
        console.print("[yellow]⚠️ [/yellow]", end="")
        console.print(limit, markup=False, highlight=False)
    if adapter.get("kind") == "extension":
        _install_extension(adapter, name)
        return
    path = config_path(adapter)
    try:
        before = read_config(path, adapter) if path.suffix == ".json" else {}
        after = with_guard(before, adapter)  # builds guard's entries: refuses a command a shell would misread
    except AdapterError as e:
        console.print(f"[bold red]❌ {e}[/bold red]", highlight=False)  # the full error, on this screen only
        _cannot_set_up(name, f"{_home_relative(path)} could not be read or filled ({type(e).__name__})")
    if path.suffix != ".json":
        entries: dict = {}  # every entry of an event, in order (one event may carry several matchers)
        for h in adapter["hooks"]:
            entries.setdefault(h["harness_event"], []).append(_entry(adapter, h, guard_command()))
        console.print(f"[bold yellow]⚠️ {path} is not JSON: guard does not edit it.[/bold yellow] These are the hook "
                      "entries to add there yourself, in its own format:")
        console.print(dump(entries), markup=False, highlight=False)
        if not typer.confirm(f"Register this adapter for {name} (guard answers these hooks with it)?", default=False):
            console.print("[dim]Nothing changed.[/dim]")
            raise typer.Exit(code=1)
        save_adapter(adapter)  # agent-event reads its answers from it
        console.print(f"Add the entries, then check it with [bold]guard agent test {name}[/bold].")
        return
    change = diff(path, before, after)
    if not change:
        # the entries are in place, but the adapter decides how guard reads and answers them
        if load_adapter(name) != adapter:
            if not typer.confirm(f"{path} needs no change. Save the new adapter for {name}?", default=False):
                console.print("[dim]Nothing changed.[/dim]")
                raise typer.Exit(code=1)
            save_adapter(adapter)
        if not installed(adapter):  # the entries are there, but the agent's own switch is off (ZCode's hooks.enabled)
            console.print(f"[yellow]⚠️ Guard's entries are in {path}, but its hooks are switched off there "
                          "(hooks.enabled is false). Turn them on in that file; guard does not override your choice.[/yellow]")
            return
        console.print(f"[green]✅ {adapter['title']} already runs guard's hooks ({path}).[/green]")
        return
    _show_diff(change)
    switched = switched_on(adapter, before)
    others = others_under(adapter, before)
    if switched and others:
        console.print(f"[bold yellow]⚠️ This turns on {', '.join(switched)} in {path}: the {others} hook(s) already "
                      "there start running too.[/bold yellow] `guard agent remove` switches it back off.")
    if not typer.confirm(f"Write these hooks to {path}?", default=False):
        console.print("[dim]Nothing changed.[/dim]")
        raise typer.Exit(code=1)
    _unchanged_since_diff(path, before)
    # the adapter first: a config that calls `agent-event --agent <name>` must never exist without it
    record, switch_record = adapters_dir() / f"{_record_name(name)}.json", switched_path(name)
    kept = record.read_bytes() if record.is_file() else None
    kept_switch = switch_record.read_bytes() if switch_record.is_file() else None
    save_adapter(adapter)
    try:
        # what guard turns on now, so that remove turns exactly that back off; an earlier record stays
        # while the switch it names is still on (guard's hooks put back after being taken out by hand)
        try:
            earlier = json.loads(kept_switch) if kept_switch else []
        except ValueError:
            earlier = []
        still_on = [k for k in earlier if isinstance(k, str) and _at(before, k.split(".")) is True] \
            if isinstance(earlier, list) else []
        if switched or still_on:
            switch_record.write_text(json.dumps(sorted(set(switched) | set(still_on))), encoding="utf-8")
        else:
            switch_record.unlink(missing_ok=True)
        backup = write_config(path, after)
    except (OSError, AdapterError) as e:  # the config is as it was: so are the records about it
        for file, old in ((record, kept), (switch_record, kept_switch)):
            if old is None:
                file.unlink(missing_ok=True)
            else:
                file.write_bytes(old)
        console.print(f"[bold red]❌ {e}[/bold red]", highlight=False)  # the full error, on this screen only
        _cannot_set_up(name, f"writing {_home_relative(path)} failed ({type(e).__name__})")
    events = ", ".join(sorted({h["event"] for h in adapter["hooks"]}))
    if installed(adapter):
        console.print(f"[bold green]✅ {adapter['title']} now calls guard on: {events}.[/bold green]")
    else:  # written, but the agent's own switch is off (ZCode's hooks.enabled): nothing runs yet
        console.print(f"[yellow]⚠️ Guard's entries are in {path}, but its hooks are switched off there "
                      "(hooks.enabled is false). Turn them on in that file; guard does not override your choice.[/yellow]")
    if backup:
        console.print(f"[dim]Original kept as {backup}.[/dim]")
    console.print(f"Check it with [bold]guard agent test {name}[/bold]; undo with [bold]guard agent remove {name}[/bold].")


@agent_app.command("add")
def agent_add_cmd(
    name: str = typer.Argument(..., help="An agent, e.g. claude-code (built in), cursor, codex"),
):
    """
    Add guard's hooks to the agent's own config (global, never a repository file): shows the diff,
    asks you to confirm, keeps the original as <file>.guard.bak, and changes only guard's entries.
    An agent guard does not know is investigated first (binary, version, the structure of its config
    files without their values) and the configured LLM proposes the adapter, which guard validates;
    `guard agent test` then shows whether it really works. When guard cannot set it up, it says what
    you can do and prints a prefilled GitHub issue.
    """
    from guard.agent.adapter import load_adapter
    adapter = load_adapter(name)
    if adapter is None:
        adapter = _proposed_adapter(name, _investigate(name))
        console.print(f"[bold cyan]Proposed adapter for {name}[/bold cyan] (saved to ~/.guard/agents/{name}.json when installed):")
        console.print(json.dumps(adapter, indent=2), markup=False, highlight=False)
    _install_adapter(adapter, name)


def _registered_ok(adapter: dict, name: str) -> None:
    """
    A registered adapter is a file anyone can edit: it is validated again before guard writes with
    it, and it must be the adapter of the agent asked for (`name`), not another agent's record.
    """
    from guard.agent.adapter import BUILT_IN
    from guard.agent.adapter_validation import NOT_JSON, validate_adapter
    if name in BUILT_IN and adapter is BUILT_IN[name]:
        return  # shipped with this guard version
    problems = [p for p in validate_adapter(adapter) if p != NOT_JSON]
    if isinstance(adapter, dict) and adapter.get("name") != name:
        problems.insert(0, f"name: the record is {adapter.get('name')!r}, not {name!r}")
    if problems:
        console.print(f"[bold red]❌ ~/.guard/agents/{name}.json is not safe to install:[/bold red]")
        for p in problems:
            console.print(f"  • {p}", markup=False, highlight=False)
        console.print(f"Regenerate it with [bold]guard agent fix {name}[/bold].")
        raise typer.Exit(code=1)


@agent_app.command("fix")
def agent_fix_cmd(
    name: str = typer.Argument(..., help="An agent (registered or not)"),
    note: str = typer.Option("", "--note", help="What went wrong, or what the agent's docs say about its hooks"),
):
    """
    Regenerate an agent's adapter from the current one (if any), the events guard received from it
    (guard agent test) and your note; the result is validated and installed like `guard agent add`.
    An agent `guard agent add` could not set up starts over here with your note.
    """
    from guard.agent.adapter import BUILT_IN, adapter_diff, load_adapter
    from guard.core.repo_setup import guard_home
    if name in BUILT_IN:
        console.print(f"[bold red]❌ {name} is built into guard: update guard instead.[/bold red]")
        raise typer.Exit(code=1)
    previous = load_adapter(name)  # None: add could not set it up, so this starts from the investigation
    inv = _investigate(name, need_found=not note)
    log_path = guard_home() / "agent-events.log"
    from guard.agent.discover import event_summary
    lines = [l for l in (log_path.read_text(encoding="utf-8", errors="replace").splitlines() if log_path.is_file() else [])
             if f" {name} " in l][-50:]
    log = event_summary(lines) + (f"\nThe user says: {note}" if note else "")  # the note is the user's own words
    adapter = _proposed_adapter(name, inv, previous=previous, log=log or "none")
    change = adapter_diff(previous or {}, adapter)
    if not change:
        console.print(f"[green]The LLM proposes no change to {name}'s adapter[/green]; checking its hooks are in place.")
    else:
        _show_diff(change)
    _install_adapter(adapter, name)  # also restores hook entries removed or gone stale in the agent's config


@agent_app.command("list")
def agent_list_cmd():
    """Built-in and registered agents, and whether each one's config runs guard's hooks now."""
    from guard.agent.adapter import BUILT_IN, adapters_dir, config_path, installed, load_adapter
    from guard.core.repo_setup import _agent_present
    registered = ({p.stem for p in adapters_dir().glob("*.json") if "." not in p.stem}  # not test or switch records
                  if adapters_dir().is_dir() else set())
    names = sorted(set(BUILT_IN) | registered)
    table = Table(title="🤖 Agents", show_header=True)
    for column in ("Name", "Agent", "Source", "On this machine", "Config", "Hooks"):
        table.add_column(column)
    for n in names:
        adapter = load_adapter(n)
        if adapter is None:
            continue
        extension = adapter.get("kind") == "extension"
        if adapter.get("name") != n or not isinstance(adapter.get("install" if extension else "config"), str) or not isinstance(adapter.get("hooks"), list):
            # an edited or broken record: shown, never allowed to hide the others
            table.add_row(n, "-", "registered", "-", "-", f"[red]broken record: guard agent fix {n}[/red]")
            continue
        path = config_path(adapter)
        here = "yes" if _agent_present(adapter) else "[dim]no[/dim]"
        state = ("add by hand" if not extension and path.suffix != ".json" else "[green]installed[/green]"
                 if installed(adapter) else "[yellow]not installed[/yellow]")
        table.add_row(n, adapter.get("title", n), "built in" if n in BUILT_IN else "registered", here, str(path), state)
    console.print(table)


@agent_app.command("remove")
def agent_remove_cmd(name: str = typer.Argument(..., help="Adapter, e.g. claude-code")):
    """
    For the user, in an interactive terminal: take guard's hooks out of the agent's config (only
    guard's entries; everything else stays as it is). An agent cannot remove its own guard.
    """
    from guard.agent.adapter import (
        AdapterError, config_path, diff, read_config, switched_path, without_guard, write_config, _at, _drop_at,
    )
    adapter = _adapter_or_exit(name)
    _registered_ok(adapter, name)  # an edited record cannot point remove at another config file
    path = config_path(adapter)
    if adapter.get("kind") == "extension":
        import difflib
        from guard.agent.adapter import extension_state, extension_text
        state = extension_state(adapter)
        if state in ("missing", "foreign"):
            console.print(f"[green]No guard file at {path}.[/green]")
            return
        seen = _file_state(path)
        if state == "stale":  # guard's file, but not as this guard writes it: what differs is shown first
            current = path.read_text(encoding="utf-8")
            console.print(f"[yellow]{path} differs from the file this guard writes (guard moved, another version, or "
                          "an edit):[/yellow]")
            _show_diff("".join(difflib.unified_diff(extension_text(adapter).splitlines(keepends=True),
                                                    current.splitlines(keepends=True), "guard's file", str(path))))
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            console.print("[bold red]❌ Removing guard's hooks is the user's decision: run it yourself in an interactive terminal.[/bold red]")
            raise typer.Exit(code=1)
        if not typer.confirm(f"Delete guard's file {path}?", default=False):
            console.print("[dim]Nothing changed.[/dim]")
            raise typer.Exit(code=1)
        _file_unchanged(path, seen)  # never deletes a file put there while the question was on screen
        path.unlink()
        console.print(f"[bold green]✅ {path} removed; restart {adapter['title']}.[/bold green]")
        return
    if path.suffix != ".json":
        console.print(f"[yellow]Guard does not edit {path}: remove the entries that run `guard agent-event` from it yourself.[/yellow]")
        return
    try:
        before = read_config(path, adapter)
    except AdapterError as e:
        console.print(f"[bold red]❌ {e}[/bold red]")
        raise typer.Exit(code=1)
    after = without_guard(before, adapter["name"], adapter)
    record = switched_path(name)
    try:  # the settings guard turned on at add (ZCode's hooks.enabled), still as guard left them
        switched = json.loads(record.read_text(encoding="utf-8")) if record.exists() else []
    except (OSError, ValueError):
        switched = None
    if not isinstance(switched, list) or not all(isinstance(k, str) for k in switched):
        console.print(f"[bold red]❌ {record} cannot be read, so guard does not know what it switched on in {path}."
                      "[/bold red] Nothing was changed. Delete that file to keep every switch as it is now, then run "
                      f"guard agent remove {name} again.", highlight=False)
        raise typer.Exit(code=1)
    own = {k for k, v in (adapter.get("defaults") or {}).items() if v is True} if isinstance(adapter.get("defaults"), dict) else set()
    # the diff below shows it before anything is written: a switch the user wants kept is kept by declining
    # (asked only in a terminal: without one, remove stops below before writing anything)
    if not record.exists() and before != after and sys.stdin.isatty() and sys.stdout.isatty():
        for key in sorted(own):
            if _at(after, key.split(".")) is True and typer.confirm(
                    f"{key} is on in {path}. Guard may have switched it on when it was added (before it kept a record "
                    "of that). Switch it off too? It also stops the other hooks there", default=False):
                switched.append(key)
    for key in switched:
        if key in own and _at(after, key.split(".")) is True:
            after = _drop_at(after, key.split("."))
    change = diff(path, before, after)
    if not change:
        _forget_switches(name, path)  # nothing of guard's there: nothing to switch back later
        console.print(f"[green]No guard hooks in {path}.[/green]")
        return
    _show_diff(change)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        console.print("[bold red]❌ Removing guard's hooks is the user's decision: run it yourself in an interactive terminal.[/bold red]")
        raise typer.Exit(code=1)
    if not typer.confirm(f"Remove guard's hooks from {path}?", default=False):
        console.print("[dim]Nothing changed.[/dim]")
        raise typer.Exit(code=1)
    _unchanged_since_diff(path, before)
    write_config(path, after)
    _forget_switches(name, path)
    console.print(f"[bold green]✅ Guard's hooks removed from {path}.[/bold green]")


@agent_app.command("test")
def agent_test_cmd(
    name: str = typer.Argument(..., help="Adapter, e.g. claude-code"),
    report: bool = typer.Option(False, "--report", help="Report the events that arrived since the test started, and stop listening"),
):
    """
    Check that the agent really calls guard. Step 1 starts listening; then, in the agent, ask for one
    small file edit in a repository with no guard session. Step 2 (--report) lists the events that
    arrived and whether the edit was blocked.
    """
    from guard.agent.adapter import installed
    from guard.core.repo_setup import guard_home
    adapter = _adapter_or_exit(name)
    flag, log_path = guard_home() / AGENT_TEST_FLAG, guard_home() / "agent-events.log"
    if not report:
        if not installed(adapter):
            console.print(f"[yellow]⚠️ {adapter['title']} does not run guard's hooks yet: guard agent add {name}[/yellow]")
        flag.parent.mkdir(parents=True, exist_ok=True)
        flag.write_text(json.dumps({"agent": name, "since": datetime.now(timezone.utc).isoformat()}), encoding="utf-8")
        console.print(f"[bold cyan]Listening.[/bold cyan] In {adapter['title']}, in a repository without a guard session, ask it to "
                      "create or edit one small file. Then run [bold]guard agent test " + name + " --report[/bold].")
        return
    try:
        started = json.loads(flag.read_text(encoding="utf-8"))
        since = started["since"] if isinstance(started, dict) and started.get("agent") == name else None
    except (OSError, ValueError, KeyError, TypeError):
        since = None
    if not isinstance(since, str):
        console.print(f"[bold red]❌ No test of {name} is running: start it with guard agent test {name}[/bold red]")
        raise typer.Exit(code=1)
    lines = []
    if log_path.is_file():
        lines = [l for l in log_path.read_text(encoding="utf-8", errors="replace").splitlines()
                 if l[:32] >= since[:32] and f" {name} " in l and " EVENT " in l]
    flag.unlink(missing_ok=True)
    def same(name: str) -> str:  # `PreToolUse`, `preToolUse` and `pre_tool_use` are one event
        return name.replace("_", "").lower()
    seen = {h["harness_event"]: [] for h in adapter["hooks"]}
    by_key = {same(e): e for e in seen}
    for line in lines:
        parts = line.split(" EVENT ", 1)[1].split()
        seen.setdefault(by_key.get(same(parts[0]), parts[0]), []).append(" ".join(parts[1:]))
    table = Table(title=f"🤖 {adapter['title']}: events since {since[:19]}", show_header=True)
    table.add_column("Harness event", style="bold")
    table.add_column("Arrived", justify="right")
    table.add_column("Decisions")
    for event, results in seen.items():
        table.add_row(event, str(len(results)), ", ".join(sorted(set(results))) or "[yellow]none[/yellow]")
    console.print(table)
    # the harness's own name for its before-edit hook (PreToolUse for Claude Code, preToolUse for Cursor, …)
    edit_events = {h["harness_event"] for h in adapter["hooks"] if h["event"] == "before-edit"}
    blocked_edit = any("-> block" in r for e in edit_events for r in seen.get(e, []))
    missing = [e for e, r in seen.items() if not r]
    from guard.agent.adapter import test_record_path  # what doctor shows as this agent's last test
    record = test_record_path(name)
    record.parent.mkdir(parents=True, exist_ok=True)
    from guard.agent.adapter import config_path, config_fingerprint
    record.write_text(json.dumps({"at": datetime.now(timezone.utc).isoformat(), "events": len(lines),
                                  "blocked_edit": blocked_edit, "missing": missing,
                                  "config": config_fingerprint(config_path(adapter))}), encoding="utf-8")
    if not lines:
        console.print("[bold red]❌ No event arrived: the agent is not calling guard.[/bold red] Restart the agent and try "
                      "once more; some agents only read their hooks at start.")
        _cannot_set_up(name, f"guard agent test: no event arrived from {adapter['title']} after an edit was asked for")
    if blocked_edit:
        # the log shows what guard answered, not what the agent did with it: only the user can see that
        console.print("[green]✅ Guard answered the edit with a block.[/green] Now check in the agent that the file was "
                      "NOT changed and that it showed guard's reason; if the edit went through anyway, run "
                      f"[bold]guard agent fix {name} --note \"the edit was not blocked\"[/bold].")
    else:
        console.print("[yellow]⚠️ No edit was blocked: ask for a file edit in a repository without a guard session.[/yellow] "
                      f"If you did and the edit went through, run [bold]guard agent fix {name} --note \"edits are not "
                      "blocked\"[/bold], or ask for support with this prefilled issue:")
        from guard.agent.discover import issue_url
        console.print(issue_url(name, f"guard agent test: events arrived from {adapter['title']} but no edit was blocked"),
                      markup=False, highlight=False, soft_wrap=True)
    if missing:
        console.print(f"[yellow]Events that did not arrive: {', '.join(missing)} (a stop arrives when the agent finishes its turn).[/yellow]")


@app.command("agent-event")
def agent_event_cmd(
    event: str = typer.Argument(..., help="prompt | before-edit | after-bash | stop | before-commit"),
    agent: Optional[str] = typer.Option(None, "--agent", "-a", help="Adapter whose field mapping and output style to use"),
):
    """
    Called by an agent harness hook with the hook payload (JSON) on stdin. Prints the decision as
    JSON; a block also exits 2 with the reason on stderr. A payload guard cannot read is allowed and
    logged: a broken adapter must never lock the user out of their agent.
    """
    from guard.agent.adapter import harness_event, load_adapter, render
    from guard.agent.events import EVENTS, Decision, decide, normalise
    from guard.core.repo_setup import guard_home

    if event not in EVENTS:
        console.print(f"[bold red]❌ Unknown event {event!r}; expected one of: {', '.join(EVENTS)}[/bold red]")
        raise typer.Exit(code=1)
    def log(message: str) -> None:
        try:
            path = guard_home() / "agent-events.log"
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"{datetime.now(timezone.utc).isoformat()} {agent or '-'} {event} {message}\n")
        except OSError:
            pass

    adapter = load_adapter(agent) if agent else None  # where this harness puts each field, how it reads answers
    payload: dict = {}
    try:
        # Harnesses send UTF-8 JSON; the console code page (cp1252 on Windows) would garble the user's prompt
        stream = getattr(sys.stdin, "buffer", None)
        raw = stream.read(MAX_EVENT_BYTES + 1).decode("utf-8", "replace") if stream else sys.stdin.read(MAX_EVENT_BYTES + 1)
        if len(raw) > MAX_EVENT_BYTES:
            raise ValueError(f"payload larger than {MAX_EVENT_BYTES} characters")
        payload = json.loads(raw) if raw.strip() else {}
        if not isinstance(payload, dict):
            raise ValueError(f"payload is a JSON {type(payload).__name__}, not an object")
        fields = adapter.get("fields") if adapter else None
        ev = normalise(event, payload, fields)
        ev.agent = agent or ""
        if event != "stop" and not (ev.prompt or ev.tool or ev.file_paths or ev.command):
            log(f"INCOMPLETE payload without the fields this event needs (keys: {sorted(payload)[:12]})")
    except Exception as e:  # a payload guard cannot read: never break the agent because of guard
        ev, decision = None, Decision()
        log(f"UNREADABLE {type(e).__name__}: {e}")
    if ev is not None:
        try:
            decision = decide(ev)
        except Exception as e:  # guard's own failure: allowed, but the agent is told it was not checked
            decision = Decision(action="notify", reason=f"Guard could not check this action ({type(e).__name__}: {e}); it was allowed. Tell the user.")
            log(f"ERROR {type(e).__name__}: {e}")
    harness = harness_event(adapter, event, payload if isinstance(payload, dict) else {})
    if _test_listening():  # `guard agent test` is listening
        tool = f" tool={ev.tool}" if ev is not None and ev.tool else ""
        tool += f" session={ev.agent_session[:8]}" if ev is not None and ev.agent_session else " session=-"
        log(f"EVENT {harness or '-'}{tool} -> {decision.action}")
    out, err, code = render((adapter or {}).get("output"), harness, decision)
    sys.stdout.write(out)
    sys.stderr.write(err)
    if code:
        raise typer.Exit(code=code)
