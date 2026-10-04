"""
Project-defined invariants (`guard.invariants.json` at the repository root).

Each invariant may carry machine checks evaluated against the CURRENT file contents:
  {"files": "src/ai/**/*.ts", "forbid": "AbortSignal\\.timeout"}   -> no file may match
  {"files": "src/ui/main-screen.ts", "require": "pushSentHistory"} -> at least one file must match
An invariant without checks is reported as UNVERIFIED (manual), never as passed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional, Tuple

INVARIANTS_FILENAME = "guard.invariants.json"

STATUS_PASSED = "passed"
STATUS_FAILED = "failed"
STATUS_UNVERIFIED = "unverified"


class InvariantsFileError(ValueError):
    pass


# Guard never creates a diff in the user's repository. Rules guard generates (lazy setup, rules
# learned in review) live in a local, Git-excluded file; the repository's guard.invariants.json
# belongs to the user and is only read.
LOCAL_INVARIANTS = Path(".guard") / "invariants.json"


def local_invariants_path(repo_path: Path) -> Path:
    return repo_path / LOCAL_INVARIANTS


def _read_items(path: Path) -> Optional[List[dict]]:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise InvariantsFileError(f"{path.name} is not valid JSON: {e}") from e
    items = data.get("invariants", []) if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise InvariantsFileError(f"{path.name}: 'invariants' must be a list")
    return [i for i in items if isinstance(i, dict) and i.get("id") and i.get("description")]


def load_shared_invariants(repo_path: Path) -> Optional[List[dict]]:
    """The repository's own guard.invariants.json (user-owned, committed), or None."""
    return _read_items(repo_path / INVARIANTS_FILENAME)


def load_local_invariants(repo_path: Path) -> Optional[List[dict]]:
    """Guard-owned local rules in .guard/invariants.json (never committed), or None."""
    return _read_items(local_invariants_path(repo_path))


def load_project_invariants(repo_path: Path) -> Optional[List[dict]]:
    """
    Shared rules plus local rules (a local rule with the same id as a shared one is ignored).
    None when neither file exists.
    """
    shared = load_shared_invariants(repo_path)
    local = load_local_invariants(repo_path)
    if shared is None and local is None:
        return None
    items = list(shared or [])
    ids = {str(i["id"]) for i in items}
    items.extend({**i, "scope": "local"} for i in (local or []) if str(i["id"]) not in ids)
    return items


def ensure_local_excluded(repo_path: Path) -> None:
    """
    Keep .guard/ out of Git through info/exclude (never through a tracked .gitignore). Already there:
    nothing to do and no lock taken, so a caller holding the repository lock can write rules.
    """
    from guard.core.git_exclude import exclude_file
    from guard.core.session import SessionManager
    exclude = exclude_file(repo_path)
    try:
        if exclude is not None and exclude.is_file() and {".guard/", ".guard"} & {
                line.strip() for line in exclude.read_text(encoding="utf-8", errors="ignore").splitlines()}:
            return
    except OSError:
        pass  # unreadable: let the locked writer try and report
    SessionManager(repo_path).ensure_gitignore()


SKIP_DIRS = {"node_modules", ".git", ".guard", "dist", "build", ".venv", "venv", "__pycache__"}


def _match_files(repo_path: Path, pattern: str) -> List[Path]:
    return sorted(
        p for p in repo_path.glob(pattern)
        if p.is_file() and not SKIP_DIRS.intersection(p.relative_to(repo_path).parts)
    )


def evaluate_checks(repo_path: Path, checks: List[dict]) -> Tuple[str, str]:
    """Evaluate one invariant's checks. Returns (status, note)."""
    if not checks:
        return STATUS_UNVERIFIED, "No automated check defined (manual verification required)"

    for check in checks:
        pattern = check.get("files", "")
        files = _match_files(repo_path, pattern) if pattern else []
        if not files:
            return STATUS_FAILED, f"Check target `{pattern}` matches no file (renamed or deleted?)"

        forbid = check.get("forbid")
        require = check.get("require")
        try:
            forbid_rx = re.compile(forbid, re.MULTILINE) if forbid else None
            require_rx = re.compile(require, re.MULTILINE) if require else None
        except re.error as e:
            return STATUS_FAILED, f"Invalid regex in check for `{pattern}`: {e}"
        if forbid_rx:
            rx = forbid_rx
            for f in files:
                text = f.read_text(encoding="utf-8", errors="ignore")
                m = rx.search(text)
                if m:
                    line = text.count("\n", 0, m.start()) + 1
                    rel = f.relative_to(repo_path).as_posix()
                    return STATUS_FAILED, f"Forbidden pattern `{forbid}` found at {rel}:{line}"
        if require_rx:
            rx = require_rx
            if not any(rx.search(f.read_text(encoding="utf-8", errors="ignore")) for f in files):
                return STATUS_FAILED, f"Required pattern `{require}` not found in `{pattern}`"

    return STATUS_PASSED, f"{len(checks)} automated check(s) passed"


# ---------------------------------------------------------------------------
# Authoring: init from agent docs, LLM-learned additions, removal detection
# ---------------------------------------------------------------------------

AGENT_DOCS = ("AGENT.md", "AGENTS.md", "CLAUDE.md")
_SECTION_RE = re.compile(r"^#{1,6}\s.*(INVARIANT|BẤT BIẾN)", re.IGNORECASE)
_ITEM_RE = re.compile(r"^(\d+)\.\s+(.+?)\s*$")
_ID_RE = re.compile(r"^[A-Z][A-Z0-9_-]{1,39}$")

FILE_COMMENT = (
    "Project invariants checked by `guard pre`/`guard post`. Each check: "
    "{\"files\": glob, \"forbid\" | \"require\": regex} on current file contents. "
    "Entries without checks are reported UNVERIFIED. Validate with `guard invariants check`."
)


def _clean_md(text: str) -> str:
    # Keep underscores: identifiers such as update_project_synopsis must survive
    return re.sub(r"[*`]", "", text).strip().rstrip(":").strip()


def import_from_agent_docs(repo_path: Path) -> List[dict]:
    """Numbered items under an 'Invariants' / 'Bất biến' heading of AGENT.md / CLAUDE.md."""
    found: List[dict] = []
    seen = set()
    for name in AGENT_DOCS:
        path = repo_path / name
        if not path.is_file():
            continue
        in_section, current = False, None
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("#"):
                in_section = bool(_SECTION_RE.match(line))
                current = None
                continue
            if not in_section:
                continue
            m = _ITEM_RE.match(line)
            if m:
                title = _clean_md(m.group(2))
                if title and title.lower() not in seen:
                    seen.add(title.lower())
                    current = {"id": f"INV-{len(found) + 1:02d}", "description": title,
                               "rationale": f"Imported from {name}", "checks": []}
                    found.append(current)
                else:
                    current = None
            elif current is not None and line.strip().startswith(("*", "-")):
                detail = _clean_md(line.strip()[1:])
                if detail:
                    current["description"] += f". {detail}" if len(current["description"]) < 300 else ""
    return found


def dump_invariants(payload: dict) -> str:
    """
    Stable, review-friendly layout: one invariant per block, one check per line. Rewriting a file
    in this layout (e.g. after appending a learned rule) leaves existing entries byte-identical.
    """
    def value(v) -> str:
        return json.dumps(v, ensure_ascii=False)

    def check_line(c: dict) -> str:
        return "{ " + ", ".join(f"{value(k)}: {value(v)}" for k, v in c.items()) + " }"

    blocks = []
    for inv in payload.get("invariants", []):
        fields = []
        for k, v in inv.items():
            if k == "checks" and v:
                body = ",\n".join(f"        {check_line(c)}" for c in v)
                fields.append(f'      "checks": [\n{body}\n      ]')
            else:
                fields.append(f"      {value(k)}: {value(v)}")
        blocks.append("    {\n" + ",\n".join(fields) + "\n    }")
    head = [f'  "$comment": {value(payload["$comment"])},'] if "$comment" in payload else []
    return "\n".join(["{", *head, '  "invariants": [', ",\n".join(blocks), "  ]", "}"]) + "\n"


def write_invariants_file(repo_path: Path, items: List[dict], comment: str = FILE_COMMENT, local: bool = False) -> Path:
    path = local_invariants_path(repo_path) if local else repo_path / INVARIANTS_FILENAME
    if local:
        path.parent.mkdir(parents=True, exist_ok=True)
        ensure_local_excluded(repo_path)
    payload = {"$comment": comment, "invariants": items} if comment else {"invariants": items}
    path.write_text(dump_invariants(payload), encoding="utf-8", newline="\n")
    return path


def init_invariants_file(repo_path: Path, shared: bool = False) -> Tuple[Path, bool, int]:
    """
    Create the invariants file if missing. Returns (path, created, imported_count).
    Default: the local .guard/invariants.json, so nothing appears in the repository. `shared=True`
    creates guard.invariants.json in the repository root, only when the user asks for it.
    """
    shared_path = repo_path / INVARIANTS_FILENAME
    if shared_path.exists():
        return shared_path, False, 0
    path = shared_path if shared else local_invariants_path(repo_path)
    if path.exists():
        return path, False, 0
    items = import_from_agent_docs(repo_path)
    write_invariants_file(repo_path, items, local=not shared)
    return path, True, len(items)


_STOP_WORDS = frozenset(
    "a an the is are be to of in on for and or its it this that with by as at from "
    "must should can when while every each all any than into their them they".split()
)
_NEGATIONS = frozenset({"not", "no", "never", "without", "nor", "cannot"})
SIMILAR_OVERLAP = 0.7  # share of the shorter description's words found in the other one
SIMILAR_MIN_WORDS = 3


def _words(text: str) -> set:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if len(w) > 1 and w not in _STOP_WORDS}


def similar(a: str, b: str) -> bool:
    """
    Two descriptions state the same rule when most words of the shorter one (stop words aside) are
    in the other: a reworded rule is caught, a different rule on the same file is not.
    """
    if " ".join(a.lower().split()) == " ".join(b.lower().split()):
        return True  # the same text, however short
    wa, wb = _words(a), _words(b)
    if bool(wa & _NEGATIONS) != bool(wb & _NEGATIONS):
        return False  # a rule and its negation share words but say the opposite
    if wa and wa == wb:
        return True  # the same words, whatever the order, case or punctuation
    if min(len(wa), len(wb)) < SIMILAR_MIN_WORDS:
        # Too few words for a share to mean much: a short rule restates one that contains all its words
        return bool(wa and wb) and (wa <= wb or wb <= wa)
    return len(wa & wb) / min(len(wa), len(wb)) >= SIMILAR_OVERLAP


def similar_to(description: str, items: List[dict]) -> Optional[str]:
    """Id of the first rule in `items` that states the same rule as `description`, or None."""
    return next((str(i["id"]) for i in items if similar(description, str(i.get("description", "")))), None)


def similar_groups(items: List[dict]) -> List[List[str]]:
    """Ids of rules that restate each other (each group in file order, groups of two or more)."""
    groups: List[List[dict]] = []
    for item in items:
        # a rule similar to members of several groups joins them into one
        matching = [g for g in groups if any(similar(item["description"], o["description"]) for o in g)]
        merged = [o for g in matching for o in g] + [item]
        groups = [g for g in groups if all(g is not m for m in matching)] + [merged]
    order = {id(i): n for n, i in enumerate(items)}
    groups = [sorted(g, key=lambda i: order[id(i)]) for g in groups if len(g) > 1]
    return [[str(i["id"]) for i in g] for g in sorted(groups, key=lambda g: order[id(g[0])])]


def _learned(item: dict) -> bool:
    return str(item.get("origin", "")).startswith("llm:")


def learned_without_checks(repo_path: Path) -> List[dict]:
    """Rules the LLM gate added to the local file without any check (reported UNVERIFIED every time)."""
    return [i for i in (load_local_invariants(repo_path) or []) if _learned(i) and not i.get("checks")]


def prune_learned_without_checks(repo_path: Path, confirmed: List[dict]) -> List[str]:
    """
    Remove the learned rules without checks that the user confirmed (exactly those entries, as they
    were listed) from the local file; returns their ids. A rule added or changed since the listing,
    the team's guard.invariants.json and every rule with a check or not learned by the gate stay.
    """
    def unchecked(i: dict) -> bool:
        return _learned(i) and not i.get("checks") and i in confirmed

    ensure_local_excluded(repo_path)  # before the lock: it takes the same lock
    with _local_file_lock(repo_path):  # read and write as one step: a rule learned meanwhile is kept
        local = load_local_invariants(repo_path)
        if not local:
            return []
        # each entry is judged on its own: a kept rule sharing an id with a removed one stays
        gone = [str(i["id"]) for i in local if unchecked(i)]
        if gone:
            write_invariants_file(repo_path, [i for i in local if not unchecked(i)], comment="", local=True)
        return gone


def _local_file_lock(repo_path: Path):
    """
    The repository's guard lock (the one info/exclude writers take), so learning and pruning never
    overwrite each other's rules. Outside Git there is no shared metadata to protect: no lock.
    """
    from contextlib import nullcontext
    from guard.core.git_exclude import ExcludeLock
    try:
        return ExcludeLock(repo_path)
    except OSError:
        return nullcontext()


def _unusable_check(checks: List[dict]) -> Optional[str]:
    """Why a learned rule's checks cannot hold it, or None: every check needs a target and a pattern."""
    if not checks:
        return "no automated check (a learned rule is kept only with a `files` + `forbid`/`require` check)"
    for c in checks:
        if not isinstance(c, dict):
            return "a check must be an object with `files` and `forbid` or `require`"
        text = [c.get(k) for k in ("files", "forbid", "require") if c.get(k) is not None]
        if not isinstance(c.get("files"), str) or not c["files"] or not (c.get("forbid") or c.get("require")) \
                or not all(isinstance(v, str) for v in text):
            return "a check needs `files` and a `forbid` or `require` pattern, all text"
        if not all(re.search(r"\w{3,}", c[k]) for k in ("forbid", "require") if c.get(k)):
            # `.` or `\s` matches almost any file: it holds without verifying the rule it names
            return "a check pattern needs a literal of at least three letters or digits (e.g. a name it looks for)"
        if c.get("require") and _matches_anything(c["require"]):
            return "the `require` pattern matches unrelated text (e.g. `.*|name`), so it verifies nothing"
        if c.get("forbid") and not _can_match(c["forbid"]):
            return ("the `forbid` pattern cannot be shown to match anything (e.g. `(?!)name`, or a construct guard "
                    "cannot check), so it may forbid nothing")
    return None


def _example(pattern: str) -> Optional[str]:
    """
    One string the pattern describes, built from its parse tree (first alternative, fewest repeats,
    assertions left out); None when a construct is not understood. Uses the stdlib regex parser.
    """
    try:
        import re._parser as sre_parse  # Python 3.11+
    except ImportError:  # pragma: no cover - Python 3.10
        import sre_parse  # type: ignore[no-redef]

    def build(items) -> str:
        out = []
        for op, arg in items:
            name = str(op)
            if name == "LITERAL":
                out.append(chr(arg))
            elif name == "NOT_LITERAL":
                out.append("a" if chr(arg) != "a" else "b")
            elif name == "ANY":
                out.append("a")
            elif name == "IN":
                out.append(_in_example(arg))
            elif name == "BRANCH":
                out.append(build(arg[1][0]))
            elif name == "SUBPATTERN":
                out.append(build(arg[-1]))
            elif name == "ATOMIC_GROUP":
                out.append(build(arg))
            elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                out.append(build(arg[2]) * max(arg[0], 0))
            elif name in ("AT", "ASSERT", "ASSERT_NOT", "GROUPREF", "GROUPREF_EXISTS"):
                continue  # zero-width or back-reference: the real regex decides below
            else:
                raise ValueError(name)
        return "".join(out)

    def _in_example(items) -> str:
        op, arg = items[0]
        name = str(op)
        if name == "NEGATE":
            return "\x00" if len(items) > 1 else "a"
        if name == "LITERAL":
            return chr(arg)
        if name == "RANGE":
            return chr(arg[0])
        if name == "CATEGORY":
            return {"CATEGORY_DIGIT": "0", "CATEGORY_SPACE": " "}.get(str(arg), "a")
        raise ValueError(name)

    try:
        return build(sre_parse.parse(pattern))
    # Unusual regex construct: no example string can be built, caller does not reject on it
    except (re.error, ValueError, IndexError, TypeError, RecursionError, OverflowError, MemoryError):
        return None


def _can_match(pattern: str) -> bool:
    """
    A forbidden pattern must be able to match something: its own example string (`(?!)name` has
    none that it matches, so it forbids nothing). A construct guard cannot build an example for is
    not trusted either: the learned rule is simply not kept.
    """
    try:
        rx = re.compile(pattern, re.MULTILINE)
    except re.error:
        return True  # reported by evaluate_checks as an invalid regex
    sample = _example(pattern)
    return sample is not None and bool(rx.search(sample))


def _random_text(size: int = 4096) -> str:
    """Deterministic text of letters, digits, punctuation and line breaks that names nothing."""
    import random
    rng = random.Random(1729)
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \t\n.,;:(){}[]<>=+-*/'\"!?_#$%&|"
    return "".join(rng.choice(alphabet) for _ in range(size))


_PROBES = ("", "zq", "unrelated probe text\nsecond line 42", _random_text())


def _matches_anything(pattern: str) -> bool:
    """
    A required pattern that also matches empty text or a long random text holds in almost every file
    (`.*|name`, `(?s).{100}|name`), so it verifies nothing.
    """
    try:
        rx = re.compile(pattern, re.MULTILINE)
    except re.error:
        return False  # reported by evaluate_checks as an invalid regex
    return any(rx.search(p) for p in _PROBES)


def append_learned_invariants(repo_path: Path, proposals: List[dict], session_id: str) -> Tuple[List[str], List[str]]:
    """
    Add invariants the reviewer discovered. A proposal is kept only when it is verifiable and new:
    it has checks that target existing files and pass on the current tree (a rule that fails on the
    code it describes is wrong, one without a check is never verified), and neither its id nor its
    meaning is already a rule (team file, local file, or learned earlier in this session: learned
    rules are written to the local file at once). Returns (added ids, rejection notes).
    """
    if not proposals:
        return [], []
    try:
        items = load_project_invariants(repo_path) or []
    except InvariantsFileError as e:
        return [], [f"not written: {e}"]
    ids = {str(i["id"]) for i in items}
    added, rejected = [], []
    for prop in proposals:
        pid = str(prop.get("id", "")).strip().upper()
        desc = str(prop.get("description", "")).strip()
        raw_checks = prop.get("checks") or []
        checks = list(raw_checks) if isinstance(raw_checks, list) else [raw_checks]  # malformed: rejected below
        if not _ID_RE.match(pid) or not desc:
            rejected.append(f"{pid or '?'}: missing or invalid id/description")
            continue
        if pid in ids:
            rejected.append(f"{pid}: already present")
            continue
        same = similar_to(desc, items)
        if same:
            rejected.append(f"{pid}: similar to {same} (already a rule)")
            continue
        unusable = _unusable_check(checks)
        if unusable:
            rejected.append(f"{pid}: {unusable}")
            continue
        status, note = evaluate_checks(repo_path, checks)  # a target matching no file fails here too
        if status != STATUS_PASSED:
            rejected.append(f"{pid}: check does not pass on the current code ({note})")
            continue
        items.append({
            "id": pid, "description": desc,
            "rationale": str(prop.get("rationale", "")).strip() or "Discovered by the LLM gate review",
            "checks": checks, "origin": f"llm:{session_id}",
        })
        ids.add(pid)
        added.append(pid)
    if added:
        # Learned rules go to the local file: guard never edits the repository's own rulebook
        ensure_local_excluded(repo_path)  # before the lock: it takes the same lock
        with _local_file_lock(repo_path):
            local = load_local_invariants(repo_path) or []
            local.extend(i for i in items if i["id"] in added)
            write_invariants_file(repo_path, local, comment="", local=True)
    return added, rejected


def removed_or_relaxed(old_items: List[dict], new_items: List[dict]) -> List[str]:
    """Invariants that disappeared or whose checks changed between two versions of the file."""
    new_by_id = {str(i["id"]): i for i in new_items}
    notes = []
    for old in old_items:
        oid = str(old["id"])
        new = new_by_id.get(oid)
        if new is None:
            notes.append(f"`{oid}` was removed")
        elif (old.get("checks") or []) != (new.get("checks") or []):
            notes.append(f"`{oid}` checks were changed")
    return notes
