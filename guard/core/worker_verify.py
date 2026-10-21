"""
Auditing one worker's delivery before the coordinator accepts it.

A worker's own report is a claim; this module looks for the ways a claim can be false:
edits outside the declared ownership, weakened or deleted tests, CI workflow edits, a
stale report, reused evidence, and acceptance commands that no longer pass. Stdlib only
and no guard imports, so the watchdog can run it cheaply on every tick.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

FAIL = "FAIL"
WARN = "WARN"

TAIL_CHARS = 400
SMALL_IMAGE_BYTES = 8 * 1024
IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg")
REPORT_SUFFIXES = tuple(f".{ext}" for ext in ("png", "jpg", "jpeg", "webm", "mp4", "json", "log", "txt", "md"))
# Documentation quotes the weakening patterns themselves, and config data is not executable,
# so the weakening scan skips these extensions - a deny-list, so unknown code files stay covered.
SCAN_SKIP_SUFFIXES = (
    ".md",
    ".rst",
    ".txt",
    ".adoc",
    ".html",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
)

TEST_PATH_RE = re.compile(r"(^|/)test_.*\.py$|_test\.py$|(^|/)tests?/.*\.py$|\.(spec|test)\.[cm]?[jt]sx?$")
ASSERTION_RE = re.compile(r"\b(assert|expect)\b")
PACKAGE_JSON_RE = re.compile(r"(^|/)package\.json$")
SPEC_IN_TEST_LINE_RE = re.compile(r"[\w./-]+\.(spec|test)\.[cm]?[jt]s")
CLAIM_RE = re.compile(r"all (tests|checks|steps) pass", re.IGNORECASE)
ADDED_LINE_RE = re.compile(r"^\+[^+]")
REMOVED_LINE_RE = re.compile(r"^-[^-]")
REPORT_TOKEN_RE = re.compile(r"[^\s\"'`<>|)\]]+")
GIT_ESCAPE_RE = re.compile(r"\\([abfnrtv\\\"]|[0-7]{1,3})")
GIT_ESCAPES = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", '"': '"'}

# The weakening sources are assembled from parts on purpose: a line carrying a whole pattern
# would match the very scan this module runs, in this module's own diff.
_SKIP_FOCUS_SOURCE = "|".join(
    [
        r"\b(describe|it|test)\.(skip|only|todo)\(",
        r"\bx(it|describe)\(",
        r"\.only\(",
        r"pytest\.mark\.(?:skip|xfail)\b",
        r"pytest\.skip\(",
        r"unittest\.skip",
        "@ski" + "p(If)?\\(",
    ]
)
_SWALLOWED_SOURCE = "|".join(
    [r"\|\|\s*true\b", "--passWith" + "NoTests", r"process\.exit\(0\)", r"pytest\.exit\(0\)"]
)
_SILENCED_SOURCE = "|".join(
    [
        "eslint-" + "disable",
        "@ts-" + "ignore",
        "@ts-" + "nocheck",
        "@ts-" + "expect-" "error",
        r"#\s*type:\s*ignore",
    ]
)
_ANY_ESCAPE_SOURCE = "|".join([r"\bas any\b", r":\s*any\b", "<" "any>"])

# The scans, in the order their issues are reported: one FAIL per pattern that hits.
_WEAKENING_CHECKS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("weakened-skip-focus", "skipped or focused test added", re.compile(_SKIP_FOCUS_SOURCE)),
    ("weakened-swallowed-failure", "swallowed failure added", re.compile(_SWALLOWED_SOURCE)),
    ("weakened-lint-type-silenced", "lint or type check silenced", re.compile(_SILENCED_SOURCE)),
    ("weakened-any-escape", "any escape hatch added", re.compile(_ANY_ESCAPE_SOURCE)),
)


@dataclass(frozen=True)
class VerifyIssue:
    severity: str  # FAIL | WARN
    code: str
    message: str


@dataclass(frozen=True)
class CheckOutcome:
    command: str
    exit_code: int
    output_tail: str  # last ~400 characters of combined output


@dataclass
class VerifyResult:
    issues: list[VerifyIssue] = field(default_factory=list)
    checks: list[CheckOutcome] = field(default_factory=list)

    @property
    def fails(self) -> list[VerifyIssue]:
        return [issue for issue in self.issues if issue.severity == FAIL]

    @property
    def warns(self) -> list[VerifyIssue]:
        return [issue for issue in self.issues if issue.severity == WARN]

    @property
    def passed(self) -> bool:
        return not self.fails

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "issues": [
                {"severity": issue.severity, "code": issue.code, "message": issue.message} for issue in self.issues
            ],
            "checks": [
                {"command": check.command, "exit_code": check.exit_code, "output_tail": check.output_tail}
                for check in self.checks
            ],
        }


def _git(worktree: Path, *args: str) -> str:
    """Run one read-only git command in the worktree; a Git error reads as empty output."""
    proc = subprocess.run(
        ["git", "-C", str(worktree), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return proc.stdout if proc.returncode == 0 else ""


def _unquote_git_path(raw: str) -> str:
    """Undo the C-style quoting Git applies to paths with unusual characters (core.quotePath)."""
    if len(raw) < 2 or not raw.startswith('"') or not raw.endswith('"'):
        return raw
    body = raw[1:-1]
    out = bytearray()
    pos = 0
    for match in GIT_ESCAPE_RE.finditer(body):
        out += body[pos:match.start()].encode("utf-8", "surrogateescape")
        escape = match.group(1)
        out += GIT_ESCAPES[escape].encode("utf-8") if escape in GIT_ESCAPES else bytes([int(escape, 8) & 0xFF])
        pos = match.end()
    out += body[pos:].encode("utf-8", "surrogateescape")
    return out.decode("utf-8", "replace")


def _status_entries(worktree: Path) -> list[tuple[str, str]]:
    """(status, path) for every working-tree entry Git reports, one entry per path.

    `-uall` lists each file inside a new folder instead of the folder itself, so a narrow `own`
    glob can match it; `-z` gives raw, unquoted paths. A rename or copy entry is `new NUL old`,
    and both paths count as changed.
    """
    entries = []
    parts = _git(worktree, "status", "--porcelain", "-z", "-uall").split("\0")
    i = 0
    while i < len(parts):
        item = parts[i]
        i += 1
        if len(item) < 4:
            continue
        status = item[:2]
        entries.append((status, item[3:]))
        if "R" in status or "C" in status:
            if i < len(parts) and parts[i]:
                entries.append((status, parts[i]))
            i += 1
    return entries


def _name_lines(text: str) -> list[str]:
    """One path per line, as `git diff --name-only` prints it, with Git quoting undone."""
    return [path for path in (_unquote_git_path(line) for line in text.splitlines()) if path]


def _changed_paths(committed: list[str], entries: list[tuple[str, str]]) -> list[str]:
    """Committed-since-base plus working-tree paths, sorted and deduplicated."""
    return sorted({path for path in committed + [path for _, path in entries] if path})


def _glob_re(glob: str) -> re.Pattern[str]:
    """PS1 glob: `**` is any path, `*` is within a segment, `?` is one character; case-sensitive."""
    escaped = re.escape(glob.replace("\\", "/"))
    pattern = escaped.replace(r"\*\*", ".*").replace(r"\*", "[^/]*").replace(r"\?", ".")
    return re.compile(pattern)


def _owned_matcher(own: Sequence[str]) -> Callable[[str], bool]:
    """Ownership test for a path; an empty `own` declares everything owned."""
    if not own:
        return lambda path: True
    patterns = [_glob_re(glob) for glob in own]

    def owned(path: str) -> bool:
        return any(pattern.fullmatch(path) for pattern in patterns)

    return owned


def _listed(paths: Sequence[str], limit: int) -> str:
    return ", ".join(paths[:limit])


def _names(paths: Sequence[Path], limit: int) -> str:
    return ", ".join(path.name for path in paths[:limit])


def _scope_issues(
    committed: list[str], entries: list[tuple[str, str]], role: str, own: Sequence[str]
) -> list[VerifyIssue]:
    """A fix worker edits only its `own` globs; a test worker never touches a tracked file."""
    if role == "test":
        tracked = sorted({path for path in committed + [path for status, path in entries if status != "??"] if path})
        if tracked:
            return [
                VerifyIssue(
                    FAIL, "test-worker-tracked-edits", f"test worker changed tracked files: {_listed(tracked, 8)}"
                )
            ]
        return []
    outside = [path for path in _changed_paths(committed, entries) if not _owned_matcher(own)(path)]
    if outside:
        return [
            VerifyIssue(FAIL, "scope-outside-ownership", f"edited outside its ownership: {_listed(outside, 8)}")
        ]
    return []


def _diff_path(raw: str) -> str | None:
    """The repo-relative path a `---`/`+++` diff header names; None for `/dev/null`."""
    raw = raw.strip()
    if raw.startswith('"'):  # Git quotes paths with unusual characters (core.quotePath)
        raw = _unquote_git_path(raw)
    if not raw or raw == "/dev/null":
        return None
    return raw[2:] if raw[:2] in ("a/", "b/") else raw


def _diff_files(worktree: Path, base: str) -> list[tuple[str, list[str], list[str]]]:
    """Added and removed lines of `base` vs the working tree, grouped per changed file.

    A deleted file keeps its old path; a file with no content change has no lines and no entry.
    """
    files: list[tuple[str, list[str], list[str]]] = []
    for chunk in re.split(r"^diff --git ", _git(worktree, "diff", base, "-U0"), flags=re.MULTILINE)[1:]:
        added: list[str] = []
        removed: list[str] = []
        old_path = new_path = None
        in_hunk = False
        for line in chunk.splitlines():
            if not in_hunk and line.startswith("--- "):
                old_path = _diff_path(line[4:])
            elif not in_hunk and line.startswith("+++ "):
                new_path = _diff_path(line[4:])
            elif line.startswith("@@"):
                in_hunk = True
            elif in_hunk and ADDED_LINE_RE.match(line):
                added.append(line)
            elif in_hunk and REMOVED_LINE_RE.match(line):
                removed.append(line)
        path = new_path or old_path
        if path is not None:
            files.append((path, added, removed))
    return files


def _scannable(path: str) -> bool:
    """Whether the weakening scan reads this file: everything but docs and config data."""
    return Path(path).suffix.lower() not in SCAN_SKIP_SUFFIXES


def _weakening_issues(added: list[str]) -> list[VerifyIssue]:
    """One FAIL per weakening pattern the added lines hit, naming the first 3 lines."""
    issues = []
    for code, label, pattern in _WEAKENING_CHECKS:
        hits = [line for line in added if pattern.search(line)]
        if hits:
            issues.append(VerifyIssue(FAIL, code, f"{label}: " + " | ".join(hits[:3])))
    return issues


def _ci_issues(changed: list[str], own: Sequence[str]) -> list[VerifyIssue]:
    """A CI workflow edit is accepted only when a non-empty `own` covers that file."""
    matcher = _owned_matcher(own)
    offenders = [
        path
        for path in changed
        if path.startswith(".github/workflows/") and not (bool(own) and matcher(path))
    ]
    if offenders:
        return [VerifyIssue(FAIL, "ci-workflow-changed", f"CI workflow changed: {_listed(offenders, 8)}")]
    return []


def _deleted_test_issues(worktree: Path, base: str) -> list[VerifyIssue]:
    """A deleted test file is a dropped check, whatever else the diff says."""
    deleted = _name_lines(_git(worktree, "diff", "--diff-filter=D", "--name-only", base))
    tests = [path for path in deleted if TEST_PATH_RE.search(path)]
    if tests:
        return [VerifyIssue(FAIL, "weakened-deleted-test", f"deleted test files: {_listed(tests, 8)}")]
    return []


def _spec_dropped_issues(worktree: Path, base: str, changed: list[str]) -> list[VerifyIssue]:
    """A spec path removed from a package.json test script and kept by no added line."""
    issues = []
    for path in changed:
        if not PACKAGE_JSON_RE.search(path):
            continue
        patch = _git(worktree, "diff", base, "-U0", "--", path)
        lines = patch.splitlines()
        gone = [
            match.group(0)
            for line in lines
            if REMOVED_LINE_RE.match(line) and '"test"' in line
            for match in SPEC_IN_TEST_LINE_RE.finditer(line)
        ]
        kept = " ".join(line for line in lines if ADDED_LINE_RE.match(line) and '"test"' in line)
        dropped = [spec for spec in dict.fromkeys(gone) if spec not in kept]
        if dropped:
            issues.append(
                VerifyIssue(
                    FAIL, "weakened-spec-dropped", f"spec removed from {path} test script: {_listed(dropped, 8)}"
                )
            )
    return issues


def _assertion_issues(worktree: Path, base: str, changed: list[str]) -> list[VerifyIssue]:
    """WARN per changed test file whose diff removes more assertion lines than it adds."""
    issues = []
    for path in changed:
        if not TEST_PATH_RE.search(path):
            continue
        lines = _git(worktree, "diff", base, "-U0", "--", path).splitlines()
        removed = sum(1 for line in lines if REMOVED_LINE_RE.match(line) and ASSERTION_RE.search(line))
        added = sum(1 for line in lines if ADDED_LINE_RE.match(line) and ASSERTION_RE.search(line))
        if removed > added:
            issues.append(
                VerifyIssue(
                    WARN,
                    "fewer-assertions",
                    f"{path} has fewer assertion lines than before (-{removed} / +{added}) - read that diff: "
                    "merged asserts are fine, dropped ones are not",
                )
            )
    return issues


def _named_paths(text: str) -> list[str]:
    """Paths the report names: Windows or POSIX absolute ones, and worktree-relative ones."""
    found: list[str] = []
    for token in REPORT_TOKEN_RE.findall(text):
        candidate = token.lstrip("([<\"'`*").rstrip(".,;:]>\"'`*")
        if "://" in candidate or not candidate.lower().endswith(REPORT_SUFFIXES):
            continue
        if re.split(r"[/\\]", candidate)[-1].startswith("."):
            continue  # a bare extension or hidden-file token, not a path the report points at
        if candidate not in found:
            found.append(candidate)
    return found


def _path_exists(token: str, worktree: Path) -> bool:
    if token.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", token):
        return Path(token).exists()
    return (worktree / token).exists()


def _report_issues(
    worktree: Path, report: Path, since: float | None, check_commands: Sequence[str]
) -> list[VerifyIssue]:
    """The report exists, is fresh for this dispatch, names files that exist, and matches the checks."""
    if not report.is_file():
        return [VerifyIssue(FAIL, "report-missing", f"report missing: {report}")]
    issues: list[VerifyIssue] = []
    modified = report.stat().st_mtime
    if since is not None and modified < since:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(modified))
        issues.append(
            VerifyIssue(FAIL, "report-stale", f"report is older than the dispatch ({stamp}) - a previous run's?")
        )
    text = report.read_text(encoding="utf-8", errors="replace")
    missing = [path for path in _named_paths(text) if not _path_exists(path, worktree)]
    if missing:
        issues.append(
            VerifyIssue(FAIL, "report-missing-paths", f"report names files that do not exist: {_listed(missing, 5)}")
        )
    if not check_commands and CLAIM_RE.search(text):
        issues.append(
            VerifyIssue(
                WARN, "report-unchecked-claim", "report claims everything passes but no check command was re-run"
            )
        )
    return issues


def _evidence_issues(evidence: Path, since: float | None) -> list[VerifyIssue]:
    """WARN on missing, stale, suspiciously small or byte-identical screenshots."""
    images = sorted(
        (path for path in evidence.rglob("*") if path.is_file() and path.suffix.lower() in IMAGE_SUFFIXES),
        key=lambda path: str(path),
    )
    issues: list[VerifyIssue] = []
    if not images:
        issues.append(VerifyIssue(WARN, "evidence-empty", f"no screenshots under {evidence}"))
    if since is not None:
        old = [path for path in images if path.stat().st_mtime < since]
        if old:
            issues.append(
                VerifyIssue(
                    WARN,
                    "evidence-old",
                    f"{len(old)} screenshots are older than the dispatch (reused?): {_names(old, 3)}",
                )
            )
    tiny = [path for path in images if path.stat().st_size < SMALL_IMAGE_BYTES]
    if tiny:
        issues.append(
            VerifyIssue(WARN, "evidence-tiny", f"{len(tiny)} very small screenshots (blank/error frame?): {_names(tiny, 3)}")
        )
    by_digest: dict[str, list[Path]] = {}
    for image in images:
        by_digest.setdefault(hashlib.md5(image.read_bytes()).hexdigest(), []).append(image)
    for group in by_digest.values():
        if len(group) > 1:
            issues.append(
                VerifyIssue(WARN, "evidence-duplicate", f"identical images under different names: {_names(group, 4)}")
            )
    return issues


def _tail(text: str) -> str:
    return text[-TAIL_CHARS:]


def _run_checks(worktree: Path, check_commands: Sequence[str]) -> tuple[list[CheckOutcome], list[VerifyIssue]]:
    """Re-run every acceptance command and FAIL the delivery when one no longer passes."""
    outcomes: list[CheckOutcome] = []
    issues: list[VerifyIssue] = []
    for command in check_commands:
        # A check may be compound (`cd x; run y`), so it has to go through the shell.
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=worktree,
            check=False,
        )
        output = _tail((proc.stdout or "") + (proc.stderr or ""))
        outcomes.append(CheckOutcome(command=command, exit_code=proc.returncode, output_tail=output))
        if proc.returncode:
            issues.append(
                VerifyIssue(
                    FAIL,
                    "check-failed",
                    f"re-run failed (exit {proc.returncode}): {command} :: {output}",
                )
            )
    return outcomes, issues


def verify_worker(
    worktree: Path,
    *,
    base: str,
    role: str = "fix",  # "fix" | "test"
    own: Sequence[str] = (),
    report: Path | None = None,
    evidence: Path | None = None,
    since: float | None = None,  # epoch seconds; no freshness check when None
    check_commands: Sequence[str] = (),
    quick: bool = False,  # scope + weakening only
) -> VerifyResult:
    """
    Audit one worker's delivery in `worktree` against `base` and its declared ownership.

    Issues come back in the order the phases run: scope, weakening, CI/deleted/spec/assertions,
    report, evidence, checks.
    """
    if role not in ("fix", "test"):
        raise ValueError(f"unknown worker role: {role}")
    result = VerifyResult()
    committed = _name_lines(_git(worktree, "diff", "--name-only", f"{base}...HEAD"))
    entries = _status_entries(worktree)
    changed = _changed_paths(committed, entries)

    result.issues.extend(_scope_issues(committed, entries, role, own))
    diffs = _diff_files(worktree, base)
    added = [line for path, lines, _removed in diffs if _scannable(path) for line in lines]
    result.issues.extend(_weakening_issues(added))
    result.issues.extend(_ci_issues(changed, own))
    result.issues.extend(_deleted_test_issues(worktree, base))
    result.issues.extend(_spec_dropped_issues(worktree, base, changed))
    result.issues.extend(_assertion_issues(worktree, base, changed))

    if not quick:
        if report is not None:
            result.issues.extend(_report_issues(worktree, report, since, check_commands))
        if evidence is not None:
            result.issues.extend(_evidence_issues(evidence, since))
        outcomes, issues = _run_checks(worktree, check_commands)
        result.checks.extend(outcomes)
        result.issues.extend(issues)
    return result
