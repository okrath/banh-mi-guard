"""
Deterministic check for removals that a compiler cannot see.

String-keyed lookups (`case 'edit':` in an icon switch), exported functions/constants and CSS
classes can be deleted while something still uses them at runtime. For every such symbol
removed by the diff, search the current repository: a symbol that is no longer defined but is
still referenced is a likely runtime break. The summary is also handed to the LLM reviewer as
evidence, because a batched review cannot see references that live in another diff part.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

from guard.core.ocr_engine import RuleViolation

CODE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".py")
STYLE_EXTS = (".css", ".scss", ".sass", ".less")

REMOVED_KEY = re.compile(r"""^-\s*case\s+['"]([\w\-.:]+)['"]\s*:""")
REMOVED_EXPORT = re.compile(r"""^-\s*export\s+(?:default\s+)?(?:async\s+)?(?:function\*?|const|let|var|class|enum|interface|type)\s+([A-Za-z_$][\w$]*)""")
REMOVED_CSS_CLASS = re.compile(r"""\.(-?[A-Za-z_][\w-]*)""")


def _collect_removed(raw_diff: str) -> Dict[str, Tuple[str, str]]:
    """name -> (kind, file) for every key/export/CSS class on a removed line."""
    removed: Dict[str, Tuple[str, str]] = {}
    current = ""
    for line in raw_diff.splitlines():
        if line.startswith("--- "):
            continue
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else ""
            continue
        if line.startswith("diff --git "):
            m = re.search(r" b/(.+)$", line)
            current = m.group(1) if m else ""
            continue
        if not line.startswith("-") or not current:
            continue
        if current.endswith(STYLE_EXTS):
            selector = line[1:].split("{", 1)[0]
            if "{" in line or selector.rstrip().endswith(","):
                for name in REMOVED_CSS_CLASS.findall(selector):
                    removed.setdefault(name, ("css-class", current))
            continue
        m = REMOVED_KEY.match(line)
        if m:
            removed.setdefault(m.group(1), ("string-key", current))
            continue
        m = REMOVED_EXPORT.match(line)
        if m:
            removed.setdefault(m.group(1), ("export", current))
    return removed


def _repo_files(repo_path: Path) -> List[Path]:
    res = subprocess.run(
        ["git", "-C", str(repo_path), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    if res.returncode != 0:
        raise OSError(f"git ls-files failed (exit code {res.returncode}): {res.stderr or ''}".strip())
    names = [n for n in (res.stdout or "").split("\0") if n]
    return [repo_path / n for n in names if n.endswith(CODE_EXTS + STYLE_EXTS) and (repo_path / n).is_file()]


def check_removed_symbols(repo_path: Path, raw_diff: str) -> Tuple[List[RuleViolation], str]:
    removed = _collect_removed(raw_diff)
    if not removed:
        return [], ""
    try:
        files = _repo_files(repo_path)
    except (subprocess.SubprocessError, OSError) as e:
        origin = next(iter(removed.values()))[1]
        violation = RuleViolation(
            rule_id="DEAD-REF-UNVERIFIED",
            severity="HIGH",
            file_path=origin,
            message="could not verify removed-symbol references",
        )
        return [violation], "could not verify removed-symbol references"

    texts = {}
    violations: List[RuleViolation] = []
    for f in files:
        try:
            texts[f.relative_to(repo_path).as_posix()] = f.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            violations.append(RuleViolation(
                rule_id="DEAD-REF-UNREADABLE",
                severity="HIGH",
                file_path=f.relative_to(repo_path).as_posix(),
                message=f"Removal check could not read `{f.relative_to(repo_path).as_posix()}` to verify references: {e}",
            ))
    counts: Dict[str, int] = {}
    for name, (kind, origin) in sorted(removed.items()):
        counts[kind] = counts.get(kind, 0) + 1
        esc = re.escape(name)
        if kind == "string-key":
            defined_rx = re.compile(rf"""case\s+['"]{esc}['"]\s*:""")
            ref_rx = re.compile(rf"""['"`]{esc}['"`]""")
        elif kind == "export":
            defined_rx = re.compile(rf"""(?:function\*?|const|let|var|class|enum|interface|type)\s+{esc}\b""")
            ref_rx = re.compile(rf"""(?<![\w$.]){esc}(?![\w$])""")
        else:
            defined_rx = re.compile(rf"""\.{esc}(?![\w-])""")
            ref_rx = re.compile(rf"""(?<![\w-]){esc}(?![\w-])""")

        style_only = kind == "css-class"
        defined = any(
            defined_rx.search(t) for p, t in texts.items()
            if (p.endswith(STYLE_EXTS) if style_only else not p.endswith(STYLE_EXTS))
        )
        if defined:
            continue
        refs = [
            f"{p}:{t.count(chr(10), 0, m.start()) + 1}"
            for p, t in texts.items() if not p.endswith(STYLE_EXTS)
            for m in [ref_rx.search(t)] if m
        ]
        if refs:
            violations.append(RuleViolation(
                rule_id="DEAD-REF",
                severity="HIGH",
                file_path=origin,
                message=f"Removed {kind} `{name}` is no longer defined but still referenced at {', '.join(refs[:5])}.",
            ))

    kinds = ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))
    dead_refs = [v for v in violations if v.rule_id == "DEAD-REF"]
    broken = ", ".join(f"`{v.message.split('`')[1]}`" for v in dead_refs if "`" in v.message) or "none"
    read_errs = [v for v in violations if v.rule_id == "DEAD-REF-UNREADABLE"]
    err_note = f"; unreadable files: {len(read_errs)}" if read_errs else ""
    summary = (
        f"Removed-symbol reference check (deterministic, whole repository): removed {kinds}; "
        f"removed and still referenced without a definition: {broken}{err_note}."
    )
    return violations, summary
