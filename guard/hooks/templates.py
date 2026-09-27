"""
Hook Script Templates for Git and AI Coding Agents.
"""

# Shared prelude: a global core.hooksPath hides each repository's own hooks, so run them first.
# --git-common-dir (not --git-dir) so linked worktrees find the main repository's hooks.
# A repo-local guard hook is skipped (it would run guard twice) but its .guard.bak original is run.
_CHAIN_LOCAL_HOOKS = """SELF_DIR="$(cd "$(dirname "$0")" && pwd -P)"
HOOK_NAME="$(basename "$0")"
LOCAL_DIR="$(cd "$(git rev-parse --git-common-dir 2>/dev/null)/hooks" 2>/dev/null && pwd -P)"
if [ -n "$LOCAL_DIR" ] && [ "$LOCAL_DIR" != "$SELF_DIR" ] && [ -x "$LOCAL_DIR/$HOOK_NAME" ] \\
   && ! grep -q "BANH-MI-GUARD" "$LOCAL_DIR/$HOOK_NAME"; then
  "$LOCAL_DIR/$HOOK_NAME" "$@" || exit $?
fi
if [ -n "$LOCAL_DIR" ] && [ -x "$LOCAL_DIR/$HOOK_NAME.guard.bak" ]; then
  "$LOCAL_DIR/$HOOK_NAME.guard.bak" "$@" || exit $?
fi
"""

# Git pre-commit hook: runs guard post to verify build, blast radius, and invariants before allowing commit
GIT_PRE_COMMIT_HOOK = """#!/usr/bin/env sh
# --- BANH-MI-GUARD AUTO-GENERATED HOOK ---
""" + _CHAIN_LOCAL_HOOKS + """if ! command -v guard >/dev/null 2>&1; then
  echo "⚠️  Banh-Mi-Guard: 'guard' is not on PATH, skipping guard check."
  exit 0
fi
echo "🛡️  Running Banh-Mi-Guard Pre-Commit Check..."
# --hook: skipped without a guard session, or when the changes are exactly what was last approved
guard post --hook
STATUS=$?
if [ $STATUS -ne 0 ]; then
  echo "❌ Guard Verification FAILED! Commit aborted."
  echo "💡 Tip: Review the violations above or run 'guard post' manually."
  exit 1
fi
echo "✅ Guard Verification PASSED. Proceeding with commit."
exit 0
"""

# Git prepare-commit-msg hook template
GIT_PREPARE_COMMIT_MSG_HOOK = """#!/usr/bin/env sh
# --- BANH-MI-GUARD COMMIT MSG HOOK ---
""" + _CHAIN_LOCAL_HOOKS + """exit 0
"""

# Agent wrapper script template (for command line harness execution)
# Extra pre-task flags (e.g. --scope src/ui --force) are passed through GUARD_PRE_ARGS.
AGENT_WRAPPER_SCRIPT = """#!/usr/bin/env sh
# --- BANH-MI-GUARD AGENT HARNESS ---
PROMPT="$1"
shift

echo "🛡️  [1/3] Triggering Pre-Task Guard..."
# shellcheck disable=SC2086
guard pre "$PROMPT" $GUARD_PRE_ARGS || exit 1

echo "🤖 [2/3] Executing Agent Command: $*"
"$@"
CMD_STATUS=$?

echo "🧪 [3/3] Triggering Post-Task Guard..."
guard post
POST_STATUS=$?

if [ $CMD_STATUS -ne 0 ]; then
  exit $CMD_STATUS
fi
exit $POST_STATUS
"""

# Agent Instruction Directive Template for CLAUDE.md & AGENT.md (Auto-consumed by omp, Claude Code, Cursor, Windsurf)
AGENT_DIRECTIVES_TEMPLATE = """# 🛡️ MANDATORY PROTOCOL: BANH-MI-GUARD DUAL-GATE HOOK

This document establishes **Mandatory Operational Directives** for any AI Coding Agent (`omp`, Claude Code, Cursor, Windsurf, Aider) working in this repository.

To strictly prevent regressions, feature breakage, and unintended code loss, **AI AGENTS MUST EXECUTE BOTH HOOK PHASES VIA THE BASH TOOL**:

```text
[Incoming Task / Bugfix Request]
             │
             ▼
┌────────────────────────────────────────────────────────┐
│ 1. PRE-TASK HOOK (MANDATORY BEFORE TOUCHING ANY CODE): │
│ • Run: `guard pre "<user_request>" --scope <path/glob>`│
│ • Read: `.guard/PRE_TASK_NOTE.md` to learn Invariants  │
│ • Present format: ### 🔍 PRE-TASK IMPACT NOTE          │
└────────────────────────────────────────────────────────┘
             │
             ▼ (Agent performs minimal, scoped, precise code edits)
             │
┌────────────────────────────────────────────────────────┐
│ 2. POST-TASK HOOK (MANDATORY AFTER FINISHING EDITS):   │
│ • Run: `guard post`                                    │
│ • Verify build check, OCR diff rules & LLM Gate verdict│
│ • If REVISE: Self-heal and fix listed violations       │
│ • Present format: ### 🧪 POST-TASK VERIFICATION       │
└────────────────────────────────────────────────────────┘
```

**Gate rules:**
- Run `guard pre` on a clean working tree, before the first edit. It refuses a dirty tree unless `--allow-dirty` (for unrelated work that must stay; the report flags every pre-existing change). An unfinished or rejected session can only be restarted with `--force`: the restart keeps the original baseline, base commit and scope, is recorded in the report, and files covered only by scope added in the restart fail as SCOPE-004.
- Declare scope with file names in the request or `--scope` (repeatable, globs allowed). Without a scope, the post report says scope was not audited.
- Project invariants come from `guard.invariants.json` in the repository root (the team's file; add or change it only when the task asks for it) and the local, Git-excluded `.guard/invariants.json` (guard's own; rules the LLM gate learns go there). `checks`: `{"files": glob, "forbid"|"require": regex}`. `guard invariants check` validates them. Invariants without checks are UNVERIFIED and must be verified manually. Never remove or relax an invariant unless the task explicitly asks for it and declares the file in `--scope`.
- Guard stays invisible in the user's work. Never mention guard, its gates, verdicts or scores in commit messages, PR descriptions, branch names or code comments, and never make a commit only for guard files. Never add a `guard-allow` comment yourself: report the violation and let the user decide. Guard results go in your reply to the user.
- `guard post --full` adds the Alibaba OCR review (it reads the repository and takes minutes; OCR failing or a high/critical finding blocks). After a plain `guard post` is approved, and before committing, ask the user whether they want that full review; run it if they say yes, otherwise the gate approval is enough. Run it directly when the user asks for a full or deep review.
- Commit messages follow the **Commit** line of the post report: in mode `auto` you write the message, in mode `ask` you ask the user for it and use it as given. When the mode is not set, ask the user which one they want and run `guard config commit auto` or `guard config commit ask`.
- Guard never edits repository files. When `guard doctor` reports that a repository file (agent doc, hook kept in the tree) needs a change, tell the user instead of editing it as a side effect.
- The report names the gate that actually ran: "LLM Gate" only when the LLM answered, otherwise "Heuristic Gate" plus the reason.

---

### 🛋️ THE EFFICIENT LAZINESS PRINCIPLE (KISS & YAGNI — THE NECESSITY LADDER):
*"The least buggy code is the code that is never written."*

Before writing any new function or creating a new file, the Agent **MUST** climb the necessity ladder:
1. **[YAGNI]** Is this code truly necessary? Deleting or avoiding code is always better than adding code.
2. **[Reuse]** Inspect the existing codebase thoroughly to reuse existing functions/components (avoid reinventing the wheel).
3. **[Standard Library & Native APIs]** Prefer stdlib (Python) or runtime native APIs (Browser/Node: fetch, crypto, Intl).
4. **[Installed Dependencies]** NEVER arbitrarily install new npm/pip packages unless explicitly requested.
5. **[KISS / 1-liner]** Favor concise, straightforward solutions. Do NOT introduce bloated interfaces, factories, or classes for trivial logic.

---

### 📐 MANDATORY AGENT REPORTING FORMAT:

When replying to the user, the Agent must strictly structure the response:

```markdown
### 🔍 PRE-TASK IMPACT NOTE:
* **Current Baseline:** [Brief summary of existing functionality and contracts]
* **Expected Impact Range:** [List of files and components to be modified]
* **Locked Invariants:** [Technical constraints that must NOT be broken]

---
(Implementation content: clean, minimal, scoped code modifications)
---

### 🧪 POST-TASK VERIFICATION:
* **Actual Impact Range:** [Confirmed list of modified files]
* **Build Check:** [Automated compilation & test results from guard post]
* **LLM Gate Verdict:** [APPROVED or REVISE]
```
"""
