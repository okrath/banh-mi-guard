"""
Hook Script Templates for Git and AI Coding Agents.
"""

# Shared prelude: a global core.hooksPath hides each repository's own hooks, so run them first.
# --git-common-dir (not --git-dir) so linked worktrees find the main repository's hooks.
# A repo-local guard hook is skipped (it would run guard twice) but its .guard.bak original is run;
# so is one written by guard <= 0.10 (LAYA-OCR-GUARD: an old banner, a second post, a commit trailer).
_CHAIN_LOCAL_HOOKS = """SELF_DIR="$(cd "$(dirname "$0")" && pwd -P)"
HOOK_NAME="$(basename "$0")"
LOCAL_DIR="$(cd "$(git rev-parse --git-common-dir 2>/dev/null)/hooks" 2>/dev/null && pwd -P)"
if [ -n "$LOCAL_DIR" ] && [ "$LOCAL_DIR" != "$SELF_DIR" ] && [ -x "$LOCAL_DIR/$HOOK_NAME" ] \\
   && ! grep -qE "BANH-MI-GUARD|LAYA-OCR-GUARD" "$LOCAL_DIR/$HOOK_NAME"; then
  "$LOCAL_DIR/$HOOK_NAME" "$@" || exit $?
fi
if [ -n "$LOCAL_DIR" ] && [ -x "$LOCAL_DIR/$HOOK_NAME.guard.bak" ] \\
   && ! grep -q "LAYA-OCR-GUARD AUTO-GENERATED HOOK\\|LAYA-OCR-GUARD COMMIT MSG HOOK" "$LOCAL_DIR/$HOOK_NAME.guard.bak"; then
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

Every AI coding agent working in this repository runs both gates through its shell tool:

1. **Before the first edit:** `guard pre "<user request>" --scope <path/glob>` (repeatable), then read `.guard/PRE_TASK_NOTE.md` for the locked invariants and present it as the PRE-TASK IMPACT NOTE. File names in the request also count as scope.
2. **After the edits:** `guard post`. On REVISE, fix the listed blocking findings and run it again.

**Gate rules:**
- `guard pre` needs a clean tree; `--allow-dirty` keeps unrelated changes (the report flags each one). Restart an unfinished or rejected session with `--force`: it keeps the original baseline, base commit and scope, and files covered only by scope added in the restart fail as SCOPE-004. Without a scope, the post report says scope was not audited.
- Invariants come from the team's `guard.invariants.json` (change it only when the task asks) and the local, Git-excluded `.guard/invariants.json` (rules the LLM gate learns). `checks`: `{"files": glob, "forbid"|"require": regex}`; `guard invariants check` validates them; invariants without checks are UNVERIFIED and must be verified manually. Never remove or relax an invariant unless the task asks for it and declares the file in `--scope`.
- Keep guard invisible: never mention guard, its gates, verdicts or scores in commit messages, PR descriptions, branch names or code comments, and never commit only guard files. Never add a `guard-allow` comment yourself: report the violation and let the user decide. Guard results go in your reply.
- Only critical/high correctness or security findings, or a violated requirement quoted from the task, block; the rest are advisory. A finding you will not fix now: `guard finding <id> --defer "<reason>"` (or `--reject "<evidence>"`). When post reports `needs_user`, stop and ask the user: only they decide, with `guard accept` in their own terminal.
- After a plain `guard post` is approved and before committing, ask the question the report's **Commit** line gives (a full OCR review with `guard post --full`, a review panel with `--reviewers 3`, or both) and run what the user chooses; if they want neither, the approval is enough. OCR failing or a high/critical OCR finding blocks. Run it directly when they ask for a full or deep review; with `guard config ocr always` on, do not ask.
- Commit messages follow the **Commit** line: mode `auto`, you write it; mode `ask`, you ask the user and use it as given; unset, ask which mode they want and run `guard config commit auto|ask`.
- Where guard's hooks run for your agent (`guard agent add <agent>`; `guard agent list` shows them), they refuse an unapproved commit, an edit before `guard pre` or outside the scope, and a stop with unapproved edits, or report them right after where the agent cannot refuse (`guard doctor` says which). Do what the reason says. Without hooks, these rules are the only gate.
- Guard never edits repository files: when `guard doctor` says one needs a change, tell the user instead.
- Name the gate that ran: "LLM Gate" only when the LLM answered, otherwise "Heuristic Gate" plus the reason.

**Necessity ladder** (before any new function or file): avoid the code if you can (YAGNI), reuse what exists, prefer the standard library and native APIs, never install a package unless asked, and keep it simple: no interfaces, factories or classes for trivial logic.

**Reply format:**

```markdown
### 🔍 PRE-TASK IMPACT NOTE:
* **Current Baseline:** [existing behavior and contracts]
* **Expected Impact Range:** [files and components to change]
* **Locked Invariants:** [constraints that must not break]

(minimal, scoped changes)

### 🧪 POST-TASK VERIFICATION:
* **Actual Impact Range:** [modified files]
* **Build Check:** [build and test results from guard post]
* **LLM Gate Verdict:** [APPROVED or REVISE]
```
"""
