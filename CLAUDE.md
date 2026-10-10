<!-- === BANH-MI-GUARD DUAL-GATE HOOK: START === -->
# 🛡️ MANDATORY PROTOCOL: BANH-MI-GUARD DUAL-GATE HOOK

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
<!-- === BANH-MI-GUARD DUAL-GATE HOOK: END === -->
