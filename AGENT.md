<!-- === BANH-MI-GUARD DUAL-GATE HOOK: START === -->
# 🛡️ MANDATORY PROTOCOL: BANH-MI-GUARD DUAL-GATE HOOK

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
- `guard post --full` adds the Alibaba OCR review (it reads the repository and takes minutes; OCR failing or a high/critical finding blocks). After a plain `guard post` is approved, and before committing, ask the user the question the report's **Commit** line gives (a full OCR review, a review panel with `--reviewers 3`, or both) and run what they choose; if they want neither, the gate approval is enough. Run it directly when the user asks for a full or deep review.
- The gate decides from structured findings: only critical/high correctness or security findings, or a violated requirement quoted from the task, block; the rest are advisory follow-ups. A finding you will not fix now: `guard finding <id> --defer "<reason>"` (or `--reject "<evidence>"`). When post reports `needs_user`, stop and ask the user: only they decide, with `guard accept` in their own terminal.
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
<!-- === BANH-MI-GUARD DUAL-GATE HOOK: END === -->
