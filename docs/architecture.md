# Architectural Specification: Dual-Gate Safety Harness

> 📦 **GitHub Repository:** [github.com/okrath/banh-mi-guard](https://github.com/okrath/banh-mi-guard) &bull; 👤 **Author:** [@okrath](https://github.com/okrath) &bull; 📖 **Live Documentation:** [okrath.github.io/banh-mi-guard](https://okrath.github.io/banh-mi-guard/)

`banh-mi-guard` implements a **Dual-Gate Agentic Architecture** (the Sandwich Pattern) that checks changes made with AI coding agents for regressions, scope violations and the security patterns its rules know.

---

## 1. System Taxonomy & Separation of Concerns

The architecture separates deterministic checks (no tokens) from the generative final review:

| Component | Nature | Execution Latency | Token Cost | Core Responsibility |
| :--- | :--- | :--- | :--- | :--- |
| **Repository Domain Scorer** | Deterministic signal scoring | <50ms | **0 tokens ($0.00)** | Scores Node dependencies (monorepos included), framework configs, `index.html`, UI files, server/API dirs, language manifests and IaC files to pick frontend / backend / fullstack / infra / mobile. Selects template invariants; the build command is resolved per ecosystem. |
| **Git Diff Inspector & Rulebook** | Deterministic diff measurement and static rules | Sub-50ms (Local) | **0 tokens ($0.00)** | Precise git diff measurement against the base commit recorded at pre, blast-radius enforcement (out-of-scope breach detection), and multi-language deterministic static rules (secrets, SQL injection, XSS, …); memory leaks, null dereferences, and blocking calls are checked by the LLM review in every language. Propagates diff and snapshot inspection errors to force revision (see [Quality Pillars: Scoring](quality-pillars.md#scoring-and-the-final-verdict)). |
| **Impact Range** | Whole-repository reference search | <1s | **0 tokens ($0.00)** | At pre: the symbols of the scoped files, the files that reference them, the tests among them and the invariants whose globs match. At post: changed symbols referenced outside that range, and changed symbols no test references (MEDIUM, never blocking; passed to the LLM as evidence). |
| **Alibaba Open Code Review (OCR)** | An LLM review agent that reads the repository (tool calls) | Minutes, no time limit | OCR's own LLM (not guard's) | Optional full review (`guard post --full`, or every post with `guard config ocr always`). A high or critical finding, or OCR not running, blocks. Unchanged files reuse their cached findings. |
| **Agent Hooks** | The agent's own hook system calling `guard agent-event` | <1s per event | **0 tokens ($0.00)** | Enforces the flow where the agent can refuse: an edit before `guard pre` or outside the scope, a stop with unapproved edits, a commit without an approval. Adapters are data (events, payload fields, answers); the gate logic is guard's alone. Events carry the agent's session id: the session that ran `guard pre` owns the task, and another agent session in the same working tree is judged on its own work only. |
| **Hygiene Engine** | Reference Reachability Scanner | <50ms (Diff) / <2s (Full) | **0 tokens ($0.00)** | Dead code detection: catches orphan/draft files (DEAD-001); commented-out code, unused imports and private functions are checked by the LLM review in every language. |
| **Simplicity Engine** | KISS/YAGNI & Dependency Bloat Scanner | <30ms (Diff) / <2s (Full) | **0 tokens ($0.00)** | Checks the necessity ladder: catches redundant packages (LAZY-001); premature abstractions and wheel reinventions are checked by the LLM review in every language. Net LOC is reported, never scored. |
| **Project Invariants** | Regex checks from `guard.invariants.json` | <100ms | **0 tokens ($0.00)** | Project rules evaluated on the current files at pre (baseline) and post. Rules without checks are `UNVERIFIED`; removing or relaxing a rule raises `INV-WEAKENED`. |
| **Removal Reference Check** | Whole-repository search | <1s | **0 tokens ($0.00)** | Removed string keys, exports and CSS classes that are still referenced raise `DEAD-REF`; the summary is passed to the LLM as verified evidence. |
| **Your Configured LLM** | An API (Claude, GPT, DeepSeek, Ollama) or your own agent CLI (`claude`, `codex`, `omp`), which then also answers Alibaba OCR through a local endpoint, falling back to OCR's delegation mode (its rules and the diff in one prompt per rule group) when that does not run | No time limit (it ends when the LLM answers or fails) | User standard pricing, or your subscription | **Final Safety Gatekeeper**, consulted when no hard block applies. Large diffs are reviewed in parts (one REVISE rejects the whole diff); deleted files are sent as a one-line note. It may propose new invariants, which guard writes to the local `.guard/invariants.json` only after they pass on the current code. If the LLM does not answer, the report says "Heuristic Gate (no LLM review)" and why. |

---

## 2. End-to-End Workflow Pipeline

```text
               [User Task / Issue Prompt]
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. PRE-TASK PHASE: `guard pre "<prompt>"`                   │
│ • Scope declaration & repository domain detection           │
│ • Contract hints (keyword scan of up to 5 scoped files)     │
│ • Lock Invariant Rules (Must NOT be broken)                 │
│ ➔ Emits: "### 🔍 PRE-TASK IMPACT NOTE"                      │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼ (AI Coding Agent / Developer modifies code)
                           │
┌─────────────────────────────────────────────────────────────┐
│ 2. POST-TASK PHASE: `guard post`                            │
│ • Diff Inspector (0-cost): Diff audit & blast radius check  │
│ • Static rules: secrets, injection, XSS, infra, UX         │
│ • Hygiene Engine: Orphan files, referenced removals        │
│ • Project Health Check: Automated compile & test execution  │
│ • Invariant checks (0-cost): guard.invariants.json rules    │
│ ➔ Compiles: "### 🧪 POST-TASK VERIFICATION"                 │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. FINAL SAFETY GATE: YOUR CONFIGURED LLM                   │
│ (Claude / GPT / DeepSeek / Ollama / OpenAI-compatible)      │
│ • Reviews the report, verified evidence & batched diff      │
│ • Technical Audit (architecture, memory, nulls, scope)      │
│ • Cross-Platform UX/UI & Ergonomics Assessment              │
│ • Verdict: [APPROVED] or [REVISE] with Actionable Remediation│
└─────────────────────────────────────────────────────────────┘
```


### The review inside step 3

The final gate runs these stages in order. The checks, partitioning, single review and coverage notes (stages 1, 2, 4 and 6) are the default path; the additions of stage 3, the panel of stage 4 and the validation of stage 5 are opt-in, because they cost LLM calls or lengthen the prompt; flags, config keys, defaults and call costs are owned by [CLI Reference: Review Options, Stages & Limits](cli-reference.md#review-options-stages--limits), and the code is in `guard/core/llm_reviewer.py`.

1. **Hard blockers first.** A failed build, a violated invariant, a CRITICAL rule and the other outright blockers reject before any LLM is asked (see [Quality Pillars: Scoring](quality-pillars.md#scoring-and-the-final-verdict)).
2. **Partitioning.** The diff is split on file boundaries into parts that fit one request. Assets, lockfiles and images are not sent, deleted files are sent as a one-line note, and parts beyond the part limit are cut. Everything left out is remembered so the report can say so.
3. **Evidence and prompt additions.** Optional test-quality evidence (facts about changed tests), an optional test-quality checklist, and an optional threat frame: a deterministic scan for security-sensitive surface that, only when it triggers, adds an adversarial instruction and asks for a threat model. Evidence is stated as fact; the reviewer judges it.
4. **Review.** One reviewer reads each part (default), or an optional panel of independent lenses reads every part and replaces that single review.
5. **Finding validation.** Optional. A blocking finding of a multi-part diff can be demoted to advisory, only when a verbatim line of the diff disproves it. This is the only stage that can weaken a blocking finding, and it fails safe: on any error, timeout or missing evidence the finding stays as it was.
6. **Coverage notes.** What the review did not see (cut parts, skipped files, omitted deletions, what the reviewer did not trace, a panel or validation that could not run) is reported under *Not reviewed / limits*, and an approval says it covers only what the review saw.

None of these options changes the OCR setting or `--full`; they apply to the LLM gate only. The `bench/` directory is a developer tool for measuring them; see [Benchmark](benchmark.md).

---

## 3. The Three Defense Layers

### Layer 1: Agent Directives (`CLAUDE.md` & `AGENT.md`)
AI coding agents (Claude Code, Codex, Gemini CLI, opencode, Cursor, omp, Aider) read their instruction files at the start of a session. The directives mandate executing `guard pre` prior to editing and `guard post` upon task completion. `guard install` writes the directives into each installed agent's global instruction file (Claude Code, Codex, Gemini CLI, opencode); `guard install --workspace <dir>` writes them into that folder's `CLAUDE.md`/`AGENT.md` for agents without a global file. The first guard run in a repository then sets it up without creating a repository diff (local, Git-excluded invariants file; a hook only inside `.git`).

### Layer 2: Agent Tool Interception & Hook Adapters
Agent hook adapters intercept agent operations directly where the agent supports refusal:
* **Tool-level protection & tamper detection:** Blocks edit tools (`edit`, `write`, `multiedit`, `notebookedit`) targeting `.guard/` or files outside declared scope, and warns on shell modifications to `.guard/session.json` (see [Security Model & State Integrity](#4-security-model--state-integrity)).
* **Stop protection:** Refuses agent completion when edits remain unapproved.
* **Repository targeting:** Each event is checked against the repository it acts in, not only the folder the agent runs in. A commit is checked in its target repository (`git -C <dir> commit`, `cd <dir> && git commit`, `Set-Location <dir>; git commit`), edits are grouped by the repository of each file, and shell commands, stops and prompts are checked in the working repository plus the worktrees this agent session has touched. A command shape guard cannot read with certainty falls back to the working repository; the Git pre-commit hook below covers what remains.
* **Multi-session isolation:** Sessions are tracked per conversation; sibling agents in the same repository are isolated and guided toward Git worktrees.

### Layer 3: Git Hook Defense (`pre-commit`) & Cryptographic Verification
The Git `pre-commit` hook runs `guard post --hook` on every commit. Without a guard session it skips. With an unfinished or rejected session it runs the full verification pipeline and aborts the commit on failure. With an approved session it passes only when every changed file matches the approved content fingerprints and the approval carries a valid HMAC-SHA256 signature (see [Security Model & State Integrity](#4-security-model--state-integrity)), so later, unrelated or unsigned edits cannot ride on an old approval. Repository-local hooks (and an existing hook kept as `.guard.bak`) still run first, including from linked worktrees. Guard never edits hooks kept in the repository tree (e.g. `.husky/`); `guard doctor` shows the line to add there.

### Layer 4: Process Harness Wrapper (`guard run`)
For external CI/CD pipelines or headless scripts, `guard run "<prompt>" -- <command>` enforces the complete sandwich sequence as a single atomic process.

---

## 4. Security Model & State Integrity

Banh-Mi-Guard enforces strict boundaries to protect repository integrity and prevent AI agents from bypassing review:

1. **Non-Invasive Repository State:** Guard never creates a diff in your repository or pollutes Git tracking. Inside a repository it writes only where Git tracks nothing: the `.git` directory and the `.guard/` folder, which it keeps out of Git through `.git/info/exclude` (never `.gitignore`). Repository files like agent docs and invariants are read-only for guard unless explicitly modified by user commands.
2. **Approval Signature Verification:** Approved sessions are signed using HMAC-SHA256 over canonical representations of the repository path, session ID, and approved file fingerprints. The private key lives in `$GUARD_HOME/approval.key` (default `~/.guard/approval.key`, 32 bytes, created atomically on first use with mode 0600 on POSIX). Unsigned approvals from older versions or tampered sessions cannot be committed by agents or Git hooks and must post again.
3. **Internal State Protection:** Agents cannot write to or tamper with `.guard/` files using automated editing tools (`Guard: guard's state is written only by guard commands.`). Shell commands modifying `session.json` trigger warnings, and commits require an HMAC-verified approval record.
4. **Error Propagation (Diff & Snapshot Integrity):** Failures in Git diff inspection or snapshot computation surface in `diff_summary.error` and trigger a `REVISE` verdict (see [Quality Pillars: Scoring and the final verdict](quality-pillars.md#scoring-and-the-final-verdict)), preventing broken Git states from falsely passing verification.

---
*Created and maintained by [@okrath](https://github.com/okrath) &mdash; Source code available at [github.com/okrath/banh-mi-guard](https://github.com/okrath/banh-mi-guard).*
