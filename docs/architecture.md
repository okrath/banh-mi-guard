# Architectural Specification: Dual-Gate Safety Harness

> 📦 **GitHub Repository:** [github.com/okrath/banh-mi-guard](https://github.com/okrath/banh-mi-guard) &bull; 👤 **Author:** [@okrath](https://github.com/okrath) &bull; 📖 **Live Documentation:** [okrath.github.io/banh-mi-guard](https://okrath.github.io/banh-mi-guard/)

`banh-mi-guard` implements a **Dual-Gate Agentic Architecture** (the Sandwich Pattern) designed to eliminate silent regressions, security violations, and memory leaks when using AI Coding Agents.

---

## 1. System Taxonomy & Separation of Concerns

The architecture separates deterministic checks (no tokens) from the generative final review:

| Component | Nature | Execution Latency | Token Cost | Core Responsibility |
| :--- | :--- | :--- | :--- | :--- |
| **Repository Domain Scorer** | Deterministic signal scoring | <50ms | **0 tokens ($0.00)** | Scores Node dependencies (monorepos included), framework configs, `index.html`, UI files, server/API dirs, language manifests and IaC files to pick frontend / backend / fullstack / infra / mobile. Selects template invariants; the build command is resolved per ecosystem. |
| **Git Diff Inspector & Rulebook** | Deterministic diff measurement and static rules | Sub-50ms (Local) | **0 tokens ($0.00)** | Precise git diff measurement against the base commit recorded at pre, blast-radius enforcement (out-of-scope breach detection), and multi-language deterministic static rules (secrets, SQL injection, XSS, …). |
| **Impact Range** | Whole-repository reference search | <1s | **0 tokens ($0.00)** | At pre: the symbols of the scoped files, the files that reference them, the tests among them and the invariants whose globs match. At post: changed symbols referenced outside that range, and changed symbols no test references (MEDIUM, never blocking; passed to the LLM as evidence). |
| **Alibaba Open Code Review (OCR)** | An LLM review agent that reads the repository (tool calls) | Minutes, no time limit | OCR's own LLM (not guard's) | Optional full review (`guard post --full`, or every post with `guard config ocr always`). A high or critical finding, or OCR not running, blocks. Unchanged files reuse their cached findings. |
| **Agent Hooks** | The agent's own hook system calling `guard agent-event` | <1s per event | **0 tokens ($0.00)** | Enforces the flow where the agent can refuse: an edit before `guard pre` or outside the scope, a stop with unapproved edits, a commit without an approval. Adapters are data (events, payload fields, answers); the gate logic is guard's alone. |
| **Hygiene Engine** | AST & Reference Reachability Scanner | <50ms (Diff) / <2s (Full) | **0 tokens ($0.00)** | Two-tier dead code detection: catches orphan/draft files (DEAD-001), commented-out code blocks (DEAD-002), and AST unreferenced symbols/imports (DEAD-003). |
| **Simplicity Engine** | KISS/YAGNI & Dependency Bloat Scanner | <30ms (Diff) / <2s (Full) | **0 tokens ($0.00)** | Enforces the Ponytail Necessity Ladder: catches redundant packages (LAZY-001), premature abstractions (LAZY-002) and wheel reinventions (LAZY-003). Net LOC is reported, never scored. |
| **Project Invariants** | Regex checks from `guard.invariants.json` | <100ms | **0 tokens ($0.00)** | Project rules evaluated on the current files at pre (baseline) and post. Rules without checks are `UNVERIFIED`; removing or relaxing a rule raises `INV-WEAKENED`. |
| **Removal Reference Check** | Whole-repository search | <1s | **0 tokens ($0.00)** | Removed string keys, exports and CSS classes that are still referenced raise `DEAD-REF`; the summary is passed to the LLM as verified evidence. |
| **Your Configured LLM** | An API (Claude, GPT, DeepSeek, Ollama) or your own agent CLI (`claude`, `codex`) | No time limit (it ends when the LLM answers or fails) | User standard pricing, or your subscription | **Final Safety Gatekeeper**, consulted when no hard block applies. Large diffs are reviewed in parts (one REVISE rejects the whole diff); deleted files are sent as a one-line note. It may propose new invariants, which guard writes to the local `.guard/invariants.json` only after they pass on the current code. If the LLM does not answer, the report says "Heuristic Gate" and records why. |

---

## 2. End-to-End Workflow Pipeline

```text
               [User Task / Issue Prompt]
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. PRE-TASK PHASE: `guard pre "<prompt>"`                   │
│ • Scope declaration & repository domain detection           │
│ • Domain Contract Extractor (FE / BE / Infra / MB)          │
│ • Lock Invariant Rules (Must NOT be broken)                 │
│ ➔ Emits: "### 🔍 PRE-TASK IMPACT NOTE"                      │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼ (AI Coding Agent / Developer modifies code)
                           │
┌─────────────────────────────────────────────────────────────┐
│ 2. POST-TASK PHASE: `guard post`                            │
│ • OCR Inspector (0-cost): Diff audit & blast radius check   │
│ • Static Rulebook: Detect Secrets, SQLi, Memory Leaks, NPE  │
│ • Hygiene Engine: Orphan files, commented code, dead symbols│
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
│ • Technical Audit (Architecture, Memory Leaks, Scope)       │
│ • Cross-Platform UX/UI & Ergonomics Assessment              │
│ • Verdict: [APPROVED] or [REVISE] with Actionable Remediation│
└─────────────────────────────────────────────────────────────┘
```

---

## 3. The Three Defense Layers

### Layer 1: Agent Directives (`CLAUDE.md` & `AGENT.md`)
AI coding agents (Claude Code, Codex, Gemini CLI, opencode, Cursor, omp, Aider) read their instruction files at the start of a session. The directives mandate executing `guard pre` prior to editing and `guard post` upon task completion. `guard install` writes the directives into each installed agent's global instruction file (Claude Code, Codex, Gemini CLI, opencode); `guard install --workspace <dir>` writes them into that folder's `CLAUDE.md`/`AGENT.md` for agents without a global file. The first guard run in a repository then sets it up without creating a repository diff (local, Git-excluded invariants file; a hook only inside `.git`).

### Layer 2: Git Hook Defense (`pre-commit`)
The Git `pre-commit` hook runs `guard post --hook` on every commit. Without a guard session it skips. With an unfinished or rejected session it runs the full verification pipeline and aborts the commit on failure. With an approved session it passes only when every changed file matches the approved content fingerprints, so later or unrelated edits cannot ride on an old approval. Repository-local hooks (including in linked worktrees) still run first. Guard never edits hooks kept in the repository tree (e.g. `.husky/`); `guard doctor` shows the line to add there.

### Layer 3: Process Harness Wrapper (`guard run`)
For external CI/CD pipelines or headless scripts, `guard run "<prompt>" -- <command>` enforces the complete sandwich sequence as a single atomic process.

---
*Created and maintained by [@okrath](https://github.com/okrath) &mdash; Source code available at [github.com/okrath/banh-mi-guard](https://github.com/okrath/banh-mi-guard).*
