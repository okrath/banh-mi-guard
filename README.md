# Banh Mi Guard (`guard`)

<p align="center">
  <img src="docs/assets/logo.svg" width="160" height="160" alt="Banh Mi Guard Logo - The Bánh Mì Sandwich Pattern">
  <br>
  <strong>Dual-Gate Impact Analysis & Regression Guard for AI-Assisted Development</strong>
  <br>
  <em>Enforcing the Sandwich Pattern with scope control, deterministic diff auditing, project invariants and LLM gatekeeping.</em>
</p>

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Documentation](https://img.shields.io/badge/docs-live_website-brightgreen.svg)](https://okrath.github.io/banh-mi-guard/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#-cross-platform-installation-windows-linux-macos)
[![Architecture](https://img.shields.io/badge/architecture-Dual--Gate-green.svg)](#-three-pillar-architecture)

**Dual-Gate Impact Analysis & Regression Guard for AI-Assisted Development.**

📖 **Live Documentation & Interactive Guide:** [https://okrath.github.io/banh-mi-guard/](https://okrath.github.io/banh-mi-guard/)

`guard` wraps coding workflows in an automated safety harness by uniting three distinct pillars:
1. **Deterministic gates** (0 token): declared scope, base-commit diff audit, build/test command, project invariants (`guard.invariants.json`) and removed-symbol reference checks
2. **Alibaba Open Code Review - OCR** (optional full review: `guard post --full` adds an LLM code review of the task's changes that reads the repository; it uses your configured LLM, costs tokens and takes minutes)
3. **Your Configured LLM** (Claude, GPT, DeepSeek, Ollama...): Acting as the Architectural Brain & **Final Safety Gatekeeper**.

Automates and enforces the rigorous **Impact & Regression Protocol** pioneered in `oh-my-ainovel`.

---

## 🏛️ Three-Pillar Architecture

> 🥖 **The Bánh Mì Sandwich Pattern:**
> Just like a crisp Vietnamese Bánh Mì, `guard` sandwiches code modifications between two protective crusts:
> * **Top Crust (`guard pre`):** Scope declaration, baseline snapshot, invariant locking & domain contract extraction.
> * **Core Filling (Developer / AI Agent edits):** Safe, scoped code implementation within contract boundaries.
> * **Bottom Crust (`guard post`):** Deterministic diff blast-radius audit, built-in static rulebook, Alibaba OCR review (with `--full`), project build/test command, `guard.invariants.json` checks, and LLM Gatekeeper approval.

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
│ • Diff Inspector (0-cost): Diff audit & blast radius check  │
│ • Static Rulebook: Detect Secrets, SQLi, Memory Leaks, NPE  │
│ • Alibaba OCR (LLM, --full): Reviews the task's changes     │
│ • Hygiene Engine (0-cost): Detects orphan files & dead code │
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

## 🚀 Cross-Platform Installation (Windows, Linux, macOS)

Install the `guard` CLI globally on any platform using one of the following methods:

### Method 1: Install directly from GitHub (Recommended)
```bash
# On Linux / macOS (Recommended with pipx for isolated global binary):
pipx install git+https://github.com/okrath/banh-mi-guard.git

# Or with standard pip across all platforms (Windows / Linux / macOS):
pip install git+https://github.com/okrath/banh-mi-guard.git
```

### Method 2: Clone repository & install in editable mode
```bash
git clone https://github.com/okrath/banh-mi-guard.git
cd banh-mi-guard
pip install -e .
```

### 💡 Environment `$PATH` Setup:
* **Windows**: `guard.exe` is automatically installed into `Python3xx\Scripts\guard.exe`.
* **Linux / macOS**: The `guard` executable lives in `~/.local/bin/guard` or `/usr/local/bin/guard`.  
  If your terminal displays `command not found: guard`, add it to your shell configuration:
  ```bash
  # For bash:
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc

  # For zsh (default on macOS):
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
  ```

**No model download.** Earlier versions shipped the "Laya" neural triage (a 554 MB ONNX model plus numpy, onnxruntime and tokenizers). It only produced informational domain / intent / risk guesses, never changed a gate decision, and scored at chance level, so it was removed in 0.11. If `~/.guard/models` exists from an older version, it can be deleted.

### Optional: Install Alibaba OCR CLI (for full reviews)
`guard post --full` adds an Alibaba OCR review and cannot approve without it; plain `guard post` does not need it:
```bash
npm install -g @alibaba-group/open-code-review
```

Check system environment health:
```bash
guard doctor
```

---

## ⚙️ LLM Configuration & OCR Auto-Sync

Configure your LLM credentials once; `guard` writes them into the Alibaba OCR CLI as the custom provider `guard` (same URL, protocol, key and model), so OCR reviews with the same LLM. OCR keeps that key in plain text in its own configuration file (`~/.opencodereview/config.json`), as guard does in `~/.guard/config.json`. `guard config llm --local` does not touch OCR, because OCR's settings apply to the whole machine; run `guard config sync --repo <repository>` if that repository's LLM should serve OCR. `guard config sync` repeats that step, and `ocr llm test` checks it:

```bash
guard config llm
```

The interactive wizard offers three ways to reach an LLM:
1. **OpenAI / OpenAI-Compatible**: OpenAI, **Ollama** (`http://localhost:11434/v1`), **DeepSeek** (`https://api.deepseek.com/v1`), OpenRouter, vLLM, or Local Gateways (`http://127.0.0.1:8090/v1`).
2. **Anthropic**: Claude API (any current Claude model id).
3. **My agent CLI**: `claude` or `codex` on this machine answers the review gate through your subscription, with no API key or gateway: Claude with its tools and your MCP servers off; Codex without your config and without its shell tool, in its read-only sandbox; both in an empty folder outside any repository, with the review rules in the CLI's system prompt. Guard checks the CLI by its sign-in and model list (codex reads its catalog locally; claude answers `/model`, usually without a model call) and offers those models to choose from. Alibaba OCR cannot use a CLI (it calls an HTTP endpoint with tool calls): it keeps its own LLM, and `guard doctor` says so.

Verify connectivity with an instant, token-free latency ping:
```bash
guard config test
```

---

## 🌐 Multi-Domain Coverage (FE, BE, Fullstack, Infra, MB)

`guard` detects the repository's domain from the repository itself, scoring several signals instead of taking the first marker file: Node dependencies of every `package.json` (monorepos included), web framework configs, `index.html`, UI component files, `server/`/`api/` directories, Python/Go/Rust/Java manifests, Terraform/Helm/Kubernetes and container files. A Node backend is not reported as frontend, an app with a `Dockerfile` is not infra, and a repository with both a web client and a server is `fullstack`.

The domain selects the **template invariants** used when the repository has no project invariants (most of them are diff heuristics and show as `UNVERIFIED`). The build command is chosen per ecosystem, not per domain:

| Domain | Typical stacks | Template invariants (only without project invariants) | Build / test command guard runs |
| :--- | :--- | :--- | :--- |
| **FE** (Frontend) | React, Next.js, Vue, Svelte, Vite | loading / disabled states, keyboard shortcuts (`Escape`, `Enter`), responsive layout | `<pm> run build` (or `check`, else `<pm> test`) |
| **BE** (Backend) | Go, Python, Node APIs (Fastify, Express, NestJS), Rust | JSON schema compatibility, parameterized SQL, atomic DB transactions | `go test ./...`, `cargo test`, `pytest`, or the package script for Node |
| **Fullstack** | web client + server in one repository or monorepo | frontend templates | the package script |
| **Infra** (DevOps) | Terraform, Helm, Kubernetes (IaC-only repositories) | no hardcoded secrets, no 0.0.0.0 DB binding, health checks | `terraform validate`, `docker compose config` |
| **MB** (Mobile) | Flutter, React Native, iOS, Android | permission flows, SafeArea, offline fallback | `flutter analyze`, `./gradlew test` |

`<pm>` is `pnpm`, `yarn`, `bun` or `npm`, from the lockfile. See [docs/quality-pillars.md](docs/quality-pillars.md) for what each rule actually checks.

---

## 🧹 Code Hygiene & Dead Code Gate

AI coding agents often leave behind code rot: scratchpad files, commented-out dead code blocks, and unreferenced helper functions. `guard` prevents codebase rot via a **Two-Tier Hygiene Scanner**:

| Rule ID | Severity | Inspection Rule | Detection Target |
| :--- | :--- | :--- | :--- |
| **`DEAD-001`** | `HIGH` / `MEDIUM` | **Orphan & Draft Files** | Unreferenced newly added files or draft names (`*.tmp`, `*backup*`, `temp_*`, `test_scratch*`). |
| **`DEAD-002`** | `MEDIUM` | **Commented-Out Code** | Blocks of 3+ consecutive lines of commented source code instead of clean Git deletion. |
| **`DEAD-003`** | `MEDIUM` / `LOW` | **Unused Symbols & Imports** | AST analysis flags unreferenced private helpers (`def _foo`) and unused imported symbols. |

### Two-Tier Execution Strategy:
1. **Commit-Level (Diff-Level, <50ms):** Automatically runs during `guard post` and Git hooks. Checks newly added files for orphan status and diff additions (`+`) for commented-out code.
2. **Focus-Level (Full-File Deep Scan):** Triggered via `--focus dead-code`. Scans entire touched files and AST to detect all unreferenced helpers, unused imports, and zombie code blocks.
---

## 🛋️ Simplicity & Engineering Frugality (KISS & YAGNI)

Inspired by Larry Wall's virtue of Laziness and [Dietrich Gebert's Ponytail](https://github.com/DietrichGebert/ponytail) philosophy: *"The best code is the code you never wrote."*

AI coding agents tend to be hyperactive—installing heavy libraries for trivial tasks or building 4-layer abstract classes for 10 lines of logic. `guard` enforces the **Ponytail Necessity Ladder**:

| Rule ID | Severity | Inspection Rule | Detection Target |
| :--- | :--- | :--- | :--- |
| **`LAZY-001`** | `HIGH` | **Dependency Bloat** | Redundant npm/pip packages (`is-odd`, `uuid`, `mkdirp`, `rimraf`, `pathlib2`, `mock`) when native APIs or stdlib suffice. |
| **`LAZY-002`** | `MEDIUM` | **Premature Abstraction** | Single-use interfaces, trivial pass-through wrapper functions, and over-engineered class hierarchies. |
| **`LAZY-003`** | `MEDIUM` | **Wheel Reinvention** | Re-implementing common utilities (`clamp`, `slugify`, `is_empty`, `flatten`, `deep_clone`) when stdlib or 1-liners suffice. |
| **`NET-LOC`** | ℹ️ **Info** | **Change Size** | Reports net lines added or removed. It is informational only: deleting code earns no score bonus. |

---

## 📖 CLI Usage Workflows

### 1. Install (`guard install`)
There are two ways to install guard. Neither needs a per-repository step.

```bash
# Global (whole machine):
#  - Git hooks for every repository (git config --global core.hooksPath ~/.guard/hooks)
#  - the guard directives in the global instruction file of each agent found on this machine:
#    ~/.claude/CLAUDE.md (Claude Code), ~/.codex/AGENTS.md (Codex), ~/.gemini/GEMINI.md (Gemini CLI),
#    ~/.config/opencode/AGENTS.md (opencode). Existing content is kept (backup: *.guard.bak).
guard install

# Workspace (one folder only):
#  - the guard directives in CLAUDE.md and AGENT.md of that folder
#  - Git hooks in the folder's repository, or in every Git repository below it
guard install --workspace path/to/workspace

# Remove what install added (marked blocks and guard's hooks; a foreign core.hooksPath is kept):
guard uninstall [--workspace path/to/workspace]

# Rewrite what guard installed earlier to the current version. Runs automatically after upgrades.
guard hook refresh
```

**How it chains together.** The agent reads the guard directives (global or workspace) and runs `guard pre` before editing. The first guard run inside a repository sets it up (below), and the Git hook checks every commit. Agents without a global instruction file (Cursor, omp) see the directives through a workspace install.

**Agent hooks: the directives ask, the hooks enforce.** `guard agent add <agent>` puts guard on the agent's own path, so an edit before `guard pre` or outside the scope, a stop with unapproved edits and a commit without an approval are refused with the reason instead of relying on the agent to obey. Guard ships checked adapters for Claude Code (CLI, Desktop, IDE extensions), Codex, Cursor, Grok Build, Gemini CLI, Google Antigravity, ZCode, omp, pi and opencode; `guard agent list` shows them and `guard install` offers the ones it finds. Some agents cannot refuse everything (pi and opencode have no stop that can be refused; Antigravity's is only reminded; Codex edits are checked right after they happen): `guard agent add` says so first, and the Git hook remains the backstop. For any other agent guard investigates it on this machine, has the LLM propose an adapter, tests it with you (`guard agent test`), and, when it cannot be set up, tells you why with a prefilled GitHub issue. Details: [`docs/cli-reference.md`](docs/cli-reference.md#12-guard-agent).

The older `guard hook install` still works: without options it runs `guard install`, and its options (`--stealth`, `--mode`, `--all-repos`, `--select-repos`, `--global`) keep their previous per-repository behavior. `guard hook status` shows the current hooks and directives.

> 🔒 **Safe-append for the agent docs guard is asked to write.** `guard install` (your global agent docs), `guard install --workspace` (only docs Git does not track) and the legacy `guard hook install --mode agent|all` append a marked block and keep your content, with a one-time `.guard.bak` backup. Uninstall removes only the marked block.

> 🧾 **Guard never creates a diff in your repository.** Inside a repository it writes only where Git tracks nothing: the `.git` directory and the `.guard/` folder, which it keeps out of Git through `.git/info/exclude` (never through `.gitignore`). Files that belong to the repository (agent docs, hooks kept in the tree such as `.husky/`, `guard.invariants.json`) are only read. When one of them needs a change, `guard doctor` tells you what to change; you decide.

**Automatic repository setup.** The first time guard runs inside a Git repository (`guard pre`, `guard post`, `guard install`), it:
- creates the local `.guard/invariants.json` when the repository has no invariants yet, importing the agent docs' invariant section;
- checks which hook directory Git really uses. With the global hooks nothing is added. When Git runs hooks from inside `.git`, guard makes that `pre-commit` call guard. When the repository keeps its hooks in its own tree (for example husky's `.husky`), guard does not touch them; the setup check shows the one line to add;
- records the repository in `~/.guard/repos.json`.

Outside a Git repository only the agent directives apply.

**Refresh after an upgrade.** The first guard command after a version change rewrites what guard owns: the global hooks (when `core.hooksPath` points at `~/.guard/hooks`), guard hooks inside `.git` of recorded repositories, and the directive block between the `BANH-MI-GUARD DUAL-GATE HOOK: START/END` markers in your global agent docs (`~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, `~/.gemini/GEMINI.md`, `~/.config/opencode/AGENTS.md`). Agent docs inside repositories are never rewritten; an outdated or unmarked guard section there is reported by the setup check. `guard hook refresh` runs the same refresh on demand.

### 2. Pre-Task Phase (`guard pre`)
Execute before modifying source code:
```bash
guard pre "Refactor checkout button to sticky bottom on mobile, update CSS and responsive modal"

# Declare scope explicitly (repeatable, globs allowed) when the prompt names no files:
guard pre "Review and fix bugs in the chat UI" --scope src/ui --scope src/ai/service.ts
```
A directory scope (`src/ui`) covers everything below it. Prefer it over `"src/ui/**"` on Windows, where the `guard.exe` launcher expands glob arguments even when they are quoted.
*Output:* Records the scope, the base commit (and a baseline snapshot with `--allow-dirty`), detects the repository domain, locks the invariants and evaluates them once as a baseline, and writes `### 🔍 PRE-TASK IMPACT NOTE` to `.guard/PRE_TASK_NOTE.md`.

Gate rules that keep the pre-task gate meaningful:
- Scope is only what the prompt names or `--scope` declares. Files that are already dirty are never added to it. With no scope, the post report says scope was not audited instead of flagging every file.
- A dirty working tree is refused. `--allow-dirty` records those files as a pre-existing baseline and snapshots them with `git stash create` (pinned at `refs/guard/baseline`; the working tree is not touched). Post then reviews only the edits made after pre (diff against the snapshot), marks untouched files `PRE-EXISTING`, and raises `SCOPE-003` as a MEDIUM notice.
- An unfinished (pre without post) or rejected (`REVISE`) session is refused. `--force` restarts it but keeps its baseline, snapshot, base commit, scope and locked invariants. The restart is listed in both reports, and files covered only by scope added in the restart fail as `SCOPE-004`. Stashing, restarting and popping, or committing mid-task, is still audited, because post diffs against the base commit recorded at the first pre.
- Paths come from `git status --porcelain -z`, so renamed files and names with spaces or Vietnamese characters are tracked correctly. Globs are accepted only via `--scope`: prose such as "do not edit *.css" never widens scope.

#### Project invariants (`guard.invariants.json`)
Invariants turn the rules an agent is told to respect (for example the invariant section of `AGENT.md`) into checks guard runs on every task, replacing the generic domain templates. They come from two files, which guard merges:

| File | Owner | In Git |
|---|---|---|
| `.guard/invariants.json` | guard (setup, `guard invariants init`, rules learned in review) | never (Git-excluded) |
| `guard.invariants.json` in the repository root | the user or team | committed by the user, read-only for guard |

A rule in the repository file wins over a local rule with the same id.

```bash
guard invariants init            # create the local file; imports numbered items under an "Invariants" / "Bất biến" heading of AGENT.md / AGENTS.md / CLAUDE.md
guard invariants init --shared   # create guard.invariants.json in the repository root instead, to commit for the team
guard invariants check           # evaluate every check on the current code, no session needed (exit 1 = a check fails, 2 = file missing/invalid)
```
Setup creates the local file automatically and never overwrites an existing one. Imported entries start without checks (`UNVERIFIED`) until you add them:
```json
{"invariants": [
  {"id": "CHAT-01", "description": "Chat requests never time out",
   "checks": [{"files": "src/ai/**/*.ts", "forbid": "AbortSignal\\.timeout"}]},
  {"id": "UX-01", "description": "Message renders within 1ms"}
]}
```
Every check runs on the current file contents. `forbid` fails when any matched file contains the regex, and `require` fails when none of them does. A check whose `files` glob matches nothing also fails, and so does an invalid regex. A malformed `guard.invariants.json` makes `guard pre` stop with the parse error. Invariants without checks are reported as `UNVERIFIED` (manual) and never counted as passed. A check that was already failing when pre ran is reported as `BASELINE_FAILED` (a warning), so an old defect does not block unrelated tasks; a check that starts failing during the task blocks approval. When a task adds or edits `guard.invariants.json`, post also self-checks the new file on the current tree (`... (new guard.invariants.json, self-check)`), so a rule that fails on the code it was written for blocks approval. This repository's own gate-integrity invariants live in [`guard.invariants.json`](guard.invariants.json).

**Rules learned during review.** The LLM gate may propose durable rules it notices in the diff (`INVARIANTS:` section of its answer). Guard writes a proposal into the local `.guard/invariants.json` (never into the repository's file) only when its id and description are new and its check passes on the current code; it is tagged `"origin": "llm:<session>"`, listed under "Invariants learned in this review", and enforced from the next `guard pre`. To share a learned rule with the team, copy it into `guard.invariants.json` yourself. Rejected proposals are listed with the reason.

**The rulebook cannot be weakened as a side effect.** Adding invariants never counts as out of scope. Removing an invariant or changing its checks raises `INV-WEAKENED`: CRITICAL (blocks) unless the task declares `guard.invariants.json` in its scope. A declared edit is reported as MEDIUM for the reviewer, and the locked rules it removes are shown as RETIRED (a changed rule is re-evaluated with its new definition) instead of failing.

### 3. Post-Task Phase (`guard post`)
Execute after code modifications are complete:
```bash
# Standard verification:
guard post

# Deep focus on code hygiene & dead code:
guard post --focus dead-code

# Deep focus on KISS, YAGNI & over-engineering:
guard post --focus simplicity
```
*Output:* Inspects git diff, detects out-of-scope and deleted files, scans the built-in rules and code hygiene, runs the Alibaba OCR review (only with `--full`), executes the build command, runs invariant checks, and requests **Final Gate Approval from your configured LLM** (`APPROVED` or `REVISE`) in `.guard/POST_TASK_REPORT.md`.

The report names the gate that actually ran. It says "LLM Gate" only when the LLM answered. Otherwise it says "Heuristic Gate (no LLM review)" and records the reason (`llm_error`, `review_mode` in `.guard/session.json`), for example a timeout or a model that refused to review a part. A heuristic REVISE (failed build, violated invariant, CRITICAL rule, out-of-scope file, with `--full` an OCR review that did not run or a high/critical OCR finding, or a score below 7.5) is final; otherwise the LLM decides. Large diffs are reviewed in parts of up to 80k characters (one REVISE rejects the whole diff); deleted files are sent as a one-line note; an answer that ignores the SCORE/VERDICT format is retried once. A review request has no time limit: AI review takes as long as it takes, and it ends when the LLM answers or its provider returns an error (`llm.timeout` applies only to `guard config test` pings). Deleting code earns no score bonus.

**Alibaba OCR review (`guard post --full`).** OCR is optional: a plain `guard post` does not run it and the report says "Alibaba OCR: not run". When a plain `guard post` is approved, the report tells the agent to ask you before committing whether you want a full review with OCR: say yes and it runs `guard post --full`, say no and the gate approval is enough. Asking for a full review at any time also runs it; Git hooks never run it. With `--full`, guard runs `ocr review` from the base commit recorded at pre to a snapshot of the working tree, so commits made mid-task, unstaged edits and new files are all reviewed (the snapshot is a Git object built in a throwaway index; your index, working tree and branches are not touched). The task prompt is passed as `--background`. It takes minutes, not seconds, and has no time limit: guard passes `--timeout 0` and sets OCR's per-request limit, which OCR cannot switch off, to ten years (`OCR_LLM_TIMEOUT`, overriding a shorter value in the environment), so the review ends only when OCR finishes or reports the provider's error; Ctrl+C stops it. A high or critical OCR finding blocks (REVISE); medium and low findings are listed and passed to the LLM gate. OCR not running (not installed, a provider error, a partial review) is `OCR-RUN` (HIGH) and also blocks: the report says "did not run" with the reason, never a pass. Findings on files that were already dirty before pre and that the task left untouched are dropped, and the report counts them; a dirty file the task edits is reviewed like any other. A partial review (the provider failed on some files) is resumed once with `--resume`, so only the failed files run again. A gateway that drops parallel requests needs a lower `ocr.concurrency` in `~/.guard/config.json` (0 keeps OCR's default of 8).

**Commit messages.** Who writes them is your choice, saved machine-wide: `guard config commit auto` lets the agent write them (a conventional message that never mentions guard), `guard config commit ask` makes the agent ask you for every one. The post report of approved work ends with a **Commit** line that tells the agent which mode is set; while none is set, it tells the agent to ask you which one you want. `guard install` and `guard doctor` show the choice as "Commit messages".

Removals that a compiler cannot see are checked over the whole repository: every string key (`case 'edit':`), export and CSS class deleted by the diff is searched for. One that is no longer defined but still referenced raises `DEAD-REF` (HIGH) with the locations. The summary line goes into every LLM review part as verified evidence, so a batched review does not have to guess about references in another part.

`SEC-003` (`innerHTML`/`outerHTML` `=` and `+=` sinks) checks every assignment on a line, and a comment that mentions "sanitize" does not silence it. Only an empty literal, a value that is exactly one `DOMPurify.sanitize(...)` call, or an explicit `// guard-allow SEC-003: <reason>` exempts a line, and that marker is still listed as a `LOW` finding.

Git hooks call `guard post --hook`. It skips repositories that have no guard session, and it also skips when `guard` is not on `PATH`. An approved session covers only the exact file contents it approved: committing them passes, while any file changed after the approval (or unrelated to it) is blocked until a new `guard pre`/`guard post` round. `guard reset` closes the current session (for work that was committed or abandoned) and archives it to `.guard/history/`. With global hooks (`core.hooksPath`), each repository's own hook (and a `.guard.bak` original) in its common `hooks/` directory still runs first, including from linked worktrees. `guard run` and the agent wrapper script accept the same pre-task flags (`--scope`, `--allow-dirty`, `--force`; the wrapper script reads them from `GUARD_PRE_ARGS`).

### 4. Automated Sandwich Pattern Execution (`guard run`)
Wraps any developer or agent command in pre- and post-task gates:
```bash
guard run "Add shipping fee calculation endpoint" -- git status
```

### 5. On-Demand LLM Code Review (`guard review`)
Run an immediate architectural and safety review on the current Git diff:
```bash
# Standard on-demand review:
guard review

# Focused review on code hygiene & orphan files:
guard review --focus dead-code

# Focused review acting as "The Laziest Senior Architect in the Room":
guard review --focus simplicity
```
### 6. Supply-Chain Security & Safe Updates (`guard update`)
Guard enforces a **3-day Quarantine Cooling Period** on Alibaba OCR npm releases to defend against zero-day backdoors:
```bash
# Check for new releases without installing:
guard update --check

# Safely upgrade Alibaba OCR (automatically halts if release is < 3 days old):
guard update

# Bypass quarantine hold explicitly:
guard update --force

# Upgrade the Guard CLI itself directly from GitHub:
guard update self

# Check for Guard CLI updates on GitHub without installing:
guard update self --check

# Check system diagnostics & release audits:
guard doctor
```

#### Upgrading from an older version
Guard tells you what is still missing after an upgrade:

- `guard update self` runs `guard hook refresh` with the new version and then prints a **setup check** listing each missing item and the command that fixes it.
- If guard was upgraded another way, the first guard command of the new version prints the same check once.
- `guard doctor` always shows it, in the "Installation & Repository Setup" table.

| Check says | Run |
|---|---|
| Git hooks missing / commits not checked | `guard install` (or `guard install --workspace <dir>`) |
| Agent directives missing (no agent is told to run guard) | `guard install` (or `guard install --workspace <dir>`) |
| Repository hook does not call guard (hooks inside `.git`) | `guard hook refresh` inside the repository |
| Repository keeps its hooks in its tree (e.g. `.husky/`) | add the line the check prints to that `pre-commit` (guard does not edit repository files) |
| Repository agent doc has an older or unmarked guard section | update or remove it yourself (guard does not edit repository files) |
| Guard directives without START/END markers | wrap the guard section as shown below, or delete it and run `guard install` |
| No `guard.invariants.json` / invariants without checks | `guard invariants init`, then add checks and run `guard invariants check` |
| Alibaba OCR not on PATH (needed only by `guard post --full`) | `npm install -g @alibaba-group/open-code-review`, then `guard config sync` |
| Commit messages: not chosen yet | `guard config commit auto` (or `guard config commit ask`) |
| Old Laya model files left by guard <= 0.10 | delete `~/.guard/models` |

Markers that let guard refresh a pasted directive section:
```markdown
<!-- === BANH-MI-GUARD DUAL-GATE HOOK: START === -->
...guard directives...
<!-- === BANH-MI-GUARD DUAL-GATE HOOK: END === -->
```

**After an upgrade, what guard owns is refreshed for you.** `guard update self` starts the newly installed guard to run `guard hook refresh`, which rewrites the global hooks, guard hooks inside `.git` of recorded repositories and the marked directive block in your global agent docs. If guard was upgraded another way (for example `pipx upgrade`), the first guard command of the new version does the same once. Repository files (agent docs, hooks kept in the tree) are only reported, with the change to make.

**Coming from `laya-ocr-guard` (0.10 or older).** 0.11 renamed the project to `banh-mi-guard` and its markers from `LAYA-OCR-GUARD` to `BANH-MI-GUARD`; old markers are not recognized. To move over:
1. `pip uninstall laya-ocr-guard` (or `pipx uninstall laya-ocr-guard`), then install `banh-mi-guard` as shown in [Installation](#-cross-platform-installation-windows-linux-macos).
2. Run `guard install` (or `guard install --workspace <dir>`): it rewrites the global hooks and adds the new directive block.
3. Remove old `LAYA-OCR-GUARD` directive sections from agent docs and old guard hooks from `.git/hooks/pre-commit` of repositories where you installed them per repository.
4. Delete `~/.guard/models` (the removed Laya model, about 555 MB).

---

## 🧪 Running the Test Suite

The project includes a comprehensive end-to-end integration and unit test suite (140+ tests):
```bash
pytest
```
