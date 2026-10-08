# CLI Command Reference: `guard`

> 📦 **GitHub Repository:** [github.com/okrath/banh-mi-guard](https://github.com/okrath/banh-mi-guard) &bull; 👤 **Author:** [@okrath](https://github.com/okrath) &bull; 📖 **Live Documentation:** [okrath.github.io/banh-mi-guard](https://okrath.github.io/banh-mi-guard/)

Complete command-line manual for `banh-mi-guard`.

---

## Installation & Environment Setup

Install the `guard` CLI globally on any platform using one of the following methods:

### Method 1: Install from PyPI (Recommended)
```bash
# With pipx (isolated global binary, recommended on Linux / macOS):
pipx install banh-mi-guard

# Or with standard pip across all platforms (Windows / Linux / macOS):
pip install banh-mi-guard
```
PyPI carries each released version ([pypi.org/project/banh-mi-guard](https://pypi.org/project/banh-mi-guard/)). To upgrade: `pipx upgrade banh-mi-guard` or `pip install --upgrade banh-mi-guard`.

### Method 2: Install the latest `main` directly from GitHub
```bash
pipx install git+https://github.com/okrath/banh-mi-guard.git
# or
pip install git+https://github.com/okrath/banh-mi-guard.git
```
This is the newest code, which can be ahead of the last release. `guard update self` upgrades from here (see `guard update` below).

### Method 3: Clone repository & install in editable mode
```bash
git clone https://github.com/okrath/banh-mi-guard.git
cd banh-mi-guard
pip install -e .
```

### Environment `$PATH` Setup
* **Windows**: `guard.exe` is automatically installed into `Python3xx\Scripts\guard.exe`.
* **Linux / macOS**: The `guard` executable lives in `~/.local/bin/guard` or `/usr/local/bin/guard`. If your terminal displays `command not found: guard`, add it to your shell configuration:
  ```bash
  # For bash:
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc

  # For zsh (default on macOS):
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
  ```

**No model download.** The neural triage ONNX model from versions <= 0.10 was removed in 0.11. If `~/.guard/models` exists from an older version, it can be deleted (see [guard laya](#13-guard-laya)).

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

## 1. `guard pre`

Runs the Pre-Task Guard phase before modifying code.

```bash
guard pre "<prompt>" [options]
```

### Arguments:
* `prompt` (required): Natural language description of the task about to be performed. Files and directory paths named in the prompt are automatically added to the task scope.

### Options:
* `-r, --repo <path>`: Target repository directory (default: current directory).
* `-q, --quick`: Accepted for compatibility; has no effect since the triage was removed in 0.11.
* `-s, --scope <path|dir|glob>` (repeatable): Declare the files the task may change. Files named in the prompt are added automatically; globs are accepted only here. On Windows prefer a directory (`--scope src/ui`) over a quoted glob (`"src/ui/**"`), where the `guard.exe` launcher expands glob arguments even when they are quoted. A directory scope covers everything below it.
* `--allow-dirty`: Start although files are already modified. They are snapshotted (`git stash create`, working tree untouched, pinned at `refs/guard/baseline`) and reported as pre-existing; post reviews only the edits made after pre (diff against the snapshot), marks untouched files `PRE-EXISTING`, and raises `SCOPE-003` as a MEDIUM notice. If baseline snapshot creation fails (e.g. repository has no commits or no tracked modifications), the failure reason is recorded in the pre-task note, and post falls back to reviewing the full diff.
* `--force`: Restart an unfinished (pre without post) or rejected (`REVISE`) session. The restart keeps its baseline, snapshot, base commit, scope and locked invariants, is listed in the reports, and files covered only by scope added in the restart fail as `SCOPE-004`. Stashing, restarting and popping, or committing mid-task, is still audited, because post diffs against the base commit recorded at the first pre.

*Output:* Records the scope, the base commit (and a baseline snapshot with `--allow-dirty`), detects the repository domain, locks the invariants and evaluates them once as a baseline, and writes `### 🔍 PRE-TASK IMPACT NOTE` to `.guard/PRE_TASK_NOTE.md`.

Pre refuses to start on a dirty tree (without `--allow-dirty`) and over an unfinished or rejected session (without `--force`). Scope is strictly what the prompt names or `--scope` declares; files already dirty are never added to it. With no scope, the post report says scope was not audited instead of flagging every file. Paths come from `git status --porcelain -z`, so renamed files and names with spaces or Vietnamese characters are tracked correctly. Globs are accepted only via `--scope`: prose such as "do not edit *.css" never widens scope.

---

## 2. `guard post`

Runs the Post-Task Guard verification phase after code has been edited.

```bash
guard post [options]
```

### Options:
* `-r, --repo <path>`: Target repository directory.
* `-f, --focus <area>`: Quality pillar to focus scrutiny on (`all`, `security`, `memory`, `performance`, `ux`, `dead-code`, `simplicity`). Default: `all`.
* `--auto-fix`: Trigger self-healing remediation suggestions if verification fails.
* `--hook`: Git-hook mode. Skips when the repository has no guard session or when guard is not on `PATH`; with an approved session, passes only when staged/committed changes match what was approved. Never runs OCR.
* `--full`: Full review. Adds an Alibaba OCR review of the task's changes (it reads the repository, costs tokens, takes minutes; see details below). Without it the report says "Alibaba OCR: not run", and an approved report tells the agent to ask you before committing whether you want this full review.
* `--reviewers <1-5>`: LLM review panel size. Default 1 (one reviewer). See [Review Options](#review-options-stages--limits).
* `--validate` / `--no-validate`: Check blocking findings of a multi-part diff against the whole diff before they block.
* `--test-checklist` / `--no-test-checklist`: Add the test-quality checklist to the review prompt.
* `--threat-frame <off|auto>`: Add a threat-model frame when the diff touches security-sensitive surface.
* `--max-llm-calls <N>`: Cap on the LLM calls of the extra stages (panel and validation) for this run. Default 12.

A flag you do not pass keeps the value from `guard config review`. Four more review options have no flag and are set only there: `coverage_notes`, `part_manifest`, `test_evidence` and `stage_timeout_s`.

*Output:* Inspects git diff, detects out-of-scope and deleted files, scans the built-in rules and code hygiene, runs the Alibaba OCR review (only with `--full`), executes the build command, runs invariant checks, and requests **Final Gate Approval from your configured LLM** (`APPROVED` or `REVISE`) in `.guard/POST_TASK_REPORT.md`.

### Inspection Pipeline & Gate Decisions:
Post audits against the base commit recorded at pre, runs the build command, invariant checks and the removed-symbol reference check, then asks the LLM.
- **Diff & Baseline Snapshot Errors Force REVISE:** If Git diff inspection or baseline snapshot diff inspection fails, the error is surfaced in `diff_summary.error` and docks 5.0 points from the heuristic score, forcing a `REVISE` verdict (see [Quality Pillars: Scoring and the final verdict](quality-pillars.md#scoring-and-the-final-verdict)). If snapshot creation failed at pre, the report details why and reviews the full diff.
- **Heuristic vs LLM Gate:** The report names the gate that actually ran. It says "LLM Gate" only when the LLM answered. Otherwise it says "Heuristic Gate (no LLM review)" and records the reason (`llm_error`, `review_mode` in `.guard/session.json`), for example a timeout or a model that refused to review a part. A heuristic REVISE (outright blockers such as build failure, violated invariant, CRITICAL rule, out-of-scope file, diff error, or score below 7.5; see [Quality Pillars](quality-pillars.md#scoring-and-the-final-verdict)) is final; otherwise the LLM decides.
- **Large Diff Handling:** Large diffs are reviewed in parts of up to 80k characters, at most 6 parts (one REVISE rejects the whole diff; parts beyond the limit are not reviewed and the report says so under *Not reviewed / limits*); deleted files are sent as a one-line note; an answer that ignores the SCORE/VERDICT format is retried once. A review request has no time limit: AI review takes as long as it takes, and it ends when the LLM answers or its provider returns an error (`llm.timeout` applies only to `guard config test` pings). Deleting code earns no score bonus.
- **Removed Symbol References (`DEAD-REF`):** Removals that a compiler cannot see are checked over the whole repository: every string key (`case 'edit':`), export and CSS class deleted by the diff is searched for. One that is no longer defined but still referenced raises `DEAD-REF` (HIGH) with the locations. The summary line goes into every LLM review part as verified evidence.
- **HTML Sinks (`SEC-003`):** Checks every assignment on a line, and a comment that mentions "sanitize" does not silence it. Only an empty literal, a value that is exactly one `DOMPurify.sanitize(...)` call, or an explicit `// guard-allow SEC-003: <reason>` exempts a line, and that marker is still listed as a `LOW` finding.
- **Alibaba OCR review (`guard post --full`):** OCR is optional: a plain `guard post` does not run it and the report says "Alibaba OCR: not run". When a plain `guard post` is approved, the report tells the agent to ask you before committing whether you want a full review with OCR: say yes and it runs `guard post --full`, say no and the gate approval is enough. Asking for a full review at any time also runs it; Git hooks never run it. `guard config ocr always` runs it on every post and `guard config ocr optional` switches that off; only you can run `guard config ocr`, in an interactive terminal. With `--full`, guard runs `ocr review` from the base commit recorded at pre to a snapshot of the working tree, so commits made mid-task, unstaged edits and new files are all reviewed (the snapshot is a Git object built in a throwaway index; your index, working tree and branches are not touched). The task prompt is passed as `--background`. It takes minutes, not seconds, and has no time limit: guard passes `--timeout 0` and sets OCR's per-request limit, which OCR cannot switch off, to ten years (`OCR_LLM_TIMEOUT`, overriding a shorter value in the environment), so the review ends only when OCR finishes or reports the provider's error; Ctrl+C stops it. A high or critical OCR finding blocks (REVISE); medium and low findings are listed and passed to the LLM gate. OCR not running (not installed, a provider error, a partial review) is `OCR-RUN` (HIGH) and also blocks: the report says "did not run" with the reason, never a pass. Findings on files that were already dirty before pre and that the task left untouched are dropped, and the report counts them; a dirty file the task edits is reviewed like any other. A partial review (the provider failed on some files) is resumed once with `--resume`, so only the failed files run again. A gateway that drops parallel requests needs a lower `ocr.concurrency` in `~/.guard/config.json` (0 keeps OCR's default of 8).
- **Commit Line:** The post report of approved work ends with a **Commit** line telling the agent which mode is set (`auto` or `ask`); see [guard config commit](#5-guard-config).
- **Deeper Review Offer:** When one reviewer approved a large or security-sensitive change, the Commit line tells the agent to ask you one question before committing instead of the OCR question alone: is the approval enough, or do you want a review panel of three reviewers, a full OCR review, or both. The line gives the exact commands, for example `guard post --reviewers 3 --max-llm-calls 6`, with the worst-case number of LLM calls. A change is large when it is reviewed in 2 or more parts or changes more than 400 lines; it is sensitive when the threat frame's scan (no LLM) finds security-sensitive paths or lines. Nothing runs until you say yes, and no offer is made when the gate rejects, when a panel already ran, or for a small, plain change.

### Review Options, Stages & Limits:
Every option below is off or at its default unless you change it, so a plain `guard post` is one review per diff part. The extra stages cost LLM calls and are opt-in. None of these options changes the Alibaba OCR setting or what `--full` does. They apply to `guard post`; `guard review` always runs with the defaults.

Resolution order: built-in defaults, then the `review` object of the config file (`guard config review`), then the flags of this run. Environment variables are deliberately not read, so nothing in the environment can switch a review stage on or off. When an option differs from its default, `guard post` prints one `Review options:` line naming it, where its value came from, "weaker than default" for an option that reviews less, and the worst-case LLM call count when options add calls.

| Option | Flag | Default | What it does and what it costs |
| :--- | :--- | :--- | :--- |
| `coverage_notes` | none | `true` | Shows the *Not reviewed / limits* section described below. No LLM cost. Turning it off is reported as weaker than default. |
| `part_manifest` | none | `false` | On a multi-part diff, each part's prompt also lists the other parts and the files in them with their added and removed line counts (at most 1,500 characters), so the reviewer knows where a missing piece may live. A longer prompt, no extra calls. |
| `test_evidence` | none | `false` | Adds facts about changed tests to the evidence the reviewer reads (see *Test-quality evidence*). No extra calls. |
| `test_checklist` | `--test-checklist` | `false` | Adds a test-quality checklist to the review prompt. A longer prompt, no extra calls. |
| `threat_frame` | `--threat-frame` | `off` | `auto` adds an adversarial frame when the diff touches security-sensitive surface (see *Threat frame*). No extra calls. |
| `validate_findings` | `--validate` | `false` | Re-checks blocking findings against the whole diff (see *Finding validation*). Up to 5 extra calls. |
| `reviewers` | `--reviewers` | `1` | A panel of 1 to 5 reviewers (see *Reviewer panel*). Multiplies the calls. |
| `max_llm_calls` | none | `12` | Cap on the calls the extra stages (panel and validation) may use. At least 1. |
| `stage_timeout_s` | none | `900` | Seconds each extra stage may take. At least 30. |

**Calls per part.** One reviewer makes one call per diff part, plus one retry when the answer ignores the required format, so at most 2 calls per part. The worst case is `2 x parts x reviewers`, plus 5 with `validate_findings`; that is the number the `Review options:` line prints (only when `reviewers` is above 1 or validation is on). The calls a review really made are recorded as `llm_calls` in `.guard/session.json`.

**Reviewer panel.** With `reviewers` of N, the first N of these lenses each review every part independently: correctness, requirements, contracts, tests, adversary. Their findings are merged and de-duplicated, and any blocking finding makes the verdict REVISE. The panel replaces the single review; it does not run in addition to it, and it proposes no new invariants. Use it for a change where one pass is likely to miss something and the extra calls are acceptable; it is not a default. The panel needs at least half of its lenses to answer every part, otherwise it falls back to one reviewer. With `test_checklist` the checklist goes to the tests lens, and with an active threat frame the frame goes to the adversary lens.

**The call cap.** The single review always runs, retries included, and is never capped or skipped. `max_llm_calls` limits only the extra stages: the panel starts only when `2 x reviewers x parts` is within the cap, and validation only when its worst case is. At the default of 12, `--reviewers 3` on a diff of 3 parts (18 calls) or `--reviewers 5` on 2 parts (20 calls) does not start; one reviewer runs and the report says so. Raise `max_llm_calls` together with `reviewers`. `stage_timeout_s` bounds how long the panel and validation may take; the single review keeps no time limit (see *Large Diff Handling* above).

**Finding validation.** Runs only when `validate_findings` is on, a finding blocks, and the diff has more than one part (or parts that were cut), because a finding about one part may be answered by another. At most 5 blocking findings are checked, one call each, with the surrounding lines of the whole diff. A finding is demoted to advisory only when the validator answers "refuted" and quotes one line (12 to 160 characters) that literally appears in the diff, in a different file than the finding's own or moved verbatim out of the finding's file, and the finding is not a security finding and the quote is not a comment, docstring or secret. A demoted finding keeps its text with a `[contested: ... evidence: "..."]` note, and the report says `Finding validation: N checked, M demoted (evidence quoted)`. If every blocking finding is demoted, the verdict becomes APPROVED. The stage is fail-safe: an error, a timeout, an unparseable answer or a missing quote leaves every finding exactly as it was.

**Test-quality evidence.** With `test_evidence`, guard reads the diff of test files and gives the reviewer up to 12 factual lines, never a verdict and never a block of their own: fewer assertions after the change than before, an added skip or disable marker, a mutation of process-wide state (path, environment, working directory), an added test with no assertion, and a test file deleted or only shortened. The languages, frameworks and patterns it recognises, and what it leaves to the LLM, are in the table at the top of [`guard/core/test_evidence.py`](../guard/core/test_evidence.py).

**Threat frame.** With `threat_frame` set to `auto`, guard scans the diff without an LLM for security-sensitive surface: paths such as authentication, sessions, tokens, secrets, crypto, permissions, CI workflows, Dockerfiles, hooks, `.env` and key files, and added or removed lines such as process execution, dynamic evaluation, HTML sinks, SQL built from strings, disabled certificate checks, `curl | sh`, or a removed authorization check. The full trigger table is at the top of [`guard/core/threat_frame.py`](../guard/core/threat_frame.py). When something triggers, the evidence names the reasons and the prompt asks for an adversarial review plus two short sections: a threat model (shown in the technical audit as `Threat model: ...`) and a list of what the reviewer did not examine (shown under *Not reviewed / limits*). Suspected issues still go through the normal findings; when nothing triggers, the review is unchanged.

**Not reviewed / limits.** The terminal and `.guard/POST_TASK_REPORT.md` end the review with this section whenever the review left something out; it is absent when the review saw everything. An approved report starts it with "The approval covers only what the review saw." The notes it can show, in this order:
- `N diff part(s) were NOT reviewed (limit M).` Parts beyond the part limit.
- `Not shown to the reviewer (assets, lockfiles, images): ...` Files filtered out before review (the first 10, then `+N more`).
- `Content omitted for deleted file(s): ...` Deleted files, which are sent as a one-line note.
- `Reviewer did not trace: ...` What the reviewer reported as not examined (threat frame only).
- `Reviewer panel unavailable (...); one reviewer ran.` The call cap was too low, the panel failed, or too few lenses answered.
- `Finding validation skipped (budget exceeded).` or `Finding validation timed out after Ns.`

The first three notes are also shown when a hard blocker such as a failed build decided before the LLM was asked.

### Signed Approvals & State Protection:
Approvals are cryptographically signed using HMAC-SHA256, automated agent edit tools targeting `.guard/` are blocked, shell modifications to `session.json` trigger warnings, and unsigned or older approvals are rejected on agent commit, stop hooks, and Git pre-commit hooks (`guard post --hook`).

For complete cryptographic signing rules (`$GUARD_HOME/approval.key`, default `~/.guard/approval.key`), state isolation, and tamper protection specifications, see [Architecture: Security Model & State Integrity](architecture.md#4-security-model--state-integrity).
---

## 3. `guard run`

Executes the automated Sandwich Pattern around any command.

```bash
guard run "<prompt>" -- <command...>
```

Accepts the same pre-task options: `--scope`, `--allow-dirty`, `--force`. The agent wrapper script (`.guard/bin/guard-exec`) accepts these same pre-task flags, reading them from `GUARD_PRE_ARGS`.

### Example:
```bash
guard run "Add customer discount calculation" --scope src/pricing -- git status
```

---

## 4. `guard review`

Performs an on-demand review of the current Git working tree diff using your configured LLM.

```bash
guard review [options]
```

### Options:
* `-r, --repo <path>`: Target repository directory.
* `-f, --focus <area>`: Quality pillar focus (`all`, `security`, `memory`, `performance`, `ux`, `dead-code`, `simplicity`).

---

## 5. `guard config`

Manages configuration for LLM providers and Alibaba OCR sync.

```bash
# View active configuration table:
guard config

# Launch interactive configuration wizard:
guard config llm [--local]

# Test LLM connection with token-free latency ping:
guard config test

# Write the LLM settings into Alibaba OCR as its custom provider `guard` (check with `ocr llm test`):
guard config sync [--repo <repository>]

# Choose whether every guard post runs Alibaba OCR (only the user can run this, in an interactive terminal):
guard config ocr always   # every guard post runs Alibaba OCR review
guard config ocr optional # only guard post --full runs it

# Choose who writes commit messages for approved work (machine-wide):
guard config commit auto   # the agent writes them (conventional, never mentions guard)
guard config commit ask    # the agent asks you for every commit message

# Show the effective review options and where each comes from (default, config or cli):
guard config review
# Set one review option machine-wide (only the user can run this, in an interactive terminal):
guard config review <option> <value>   # e.g. reviewers 3, threat_frame auto, validate_findings true

# Choose which tests the build check runs (machine-wide):
guard config tests full      # every guard post runs the whole test suite (the default)
guard config tests related   # a pytest build runs only the related tests until the gate would approve
```

`guard config tests related` shortens the rounds that fail. It applies only when the build command is `pytest`, and only when every file the task changed is Python code: guard then runs the changed test files and the tracked test files that import a changed module or are named after it. Any other change (a non-Python file, `conftest.py`, `pyproject.toml`, a package `__init__.py`, a deleted file), or no matching test, runs the whole suite as before. When the related tests pass and the gate would approve, guard runs the whole suite before approving, and a failure there rejects the change, so every approval and every commit has a full test run behind it. The build line of the report says "Related tests only (N file(s))" when only related tests ran. The setting is stored as `tests_scope` in `~/.guard/config.json`; a repository's own `.guard/config.json` is read instead when it exists, and an older guard that re-saves the config drops it (the scope returns to `full`).

`guard config ocr` is the user's decision and can only be run by the user in an interactive terminal.
`guard post` reports the chosen mode in the **Commit** line of an approved report; while no mode is set, the agent is told to ask you which one you want. `guard install` and `guard doctor` list it as "Commit messages".

`guard config review` accepts `coverage_notes`, `part_manifest`, `test_evidence`, `test_checklist`, `validate_findings` (true or false), `threat_frame` (`off` or `auto`), `reviewers` (1 to 5), `max_llm_calls` and `stage_timeout_s`; what each does is in [Review Options, Stages & Limits](#review-options-stages--limits). A wrong value or an unknown option is refused naming the allowed values. The options are stored as the `review` object of `~/.guard/config.json`; when the repository has its own `.guard/config.json`, that file is read instead of the machine-wide one (it is not merged with it). A saved `review` value that cannot be parsed makes `guard post` fail instead of silently using defaults.

**Compatibility.** An older guard does not know the new fields. If it re-saves the config (for example `guard config commit`), it drops the `review` object, and if it re-saves a session, it drops the review fields of that post record (`review_options`, `coverage_notes`, `validation_log`, `llm_calls`, `panel_hint`). Nothing crashes: the saved review options or the record of how that review ran are lost, and the options return to their defaults.

**LLM Configuration Providers:**
1. **OpenAI / OpenAI-Compatible**: OpenAI, **Ollama** (`http://localhost:11434/v1`), **DeepSeek** (`https://api.deepseek.com/v1`), OpenRouter, vLLM, or Local Gateways (`http://127.0.0.1:8090/v1`).
2. **Anthropic**: Claude API (any current Claude model id).
3. **My agent CLI**: `claude`, `codex` or `omp` on this machine answers the review gate through your subscription, with no API key or gateway:
   - Claude runs with its tools and your MCP servers off (`claude -p --tools ""`).
   - Codex runs without your config and without its shell tool, in its read-only sandbox (`codex exec --sandbox read-only`).
   - omp runs with no tools and no saved session (omp ignores a system prompt in print mode, so the rules lead the prompt, ahead of the marked repository text).
   - Claude and Codex both execute in an empty folder outside any repository, with the review rules in the CLI's system prompt.
   - `agy` is not offered: headless it asks for tools that only `--dangerously-skip-permissions` would allow.
   - `guard agent add claude-code`, `codex` or `omp` offers to make that agent guard's LLM. Guard checks the CLI by its sign-in and model list (`codex debug models` reads its catalog locally; `claude -p /model` usually answers without a model call) and offers those models to choose from.
   - With *My agent CLI*, `guard post --full` runs Alibaba OCR through the same CLI: guard starts a local endpoint for that review only (127.0.0.1, a random port and token), runs OCR from a throwaway home whose OCR settings point at it (your own OCR settings are never changed), and answers each of OCR's requests with one CLI call that has OCR's tools written into the prompt and returns one tool call, which OCR runs. Two requests run at a time. The report says `answered by the <cli> CLI (tool calls written as text)`, and a CLI that fails is an OCR failure with its reason.
   - When that review does not run, guard warns and falls back to OCR's delegation mode: `ocr delegate` lists the files and OCR's rules for them (using OCR's rules, not guard's), and the same CLI, tools still off, reviews each rule group's diff in one prompt (in parts of up to 150,000 characters when it is larger). The report then says `answered by the <cli> CLI as the fallback after …` with the first path's reason. A file the fallback did not review (the CLI failed, or its diff is over 150,000 characters) keeps the review failed.
4. **Credential Security:** Keys are kept in `~/.guard/config.json` (readable by its owner only, mode 0600 on Linux and macOS). When synced to Alibaba OCR, OCR stores the key in plain text in its own configuration file (`~/.opencodereview/config.json`). `guard config llm --local` does not touch OCR, because OCR's settings apply to the whole machine; run `guard config sync --repo <repository>` if that repository's LLM should serve OCR.

---

## 6. `guard install` / `guard uninstall`

```bash
guard install                          # global: hooks for every repo + directives in installed agents' global files
guard install --workspace <dir>        # workspace: directives in <dir>/CLAUDE.md and AGENT.md + hooks in its repos
guard uninstall [--workspace <dir>]    # remove the marked directive blocks and guard's hooks
```

Global writes the marked guard block into `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, `~/.gemini/GEMINI.md` and `~/.config/opencode/AGENTS.md`, only for agents whose config directory exists; existing content is kept and backed up once (`*.guard.bak`). Uninstall removes only the marked block (deleting a file that held nothing else) and unsets `core.hooksPath` only when it points at guard's hooks. With global hooks (`core.hooksPath`), each repository's own hook (and an existing hook kept as `.guard.bak`) in its common `hooks/` directory still runs first, including from linked worktrees. `guard install` offers the agents it finds on this machine (checked adapters for Claude Code, Codex, Cursor, Grok Build, Gemini CLI, Google Antigravity, ZCode, omp, pi and opencode).

**Safe-append for agent docs written by guard:** `guard install` (your global agent docs), `guard install --workspace` (only docs Git does not track) and the legacy `guard hook install --mode agent|all` append a marked block and keep your content, with a one-time `.guard.bak` backup. Uninstall removes only the marked block.

**Guard never creates a diff in your repository:** It writes only in `.git` and the Git-excluded `.guard/` directory; repository files are read-only. See [Architecture: Non-Invasive Repository State](architecture.md#4-security-model--state-integrity).

**Automatic repository setup:** The first time guard runs inside a Git repository (`guard pre`, `guard post`, `guard install`), it:
- creates the local `.guard/invariants.json` when the repository has no invariants yet, importing the agent docs' invariant section;
- checks which hook directory Git really uses. With the global hooks nothing is added. When Git runs hooks from inside `.git`, guard makes that `pre-commit` call guard. When the repository keeps its hooks in its own tree (for example husky's `.husky`), guard does not touch them; the setup check shows the one line to add;
- records the repository in `~/.guard/repos.json`.

Outside a Git repository only the agent directives apply.

---

## 7. `guard hook`

Manages Git hooks, AI Agent directives, and multi-repo workspace protection. `guard hook install` without options runs `guard install`; its options keep the previous per-repository behavior.

Repositories are set up automatically on first use without creating a diff (see [Automatic repository setup](#6-guard-install--guard-uninstall)). Hooks kept in the repository tree (e.g. `.husky/`) and repository agent docs are never edited; `guard doctor` shows what to change. `guard hook refresh` rewrites what guard installed earlier to the current version; the same refresh runs once automatically after each upgrade.

```bash
guard hook install          # same as `guard install` when used without options
guard hook refresh          # refresh global hooks, guard hooks inside .git and marked blocks in global agent docs

# Workspace / Multi-Repo Mode (auto-discovers child Git repositories):
# Interactive menu: [A] All repos, [1-N] specific repos (e.g. 2,3,7,8), [G] Global, [N] None
guard hook install --all-repos              # Install Git hooks to all discovered child repos
guard hook install --select-repos "1,2"     # Selectively install to specific child repos

# Global Git Protection (Protects EVERY repository on your machine automatically):
guard hook install --global                 # Sets git config --global core.hooksPath ~/.guard/hooks

# Legacy per-repository modes:
guard hook install --stealth                # 👻 Git hook in .git/hooks only (no repository file changes)
guard hook install --mode agent             # 🤖 Agent directives appended to the repository's CLAUDE.md & AGENT.md (you asked for it: this is a repository change)
guard hook install --mode all               # 🛡️ Both of the above

# Check active status of hooks, child repositories, and global hooks:
guard hook status

# Safely uninstall hooks and restore previous user files:
guard hook uninstall [--mode <git|agent|all>] [--global]
```

### Options for `guard hook install`:
* `-r, --repo <path>`: Target repository or workspace directory.
* `-m, --mode <git|agent|all>`: Installation mode (`git`, `agent`, `all`).
* `-s, --stealth`: Shortcut for `--mode git` (Git hooks only, no `CLAUDE.md`/`AGENT.md`).
* `-g, --global`: Configure Git hooks globally for all repositories via `git config --global core.hooksPath ~/.guard/hooks`.
* `--all-repos`: Automatically install Git hooks into all discovered child Git repositories in workspace mode.
* `--select-repos <indices|names>`: Comma-separated list of child repo numbers (e.g. `2,3,7,8`) or folder names.

Legacy install modes support safe-append for agent directives and automatic invariant initialization (see [Safe-append](#6-guard-install--guard-uninstall) and [guard invariants init](#8-guard-invariants)). Linked worktrees are fully supported via `--git-common-dir`.

---

## 8. `guard invariants`

Create and validate project invariants: the local, Git-excluded `.guard/invariants.json` (guard's) and the optional `guard.invariants.json` in the repository root (yours, committed; a rule there wins over a local rule with the same id).

Invariants turn the rules an agent is told to respect (for example the invariant section of `AGENT.md`) into checks guard runs on every task, replacing the generic domain templates. They come from two files, which guard merges:

| File | Owner | In Git |
|---|---|---|
| `.guard/invariants.json` | guard (setup, `guard invariants init`, rules learned in review) | never (Git-excluded) |
| `guard.invariants.json` in the repository root | the user or team | committed by the user, read-only for guard |

A rule in the repository file wins over a local rule with the same id.

```bash
# Create the local, Git-excluded .guard/invariants.json; imports numbered items under an "Invariants" (or Vietnamese "Bất biến") heading of AGENT.md / AGENTS.md / CLAUDE.md:
guard invariants init

# Create guard.invariants.json in the repository root instead, to commit for the team:
guard invariants init --shared

# Evaluate every check on the current code, without a session (exit 1: a check fails, exit 2: file missing or invalid):
guard invariants check

# Prune rules learned by the review gate without checks from the local .guard/invariants.json:
guard invariants prune
```

`guard invariants prune` is user-only and needs an interactive terminal; an agent cannot run it.

Setup creates the local file automatically and never overwrites an existing one. Imported entries start without checks (`UNVERIFIED`) until you add them:
```json
{
  "invariants": [
    {"id": "CHAT-01", "description": "Chat requests never time out",
     "checks": [{"files": "src/ai/**/*.ts", "forbid": "AbortSignal\\.timeout"}]},
    {"id": "UX-01", "description": "Message renders within 1ms"}
  ]
}
```
Every check runs on the current file contents. `forbid` fails when any matched file contains the regex, and `require` fails when none of them does. A check whose `files` glob matches nothing also fails, and so does an invalid regex. A malformed `guard.invariants.json` makes `guard pre` stop with the parse error. Invariants without checks are reported as `UNVERIFIED` (manual) and never counted as passed. A check that was already failing when pre ran is reported as `BASELINE_FAILED` (a warning), so an old defect does not block unrelated tasks; a check that starts failing during the task blocks approval. When a task adds or edits `guard.invariants.json`, post also self-checks the new file on the current tree (`... (new guard.invariants.json, self-check)`), so a malformed or failing file cannot be committed. This repository's own gate-integrity invariants live in [`guard.invariants.json`](../guard.invariants.json).

**Rules learned during review:** The LLM gate may propose durable rules it notices in the diff (`INVARIANTS:` section of its answer). Guard writes a proposal into the local `.guard/invariants.json` (never into the repository's file) only when its id and description are new and its check passes on the current code; it is tagged `"origin": "llm:<session>"`, listed under "Invariants learned in this review", and enforced from the next `guard pre`. To share a learned rule with the team, copy it into `guard.invariants.json` yourself. Rejected proposals are listed with the reason.

**The rulebook cannot be weakened as a side effect:** Adding invariants never counts as out of scope. Removing an invariant or changing its checks raises `INV-WEAKENED`: CRITICAL (blocks) unless the task declares `guard.invariants.json` in its scope. A declared edit is reported as MEDIUM for the reviewer, and the locked rules it removes are shown as RETIRED (a changed rule is re-evaluated with its new definition) instead of failing.

---

## 9. `guard reset`

Close the current guard session, for example after its work was committed or abandoned. The session is archived to `.guard/history/<session_id>.json`.

```bash
guard reset
```

---

## 10. `guard update`

Safely updates Alibaba OCR respecting the 3-day supply-chain quarantine cooling period.

```bash
# Check update status without installing:
guard update --check

# Safely upgrade Alibaba OCR (halts if release is < 3 days old):
guard update

# Explicitly bypass quarantine hold:
guard update --force

# Upgrade Banh-Mi-Guard CLI itself from the GitHub main branch (newest code, possibly ahead of the last release;
# for released versions only use `pipx upgrade banh-mi-guard` or `pip install --upgrade banh-mi-guard`):
guard update self

# Check for Guard CLI updates on GitHub without installing:
guard update self --check
```

After a successful `guard update self`, the new version runs `guard hook refresh` automatically (global hooks, guard hooks inside `.git` of recorded repositories, marked blocks in global agent docs) and prints the setup check. An upgrade done outside guard is refreshed by the first guard command of the new version.

---

## 11. `guard doctor`

Runs comprehensive system environment diagnostics and audits latest releases for both Banh-Mi-Guard CLI (GitHub) and Alibaba OCR (npm).

It also prints the **Installation & Repository Setup** table for the current folder: Git hooks, agent directives (global and in this folder/repository, including sections without guard markers), the repository's own `core.hooksPath`, `guard.invariants.json` and leftover files from older versions. Every missing item comes with the command that fixes it (`guard install`, `guard hook refresh`, `guard invariants init`). The same check runs after `guard update self` and once on the first command of a new version, showing only the problems.

```bash
guard doctor [options]
```

### Options:
* `--updates / --no-updates`: Toggle npm registry update checking (default: on).
* `-q, --quarantine-days <float>`: Cooling period in days (default: 3.0 days).

### Upgrade & Setup Check Reference:
Guard tells you what is still missing after an upgrade or during diagnostics:

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
| Old laya-ocr-guard files (hooks, agent wrapper, exclude comment, directive blocks, the old package) | `guard hook refresh`; for repository files and the package, the change doctor shows |

Markers that let guard refresh a pasted directive section:
```markdown
<!-- === BANH-MI-GUARD DUAL-GATE HOOK: START === -->
...guard directives...
<!-- === BANH-MI-GUARD DUAL-GATE HOOK: END === -->
```

**Coming from `laya-ocr-guard` (0.10 or older):** The first guard command of the new version cleans up what the old versions left wherever guard may write: their hooks inside `.git` (a copy is kept as `<hook>.laya.bak`, and the global hooks never run them), the `LAYA-OCR-GUARD` block in your global agent docs, the old agent wrapper in `.guard/bin` and the old comment in `.git/info/exclude`; `guard hook refresh` does it again on demand. `guard doctor` lists what is left, with the fix. Three things only you can do:
1. `pip uninstall laya-ocr-guard` (or `pipx uninstall laya-ocr-guard`): the old package owns the same `guard` command.
2. Replace `LAYA-OCR-GUARD` directive sections in repository agent docs, and old guard lines in hooks kept in the repository tree; guard never edits repository files.
3. Delete `~/.guard/models` (the removed Laya model, about 555 MB).

---

## 12. `guard agent`

Puts guard on the agent's own path through its hooks: an edit before `guard pre` or outside the scope, a stop with unapproved edits and a commit without an approval are refused with the reason, where the agent can refuse them. Guard writes only the agent's global (user-level) config or its own extension file, after you saw the diff, with a one-time backup; it never touches a repository file.

```bash
guard agent list                      # every agent guard knows, whether it is on this machine, and its hooks
guard agent add <agent>               # show the diff, ask, back up, write (the limits are shown first)
guard agent test <agent>              # start listening; ask the agent for one small edit; then:
guard agent test <agent> --report     # which events arrived, and whether guard answered the edit with a block
guard agent fix <agent> [--note "…"]  # regenerate an adapter from what the test saw and your note
guard agent remove <agent>            # in your own terminal: take guard's entries (or guard's file) out again
```

Agents guard ships an adapter for, each checked against the agent's own source, local install or docs:

| Agent | Where guard writes | What it can refuse |
|---|---|---|
| `claude-code` (CLI, Desktop, IDE extensions) | `~/.claude/settings.json` | edits, commits, stops |
| `codex` | `~/.codex/hooks.json` (never `config.toml`) | edits and commits (an `apply_patch` edit is reported right after it), stops; trust the hook once in Codex |
| `cursor` (app and `cursor-agent`) | `~/.cursor/hooks.json` | edits, commits, stops (`cursor-agent` sends no prompt event) |
| `grok` (Grok Build) | `~/.grok/hooks/guard.json` (guard's own file) | edits, commits, stops |
| `gemini` (Gemini CLI) | `~/.gemini/settings.json` | edits, commits, stops |
| `antigravity` | `~/.gemini/config/hooks.json` | edits and commits; a stop is only reminded |
| `zcode` | `~/.zcode/cli/config.json` (`hooks.events`, `hooks.enabled`) | edits, commits, stops |
| `omp` | `~/.omp/agent/extensions/guard-hook.ts` (guard's own file) | edits, commits, stops |
| `pi` | `~/.pi/agent/extensions/guard-hook.ts` (guard's own file) | edits and commits; pi has no stop that can be refused |
| `opencode` | `~/.config/opencode/plugins/guard-hook.js` (guard's own file) | edits and commits; opencode has no stop that can be refused |

Where a stop cannot be refused, the Git pre-commit hook still blocks an unapproved commit. Restart an agent after adding guard; `guard doctor` shows each agent's hooks and its last test.

**Several agent sessions in one folder.** Each hook event carries the agent's own session id (`session_id`, `conversation_id`, `sessionId` or `thread_id` in its payload). The agent session whose command ran `guard pre` owns that guard session; the pre note and the post report name it (`claude-code session 1a2b3c4d`), and pre records that session's own prompt, never the last one typed into any agent there. Another agent session in the same folder is judged on its own work only: its stop never waits for the owner's post or answers for the owner's edits, its edit of a tracked file and its commit are refused with the owner's task and the fix (`git worktree add` for parallel work, or wait until the task is committed), and files its commands change outside the owner's scope are reported to it and stop it until they are undone. A `guard pre --force` from another session is refused. A `guard pre` run by hand has no owner, nor has one started by two agent sessions at the same moment, and an agent that sends no session id keeps the shared behaviour; `guard doctor` names those agents.

**Any other agent.** `guard agent add <name>` investigates it on this machine: its binary, its version number and the structure of its config files (key names, numbers and booleans; every text value and any key that could be data is replaced, so nothing you wrote leaves the machine). The configured LLM proposes an adapter from that and what it knows of the agent; guard checks it (only guard's own command can run, only a user-level JSON config is written) and shows the diff. A config that is not JSON (TOML, YAML) gets the entries printed for you to add. When guard cannot set an agent up (not found, no hooks, an unsafe proposal, or a test that saw no event), it says why, suggests `guard agent fix <name> --note "<what the docs say>"`, and prints a prefilled GitHub issue (agent, guard version, OS, config file names, the problem; never a config's contents) that you can read and send yourself.

---

## 13. `guard laya`

Removed in 0.11. The Laya neural triage only produced informational guesses and never influenced a gate decision; the repository domain is detected from the repository itself. `guard laya ...` prints this notice, and old model files in `~/.guard/models` can be deleted.

---

## 14. `guard accept`

For the user, in an interactive terminal: decide a task that used its review rounds (`needs_user`). An agent cannot run it.

```bash
guard accept
```

The screen names the task, the session, the rounds used, the last verdict with the gate that ran, and the time of the last post. Under it come the deterministic gates of that round (build, invariants, scope, OCR: passed, failed or not run) and the files changed since the review. The remaining findings follow in two groups, blocking first, then the advisory follow-ups, each sorted by severity. At 100 columns or more they are a table; below that, stacked blocks. The prompt accepts only the choices that are possible and defaults to `q`:

- `a` approves the files exactly as last reviewed and keeps the findings as follow-ups. It is shown as not possible, with the reason, when a file changed since the review or a deterministic gate did not pass.
- `c` allows three more review rounds; run `guard post` next.
- `q` changes nothing.

A sample at 80 columns:

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ 🧑 GUARD ACCEPT: a task is waiting for your decision                         │
│ Task: Scope the SEC-008 exemption to the receiver of the storage call        │
│ Session: guard-1790907479                                                    │
│ Rounds: 3 of 3 review rounds used                                            │
│ Last verdict: REVISE 5.5/10 (LLM Gate)                                       │
│ Last post: 2026-10-02 04:50:33 UTC                                           │
└──────────────────────────────────────────────────────────────────────────────┘
Build: ✅ passed   Invariants: - not run   Scope: ✅ passed   OCR: ✅ passed
Files changed since the review: 0

Blocking (would stop the commit): 1
• [15e3ecbb] HIGH security · open
  guard/core/rules.py:294
    A ternary that reads an encrypted store can exempt a plaintext write.

Follow-ups (advisory): 1
• [c84561df] MEDIUM correctness · deferred
  guard/core/rules.py:432
    Several Swift branches on one line.
    note: heuristic limit; later version
┌─────────────────────────────── Your decision ────────────────────────────────┐
│ (a) approve the files exactly as last reviewed; the findings above stay as   │
│ follow-ups                                                                   │
│ (c) allow three more review rounds (budget 3 -> 6), then run guard post      │
│ (q) quit, nothing changes                                                    │
└──────────────────────────────────────────────────────────────────────────────┘
Your choice [a/c/q] (q):
```

With `NO_COLOR` set the screen is plain text, and it shows `[ok]`, `[x]` and `[?]` instead of emoji. So does a legacy Windows console, or one whose encoding cannot hold emoji (cp1252).

---

## 15. `guard finding`

Records a user or agent decision to defer or reject a specific review finding for the next review round:

```bash
# Defer finding with rationale:
guard finding <id> --defer "Deferred to next sprint; handled in issue #42"

# Reject finding with evidence:
guard finding <id> --reject "False positive: sanitization occurs in upstream middleware"
```

The next review round sees the reason; a finding still blocks until the review agrees or the violation is fixed.

---

## 16. `guard untracked`

Decides whether an untracked file or folder is a normal part of the repository or should always be ignored:

```bash
guard untracked                       # list recorded untracked file decisions
guard untracked <path> --include       # mark path as tracked/audited part of repository
guard untracked <path> --ignore        # mark path as locally ignored (added to .git/info/exclude)
```

---

## 17. `guard setup`

Interactive setup wizard checking for what is missing on this machine: LLM credentials, Alibaba OCR installation, commit message policy, and agent hook integration:

```bash
guard setup
```

---
*Created and maintained by [@okrath](https://github.com/okrath) &mdash; Source code available at [github.com/okrath/banh-mi-guard](https://github.com/okrath/banh-mi-guard).*
