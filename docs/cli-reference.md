# CLI Command Reference: `guard`

> 📦 **GitHub Repository:** [github.com/okrath/banh-mi-guard](https://github.com/okrath/banh-mi-guard) &bull; 👤 **Author:** [@okrath](https://github.com/okrath) &bull; 📖 **Live Documentation:** [okrath.github.io/banh-mi-guard](https://okrath.github.io/banh-mi-guard/)

Complete command-line manual for `banh-mi-guard`.

---
## 1. `guard pre`

Runs the Pre-Task Guard phase before modifying code.

```bash
guard pre "<prompt>" [options]
```

### Arguments:
* `prompt` (required): Natural language description of the task about to be performed.

### Options:
* `-r, --repo <path>`: Target repository directory (default: current directory).
* `-q, --quick`: Accepted for compatibility; has no effect since the triage was removed in 0.11.
* `-s, --scope <path|dir|glob>` (repeatable): Declare the files the task may change. Files named in the prompt are added automatically; globs are accepted only here. On Windows prefer a directory (`--scope src/ui`) over a quoted glob.
* `--allow-dirty`: Start although files are already modified. They are snapshotted (`git stash create`, working tree untouched) and reported as pre-existing; post reviews only the edits made after pre.
* `--force`: Restart an unfinished or rejected session. The restart keeps its baseline, snapshot, base commit, scope and locked invariants, is listed in the reports, and scope added by it fails as `SCOPE-004`.

Pre refuses to start on a dirty tree (without `--allow-dirty`) and over an unfinished or rejected session (without `--force`).

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
* `--hook`: Git-hook mode. Skips when the repository has no guard session; with an approved session, passes only when the changes match what was approved. Never runs OCR.
* `--full`: Full review. Also runs the Alibaba OCR review of the task's changes (it reads the repository, takes minutes and has no time limit). OCR not running, or a high/critical finding, blocks (REVISE). Without it the report says "Alibaba OCR: not run", and an approved report tells the agent to ask you before committing whether you want this full review.

Post audits against the base commit recorded at pre, runs the build command, invariant checks and the removed-symbol reference check, then asks the LLM. A new or edited `guard.invariants.json` is self-checked on the current tree; a declared edit that removes or changes rules shows them as RETIRED / re-evaluated and reports `INV-WEAKENED` (MEDIUM), an undeclared one blocks (CRITICAL). Rules the LLM discovers are written, after validation, into the local `.guard/invariants.json` (never into the repository's file).

---

## 3. `guard run`

Executes the automated Sandwich Pattern around any command.

```bash
guard run "<prompt>" -- <command...>
```

Accepts the same pre-task options: `--scope`, `--allow-dirty`, `--force`.

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
guard config sync

# Choose whether every guard post runs Alibaba OCR (only the user can run this, in an interactive terminal):
guard config ocr always   # every guard post runs Alibaba OCR review
guard config ocr optional # only guard post --full runs it

# Choose who writes commit messages for approved work (machine-wide):
guard config commit auto   # the agent writes them (conventional, never mentions guard)
guard config commit ask    # the agent asks you for every commit message
```

`guard config ocr` is the user's decision and can only be run by the user in an interactive terminal.
`guard post` reports the chosen mode in the **Commit** line of an approved report; while no mode is set, the agent is told to ask you which one you want. `guard install` and `guard doctor` list it as "Commit messages".

**Your own agent CLI instead of an API key.** `guard config llm` offers a third choice, *My agent CLI*: the review gate then asks `claude`, `codex` or `omp` on this machine (`guard agent add` offers it for the agent it adds) (your subscription answers, no key or gateway). Guard sends one prompt and reads one answer, with the CLI's tools off (`claude -p --tools ""`) or read-only (`codex exec --sandbox read-only`), in an empty temporary folder outside any repository. `guard config test` checks it without a review prompt: the CLI's sign-in (`claude auth status`, `codex login status`) and its model list (`codex debug models` reads the catalog locally; `claude -p /model` usually answers without a model call), which `guard config llm` also offers to pick the model from. A CLI that fails is an LLM failure (Heuristic Gate plus the reason), never an approval. With *My agent CLI*, `guard post --full` runs Alibaba OCR through the same CLI: guard starts a local endpoint for that review only (127.0.0.1, a random port and token), runs OCR from a throwaway home whose OCR settings point at it (your own OCR settings are never changed), and answers each of OCR's requests with one CLI call that has OCR's tools written into the prompt and returns one tool call, which OCR runs. Two requests run at a time. The report says `answered by the <cli> CLI (tool calls written as text)`, and a CLI that fails is an OCR failure with its reason. When that review does not run, guard warns and falls back to OCR's delegation mode: `ocr delegate preview` and `ocr delegate rule` list the files and OCR's rules for them, and the same CLI, tools still off, reviews each rule group's diff (20 lines of context) in one prompt, in parts with the same rules when the group is over 150,000 characters, and answers OCR's findings as JSON. The report then says `answered by the <cli> CLI as the fallback after …` with the first path's reason. A file the fallback did not review (the CLI failed or answered something unreadable, or its diff alone is over the limit) keeps it a failed review (OCR-RUN).

---

## 6. `guard install` / `guard uninstall`

```bash
guard install                          # global: hooks for every repo + directives in installed agents' global files
guard install --workspace <dir>        # workspace: directives in <dir>/CLAUDE.md and AGENT.md + hooks in its repos
guard uninstall [--workspace <dir>]    # remove the marked directive blocks and guard's hooks
```

Global writes the marked guard block into `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, `~/.gemini/GEMINI.md` and `~/.config/opencode/AGENTS.md`, only for agents whose config directory exists; existing content is kept and backed up once (`*.guard.bak`). Uninstall removes only the marked block (deleting a file that held nothing else) and unsets `core.hooksPath` only when it points at guard's hooks.

---

## 7. `guard hook`

Manages Git hooks, AI Agent directives, and multi-repo workspace protection. `guard hook install` without options runs `guard install`; its options keep the previous per-repository behavior.

After `guard install`, every repository is set up automatically the first time guard runs in it, without creating any repository diff: the local, Git-excluded `.guard/invariants.json` is created when the repository has no invariants, and a guard hook is added only when Git runs hooks from inside `.git`. Hooks kept in the repository tree (e.g. `.husky/`) and repository agent docs are never edited; `guard doctor` shows what to change. `guard hook refresh` rewrites what guard installed earlier to the current version; the same refresh runs once automatically after each upgrade.

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

Every install mode creates the local `.guard/invariants.json` when the repository has no invariants (see `guard invariants init`) and never overwrites an existing file. Where guard appends directives it keeps the existing content, adds a marked block and makes a one-time `.guard.bak` backup.
---

## 8. `guard invariants`

Create and validate project invariants: the local, Git-excluded `.guard/invariants.json` (guard's) and the optional `guard.invariants.json` in the repository root (yours, committed; a rule there wins over a local rule with the same id).

```bash
# Create the local, Git-excluded .guard/invariants.json; imports numbered items under an "Invariants" (or Vietnamese "Bất biến") heading of AGENT.md / AGENTS.md / CLAUDE.md:
guard invariants init

# Create guard.invariants.json in the repository root instead, to commit for the team:
guard invariants init --shared

# Evaluate every check on the current code, without a session (exit 1: a check fails, exit 2: file missing or invalid):
guard invariants check
```

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

## 13. `guard laya` (removed)

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
*Created and maintained by [@okrath](https://github.com/okrath) &mdash; Source code available at [github.com/okrath/banh-mi-guard](https://github.com/okrath/banh-mi-guard).*
