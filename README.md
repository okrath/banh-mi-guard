# Banh Mi Guard (`guard`)

<p align="center">
  <img src="docs/assets/logo.svg" width="160" height="160" alt="Banh Mi Guard Logo - The Bánh Mì Sandwich Pattern">
  <br>
  <strong>Dual-Gate Impact Analysis & Regression Guard for AI-Assisted Development</strong>
  <br>
  <em>Enforcing the Sandwich Pattern with scope control, deterministic diff auditing, project invariants, and LLM gatekeeping.</em>
</p>

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Documentation](https://img.shields.io/badge/docs-live_website-brightgreen.svg)](https://okrath.github.io/banh-mi-guard/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#cross-platform-installation-windows-linux-macos)
[![Architecture](https://img.shields.io/badge/architecture-Dual--Gate-green.svg)](#three-pillar-architecture)

`guard` wraps coding workflows in an automated safety harness that verifies changes before and after execution. It runs two gates around each task: a pre-task scope check and a post-task verification gate combining deterministic diff checks, static rules, project invariants, and an LLM review.

**Live Documentation:** [https://okrath.github.io/banh-mi-guard/](https://okrath.github.io/banh-mi-guard/)

---

## Cross-Platform Installation (Windows, Linux, macOS)

Install the `guard` CLI globally on any platform:

```bash
# Recommended: Isolated global installation with pipx
pipx install banh-mi-guard

# Or with standard pip across all platforms:
pip install banh-mi-guard
```

For environment `$PATH` configuration, installation from GitHub main, and optional Alibaba OCR CLI setup, see [CLI Reference: Installation & Environment Setup](docs/cli-reference.md#installation--environment-setup).

---

## Five-Minute Quickstart

Integrate guard into your workflow in four simple steps:

```bash
# 1. PRE-TASK: Declare scope and capture baseline before editing code
guard pre "Implement mobile responsive navigation drawer" --scope src/components/nav

# 2. EDIT: Modify code using your AI agent (Claude Code, Cursor, Codex, etc.) or editor

# 3. POST-TASK: Verify diffs, static security rules, build health, and LLM approval
guard post

# 4. COMMIT: Commit approved changes (approvals are HMAC-signed; unapproved commits or unsigned older sessions are blocked)
git commit -m "feat: add responsive navigation drawer"
```

To run deep repository inspection with Alibaba OCR, use `guard post --full`. For a large or security-sensitive change, the post report asks you (through your agent) whether you want a deeper review by a panel of three reviewers, a full OCR review, or both.

---

## Three-Pillar Architecture

Every modification is verified before and after execution across three layers:
1. **Deterministic Pre-Task Gate (0 tokens):** Locks declared scope boundaries, records baseline snapshots, and evaluates project invariants.
2. **Deterministic Post-Task Verification (0 tokens):** Audits diff blast radius, runs compilation/tests, checks for deleted references (`DEAD-REF`), evaluates static rules (`SEC-001` to `SEC-008`), and detects code hygiene issues.
3. **Generative LLM Gatekeeper:** Configured LLM (Claude, GPT, DeepSeek, Ollama, or local agent CLIs) evaluates batched diffs and verified evidence for a final `APPROVED` or `REVISE` verdict. Approved sessions receive a cryptographic HMAC signature required by Git commit hooks.

For architectural diagrams, taxonomy, and security specifications, see [Architecture Specification](docs/architecture.md).

---

## Command Overview

* **Verification Harness (`guard pre`, `guard post`, `guard run`):** Enforces the Sandwich Pattern. `guard pre` sets scope and invariant baselines; `guard post` audits diffs, executes test suites, and requests gate approval; `guard run` wraps external commands in both gates atomically. See [CLI Reference: Pre & Post](docs/cli-reference.md#1-guard-pre).
* **Project Invariants (`guard invariants`):** Enforces domain and team behavioral invariants without token costs using regex checks across local (`.guard/invariants.json`) and shared (`guard.invariants.json`) files. See [CLI Reference: Invariants](docs/cli-reference.md#8-guard-invariants).
* **Agent & Hook Integration (`guard install`, `guard hook`, `guard agent`, `guard uninstall`):** Configures Git hooks (`core.hooksPath`) and injects directives into global agent instruction files (`CLAUDE.md`, `AGENT.md`). Agent hook adapters intercept edit tools to block out-of-scope or unauthorized modifications. See [CLI Reference: Installation & Hooks](docs/cli-reference.md#6-guard-install--guard-uninstall).
* **Configuration & Setup (`guard config`, `guard setup`):** Interactive wizards for configuring LLM credentials (APIs or local agent CLIs like `claude`, `codex`, `omp`), syncing settings to Alibaba OCR, and choosing commit message policies. See [CLI Reference: Configuration](docs/cli-reference.md#5-guard-config).
* **Review, Findings & Approvals (`guard review`, `guard finding`, `guard accept`, `guard reset`):** Runs on-demand LLM diff reviews, tracks deferred or rejected findings, provides an interactive decision screen when review budgets are exhausted, and archives sessions. See [CLI Reference: Review & Accept](docs/cli-reference.md#4-guard-review).
* **Diagnostics & Supply-Chain Security (`guard doctor`, `guard update`, `guard untracked`):** Performs environment diagnostics, upgrades guard (directly from GitHub) or Alibaba OCR (under a 3-day supply-chain quarantine cooling period covering OCR only), and tracks untracked directory exclusions. See [CLI Reference: Doctor & Update](docs/cli-reference.md#10-guard-update).

---

## Documentation & Quality Reference

* 📖 **[CLI Command Reference](docs/cli-reference.md):** Complete option flags, syntax, and operational rules for every command.
* 🏛️ **[Architecture Specification](docs/architecture.md):** Detailed system taxonomy, defense layers, state isolation, and HMAC approval signing.
* 🔎 **[Review Options, Stages & Limits](docs/cli-reference.md#review-options-stages--limits):** Optional review stages of `guard post` (reviewer panel, finding validation, test evidence, threat frame), what they cost, and the *Not reviewed / limits* section of the report. Developer-only measurement tool: [Benchmark](docs/benchmark.md).
* 🛡️ **[Quality Pillars & Matrix](docs/quality-pillars.md):** 2D quality matrix (domains × pillars), static rule catalog, and scoring rules.
* 🚀 **[Releasing Guide](docs/quality-pillars.md#releasing-maintainers):** Release process, version tagging, and PyPI trusted publishing workflow.
* 🌐 **[Live Documentation Website](https://okrath.github.io/banh-mi-guard/):** Interactive documentation guide and full feature matrix.

---

## Running the Test Suite

Run the integration and unit test suite locally:
```bash
pytest
```
