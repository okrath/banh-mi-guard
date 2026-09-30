# Quality Pillars: What Guard Checks, and How

> 📦 **GitHub Repository:** [github.com/okrath/banh-mi-guard](https://github.com/okrath/banh-mi-guard) &bull; 👤 **Author:** [@okrath](https://github.com/okrath) &bull; 📖 **Live Documentation:** [okrath.github.io/banh-mi-guard](https://okrath.github.io/banh-mi-guard/)

`guard` looks at a change through several quality pillars. Each concern below is covered in one of three ways, and this page says which:

| How | What it means |
| :--- | :--- |
| **Rule** | A deterministic check on the diff or the repository, with a rule ID. It runs on every `guard post`, costs no tokens, and its findings are listed in the report. |
| **Project invariant** | A regex check you (or the LLM gate, locally) wrote in `guard.invariants.json` / `.guard/invariants.json`. Evaluated on the current files at pre and post. |
| **LLM review** | Something the configured LLM is asked to look at in the diff (the default 360° audit, or a `--focus` area). Not a deterministic check. |

When a repository has no project invariants, guard adds a few generic **template invariants** for the detected domain (frontend, backend, fullstack, infra, mobile). Most of them are only heuristics on the diff and are reported as `UNVERIFIED` when no heuristic applies.

---

## 1. 🛡️ Security & Secrets

| Concern | How | ID |
| :--- | :--- | :--- |
| Hardcoded API keys, tokens, passwords in added lines | Rule | `SEC-001` (CRITICAL) |
| SQL built by string concatenation | Rule | `SEC-002` (CRITICAL) |
| Unsanitized HTML sinks: `innerHTML`/`outerHTML` `=` and `+=`, `dangerouslySetInnerHTML`, `v-html`. A comment mentioning "sanitize" does not exempt a line; only an empty literal, a single `DOMPurify.sanitize(...)` value or `// guard-allow SEC-003: <reason>` (listed as LOW) does | Rule | `SEC-003` (HIGH) |
| Unsafe deserialization: `yaml.load` / `yaml.load_all` whose own arguments name no `SafeLoader`, `yaml.unsafe_load(_all)`, `pickle`/`marshal` loads (Python) | Rule | `SEC-004` (HIGH) |
| A string run as a shell command or code: `shell=True`, `os.system`/`os.popen`, `eval`/`exec` (Python); `eval`, `new Function` (JS/TS) | Rule | `SEC-005` (HIGH) |
| TLS certificate checking turned off: `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`, `NODE_TLS_REJECT_UNAUTHORIZED=0` | Rule | `SEC-006` (HIGH) |
| CORS open to every origin (`Access-Control-Allow-Origin: *`, `allow_origins=["*"]`, `origin: '*'`) | Rule | `SEC-007` (MEDIUM) |
| A credential stored in `localStorage` (token, jwt, secret, password, API key, session keys; by `setItem`, property or index) | Rule | `SEC-008` (MEDIUM) |
| Container with host-level privileges (`privileged`, `allowPrivilegeEscalation`, `hostNetwork`, `hostPID`, `hostIPC`: `true` in YAML) | Rule | `INFRA-001` (HIGH) |
| Container running as root (`USER root` / `USER 0` with no later `USER` of another user in the diff) | Rule | `INFRA-003` (MEDIUM) |
| Android app shipped debuggable or allowing plain-HTTP traffic (`android:debuggable`, `usesCleartextTraffic`; not in `debug/` manifests) | Rule | `MOB-001` (HIGH) |
| App data in device backups (`android:allowBackup="true"`) | Rule | `MOB-002` (MEDIUM) |
| Auth, RBAC, IDOR, public ports, secrets in manifests | LLM review (`--focus security`); template invariants for backend/infra | — |

These line rules read added lines only, and skip docs (Markdown and text files, and anything in a `docs/` or `doc/` folder), test files (in a `tests/`, `test/` or `__tests__/` folder, or named `test_*`, `*_test.*`, `*.test.*`, `*.spec.*`), comment lines, trailing comments (`#` in Python, YAML and Dockerfiles, `//` elsewhere, and a `/*` or `<!--` left open, found outside strings; code after a block comment closed on the line is still read), names quoted in prose (``eval()``), lines over 2,000 characters (minified or generated), and in a Dockerfile a `FROM` that names an earlier stage. Text inside strings and docstrings is read like code: a string can hold code that runs, and a security rule would rather report a sentence that mentions `eval(` than miss a call (mark such a line with `guard-allow`). A line that is intended keeps the finding as a LOW note with `guard-allow <RULE>: <reason>` in a comment on it (in a string it counts for nothing) (for example `# guard-allow SEC-005: fixed command, no user input`).

## 2. 🧠 Memory Safety & Resource Leaks

| Concern | How | ID |
| :--- | :--- | :--- |
| Global `resize`/`scroll`/`mousemove`/`keydown` listener added with no `removeEventListener` in the diff | Rule | `PERF-001` (HIGH) |
| `setInterval` added with no `clearInterval(` call (outside strings and comments) in the lines of the same file the diff shows (JS/TS, Vue, Svelte) | Rule | `PERF-003` (MEDIUM) |
| A new Kubernetes workload (Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob, Pod) whose YAML document sets no `resources.limits` in the lines the diff shows (judged per document, not per container) | Rule | `INFRA-004` (MEDIUM) |
| Unclosed streams, sockets, DB connections; retained closures; DOM leaks | LLM review (`--focus memory`) | — |

## 3. ⚡ Performance & Latency

| Concern | How | ID |
| :--- | :--- | :--- |
| Blocking sync I/O (`readFileSync`, `writeFileSync`, `execSync`, `spawnSync`) in JS/TS | Rule | `PERF-002` (MEDIUM) |
| N+1 queries, excessive re-renders, thread lockups | LLM review (`--focus performance`) | — |

## 4. 🧱 Integrity, Scope & Contracts

| Concern | How | ID |
| :--- | :--- | :--- |
| Files changed outside the declared scope | Scope audit (marked OUT-OF-SCOPE; blocks) | `SCOPE-001` in `guard review` |
| File deleted (confirm the task asked for it) | Rule | `SCOPE-002` (MEDIUM) |
| Files already modified before pre (`--allow-dirty`) | Rule | `SCOPE-003` |
| File covered only by scope added in a `--force` restart | Rule | `SCOPE-004` (HIGH) |
| Project rules (behavior that must not break) | Project invariant | your IDs |
| Invariants file removed or relaxed; malformed invariants file | Rule | `INV-WEAKENED`, `INV-FILE` |
| Deep property access without optional chaining (`a.b.c.d`) | Rule | `STAB-001` (MEDIUM) |
| Image without a pinned tag or digest, or `:latest` (YAML `image:`, Dockerfile `FROM`; in an edited Dockerfile a stage defined outside the diff looks like an image: mark that line with `guard-allow`) | Rule | `INFRA-002` (MEDIUM) |
| API schema compatibility, atomic multi-table writes | LLM review; backend template invariants (UNVERIFIED) | — |
| The project still builds / tests pass | Build command (`pnpm run build`, `pytest`, `go test ./...`, ...) | build check (blocks on failure) |

## 5. ♿ Ergonomics & UX

| Concern | How | ID |
| :--- | :--- | :--- |
| Removed keyboard handlers (`keydown`, `'Escape'`, `keyCode 27`) when a template invariant asks to keep them | Template invariant heuristic | frontend template |
| Keyboard focus ring removed (`outline: none` / `outline: 0` in CSS or markup), a hint to check for a `:focus-visible` style | Rule | `UX-001` (LOW) |
| Image without alt text (an `<img>` tag on one line with no `alt`, `[alt]` or `{alt}`, props not spread) | Rule | `UX-002` (MEDIUM) |
| A new long-running Kubernetes workload with no liveness or readiness probe | Rule | `INFRA-005` (LOW) |
| Responsive layout, focus handling, visual feedback, modal dismissal | LLM review (`--focus ux`) | — |

## 6. 🧹 Code & Asset Hygiene (Dead Code Gate)

| Concern | How | ID |
| :--- | :--- | :--- |
| New files that nothing references, draft names (`*.tmp`, `*backup*`, `temp_*`) | Rule | `DEAD-001` |
| 3+ consecutive lines of commented-out code | Rule | `DEAD-002` |
| Unused private helpers and imports (AST, with `--focus dead-code`) | Rule | `DEAD-003` |
| A removed string key (`case 'edit':`), export or CSS class that is still referenced somewhere in the repository | Rule | `DEAD-REF` (HIGH) |

## 7. 🛋️ Simplicity (KISS & YAGNI)

*Inspired by Larry Wall's virtue of Laziness and Dietrich Gebert's Ponytail philosophy: "The best code is the code you never wrote."*

| Concern | How | ID |
| :--- | :--- | :--- |
| Redundant packages (`is-odd`, `uuid`, `mkdirp`, `rimraf`, `pathlib2`, `mock`) when stdlib or the runtime suffices | Rule | `LAZY-001` |
| Single-use interfaces, pass-through wrappers, deep class hierarchies | Rule | `LAZY-002` |
| Re-implemented utilities (`clamp`, `slugify`, `is_empty`, `flatten`, `deep_clone`) | Rule | `LAZY-003` |
| Net lines added or removed | Informational only (deleting code earns no score bonus) | `NET-LOC` |

---

## Domains × pillars: what is deterministic where

The same rules run on every repository; which ones matter depends on the files a change touches. A cell
lists the rules that cover it; a cell with none relies on the LLM review (and on your project invariants).

| Domain | 🛡️ Security | 🧠 Memory | ⚡ Performance | 🧱 Integrity | ♿ UX | 🧹 Hygiene | 🛋️ Simplicity |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Frontend | `SEC-001` `SEC-003` `SEC-005` `SEC-006` `SEC-007` `SEC-008` | `PERF-001` `PERF-003` | `PERF-002` | `STAB-001` | `UX-001` `UX-002` | `DEAD-*` | `LAZY-*` |
| Backend | `SEC-001` `SEC-002` `SEC-004` `SEC-005` `SEC-006` `SEC-007` | `PERF-003` (Node) | `PERF-002` (Node) | build check, invariants, `STAB-001` | LLM | `DEAD-*` | `LAZY-*` |
| Fullstack | frontend + backend rules | as both | as both | invariants on the API contract | as both | `DEAD-REF` across halves | `LAZY-*` |
| Infra | `SEC-001` `INFRA-001` `INFRA-003` `SEC-006` | `INFRA-004` | LLM | `INFRA-002` | `INFRA-005` | `DEAD-001` | LLM |
| Mobile | `SEC-001` `SEC-006` `MOB-001` `MOB-002` | `PERF-003` (React Native) | LLM | LLM | LLM | `DEAD-001` `DEAD-002` | LLM |

---

## Scoring and the final verdict

- **Blocks outright** (no LLM can approve): a failed build, a violated invariant, a CRITICAL rule, a file out of scope, and in `--focus dead-code` / `--focus simplicity` any finding of that pillar.
- Otherwise the heuristic score starts at 10 and loses points for HIGH findings (and, lightly, for hygiene and simplicity findings); below 7.5 the heuristic verdict is REVISE.
- The configured LLM then reviews the report, the verified evidence and the diff (in parts when it is large) and gives the final `APPROVED` / `REVISE`. If it does not answer, the report says "Heuristic Gate (no LLM review)" and why.

## Focus flag (`--focus`)

By default the LLM runs a 360° audit (`--focus all`). A focus narrows the review, and for `dead-code` and `simplicity` also makes that pillar's rules blocking:

```bash
guard post --focus security      # injection, secrets, CSRF, auth bypass
guard post --focus memory        # listeners, unclosed resources, leaks
guard post --focus performance   # blocking I/O, N+1, re-renders
guard post --focus ux            # keyboard, modals, responsiveness, feedback
guard post --focus dead-code     # orphans, commented code, unused symbols (full-file AST scan)
guard post --focus simplicity    # over-engineering, bloat, reinvented wheels
```
The same `--focus` values work with `guard review`.

---
*Created and maintained by [@okrath](https://github.com/okrath) &mdash; Source code available at [github.com/okrath/banh-mi-guard](https://github.com/okrath/banh-mi-guard).*
