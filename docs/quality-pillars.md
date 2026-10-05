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

## Multi-Domain Coverage (FE, BE, Fullstack, Infra, MB)

`guard` detects the repository's domain from the repository itself, scoring several signals instead of taking the first marker file: Node dependencies of every `package.json` (monorepos included), web framework configs, `index.html`, UI component files, `server/`/`api/` directories, Python/Go/Rust/Java manifests, Terraform/Helm/Kubernetes and container files. A Node backend is not reported as frontend, an app with a `Dockerfile` is not infra, and a repository with both a web client and a server is `fullstack`.

The domain selects the **template invariants** used when the repository has no project invariants (most of them are diff heuristics and show as `UNVERIFIED`). The build command is chosen per ecosystem, not per domain:

| Domain | Typical stacks | Template invariants (only without project invariants) | Build / test command guard runs |
| :--- | :--- | :--- | :--- |
| **FE** (Frontend) | React, Next.js, Vue, Svelte, Vite | loading / disabled states, keyboard shortcuts (`Escape`, `Enter`), responsive layout | `<pm> run build` (or `check`, else `<pm> test`) |
| **BE** (Backend) | Go, Python, Node APIs (Fastify, Express, NestJS), Rust | JSON schema compatibility, parameterized SQL, atomic DB transactions | `go test ./...`, `cargo test`, `pytest`, or the package script for Node |
| **Fullstack** | web client + server in one repository or monorepo | frontend templates | the package script |
| **Infra** (DevOps) | Terraform, Helm, Kubernetes (IaC-only repositories) | no hardcoded secrets, no 0.0.0.0 DB binding, health checks | `terraform validate`, `docker compose config` |
| **MB** (Mobile) | Flutter, React Native, iOS, Android | permission flows, SafeArea, offline fallback | `flutter analyze`, `./gradlew test` |

`<pm>` is `pnpm`, `yarn`, `bun` or `npm`, from the lockfile.

---

## 1. 🛡️ Security & Secrets

| Concern | How | ID |
| :--- | :--- | :--- |
| Hardcoded API keys, tokens, passwords in added lines | Rule | `SEC-001` (CRITICAL) |
| SQL built by string concatenation or interpolation (`+`, `.`, f-strings, `%`, `.format`, `${...}`, `fmt.Sprintf`, `String.format`, `string.Format`, `#{...}`, `"$var"`, `format!`, `"\(x)"` in Python, JS/TS, Go, Ruby, PHP, Java, Kotlin, C#, Rust, Swift, Dart) | Rule | `SEC-002` (CRITICAL) |
| Raw HTML sinks: `innerHTML`/`outerHTML` `=` and `+=`, `dangerouslySetInnerHTML`, `v-html` (JS/TS); `mark_safe`, `Markup`, `|safe` (Python); `template.HTML` (Go); `html_safe`, `raw` (Ruby); `Html.Raw` (C#); `bypassSecurityTrustHtml` (Angular); echoed `$_GET`/`$_POST`/`$_REQUEST` (PHP). A comment mentioning "sanitize" does not exempt a line; only an empty literal, a single `DOMPurify.sanitize(...)` value or `// guard-allow SEC-003: <reason>` (listed as LOW) does | Rule | `SEC-003` (HIGH) |
| Unsafe deserialization: `yaml.load` / `yaml.load_all` without `SafeLoader`, `yaml.unsafe_load(_all)`, `pickle`/`marshal` (Python); `ObjectInputStream.readObject`, Jackson default typing (Java, Kotlin); `unserialize` (PHP); `Marshal.load`, `YAML.load` (Ruby); `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter` (C#) | Rule | `SEC-004` (HIGH) |
| A string run as a shell command or code: `shell=True`, `os.system`/`os.popen`, `eval`/`exec` (Python); `eval`, `new Function` (JS/TS); `exec.Command` with a shell (Go); `Runtime.exec`/`ProcessBuilder` with a shell (Java, Kotlin); `system`/`exec`/`shell_exec`/`passthru`/`popen`/`proc_open`/`eval`/backticks (PHP); `system`/`exec`/%x/backticks/`eval` (Ruby); `Process.Start` with a shell (C#); `Command::new("sh").arg("-c")` (Rust); `Process()` with `/bin/sh` (Swift) | Rule | `SEC-005` (HIGH) |
| TLS certificate checking turned off: `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`, `NODE_TLS_REJECT_UNAUTHORIZED=0` | Rule | `SEC-006` (HIGH) |
| CORS open to every origin (`Access-Control-Allow-Origin: *`, `allow_origins=["*"]`, `origin: '*'`) | Rule | `SEC-007` (MEDIUM) |
| A credential stored in client storage: `localStorage`/`sessionStorage` (JS/TS), `AsyncStorage.setItem` (React Native), `SharedPreferences` `putString` (Java, Kotlin), `UserDefaults.set` (Swift), `SharedPreferences` `setString` (Dart) | Rule | `SEC-008` (MEDIUM) |
| Container with host-level privileges (`privileged`, `allowPrivilegeEscalation`, `hostNetwork`, `hostPID`, `hostIPC`: `true` in YAML) | Rule | `INFRA-001` (HIGH) |
| Container running as root (`USER root` / `USER 0` with no later `USER` of another user in the diff) | Rule | `INFRA-003` (MEDIUM) |
| Android app shipped debuggable or allowing plain-HTTP traffic (`android:debuggable`, `usesCleartextTraffic`; not in `debug/` manifests) | Rule | `MOB-001` (HIGH) |
| App data in device backups (`android:allowBackup="true"`) | Rule | `MOB-002` (MEDIUM) |
| iOS App Transport Security off (`NSAllowsArbitraryLoads` true in `Info.plist`, value on the same or next line) | Rule | `MOB-001` (HIGH) |
| iOS Documents folder shared through Finder (`UIFileSharingEnabled` true in `Info.plist`) | Rule | `MOB-002` (MEDIUM) |
| Auth, RBAC, IDOR, public ports, secrets in manifests | LLM review (`--focus security`); template invariants for backend/infra | — |

These line rules read added lines only, and skip docs (Markdown and text files, and anything in a `docs/` or `doc/` folder), test files (in a `tests/`, `test/` or `__tests__/` folder, or named `test_*`, `*_test.*`, `*.test.*`, `*.spec.*`), comment lines, trailing comments (`#` in Python, YAML and Dockerfiles, `//` elsewhere, and a `/*` or `<!--` left open, found outside strings; code after a block comment closed on the line is still read), names quoted in prose (``eval()``), lines over 2,000 characters (minified or generated), and in a Dockerfile a `FROM` that names an earlier stage. Text inside strings and docstrings is read like code: a string can hold code that runs, and a security rule would rather report a sentence that mentions `eval(` than miss a call (mark such a line with `guard-allow`). A line that is intended keeps the finding as a LOW note with `guard-allow <RULE>: <reason>` in a comment on it (in a string it counts for nothing) (for example `# guard-allow SEC-005: fixed command, no user input`).

---

## 2. 🧠 Memory Safety & Resource Leaks

| Concern | How | ID |
| :--- | :--- | :--- |
| Resources opened without a guaranteed close (files, sockets, DB connections, child processes); listeners, timers and subscriptions never removed on teardown; caches and collections that only grow; closures that hold large objects (any language) | LLM review | — |
| A new Kubernetes workload without `resources.limits` | LLM review (`--focus memory`) | — |

---

## 3. ⚡ Performance & Latency

| Concern | How | ID |
| :--- | :--- | :--- |
| Blocking calls inside async or event-loop code; N+1 queries, excessive re-renders, thread lockups (any language) | LLM review | — |

---

## 4. 🧱 Integrity, Scope & Contracts

| Concern | How | ID |
| :--- | :--- | :--- |
| Files changed outside the declared scope | Scope audit (marked OUT-OF-SCOPE; blocks) | `SCOPE-001` in `guard review` |
| File deleted (confirm the task asked for it) | Rule | `SCOPE-002` (MEDIUM) |
| Files already modified before pre (`--allow-dirty`) | Rule | `SCOPE-003` |
| File covered only by scope added in a `--force` restart | Rule | `SCOPE-004` (HIGH) |
| Project rules (behavior that must not break) | Project invariant | your IDs |
| Invariants file removed or relaxed; malformed invariants file | Rule | `INV-WEAKENED`, `INV-FILE` |
| Values that can be null/None/undefined/nil used without a check (any language) | LLM review | — |
| Image without a pinned tag or digest, or `:latest` (YAML `image:`, Dockerfile `FROM`; in an edited Dockerfile a stage defined outside the diff looks like an image: mark that line with `guard-allow`) | Rule | `INFRA-002` (MEDIUM) |
| API schema compatibility, atomic multi-table writes | LLM review; backend template invariants (UNVERIFIED) | — |
| The project still builds / tests pass | Build command (`pnpm run build`, `pytest`, `go test ./...`, ...) | build check (blocks on failure) |
| Diff & baseline snapshot inspection integrity | Git diff inspection | blocks on diff error (see [Scoring and the final verdict](#scoring-and-the-final-verdict)) |

---

## 5. ♿ Ergonomics & UX

| Concern | How | ID |
| :--- | :--- | :--- |
| Removed keyboard handlers (`keydown`, `'Escape'`, `keyCode 27`) when a template invariant asks to keep them | Template invariant heuristic | frontend template |
| Keyboard focus ring removed (`outline: none` / `outline: 0` in CSS or markup), a hint to check for a `:focus-visible` style | Rule | `UX-001` (LOW) |
| Image without alt text (an `<img>` tag on one line with no `alt`, `[alt]` or `{alt}`, props not spread) | Rule | `UX-002` (MEDIUM) |
| A long-running Kubernetes workload with no liveness or readiness probe | LLM review | — |
| Responsive layout, focus handling, visual feedback, modal dismissal | LLM review (`--focus ux`) | — |

---

## 6. 🧹 Code & Asset Hygiene (Dead Code Gate)

| Concern | How | ID |
| :--- | :--- | :--- |
| New files that nothing references in any language's code or config (a Go file also counts as referenced through its package directory; MEDIUM), draft or scratchpad names (`*.tmp`, `*backup*`, `temp_*`, `test_scratch*`; HIGH) | Rule | `DEAD-001` (HIGH / MEDIUM) |
| A removed string key (`case 'edit':`), export or CSS class that is still referenced somewhere in the repository | Rule | `DEAD-REF` (HIGH) |
| Commented-out code, unused imports and private functions (any language) | LLM review | — |

## 7. 🛋️ Simplicity (KISS & YAGNI)

*Inspired by Larry Wall's virtue of Laziness and Dietrich Gebert's Ponytail philosophy: "The best code is the code you never wrote."*

| Concern | How | ID |
| :--- | :--- | :--- |
| Redundant packages when stdlib or the runtime suffices, matched as whole names: npm (`is-odd`, `uuid`, `mkdirp`, `rimraf`), Python (`pathlib2`, `mock`), Go (`github.com/pkg/errors`, not `// indirect` modules), Rust (`lazy_static`, `once_cell`), Java/Kotlin (`joda-time`), PHP (`paragonie/random_compat`), .NET (`System.ValueTuple`); Gemfile, pubspec.yaml and Package.swift list none yet; also with `--focus simplicity` | Rule | `LAZY-001` (HIGH) |
| Over-engineering (pass-through wrappers, one-method classes, reinvented standard helpers in any language) | LLM review | — |
| Net lines added or removed | Informational only (deleting code earns no score bonus) | `NET-LOC` |

---

## Domains × pillars: what is deterministic where

The same rules run on every repository; which ones matter depends on the files a change touches. A cell
lists the rules that cover it; a cell with none relies on the LLM review (and on your project invariants).

| Domain | 🛡️ Security | 🧠 Memory | ⚡ Performance | 🧱 Integrity | ♿ UX | 🧹 Hygiene | 🛋️ Simplicity |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Frontend | `SEC-001` `SEC-003` `SEC-005` `SEC-006` `SEC-007` `SEC-008` | LLM | LLM | LLM | `UX-001` `UX-002` | `DEAD-001` `DEAD-REF` | `LAZY-001` |
| Backend | `SEC-001` `SEC-002` `SEC-003` `SEC-004` `SEC-005` `SEC-006` `SEC-007` | LLM | LLM | build check, invariants | LLM | `DEAD-001` `DEAD-REF` | `LAZY-001` |
| Fullstack | frontend + backend rules | as both | as both | invariants on the API contract | as both | `DEAD-REF` across halves | `LAZY-001` |
| Infra | `SEC-001` `INFRA-001` `INFRA-003` `SEC-006` | LLM | LLM | `INFRA-002` | LLM | `DEAD-001` | LLM |
| Mobile | `SEC-001` `SEC-002` `SEC-004` `SEC-005` `SEC-006` `SEC-008` `MOB-001` `MOB-002` | LLM | LLM | LLM | LLM | `DEAD-001` | `LAZY-001` |

---

## Scoring and the final verdict

- **Blocks outright** (no LLM can approve): a failed build, a violated invariant, a CRITICAL rule, a file out of scope, a Git diff inspection or snapshot error (surfaced in `diff_summary.error`), with `--full` an OCR review that did not run or a high/critical OCR finding, and in `--focus dead-code` / `--focus simplicity` any finding of that pillar.
- **Heuristic score:** starts at 10.0 and docks points for CRITICAL and HIGH rule violations, code hygiene (`DEAD-*`), simplicity (`LAZY-*`), out-of-scope files, invariant check failures, and Git diff inspection errors (which dock 5.0 points, dropping the score below 7.5 and forcing REVISE). Code hygiene and simplicity findings cost lightly compared to stability or security warnings. MEDIUM findings do not lower the score (they are advisory follow-ups). If the heuristic score falls below 7.5, the heuristic verdict is `REVISE`.
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

## Releasing (maintainers)

Every version bump updates `pyproject.toml`, `guard/__init__.py` and `docs/index.html` (badge and footer) together (`REL-VERSION-SYNC`). Merge it, then publish a GitHub Release whose tag is the version with a leading `v` (for example `v0.15.0`). The `Publish to PyPI` workflow builds the sdist and wheel and uploads them with PyPI trusted publishing, so no token is stored; it verifies that the release tag matches the package version strings (`pyproject.toml` and `guard/__init__.py`). One-time setup on pypi.org: add a (pending) trusted publisher for project `banh-mi-guard`, owner `okrath`, repository `banh-mi-guard`, workflow `publish.yml`, environment `pypi`, and create the `pypi` environment in the repository settings. A version on PyPI cannot be changed or reused: a mistake is fixed by the next version.

---
*Created and maintained by [@okrath](https://github.com/okrath) &mdash; Source code available at [github.com/okrath/banh-mi-guard](https://github.com/okrath/banh-mi-guard).*
