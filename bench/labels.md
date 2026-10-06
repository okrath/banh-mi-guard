# Seed labels for the benchmark corpus

Each row is a commit that is an ancestor of `origin/main` (checked). "Diff" means `git show <commit>`
restricted to the files named. The task prompt for a case is the plan or task text that produced the
change; the worker writes a one-paragraph prompt per case from the commit message and the file list.
Defects were confirmed by independent read-only review during the session, with file and line.

| Case | Commit | Kind | Known defect (file, what) | Severity |
|---|---|---|---|---|
| c01 | `efea26f` | security | OMISSION: `guard/task_flow.py` (not in this diff) git pre-commit path still reads `post.approved_fingerprints` unverified, so a forged approval passes `git commit`; the diff adds signing but leaves this reader. A correct review must trace the other readers of the field | high |
| c01b | `efea26f` | correctness | `guard/agent/events.py` a `startswith("__")` filter hid top-level `__init__.py` and `__tests__/` (repo-relative paths) from shell-edit detection | medium |
| c01c | `efea26f` | correctness | `guard/agent/events.py` an early return on a `session.json` change skipped commit detection for other files | medium |
| c01d | `efea26f` | test-quality | `tests/test_approval_signature.py` the "forgery" test wrote zero hashes, which was already refused before the change | medium |
| c02 | `7d396ff` | correctness | `guard/core/diff_inspector.py` a failed `git diff <base_ref>` silently fell back to an unstaged-only diff, so the review saw a partial diff | high |
| c02b | `7d396ff` | correctness | `guard/core/llm_client.py` `httpx.InvalidURL` is not caught by the narrowed handlers, `guard config` ping crashes | medium |
| c02c | `7d396ff` | correctness | `guard/domains/pre_analysis.py` an unexpected error from the agent CLI escapes and crashes `guard pre` instead of falling back | medium |
| c03 | `13610a6` | correctness | `guard/core/diff_inspector.py` any added line starting `+# [ERROR:` in file content is read as a diff error, so a normal comment forces REVISE | high |
| c04 | `6fce2cb` | correctness | `guard/cli.py` an isort reorder changed the command order in `guard --help` (the comment above says the order is the help order) | medium |
| c05 | `4fb9917` | test-quality | `tests/test_cli_command_order.py` parses coloured help text, fails on CI where colour is on | medium |
| c06 | `d3eec3b` | correctness | `guard/core/llm_reviewer.py` penalties summed then subtracted, the saved score changes in its last digits (a refactor must be bit-identical) | low |
| c06b | `d3eec3b` | test-quality | `tests/test_main_module.py` tests depend on cwd and the installed script, and mutate `sys.path` and `guard.__path__` without restoring | medium |
| c07 | `c8ef678` | maintainability | `guard/task_flow.py` a comment explaining why a build command is turned into an argument list was deleted (out of scope) | low |
| c09 | `a9b6802` | correctness | `guard/agent/events.py` guard-command detection returns a notice for `C:\...\python.exe -m guard post` and for `cd sub && guard post` (note: `guard run -- <cmd>` returning False is intentional per docstrings and tests) | medium |
| c11 | fixtures/t1-v1-bash.patch | correctness | `strict`-style command parser returned a concrete but wrong directory for about ten shapes and dropped commits behind git aliases | high |

## Cases that must NOT block (clean or advisory-only at the time)

| Case | Commit | Why it is fair to call it clean |
|---|---|---|
| n01 | `92f6166` | commands/updater split, independent review found equivalence and only cosmetic differences |
| n02 | `004a7fe` | rules/diff split, 200,000-case equivalence test and timing within noise |
| n03 | `5879249` | comments only, AST identical to the previous commit |
| n04 | `3ea1af9` | the test fix itself, CI green |
| n05 | `1dfb152` | docs after the review round (a residual advisory only) |
| c10 | `d477e26` | docs reorganization: operational facts moved from README to docs/cli-reference.md, clean standalone; evaluated in composite m01 |

Visibility: a defect is `visible_in_diff: true` when its file and lines are in the stored diff. c01 is
`visible_in_diff: false` (an omission: the file is not in the diff, but exists at that commit). The
validation rule for such a defect is that the file exists at the commit (`git cat-file -e <commit>:<file>`).
Dropped from the earlier draft:
- c08 (`8040020` is the FIX commit and the faulty code is outside its hunk).
- c10 (facts moved to `docs/cli-reference.md` rather than lost; moved to clean table).
- c11b (fixture `t1-v1-test_command_target.py` does not contain path mutations or assertion-free tests).

Notes for the worker:
- The corpus also includes every archived session in `<repo>/.guard/history/*.json`: each has the prompt,
  `post.diff_summary.raw_diff`, the findings and the verdict. They are UNLABELLED: use them for cost,
  stability (same diff run twice) and the needs_user rate, never for recall.
- The ground truth is the table above. Do not invent labels. If a commit does not show the defect,
  report it and drop the case.
