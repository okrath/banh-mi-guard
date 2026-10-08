# Benchmark: measuring the review options

`bench/` is a developer tool for measuring whether a review option (see [CLI Reference: Review Options, Stages & Limits](cli-reference.md#review-options-stages--limits)) finds more real defects, or blocks more clean changes, than the plain review. It is not part of the installed package (the package includes only `guard*`), so every command below runs from the root of a checkout of this repository. This page tells you how to run it and how to read the output; it holds no results, because results depend on the model, the corpus and the day.

## What it runs

A benchmark run feeds each stored case to the real `LLMReviewerEngine.review` with a set of review options and scores the findings against labelled defects. A run therefore makes real LLM calls through your configured LLM and costs what those calls cost. `--dry-run` swaps the model for a deterministic scripted answer; use it only to check that the tool itself works, since its numbers say nothing about review quality.

## The corpus

- `bench/cases/*.json` are the stored cases: a task prompt, a diff, a label (`defect`, `clean` or `unlabelled`) and, for a defect case, the labelled defects with the file and the keywords that identify each one.
- `bench/labels.md` explains where the labels come from. `bench/fixtures/` holds diffs that are not in Git history.
- A finding counts as catching a defect when its location matches the defect's file and its text contains one of the defect's keywords (`match_defects` in `bench/metrics.py`).

Validate the stored cases (the commits they refer to must exist in the repository), or rebuild them:

```bash
python -m bench.corpus check
python -m bench.corpus build [--labels FILE] [--repo DIR] [--out DIR] [--archive DIR]
```

`--archive` additionally turns a directory of archived guard sessions into unlabelled cases under `cases/archive/`, which is Git-ignored.

## Running a variant

A variant is a named set of review option overrides. List them, then run one:

```bash
python -m bench.variants list
python -m bench.variants run panel3 --max-calls 40 --repeats 1 --out bench/results/panel3.json
```

Everything after the variant name goes to `python -m bench run`: `--cases`, `--label {defect,clean,unlabelled,all}`, `--repeats`, `--max-calls`, `--out` and `--dry-run`. `--max-calls` is required for a real run and is the hard cap on LLM calls for the whole run; a run that would exceed it stops. For an option set that has no variant, pass the options yourself with repeatable `--variant key=value` to `python -m bench run`. Without `--out`, the result is written to `bench/results/run_<timestamp>.json`; `bench/results/` is Git-ignored.

Always run a baseline (`python -m bench.variants run baseline ...`) with the same `--repeats`, `--label` and cases as the variant you want to judge.

## Reading a result

```bash
python -m bench report RESULT.json [--out PATH]
python -m bench compare BASELINE.json VARIANT.json [--opt-in-by-design] [--out PATH]
```

`report` prints a summary and one row per case:

- **Recall (blocking)** is the share of labelled defects caught by a finding that blocks; **Recall (any)** also counts advisory findings. A defect that is only advisory did not stop a bad change.
- **False Blocks** counts clean cases that were rejected. A rejection of a clean change is a cost, not a safe default.
- **Calls**, **Characters Sent** and **Total Time** are the cost of the run.
- **Stability** is the share of repeats of a case that ended in the same outcome. With one repeat it is always 100%, which says nothing.

`compare` judges a variant against the baseline with four checks, and prints "adopt" only when all four pass: (a) it caught a defect the baseline missed, or removed a false block; (b) it lost no defect the baseline caught; (c) it added no false block; (d) it used at most 2.0 times the baseline's calls. With `--opt-in-by-design` (for the panel, which is opt-in whatever it measures) the cost check is ignored and "adopt" is always no; the recommendation is still printed.

Treat a comparison with care:

- Compare runs with the same number of repeats. The checks compare totals, so a one-repeat variant against a two-repeat baseline distorts both the cost ratio and the lost and gained defects.
- A single run of a non-deterministic model is noisy. A difference in one or two cases is not evidence; look at the stability of the baseline before reading a gain into it.
- The corpus is small and comes from one project, and its labels were written by people and models of the same kind that are being measured. A result describes this corpus, not review quality in general.
- A variant that reports no gain here is not proven useless, only unmeasured at this noise level.
