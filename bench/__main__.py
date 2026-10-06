"""
Benchmark CLI entrypoint.

Commands:
    python -m bench run [--cases DIR] [--label defect|clean|unlabelled|all]
                        [--repeats N] [--max-calls N] [--variant key=value ...]
                        [--out PATH] [--dry-run]
    python -m bench compare A.json B.json [--opt-in-by-design] [--out PATH]
    python -m bench report RESULT.json [--out PATH]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, List, Optional

from bench.metrics import compare as compare_metrics
from bench.metrics import to_markdown
from bench.runner import (
    default_review_fn,
    load_cases_from_path,
    make_dry_run_review_fn,
    run_corpus,
    validate_variant,
)


def parse_variant_args(variant_list: list[str]) -> dict:
    """Parse repeatable `--variant key=value` arguments into a typed dictionary."""
    result: dict[str, Any] = {}
    for item in variant_list:
        if "=" in item:
            k, v = item.split("=", 1)
            k = k.strip()
            v = v.strip()
            v_lower = v.lower()
            if v_lower == "true":
                result[k] = True
            elif v_lower == "false":
                result[k] = False
            else:
                try:
                    result[k] = int(v)
                except ValueError:
                    try:
                        result[k] = float(v)
                    except ValueError:
                        result[k] = v
        else:
            sys.stderr.write(f"Warning: ignoring invalid variant argument '{item}' (expected key=value)\n")
    return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bench", description="Benchmark runner and metrics")
    subparsers = parser.add_subparsers(dest="command")

    # Command: run
    run_p = subparsers.add_parser("run", help="Run benchmark on corpus cases")
    run_p.add_argument("--cases", default="bench/cases", help="Directory or file of benchmark cases")
    run_p.add_argument(
        "--label",
        choices=["defect", "clean", "unlabelled", "all"],
        default="all",
        help="Filter cases by label",
    )
    run_p.add_argument("--repeats", type=int, default=1, help="Number of repeats per case")
    run_p.add_argument(
        "--max-calls",
        type=int,
        default=None,
        help="Maximum LLM call budget (required for real runs; default 1000 for --dry-run)",
    )
    run_p.add_argument(
        "--variant",
        action="append",
        default=[],
        help="Variant options in key=value format (repeatable)",
    )
    run_p.add_argument("--out", default=None, help="Output JSON path (or '-' to print markdown)")
    run_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Use deterministic scripted review without real LLM calls",
    )

    # Command: compare
    cmp_p = subparsers.add_parser("compare", help="Compare variant results against baseline")
    cmp_p.add_argument("baseline", help="Baseline result JSON file")
    cmp_p.add_argument("variant", help="Variant result JSON file")
    cmp_p.add_argument(
        "--opt-in-by-design",
        action="store_true",
        help="Evaluate panel under opt-in-by-design rule (clause d ignored; adopt always False)",
    )
    cmp_p.add_argument("--out", default=None, help="Output path (or '-' to print markdown)")

    # Command: report
    rep_p = subparsers.add_parser("report", help="Generate Markdown report from result JSON")
    rep_p.add_argument("result", help="Result JSON file")
    rep_p.add_argument("--out", default=None, help="Output file path (default: print to stdout)")

    return parser


def handle_run(args: argparse.Namespace) -> int:
    cases = load_cases_from_path(args.cases)
    if not cases:
        sys.stderr.write(f"Error: no benchmark cases found at '{args.cases}'. Check --cases path.\n")
        return 2

    if args.repeats < 1:
        sys.stderr.write(f"Error: --repeats must be at least 1, got {args.repeats}\n")
        return 2

    variant = parse_variant_args(args.variant) if args.variant else {}
    try:
        variant = validate_variant(variant)
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2

    if args.dry_run:
        max_calls = args.max_calls if args.max_calls is not None else 1000
    else:
        if args.max_calls is None:
            sys.stderr.write(
                "Error: --max-calls is required for real runs (e.g. --max-calls 20) "
                "to prevent unintended API spending. Use --dry-run for testing.\n"
            )
            return 2
        max_calls = args.max_calls

    if max_calls < 1:
        sys.stderr.write(f"Error: --max-calls must be at least 1, got {max_calls}\n")
        return 2

    model_name = "dry-run"
    if not args.dry_run:
        try:
            from guard.core.config import load_config

            cfg = load_config()
            model_name = cfg.llm.model or "unknown"
        except Exception:
            model_name = "unknown"
    if variant.get("model"):
        model_name = str(variant["model"])

    # Print model name and budget before the first call
    sys.stdout.write(
        f"Benchmark starting: model={model_name}, budget={max_calls} calls, "
        f"repeats={args.repeats}, cases={len(cases)}\n"
    )

    review_fn = make_dry_run_review_fn() if args.dry_run else default_review_fn

    summary = run_corpus(
        cases,
        review_fn,
        repeats=args.repeats,
        max_calls=max_calls,
        label_filter=args.label,
        variant=variant,
    )
    summary["model"] = model_name

    md = to_markdown(summary)

    if args.out == "-":
        sys.stdout.write(md + "\n")
    else:
        out_path = (
            Path(args.out)
            if args.out
            else Path("bench/results") / f"run_{time.strftime('%Y%m%d_%H%M%S')}.json"
        )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        sys.stdout.write(md + "\n")

    return 0


def handle_compare(args: argparse.Namespace) -> int:
    base_path = Path(args.baseline)
    var_path = Path(args.variant)

    if not base_path.is_file():
        sys.stderr.write(f"Error: baseline file not found: {args.baseline}\n")
        return 2
    if not var_path.is_file():
        sys.stderr.write(f"Error: variant file not found: {args.variant}\n")
        return 2

    try:
        with open(base_path, "r", encoding="utf-8") as f:
            baseline_data = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Error reading baseline file {args.baseline}: {e}\n")
        return 2

    try:
        with open(var_path, "r", encoding="utf-8") as f:
            variant_data = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Error reading variant file {args.variant}: {e}\n")
        return 2

    comp = compare_metrics(
        baseline_data,
        variant_data,
        opt_in_by_design=args.opt_in_by_design,
    )
    md = to_markdown(variant_data, compare=comp)

    if args.out and args.out != "-":
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(comp, f, indent=2)
    else:
        sys.stdout.write(md + "\n")

    return 0


def handle_report(args: argparse.Namespace) -> int:
    res_path = Path(args.result)
    if not res_path.is_file():
        sys.stderr.write(f"Error: result file not found: {args.result}\n")
        return 2

    try:
        with open(res_path, "r", encoding="utf-8") as f:
            result_data = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Error reading result file {args.result}: {e}\n")
        return 2

    md = to_markdown(result_data)
    if args.out and args.out != "-":
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(md, encoding="utf-8")
    else:
        sys.stdout.write(md + "\n")

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "run":
        return handle_run(args)
    if args.command == "compare":
        return handle_compare(args)
    if args.command == "report":
        return handle_report(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
