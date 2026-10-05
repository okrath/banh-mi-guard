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
    run_p.add_argument("--max-calls", type=int, default=1000, help="Maximum LLM call budget")
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
        help="Evaluate panel under opt-in-by-design rule (clause d ignored)",
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

    variant = parse_variant_args(args.variant) if args.variant else {}
    review_fn = make_dry_run_review_fn() if args.dry_run else default_review_fn

    summary = run_corpus(
        cases,
        review_fn,
        repeats=args.repeats,
        max_calls=args.max_calls,
        label_filter=args.label,
        variant=variant,
    )

    md = to_markdown(summary)

    if args.out == "-":
        sys.stdout.write(md + "\n")
    else:
        out_path = Path(args.out) if args.out else Path("bench/results") / f"run_{time.strftime('%Y%m%d_%H%M%S')}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        # Also print markdown summary to stdout when saving to default or specified file
        sys.stdout.write(md + "\n")

    return 0


def handle_compare(args: argparse.Namespace) -> int:
    with open(args.baseline, "r", encoding="utf-8") as f:
        baseline_data = json.load(f)
    with open(args.variant, "r", encoding="utf-8") as f:
        variant_data = json.load(f)

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
    with open(args.result, "r", encoding="utf-8") as f:
        result_data = json.load(f)

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
