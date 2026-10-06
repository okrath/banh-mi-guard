"""Regenerate golden fixture cases for diff_partition using commit 7f67d12.

Loads LLMReviewerEngine from the pinned commit 7f67d12, runs _prepare_diff_batches
on the canonical test cases required by task PC, and saves inputs and expected outputs
to tests/fixtures/diff_partition/golden_cases.json.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path


def load_old_reviewer_from_commit(commit: str = "7f67d12"):
    out = subprocess.check_output(
        ["git", "show", f"{commit}:guard/core/llm_reviewer.py"],
        text=True,
    )
    spec = importlib.util.spec_from_loader(f"old_llm_reviewer_{commit}", loader=None)
    if spec is None:
        raise RuntimeError("Failed to create module spec")
    mod = importlib.util.module_from_spec(spec)
    exec(out, mod.__dict__)
    return mod


def build_cases() -> list[dict[str, str]]:
    cases = []

    # 1. Empty diff
    cases.append({
        "name": "empty_diff",
        "raw_diff": "",
    })

    # 2. One-file diff
    cases.append({
        "name": "one_file_diff",
        "raw_diff": (
            "diff --git a/src/main.py b/src/main.py\n"
            "index 1234567..89abcdef 100644\n"
            "--- a/src/main.py\n"
            "+++ b/src/main.py\n"
            "@@ -1,3 +1,4 @@\n"
            " def hello():\n"
            "-    return 'old'\n"
            "+    return 'new'\n"
            "+    # extra line\n"
        ),
    })

    # 3. Asset and lockfile
    cases.append({
        "name": "asset_and_lockfile",
        "raw_diff": (
            "diff --git a/assets/logo.png b/assets/logo.png\n"
            "new file mode 100644\n"
            "index 0000000..1234567\n"
            "Binary files /dev/null and b/assets/logo.png differ\n"
            "diff --git a/package-lock.json b/package-lock.json\n"
            "index 1234567..89abcdef 100644\n"
            "--- a/package-lock.json\n"
            "+++ b/package-lock.json\n"
            "@@ -1,2 +1,3 @@\n"
            "+{\n"
            "+  'lockfileVersion': 3\n"
            "+}\n"
            "diff --git a/src/app.py b/src/app.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/src/app.py\n"
            "+++ b/src/app.py\n"
            "@@ -1 +1 @@\n"
            "-print('old')\n"
            "+print('new')\n"
        ),
    })

    # 4. Deleted file
    cases.append({
        "name": "deleted_file",
        "raw_diff": (
            "diff --git a/old_module.py b/old_module.py\n"
            "deleted file mode 100644\n"
            "index 1234567..0000000\n"
            "--- a/old_module.py\n"
            "+++ /dev/null\n"
            "@@ -1,5 +0,0 @@\n"
            "-def unused():\n"
            "-    pass\n"
            "-x = 1\n"
            "-y = 2\n"
            "-z = 3\n"
            "diff --git a/kept.py b/kept.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/kept.py\n"
            "+++ b/kept.py\n"
            "@@ -1 +1 @@\n"
            "-a = 1\n"
            "+a = 2\n"
        ),
    })

    # 5. Single oversized file (> 80k chars -> 85k chars -> 2 parts)
    oversized_lines = "".join(f"+data_line_{i} = '{i}' * 20\n" for i in range(2900))
    cases.append({
        "name": "single_oversized_file",
        "raw_diff": (
            "diff --git a/large_generated.py b/large_generated.py\n"
            "index 1234567..89abcdef 100644\n"
            "--- a/large_generated.py\n"
            "+++ b/large_generated.py\n"
            "@@ -1 +1,2900 @@\n"
            + oversized_lines
        ),
    })

    # 6. 80 files over many parts (80 files * ~1050 chars = ~84k chars -> 2 parts)
    eighty = "".join(
        f"diff --git a/src/mod_{i:02d}.py b/src/mod_{i:02d}.py\n"
        f"index 0000000..1111111 100644\n"
        f"--- /dev/null\n"
        f"+++ b/src/mod_{i:02d}.py\n"
        f"@@ -0,0 +1,25 @@\n"
        + "".join(f"+def func_{i:02d}_{j:02d}(): return 'sample code line testing multi-part diff chunk'\n" for j in range(15))
        for i in range(80)
    )
    cases.append({
        "name": "eighty_files",
        "raw_diff": eighty,
    })

    # 7. Diff over the batch limit (> 6 parts -> 7 parts of ~80.5k chars -> 7 parts with 1 cut part)
    over_limit = "".join(
        f"diff --git a/pkg/part_{i}.py b/pkg/part_{i}.py\n"
        f"index 0000000..1111111 100644\n"
        f"--- /dev/null\n"
        f"+++ b/pkg/part_{i}.py\n"
        f"@@ -0,0 +1,1000 @@\n"
        + ("+line_of_code_for_diff = 1234567890\n" * 2300)
        for i in range(7)
    )
    cases.append({
        "name": "over_batch_limit",
        "raw_diff": over_limit,
    })

    return cases


def regenerate_golden_cases():
    mod = load_old_reviewer_from_commit("7f67d12")
    engine = mod.LLMReviewerEngine()
    diff_summary_cls = mod.DiffSummary

    cases = build_cases()
    golden_data = []

    for c in cases:
        raw_diff = c["raw_diff"]
        summary = diff_summary_cls(raw_diff=raw_diff) if raw_diff else None
        expected_parts = engine._prepare_diff_batches(summary)
        golden_data.append({
            "name": c["name"],
            "raw_diff": raw_diff,
            "expected_parts": expected_parts,
        })
        print(f"Generated case '{c['name']}': {len(expected_parts)} parts")

    out_path = Path(__file__).parent / "golden_cases.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(golden_data, f, indent=2)
    print(f"Wrote {len(golden_data)} golden cases to {out_path}")


if __name__ == "__main__":
    regenerate_golden_cases()
