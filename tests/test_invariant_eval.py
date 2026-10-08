"""
Deterministic invariant evaluation (diff heuristics for template invariants).
"""

from guard.core.invariant_eval import evaluate_invariants


def test_a_keyword_match_is_a_hint_for_the_llm_not_a_failed_invariant():
    invariants = [
        {"id": "INV-01", "description": "Không được bỏ phím Escape để đóng modal"},
        {"id": "INV-02", "description": "Không được hardcode secret token trong code"},
    ]
    # Diff that removes keydown / escape
    diff = """
--- a/src/Modal.tsx
+++ b/src/Modal.tsx
@@ -10,3 +10,1 @@
- window.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
+ console.log("modal opened");
    """
    files = ["src/Modal.tsx"]
    eval_res = evaluate_invariants(invariants, diff, files)
    assert eval_res.all_passed is True  # a keyword guess never blocks the gate by itself
    assert eval_res.checks[0].status == "unverified" and eval_res.checks[0].confidence == 0.0
    assert eval_res.checks[0].notes.startswith("Keyword hint, not a check") and "keyboard/escape handler" in eval_res.checks[0].notes
    assert "Escape" in eval_res.checks[0].description


def test_a_deleted_file_is_not_a_removed_handler():
    invariants = [{"id": "FE-INV-02", "description": "Ensure keyboard navigation (Escape, Enter) and modal dismissal work."}]
    diff = """diff --git a/src/PeelCard.vue b/src/PeelCard.vue
deleted file mode 100644
index 1111111..0000000
--- a/src/PeelCard.vue
+++ /dev/null
@@ -1,3 +0,0 @@
-<template>
-  <div @keydown.esc="close" tabindex="0"></div>
-</template>
diff --git a/src/Other.vue b/src/Other.vue
--- a/src/Other.vue
+++ b/src/Other.vue
@@ -1,1 +1,1 @@
-const color = "blue";
+const color = "indigo";
"""
    check = evaluate_invariants(invariants, diff, ["src/PeelCard.vue", "src/Other.vue"]).checks[0]
    assert check.status == "passed", check.notes
    still_there = diff.replace("deleted file mode 100644\n", "").replace("+++ /dev/null", "+++ b/src/PeelCard.vue")
    assert evaluate_invariants(invariants, still_there, []).checks[0].status == "unverified"  # an edited file still counts


def test_a_real_check_still_fails_and_blocks(tmp_path):
    (tmp_path / "a.ts").write_text("eval(x)\n", encoding="utf-8")
    inv = [{"id": "NO-EVAL", "description": "Never call eval", "checks": [{"files": "*.ts", "forbid": "eval[(]"}]}]
    res = evaluate_invariants(inv, "", ["a.ts"], repo_path=tmp_path)
    assert res.all_passed is False and res.checks[0].status == "failed"


def test_evaluate_invariants_pass():
    invariants = [
        {"id": "INV-01", "description": "Nút thanh toán phải disabled khi giỏ hàng trống"},
    ]
    diff = """
--- a/src/Button.tsx
+++ b/src/Button.tsx
@@ -10,3 +10,3 @@
- const color = "blue";
+ const color = "indigo";
    """
    files = ["src/Button.tsx"]
    eval_res = evaluate_invariants(invariants, diff, files)
    assert eval_res.all_passed is True
    assert eval_res.checks[0].passed is True


def test_evaluate_invariants_ignore_escape_html():
    invariants = [
        {"id": "INV-01", "description": "Không được bỏ phím Escape để đóng modal"},
    ]
    # Diff that removes escapeHtml helper, NOT keyboard escape handler
    diff = """
--- a/src/utils.ts
+++ b/src/utils.ts
@@ -5,3 +5,1 @@
- const safe = escapeHtml(userInput);
+ const safe = sanitize(userInput);
    """
    files = ["src/utils.ts"]
    eval_res = evaluate_invariants(invariants, diff, files)
    assert eval_res.all_passed is True
    assert eval_res.checks[0].passed is True


ESCAPE_REMOVED = (
    "diff --git a/src/Modal.tsx b/src/Modal.tsx\n--- a/src/Modal.tsx\n+++ b/src/Modal.tsx\n@@ -1,1 +1,1 @@\n"
    "-  window.addEventListener('keydown', onKey);\n+  // gone\n"
)
FE_INV = [{"id": "FE-INV-02", "description": "Ensure keyboard navigation (Escape, Enter) and modal dismissal work."}]


def _review(monkeypatch, llm_answer):
    from guard.core.config import GuardConfig, LLMConfig
    from guard.core.llm_reviewer import LLMReviewerEngine
    from guard.core.ocr_engine import DiffSummary

    prompts = []

    def call(cfg, prompt, system_prompt, **kwargs):
        prompts.append(prompt)
        return llm_answer

    monkeypatch.setattr("guard.core.llm_reviewer.call_llm", call)
    cfg = GuardConfig()
    if llm_answer is not None:
        cfg.llm = LLMConfig(api_key="k", model="mock-model", base_url="https://mock.llm")
    verdict = LLMReviewerEngine(config=cfg).review(
        prompt="Restyle the modal", domain="frontend", diff_summary=DiffSummary(raw_diff=ESCAPE_REMOVED),
        invariant_result=evaluate_invariants(FE_INV, ESCAPE_REMOVED, ["src/Modal.tsx"]),
    )
    return verdict, prompts


def test_the_llm_judges_a_hint_and_its_approval_stands(monkeypatch):
    verdict, prompts = _review(monkeypatch, "SCORE: 9.0\nSUMMARY: the handler moved to useKeys\nFINDINGS:\nNone\n")
    assert verdict.verdict.value == "APPROVED" and verdict.review_mode == "llm_deep"
    assert "[UNVERIFIED] FE-INV-02" in prompts[0] and "Keyword hint, not a check" in prompts[0]


def test_without_an_llm_a_hint_still_decides(monkeypatch):
    verdict, _ = _review(monkeypatch, None)
    assert verdict.verdict.value == "REVISE" and verdict.llm_error
    assert "FE-INV-02" in verdict.summary and any("FE-INV-02" in s for s in verdict.remediation_steps)
