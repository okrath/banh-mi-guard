"""
Unit tests for Hygiene & Dead Code Engine.
"""

from pathlib import Path
from guard.core.hygiene_engine import HygieneEngine
from guard.core.ocr_engine import DiffSummary, FileDiffStat


def test_is_junk_filename():
    engine = HygieneEngine()
    assert engine.is_junk_filename("src/temp_auth.py") is True
    assert engine.is_junk_filename("components/Modal.backup.tsx") is True
    assert engine.is_junk_filename("test_scratchpad.py") is True
    assert engine.is_junk_filename("build/output.tmp") is True
    assert engine.is_junk_filename("src/copy_of_header.ts") is True

    assert engine.is_junk_filename("src/components/Header.tsx") is False
    assert engine.is_junk_filename("guard/core/invariant_eval.py") is False


def test_is_entrypoint_or_whitelisted():
    engine = HygieneEngine()
    assert engine.is_entrypoint_or_whitelisted("README.md") is True
    assert engine.is_entrypoint_or_whitelisted("pyproject.toml") is True
    assert engine.is_entrypoint_or_whitelisted("src/main.ts") is True
    assert engine.is_entrypoint_or_whitelisted("src/index.tsx") is True
    assert engine.is_entrypoint_or_whitelisted("tests/test_core.py") is True
    assert engine.is_entrypoint_or_whitelisted("docs/index.html") is True

    assert engine.is_entrypoint_or_whitelisted("src/components/DeadWidget.tsx") is False
    assert engine.is_entrypoint_or_whitelisted("services/unused_helper.py") is False


def test_check_orphan_file_in_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    # File A is imported by main.py
    (repo / "main.py").write_text("from active_module import do_work\n", encoding="utf-8")
    (repo / "active_module.py").write_text("def do_work(): pass\n", encoding="utf-8")

    # File B is completely orphaned (not imported anywhere)
    (repo / "orphan_service.py").write_text("def abandoned(): pass\n", encoding="utf-8")

    engine = HygieneEngine(repo_path=repo)

    # Active module is not orphan
    assert engine.check_orphan_file("active_module.py") is None

    # Orphan service is flagged
    viol = engine.check_orphan_file("orphan_service.py")
    assert viol is not None
    assert viol.rule_id == "DEAD-001"
    assert "Orphan file" in viol.message



def test_scan_diff_level(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("print('hello')\n", encoding="utf-8")

    engine = HygieneEngine(repo_path=repo)

    raw_diff = """
diff --git a/temp_draft.py b/temp_draft.py
new file mode 100644
--- /dev/null
+++ b/temp_draft.py
@@ -0,0 +1,5 @@
+# const a = 1;
+# const b = 2;
+# return a + b;
+print("draft")
"""
    diff_summary = DiffSummary(
        total_files=1,
        files=[FileDiffStat(path="temp_draft.py", status="added", insertions=5, deletions=0)],
        raw_diff=raw_diff,
    )

    violations = engine.scan_diff_level(raw_diff, diff_summary)
    assert any(v.rule_id == "DEAD-001" for v in violations)


def test_scan_focus_level(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    dead_file = repo / "dead.py"
    dead_file.write_text("""
# def legacy_process():
#     const = 1;
#     return const;

def _unused_subroutine():
    return 100
""", encoding="utf-8")

    engine = HygieneEngine(repo_path=repo)
    violations = engine.scan_focus_level(["dead.py"])

    # Expect orphan check (DEAD-001)
    rule_ids = {v.rule_id for v in violations}
    assert "DEAD-001" in rule_ids


def test_documentation_is_never_an_orphan(tmp_path):
    from guard.core.hygiene_engine import HygieneEngine
    engine = HygieneEngine(tmp_path)
    for doc in ("plans/2026-x/phase-01.md", "docs/guide.rst", "NOTES.txt", "handbook/docs/a.mdx"):
        assert engine.check_orphan_file(doc) is None, doc
def test_language_reference_patterns_not_orphans(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    # Go: new util.go referenced by import ".../util"
    pkg_dir = repo / "pkg" / "util"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "util.go").write_text("package util\nfunc Do() {}\n", encoding="utf-8")
    (repo / "consumer.go").write_text('package main\nimport "example.com/project/pkg/util"\n', encoding="utf-8")

    # Java: new Helper.java referenced as Helper.
    src_java = repo / "src"
    src_java.mkdir(parents=True, exist_ok=True)
    (src_java / "Helper.java").write_text("public class Helper {}\n", encoding="utf-8")
    (src_java / "Main.java").write_text("class Main { void f() { Helper.run(); } }\n", encoding="utf-8")

    # Rust: new parser.rs referenced by mod parser;
    (repo / "parser.rs").write_text("pub fn parse() {}\n", encoding="utf-8")
    (repo / "lib.rs").write_text("mod parser;\n", encoding="utf-8")

    # Kotlin: unreferenced orphan.kt
    (repo / "orphan.kt").write_text("class Orphan {}\n", encoding="utf-8")

    engine = HygieneEngine(repo_path=repo)
    assert engine.check_orphan_file("pkg/util/util.go") is None
    assert engine.check_orphan_file("src/Helper.java") is None
    assert engine.check_orphan_file("parser.rs") is None

    kt_viol = engine.check_orphan_file("orphan.kt")
    assert kt_viol is not None
    assert kt_viol.rule_id == "DEAD-001"


def test_a_quoted_directory_name_does_not_reference_a_non_go_file(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "lonely_widget.ts").write_text("export const x = 1\n", encoding="utf-8")
    (repo / "tsconfig.json").write_text('{"include": ["src"]}\n', encoding="utf-8")
    (repo / "main.go").write_text('import "example.com/app/src"\n', encoding="utf-8")
    assert HygieneEngine(repo_path=repo).check_orphan_file("src/lonely_widget.ts") is not None
