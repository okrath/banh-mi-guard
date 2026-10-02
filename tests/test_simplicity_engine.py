"""
Unit tests for Simplicity & Engineering Frugality Engine (KISS & YAGNI).
"""

import subprocess

import pytest

from guard.commands import maintenance
from guard.core.ocr_engine import DiffSummary, FileDiffStat
from guard.core.simplicity_engine import SimplicityEngine


def test_calculate_net_loc_bonus():
    engine = SimplicityEngine()

    # Net negative LOC (deleted 100 lines, added 20 -> net: -80)
    diff_negative = DiffSummary(
        total_insertions=20,
        total_deletions=100,
        files=[],
    )
    res = engine.calculate_net_loc(diff_negative)
    assert res["is_net_negative"] is True
    assert res["net_loc"] == -80
    assert "Debt Reduction Bonus" in res["bonus_label"]

    # Neutral or standard expansion
    diff_positive = DiffSummary(
        total_insertions=40,
        total_deletions=10,
        files=[],
    )
    res_pos = engine.calculate_net_loc(diff_positive)
    assert res_pos["is_net_negative"] is False
    assert res_pos["net_loc"] == 30


def test_scan_dependency_bloat_npm():
    engine = SimplicityEngine()

    raw_diff = """
diff --git a/package.json b/package.json
index 123..456 100644
--- a/package.json
+++ b/package.json
@@ -10,2 +10,4 @@
+    "is-odd": "^3.0.1",
+    "uuid": "^9.0.0",
     "react": "^18.2.0"
"""
    violations = engine.scan_dependency_bloat(raw_diff)
    assert len(violations) == 2
    rule_ids = [v.rule_id for v in violations]
    assert all(r == "LAZY-001" for r in rule_ids)
    assert any("is-odd" in v.message for v in violations)
    assert any("uuid" in v.message for v in violations)


def test_scan_dependency_bloat_python():
    engine = SimplicityEngine()

    raw_diff = """
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,1 +1,3 @@
+pathlib2>=2.3.0
+mock>=4.0.0
 requests>=2.31.0
"""
    violations = engine.scan_dependency_bloat(raw_diff)
    assert len(violations) == 2
    assert any("pathlib2" in v.message for v in violations)
    assert any("mock" in v.message for v in violations)



def test_scan_diff_and_focus_levels(tmp_path):
    repo = tmp_path / "frugal_repo"
    repo.mkdir()

    calc_file = repo / "calc.py"
    calc_file.write_text("""
def calculate_subtotal(order):
    return compute_total(order)
""", encoding="utf-8")

    engine = SimplicityEngine(repo_path=repo)

    # Diff-level check
    diff = """
diff --git a/package.json b/package.json
+++ b/package.json
@@ -5,0 +5,1 @@
+    "rimraf": "^5.0.0"
"""
    diff_summary = DiffSummary(total_files=1, files=[FileDiffStat(path="package.json", status="modified", insertions=1, deletions=0)])
    diff_viols = engine.scan_diff_level(diff, diff_summary)
    assert len(diff_viols) == 1
    assert diff_viols[0].rule_id == "LAZY-001"


def _bloat(manifest: str, *added: str):
    diff = f"diff --git a/{manifest} b/{manifest}\n+++ b/{manifest}\n" + "".join(f"+{a}\n" for a in added)
    return SimplicityEngine().scan_dependency_bloat(diff)


def test_scan_dependency_bloat_go_and_cargo():
    v = _bloat("go.mod", "\tgithub.com/pkg/errors v0.9.1", "\tgithub.com/google/uuid v1.3.0")
    assert [x.message for x in v] == [
        "Dependency Bloat: Added redundant Go package `github.com/pkg/errors`. Replace with the standard library "
        "`errors` and `fmt.Errorf` with `%w` (Go 1.13+)."]
    assert not _bloat("go.mod", "\tgithub.com/pkg/errorsx v1.0.0")

    v = _bloat("crates/app/Cargo.toml", 'lazy_static = "1.4"', 'serde = { version = "1.0" }', 'once_cell = "1"')
    assert ["lazy_static" in v[0].message, "once_cell" in v[1].message, len(v)] == [True, True, 2]
    assert not _bloat("Cargo.toml", 'lazy_static_plus = "1"')


def test_scan_dependency_bloat_matches_whole_package_names():
    assert not _bloat("requirements.txt", "argparse-manpage==1.0", "pytest-mock>=3")
    assert len(_bloat("requirements.txt", "mock>=5")) == 1
    assert not _bloat("package.json", '"description": "a small uuid helper",')
    assert not _bloat("package.json", '"@types/uuid": "^9.0.0",')
    assert len(_bloat("package.json", '"uuid": "^9.0.0",')) == 1
    assert not _bloat("Gemfile", "gem 'fileutils'")  # no Gemfile package is listed as redundant


def test_focus_simplicity_still_reports_dependency_bloat(tmp_path, monkeypatch):
    def git(*args):
        subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
                       cwd=tmp_path, check=True, capture_output=True)

    (tmp_path / "package.json").write_text('{\n  "dependencies": {\n  }\n}\n', encoding="utf-8")
    git("init", "-q")
    git("add", "package.json")
    git("commit", "-q", "-m", "init")
    (tmp_path / "package.json").write_text('{\n  "dependencies": {\n    "rimraf": "^5.0.0"\n  }\n}\n',
                                           encoding="utf-8")

    class Reviewed(Exception):
        pass

    def review(self, **kwargs):
        raise Reviewed([v.rule_id for v in kwargs["violations"]])

    monkeypatch.setattr(maintenance.LLMReviewerEngine, "review", review)
    with pytest.raises(Reviewed) as reviewed:
        maintenance.review_cmd(repo=str(tmp_path), focus="simplicity")
    assert "LAZY-001" in reviewed.value.args[0]


def test_scan_dependency_bloat_skips_indirect_go_modules_and_reads_cargo_tables():
    assert not _bloat("go.mod", "\tgithub.com/pkg/errors v0.9.1 // indirect")
    assert len(_bloat("Cargo.toml", "[dependencies.once_cell]")) == 1
    assert len(_bloat("Cargo.toml", "[dev-dependencies.lazy_static]")) == 1


def test_scan_dependency_bloat_jvm_php_dotnet_manifests():
    assert len(_bloat("pom.xml", "<artifactId>joda-time</artifactId>")) == 1
    assert len(_bloat("app/build.gradle", "implementation 'joda-time:joda-time:2.12.5'")) == 1
    assert len(_bloat("build.gradle.kts", 'implementation("joda-time:joda-time:2.12.5")')) == 1
    assert not _bloat("pom.xml", "<artifactId>joda-money</artifactId>")
    assert len(_bloat("composer.json", '"paragonie/random_compat": "^2.0",')) == 1
    assert not _bloat("composer.json", '"paragonie/sodium_compat": "^1.20",')
    assert len(_bloat("src/App.csproj", '<PackageReference Include="System.ValueTuple" Version="4.5.0" />')) == 1
    assert not _bloat("src/App.csproj", '<PackageReference Include="System.ValueTuple.Extras" Version="1.0" />')
    assert not _bloat("pubspec.yaml", "  http: ^1.2.0")
    assert not _bloat("Package.swift", '.package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),')
