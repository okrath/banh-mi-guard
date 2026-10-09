"""
Backend (BE) Domain Analyzer.
Handles Python (FastAPI/Django), Go, Node.js (NestJS/Express), Rust (Actix/Axum), SQL/ORM.
Extracts API endpoint contracts, DB schemas, auth middleware, and transactional invariants.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from guard.core.session import LockedInvariant
from guard.domains.base import BaseDomainAnalyzer


def _pytest_config(repo_path: Path) -> bool:
    """`[tool.pytest...]` in pyproject.toml, or `[tool:pytest]` in setup.cfg."""
    for name, marker in (("pyproject.toml", "[tool.pytest"), ("setup.cfg", "[tool:pytest]")):
        try:
            if marker in (repo_path / name).read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            pass
    return False


class BackendDomainAnalyzer(BaseDomainAnalyzer):
    @property
    def name(self) -> str:
        return "Backend (API & Database Services)"

    def detect(self, repo_path: Path) -> bool:
        be_indicators = [
            "go.mod",
            "Cargo.toml",
            "requirements.txt",
            "pyproject.toml",
            "prisma/schema.prisma",
            "alembic.ini",
            "src/main.go",
            "main.py",
            "nest-cli.json",
        ]
        return any((repo_path / ind).exists() for ind in be_indicators)

    def get_default_build_command(self, repo_path: Path) -> Optional[str]:
        if (repo_path / "go.mod").exists():
            return "go test ./... -v"
        if (repo_path / "Cargo.toml").exists():
            return "cargo test"
        if (repo_path / "pyproject.toml").exists() or (repo_path / "requirements.txt").exists():
            # a Python test command only with Python tests in sight: a monorepo of other languages can keep
            # a root pyproject.toml, and unittest that finds no test fails the build
            if any((repo_path / p).exists() for p in ("pytest.ini", "conftest.py", "tests", "test")) or _pytest_config(repo_path):
                return "pytest"
            if any(repo_path.glob("test_*.py")) or any(repo_path.glob("*_test.py")):
                return "python -m unittest"
        if (repo_path / "package.json").exists():
            return "npm test"
        return None

    def generate_recommended_invariants(self, prompt: str, files: List[str]) -> List[LockedInvariant]:
        return [
            LockedInvariant(
                id="BE-INV-01",
                description="Do not break existing JSON response schemas (maintain backwards compatibility for mobile & web clients).",
                rationale="Prevent client-side breaking API contracts.",
            ),
            LockedInvariant(
                id="BE-INV-02",
                description="Must use parameterized queries or ORM models. Never concatenate raw untrusted input in SQL.",
                rationale="Prevent SQL Injection vulnerabilities.",
            ),
            LockedInvariant(
                id="BE-INV-03",
                description="Multi-table database mutations must be encapsulated within an atomic transaction with rollback.",
                rationale="Protect database consistency (ACID).",
            ),
        ]

    def generate_targeted_test_plan(self, files: List[str], diff_text: str) -> List[str]:
        return [
            "Execute unit and integration tests for modified API endpoints.",
            "Negative testing: send requests missing mandatory fields to verify standard 400 Bad Request responses.",
            "Authentication testing: verify unauthenticated calls receive 401 Unauthorized.",
        ]
