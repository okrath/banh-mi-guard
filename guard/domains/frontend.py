"""
Frontend (FE) Domain Analyzer.
Handles React, Next.js, Vue, Svelte, Vite, Tailwind projects.
Extracts UI states (loading, disabled, modal, errors), event handlers, and responsive layout constraints.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from guard.core.session import LockedInvariant
from guard.domains.base import BaseDomainAnalyzer


class FrontendDomainAnalyzer(BaseDomainAnalyzer):
    @property
    def name(self) -> str:
        return "Frontend (Web UI/UX)"

    def detect(self, repo_path: Path) -> bool:
        fe_indicators = [
            "package.json",
            "vite.config.ts",
            "vite.config.js",
            "next.config.js",
            "next.config.mjs",
            "tailwind.config.js",
            "src/App.tsx",
            "src/App.vue",
        ]
        return any((repo_path / ind).exists() for ind in fe_indicators)

    def get_default_build_command(self, repo_path: Path) -> Optional[str]:
        pkg_json = repo_path / "package.json"
        if not pkg_json.exists():
            return None

        pm = "npm"
        if (repo_path / "pnpm-lock.yaml").exists():
            pm = "pnpm"
        elif (repo_path / "yarn.lock").exists():
            pm = "yarn"
        elif (repo_path / "bun.lockb").exists() or (repo_path / "bun.lock").exists():
            pm = "bun"

        try:
            content = pkg_json.read_text(encoding="utf-8")
            if '"build":' in content:
                return f"{pm} run build"
            if '"check":' in content:
                return f"{pm} run check"
        except (OSError, UnicodeDecodeError):
            pass
        return f"{pm} test"

    def generate_recommended_invariants(self, prompt: str, files: List[str]) -> List[LockedInvariant]:
        return [
            LockedInvariant(
                id="FE-INV-01",
                description="Do not break interactive loading feedback (spinners/skeletons) during user actions.",
                rationale="Avoid perceived freezing and ensure zero perceived latency.",
            ),
            LockedInvariant(
                id="FE-INV-02",
                description="Ensure ergonomic keyboard navigation (Escape, Enter, ArrowUp/Down) and backdrop modal dismissal work.",
                rationale="Accessibility and ergonomic UI standards.",
            ),
            LockedInvariant(
                id="FE-INV-03",
                description="Preserve responsive layouts across mobile, tablet, and desktop viewports without horizontal overflow.",
                rationale="Prevent UI breakage across screen dimensions.",
            ),
        ]

    def generate_targeted_test_plan(self, files: List[str], diff_text: str) -> List[str]:
        steps = [
            "Verify responsive layout across Mobile (390px) and Desktop (1440px) breakpoints.",
            "Click primary action buttons to verify immediate `disabled` state and loading indicator.",
        ]
        if "modal" in diff_text.lower() or "dialog" in diff_text.lower():
            steps.append("Open Modal/Dialog and verify pressing 'Escape' or clicking the backdrop dismisses it cleanly.")
        if "input" in diff_text.lower() or "textarea" in diff_text.lower():
            steps.append("Test text input with IME (Asian/diacritic input methods) to verify text doesn't freeze or drop focus.")
        return steps
