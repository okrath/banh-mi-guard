"""
Mobile (MB) Domain Analyzer.
Handles Flutter (Dart), React Native (TS/JS), iOS (Swift), Android (Kotlin/Java).
Extracts native permissions, lifecycle states, offline caching, safe area/notches.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from guard.core.session import LockedInvariant
from guard.domains.base import BaseDomainAnalyzer


class MobileDomainAnalyzer(BaseDomainAnalyzer):
    @property
    def name(self) -> str:
        return "Mobile App (Flutter / React Native / iOS / Android)"

    def detect(self, repo_path: Path) -> bool:
        mb_indicators = [
            "pubspec.yaml",
            "android/build.gradle",
            "ios/Podfile",
            "app.json",
            "AndroidManifest.xml",
            "Info.plist",
        ]
        return any((repo_path / ind).exists() for ind in mb_indicators)

    def get_default_build_command(self, repo_path: Path) -> Optional[str]:
        if (repo_path / "pubspec.yaml").exists():
            return "flutter analyze"
        if (repo_path / "android" / "build.gradle").exists():
            return "./gradlew test"
        if (repo_path / "package.json").exists() and (repo_path / "ios").exists():
            return "npm run lint"
        return None

    def generate_recommended_invariants(self, prompt: str, files: List[str]) -> List[LockedInvariant]:
        return [
            LockedInvariant(
                id="MB-INV-01",
                description="Must wrap views in `SafeArea` to prevent UI overlap with notches, dynamic islands, or navigation bars.",
                rationale="Ensure ergonomics across all iOS & Android form factors.",
            ),
            LockedInvariant(
                id="MB-INV-02",
                description="Always verify runtime permission status before accessing hardware devices (Camera, GPS, Microphone).",
                rationale="Prevent application crashes when users deny permissions.",
            ),
            LockedInvariant(
                id="MB-INV-03",
                description="When network connection is lost, application must render cached state or a user-friendly offline view.",
                rationale="Protect mobile UX under unstable network conditions.",
            ),
        ]

    def generate_targeted_test_plan(self, files: List[str], diff_text: str) -> List[str]:
        return [
            "Test application on devices with camera notches (iPhone) and navigation bars (Android).",
            "Simulate Airplane Mode to verify app renders offline cached data without crashing.",
            "Test user permission denial to ensure graceful degradation prompts.",
        ]
