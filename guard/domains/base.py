"""
Base Domain Analyzer Interface.
Defines the standard contract for Frontend, Backend, Infra, and Mobile domains.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional

from guard.core.session import LockedInvariant


class BaseDomainAnalyzer(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of domain: Frontend, Backend, Infra, Mobile"""
        pass

    @abstractmethod
    def detect(self, repo_path: Path) -> bool:
        """Returns True if the repository belongs to this technical domain."""
        pass

    @abstractmethod
    def get_default_build_command(self, repo_path: Path) -> Optional[str]:
        """Returns deterministic build/validation command (e.g. 'npm run build')."""
        pass

    @abstractmethod
    def generate_recommended_invariants(self, prompt: str, files: List[str]) -> List[LockedInvariant]:
        """Generate domain-specific invariants that must NOT be broken."""
        pass

    @abstractmethod
    def generate_targeted_test_plan(self, files: List[str], diff_text: str) -> List[str]:
        """Generate actionable verification test checklist."""
        pass
