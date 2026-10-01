"""
Infrastructure (Infra) Domain Analyzer.
Handles Docker, Kubernetes, Terraform, Helm, GitHub Actions, Nginx, Cloud resources.
Extracts port mappings, secret bindings, volume mounts, resource quotas, and downtime risks.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from guard.core.session import LockedInvariant
from guard.domains.base import BaseDomainAnalyzer


class InfraDomainAnalyzer(BaseDomainAnalyzer):
    @property
    def name(self) -> str:
        return "Infrastructure & DevOps (IaC / Containers / CI-CD)"

    def detect(self, repo_path: Path) -> bool:
        infra_indicators = [
            "Dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            "main.tf",
            # CI config alone (.github/workflows) does not make a repo infrastructure
            "k8s",
            "helm",
            "nginx.conf",
        ]
        return any((repo_path / ind).exists() for ind in infra_indicators)

    def get_default_build_command(self, repo_path: Path) -> Optional[str]:
        if (repo_path / "main.tf").exists() or any(repo_path.glob("*.tf")):
            return "terraform validate"
        if (repo_path / "docker-compose.yml").exists() or (repo_path / "docker-compose.yaml").exists():
            return "docker compose config"
        if (repo_path / "Dockerfile").exists():
            return "docker build -t guard-temp-check . -f Dockerfile"
        return None

    def generate_recommended_invariants(self, prompt: str, files: List[str]) -> List[LockedInvariant]:
        return [
            LockedInvariant(
                id="INFRA-INV-01",
                description="Never hardcode passwords, private keys, or production secrets into manifests or Dockerfiles.",
                rationale="Prevent critical secret exposure in git history.",
            ),
            LockedInvariant(
                id="INFRA-INV-02",
                description="Do not bind internal database ports (PostgreSQL, Redis, MongoDB) to public 0.0.0.0/0 interfaces.",
                rationale="Prevent public port-scanning and unauthorized database access.",
            ),
            LockedInvariant(
                id="INFRA-INV-03",
                description="Ensure zero-downtime rolling updates: configure valid readiness and liveness health checks.",
                rationale="Avoid service outages during rolling deployments.",
            ),
        ]

    def generate_targeted_test_plan(self, files: List[str], diff_text: str) -> List[str]:
        return [
            "Run configuration validator: `docker compose config` or `terraform validate`.",
            "Inspect git diff to confirm 100% absence of hardcoded tokens or API credentials.",
            "Verify container port bindings and environment variables maintain service interconnectivity.",
        ]
