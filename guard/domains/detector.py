"""
Domain Detector & Dispatcher.
Auto-detects whether a repository is FE, BE, Infra, or Mobile,
and delegates contract extraction, build checks, and invariants.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from guard.core.invariant_eval import DomainType
from guard.core.project_invariants import load_project_invariants
from guard.core.session import DomainContract, LockedInvariant
from guard.domains.backend import BackendDomainAnalyzer
from guard.domains.base import BaseDomainAnalyzer
from guard.domains.frontend import FrontendDomainAnalyzer
from guard.domains.infra import InfraDomainAnalyzer
from guard.domains.mobile import MobileDomainAnalyzer

# Build commands are resolved per ecosystem, not per domain: a Node backend still builds with
# its package.json script, and a Dockerfile next to an app must not turn the check into `docker build`.
BUILD_RESOLUTION_ORDER: List[BaseDomainAnalyzer] = [
    MobileDomainAnalyzer(),    # Flutter / Gradle projects have their own toolchain
    FrontendDomainAnalyzer(),  # any package.json: `<pm> run build|check`, else `<pm> test`
    BackendDomainAnalyzer(),   # go / cargo / python
    InfraDomainAnalyzer(),     # IaC-only repositories
]

SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".venv", "venv", "__pycache__", ".guard", "coverage"}

FRONTEND_DEPS = {"react", "react-dom", "vue", "svelte", "preact", "solid-js", "@angular/core", "next", "nuxt",
                 "astro", "vite", "lit", "@sveltejs/kit", "@remix-run/react"}
BACKEND_DEPS = {"express", "fastify", "koa", "hono", "@nestjs/core", "@hono/node-server", "ws", "socket.io",
                "prisma", "@prisma/client", "pg", "mysql2", "mongoose", "sequelize", "typeorm", "better-sqlite3",
                "drizzle-orm", "@trpc/server", "graphql-yoga", "apollo-server"}
MOBILE_DEPS = {"react-native", "expo", "@capacitor/core", "@ionic/react", "@ionic/angular"}


def get_analyzer_by_domain(domain: DomainType) -> BaseDomainAnalyzer:
    if domain in (DomainType.FRONTEND, DomainType.FULLSTACK):
        return FrontendDomainAnalyzer()
    elif domain == DomainType.BACKEND:
        return BackendDomainAnalyzer()
    elif domain == DomainType.INFRA:
        return InfraDomainAnalyzer()
    elif domain == DomainType.MOBILE:
        return MobileDomainAnalyzer()
    return BackendDomainAnalyzer()  # Default fallback


def _package_manifests(repo: Path, max_depth: int = 3) -> List[Path]:
    found: List[Path] = []

    def walk(d: Path, depth: int):
        if depth > max_depth:
            return
        try:
            entries = list(d.iterdir())
        except OSError:
            return
        for e in entries:
            if e.is_dir() and e.name not in SKIP_DIRS and not e.name.startswith("."):
                walk(e, depth + 1)
            elif e.name == "package.json":
                found.append(e)

    walk(repo, 0)
    return found


def _node_manifest_signals(repo: Path) -> Tuple[set, str]:
    """(dependency names, all npm script commands joined) across the repo's package.json files."""
    deps: set = set()
    scripts: List[str] = []
    for manifest in _package_manifests(repo):
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            deps.update((data.get(key) or {}).keys())
        scripts.extend(str(v) for v in (data.get("scripts") or {}).values())
    return deps, " ".join(scripts)


FRONTEND_SCRIPT_RE = re.compile(r"\b(vite|next|nuxt|astro|webpack|react-scripts|ng build|svelte-kit|parcel)\b")


def score_repo_domain(repo_path: Optional[Path] = None) -> Tuple[DomainType, Dict[str, float], List[str]]:
    """
    Weigh several repository signals instead of taking the first marker file that exists.
    Returns (domain, scores, reasons). Frontend and backend both strong -> fullstack; infra only
    wins when infrastructure-as-code dominates (a Dockerfile next to an app does not).
    """
    repo = Path(repo_path or Path.cwd())
    scores = {"frontend": 0.0, "backend": 0.0, "infra": 0.0, "mobile": 0.0}
    reasons: List[str] = []

    def add(kind: str, pts: float, why: str):
        scores[kind] += pts
        reasons.append(f"{kind}+{pts:g} {why}")

    def exists(*names: str) -> bool:
        return any((repo / n).exists() for n in names)

    deps, scripts = _node_manifest_signals(repo)
    fe = sorted(deps & FRONTEND_DEPS)
    if not fe and FRONTEND_SCRIPT_RE.search(scripts):
        add("frontend", 2, "npm scripts run a web bundler")
    be = sorted(deps & BACKEND_DEPS)
    mb = sorted(deps & MOBILE_DEPS)
    if fe:
        add("frontend", 3 + min(len(fe) - 1, 2), f"deps {', '.join(fe[:3])}")
    if be:
        add("backend", 3 + min(len(be) - 1, 2), f"deps {', '.join(be[:3])}")
    if mb:
        add("mobile", 5, f"deps {', '.join(mb[:3])}")

    if exists("vite.config.ts", "vite.config.js", "vite.config.mjs", "next.config.js", "next.config.mjs",
              "nuxt.config.ts", "astro.config.mjs", "svelte.config.js", "angular.json"):
        add("frontend", 2, "web framework config")
    if exists("index.html", "public/index.html", "src/index.html"):
        add("frontend", 2, "index.html")
    src = repo / "src"
    if src.is_dir() and any(next(src.glob(f"**/*.{ext}"), None) for ext in ("tsx", "jsx", "vue", "svelte")):
        add("frontend", 2, "UI component files in src/")
    if exists("server", "api", "src/server", "src/api", "apps/api", "apps/server", "apps/gateway"):
        add("backend", 2, "server/api directory")
    if exists("pyproject.toml", "requirements.txt", "setup.py", "Pipfile"):
        add("backend", 3, "python project")
    if exists("go.mod", "Cargo.toml", "pom.xml", "composer.json", "Gemfile", "mix.exs"):
        add("backend", 3, "backend language manifest")
    if exists("manage.py", "alembic.ini", "prisma/schema.prisma"):
        add("backend", 2, "backend framework marker")

    if exists("pubspec.yaml"):
        add("mobile", 6, "pubspec.yaml")
    if exists("android") and exists("ios"):
        add("mobile", 4, "android/ and ios/")

    if list(repo.glob("*.tf")) or exists("terraform"):
        add("infra", 4, "terraform")
    if exists("Chart.yaml", "helm", "charts", "k8s", "kubernetes", "kustomization.yaml"):
        add("infra", 4, "kubernetes/helm")
    if exists("Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yaml"):
        add("infra", 1, "container files")
    if exists("nginx.conf", "ansible.cfg"):
        add("infra", 1, "server config")

    app = max(scores["frontend"], scores["backend"], scores["mobile"])
    if scores["mobile"] >= 5 and scores["mobile"] >= app:
        domain = DomainType.MOBILE
    elif scores["infra"] > app:
        domain = DomainType.INFRA
    elif scores["frontend"] >= 3 and scores["backend"] >= 3:
        domain = DomainType.FULLSTACK
    elif scores["frontend"] > scores["backend"]:
        domain = DomainType.FRONTEND
    elif scores["backend"] > 0:
        domain = DomainType.BACKEND
    elif scores["infra"] > 0:
        domain = DomainType.INFRA
    else:
        domain = DomainType.BACKEND
    return domain, scores, reasons


def detect_domain(repo_path: Optional[Path] = None) -> DomainType:
    return score_repo_domain(repo_path)[0]


def detect_repo_domain(repo_path: Optional[Path] = None) -> BaseDomainAnalyzer:
    return get_analyzer_by_domain(detect_domain(repo_path))


def detect_build_command(repo_path: Optional[Path] = None) -> Optional[str]:
    path = Path(repo_path or Path.cwd())
    for analyzer in BUILD_RESOLUTION_ORDER:
        if analyzer.detect(path):
            cmd = analyzer.get_default_build_command(path)
            if cmd:
                return cmd
    return None


def analyzer_domain(analyzer: BaseDomainAnalyzer) -> DomainType:
    if isinstance(analyzer, FrontendDomainAnalyzer):
        return DomainType.FRONTEND
    if isinstance(analyzer, InfraDomainAnalyzer):
        return DomainType.INFRA
    if isinstance(analyzer, MobileDomainAnalyzer):
        return DomainType.MOBILE
    return DomainType.BACKEND


def extract_contracts_and_invariants(
    repo_path: Path,
    prompt: str,
    domain: DomainType,
    files: List[str],
) -> Tuple[List[DomainContract], List[LockedInvariant]]:
    """
    Project invariants (`guard.invariants.json`) take precedence over the generic domain
    templates, which cannot know what this repository actually needs to preserve.
    """
    analyzer = get_analyzer_by_domain(domain)
    contracts: List[DomainContract] = []
    project_items = load_project_invariants(repo_path)
    if project_items:  # an empty file (e.g. just created by setup) keeps the domain templates
        invariants = [
            LockedInvariant(
                id=str(i["id"]),
                description=str(i["description"]),
                rationale=str(i.get("rationale", "")),
                source="project",
                checks=list(i.get("checks") or []),
            )
            for i in project_items
        ]
    else:
        invariants = analyzer.generate_recommended_invariants(prompt, files)
    return contracts, invariants
