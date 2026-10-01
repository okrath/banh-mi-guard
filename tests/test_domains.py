"""
Unit tests for Domain Analyzers and Automatic Detector.
"""

from guard.core.invariant_eval import DomainType
from guard.domains.backend import BackendDomainAnalyzer
from guard.domains.detector import (
    detect_build_command,
    detect_repo_domain,
    extract_contracts_and_invariants,
)
from guard.domains.frontend import FrontendDomainAnalyzer
from guard.domains.infra import InfraDomainAnalyzer
from guard.domains.mobile import MobileDomainAnalyzer


def test_detect_frontend_repo(tmp_path):
    repo = tmp_path / "fe_app"
    repo.mkdir()
    (repo / "package.json").write_text('{"scripts": {"build": "vite build"}}', encoding="utf-8")
    (repo / "pnpm-lock.yaml").write_text("", encoding="utf-8")

    analyzer = detect_repo_domain(repo)
    assert isinstance(analyzer, FrontendDomainAnalyzer)
    cmd = detect_build_command(repo)
    assert cmd == "pnpm run build"


def test_detect_backend_go_repo(tmp_path):
    repo = tmp_path / "be_go"
    repo.mkdir()
    (repo / "go.mod").write_text("module myapp\ngo 1.22", encoding="utf-8")

    analyzer = detect_repo_domain(repo)
    assert isinstance(analyzer, BackendDomainAnalyzer)
    cmd = detect_build_command(repo)
    assert cmd == "go test ./... -v"


def test_detect_infra_repo(tmp_path):
    repo = tmp_path / "infra_iac"
    repo.mkdir()
    (repo / "docker-compose.yml").write_text("version: '3.8'\nservices:\n  app:\n    image: nginx\n", encoding="utf-8")

    analyzer = detect_repo_domain(repo)
    assert isinstance(analyzer, InfraDomainAnalyzer)
    cmd = detect_build_command(repo)
    assert cmd == "docker compose config"


def test_detect_mobile_flutter_repo(tmp_path):
    repo = tmp_path / "mb_flutter"
    repo.mkdir()
    (repo / "pubspec.yaml").write_text("name: flutter_app\ndependencies:\n  flutter:\n    sdk: flutter\n", encoding="utf-8")

    analyzer = detect_repo_domain(repo)
    assert isinstance(analyzer, MobileDomainAnalyzer)
    cmd = detect_build_command(repo)
    assert cmd == "flutter analyze"


def test_extract_contracts_and_invariants_bridge(tmp_path):
    repo = tmp_path / "be_extract"
    repo.mkdir()
    api_file = repo / "routes.py"
    api_file.write_text("""
    @router.post("/api/v1/orders")
    def create_order(user: Depends(get_current_user)):
        pass
    """, encoding="utf-8")

    contracts, invariants = extract_contracts_and_invariants(
        repo_path=repo,
        prompt="Add discount code to order api",
        domain=DomainType.BACKEND,
        files=["routes.py"],
    )

    assert len(invariants) >= 3
    assert any("BE-INV-01" == inv.id for inv in invariants)
    assert contracts == []


def _write(repo, rel, text):
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_node_backend_is_not_frontend(tmp_path):
    from guard.domains.detector import detect_domain
    repo = tmp_path / "api"
    _write(repo, "package.json", '{"dependencies": {"fastify": "4"}, "scripts": {"build": "tsc"}}')
    _write(repo, "pnpm-lock.yaml", "")
    assert detect_domain(repo) == DomainType.BACKEND
    assert detect_build_command(repo) == "pnpm run build"


def test_app_with_dockerfile_is_not_infra(tmp_path):
    from guard.domains.detector import detect_domain
    repo = tmp_path / "web_and_server"
    _write(repo, "package.json", '{"dependencies": {"react": "19", "ws": "8"}, "devDependencies": {"vite": "6"}, "scripts": {"build": "vite build"}}')
    _write(repo, "index.html", "<div id=root></div>")
    _write(repo, "server/index.ts", "export {}")
    _write(repo, "Dockerfile", "FROM node:22")
    assert detect_domain(repo) == DomainType.FULLSTACK
    assert detect_build_command(repo) == "npm run build"  # never `docker build` for an app


def test_monorepo_with_web_and_api_is_fullstack(tmp_path):
    from guard.domains.detector import detect_domain
    repo = tmp_path / "mono"
    _write(repo, "package.json", '{"private": true}')
    _write(repo, "apps/gateway/package.json", '{"dependencies": {"fastify": "4", "drizzle-orm": "1"}}')
    _write(repo, "apps/web/package.json", '{"dependencies": {"react": "19"}, "devDependencies": {"vite": "6"}}')
    assert detect_domain(repo) == DomainType.FULLSTACK


def test_iac_only_repo_is_infra(tmp_path):
    from guard.domains.detector import detect_domain
    repo = tmp_path / "iac"
    _write(repo, "main.tf", 'resource "aws_s3_bucket" "b" {}')
    _write(repo, "Dockerfile", "FROM alpine")
    assert detect_domain(repo) == DomainType.INFRA
