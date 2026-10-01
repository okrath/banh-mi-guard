"""
Tests for guard pre-analysis: combined domain and baseline contracts via LLM.
"""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import subprocess


def _git_repo(path):
    """A folder that is a Git repository: guard reads only the files Git lists there."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    return path

from guard.core.config import GuardConfig, LLMConfig, LLMProtocol
from guard.core.invariant_eval import DomainType
from guard.core.llm_client import LLMClientError
from guard.domains.pre_analysis import (
    MAX_PER_FILE_CHARS,
    analyze_task,
    build_pre_analysis_prompt,
)
from guard.task_flow import execute_pre_task


def _make_config(ready: bool = True) -> GuardConfig:
    cfg = GuardConfig()
    cfg.llm = LLMConfig(
        protocol=LLMProtocol.OPENAI,
        base_url="https://api.openai.com",
        api_key="sk-test" if ready else "",
        model="gpt-4o-mini",
    )
    return cfg


def test_valid_llm_answer(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")
    (repo / "routes.py").write_text("def my_route(): pass\n", encoding="utf-8")

    response_text = """
TASK_DOMAIN: backend
REPO_DOMAIN: backend
REASON: Scoped routes.py implements backend HTTP endpoints.
CONTRACTS:
- API_ENDPOINT | list_users | routes.py:list_users | Returns user list
- DATA_INTEGRITY | commit_tx | routes.py:commit_tx | Commits transaction
"""
    called = []

    def fake_call_llm(cfg, prompt, system_prompt=None, temperature=0.2, max_tokens=2048):
        called.append(prompt)
        return response_text

    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", fake_call_llm)

    cfg = _make_config(ready=True)
    res = analyze_task(repo, "Add user route", ["routes.py"], None, cfg)

    assert res.task_domain == DomainType.BACKEND
    assert res.repo_domain == DomainType.BACKEND
    assert res.domain_source == "LLM"
    assert "routes.py" in res.reason
    assert len(res.contracts) == 2
    assert res.contracts[0].name == "list_users"
    assert res.contracts[0].category == "API_ENDPOINT"
    assert "[routes.py:list_users]" in res.contracts[0].description
    assert res.contracts_source == "LLM"
    assert len(called) == 1


def test_unknown_domain_fallback(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")
    (repo / "package.json").write_text('{"dependencies": {"react": "18.0.0"}}', encoding="utf-8")

    response_text = """
TASK_DOMAIN: unknown_domain_xyz
REPO_DOMAIN: backend
REASON: Some reason
CONTRACTS:
- none
"""
    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", lambda *a, **kw: response_text)

    cfg = _make_config(ready=True)
    res = analyze_task(repo, "Check unknown", ["package.json"], None, cfg)

    # Fallback to score_repo_domain: react dependency -> frontend
    assert res.task_domain == DomainType.FRONTEND
    assert res.repo_domain == DomainType.FRONTEND
    assert res.domain_source.startswith("heuristic: unparsable answer")
    assert res.contracts == []
    assert res.contracts_source == "not extracted (unparsable answer)"


def test_stub_raises_fallback(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")

    def fake_fail(*a, **kw):
        raise LLMClientError("Connection refused")

    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", fake_fail)

    cfg = _make_config(ready=True)
    res = analyze_task(repo, "Add something", [], None, cfg)

    assert res.domain_source.startswith("heuristic: LLMClientError: Connection refused")
    assert res.contracts == []
    assert "LLMClientError" in res.contracts_source


def test_llm_not_configured_no_call(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")

    called = []
    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", lambda *a, **kw: called.append(1))

    cfg = _make_config(ready=False)
    res = analyze_task(repo, "No config task", [], None, cfg)

    assert len(called) == 0
    assert res.domain_source == "heuristic: LLM not configured"
    assert res.contracts == []
    assert res.contracts_source == "not extracted (LLM not configured)"


def test_cache_hit_makes_only_one_call(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")
    (repo / "main.py").write_text("print('hello')\n", encoding="utf-8")

    response_text = """
TASK_DOMAIN: backend
REPO_DOMAIN: backend
REASON: Python script
CONTRACTS:
- none
"""
    call_count = [0]

    def fake_call(*a, **kw):
        call_count[0] += 1
        return response_text

    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", fake_call)

    cfg = _make_config(ready=True)
    res1 = analyze_task(repo, "Same prompt", ["main.py"], None, cfg)
    assert call_count[0] == 1
    assert res1.domain_source == "LLM"

    # Second call with the same input: cached
    res2 = analyze_task(repo, "Same prompt", ["main.py"], None, cfg)
    assert call_count[0] == 1
    assert res2.task_domain == res1.task_domain
    assert res2.domain_source == "LLM"


def test_scoped_file_content_is_capped(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    big_file = repo / "big.py"
    big_text = "x = 1\n" * 2500  # 15,000 characters > 8,000
    big_file.write_text(big_text, encoding="utf-8")

    prompt_text, notes = build_pre_analysis_prompt(repo, "Process big file", ["big.py"], None)

    assert any(f"cut to {MAX_PER_FILE_CHARS}" in n for n in notes)
    assert len(big_text) > MAX_PER_FILE_CHARS


def test_end_to_end_execute_pre_task_with_stub(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")
    (repo / "server.py").write_text("app = None\n", encoding="utf-8")

    # Mock git inspector and untracked checks
    monkeypatch.setattr("guard.task_flow.GitDiffInspector.get_working_files", lambda self: [])
    monkeypatch.setattr("guard.task_flow.GitDiffInspector.get_head", lambda self: "abc123456789")
    monkeypatch.setattr("guard.core.untracked.undecided", lambda *a, **kw: [])

    # Mock call_llm
    response_text = """
TASK_DOMAIN: backend
REPO_DOMAIN: backend
REASON: Scoped server.py is backend server code.
CONTRACTS:
- API_ENDPOINT | get_status | server.py:status | Healthcheck endpoint
"""
    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", lambda *a, **kw: response_text)

    # Ensure config has ready=True
    cfg = _make_config(ready=True)
    monkeypatch.setattr("guard.task_flow.load_config", lambda target: cfg)

    success = execute_pre_task(
        prompt="Setup status endpoint",
        scope=["server.py"],
        repo_path=repo,
    )
    assert success is True

    pre_note = (repo / ".guard" / "PRE_TASK_NOTE.md").read_text(encoding="utf-8")
    assert "BACKEND (`LLM`): `Scoped server.py is backend server code.`" in pre_note
    assert "get_status" in pre_note
    assert "[server.py:status]" in pre_note
    # A forced restart keeps the first pre's domain and contracts analysis
    cfg_no_llm = _make_config(ready=False)
    monkeypatch.setattr("guard.task_flow.load_config", lambda target: cfg_no_llm)

    success2 = execute_pre_task(
        prompt="Setup status endpoint 2",
        scope=["server.py"],
        repo_path=repo,
        force=True,
    )
    assert success2 is True

    pre_note2 = (repo / ".guard" / "PRE_TASK_NOTE.md").read_text(encoding="utf-8")
    assert "BACKEND (`LLM`): `Scoped server.py is backend server code.`" in pre_note2
    assert "get_status" in pre_note2
def test_forced_restart_after_scoped_file_edit_makes_no_llm_call_and_keeps_contracts(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")
    server_file = repo / "server.py"
    server_file.write_text("app = None\n", encoding="utf-8")

    monkeypatch.setattr("guard.task_flow.GitDiffInspector.get_working_files", lambda self: [])
    monkeypatch.setattr("guard.task_flow.GitDiffInspector.get_head", lambda self: "abc123456789")
    monkeypatch.setattr("guard.core.untracked.undecided", lambda *a, **kw: [])

    call_count = 0
    def mock_call(*a, **kw):
        nonlocal call_count
        call_count += 1
        return """
TASK_DOMAIN: backend
REPO_DOMAIN: backend
REASON: Initial pre analysis.
CONTRACTS:
- API_ENDPOINT | original_contract | server.py:func | Original baseline
"""
    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", mock_call)

    cfg = _make_config(ready=True)
    monkeypatch.setattr("guard.task_flow.load_config", lambda target: cfg)

    # 1st pre
    assert execute_pre_task(prompt="First pre", scope=["server.py"], repo_path=repo) is True
    assert call_count == 1

    # Edit scoped file
    server_file.write_text("app = 'modified'\n", encoding="utf-8")

    # 2nd pre (--force restart)
    assert execute_pre_task(prompt="Restart pre", scope=["server.py"], repo_path=repo, force=True) is True
    assert call_count == 1  # No LLM call made!

    pre_note = (repo / ".guard" / "PRE_TASK_NOTE.md").read_text(encoding="utf-8")
    assert "original_contract" in pre_note


def test_unparsable_answer_not_cached_and_retried_on_second_pre(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")
    (repo / "main.py").write_text("pass\n", encoding="utf-8")

    cfg = _make_config(ready=True)
    calls = []
    responses = [
        "Random unparsable junk from LLM",
        """
TASK_DOMAIN: frontend
REPO_DOMAIN: frontend
REASON: Frontend UI logic.
CONTRACTS:
- UI_STATE | state_var | main.py:state | State contract
""",
    ]

    def mock_call(*a, **kw):
        calls.append(kw.get("prompt", ""))
        return responses.pop(0)

    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", mock_call)

    # First pre: unparsable
    res1 = analyze_task(
        repo=repo,
        prompt="Build UI",
        scope=["main.py"],
        impact=None,
        config=cfg,
    )
    assert res1.contracts_source == "not extracted (unparsable answer)"
    assert len(calls) == 1

    # Second pre: should NOT hit cache, must call stub again and use valid answer
    res2 = analyze_task(
        repo=repo,
        prompt="Build UI",
        scope=["main.py"],
        impact=None,
        config=cfg,
    )
    assert len(calls) == 2
    assert res2.task_domain == DomainType.FRONTEND
    assert res2.domain_source == "LLM"
    assert len(res2.contracts) == 1
    assert res2.contracts[0].name == "state_var"


def test_scoped_file_over_8000_chars_shows_cut_in_contracts_source(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")
    big_file = repo / "big.py"
    big_file.write_text("x = 1\n" * 2000, encoding="utf-8")  # 12,000 characters > 8,000
    file_size = big_file.stat().st_size

    cfg = _make_config(ready=True)
    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", lambda *a, **kw: """
TASK_DOMAIN: backend
REPO_DOMAIN: backend
REASON: Backend data script.
CONTRACTS:
- DATA_FLOW | pipeline | big.py:run | Data pipeline
""")

    res = analyze_task(
        repo=repo,
        prompt="Process big data",
        scope=["big.py"],
        impact=None,
        config=cfg,
    )
    assert f"LLM (input capped: big.py cut to 8000 of {file_size} bytes)" in res.contracts_source
    assert "\n" not in res.contracts_source


def test_500_line_tree_is_capped_with_note(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")
    for i in range(500):
        (repo / f"file_{i:03d}.py").write_text("x = 1\n", encoding="utf-8")

    prompt_text, notes = build_pre_analysis_prompt(repo, "Check repository", [], None)
    assert "tree cut to 300 of 500 lines" in notes
    assert "... 200 more entries" in prompt_text

    cfg = _make_config(ready=True)
    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", lambda *a, **kw: """
TASK_DOMAIN: backend
REPO_DOMAIN: backend
REASON: Python scripts repo.
CONTRACTS:
- none
""")

    res = analyze_task(
        repo=repo,
        prompt="Check repository",
        scope=[],
        impact=None,
        config=cfg,
    )
    assert "tree cut to 300 of 500 lines" in res.contracts_source


def test_parse_exception_triggers_heuristic_fallback(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")

    cfg = _make_config(ready=True)
    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", lambda *a, **kw: "valid looking text")
    monkeypatch.setattr(
        "guard.domains.pre_analysis._parse_llm_response",
        lambda *a, **kw: (_ for _ in ()).throw(ValueError("Corrupt structure")),
    )

    res = analyze_task(
        repo=repo,
        prompt="Parse error task",
        scope=[],
        impact=None,
        config=cfg,
    )
    assert res.domain_source == "heuristic: unparsable answer"
    assert res.contracts_source == "not extracted (unparsable answer)"


def test_read_scoped_files_skips_outside_files(tmp_path):
    repo = _git_repo(tmp_path / "repo")

    # 1. Absolute path is not read and note says so
    outside_abs = tmp_path / "outside_abs.txt"
    outside_abs.write_text("CONFIDENTIAL_ABS_DATA", encoding="utf-8")

    prompt_abs, notes_abs = build_pre_analysis_prompt(repo, "Check abs", [str(outside_abs)], None)
    assert "CONFIDENTIAL_ABS_DATA" not in prompt_abs
    assert any("skipped: absolute path" in n for n in notes_abs)

    # 2. ../outside.txt path is not read and note says so
    outside_rel = tmp_path / "outside.txt"
    outside_rel.write_text("CONFIDENTIAL_REL_DATA", encoding="utf-8")

    prompt_rel, notes_rel = build_pre_analysis_prompt(repo, "Check rel", ["../outside.txt"], None)
    assert "CONFIDENTIAL_REL_DATA" not in prompt_rel
    assert any("skipped: outside repository" in n for n in notes_rel)


@pytest.mark.skipif(os.name == "nt", reason="Symlinks require privileges on Windows")
def test_read_scoped_files_skips_outside_symlink(tmp_path):
    repo = _git_repo(tmp_path / "repo")

    outside_file = tmp_path / "secret_target.txt"
    outside_file.write_text("CONFIDENTIAL_SYM_DATA", encoding="utf-8")

    symlink_file = repo / "sym_link.txt"
    symlink_file.symlink_to(outside_file)

    prompt_sym, notes_sym = build_pre_analysis_prompt(repo, "Check symlink", ["sym_link.txt"], None)
    assert "CONFIDENTIAL_SYM_DATA" not in prompt_sym
    assert any("sym_link.txt skipped:" in n and "symlink" in n for n in notes_sym)


def test_malformed_contract_row_triggers_unparsable_fallback(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")
    (repo / "routes.py").write_text("pass\n", encoding="utf-8")

    cfg = _make_config(ready=True)

    # Malformed row with 3 parts instead of 4
    response_3_parts = """
TASK_DOMAIN: backend
REPO_DOMAIN: backend
REASON: Scoped routes.py implements backend endpoints.
CONTRACTS:
- API_ENDPOINT | list_users | routes.py:list_users
"""
    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", lambda *a, **kw: response_3_parts)
    res = analyze_task(repo, "Prompt", ["routes.py"], None, cfg)
    assert res.domain_source.startswith("heuristic: unparsable answer")
    assert res.contracts == []
    assert res.contracts_source == "not extracted (unparsable answer)"

    # Malformed row with empty part
    response_empty_part = """
TASK_DOMAIN: backend
REPO_DOMAIN: backend
REASON: Scoped routes.py implements backend endpoints.
CONTRACTS:
- API_ENDPOINT | | routes.py:list_users | Some description
"""
    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", lambda *a, **kw: response_empty_part)
    res = analyze_task(repo, "Prompt", ["routes.py"], None, cfg)
    assert res.domain_source.startswith("heuristic: unparsable answer")

    # Malformed row missing leading dash
    response_no_dash = """
TASK_DOMAIN: backend
REPO_DOMAIN: backend
REASON: Scoped routes.py implements backend endpoints.
CONTRACTS:
API_ENDPOINT | list_users | routes.py:list_users | Some description
"""
    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", lambda *a, **kw: response_no_dash)
    res = analyze_task(repo, "Prompt", ["routes.py"], None, cfg)
    assert res.domain_source.startswith("heuristic: unparsable answer")


def test_contracts_section_empty_triggers_unparsable_fallback(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")
    cfg = _make_config(ready=True)

    response_empty_contracts = """
TASK_DOMAIN: backend
REPO_DOMAIN: backend
REASON: Valid reason
CONTRACTS:
"""
    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", lambda *a, **kw: response_empty_contracts)
    res = analyze_task(repo, "Prompt", [], None, cfg)
    assert res.domain_source.startswith("heuristic: unparsable answer")
    assert res.contracts == []


def test_empty_reason_triggers_unparsable_fallback(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")
    cfg = _make_config(ready=True)

    response_empty_reason = """
TASK_DOMAIN: backend
REPO_DOMAIN: backend
REASON:
CONTRACTS:
- none
"""
    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", lambda *a, **kw: response_empty_reason)
    res = analyze_task(repo, "Prompt", [], None, cfg)
    assert res.domain_source.startswith("heuristic: unparsable answer")
    assert res.contracts == []


def test_missing_contracts_section_triggers_unparsable_fallback(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")
    cfg = _make_config(ready=True)

    response_no_contracts = """
TASK_DOMAIN: backend
REPO_DOMAIN: backend
REASON: Valid reason
"""
    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", lambda *a, **kw: response_no_contracts)
    res = analyze_task(repo, "Prompt", [], None, cfg)
    assert res.domain_source.startswith("heuristic: unparsable answer")
    assert res.contracts == []


def test_manifest_signals_capped_at_60_dependencies(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    pkg = repo / "package.json"
    deps = {f"d{i:02d}": "1.0.0" for i in range(75)}
    pkg.write_text(json.dumps({"dependencies": deps}), encoding="utf-8")

    prompt_text, notes = build_pre_analysis_prompt(repo, "Check deps", [], None)
    assert any("dependencies cut to 60 of 75 names" in n for n in notes)
    assert "... and 15 more" in prompt_text


def test_manifest_line_capped_at_400_characters(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    pkg = repo / "package.json"
    deps = {f"very-long-dependency-package-name-example-{i:02d}": "1.0.0" for i in range(25)}
    pkg.write_text(json.dumps({"dependencies": deps}), encoding="utf-8")

    prompt_text, notes = build_pre_analysis_prompt(repo, "Check line cap", [], None)
    assert any("manifest line cut to 400 of" in n for n in notes)
    manifest_lines = [l for l in prompt_text.splitlines() if l.startswith("package.json files")]
    assert len(manifest_lines) == 1
    assert len(manifest_lines[0]) <= 400
    assert manifest_lines[0].endswith("...")


def test_cache_key_different_model_calls_stub_again(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")
    (repo / "main.py").write_text("print('hello')\n", encoding="utf-8")

    response_text = """
TASK_DOMAIN: backend
REPO_DOMAIN: backend
REASON: Python script
CONTRACTS:
- none
"""
    call_count = 0

    def fake_call(*a, **kw):
        nonlocal call_count
        call_count += 1
        return response_text

    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", fake_call)

    cfg1 = _make_config(ready=True)
    cfg1.llm.model = "gpt-4o-mini"

    # Call with gpt-4o-mini: calls stub
    res1 = analyze_task(repo, "Task", ["main.py"], None, cfg1)
    assert call_count == 1
    assert res1.domain_source == "LLM"

    # Repeat with same model: hits cache
    res2 = analyze_task(repo, "Task", ["main.py"], None, cfg1)
    assert call_count == 1

    # Call with different model gpt-4o: calls stub again!
    cfg2 = _make_config(ready=True)
    cfg2.llm.model = "gpt-4o"
    res3 = analyze_task(repo, "Task", ["main.py"], None, cfg2)
    assert call_count == 2
    assert res3.domain_source == "LLM"


def test_read_scoped_files_bounds_read_length(tmp_path, monkeypatch):
    from guard.domains.pre_analysis import _read_scoped_files
    repo = _git_repo(tmp_path / "repo")
    big_file = repo / "huge.txt"
    big_file.write_text("A" * 20_000, encoding="utf-8")

    read_calls = []
    real_open = open

    class WrappedFile:
        def __init__(self, f):
            self._f = f

        def read(self, n=-1):
            read_calls.append(n)
            return self._f.read(n)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self._f.__exit__(*args)

    def fake_open(file, *args, **kwargs):
        f = real_open(file, *args, **kwargs)
        if Path(file) == big_file:
            return WrappedFile(f)
        return f

    monkeypatch.setattr("builtins.open", fake_open)

    text, notes = _read_scoped_files(repo, ["huge.txt"])
    assert 8001 in read_calls
    assert any("huge.txt cut to 8000 of" in n and "bytes" in n for n in notes)


def test_scope_directories_and_globs_reach_the_prompt(tmp_path):
    import subprocess
    from guard.domains.pre_analysis import build_pre_analysis_prompt

    (tmp_path / "src" / "app").mkdir(parents=True)
    (tmp_path / "src" / "app" / "main.py").write_text("def handler(): return 1\n", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("# guide\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for scope in (["src"], ["src/**/*.py"]):
        text, _ = build_pre_analysis_prompt(tmp_path, "task", scope, None)
        assert "def handler(): return 1" in text, scope
        assert "# guide" not in text


def test_duplicate_task_domain_triggers_unparsable_fallback(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")
    cfg = _make_config(ready=True)

    duplicate_header_response = """
TASK_DOMAIN: backend
TASK_DOMAIN: frontend
REPO_DOMAIN: backend
REASON: Valid reason
CONTRACTS:
- none
"""
    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", lambda *a, **kw: duplicate_header_response)
    res = analyze_task(repo, "Prompt", [], None, cfg)
    assert res.domain_source.startswith("heuristic: unparsable answer")
    assert res.contracts_source == "not extracted (unparsable answer)"


def test_stray_prose_line_before_contracts_triggers_unparsable_fallback(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")
    cfg = _make_config(ready=True)

    stray_prose_response = """
Here is my analysis of the codebase:
TASK_DOMAIN: backend
REPO_DOMAIN: backend
REASON: Valid reason
CONTRACTS:
- none
"""
    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", lambda *a, **kw: stray_prose_response)
    res = analyze_task(repo, "Prompt", [], None, cfg)
    assert res.domain_source.startswith("heuristic: unparsable answer")
    assert res.contracts_source == "not extracted (unparsable answer)"


def test_header_after_contracts_triggers_unparsable_fallback(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path / "repo")
    cfg = _make_config(ready=True)

    header_after_response = """
TASK_DOMAIN: backend
REPO_DOMAIN: backend
REASON: Valid reason
CONTRACTS:
- none
TASK_DOMAIN: frontend
"""
    monkeypatch.setattr("guard.domains.pre_analysis.call_llm", lambda *a, **kw: header_after_response)
    res = analyze_task(repo, "Prompt", [], None, cfg)
    assert res.domain_source.startswith("heuristic: unparsable answer")
    assert res.contracts_source == "not extracted (unparsable answer)"


def test_skip_binary_file_with_nul_bytes(tmp_path):
    import subprocess
    repo = tmp_path / "repo"
    scope_dir = repo / "scoped"
    scope_dir.mkdir(parents=True)
    # Binary file containing NUL bytes
    png_file = scope_dir / "image.png"
    png_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01")
    # Text file
    py_file = scope_dir / "worker.py"
    py_file.write_text("def run_worker():\n    return 'working'\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)

    prompt_text, notes = build_pre_analysis_prompt(repo, "Test task", ["scoped"], None)
    assert "def run_worker():" in prompt_text
    assert "--- File: scoped/image.png ---" not in prompt_text
    assert any("image.png skipped: binary" in n for n in notes)


def test_scope_expanding_to_50_files_over_budget_yields_at_most_21_notes(tmp_path):
    import subprocess
    from guard.domains.pre_analysis import _read_scoped_files
    repo = tmp_path / "repo"
    scope_dir = repo / "scoped"
    scope_dir.mkdir(parents=True)
    # 5 files of 8000 chars reach the 40000 char budget
    for i in range(5):
        (scope_dir / f"budget_{i}.txt").write_text("A" * 8000, encoding="utf-8")
    # 50 files over budget
    for i in range(50):
        (scope_dir / f"extra_{i:02d}.txt").write_text("over budget content\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)

    _, notes = _read_scoped_files(repo, ["scoped"])
    assert len(notes) <= 21
    assert len(notes) == 21
    assert any("more files skipped or cut" in n for n in notes)
    assert notes[-1].endswith("more files skipped or cut")



def test_a_file_git_ignores_is_never_sent(tmp_path):
    from guard.domains.pre_analysis import build_pre_analysis_prompt

    repo = _git_repo(tmp_path / "repo")
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / ".env").write_text("API_TOKEN=do-not-send\n", encoding="utf-8")
    (repo / "app.py").write_text("def run(): pass\n", encoding="utf-8")
    for scope in ([".env", "app.py"], ["*"]):
        text, notes = build_pre_analysis_prompt(repo, "task", scope, None)
        assert "do-not-send" not in text, scope
        assert "def run(): pass" in text, scope
    _, notes = build_pre_analysis_prompt(repo, "task", [".env"], None)
    assert any(".env skipped: ignored by Git" in n for n in notes)


def test_a_description_may_contain_a_pipe():
    from guard.domains.pre_analysis import _parse_llm_response

    answer = ("TASK_DOMAIN: backend\nREPO_DOMAIN: backend\nREASON: api\nCONTRACTS:\n"
              "- API | parse | app.py:parse | returns int | None for an empty string\n")
    task, repo_domain, reason, contracts, malformed, has_section = _parse_llm_response(answer)
    assert malformed == 0 and len(contracts) == 1
    assert "int | None" in contracts[0].description


def test_cache_write_never_follows_a_planted_temp_path(tmp_path):
    from guard.domains.pre_analysis import PRE_ANALYSIS_CACHE, _save_cache

    guard_dir = tmp_path / ".guard"
    guard_dir.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me", encoding="utf-8")
    planted = guard_dir / (PRE_ANALYSIS_CACHE + ".tmp")
    try:
        planted.symlink_to(victim)
    except (OSError, NotImplementedError):
        planted.write_text("planted", encoding="utf-8")  # no symlink right on this machine: a plain file still must not be used
    _save_cache(guard_dir, "k", "answer")
    assert victim.read_text(encoding="utf-8") == "keep me"
    assert (guard_dir / PRE_ANALYSIS_CACHE).is_file()
    assert not [p for p in guard_dir.iterdir() if p.name.startswith(".pre-analysis-")]  # no temp file left


def test_text_after_the_contracts_header_is_unparsable():
    from guard.domains.pre_analysis import _parse_llm_response

    answer = "TASK_DOMAIN: backend\nREPO_DOMAIN: backend\nREASON: api\nCONTRACTS: see below\n- none\n"
    task, repo_domain, reason, contracts, malformed, has_section = _parse_llm_response(answer)
    assert malformed > 0


def test_cache_is_not_written_through_a_guard_folder_that_leads_elsewhere(tmp_path):
    from guard.domains.pre_analysis import PRE_ANALYSIS_CACHE, _load_cache, _save_cache

    repo = tmp_path / "repo"
    repo.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    try:
        (repo / ".guard").symlink_to(elsewhere, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("creating a directory symlink needs a privilege this machine does not grant")
    _save_cache(repo / ".guard", "k", "answer")
    assert not (elsewhere / PRE_ANALYSIS_CACHE).exists()
    assert list(elsewhere.iterdir()) == []
    (elsewhere / PRE_ANALYSIS_CACHE).write_text('{"key": "k", "raw_response": "planted"}', encoding="utf-8")
    assert _load_cache(repo / ".guard", "k") is None


def test_cache_works_in_a_real_guard_folder(tmp_path):
    from guard.domains.pre_analysis import _load_cache, _save_cache

    guard_dir = tmp_path / "repo" / ".guard"
    (tmp_path / "repo").mkdir()
    _save_cache(guard_dir, "k", "answer")
    assert _load_cache(guard_dir, "k") == "answer"
def test_none_contract_only_valid_alone():
    from guard.domains.pre_analysis import _parse_llm_response

    # Single - none is valid
    valid_none = "TASK_DOMAIN: backend\nREPO_DOMAIN: backend\nREASON: api\nCONTRACTS:\n- none\n"
    task, repo_domain, reason, contracts, malformed, has_section = _parse_llm_response(valid_none)
    assert malformed == 0
    assert contracts == []
    assert has_section is True

    # - none together with contract row is unparsable
    none_with_row = (
        "TASK_DOMAIN: backend\nREPO_DOMAIN: backend\nREASON: api\nCONTRACTS:\n"
        "- none\n"
        "- API_ENDPOINT | list_users | routes.py:list_users | Return users list\n"
    )
    task, repo_domain, reason, contracts, malformed, has_section = _parse_llm_response(none_with_row)
    assert malformed > 0

    # Contract row before - none is unparsable
    row_with_none = (
        "TASK_DOMAIN: backend\nREPO_DOMAIN: backend\nREASON: api\nCONTRACTS:\n"
        "- API_ENDPOINT | list_users | routes.py:list_users | Return users list\n"
        "- none\n"
    )
    task, repo_domain, reason, contracts, malformed, has_section = _parse_llm_response(row_with_none)
    assert malformed > 0

    # - none twice is unparsable
    duplicate_none = "TASK_DOMAIN: backend\nREPO_DOMAIN: backend\nREASON: api\nCONTRACTS:\n- none\n- none\n"
    task, repo_domain, reason, contracts, malformed, has_section = _parse_llm_response(duplicate_none)
    assert malformed > 0
