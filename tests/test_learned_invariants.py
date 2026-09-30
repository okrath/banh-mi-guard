"""
Rules the review gate learns are kept only when a check verifies them and they are not already a
rule in other words; the reviewer sees every rule that exists; unverified learned rules can be
listed and removed by the user.
"""

import json
from unittest.mock import patch

from typer.testing import CliRunner

import guard.cli as cli

import guard.commands.invariants as invariants_cmds
from guard.cli import app
from guard.core.config import GuardConfig, LLMConfig
from guard.core.invariant_eval import DomainType
from guard.core.llm_reviewer import LLMReviewerEngine
from guard.core.project_invariants import (
    append_learned_invariants, dump_invariants, learned_without_checks, similar, write_invariants_file,
)
from test_untracked import make_repo

CHECK = [{"files": "src/chat.ts", "require": "export"}]


def team_rules(repo, items):
    (repo / "guard.invariants.json").write_text(dump_invariants({"invariants": items}), encoding="utf-8", newline="\n")


def test_a_learned_rule_needs_a_check_that_holds(tmp_path):
    repo = make_repo(tmp_path)
    added, rejected = append_learned_invariants(repo, [
        {"id": "NO-CHECK", "description": "Esc stops generation"},
        {"id": "NO-PATTERN", "description": "Chat module stays small", "checks": [{"files": "src/chat.ts"}]},
        {"id": "NO-FILE", "description": "Retries are capped", "checks": [{"files": "src/missing.ts", "require": "retry"}]},
        {"id": "VACUOUS", "description": "Chat file has content", "checks": [{"files": "src/chat.ts", "require": "."}]},
        {"id": "ALT-ANY", "description": "Chat file mentions foo", "checks": [{"files": "src/chat.ts", "require": ".*|foo"}]},
        {"id": "NEVER-FIRES", "description": "Chat never calls foo", "checks": [{"files": "src/chat.ts", "forbid": "(?!)foo"}]},
        {"id": "ATOMIC-NEVER", "description": "Chat skips bar", "checks": [{"files": "src/chat.ts", "forbid": "(?>bar)(?!)"}]},
        {"id": "LONG-ANY", "description": "Chat long enough", "checks": [{"files": "src/chat.ts", "require": "(?s).{10}|foo"}]},
        {"id": "WORD-FORBID", "description": "No TODO left in chat", "checks": [{"files": "src/chat.ts", "forbid": r"\bTODO\b"}]},
        {"id": "HOLDS", "description": "The chat module exports its API", "checks": CHECK},
    ], "s1")
    assert added == ["WORD-FORBID", "HOLDS"]  # a forbid that can fire is fine
    notes = " / ".join(rejected)
    assert "NO-CHECK: no automated check" in notes and "NO-PATTERN: a check needs" in notes
    assert "NO-FILE: check does not pass" in notes and "matches no file" in notes
    assert "VACUOUS: a check pattern needs a literal" in notes  # `.` holds on any non-empty file
    assert "ALT-ANY: the `require` pattern matches unrelated text" in notes  # a literal does not save `.*|foo`
    assert "NEVER-FIRES: the `forbid` pattern cannot be shown to match" in notes  # `(?!)` fails everywhere
    assert "ATOMIC-NEVER: the `forbid` pattern cannot be shown to match" in notes
    assert "LONG-ANY: the `require` pattern matches unrelated text" in notes  # random text of any length


def test_a_malformed_check_is_rejected_with_a_reason_not_a_crash(tmp_path):
    repo = make_repo(tmp_path)
    added, rejected = append_learned_invariants(repo, [
        {"id": "STR-CHECK", "description": "Rule one about chat", "checks": ["src/chat.ts"]},
        {"id": "INT-CHECK", "description": "Rule two about retries", "checks": 5},
        {"id": "LIST-FILES", "description": "Rule three about send", "checks": [{"files": ["src/chat.ts"], "require": "x"}]},
        {"id": "MIXED", "description": "Rule four about ui", "checks": CHECK + ["junk"]},
    ], "s1")
    assert added == [] and len(rejected) == 4
    assert all("a check must be an object" in r or "all text" in r for r in rejected)


def test_a_reworded_rule_is_rejected_as_similar(tmp_path):
    repo = make_repo(tmp_path)
    team_rules(repo, [{"id": "GIT-EXCLUDE-LOCK", "description": "Every write to the common Git `info/exclude` uses the shared OS lock.",
                       "checks": CHECK}])
    reworded = "Every guard-owned change to Git's `info/exclude` uses the shared OS lock in `guard/core/git_exclude.py`."
    other = "The chat module exports a send function used by the UI"
    assert similar(reworded, "Every write to the common Git `info/exclude` uses the shared OS lock.")
    added, rejected = append_learned_invariants(repo, [
        {"id": "EXCLUDE-WRITE-LOCK", "description": reworded, "checks": CHECK},
        {"id": "CHAT-SEND", "description": other, "checks": CHECK},
    ], "s1")
    assert added == ["CHAT-SEND"] and rejected == ["EXCLUDE-WRITE-LOCK: similar to GIT-EXCLUDE-LOCK (already a rule)"]
    # learned in this session counts too: the same rule proposed again in the next round is similar
    _, again = append_learned_invariants(repo, [{"id": "CHAT-SEND-2", "description": other + ".", "checks": CHECK}], "s1")
    assert again == ["CHAT-SEND-2: similar to CHAT-SEND (already a rule)"]
    # a short rule is a duplicate when it says exactly the same (fewer words than the overlap measure needs)
    append_learned_invariants(repo, [{"id": "TLS-01", "description": "TLS required", "checks": CHECK}], "s1")
    _, short = append_learned_invariants(repo, [{"id": "TLS-02", "description": "tls  REQUIRED.", "checks": CHECK}], "s1")
    assert short == ["TLS-02: similar to TLS-01 (already a rule)"]
    assert not similar("TLS required", "TLS optional")
    assert similar("TLS required", "TLS required for clients")  # a short rule inside a longer one
    assert not similar("TLS required", "TLS not required")  # its negation is a different rule
    assert not similar("The chat module calls the API directly", "The chat module never calls the API directly")


def test_the_reviewer_sees_rules_learned_earlier_in_the_session(tmp_path):
    repo = make_repo(tmp_path)
    append_learned_invariants(repo, [{"id": "CHAT-SEND", "description": "The chat module exports send", "checks": CHECK}], "s1")
    cfg = GuardConfig(llm=LLMConfig(base_url="http://127.0.0.1:9/v1", api_key="k", model="m"))
    prompts = []

    def fake_call(**kw):
        prompts.append(kw["prompt"] + kw.get("system_prompt", ""))
        return "SCORE: 8\nSUMMARY: ok\nFINDINGS: None"
    with patch("guard.core.llm_reviewer.call_llm", side_effect=fake_call):
        LLMReviewerEngine(config=cfg).review(prompt="x", domain=DomainType.BACKEND, known_rules=cli._known_rules(repo))
    assert "- CHAT-SEND: The chat module exports send" in prompts[0]
    assert "A machine check is required" in prompts[0]


def test_prune_removes_only_learned_rules_without_checks_and_only_for_the_user(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    team_rules(repo, [{"id": "TEAM-01", "description": "Team rule without a check"}])
    write_invariants_file(repo, [
        {"id": "LEARNED-NO", "description": "Learned without check one", "checks": [], "origin": "llm:s1"},
        {"id": "LEARNED-YES", "description": "Learned with a check", "checks": CHECK, "origin": "llm:s1"},
        {"id": "LOCAL-OWN", "description": "Set up locally without check", "checks": []},
        {"id": "LEARNED-NO", "description": "Hand-written rule reusing that id", "checks": CHECK},  # same id, kept
    ], comment="", local=True)
    assert [i["id"] for i in learned_without_checks(repo)] == ["LEARNED-NO"]

    result = CliRunner().invoke(app, ["invariants", "check", "--repo", str(repo)])
    assert "LEARNED-NO" in result.output and "guard invariants prune" in result.output

    result = CliRunner().invoke(app, ["invariants", "prune", "--repo", str(repo)])
    assert result.exit_code == 1 and "LEARNED-NO" in result.output  # listed, but no terminal: nothing removed
    assert [i["id"] for i in learned_without_checks(repo)] == ["LEARNED-NO"]

    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    def confirm_while_a_rule_is_learned(*a, **k):
        # another session learns a rule while the prompt is open: it was never listed, so it stays
        path = repo / ".guard" / "invariants.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["invariants"].append({"id": "LATE", "description": "Learned during the prompt", "checks": [], "origin": "llm:s2"})
        path.write_text(json.dumps(data), encoding="utf-8")
        return "y"
    monkeypatch.setattr(cli.typer, "prompt", confirm_while_a_rule_is_learned)
    invariants_cmds.invariants_prune_cmd(repo=str(repo))
    local = json.loads((repo / ".guard" / "invariants.json").read_text(encoding="utf-8"))["invariants"]
    assert [(i["id"], bool(i["checks"])) for i in local] == [
        ("LEARNED-YES", True), ("LOCAL-OWN", False), ("LEARNED-NO", True), ("LATE", False)]
    assert "TEAM-01" in (repo / "guard.invariants.json").read_text(encoding="utf-8")  # the team's file is never touched


def test_learning_while_pruning_keeps_the_new_rule(tmp_path, monkeypatch):
    import threading
    import guard.core.project_invariants as pi
    repo = make_repo(tmp_path)
    old = {"id": "OLD", "description": "Learned without check", "checks": [], "origin": "llm:s1"}
    write_invariants_file(repo, [old], comment="", local=True)
    real_write, state = pi.write_invariants_file, {}

    def write_while_another_session_learns(*a, **k):
        # prune has read the file; another session learns a rule now: it must wait for the lock
        learner = threading.Thread(target=append_learned_invariants, args=(
            repo, [{"id": "NEW", "description": "The chat module exports its API", "checks": CHECK}], "s2"))
        learner.start()
        learner.join(timeout=1)
        state["waited"], state["learner"] = learner.is_alive(), learner
        return real_write(*a, **k)
    monkeypatch.setattr(pi, "write_invariants_file", write_while_another_session_learns)
    assert pi.prune_learned_without_checks(repo, confirmed=[old]) == ["OLD"]
    monkeypatch.setattr(pi, "write_invariants_file", real_write)
    state["learner"].join(timeout=40)
    assert state["waited"] and not state["learner"].is_alive()  # it waited, then finished: no deadlock
    local = json.loads((repo / ".guard" / "invariants.json").read_text(encoding="utf-8"))["invariants"]
    assert [i["id"] for i in local] == ["NEW"]  # pruned OLD, kept what was learned meanwhile


def test_invariants_check_names_rules_that_say_the_same_thing(tmp_path):
    repo = make_repo(tmp_path)
    team_rules(repo, [
        {"id": "REG-A", "description": "Untracked decisions are stored beside the common Git info/exclude so worktrees share them"},
        {"id": "REG-B", "description": "Untracked-path decisions live beside info/exclude in the common Git directory so worktrees share them"},
        {"id": "OTHER", "description": "The chat module exports a send function"},
    ])
    output = CliRunner().invoke(app, ["invariants", "check", "--repo", str(repo)]).output
    assert "REG-A, REG-B" in output and "OTHER" not in output.split("say the same thing")[-1]


def test_a_rule_bridging_two_groups_joins_them():
    from guard.core.project_invariants import similar_groups
    items = [
        {"id": "A", "description": "alpha beta gamma"},
        {"id": "B", "description": "delta epsilon zeta"},
        {"id": "C", "description": "alpha beta gamma delta epsilon zeta"},  # similar to both A and B
        {"id": "D", "description": "unrelated chat module export"},
    ]
    assert similar_groups(items) == [["A", "B", "C"]]
