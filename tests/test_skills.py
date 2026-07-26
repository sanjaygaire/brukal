"""
test_skills.py — the knowledge layer (offensive skill packs).

Proves the library loads the vendored packs, retrieves relevant playbooks, and
that when the orchestrator injects a skill into an agent's context it arrives as
labelled REFERENCE — and, the point, still cannot bypass the gate: an out-of-scope
proposal made 'with knowledge' is denied exactly the same.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import (AuditLog, Executor, FakeKali, Gate, SkillLibrary, load_scope)

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"


def test_library_loads_vendored_skills():
    lib = SkillLibrary()
    assert len(lib) >= 40                       # the claude-red pack is vendored
    cats = lib.categories()
    assert "web" in cats and "recon" in cats


def test_retrieve_is_relevant_and_empty_query_is_empty():
    lib = SkillLibrary()
    hits = lib.retrieve("cross-site scripting xss payload in a web application", limit=3)
    assert hits                                  # found something
    assert any(s.category == "web" for s in hits)
    assert lib.retrieve("") == []                # no query -> nothing


def test_render_is_labelled_untrusted_reference():
    lib = SkillLibrary()
    text = lib.context_for("sql injection web application", limit=1)
    assert "REFERENCE KNOWLEDGE" in text
    assert "gate" in text.lower()                # reminds that the gate still rules


class _CapturingLLM:
    def __init__(self, response):
        self.response = response
        self.last_user = None

    def propose(self, system, user, max_tokens=1024):
        self.last_user = user
        return self.response


def _req(command, target):
    return json.dumps({"proposing_agent": "recon", "intent": "enumerate",
                       "command": command, "target_host": target,
                       "justification": "test"})


def test_skill_reaches_the_agent_but_never_bypasses_the_gate():
    pytest.importorskip("pydantic")
    from brukal import Blackboard, Orchestrator, TaskStatus, TaskTree
    from brukal.agents import ReconAgent

    scope = load_scope(SCOPE)
    tmp = tempfile.mkdtemp()
    try:
        audit = AuditLog(Path(tmp) / "audit.jsonl")
        executor = Executor(Gate(scope), FakeKali(), audit)
        # the agent proposes an OUT-OF-SCOPE command despite the injected knowledge
        llm = _CapturingLLM(_req("nmap -sV 8.8.8.8", "8.8.8.8"))
        recon = ReconAgent(llm, executor)
        bb = Blackboard(Path(tmp) / "vault", scope)
        tree = TaskTree()
        tree.add("web application xss and sql injection recon", "8.8.8.8", agent="recon")

        Orchestrator(tree, {"recon": recon}, bb, skills=SkillLibrary()).run()

        # the skill DID reach the agent's prompt, as labelled reference
        assert "REFERENCE KNOWLEDGE" in llm.last_user
        # ...and it changed nothing about enforcement: still denied, still failed
        assert tree.all_tasks()[0].status == TaskStatus.FAILED
        assert tree.all_tasks()[0].findings[0]["verdict"] == "DENY"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
