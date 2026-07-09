"""
test_orchestrator_blackboard.py — milestone 4: orchestrator + blackboard + tree.

Properties proven (stub LLM + FakeKali + a temp vault — no API key, no Docker):

  * the orchestrator walks the task tree sequentially and executes in-scope work;
  * each agent's DIGESTED findings land in its own blackboard folder;
  * `read_context` returns a SCOPED slice (only the relevant target), not history;
  * a task whose agent proposes out-of-scope work is FAILED and never executes;
  * a task for a role with no agent is BLOCKED (fail-closed routing);
  * only DIGESTS are stored — raw tool output never enters the blackboard;
  * the scope MIRROR is reference only: rewriting it cannot widen what the gate
    allows (invariants 1 & 5);
  * agents are handed the Executor, never the Kali cage (invariant 4).

Needs pydantic (agents extra); skipped cleanly if absent.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("pydantic")

from brukal import (AuditLog, Blackboard, Executor, FakeKali, Gate,
                    Orchestrator, TaskStatus, TaskTree, load_scope)
from brukal.agents import ReconAgent

SCOPE = Path(__file__).resolve().parents[1] / "scope.json"


class StubLLM:
    """Returns queued canned responses in order (one per agent turn)."""
    def __init__(self, responses):
        self._responses = list(responses)

    def propose(self, system, user, max_tokens=1024):
        return self._responses.pop(0) if self._responses else ""


def _proposal(command, target):
    return json.dumps({
        "proposing_agent": "recon", "intent": "enumerate",
        "command": command, "target_host": target, "justification": "test",
    })


def _build(responses):
    tmp = tempfile.mkdtemp()
    scope = load_scope(SCOPE)
    kali = FakeKali()
    audit = AuditLog(Path(tmp) / "audit.jsonl")
    executor = Executor(Gate(scope), kali, audit)
    agent = ReconAgent(StubLLM(responses), executor)
    bb = Blackboard(Path(tmp) / "vault", scope)
    tree = TaskTree()
    orch = Orchestrator(tree, {"recon": agent}, bb)
    return orch, tree, bb, kali, audit, agent, tmp


def test_sequential_run_executes_and_records():
    orch, tree, bb, kali, audit, agent, tmp = _build(
        [_proposal("nmap -sV 10.10.10.5", "10.10.10.5"),
         _proposal("whatweb http://10.10.10.7", "10.10.10.7")])
    try:
        tree.add("Enumerate services on 10.10.10.5", "10.10.10.5")
        tree.add("Fingerprint web on 10.10.10.7", "10.10.10.7")

        summary = orch.run()
        assert summary == {"executed": 2, "failed": 0, "blocked": 0}

        # both ran in the cage, in order
        assert kali.executed == ["nmap -sV 10.10.10.5", "whatweb http://10.10.10.7"]
        # both tasks marked done
        assert [t.status for t in tree.all_tasks()] == [TaskStatus.DONE, TaskStatus.DONE]
        # per-agent findings written
        recon_notes = list((bb.root / "agents" / "recon").glob("*.md"))
        assert len(recon_notes) == 2
        # shared stream has two records
        stream = (bb.root / "findings.jsonl").read_text().splitlines()
        assert len(stream) == 2
        # task tree persisted for humans
        assert (bb.root / "task_tree.md").exists()
        assert audit.verify() is True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_out_of_scope_task_fails_and_never_executes():
    orch, tree, bb, kali, audit, agent, tmp = _build(
        [_proposal("nmap -sV 8.8.8.8", "8.8.8.8")])  # agent fooled -> out of scope
    try:
        tree.add("Enumerate 8.8.8.8 (agent was tricked)", "8.8.8.8")
        summary = orch.run()
        assert summary == {"executed": 0, "failed": 1, "blocked": 0}
        assert kali.executed == []                      # nothing ran
        assert tree.all_tasks()[0].status == TaskStatus.FAILED
        # the failure is recorded as a digest citing the gate layer
        rec = json.loads((bb.root / "findings.jsonl").read_text().splitlines()[0])
        assert "hard:scope" in rec["summary"]
        assert audit.verify() is True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_scoped_read_returns_only_relevant_target():
    orch, tree, bb, kali, audit, agent, tmp = _build([])
    try:
        bb.write_finding("recon", {"target": "10.10.10.5", "summary": "host A open 22"})
        bb.write_finding("recon", {"target": "10.10.10.7", "summary": "host B open 80"})
        ctx = bb.read_context("recon", "10.10.10.5")
        assert "host A open 22" in ctx
        assert "host B open 80" not in ctx            # scoped: other host excluded
        assert bb.read_context("recon", "10.10.10.99") == ""   # nothing relevant
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_unknown_role_is_blocked():
    orch, tree, bb, kali, audit, agent, tmp = _build([])
    try:
        tree.add("Exploit the box", "10.10.10.5", agent="exploit")   # no such agent
        summary = orch.run()
        assert summary == {"executed": 0, "failed": 0, "blocked": 1}
        assert tree.all_tasks()[0].status == TaskStatus.BLOCKED
        assert kali.executed == []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_only_digests_are_stored_not_raw_dumps():
    # A cage whose output is enormous — the blackboard must keep only a digest.
    class LoudKali:
        def __init__(self):
            self.executed = []

        def run(self, command):
            from brukal import ExecResult
            self.executed.append(command)
            big = "LINE0-MARKER\n" + "\n".join(f"noise-{i}" for i in range(1000)) \
                  + "\nLINE1000-SECRET"
            return ExecResult(command, 0, big, "")

    tmp = tempfile.mkdtemp()
    try:
        scope = load_scope(SCOPE)
        audit = AuditLog(Path(tmp) / "audit.jsonl")
        executor = Executor(Gate(scope), LoudKali(), audit)
        agent = ReconAgent(StubLLM([_proposal("nmap -sV 10.10.10.5", "10.10.10.5")]),
                           executor)
        bb = Blackboard(Path(tmp) / "vault", scope)
        tree = TaskTree()
        tree.add("scan", "10.10.10.5")
        Orchestrator(tree, {"recon": agent}, bb).run()

        stream = (bb.root / "findings.jsonl").read_text()
        assert "LINE0-MARKER" in stream            # the first line survived (digest)
        assert "noise-500" not in stream           # the bulk did NOT
        assert "LINE1000-SECRET" not in stream     # nor the tail
        rec = json.loads(stream.splitlines()[0])
        assert len(rec["summary"]) < 260           # a summary, not a dump
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_scope_mirror_is_reference_only_and_cannot_widen_scope():
    orch, tree, bb, kali, audit, agent, tmp = _build([])
    try:
        mirror = bb.scope_mirror_path()
        assert mirror.exists()
        assert "READ-ONLY" in mirror.read_text()

        # An attacker (or a confused process) rewrites the mirror to "authorise"
        # a public IP. The gate must not care — it reads the immutable Scope.
        os.chmod(mirror, 0o644)
        mirror.write_text("authorized_networks: 8.8.8.8/32, 0.0.0.0/0\n")

        scope = load_scope(SCOPE)
        ex = Executor(Gate(scope), FakeKali(), AuditLog(Path(tmp) / "a2.jsonl"))
        decision, result = ex.run("nmap -sV 8.8.8.8", "8.8.8.8", agent="recon")
        assert decision.verdict == "DENY"
        assert decision.layer == "hard:scope"      # mirror was ignored
        assert result is None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_agents_are_handed_the_executor_not_the_cage():
    # Invariant 4, encoded as a test: an agent can submit, but has no cage.
    orch, tree, bb, kali, audit, agent, tmp = _build([])
    try:
        assert hasattr(agent, "_executor")
        assert not hasattr(agent, "_kali")            # no direct path to the cage
        assert not hasattr(orch, "_kali")             # nor does the orchestrator
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
