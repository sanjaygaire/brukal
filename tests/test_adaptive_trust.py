"""
test_adaptive_trust.py — milestone 6: adaptive per-agent trust T_i.

Proves the novel layer and, crucially, that it stays inside its lane:

  * trust starts full, decays on bad behaviour, and "collapses" below a floor;
  * a collapsed agent's SAME benign command is ESCALATEd rather than ALLOWed —
    trust modulates the soft decision;
  * trust NEVER touches the hard gate: a collapsed agent's out-of-scope command
    still dies at hard:scope, and hard denials carry no trust value (they never
    reached the soft layer) — invariant 1 holds;
  * the orchestrator updates trust from each turn's outcome, so one bad turn
    raises scrutiny on the next (the adaptive loop);
  * a claim the verify agent could not confirm costs the CLAIMING agent trust.

Needs pydantic only for the orchestrator/verify parts; the TrustModel + gate
tests are standard-library.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import (AuditLog, Executor, FakeKali, Gate, TrustModel, load_scope)

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"


# --------------------------------------------------------------------------- #
# TrustModel in isolation
# --------------------------------------------------------------------------- #

def test_fresh_agent_is_fully_trusted():
    tm = TrustModel()
    assert tm.of("recon") == 1.0
    assert tm.collapsed("recon") is False


def test_trust_decays_and_collapses_then_recovers():
    tm = TrustModel()                       # initial 1.0, alpha 0.3, floor 0.25
    for _ in range(3):
        tm.penalize("bot")
    assert tm.of("bot") == pytest.approx(0.343, abs=1e-3)
    assert tm.collapsed("bot") is False     # 0.343 > floor
    tm.penalize("bot")
    assert tm.collapsed("bot") is True       # 0.24 < floor
    # trust is recoverable (EMA climbs back toward 1.0 but asymptotically)
    for _ in range(10):
        tm.reward("bot")
    assert tm.of("bot") > 0.9
    assert tm.collapsed("bot") is False
    assert tm.reward("solid") == 1.0         # reward from full stays clamped at full


# --------------------------------------------------------------------------- #
# Trust feeds ONLY the soft layer
# --------------------------------------------------------------------------- #

def test_collapsed_agent_benign_action_escalates():
    scope = load_scope(SCOPE)
    tm = TrustModel()
    for _ in range(5):
        tm.penalize("badbot")               # collapse it (~0.168)
    assert tm.collapsed("badbot")
    tmp = tempfile.mkdtemp()
    try:
        ex = Executor(Gate(scope, trust=tm), FakeKali(), AuditLog(Path(tmp) / "a.jsonl"))
        # a fully-trusted agent: the benign command is ALLOWed
        d_good, r_good = ex.run("nmap -sV 10.10.10.5", "10.10.10.5", agent="goodbot")
        assert d_good.verdict == "ALLOW"
        assert d_good.trust == 1.0
        # the collapsed agent: the SAME command is now ESCALATEd
        d_bad, r_bad = ex.run("nmap -sV 10.10.10.5", "10.10.10.5", agent="badbot")
        assert d_bad.verdict == "ESCALATE"
        assert d_bad.trust is not None and d_bad.trust < 0.25
        assert r_bad is None                # default approver is fail-closed
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_trust_never_affects_the_hard_gate():
    # Invariant 1: no matter how collapsed the agent, scope is enforced by the
    # deterministic hard gate, which does not consider trust at all.
    scope = load_scope(SCOPE)
    tm = TrustModel()
    for _ in range(8):
        tm.penalize("badbot")               # trust ~ 0
    tmp = tempfile.mkdtemp()
    try:
        ex = Executor(Gate(scope, trust=tm), FakeKali(), AuditLog(Path(tmp) / "a.jsonl"))
        d, r = ex.run("nmap -sV 8.8.8.8", "8.8.8.8", agent="badbot")
        assert d.verdict == "DENY"
        assert d.layer == "hard:scope"      # died at the hard gate, not the soft one
        assert d.trust is None              # hard denials never reach the soft layer
        assert r is None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- #
# The adaptive loop, through the orchestrator
# --------------------------------------------------------------------------- #

pytest.importorskip("pydantic")

from brukal import Blackboard, Orchestrator, TaskStatus, TaskTree
from brukal.agents import ReconAgent, VerifyResult


class StubLLM:
    def __init__(self, responses):
        self._responses = list(responses)

    def propose(self, system, user, max_tokens=1024):
        return self._responses.pop(0) if self._responses else ""


def _req(command, target):
    return json.dumps({"proposing_agent": "recon", "intent": "enumerate",
                       "command": command, "target_host": target,
                       "justification": "test"})


def test_orchestrator_one_bad_turn_raises_scrutiny_on_the_next():
    # Turn 1: recon proposes an out-of-scope command -> DENY -> trust drops.
    # Turn 2: recon proposes a BENIGN command that a fresh agent would ALLOW, but
    #         because trust fell it is now ESCALATEd (and declined -> not run).
    scope = load_scope(SCOPE)
    tmp = tempfile.mkdtemp()
    try:
        kali = FakeKali()
        audit = AuditLog(Path(tmp) / "audit.jsonl")
        tm = TrustModel()
        executor = Executor(Gate(scope, trust=tm), kali, audit)   # default approver = deny
        recon = ReconAgent(StubLLM([_req("nmap -sV 8.8.8.8", "8.8.8.8"),
                                    _req("nmap -sV 10.10.10.5", "10.10.10.5")]), executor)
        bb = Blackboard(Path(tmp) / "vault", scope)
        tree = TaskTree()
        tree.add("t1", "8.8.8.8", agent="recon")
        tree.add("t2", "10.10.10.5", agent="recon")

        Orchestrator(tree, {"recon": recon}, bb, trust=tm).run()

        tasks = tree.all_tasks()
        assert tasks[0].findings[0]["verdict"] == "DENY"        # bad turn
        assert tasks[1].findings[0]["verdict"] == "ESCALATE"    # now under scrutiny
        # the benign command was NOT executed (escalation declined)
        assert kali.executed == []
        assert tm.of("recon") < 1.0
        assert audit.verify() is True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_clean_agent_keeps_full_trust():
    scope = load_scope(SCOPE)
    tmp = tempfile.mkdtemp()
    try:
        tm = TrustModel()
        executor = Executor(Gate(scope, trust=tm), FakeKali(),
                            AuditLog(Path(tmp) / "audit.jsonl"))
        recon = ReconAgent(StubLLM([_req("nmap -sV 10.10.10.5", "10.10.10.5")]), executor)
        bb = Blackboard(Path(tmp) / "vault", scope)
        tree = TaskTree()
        tree.add("scan", "10.10.10.5", agent="recon")
        Orchestrator(tree, {"recon": recon}, bb, trust=tm).run()
        assert tree.all_tasks()[0].status == TaskStatus.DONE
        assert tm.of("recon") == 1.0        # clean execution -> trust intact
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_unconfirmed_claim_costs_the_claiming_agent_trust():
    # The anti-hallucination loop: getting caught with an unverifiable claim hurts.
    tm = TrustModel()
    tm.record_verification("exploit", VerifyResult("claim", "UNSUPPORTED", "", "", "x"))
    assert tm.of("exploit") < 1.0
    tm2 = TrustModel()
    tm2.record_verification("exploit", VerifyResult("claim", "UNVERIFIED", "", "", "x"))
    assert tm2.of("exploit") < 1.0
    tm3 = TrustModel()
    tm3.record_verification("exploit", VerifyResult("claim", "SUPPORTED", "ev", "cmd", "x"))
    assert tm3.of("exploit") == 1.0         # a confirmed claim keeps full trust
