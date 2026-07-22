"""
test_multiagent.py — the multi-agent mode of the grounded auto loop.

`brukal auto` can run in a "planner + specialist executors" configuration: the
strategist stays the PLANNER (it sets the phase + goal each turn) and the phase's
SPECIALIST agent (recon / exploit / verify) generates the concrete command. These
tests pin the properties that make that safe and worthwhile:

  * routing is deterministic (a keyword match, never an LLM) so target text can't
    steer which agent acts;
  * the specialist's command is what actually runs — the strategist's placeholder
    is replaced, proving the agents really drive execution;
  * routing does NOT add a way around the gate — an out-of-scope specialist command
    is DENIED and never executes (the one door is preserved);
  * a specialist that produces nothing valid falls back to the strategist's command
    (no dead turn) and takes a trust hit;
  * every executed action folds into that agent's per-agent trust.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
from brukal.agents import ExploitAgent, ReconAgent, StrategistAgent, VerifyAgent
from brukal.assist import AssistSession
from brukal.loop import GroundedLoop, _route_role
from brukal.trust import TrustModel

SCOPE = Path(__file__).resolve().parents[1] / "scope.json"
TARGET = "10.10.10.5"


class SeqLLM:
    """Returns scripted responses in order, then repeats the last one forever."""
    def __init__(self, responses):
        self.responses = list(responses)
        self.i = 0

    def propose(self, system, user, max_tokens=1024):
        r = self.responses[min(self.i, len(self.responses) - 1)]
        self.i += 1
        return r


def _adv(goal, run=None, manual=None, phase="recon"):
    lines = [f"PHASE: {phase}", f"GOAL: {goal}", f"REASONING: {goal}."]
    if run:
        lines.append(f"RUN: {run}")
    if manual:
        lines.append(f"MANUAL: {manual}")
    return "\n".join(lines)


def _req(cmd, agent="exploit", intent="exploit", host=TARGET):
    return json.dumps({"proposing_agent": agent, "intent": intent,
                       "command": cmd, "target_host": host, "justification": "x"})


def _ma_loop(strat, recon=None, exploit=None, verify=None, **kw):
    """A GroundedLoop in multi-agent mode: real gate/executor/FakeKali, a scripted
    strategist PLANNER, and scripted specialist agents sharing the executor + a
    shared TrustModel the gate reads."""
    tmp = tempfile.mkdtemp()
    kali = FakeKali()
    trust = TrustModel()
    ex = Executor(Gate(load_scope(SCOPE), trust=trust), kali, AuditLog(Path(tmp) / "a.jsonl"))
    sess = AssistSession(TARGET, ex, StrategistAgent(SeqLLM(strat)))
    agents = {}
    if recon is not None:
        agents["recon"] = ReconAgent(SeqLLM(recon), ex)
    if exploit is not None:
        agents["exploit"] = ExploitAgent(SeqLLM(exploit), ex)
    if verify is not None:
        agents["verify"] = VerifyAgent(SeqLLM(verify), ex)
    loop = GroundedLoop(sess, agents=agents, trust=trust, **kw)
    return loop, sess, kali, trust, tmp


def test_route_role_is_deterministic():
    assert _route_role("exploitation", "exploit the login form") == "exploit"
    assert _route_role("exploitation", "brute-force ssh with hydra") == "exploit"
    assert _route_role("recon", "scan services with nmap") == "recon"
    assert _route_role("enumeration", "fingerprint the web app") == "recon"
    assert _route_role("verification", "confirm the shell works") == "verify"
    # unknown phase falls through to the safe default (read-only recon)
    assert _route_role("", "do something vague") == "recon"


def test_specialist_command_runs_not_the_strategists():
    # Strategist PLANS an exploitation step with a placeholder command; the exploit
    # specialist generates a different (in-scope, allowed) command — that is what runs.
    loop, sess, kali, trust, tmp = _ma_loop(
        strat=[
            "1. [exploitation] get a foothold",                    # make_plan()
            _adv("exploit the login form", run="hydra -l admin 10.10.10.5",
                 phase="exploitation"),
            _adv("hand off", manual="manual exploitation from here"),
        ],
        exploit=[_req("curl http://10.10.10.5/login")],
    )
    try:
        sess.make_plan()
        result = loop.run()
        assert kali.executed == ["curl http://10.10.10.5/login"]   # specialist's, not hydra
        assert "hydra" not in " ".join(kali.executed)
        assert result.stop_reason == "manual"
        assert "exploit" in trust.snapshot()                       # trust was recorded
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_routing_does_not_bypass_the_gate():
    # An out-of-scope specialist command must be DENIED — routing is not a bypass.
    loop, sess, kali, trust, tmp = _ma_loop(
        strat=[
            "1. [exploitation] probe the weakness",
            _adv("attack the service", run="curl http://10.10.10.5/",
                 phase="exploitation"),
        ],
        exploit=[_req("nmap -sV 9.9.9.9", host="9.9.9.9")],        # OUT of scope
        max_steps=6,
    )
    try:
        sess.make_plan()
        result = loop.run()
        assert kali.executed == []                                 # nothing ran
        assert "9.9.9.9" not in " ".join(kali.executed)
        assert result.stop_reason == "stalled"                     # blocked, never executed
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_specialist_miss_falls_back_to_strategist_and_dings_trust():
    # The exploit specialist returns junk (no valid command). The loop must not
    # stall on a dead turn — it falls back to the strategist's own command — and the
    # specialist takes a trust hit for the invalid proposal.
    loop, sess, kali, trust, tmp = _ma_loop(
        strat=[
            "1. [exploitation] foothold",
            _adv("exploit it", run="nmap -sV 10.10.10.5", phase="exploitation"),
            _adv("hand off", manual="over to you"),
        ],
        exploit=["not json — no command here"],
    )
    try:
        sess.make_plan()
        result = loop.run()
        assert kali.executed == ["nmap -sV 10.10.10.5"]            # strategist fallback ran
        assert result.stop_reason == "manual"
        assert trust.of("exploit") < 1.0                           # miss lowered its trust
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_prepare_session_wires_specialists_on_one_executor(monkeypatch, tmp_path):
    # The auto session must expose the three specialists, all sharing the ONE
    # executor (the single door), and its trust must BE the gate's trust — otherwise
    # per-agent trust updates in the loop wouldn't modulate the gate's soft layer.
    import brukal.llm as llm_mod
    from brukal import assist as a

    class DummyLLM:                               # no key / network needed
        def __init__(self, *args, **kw):
            self.usage = None

        def propose(self, *args, **kw):
            return ""

    monkeypatch.setattr(llm_mod, "LLMClient", DummyLLM)

    prep = a._prepare_session(
        TARGET, fake=True, yes_authorised=True, scope_path=str(SCOPE),
        audit_path=str(tmp_path / "a.jsonl"), vault_path=str(tmp_path / "vault"),
        container="x", model=None, provider="anthropic", base_url=None,
        console=None, holder={"status": None})
    assert not isinstance(prep, int), prep
    session, _audit, _target, _cage = prep
    assert set(session.agents) == {"recon", "exploit", "verify"}
    for ag in session.agents.values():
        assert ag._executor is session.executor        # one door, shared
    assert session.trust is session.executor._gate._trust


def _approver_loop(approver):
    """A single-strategist loop whose executor uses `approver`, planning an in-scope
    IRREVERSIBLE action (an ssh credential attack -> ESCALATE)."""
    tmp = tempfile.mkdtemp()
    kali = FakeKali()
    ex = Executor(Gate(load_scope(SCOPE)), kali, AuditLog(Path(tmp) / "a.jsonl"),
                  approver=approver)
    sess = AssistSession(TARGET, ex, StrategistAgent(SeqLLM([
        "1. [exploitation] brute ssh",
        _adv("brute ssh creds", run="hydra -l admin -P words 10.10.10.5 ssh",
             phase="exploitation"),
        _adv("hand off", manual="over to you"),
    ])))
    return GroundedLoop(sess), sess, kali, tmp


def test_full_send_runs_irreversible_in_scope_action_that_governed_pauses():
    from brukal.assist import _auto_approver, _full_send_approver

    # Governed (reversible-only) approver: the in-scope credential attack ESCALATEs
    # and the loop PAUSES for a human — it is never self-approved.
    loop, sess, kali, tmp = _approver_loop(_auto_approver)
    try:
        sess.make_plan()
        r = loop.run()
        assert kali.executed == []                          # hydra did NOT run
        assert r.stop_reason == "escalation"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # Full-send approver: the SAME in-scope action now runs (no pause).
    loop, sess, kali, tmp = _approver_loop(_full_send_approver)
    try:
        sess.make_plan()
        r = loop.run()
        assert any("hydra" in c for c in kali.executed)     # it ran
        assert r.stop_reason == "manual"                    # continued to the next step
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_full_send_still_denies_out_of_scope():
    # Full-send only relaxes the SOFT layer — the hard scope gate is untouched, so an
    # out-of-scope command is still DENIED and never runs.
    from brukal.assist import _full_send_approver

    tmp = tempfile.mkdtemp()
    kali = FakeKali()
    ex = Executor(Gate(load_scope(SCOPE)), kali, AuditLog(Path(tmp) / "a.jsonl"),
                  approver=_full_send_approver)
    sess = AssistSession(TARGET, ex, StrategistAgent(SeqLLM([
        "1. [recon] scan",
        _adv("scan a different host", run="nmap -sV 9.9.9.9"),
    ])))
    loop = GroundedLoop(sess, max_steps=6)
    try:
        sess.make_plan()
        r = loop.run()
        assert kali.executed == []
        assert r.stop_reason == "stalled"                   # blocked, never executed
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_single_strategist_mode_unchanged_when_no_agents():
    # No agents wired -> the loop behaves exactly as before (strategist drives).
    loop, sess, kali, trust, tmp = _ma_loop(
        strat=[
            "1. [recon] scan",
            _adv("scan", run="nmap -sV 10.10.10.5"),
            _adv("done", manual="your move"),
        ],
    )
    try:
        sess.make_plan()
        result = loop.run()
        assert kali.executed == ["nmap -sV 10.10.10.5"]
        assert result.stop_reason == "manual"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
