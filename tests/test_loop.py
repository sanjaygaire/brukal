"""
test_loop.py — the grounded agentic loop.

The loop's whole point is autonomy WITHOUT losing governance or grounding. These
tests pin down the properties that matter:

  * it drives the safe, in-scope steps itself (no operator typing);
  * it stops cleanly on a MANUAL step (human exploitation) and on an ESCALATE
    (never self-approving a risky action);
  * it never spins — a re-proposed command ends the run as `stalled`;
  * its progress is grounded: only commands that really executed count, and
  * an out-of-scope proposal is DENIED inside the loop and never executes
    (the loop adds autonomy, not a way around the gate).
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.loop import GroundedLoop, _norm_cmd

SCOPE = Path(__file__).resolve().parents[1] / "scope.json"


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
    """Build a strategist advise() reply in the template."""
    lines = [f"PHASE: {phase}", f"GOAL: {goal}", f"REASONING: {goal}."]
    if run:
        lines.append(f"RUN: {run}")
    if manual:
        lines.append(f"MANUAL: {manual}")
    return "\n".join(lines)


def _loop(responses, target="10.10.10.5", **kw):
    """A GroundedLoop wired to a real gate/executor/FakeKali + a scripted brain.
    The FIRST response is consumed by make_plan(); the rest drive advise()."""
    tmp = tempfile.mkdtemp()
    kali = FakeKali()
    ex = Executor(Gate(load_scope(SCOPE)), kali, AuditLog(Path(tmp) / "a.jsonl"))
    sess = AssistSession(target, ex, StrategistAgent(SeqLLM(responses)))
    return GroundedLoop(sess, **kw), sess, kali, tmp


def test_loop_drives_safe_steps_then_hands_back_on_manual():
    # plan, then two safe scans, then a manual exploitation step -> pause.
    loop, sess, kali, tmp = _loop([
        "1. [recon] scan the host",                                   # make_plan()
        _adv("scan services", run="nmap -sV 10.10.10.5"),
        _adv("enumerate web", run="whatweb http://10.10.10.5"),
        _adv("exploit the login", manual="try default creds admin:admin"),
    ])
    try:
        sess.make_plan()
        result = loop.run()
        assert kali.executed == ["nmap -sV 10.10.10.5", "whatweb http://10.10.10.5"]
        assert result.stop_reason == "manual"
        assert result.executed == 2
        assert result.paused_for_human
        assert "admin:admin" in result.stop_detail
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_loop_stops_when_a_command_is_re_proposed():
    # The model keeps proposing the same command; grounded output didn't move it
    # forward, so the loop must stop as `stalled`, not run it forever.
    loop, sess, kali, tmp = _loop([
        "1. [recon] scan",                                            # make_plan()
        _adv("scan", run="nmap -sV 10.10.10.5"),
        _adv("scan again", run="nmap -sV 10.10.10.5"),                # repeat
    ], max_steps=10)
    try:
        sess.make_plan()
        result = loop.run()
        assert kali.executed == ["nmap -sV 10.10.10.5"]              # ran exactly once
        assert result.stop_reason == "stalled"
        assert result.executed == 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_loop_pauses_on_escalation_and_never_self_approves():
    # A full-port scan (nmap -sV -p-) is MEDIUM risk -> the soft layer ESCALATEs.
    # The executor's default approver is fail-closed, so the loop must NOT run it
    # and must pause for a human rather than self-approving.
    loop, sess, kali, tmp = _loop([
        "1. [recon] full port sweep",                                # make_plan()
        _adv("full port scan", run="nmap -sV -p- 10.10.10.5"),
    ])
    try:
        sess.make_plan()
        result = loop.run()
        assert result.stop_reason == "escalation"
        assert kali.executed == []                                   # nothing ran
        assert result.executed == 0 and result.paused_for_human
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_loop_denies_out_of_scope_and_keeps_governance():
    # Even mid-autopilot, an out-of-scope proposal is DENIED and never executes.
    # After enough consecutive blocks the loop gives up as stalled.
    loop, sess, kali, tmp = _loop([
        "1. [recon] scan",                                           # make_plan()
        _adv("scan the internet", run="nmap -sV 8.8.8.8"),           # off-scope
        _adv("scan the internet again", run="nmap -sV 1.1.1.1"),     # off-scope
        _adv("and again", run="nmap -sV 9.9.9.9"),                   # off-scope
    ], max_stalls=2)
    try:
        sess.make_plan()
        result = loop.run()
        assert kali.executed == []                                  # governance held
        assert result.stop_reason == "stalled"
        assert all(s.verdict == "DENY" for s in result.steps)
        assert result.blocked >= 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_loop_stops_when_no_command_and_no_manual():
    # The model has nothing to run and nothing manual to hand off -> `done`.
    loop, sess, kali, tmp = _loop([
        "1. [recon] scan",                                          # make_plan()
        "PHASE: recon\nGOAL: think\nREASONING: enumerate more, nothing to run.",
    ])
    try:
        sess.make_plan()
        result = loop.run()
        assert result.stop_reason == "done"
        assert kali.executed == []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_loop_respects_the_step_budget():
    # A model that always proposes a fresh, DISTINCT safe command must still be
    # bounded by the step budget (distinct URLs -> distinct signatures, so the
    # near-duplicate guard doesn't fire first).
    responses = ["1. [recon] scan"] + [
        _adv(f"enum {i}", run=f"curl http://10.10.10.5/path{i}") for i in range(50)]
    loop, sess, kali, tmp = _loop(responses, max_steps=3)
    try:
        sess.make_plan()
        result = loop.run()
        assert result.stop_reason == "exhausted"
        assert result.executed == 3 and len(kali.executed) == 3
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_loop_stops_on_near_duplicate_variants():
    # trivially-different scans of the SAME tool+target (the Nexus cycling) must be
    # caught even though no two commands are identical.
    loop, sess, kali, tmp = _loop([
        "1. [recon] scan",
        _adv("scan", run="nmap -sV -p 80 10.10.10.5"),
        _adv("scan again", run="nmap -sVC -p 80 10.10.10.5"),
        _adv("and again", run="nmap -sV -p 443 10.10.10.5"),
    ], max_similar=2)
    try:
        sess.make_plan()
        result = loop.run()
        assert result.stop_reason == "stalled"
        assert len(kali.executed) == 2          # 2 near-dups ran, the 3rd was stopped
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_sig_collapses_near_duplicates():
    from brukal.loop import _sig
    assert _sig("nmap -sV -p 80 10.10.10.5") == _sig("nmap -sVC -p 443 10.10.10.5")
    assert _sig("nmap 10.10.10.5") != _sig("gobuster dir -u http://10.10.10.5")
    assert _sig("curl http://x/a") != _sig("curl http://x/b")   # path distinguishes


def test_norm_cmd_collapses_whitespace():
    assert _norm_cmd("  nmap   -sV   10.0.0.1 ") == "nmap -sV 10.0.0.1"
    assert _norm_cmd(None) == ""
