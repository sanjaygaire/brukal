"""
test_robustness.py — PHASE 3: kill switch, budget caps, resumable checkpoints,
and safe parallel enumeration. All deterministic (FakeKali, no net/Docker).
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import (AuditLog, EngagementBudget, Executor, FakeKali, Gate, KillSwitch,
                    checkpoint, load_scope)
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.loop import GroundedLoop

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"
IN = "10.10.10.5"


class _SeqLLM:
    def __init__(self, responses): self.responses = list(responses); self.i = 0
    def propose(self, system, user, max_tokens=1024):
        r = self.responses[min(self.i, len(self.responses) - 1)]; self.i += 1; return r


def _adv(goal, run=None, manual=None, phase="recon"):
    lines = [f"PHASE: {phase}", f"GOAL: {goal}", f"REASONING: {goal}."]
    if run:
        lines.append(f"RUN: {run}")
    if manual:
        lines.append(f"MANUAL: {manual}")
    return "\n".join(lines)


def _session(responses, tmp):
    ex = Executor(Gate(load_scope(SCOPE)), FakeKali(), AuditLog(Path(tmp) / "a.jsonl"))
    return AssistSession(IN, ex, StrategistAgent(_SeqLLM(responses)))


# -- kill switch -------------------------------------------------------------

def test_killswitch_trips_once_and_keeps_first_reason():
    k = KillSwitch()
    assert not k.tripped
    k.trip("first"); k.trip("second")
    assert k.tripped and k.reason == "first"


def test_loop_aborts_when_kill_switch_tripped_before_run():
    tmp = tempfile.mkdtemp()
    sess = _session(["1. [recon] scan", _adv("scan", run=f"nmap -sV {IN}")], tmp)
    sess.make_plan()
    kill = KillSwitch(); kill.trip("stop now")
    result = GroundedLoop(sess, kill=kill).run()
    assert result.stop_reason == "aborted" and "stop now" in result.stop_detail
    assert result.executed == 0                     # nothing ran after the stop


def test_loop_aborts_mid_run_and_stops_activity():
    tmp = tempfile.mkdtemp()
    sess = _session(["1. [recon] scan", _adv("scan", run=f"nmap -sV {IN}")], tmp)
    sess.make_plan()
    kill = KillSwitch()

    def observer(kind, payload):
        if kind == "step":                          # trip right after the first real step
            kill.trip("mid-run stop")

    result = GroundedLoop(sess, kill=kill, observer=observer, max_steps=20).run()
    assert result.stop_reason == "aborted"
    assert result.executed == 1                     # exactly the one step before the trip


# -- budget caps -------------------------------------------------------------

def test_budget_exceeded_arithmetic():
    b = EngagementBudget(max_cost=1.0, max_steps=5, max_research_fetches=3).start()
    assert b.exceeded(cost=0.5, steps=2, fetches=1) is None
    assert "spend" in b.exceeded(cost=1.5, steps=0)
    assert "step cap" in b.exceeded(steps=5)
    assert "research" in b.exceeded(fetches=3)
    # a None dimension is simply not checked (local model -> no cost cap fires)
    assert b.exceeded(cost=None, steps=1, fetches=0) is None


def test_budget_wall_clock_cap_fires():
    b = EngagementBudget(max_wall_seconds=0).start()
    assert "time cap" in b.exceeded()               # elapsed >= 0 immediately


def test_loop_hands_back_on_step_budget():
    tmp = tempfile.mkdtemp()
    sess = _session(["1. [recon] scan", _adv("scan", run=f"nmap -sV {IN}")], tmp)
    sess.make_plan()
    budget = EngagementBudget(max_steps=1).start()
    result = GroundedLoop(sess, budget=budget, max_steps=20).run()
    assert result.stop_reason == "budget" and "step cap" in result.stop_detail
    assert result.executed == 1                     # ran one, then the cap stopped it


# -- resumable checkpoints ---------------------------------------------------

def test_checkpoint_round_trip_and_restore():
    tmp = tempfile.mkdtemp()
    sess = _session(["x"], tmp)
    sess.executed_cmds.extend([f"nmap -sV {IN}", f"whatweb http://{IN}/"])
    sess._learned.update({"vsftpd 2.3.4"})
    sess.add_objective("get user.txt")
    path = Path(tmp) / "checkpoint.json"
    checkpoint.save(path, sess, steps_done=4)
    data = checkpoint.load(path)
    assert data["target"] == IN and data["steps_done"] == 4
    assert f"nmap -sV {IN}" in data["executed_cmds"] and "vsftpd 2.3.4" in data["learned"]

    fresh = _session(["x"], tmp)                     # a brand-new run on the same target
    done = checkpoint.restore(fresh, data)
    assert done == 4
    assert f"nmap -sV {IN}" in fresh.executed_cmds   # won't re-run what it already ran
    assert "vsftpd 2.3.4" in fresh._learned
    assert "get user.txt" in fresh.objectives

    other = _session(["x"], tmp); other.target = "10.10.10.9"
    assert checkpoint.restore(other, data) == 0      # target mismatch -> ignored


def test_loop_writes_a_checkpoint_each_turn():
    tmp = tempfile.mkdtemp()
    sess = _session([
        "1. [recon] scan",
        _adv("scan", run=f"nmap -sV {IN}"),
        _adv("done", manual="hand off"),
    ], tmp)
    sess.make_plan()
    path = Path(tmp) / "checkpoint.json"
    GroundedLoop(sess, on_checkpoint=lambda n, why: checkpoint.save(
        path, sess, steps_done=n, stop_reason=why)).run()
    data = checkpoint.load(path)
    assert data is not None and any("nmap" in c for c in data["executed_cmds"])


# -- safe parallel enumeration ----------------------------------------------

def test_parallel_run_fans_out_and_skips_out_of_scope():
    tmp = tempfile.mkdtemp()
    ex = Executor(Gate(load_scope(SCOPE)), FakeKali(), AuditLog(Path(tmp) / "a.jsonl"))
    sess = AssistSession(IN, ex, StrategistAgent(_SeqLLM(["x"])))
    results = sess.parallel_run([
        f"nmap -sV {IN}",
        f"whatweb http://{IN}/",
        "curl http://evil.com/x",                    # out of scope
    ])
    by_cmd = {c: (d, r) for c, d, r, _ in results}
    assert by_cmd[f"nmap -sV {IN}"][1] is not None   # in-scope ran
    assert by_cmd[f"whatweb http://{IN}/"][1] is not None
    d, r = by_cmd["curl http://evil.com/x"]
    assert d.verdict == "DENY" and r is None          # out-of-scope skipped, never ran
    # the concurrent runs left the hash-chained audit intact
    assert AuditLog(Path(tmp) / "a.jsonl").verify()
