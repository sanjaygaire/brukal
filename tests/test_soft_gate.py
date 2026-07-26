"""
test_soft_gate.py — milestone 3: the soft risk layer + human-approval escalation.

Two layers of proof:

  1. `assess()` in isolation — deterministic reversibility / blast-radius /
     ALLOW-ESCALATE-DENY, plus the milestone-6 trust hook.
  2. The layer wired through the Executor — that ESCALATE consults the human
     approver and runs only if approved, that a soft DENY never runs, and — the
     load-bearing property — that the soft layer and approval can only ever
     *tighten*: a hard DENY (out of scope) can NEVER be approved back into
     execution.

Needs pydantic? No — the soft layer is standard-library only, like the core.

Run:  python -m pytest tests/test_soft_gate.py -v
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, assess, load_scope

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"


# --------------------------------------------------------------------------- #
# 1. assess() in isolation — the deterministic risk function
# --------------------------------------------------------------------------- #

# (command, reversibility, blast_radius, decision)
RISK_CASES = [
    # reversible single-host recon -> the everyday ALLOW
    ("nmap -sV 10.10.10.5",                 "reversible",   "host",   "ALLOW"),
    ("gobuster dir -u http://10.10.10.7 -w list.txt", "reversible", "host", "ALLOW"),
    ("curl http://127.0.0.1",               "reversible",   "host",   "ALLOW"),
    # reversible but broad -> escalate for a human to confirm the breadth
    ("nmap 10.10.10.0/26",                  "reversible",   "subnet", "ESCALATE"),
    ("nmap 10.10.10.5 10.10.10.6",          "reversible",   "subnet", "ESCALATE"),
    ("nmap -p- 10.10.10.5",                 "reversible",   "subnet", "ESCALATE"),
    ("nmap 10.10.10.0/24",                  "reversible",   "wide",   "ESCALATE"),
    # irreversible but small -> escalate
    ("curl -X POST --data x http://10.10.10.5", "irreversible", "host", "ESCALATE"),
    # irreversible AND broad -> over the ceiling, deny
    ("nmap --script exploit 10.10.10.0/24", "irreversible", "wide",   "DENY"),
    ("curl -X PUT --data y http://10.10.10.5 http://10.10.10.6", "irreversible", "subnet", "DENY"),
]


def test_assess_is_deterministic_and_correct():
    for command, rev, blast, decision in RISK_CASES:
        p = assess(command)
        assert p.reversibility == rev, f"{command!r}: reversibility {p.reversibility}!={rev}"
        assert p.blast_radius == blast, f"{command!r}: blast {p.blast_radius}!={blast}"
        assert p.decision == decision, f"{command!r}: decision {p.decision}!={decision} ({p.reason})"
        # determinism: same input -> identical profile
        assert assess(command) == p


def test_trust_hook_raises_caution_when_distrusted():
    # A milestone-6 seam: at full trust an everyday recon is ALLOWed; at zero
    # trust the SAME command is pushed up into ESCALATE. The soft layer only
    # ever tightens with lower trust — it never loosens.
    cmd = "nmap -sV 10.10.10.5"
    assert assess(cmd, trust=1.0).decision == "ALLOW"
    assert assess(cmd, trust=0.0).decision == "ESCALATE"
    assert assess(cmd, trust=0.0).score > assess(cmd, trust=1.0).score


# --------------------------------------------------------------------------- #
# 2. the soft layer wired through the Executor
# --------------------------------------------------------------------------- #

class RecordingApprover:
    """A human-approval stand-in that records calls and returns a fixed verdict."""
    def __init__(self, verdict: bool):
        self.verdict = verdict
        self.calls = []

    def __call__(self, decision):
        self.calls.append(decision)
        return self.verdict


def _build(approver=None):
    tmp = tempfile.mkdtemp()
    kali = FakeKali()
    audit = AuditLog(Path(tmp) / "audit.jsonl")
    executor = Executor(Gate(load_scope(SCOPE)), kali, audit, approver=approver)
    return executor, kali, audit, tmp


def test_allow_recon_still_runs():
    executor, kali, audit, tmp = _build()
    try:
        decision, result = executor.run("nmap -sV 10.10.10.5", "10.10.10.5", agent="recon")
        assert decision.verdict == "ALLOW"
        assert decision.layer == "soft:allow"
        assert decision.risk_band == "LOW"
        assert result is not None
        assert kali.executed == ["nmap -sV 10.10.10.5"]
        assert audit.verify() is True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_escalate_declined_does_not_run():
    approver = RecordingApprover(False)
    executor, kali, audit, tmp = _build(approver)
    try:
        decision, result = executor.run("nmap 10.10.10.5 10.10.10.6", "10.10.10.5", agent="recon")
        assert decision.verdict == "ESCALATE"
        assert decision.layer == "soft:escalate"
        assert len(approver.calls) == 1          # the human WAS consulted
        assert result is None                    # ...and declined -> no run
        assert kali.executed == []
        assert audit.verify() is True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_escalate_approved_runs():
    approver = RecordingApprover(True)
    executor, kali, audit, tmp = _build(approver)
    try:
        decision, result = executor.run("nmap 10.10.10.5 10.10.10.6", "10.10.10.5", agent="recon")
        assert decision.verdict == "ESCALATE"
        assert len(approver.calls) == 1
        assert result is not None                # approved -> executed
        assert kali.executed == ["nmap 10.10.10.5 10.10.10.6"]
        assert audit.verify() is True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_default_approver_is_fail_closed():
    # No approver wired at all: an ESCALATE must NOT run (fail-closed default).
    executor, kali, audit, tmp = _build(approver=None)
    try:
        decision, result = executor.run("nmap 10.10.10.5 10.10.10.6", "10.10.10.5", agent="recon")
        assert decision.verdict == "ESCALATE"
        assert result is None
        assert kali.executed == []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_soft_deny_never_runs_and_never_asks_human():
    approver = RecordingApprover(True)   # would approve anything, if asked
    executor, kali, audit, tmp = _build(approver)
    try:
        decision, result = executor.run(
            "nmap --script exploit 10.10.10.0/24", "10.10.10.5", agent="recon")
        assert decision.verdict == "DENY"
        assert decision.layer == "soft:deny"
        assert decision.risk_band == "HIGH"
        assert result is None
        assert kali.executed == []
        assert approver.calls == []          # a DENY is not negotiable
        assert audit.verify() is True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_hard_deny_cannot_be_approved_back_into_execution():
    # The load-bearing invariant: even an approve-EVERYTHING human cannot turn an
    # out-of-scope (hard) DENY into a run. The soft layer / approval sit ABOVE the
    # hard gate and can only tighten; a hard DENY returns before they are reached.
    approver = RecordingApprover(True)
    executor, kali, audit, tmp = _build(approver)
    try:
        decision, result = executor.run("nmap -sV 8.8.8.8", "8.8.8.8", agent="recon")
        assert decision.verdict == "DENY"
        assert decision.layer == "hard:scope"    # died at the hard gate
        assert result is None
        assert kali.executed == []
        assert approver.calls == []              # human was NEVER consulted
        assert audit.verify() is True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
