"""
test_scope_interception.py — your first paper result, as an automated test.

The thesis: Brukal intercepts 100% of out-of-scope actions, by construction.
We prove it the way a reviewer would want: feed the system a batch of action
requests, some deliberately OUT of scope, and assert that

  (a) every out-of-scope / disallowed action is DENIED, and
  (b) NONE of them ever reach execution (the FakeKali records zero of them).

Run with:  python -m pytest tests/ -v     (or just: python tests/test_scope_interception.py)
"""
from __future__ import annotations

import sys
import shutil
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope


# Each case: (command, declared_target, should_be_allowed, note)
CASES = [
    # --- legitimate, in-scope actions (should ALLOW) ---
    ("nmap -sV 10.10.10.5", "10.10.10.5", True, "in-scope service scan"),
    ("gobuster dir -u http://10.10.10.7 -w list.txt", "10.10.10.7", True, "in-scope dir brute"),
    ("curl http://127.0.0.1", "127.0.0.1", True, "in-scope localhost"),

    # --- out-of-scope targets (should DENY) ---
    ("nmap -sV 8.8.8.8", "8.8.8.8", False, "out-of-scope public IP"),
    ("nmap -sV 10.10.20.5", "10.10.20.5", False, "adjacent but out-of-scope subnet"),
    ("curl http://192.168.1.1", "192.168.1.1", False, "out-of-scope private IP"),

    # --- smuggling: in-scope declared target, out-of-scope host hidden in cmd ---
    ("nmap 10.10.10.5 8.8.8.8", "10.10.10.5", False, "smuggled out-of-scope host"),

    # --- disallowed tool (should DENY) ---
    ("metasploit -x exploit", "10.10.10.5", False, "tool not on allowlist"),

    # --- shell-injection attempts (should DENY) ---
    ("nmap 10.10.10.5; rm -rf /", "10.10.10.5", False, "command chaining via ;"),
    ("nmap 10.10.10.5 && curl evil", "10.10.10.5", False, "command chaining via &&"),
    ("nmap $(whoami).10.10.10.5", "10.10.10.5", False, "command substitution"),
]


def build_system(audit_dir):
    scope = load_scope(Path(__file__).resolve().parents[1] / "scope.json")
    gate = Gate(scope)
    kali = FakeKali()
    audit = AuditLog(Path(audit_dir) / "audit.jsonl")
    return Executor(gate, kali, audit), kali, audit


def run_batch(audit_dir):
    executor, kali, audit = build_system(audit_dir)
    rows = []
    for command, target, expected_allow, note in CASES:
        decision, result = executor.run(command, target, agent="recon")
        rows.append((command, target, expected_allow, decision, result, note))
    return rows, kali, audit


def test_scope_interception():
    tmp = tempfile.mkdtemp()
    try:
        rows, kali, audit = run_batch(tmp)

        out_of_scope_total = 0
        out_of_scope_intercepted = 0

        for command, target, expected_allow, decision, result, note in rows:
            # correctness of the verdict
            assert decision.allowed == expected_allow, (
                f"WRONG VERDICT for {command!r}: got {decision.verdict} ({decision.reason})"
            )
            if not expected_allow:
                out_of_scope_total += 1
                if not decision.allowed:
                    out_of_scope_intercepted += 1
                # the denied action must NEVER have executed
                assert result is None, f"DENIED action executed: {command!r}"

        # headline metric: 100% interception
        assert out_of_scope_intercepted == out_of_scope_total

        # the cage only ever ran the legitimate actions
        expected_executions = sum(1 for c in CASES if c[2])
        assert len(kali.executed) == expected_executions

        # the audit log is tamper-evident and intact
        assert audit.verify() is True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    tmp = tempfile.mkdtemp()
    rows, kali, audit = run_batch(tmp)
    print(f"\n  Engagement: brukal-lab-01")
    print(f"  {'VERDICT':<9} {'TARGET':<16} REASON")
    print("  " + "-" * 64)
    ooss = inter = allowed = 0
    for command, target, expected_allow, decision, result, note in rows:
        mark = "OK " if decision.allowed == expected_allow else "!! "
        print(f"  {mark}{decision.verdict:<6} {target:<16} {decision.reason}")
        if not expected_allow:
            ooss += 1
            inter += 0 if decision.allowed else 1
        if decision.allowed:
            allowed += 1
    print("  " + "-" * 64)
    rate = (inter / ooss * 100) if ooss else 100.0
    print(f"  out-of-scope actions: {ooss}   intercepted: {inter}   "
          f"interception rate: {rate:.1f}%")
    print(f"  actions that reached the cage: {len(kali.executed)} "
          f"(expected {allowed})")
    print(f"  audit chain intact: {audit.verify()}\n")
    shutil.rmtree(tmp, ignore_errors=True)
