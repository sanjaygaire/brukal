"""
test_authorization.py — authorization as a first-class artifact (Phase 5).

A scope file may assert authorisation (`authorization`: who signed off / a ticket
or SOW reference) and carry an `expires` date. At run start Brukal pins the
authorising scope into the audit chain by content fingerprint and refuses a stale
engagement — fail-closed: a set-but-unparseable expiry counts as expired. None of
this needs Docker, a model, or a network.
"""
from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.audit import AuditLog
from brukal.engagement import enforce_authorization
from brukal.scope import Scope, authorization_record, load_scope


def _write_scope(tmp, **extra) -> str:
    data = {
        "engagement": "test-eng",
        "authorized_cidrs": ["10.10.10.5/32"],
        "allowlisted_tools": ["nmap"],
        "rate_limit_per_min": 30,
    }
    data.update(extra)
    p = tmp / "scope.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


# --- load_scope reads the new fields ---------------------------------------

def test_load_scope_reads_authorization_and_expires(tmp_path):
    path = _write_scope(tmp_path, authorization="SOW-42, signed by J. Doe",
                        expires="2099-01-01")
    scope = load_scope(path)
    assert scope.authorization == "SOW-42, signed by J. Doe"
    assert scope.expires == "2099-01-01"
    assert scope.is_authorized() is True


def test_load_scope_defaults_when_fields_absent(tmp_path):
    scope = load_scope(_write_scope(tmp_path))
    assert scope.authorization == ""
    assert scope.expires == ""
    assert scope.is_authorized() is False
    assert scope.is_expired() is False          # unset expiry never expires


# --- is_expired: fail-closed on an unreadable window -----------------------

def test_expiry_states(tmp_path):
    today = datetime.date(2026, 7, 26)
    future = Scope("e", (), frozenset({"*"}), 30, expires="2999-12-31")
    past = Scope("e", (), frozenset({"*"}), 30, expires="2000-01-01")
    garbage = Scope("e", (), frozenset({"*"}), 30, expires="not-a-date")
    unset = Scope("e", (), frozenset({"*"}), 30)
    assert future.is_expired(today) is False
    assert past.is_expired(today) is True
    assert garbage.is_expired(today) is True    # fail-closed: unreadable = expired
    assert unset.is_expired(today) is False
    # ISO datetime is accepted (date portion used)
    assert Scope("e", (), frozenset(), 30, expires="2999-01-01T09:00:00").is_expired(today) is False


# --- fingerprint pins the authorised set -----------------------------------

def test_fingerprint_is_stable_and_moves_with_the_scope(tmp_path):
    a = load_scope(_write_scope(tmp_path, authorization="ticket-1"))
    b = load_scope(_write_scope(tmp_path, authorization="ticket-1"))
    assert a.fingerprint() == b.fingerprint()   # same content -> same fingerprint
    c = load_scope(_write_scope(tmp_path, authorization="ticket-2"))
    assert a.fingerprint() != c.fingerprint()   # a scope swap is visible


# --- scope-time host authorisation carries the fields ----------------------

def test_with_host_preserves_authorization_and_expiry(tmp_path):
    scope = load_scope(_write_scope(tmp_path, authorization="SOW-9",
                                    expires="2000-01-01"))
    widened = scope.with_host("nexus.htb")
    # A scope-time host add must NOT drop (and thereby reset) the auth window.
    assert widened.authorization == "SOW-9"
    assert widened.expires == "2000-01-01"
    assert widened.is_expired(datetime.date(2026, 7, 26)) is True


# --- authorization_record shape --------------------------------------------

def test_authorization_record_shape(tmp_path):
    scope = load_scope(_write_scope(tmp_path, authorization="SOW-42",
                                    expires="2099-01-01"))
    rec = authorization_record(scope, "10.10.10.5")
    assert rec["engagement"] == "test-eng"
    assert rec["target"] == "10.10.10.5"
    assert rec["authorization"] == "SOW-42"
    assert rec["authorized"] is True
    assert rec["expired"] is False
    assert rec["scope_fingerprint"] == scope.fingerprint()
    # must be JSON-serialisable for the ledger
    json.dumps(rec)


# --- enforce_authorization: records always, refuses when stale -------------

def _last_record(audit_path):
    lines = [l for l in Path(audit_path).read_text(encoding="utf-8").splitlines() if l.strip()]
    return json.loads(lines[-1])


def test_enforce_records_and_allows_valid_scope(tmp_path):
    scope = load_scope(_write_scope(tmp_path, authorization="SOW-42",
                                    expires="2999-01-01"))
    audit = AuditLog(tmp_path / "audit.jsonl")
    ok = enforce_authorization(scope, audit, "10.10.10.5")
    assert ok is True
    rec = _last_record(tmp_path / "audit.jsonl")
    assert rec["kind"] == "authorization"
    assert rec["data"]["target"] == "10.10.10.5"
    assert audit.verify() is True


def test_enforce_refuses_stale_scope_but_still_records_a_receipt(tmp_path, capsys):
    scope = load_scope(_write_scope(tmp_path, authorization="SOW-42",
                                    expires="2000-01-01"))
    audit = AuditLog(tmp_path / "audit.jsonl")
    ok = enforce_authorization(scope, audit, "10.10.10.5")
    assert ok is False                                  # refused: stale
    assert "expired" in capsys.readouterr().out.lower()
    rec = _last_record(tmp_path / "audit.jsonl")         # receipt written anyway
    assert rec["kind"] == "authorization"
    assert rec["data"]["expired"] is True


def test_enforce_refuses_unparseable_expiry(tmp_path):
    scope = load_scope(_write_scope(tmp_path, expires="soon"))
    audit = AuditLog(tmp_path / "audit.jsonl")
    assert enforce_authorization(scope, audit, "10.10.10.5") is False


# --- integration: a live-run entry point refuses a stale scope early -------

def test_engagement_run_refuses_expired_scope(tmp_path):
    from brukal import engagement
    path = _write_scope(tmp_path, expires="2000-01-01")
    rc = engagement.run("10.10.10.5", fake=True, scope_path=path,
                        audit_path=str(tmp_path / "audit.jsonl"),
                        vault_path=str(tmp_path / "vault"))
    assert rc == 2                                       # refused before any run
    rec = _last_record(tmp_path / "audit.jsonl")
    assert rec["kind"] == "authorization" and rec["data"]["expired"] is True
