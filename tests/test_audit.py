"""
test_audit.py — the hash-chained evidence log, default (unkeyed) and HMAC modes.

The default chain is tamper-EVIDENT (an unkeyed SHA-256 chain): naive edits are
caught, but anyone with file-write access can recompute the whole chain. The HMAC
mode (BRUKAL_AUDIT_KEY) closes that: an edit can't be re-chained without the key.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from brukal.audit import AuditLog, _chain


def _seed(path, key=None):
    log = AuditLog(path, key=key)
    log.append("decision", {"cmd": "nmap 10.10.10.5", "verdict": "ALLOW"})
    log.append("execution", {"stdout": "22/tcp open"})
    log.append("note", {"text": "found ssh"})
    return log


def test_unkeyed_chain_verifies_and_detects_naive_tamper():
    tmp = Path(tempfile.mkdtemp()) / "a.jsonl"
    _seed(tmp)
    assert AuditLog(tmp).verify() is True

    # Tamper with a record's data but leave entry_hash as-is -> chain breaks.
    lines = tmp.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["data"]["stdout"] = "ROOT SHELL (forged)"
    lines[1] = json.dumps(rec, separators=(",", ":"))
    tmp.write_text("\n".join(lines) + "\n")
    assert AuditLog(tmp).verify() is False


def test_hmac_mode_verifies_with_same_key():
    tmp = Path(tempfile.mkdtemp()) / "a.jsonl"
    _seed(tmp, key="s3cret")
    assert AuditLog(tmp, key="s3cret").verify() is True


def test_hmac_detects_tamper_even_with_full_rechain():
    # The point of HMAC: an attacker with file WRITE access edits a record AND
    # recomputes the entire chain (as they could trivially defeat the unkeyed mode) —
    # but without the key they can only recompute the UNKEYED hash, so keyed verify
    # still catches it.
    tmp = Path(tempfile.mkdtemp()) / "a.jsonl"
    _seed(tmp, key="s3cret")

    lines = [json.loads(x) for x in tmp.read_text().splitlines() if x.strip()]
    lines[0]["data"]["verdict"] = "DENY-erased"          # forge the first record
    prev = "0" * 64
    for rec in lines:                                     # re-chain WITHOUT the key
        rec.pop("entry_hash")
        rec["prev_hash"] = prev
        payload = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        rec["entry_hash"] = _chain(prev, payload, None)  # attacker has no key
        prev = rec["entry_hash"]
    tmp.write_text("\n".join(json.dumps(r, separators=(",", ":")) for r in lines) + "\n")

    assert AuditLog(tmp, key="s3cret").verify() is False   # forgery detected
    # And a wrong/absent key also fails to verify a keyed log.
    assert AuditLog(tmp, key="wrong").verify() is False


def test_default_behaviour_unchanged_without_key():
    # No key anywhere -> plain SHA-256 chain, exactly as before this change.
    tmp = Path(tempfile.mkdtemp()) / "a.jsonl"
    log = _seed(tmp)
    assert log.verify() is True
    assert log._key is None
