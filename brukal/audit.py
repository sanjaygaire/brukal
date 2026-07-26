"""
audit.py — the tamper-evident audit log and evidence spine.

Every decision and every execution result is appended here, never edited. The
records are chained: each entry stores the hash of the previous entry, so altering
or removing any past record breaks the chain and is detectable by verify(). This
turns "trust me, it scored X" into "here is the verifiable receipt for every
action" — the property the paper leans on for reproducibility.

Two chaining modes:

  * Default — an UNKEYED SHA-256 chain. This is *tamper-evident*, NOT immutable:
    anyone who can write the file can recompute the whole chain after an edit and
    still pass verify(). It detects accidental corruption and naive tampering, and
    is the right default for a local lab log.
  * Keyed (set env var BRUKAL_AUDIT_KEY) — an HMAC-SHA-256 chain. Now an edit can
    only be re-chained by someone who also holds the key, so tampering by an actor
    with mere file-write access is detectable. Use this for engagements where the
    log is evidence (e.g. bug-bounty reproducibility). verify() must run with the
    same key that wrote the log.

Stored as JSONL (one JSON object per line) so it is easy to grep, load into pandas
for results tables, and diff.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path

_GENESIS = "0" * 64  # the hash that precedes the very first record


def _chain(prev_hash: str, payload: str, key: str | None = None) -> str:
    """One link of the chain. Unkeyed SHA-256 by default; HMAC-SHA-256 when a key is
    supplied, so an edit can't be silently re-chained without the key."""
    msg = (prev_hash + payload).encode("utf-8")
    if key:
        return hmac.new(key.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return hashlib.sha256(msg).hexdigest()


# Back-compat alias for the unkeyed form (some callers/tests import _hash).
def _hash(prev_hash: str, payload: str) -> str:
    return _chain(prev_hash, payload, None)


class AuditLog:
    """Append-only, hash-chained log backed by a JSONL file."""

    def __init__(self, path: str | Path, key: str | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Chain key: explicit arg wins, else BRUKAL_AUDIT_KEY, else None (unkeyed).
        # Read once at construction so append() and verify() use the same key.
        self._key = key if key is not None else os.environ.get("BRUKAL_AUDIT_KEY") or None
        self._last_hash = self._recover_last_hash()
        self.keyed = self._key is not None   # True = HMAC (tamper-proof), False = unkeyed
        # The hash chain is inherently sequential: read prev -> compute -> write ->
        # update must be ONE atomic step, or two concurrent agents chain onto the
        # same prev_hash and corrupt the chain. This lock is what makes the audit
        # log safe under the parallel orchestrator (invariant 5 holds concurrently).
        self._lock = threading.Lock()

    def _recover_last_hash(self) -> str:
        """On startup, read the last line so new records chain onto it."""
        if not self.path.exists():
            return _GENESIS
        last = _GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)["entry_hash"]
        return last

    def append(self, kind: str, data) -> str:
        """Append one record. `data` may be a dataclass (e.g. Decision) or dict.

        Returns the new entry hash.
        """
        if is_dataclass(data):
            data = asdict(data)
        with self._lock:
            record = {
                "ts": time.time(),
                "kind": kind,          # "decision" | "execution" | "note"
                "data": data,
                "prev_hash": self._last_hash,
            }
            payload = json.dumps(record, sort_keys=True, separators=(",", ":"))
            record["entry_hash"] = _chain(self._last_hash, payload, self._key)

            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, separators=(",", ":")) + "\n")

            self._last_hash = record["entry_hash"]
            return self._last_hash

    def verify(self) -> bool:
        """Re-walk the file and confirm the hash chain is intact.

        Returns True if no record has been altered or removed.
        """
        prev = _GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                stored = record.pop("entry_hash")
                if record["prev_hash"] != prev:
                    return False
                payload = json.dumps(record, sort_keys=True, separators=(",", ":"))
                if _chain(prev, payload, self._key) != stored:
                    return False
                prev = stored
        return True
