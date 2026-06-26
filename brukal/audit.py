"""
audit.py — the immutable audit log and evidence spine.

Every decision and every execution result is appended here, never edited.
To make "immutable" mean something we chain the records with hashes: each
entry stores the SHA-256 of the previous entry, so altering any past record
breaks the chain and is detectable. This is what turns "trust me, it scored
X" into "here is the verifiable receipt for every action" — the property your
paper leans on for reproducibility.

Stored as JSONL (one JSON object per line) so it is easy to grep, load into
pandas for your results tables, and diff.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path

_GENESIS = "0" * 64  # the hash that precedes the very first record


def _hash(prev_hash: str, payload: str) -> str:
    return hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only, hash-chained log backed by a JSONL file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._recover_last_hash()

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
        record = {
            "ts": time.time(),
            "kind": kind,          # "decision" | "execution" | "note"
            "data": data,
            "prev_hash": self._last_hash,
        }
        payload = json.dumps(record, sort_keys=True, separators=(",", ":"))
        record["entry_hash"] = _hash(self._last_hash, payload)

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
                if _hash(prev, payload) != stored:
                    return False
                prev = stored
        return True
