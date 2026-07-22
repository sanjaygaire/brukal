"""
findings.py — the structured vulnerability findings model (stdlib-only).

A "finding" is a single, deduplicated, severity-ranked vulnerability observation,
carrying the REAL evidence and the exact command that produced it. This is what
turns "Brukal ran some tools" into "here is the audited report an engineer can act
on."

Two design choices carry the trust story over from the rest of the system:

  * Every finding is EVIDENCE-BACKED. It is built only from real, gate-executed
    output (webprobe.scan_output over a command's stdout, or a Verifier-confirmed
    success) — never from model prose. There is no path to record a finding that no
    command actually produced.
  * Findings are two-tier, exactly like lessons: a heuristic signal is a `candidate`
    (confirmed=False), and only an explicit, unambiguous signal (sqlmap "is
    vulnerable", a Verifier-confirmed foothold/flag) is `confirmed`. The report shows
    both, clearly separated, so a reviewer is never handed a false positive dressed
    as a fact.

The store is an append-only JSONL ledger (mirroring the audit/lessons pattern): each
add() appends the raw event, and load() merges events per signature, keeping the
strongest severity and OR-ing confirmation. Nothing is ever rewritten in place.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

_FIELDS = ("title", "severity", "target", "evidence", "source", "param",
           "category", "confirmed", "ts")


def _norm(s: str) -> str:
    return " ".join((s or "").split()).lower()


@dataclass
class Finding:
    title: str                              # e.g. "SQL injection", "known CVE"
    severity: str = "info"                  # one of SEVERITIES
    target: str = ""                        # url / endpoint / host
    evidence: str = ""                      # the real output line that flagged it
    source: str = ""                        # the command that produced the evidence
    param: str = ""                         # the parameter / field under test, if any
    category: str = "web"
    confirmed: bool = False                 # explicit signal / Verifier-backed vs heuristic
    ts: float = field(default_factory=time.time)

    def __post_init__(self):
        if self.severity not in _SEV_ORDER:
            self.severity = "info"

    @property
    def signature(self) -> tuple:
        """Dedup key: same vuln class + endpoint + parameter is the same finding,
        however many times a probe re-reports it."""
        return (_norm(self.title), _norm(self.target), _norm(self.param))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(**{k: d[k] for k in _FIELDS if k in d})


class FindingStore:
    """Deduplicated, severity-ranked collection of findings, optionally persisted to
    an append-only JSONL ledger in the engagement vault."""

    def __init__(self, path=None):
        self.path = Path(path) if path else None
        self._by_sig: dict[tuple, Finding] = {}
        if self.path is not None and self.path.exists():
            self._load()

    def _absorb(self, f: Finding) -> bool:
        """Merge a finding into the map. Returns True if it was a NEW signature."""
        cur = self._by_sig.get(f.signature)
        if cur is None:
            self._by_sig[f.signature] = f
            return True
        if _SEV_ORDER[f.severity] < _SEV_ORDER[cur.severity]:
            cur.severity = f.severity                 # keep the strongest severity
        cur.confirmed = cur.confirmed or f.confirmed  # confirmation only ever grows
        if len(f.evidence) > len(cur.evidence):
            cur.evidence = f.evidence                 # keep the richest evidence
        cur.ts = min(cur.ts, f.ts)                    # first-seen time
        return False

    def add(self, finding: Finding) -> bool:
        is_new = self._absorb(finding)
        self._persist(finding)                        # append-only: record the raw event
        return is_new

    def all(self) -> list[Finding]:
        """Findings ranked by severity, confirmed before candidate, then first-seen."""
        return sorted(self._by_sig.values(),
                      key=lambda f: (_SEV_ORDER[f.severity], not f.confirmed, f.ts))

    def confirmed(self) -> list[Finding]:
        return [f for f in self.all() if f.confirmed]

    def candidates(self) -> list[Finding]:
        return [f for f in self.all() if not f.confirmed]

    def counts(self) -> dict:
        c = {s: 0 for s in SEVERITIES}
        for f in self._by_sig.values():
            c[f.severity] += 1
        return c

    def __len__(self) -> int:
        return len(self._by_sig)

    def _persist(self, f: Finding) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(f.to_dict()) + "\n")
        except OSError:
            pass                                      # persistence is best-effort

    def _load(self) -> None:
        try:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    self._absorb(Finding.from_dict(json.loads(line)))
                except (ValueError, TypeError):
                    continue                          # skip a corrupt line, keep loading
        except OSError:
            pass
