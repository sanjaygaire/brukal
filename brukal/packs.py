"""
packs.py — signature packs: detections contributed as DATA, never as code.

A researcher who finds a new pattern, or an organisation with an internal service whose
error strings nobody else would recognise, should be able to teach Brukal without
forking it. That is what a pack is: a JSON file of named patterns.

The design constraint is the interesting part. A plugin system that loads Python would
hand arbitrary code the same process as the gate — and the whole safety argument rests
on agents being unable to reach the cage except through `Executor.run`. So a pack cannot
execute, cannot request, and cannot widen scope. It can only say "this text means this
finding". The worst a hostile pack can do is describe a finding badly, which a human
reads in a report; it can never cause an action against a target.

Pack format (JSON, one object):

    {
      "name": "acme-internal",
      "description": "error strings from Acme's internal services",
      "signatures": [
        {"pattern": "AcmeAuthError: token rejected",
         "severity": "medium",
         "title": "Acme auth service error disclosed",
         "category": "web",
         "confirmed": false}
      ]
    }

`pattern` is a regular expression matched against tool or response text. Everything else
is metadata. Patterns are compiled defensively and a broken one disables that signature
alone, never the pack and never the run.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
# A pack pattern runs against untrusted target output, so a pathological regex is a
# denial-of-service against ourselves. Length is a crude but effective guard, and
# catastrophic backtracking needs a nested quantifier to get going.
_MAX_PATTERN = 400
_NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*]\)[+*]")


class Signature:
    """One contributed detection: a compiled pattern plus how to report a hit."""

    __slots__ = ("rx", "severity", "title", "category", "confirmed", "pack")

    def __init__(self, rx, severity, title, category, confirmed, pack):
        self.rx, self.severity, self.title = rx, severity, title
        self.category, self.confirmed, self.pack = category, confirmed, pack


def _compile(entry: dict, pack_name: str):
    """One signature, or None if it is malformed. Fail-closed per signature: a bad entry
    is skipped rather than allowed to take down the pack."""
    if not isinstance(entry, dict):
        return None
    pattern = entry.get("pattern")
    title = entry.get("title")
    if not isinstance(pattern, str) or not isinstance(title, str):
        return None
    if not pattern.strip() or not title.strip() or len(pattern) > _MAX_PATTERN:
        return None
    if _NESTED_QUANTIFIER.search(pattern):
        return None                       # catastrophic-backtracking shape: refuse it
    try:
        rx = re.compile(pattern, re.I)
    except re.error:
        return None
    severity = entry.get("severity", "info")
    if severity not in _VALID_SEVERITIES:
        severity = "info"
    category = entry.get("category", "web")
    if not isinstance(category, str) or not category.strip():
        category = "web"
    # A pack may NOT self-declare a finding as confirmed. Confirmation in Brukal means a
    # deterministic proof was executed and observed; a pattern match is a signal, and
    # letting contributed data claim otherwise would corrupt the one distinction the
    # whole report rests on.
    return Signature(rx, severity, title.strip(), category.strip(), False, pack_name)


def load_pack(path) -> list[Signature]:
    """Signatures from one pack file. Never raises: an unreadable or malformed pack
    contributes nothing and the engagement continues."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(doc, dict):
        return []
    name = doc.get("name")
    name = name if isinstance(name, str) and name.strip() else Path(path).stem
    entries = doc.get("signatures")
    if not isinstance(entries, list):
        return []
    out = []
    for entry in entries[:500]:           # a pack is a contribution, not a corpus
        sig = _compile(entry, name.strip())
        if sig is not None:
            out.append(sig)
    return out


def load_dir(directory) -> list[Signature]:
    """Every *.json pack in a directory, sorted so loading is reproducible."""
    d = Path(directory)
    if not d.is_dir():
        return []
    sigs: list[Signature] = []
    for path in sorted(d.glob("*.json")):
        sigs.extend(load_pack(path))
    return sigs


def scan(text: str, signatures) -> list[tuple[str, str, str]]:
    """(severity, label, evidence) for each signature that matches.

    Same shape the built-in detectors return, so a contributed signature reaches the
    report through exactly the path a built-in one does — including deduplication and
    the soft-404 downgrade. One hit per signature: a pattern matching fifty times is one
    finding, not fifty."""
    hits: list[tuple[str, str, str]] = []
    if not text:
        return hits
    seen: set = set()
    for sig in signatures:
        if sig.title in seen:
            continue
        try:
            m = sig.rx.search(text)
        except Exception:
            continue                       # a pathological pattern must not end the run
        if not m:
            continue
        seen.add(sig.title)
        line = re.sub(r"\s+", " ", m.group(0) or "").strip()[:200]
        hits.append((sig.severity, f"{sig.title} [{sig.pack}]", line))
    return hits
