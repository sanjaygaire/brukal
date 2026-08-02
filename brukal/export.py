"""
export.py — hand Brukal's findings to whatever an organisation already runs.

A pentest tool that only prints for humans is a dead end in a real pipeline. Findings
here are already structured and evidence-backed, so the work is emitting them in formats
other systems ingest without anyone writing glue:

  * **SARIF 2.1.0** — the interchange format GitHub code scanning, GitLab, Azure DevOps,
    DefectDojo and most security dashboards already read. One file, no integration code.
  * **Stable JSON** — a documented, versioned envelope for anything bespoke: a
    researcher's notebook, a triage script, a data warehouse.

Both are pure functions of the finding store: no I/O, no network, nothing that can
change what an engagement did. Export can never alter a verdict.
"""
from __future__ import annotations

import json
import re
import time

from . import knowledge

SCHEMA_VERSION = "1.0"
TOOL_URI = "https://github.com/sanjaygaire/brukal"

# SARIF speaks error/warning/note; GitHub additionally reads security-severity (a CVSS
# number) to place a finding in its own severity bands.
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def rule_id(title: str) -> str:
    """A stable, readable rule id derived from the finding title.

    Stability matters more than beauty: dashboards deduplicate and track history by this
    id, so it must not drift when wording changes around it."""
    slug = re.sub(r"[^a-z0-9]+", "-", (title or "finding").lower()).strip("-")
    return f"brukal/{slug or 'finding'}"


def _fingerprint(f) -> str:
    """Identity of a finding ACROSS runs, so a dashboard shows one issue with a history
    rather than a new issue every scan. Deliberately excludes evidence and timestamps,
    which vary run to run for the same underlying flaw."""
    import hashlib
    key = "|".join(str(x).strip().lower() for x in
                   (getattr(f, "title", ""), getattr(f, "target", ""),
                    getattr(f, "param", "")))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def to_sarif(findings, meta: dict | None = None) -> dict:
    """SARIF 2.1.0 for a list of findings.

    Unconfirmed findings are emitted too, but marked: they carry a `confirmed: false`
    property and a message that says so, because a reviewer deciding what to action
    needs to know which results carry a deterministic proof and which are leads."""
    meta = meta or {}
    rules: dict = {}
    results = []
    for f in findings:
        rid = rule_id(getattr(f, "title", ""))
        title = getattr(f, "title", "") or "finding"
        severity = getattr(f, "severity", "info")
        kb = knowledge.enrich(title, severity)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": re.sub(r"[^A-Za-z0-9]", "", title.title())[:120] or "Finding",
                "shortDescription": {"text": title},
                "fullDescription": {"text": kb["impact"]},
                "help": {"text": f"{kb['impact']}\n\nRemediation: {kb['remediation']}",
                         "markdown": (f"**Impact.** {kb['impact']}\n\n"
                                      f"**Remediation.** {kb['remediation']}\n\n"
                                      f"**References.** {', '.join(kb['refs'])}")},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(severity, "note")},
                "properties": {
                    "tags": ["security", getattr(f, "category", "web"), *kb["refs"]],
                    "security-severity": str(kb["cvss"]),
                    "precision": "high" if getattr(f, "confirmed", False) else "medium",
                },
            }
        target = getattr(f, "target", "") or meta.get("target", "")
        confirmed = bool(getattr(f, "confirmed", False))
        prefix = "" if confirmed else "UNCONFIRMED LEAD (no deterministic proof) — "
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(severity, "note"),
            "message": {"text": f"{prefix}{title}: {getattr(f, 'evidence', '')}".strip()},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": target or "unknown"}},
                "logicalLocations": [{"fullyQualifiedName": getattr(f, "param", "")
                                      or target or "unknown"}],
            }],
            "partialFingerprints": {"brukalFindingV1": _fingerprint(f)},
            "properties": {
                "confirmed": confirmed,
                "category": getattr(f, "category", "web"),
                "severity": severity,
                "cvss": kb["cvss"],
                "cvssVector": kb["vector"],
                "parameter": getattr(f, "param", ""),
                "reproduce": getattr(f, "source", ""),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Brukal",
                "informationUri": TOOL_URI,
                "semanticVersion": meta.get("version", "0.1.0"),
                "rules": list(rules.values()),
            }},
            "invocations": [{
                "executionSuccessful": True,
                "commandLine": meta.get("command", "brukal"),
                "endTimeUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "properties": {
                    "auditChainIntact": meta.get("audit_chain_intact"),
                    "scope": meta.get("scope"),
                    "engagement": meta.get("engagement"),
                },
            }],
            "results": results,
        }],
    }


def to_json(findings, meta: dict | None = None) -> dict:
    """A versioned envelope for anything bespoke.

    `schema_version` is the contract: fields are added, never repurposed, so a consumer
    written today keeps working. Governance travels WITH the findings — a result is only
    worth as much as the evidence that it was obtained in scope."""
    meta = meta or {}
    items = []
    for f in findings:
        title = getattr(f, "title", "")
        kb = knowledge.enrich(title, getattr(f, "severity", "info"))
        items.append({
            "id": _fingerprint(f),
            "rule": rule_id(title),
            "title": title,
            "severity": getattr(f, "severity", "info"),
            "confirmed": bool(getattr(f, "confirmed", False)),
            "category": getattr(f, "category", "web"),
            "target": getattr(f, "target", ""),
            "parameter": getattr(f, "param", ""),
            "evidence": getattr(f, "evidence", ""),
            "reproduce": getattr(f, "source", ""),
            "cvss": kb["cvss"],
            "cvss_vector": kb["vector"],
            "impact": kb["impact"],
            "remediation": kb["remediation"],
            "references": kb["refs"],
            "observed_at": getattr(f, "ts", None),
        })
    confirmed = [i for i in items if i["confirmed"]]
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "brukal", "uri": TOOL_URI,
                 "version": meta.get("version", "0.1.0")},
        "engagement": {
            "target": meta.get("target", ""),
            "scope": meta.get("scope", ""),
            "engagement": meta.get("engagement", ""),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "governance": {
            "audit_chain_intact": meta.get("audit_chain_intact"),
            "audit_log": meta.get("audit_log", ""),
            "commands_executed": meta.get("executed"),
            "commands_blocked": meta.get("blocked"),
        },
        "summary": {
            "total": len(items),
            "confirmed": len(confirmed),
            "by_severity": {s: sum(1 for i in items if i["severity"] == s)
                            for s in ("critical", "high", "medium", "low", "info")},
        },
        "findings": items,
    }


def worst_severity(findings) -> str:
    """The highest severity present, or "" for none — the value a CI gate compares."""
    order = ("critical", "high", "medium", "low", "info")
    present = {getattr(f, "severity", "info") for f in findings}
    for s in order:
        if s in present:
            return s
    return ""


def exit_code(findings, fail_on: str = "high", confirmed_only: bool = True) -> int:
    """0 or 1 for a pipeline.

    Defaults to CONFIRMED findings only: a build should break on something Brukal
    proved, not on a lead a human has not looked at yet. `fail_on` is the lowest
    severity that fails.
    """
    order = ("critical", "high", "medium", "low", "info")
    if fail_on not in order:
        fail_on = "high"
    threshold = order.index(fail_on)
    for f in findings:
        if confirmed_only and not getattr(f, "confirmed", False):
            continue
        sev = getattr(f, "severity", "info")
        if sev in order and order.index(sev) <= threshold:
            return 1
    return 0


def write(findings, out_dir, meta: dict | None = None) -> dict:
    """Write both interchange files next to the human report. Returns the paths."""
    from pathlib import Path
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    sarif_path = out / "brukal.sarif"
    json_path = out / "findings.json"
    sarif_path.write_text(json.dumps(to_sarif(findings, meta), indent=2),
                          encoding="utf-8")
    json_path.write_text(json.dumps(to_json(findings, meta), indent=2), encoding="utf-8")
    return {"sarif": str(sarif_path), "json": str(json_path)}
