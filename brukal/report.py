"""
report.py — render a FindingStore + engagement metadata into a deliverable.

Markdown (the human deliverable) and JSON (machine-readable). The report is
deliberately honest about provenance: every finding shows the exact command that
produced it and its real evidence line, confirmed findings are separated from
candidates (heuristic signals a human should verify), and the methodology section
states the governance guarantees (scope-locked, one gate, append-only audit) so a
reader knows the tool could not have strayed off the authorised target.
"""
from __future__ import annotations

import json
import time

from .findings import SEVERITIES, FindingStore

_BADGE = {"critical": "🔴 CRITICAL", "high": "🟠 HIGH", "medium": "🟡 MEDIUM",
          "low": "🔵 LOW", "info": "⚪ INFO"}


def _ts(t=None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


def _finding_md(f) -> str:
    lines = [f"### {_BADGE.get(f.severity, f.severity)} — {f.title}"
             f"{' *(candidate)*' if not f.confirmed else ''}"]
    lines.append(f"- **Target:** `{f.target or '-'}`"
                 + (f"  ·  **Parameter:** `{f.param}`" if f.param else ""))
    if f.evidence:
        lines.append(f"- **Evidence:**\n\n  ```\n  {f.evidence.strip()[:500]}\n  ```")
    if f.source:
        lines.append(f"- **Reproduce:** `{f.source}`")
    lines.append(f"- **Status:** {'confirmed (evidence-backed)' if f.confirmed else 'candidate — verify manually'}")
    return "\n".join(lines)


def build_report(store: FindingStore, meta: dict) -> str:
    """A Markdown pentest report from the findings + engagement metadata."""
    m = meta or {}
    counts = store.counts()
    total = len(store)
    out = [f"# Brukal Pentest Report — {m.get('target', 'target')}", ""]

    # --- engagement metadata table -------------------------------------------
    rows = [
        ("Engagement", m.get("engagement", "-")),
        ("Target", m.get("target", "-")),
        ("Scope", m.get("scope", "-")),
        ("Cage", m.get("cage", "-")),
        ("Generated", _ts()),
        ("Autonomous steps", str(m.get("steps", "-"))),
        ("Commands executed", str(m.get("executed", "-"))),
        ("Stopped because", m.get("stop_reason", "-")),
        ("Audit chain intact", "✅ yes" if m.get("audit_intact") else "⚠ NOT VERIFIED"),
        ("Model spend", m.get("spend", "-")),
    ]
    out.append("| Field | Value |")
    out.append("|---|---|")
    out += [f"| {k} | {v} |" for k, v in rows]
    out.append("")

    # --- executive summary ----------------------------------------------------
    out.append("## Summary")
    out.append("")
    badges = "  ".join(f"**{counts[s]}** {s}" for s in SEVERITIES if counts[s])
    out.append(f"{total} finding(s): {badges or 'none'}."
               f"  ({len(store.confirmed())} confirmed, {len(store.candidates())} candidate.)")
    out.append("")

    # --- findings, ranked -----------------------------------------------------
    confirmed, candidates = store.confirmed(), store.candidates()
    if confirmed:
        out.append("## Confirmed findings")
        out.append("")
        out += [_finding_md(f) + "\n" for f in confirmed]
    if candidates:
        out.append("## Candidate findings (verify manually)")
        out.append("")
        out += [_finding_md(f) + "\n" for f in candidates]
    if total == 0:
        out.append("_No vulnerability signals were flagged in this run._")
        out.append("")

    # --- attack surface -------------------------------------------------------
    if m.get("surface"):
        out.append("## Web attack surface")
        out.append("")
        out.append("```")
        out.append(str(m["surface"]).strip())
        out.append("```")
        out.append("")

    # --- methodology / governance --------------------------------------------
    out.append("## Methodology & governance")
    out.append("")
    out.append(
        "Every command in this engagement was executed through a single deterministic "
        "gate (`Executor.run`): scope was enforced by CIDR/host arithmetic (no LLM in "
        "the gate), out-of-scope actions were denied, irreversible/attack actions were "
        "escalated for human sign-off, and the full action ledger is hash-chained and "
        "tamper-evident. Findings are evidence-backed — each is derived from real "
        "gate-executed output, with the reproducing command shown above.")
    out.append("")
    return "\n".join(out)


def report_json(store: FindingStore, meta: dict) -> dict:
    """Machine-readable report: metadata + counts + every finding."""
    return {
        "meta": {**(meta or {}), "generated": _ts()},
        "counts": store.counts(),
        "total": len(store),
        "findings": [f.to_dict() for f in store.all()],
    }


def write_reports(store: FindingStore, meta: dict, out_dir) -> dict:
    """Write report.md + report.json into out_dir. Returns {fmt: path} for those
    that wrote. Best-effort: an I/O error on one format never aborts the other."""
    from pathlib import Path
    out_dir = Path(out_dir)
    written = {}
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        md = out_dir / "report.md"
        md.write_text(build_report(store, meta), encoding="utf-8")
        written["md"] = str(md)
    except OSError:
        pass
    try:
        js = out_dir / "report.json"
        js.write_text(json.dumps(report_json(store, meta), indent=2), encoding="utf-8")
        written["json"] = str(js)
    except OSError:
        pass
    return written
