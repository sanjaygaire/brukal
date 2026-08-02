#!/usr/bin/env python3
"""
comparative.py — Brukal against established scanners, on the same authorised targets.

A benchmark that only measures itself is marketing. This one runs Brukal beside the
tools an organisation already owns (nuclei, nikto) against targets whose vulnerabilities
were verified BY HAND during development, and reports where each tool lands.

The metric design matters more than the numbers:

  * **Ground-truth recall.** Of the flaws known to exist in a target, how many did the
    tool report? Ground truth is fixed in this file with a note on how each was
    verified, so the scoring cannot drift to flatter anyone.

  * **Additional findings are NOT called false positives.** A scanner reporting a
    missing security header is reporting something real that simply is not in this
    ground-truth set. Calling that a false positive would be dishonest and would flatter
    Brukal, which reports far fewer things. They are counted separately and left
    unjudged.

  * **Proof-carrying findings.** How many results came with a deterministic proof rather
    than a signature match. For a template scanner this is 0 by construction — that is
    not a defect in those tools, it is a different design, and the column exists so the
    difference is visible rather than implied.

Brukal will lose on breadth. Nuclei ships thousands of templates and will surface things
Brukal never looks for. The claim being tested is narrower and falsifiable: that the
flaws requiring STATE — a second identity, a captured token, a canary the model must
compute — are reachable by proof-carrying multi-step testing and not by templates.

Only ever run this against a target you are authorised to test.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, jwtscan, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession, _full_send_approver
from brukal.kali import DockerKali
from brukal.web import DockerHttpWebCage, GovernedBrowser


class _NullLLM:
    def propose(self, *a, **k):
        return ""


# --------------------------------------------------------------------------- #
# Ground truth: verified by hand during development, with how.
# `needs_state` marks a flaw that cannot be decided from a single request/response
# pair — it requires a second identity, a captured credential, or a computed canary.
# --------------------------------------------------------------------------- #
GROUND_TRUTH = {
    "vampi": [
        {"id": "sqli-path-param", "needs_state": False,
         "how_verified": "GET /users/v1/name1' returns sqlite3 'unrecognized token'; "
                         "the balanced payload does not",
         "match": r"sql injection|sqli"},
        {"id": "unauth-credential-exposure", "needs_state": False,
         "how_verified": "GET /users/v1/_debug returns every user's plaintext password",
         "match": r"exposure of credentials|password.*(exposed|disclos)"},
        {"id": "unauth-pii-exposure", "needs_state": False,
         "how_verified": "GET /users/v1 returns every user's email without a credential",
         "match": r"exposure of personal data"},
        {"id": "jwt-weak-key", "needs_state": True,
         "how_verified": "the HS256 signing key is 'random', recovered offline from a "
                         "captured token's own signature",
         "match": r"guessable secret|weak.*(jwt|secret|key)"},
        {"id": "jwt-forgery", "needs_state": True,
         "how_verified": "a token minted with that key is accepted (200) where an "
                         "anonymous request is refused (401)",
         "match": r"forged jwt|authentication bypass"},
        {"id": "bola", "needs_state": True,
         "how_verified": "identity A read identity B's book, byte-identical to B's own "
                         "view, while anonymous is refused",
         "match": r"object-level authorization|bola"},
        {"id": "mass-assignment", "needs_state": True,
         "how_verified": "registering with admin=true yields an admin account while a "
                         "control registration does not",
         "match": r"mass assignment"},
    ],
    "dvga": [
        {"id": "graphql-introspection", "needs_state": False,
         "how_verified": "an anonymous introspection query returns 21 types",
         "match": r"introspection"},
        {"id": "graphql-batching", "needs_state": False,
         "how_verified": "one request carrying 3 operations is answered with 3 results",
         "match": r"batching"},
        {"id": "graphql-suggestions", "needs_state": False,
         "how_verified": "an unknown field 'usr' produces a suggestion naming 'users'",
         "match": r"suggestion"},
    ],
}


def _session(scope_path: str, host: str, cage: str, audit_out: str,
             cage_timeout: int = 180):
    """`cage_timeout` is generous for the BASELINES on purpose. Brukal finishes in
    seconds; a template scanner sweeping thousands of templates needs minutes, and
    scoring it on a run the cage cut short would be a rigged comparison."""
    scope = load_scope(scope_path)
    ap = Path(audit_out)
    if ap.exists():
        ap.unlink()
    audit = AuditLog(ap)
    ex = Executor(Gate(scope), DockerKali(container=cage, timeout=cage_timeout), audit,
                  approver=_full_send_approver)
    browser = GovernedBrowser(scope, DockerHttpWebCage(container=cage), audit)
    sess = AssistSession(host, ex, StrategistAgent(_NullLLM()), browser=browser)
    return sess, audit


def run_brukal_vampi(base: str, scope_path: str, cage: str, login: tuple) -> dict:
    """Brukal's own checks against VAmPI, through the governed browser."""
    from urllib.parse import urlsplit
    host = urlsplit(base).hostname or ""
    sess, audit = _session(scope_path, host, cage, "runs/cmp_brukal_vampi.jsonl")
    sess.allow_intrusive = True          # the mass-assignment proof creates two accounts
    t0 = time.time()
    surface = sess.crawl(seeds=[base + "/"], max_pages=3)
    routes = list(getattr(surface, "api_routes", []) or [])

    def attempt(fn):
        try:
            return bool(fn())
        except Exception as e:
            print(f"  ! {e}", file=sys.stderr)
            return False

    if login:
        attempt(lambda: sess.login(base + login[0], login[1], login[2],
                                   login_type="json"))
    token = sess.last_jwt
    for route in [r for r in routes if "{" not in r]:
        attempt(lambda r=route: sess.confirm_data_exposure(base + r))
    for route in [r for r in routes if "{" in r]:
        ph = sess._PATH_PARAM_RE.search(route).group(0)
        if attempt(lambda r=route, p=ph: sess.confirm_sqli_error(base + r, p, base="1",
                                                                 method="PATH")):
            break
    if token:
        attempt(lambda: sess.confirm_jwt_forgery(base + "/me", token))
        for route in [r for r in routes if "{" in r]:
            ph = sess._PATH_PARAM_RE.search(route).group(0)
            coll = (base + route).split(ph)[0].rstrip("/")
            if attempt(lambda c=coll, r=route, p=ph: sess.confirm_bola_from_collection(
                    c, base + r, p, token, sess.identity)):
                break
    attempt(lambda: sess.confirm_mass_assignment(
        base + "/users/v1/register", base + "/users/v1/login", base + "/me"))
    return _tool_result("brukal", sess.findings.all(), time.time() - t0,
                        audit_intact=audit.verify())


def run_brukal_dvga(url: str, scope_path: str, cage: str) -> dict:
    from urllib.parse import urlsplit
    host = urlsplit(url).hostname or ""
    sess, audit = _session(scope_path, host, cage, "runs/cmp_brukal_dvga.jsonl")
    t0 = time.time()
    intro = False
    try:
        intro = bool(sess.confirm_graphql_introspection(url))
        sess.confirm_graphql_batching(url)
        sess.confirm_graphql_suggestions(url, introspection_open=False)
    except Exception as e:
        print(f"  ! {e}", file=sys.stderr)
    _ = intro
    return _tool_result("brukal", sess.findings.all(), time.time() - t0,
                        audit_intact=audit.verify())


def _tool_result(name, findings, seconds, audit_intact=None) -> dict:
    items = []
    for f in findings:
        items.append({"title": getattr(f, "title", ""),
                      "severity": getattr(f, "severity", "info"),
                      "proof": bool(getattr(f, "confirmed", False)),
                      "evidence": (getattr(f, "evidence", "") or "")[:160]})
    return {"tool": name, "seconds": round(seconds, 1), "findings": items,
            "audit_chain_intact": audit_intact}


# nuclei colourises its output, so the template id arrives wrapped in ANSI escapes.
# Parsing without stripping them matched nothing and reported the baseline as finding
# ZERO — a fabricated win that nearly went into the published comparison.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_NUCLEI_LINE = re.compile(r"\[([a-z0-9_.:-]+)\]\s*\[[^\]]+\]\s*\[(\w+)\]")


def run_nuclei(target_url: str, scope_path: str, cage: str, seconds: int = 900) -> dict:
    """nuclei through Brukal's own governed executor, so the baseline runs under the
    same scope wall and lands in the same ledger. Nothing is measured that the gate
    would not have allowed Brukal itself to do."""
    from urllib.parse import urlsplit
    host = urlsplit(target_url).hostname or ""
    sess, audit = _session(scope_path, host, cage, "runs/cmp_nuclei.jsonl",
                           cage_timeout=seconds)
    t0 = time.time()
    # All severities: excluding info would hide exactly the breadth a template scanner
    # is good at, and this comparison is worthless if it is tuned to flatter Brukal.
    cmd = (f"nuclei -u {target_url} -silent -duc -timeout 5 -retries 1 "
           f"-no-interactsh")
    decision, result, _hl = sess.run(cmd, agent="recon")
    raw = (getattr(result, "stdout", "") or "") if result else ""
    items = []
    for line in raw.splitlines():
        line = _ANSI.sub("", line)
        m = _NUCLEI_LINE.search(line)
        if not m:
            continue
        items.append({"title": m.group(1), "severity": m.group(2).lower(),
                      "proof": False, "evidence": line.strip()[:160]})
    rc = getattr(result, "returncode", None) if result else None
    return {"tool": "nuclei", "seconds": round(time.time() - t0, 1),
            "findings": items, "audit_chain_intact": audit.verify(),
            "verdict": getattr(decision, "verdict", None),
            "ran_successfully": bool(result is not None and rc == 0),
            "returncode": rc, "stderr": ((getattr(result, "stderr", "") or "")[:200]
                                         if result else "")}


def run_nikto(target_url: str, scope_path: str, cage: str) -> dict:
    from urllib.parse import urlsplit
    host = urlsplit(target_url).hostname or ""
    sess, audit = _session(scope_path, host, cage, "runs/cmp_nikto.jsonl",
                           cage_timeout=600)
    t0 = time.time()
    decision, result, _hl = sess.run(f"nikto -host {target_url} -maxtime 120",
                                     agent="recon")
    raw = (getattr(result, "stdout", "") or "") if result else ""
    items = [{"title": _ANSI.sub("", line).strip()[:90], "severity": "info",
              "proof": False, "evidence": _ANSI.sub("", line).strip()[:160]}
             for line in (_ANSI.sub("", l) for l in raw.splitlines())
             if line.strip().startswith("+")
             and "0 host(s) tested" not in line]
    rc = getattr(result, "returncode", None) if result else None
    return {"tool": "nikto", "seconds": round(time.time() - t0, 1),
            "findings": items, "audit_chain_intact": audit.verify(),
            "verdict": getattr(decision, "verdict", None),
            # A baseline that never ran must not be scored as "found nothing" — that
            # would flatter Brukal for someone else's broken invocation.
            "ran_successfully": bool(result is not None and rc == 0 and len(raw) > 500),
            "returncode": rc, "stderr": ((getattr(result, "stderr", "") or "")[:200]
                                         if result else "")}


def score(target_key: str, tool_result: dict) -> dict:
    """Ground-truth recall for one tool, plus what it found beyond the known set."""
    truth = GROUND_TRUTH[target_key]
    blob = " | ".join(f"{f['title']} {f['evidence']}" for f in tool_result["findings"])
    hit_ids, matched_titles = [], set()
    for entry in truth:
        rx = re.compile(entry["match"], re.I)
        for f in tool_result["findings"]:
            if rx.search(f"{f['title']} {f['evidence']}"):
                hit_ids.append(entry["id"])
                matched_titles.add(f["title"])
                break
    _ = blob
    stateful = [e for e in truth if e["needs_state"]]
    stateful_hits = [i for i in hit_ids if any(e["id"] == i and e["needs_state"]
                                               for e in truth)]
    return {
        "tool": tool_result["tool"],
        "seconds": tool_result["seconds"],
        "ground_truth_total": len(truth),
        "ground_truth_found": len(hit_ids),
        "found_ids": sorted(hit_ids),
        "missed_ids": sorted(e["id"] for e in truth if e["id"] not in hit_ids),
        "stateful_total": len(stateful),
        "stateful_found": len(stateful_hits),
        "findings_reported": len(tool_result["findings"]),
        # NOT called false positives: real things outside this ground-truth set.
        "additional_findings_unjudged": max(
            0, len(tool_result["findings"]) - len(matched_titles)),
        "proof_carrying_findings": sum(1 for f in tool_result["findings"] if f["proof"]),
        "audit_chain_intact": tool_result.get("audit_chain_intact"),
        # Scored only if the tool actually executed. Absent this, a baseline that failed
        # to start reads as 0/7 and the comparison becomes worthless.
        "ran_successfully": tool_result.get("ran_successfully", True),
        "returncode": tool_result.get("returncode"),
        "stderr": tool_result.get("stderr", ""),
    }


def render(report: dict) -> str:
    lines = ["", "  Brukal vs established scanners — ground truth verified by hand", ""]
    for target, rows in report["targets"].items():
        lines.append(f"  {target}")
        lines.append(f"  {'tool':10} {'GT found':>9} {'stateful':>9} {'reported':>9} "
                     f"{'w/ proof':>9} {'extra':>7} {'secs':>6}")
        for r in rows:
            lines.append(f"  {r['tool']:10} "
                         f"{r['ground_truth_found']:>4}/{r['ground_truth_total']:<4} "
                         f"{r['stateful_found']:>4}/{r['stateful_total']:<4} "
                         f"{r['findings_reported']:>9} {r['proof_carrying_findings']:>9} "
                         f"{r['additional_findings_unjudged']:>7} {r['seconds']:>6}")
            if not r.get("ran_successfully", True):
                lines.append(f"  {'':10} ⚠ DID NOT RUN (exit {r.get('returncode')}) — "
                             f"not a result: {r.get('stderr','')[:70]}")
            if r["missed_ids"]:
                lines.append(f"  {'':10} missed: {', '.join(r['missed_ids'])}")
        lines.append("")
    lines.append("  'extra' = findings outside this ground-truth set. They are NOT")
    lines.append("  counted as false positives: a missing security header is real, it")
    lines.append("  simply is not one of the flaws being scored here.")
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="comparative")
    p.add_argument("--vampi-url", default="http://172.20.0.5:5000")
    p.add_argument("--vampi-scope", default="runs/vampi.json")
    p.add_argument("--vampi-login", nargs=3,
                   default=["/users/v1/login", "brkA9931", "Pw1brkA9931"])
    p.add_argument("--dvga-url", default="http://172.20.0.6:5013/graphql")
    p.add_argument("--dvga-scope", default="runs/dvga.json")
    p.add_argument("--cage", default="brukal-kali")
    p.add_argument("--json", help="also write the report here")
    p.add_argument("--yes-authorised", action="store_true", required=False)
    a = p.parse_args(argv)
    if not a.yes_authorised:
        print("Refused: a live comparison needs --yes-authorised.")
        return 2

    report = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "targets": {}}

    print("  running brukal against VAmPI ...", file=sys.stderr)
    b_v = run_brukal_vampi(a.vampi_url, a.vampi_scope, a.cage, tuple(a.vampi_login))
    print("  running nuclei against VAmPI ...", file=sys.stderr)
    n_v = run_nuclei(a.vampi_url, a.vampi_scope, a.cage)
    print("  running nikto against VAmPI ...", file=sys.stderr)
    k_v = run_nikto(a.vampi_url, a.vampi_scope, a.cage)
    report["targets"]["VAmPI (REST API)"] = [score("vampi", r) for r in (b_v, n_v, k_v)]

    print("  running brukal against DVGA ...", file=sys.stderr)
    b_d = run_brukal_dvga(a.dvga_url, a.dvga_scope, a.cage)
    print("  running nuclei against DVGA ...", file=sys.stderr)
    n_d = run_nuclei(a.dvga_url.rsplit("/graphql", 1)[0], a.dvga_scope, a.cage)
    report["targets"]["DVGA (GraphQL)"] = [score("dvga", r) for r in (b_d, n_d)]

    print(render(report))
    if a.json:
        Path(a.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"  wrote {a.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
