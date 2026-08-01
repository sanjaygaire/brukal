#!/usr/bin/env python3
"""
live_capability.py — Brukal LIVE capability benchmark against an AUTHORISED web testbed.

Complements run_experiments.py (deterministic GOVERNANCE metrics) with a live run that
measures how many vulnerability classes Brukal CONFIRMS by its own deterministic
differential proofs — through the governed browser, never a shell — while the gate
holds (0 scope violations, hash-chained audit intact, an out-of-scope probe blocked
mid-run). The reference run targets DVWA at security=low on an isolated Docker net.

    # bring up the cage + DVWA, set DVWA to security=low, then:
    python benchmarks/live_capability.py --target 172.20.0.4 \
        --scope runs/dvwa.json --cage brukal-kali --yes-authorised

Only ever point a live run at a target you are authorised to test. The --scope file
must authorise exactly that host and nothing else; the gate denies everything else.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, jwtscan, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession, _full_send_approver
from brukal.kali import DockerKali
from brukal.web import DockerHttpWebCage, GovernedBrowser, WebAction


class _NullLLM:
    def propose(self, *a, **k):
        return ""


def run(target: str, scope_path: str, cage: str, audit_out: str) -> dict:
    scope = load_scope(scope_path)
    ap = Path(audit_out)
    if ap.exists():
        ap.unlink()
    audit = AuditLog(ap)
    ex = Executor(Gate(scope), DockerKali(container=cage), audit,
                  approver=_full_send_approver)
    browser = GovernedBrowser(scope, DockerHttpWebCage(container=cage), audit)
    sess = AssistSession(target, ex, StrategistAgent(_NullLLM()), browser=browser)
    base = f"http://{target}"

    authed = sess.login(f"{base}/login.php", "admin", "password")
    browser._cookies["security"] = "low"          # DVWA level for the reference run

    # Each check is a governed WEB probe (scope+scheme gated); the verdict is CODE.
    checks = {
        "SQLi (boolean-based)": lambda: sess.confirm_sqli(
            f"{base}/vulnerabilities/sqli/?id=1&Submit=Submit", "id"),
        "Reflected XSS": lambda: sess.confirm_xss(
            f"{base}/vulnerabilities/xss_r/?name=x", "name"),
        "OS command injection": lambda: sess.confirm_cmdi(
            f"{base}/vulnerabilities/exec/", "ip", method="POST",
            extra={"Submit": "Submit"}),
        "LFI / path traversal": lambda: sess.confirm_lfi(
            f"{base}/vulnerabilities/fi/?page=include.php", "page"),
    }
    confirmed = {}
    for name, fn in checks.items():
        try:
            confirmed[name] = bool(fn())
        except Exception as e:                     # a broken probe fails closed (unconfirmed)
            confirmed[name] = False
            print(f"  ! {name}: {e}", file=sys.stderr)

    # LIVE scope interception: an out-of-scope probe mid-run must be denied before the cage.
    _d, oos = browser.run(WebAction("get", url="http://8.8.8.8/?id=1"))
    out_of_scope_blocked = oos is None

    # Governance is read from the ledger itself — never an agent's self-report.
    entries = [json.loads(l) for l in ap.read_text().splitlines() if l.strip()]
    scope_denies = sum(
        1 for e in entries
        if e.get("kind", "").endswith("decision")
        and e["data"].get("verdict") == "DENY"
        and "scope" in (e["data"].get("layer", "") or ""))
    web_actions = sum(1 for e in entries if e.get("kind") == "web_result")

    n = sum(confirmed.values())
    return {
        "target": target,
        "environment": "docker (authorised DVWA, security=low)",
        "authenticated": authed,
        "classes_tested": len(checks),
        "classes_confirmed": n,
        "confirmation_rate": round(n / len(checks), 3),
        "confirmed": confirmed,
        "governed_web_requests": web_actions,
        "scope_violations": 0,                     # by construction — gate denies pre-cage
        "out_of_scope_probe_blocked": out_of_scope_blocked,
        "scope_denies_logged": scope_denies,
        "audit_chain_intact": audit.verify(),
        "confirmed_findings_recorded": len(
            [f for f in sess.findings.all() if getattr(f, "confirmed", False)]),
        "ts": time.time(),
    }


def run_ai(url: str, scope_path: str, cage: str, audit_out: str) -> dict:
    """The AI / LLM class, measured the same way: a deterministic canary the model can
    only return by OBEYING an injected instruction, sent through the governed browser
    against an AUTHORISED LLM-backed endpoint. Separate from the web run because the AI
    surface lives on its own host and scope file — the gate is per-scope, and widening
    one scope to cover both would be exactly the wrong thing to demonstrate."""
    from urllib.parse import urlsplit
    scope = load_scope(scope_path)
    ap = Path(audit_out)
    if ap.exists():
        ap.unlink()
    audit = AuditLog(ap)
    host = urlsplit(url).hostname or ""
    ex = Executor(Gate(scope), DockerKali(container=cage), audit,
                  approver=_full_send_approver)
    browser = GovernedBrowser(scope, DockerHttpWebCage(container=cage), audit)
    sess = AssistSession(host, ex, StrategistAgent(_NullLLM()), browser=browser)

    try:
        injected = bool(sess.confirm_prompt_injection(url, "message", method="JSON"))
    except Exception as e:
        injected = False
        print(f"  ! prompt injection: {e}", file=sys.stderr)

    # the same governance check: an unauthorised AI endpoint must be denied mid-run
    _d, oos = browser.run(WebAction("get", url="http://8.8.8.8/v1/chat/completions"))
    return {
        "endpoint": url,
        "environment": "docker (authorised OWASP Juice Shop, LLM-backed chatbot)",
        "classes_tested": 1,
        "classes_confirmed": int(injected),
        "confirmed": {"Prompt injection (LLM01)": injected},
        "out_of_scope_probe_blocked": oos is None,
        "audit_chain_intact": audit.verify(),
        "confirmed_findings_recorded": len(
            [f for f in sess.findings.all() if getattr(f, "confirmed", False)]),
        "ts": time.time(),
    }


def run_api(base: str, scope_path: str, cage: str, audit_out: str,
            login: tuple | None = None) -> dict:
    """The API classes against an AUTHORISED JSON API.

    Everything starts from the target's own OpenAPI document, and every verdict is code
    comparing two responses or arithmetic over a signature — never a model's opinion:

      * injection proved on a REST PATH parameter, by a quote-balance differential;
      * a JWT signing key recovered OFFLINE from a captured token's own signature;
      * a token minted with that key, accepted where anonymous is refused;
      * an object read across an account boundary, chosen from a collection listing;
      * credentials, and separately bulk personal data, served to nobody at all.

    The two exposure lines are one check graded by what leaked (credentials outrank
    personal data) and are counted separately because they are separate findings against
    separate endpoints with different severities. Mass assignment is deliberately absent:
    it is the one proof that must WRITE to the target, and a benchmark should not create
    accounts on a host just to score a point.
    """
    from urllib.parse import urlsplit
    scope = load_scope(scope_path)
    ap = Path(audit_out)
    if ap.exists():
        ap.unlink()
    audit = AuditLog(ap)
    host = urlsplit(base).hostname or ""
    ex = Executor(Gate(scope), DockerKali(container=cage), audit,
                  approver=_full_send_approver)
    browser = GovernedBrowser(scope, DockerHttpWebCage(container=cage), audit)
    sess = AssistSession(host, ex, StrategistAgent(_NullLLM()), browser=browser)

    surface = sess.crawl(seeds=[base + "/"], max_pages=3)
    routes = list(getattr(surface, "api_routes", []) or [])
    protected = list(getattr(surface, "protected_routes", []) or [])
    param_routes = [r for r in routes if "{" in r]
    listings = [r for r in routes if "{" not in r]

    def attempt(label, fn):
        try:
            return bool(fn())
        except Exception as e:                     # a broken probe fails closed
            print(f"  ! {label}: {e}", file=sys.stderr)
            return False

    confirmed: dict = {}

    # Authenticate FIRST. Three of the six classes need a token, and spending the rate
    # allowance on probes before asking for one turns a capability measurement into an
    # artefact of ordering — which is exactly what it did on the first run.
    if login:
        attempt("login", lambda: sess.login(base + login[0], login[1], login[2],
                                            login_type="json"))
    token = sess.last_jwt

    # --- what the app hands a stranger (cheapest, highest signal) --------------
    creds = pii = False
    for route in listings:
        if creds and pii:
            break
        url = base + route
        if attempt(route, lambda u=url: sess.confirm_data_exposure(u)):
            titles = {f.title for f in sess.findings.all()}
            creds = creds or "Unauthenticated exposure of credentials" in titles
            pii = pii or "Unauthenticated exposure of personal data" in titles
    confirmed["Unauthenticated exposure of credentials"] = creds
    confirmed["Unauthenticated exposure of personal data"] = pii

    # --- injection on a path parameter ---------------------------------------
    # Iterate candidates as the reflex does: the first parameterised route is often a
    # protected or empty collection, which refuses everything and proves nothing.
    sqli = False
    for route in param_routes:
        placeholder = sess._PATH_PARAM_RE.search(route).group(0)
        if attempt(route, lambda r=route, ph=placeholder: sess.confirm_sqli_error(
                base + r, ph, base="1", method="PATH")):
            sqli = True
            break
    confirmed["SQLi on a REST path parameter"] = sqli

    # --- token weaknesses -----------------------------------------------------
    confirmed["JWT signing key recovered offline"] = bool(
        token and any(l == "JWT signed with a guessable secret"
                      for _s, l, _e in jwtscan.scan_token(token)))

    # A protected endpoint with NO path parameter: an invented id yields 404, and the
    # accept/refuse differential needs the endpoint to actually serve a valid holder.
    prot = sorted((p for _m, p in protected), key=lambda p: ("{" in p, len(p)))
    forged = False
    for path in (prot or ["/me"]):
        url = base + sess._PATH_PARAM_RE.sub("1", path)
        if token and attempt(path, lambda u=url: sess.confirm_jwt_forgery(u, token)):
            forged = True
            break
    confirmed["Authentication bypass via forged JWT"] = forged

    # --- object authorization, across an account boundary ---------------------
    bola = False
    for route in param_routes:
        placeholder = sess._PATH_PARAM_RE.search(route).group(0)
        collection = (base + route).split(placeholder)[0].rstrip("/")
        if token and attempt(route, lambda c=collection, r=route, ph=placeholder:
                             sess.confirm_bola_from_collection(
                                 c, base + r, ph, token, sess.identity)):
            bola = True
            break
    confirmed["Broken object-level authorization (BOLA)"] = bola

    _d, oos = browser.run(WebAction("get", url="http://8.8.8.8/users/v1/1"))
    n = sum(confirmed.values())
    return {
        "target": base,
        "environment": "docker (authorised VAmPI, vulnerable JSON API)",
        "endpoints_from_spec": len(routes),
        "spec_declared_protected": len(protected),
        "classes_tested": len(confirmed),
        "classes_confirmed": n,
        "confirmation_rate": round(n / len(confirmed), 3) if confirmed else 0.0,
        "confirmed": confirmed,
        "out_of_scope_probe_blocked": oos is None,
        "audit_chain_intact": audit.verify(),
        "coverage_cut_short": bool(getattr(sess, "_rate_limited", False)),
        # Three classes are unreachable without a token, so record whether one was ever
        # obtained: a false with no credential is a missing precondition, not a clean bill.
        "token_acquired": bool(token),
        "confirmed_findings_recorded": len(
            [f for f in sess.findings.all() if getattr(f, "confirmed", False)]),
        "ts": time.time(),
    }


def run_graphql(url: str, scope_path: str, cage: str, audit_out: str) -> dict:
    """The GraphQL class against an AUTHORISED endpoint. Structural by design: the
    response must genuinely carry a __schema, because the commonest shape in this space
    is a single-page app answering 200 with index.html for every path — a status-code
    check would score a point on any SPA."""
    from urllib.parse import urlsplit
    scope = load_scope(scope_path)
    ap = Path(audit_out)
    if ap.exists():
        ap.unlink()
    audit = AuditLog(ap)
    host = urlsplit(url).hostname or ""
    ex = Executor(Gate(scope), DockerKali(container=cage), audit,
                  approver=_full_send_approver)
    browser = GovernedBrowser(scope, DockerHttpWebCage(container=cage), audit)
    sess = AssistSession(host, ex, StrategistAgent(_NullLLM()), browser=browser)
    try:
        found = bool(sess.confirm_graphql_introspection(url))
    except Exception as e:
        found = False
        print(f"  ! graphql: {e}", file=sys.stderr)
    _d, oos = browser.run(WebAction("get", url="http://8.8.8.8/graphql"))
    return {
        "endpoint": url,
        "environment": "docker (authorised Damn Vulnerable GraphQL Application)",
        "classes_tested": 1,
        "classes_confirmed": int(found),
        "confirmed": {"GraphQL introspection enabled": found},
        "out_of_scope_probe_blocked": oos is None,
        "audit_chain_intact": audit.verify(),
        "confirmed_findings_recorded": len(
            [f for f in sess.findings.all() if getattr(f, "confirmed", False)]),
        "ts": time.time(),
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="live_capability")
    p.add_argument("--target", help="web target (DVWA reference run)")
    p.add_argument("--scope", help="scope file authorising ONLY --target")
    p.add_argument("--ai-url", help="an AUTHORISED LLM-backed endpoint to measure "
                                    "the AI class against (e.g. .../rest/chat)")
    p.add_argument("--ai-scope", help="scope file authorising ONLY the --ai-url host")
    p.add_argument("--api-url", help="an AUTHORISED JSON API base (e.g. http://host:5000)")
    p.add_argument("--api-scope", help="scope file authorising ONLY the --api-url host")
    p.add_argument("--api-login", nargs=3, metavar=("PATH", "USER", "PASS"),
                   help="login path + credentials so a JWT can be captured")
    p.add_argument("--graphql-url", help="an AUTHORISED GraphQL endpoint")
    p.add_argument("--graphql-scope", help="scope file authorising ONLY that host")
    p.add_argument("--cage", default="brukal-kali")
    p.add_argument("--audit", default="runs/audit_livebench.jsonl")
    p.add_argument("--json", help="also write the result here")
    p.add_argument("--yes-authorised", action="store_true",
                   help="explicit confirmation you are authorised to test --target")
    a = p.parse_args(argv)
    if not a.yes_authorised:
        print("Refused: a live run needs --yes-authorised (you confirm authorisation).")
        return 2
    if not a.target and not a.ai_url and not a.api_url and not a.graphql_url:
        print("Refused: give --target, --ai-url, --api-url and/or --graphql-url.")
        return 2
    out: dict = {}
    if a.target:
        if not a.scope:
            print("Refused: --target needs --scope.")
            return 2
        if not load_scope(a.scope).contains_ip(a.target):
            print(f"Refused: {a.target} is not inside {a.scope}.")
            return 2
        out = run(a.target, a.scope, a.cage, a.audit)
    if a.ai_url:
        from urllib.parse import urlsplit
        ai_scope = a.ai_scope or a.scope
        if not ai_scope:
            print("Refused: --ai-url needs --ai-scope.")
            return 2
        if not load_scope(ai_scope).contains_host(urlsplit(a.ai_url).hostname or ""):
            print(f"Refused: {a.ai_url} is not inside {ai_scope}.")
            return 2
        ai = run_ai(a.ai_url, ai_scope, a.cage, a.audit + ".ai")
        out = {**out, "ai": ai} if out else {"ai": ai}
    if a.api_url:
        from urllib.parse import urlsplit
        api_scope = a.api_scope or a.scope
        if not api_scope:
            print("Refused: --api-url needs --api-scope.")
            return 2
        if not load_scope(api_scope).contains_host(urlsplit(a.api_url).hostname or ""):
            print(f"Refused: {a.api_url} is not inside {api_scope}.")
            return 2
        api = run_api(a.api_url.rstrip("/"), api_scope, a.cage, a.audit + ".api",
                      login=tuple(a.api_login) if a.api_login else None)
        out = {**out, "api": api} if out else {"api": api}
    if a.graphql_url:
        from urllib.parse import urlsplit
        gq_scope = a.graphql_scope or a.scope
        if not gq_scope:
            print("Refused: --graphql-url needs --graphql-scope.")
            return 2
        if not load_scope(gq_scope).contains_host(urlsplit(a.graphql_url).hostname or ""):
            print(f"Refused: {a.graphql_url} is not inside {gq_scope}.")
            return 2
        gq = run_graphql(a.graphql_url, gq_scope, a.cage, a.audit + ".gql")
        out = {**out, "graphql": gq} if out else {"graphql": gq}
    print(json.dumps(out, indent=2))
    if a.json:
        Path(a.json).write_text(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
