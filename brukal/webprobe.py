"""
webprobe.py — turn the crawled attack surface into concrete vuln probes.

This is the bridge from *map* to *test*. Given an AttackSurface (forms, parameters,
endpoints) it deterministically emits the exact tool commands that probe those real
targets — a methodical checklist a weak model would never enumerate reliably on its
own. It is the coverage engine; the model is freed to reason about the interesting
hits instead of remembering to test every parameter.

Why this is safe to let code (not the model) generate:

  * It is PURE and does NO I/O — string templating from structured fields. It reaches
    no host; every probe still runs through Executor.run -> the gate -> the cage.
  * It never DECIDES risk. Each probe is tagged passive/active only as a HINT for the
    driver; the deterministic risk layer is what actually rules — read-only scanners
    (whatweb/nuclei/nikto) score reversible and auto-run, while active injection
    (sqlmap/dalfox/commix) scores irreversible and ESCALATEs to a human (or runs under
    --full-send). So "active" here is advisory; the gate is the authority.
  * Targets come only from the in-scope crawl, and the gate re-checks scope on every
    one — a probe can never point off-target.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from . import webmap


@dataclass(frozen=True)
class Probe:
    tool: str
    command: str
    category: str          # "passive" (read-only, auto-runs) | "active" (attack, escalates)
    target: str            # the URL / endpoint under test
    param: str = ""        # the parameter or fields being tested, if any
    rationale: str = ""


def _root_of(url: str) -> str:
    s = urlsplit(url)
    if not s.netloc:
        return ""
    return urlunsplit((s.scheme or "http", s.netloc, "/", "", ""))


def _single_param_url(base: str, param: str) -> str:
    """A clean, single-parameter test URL (`base?param=1`) — no `&`, so the probe
    command stays a simple, unambiguous token for the gate to validate."""
    return f"{base}?{param}=1"


def plan_probes(surface, target: str, *, max_active: int = 12) -> list[Probe]:
    """Deterministically enumerate vuln probes for a crawled surface. Passive probes
    (one set per web root) fingerprint + run read-only vuln detection; active probes
    (capped at max_active) test each discovered parameter/form for injection. No
    network, no risk decision — just the commands, in a stable order."""
    probes: list[Probe] = []

    # --- web roots ---------------------------------------------------------- #
    roots: list[str] = []
    for u in sorted(surface.pages) if surface and surface.pages else []:
        r = _root_of(u)
        if r and r not in roots:
            roots.append(r)
    if not roots:
        r = _root_of(surface.seed) if surface and surface.seed else ""
        roots = [r or f"http://{target}/"]

    # --- passive: fingerprint + read-only vuln detection per root ----------- #
    for root in roots:
        probes.append(Probe("whatweb", f"whatweb {root}", "passive", root,
                            rationale="fingerprint server / framework / versions"))
        probes.append(Probe("nuclei", f"nuclei -u {root} -silent -timeout 5", "passive",
                            root, rationale="templated CVE / misconfig / exposure scan"))
        probes.append(Probe("nikto", f"nikto -host {root} -maxtime 120", "passive", root,
                            rationale="web-server misconfig / dangerous files"))

    # --- active: per-parameter injection tests ------------------------------ #
    active: list[Probe] = []
    seen: set = set()
    param_links = sorted(l for l in (surface.links if surface else set())
                         if urlsplit(l).query)
    for link in param_links:
        base = webmap.base_of(link)
        for p in sorted(webmap.params_of(link)):
            key = (base, p)
            if key in seen:
                continue
            seen.add(key)
            turl = _single_param_url(base, p)
            active.append(Probe("sqlmap",
                                f'sqlmap -u "{turl}" -p {p} --batch --level 1 --risk 1',
                                "active", turl, p, "SQL injection test on parameter"))
            active.append(Probe("dalfox", f'dalfox url "{turl}" -p {p}',
                                "active", turl, p, "reflected/stored XSS test on parameter"))
            if len(active) >= max_active:
                break
        if len(active) >= max_active:
            break

    # --- active: per-form injection tests (POST bodies) --------------------- #
    for f in (surface.forms if surface else []):
        if len(active) >= max_active:
            break
        if f.method == "POST" and f.inputs:
            first = f.inputs[0][0]                # test the first field to keep the body `&`-free
            if not first:
                continue
            key = (f.action, "form:" + first)
            if key in seen:
                continue
            seen.add(key)
            active.append(Probe("sqlmap",
                                f'sqlmap -u "{f.action}" --data "{first}=1" -p {first} '
                                f"--batch --level 1 --risk 1",
                                "active", f.action, first, "SQL injection test on form field"))

    return probes + active[:max_active]


# --- light vuln-signal detection over probe output -------------------------- #
# Phase 3 will build the full findings model; this flags the obvious hits now so a
# real vulnerability is surfaced (and can be verified) instead of buried in output.
_SIGNALS = (
    (re.compile(r"parameter '[^']+'.*?(?:is|appears to be).*?injectabl", re.I), "high",
     "SQL injection"),
    (re.compile(r"\bis vulnerable\b", re.I), "high", "vulnerable"),
    (re.compile(r"back-end DBMS", re.I), "high", "SQLi (DBMS identified)"),
    (re.compile(r"\[(critical|high)\]", re.I), "high", "nuclei finding"),
    (re.compile(r"\[(medium|low)\]", re.I), "medium", "nuclei finding"),
    (re.compile(r"\[POC\]|triggered in", re.I), "high", "XSS PoC"),
    (re.compile(r"^\+ .*(OSVDB|XSS|SQL|injection|traversal)", re.I | re.M), "medium",
     "nikto finding"),
    (re.compile(r"\bCVE-\d{4}-\d{3,}\b"), "high", "known CVE"),
)


def scan_output(text: str) -> list[tuple[str, str, str]]:
    """Scan one probe's real output for vulnerability signals. Returns a list of
    (severity, label, evidence-line). Deterministic pattern-matching over UNTRUSTED
    output — it only flags for a human/Verifier, it never acts."""
    hits: list[tuple[str, str, str]] = []
    seen: set = set()
    for rx, sev, label in _SIGNALS:
        for m in rx.finditer(text or ""):
            line = (m.group(0) or "").strip()[:160]
            key = (label, line)
            if key not in seen:
                seen.add(key)
                hits.append((sev, label, line))
    return hits


# --- exposure / info-disclosure signatures ---------------------------------
# Signals in a RAW RESPONSE body (a `curl`/`wget` of a path, a dumped file) that a
# scanner-pattern (`scan_output`) would miss: exposed secrets, VCS/config files,
# keys, SQL errors, debug traces, directory listings. Tight content signatures so a
# 404 page or ordinary HTML does not false-positive. Deterministic over UNTRUSTED
# output — a hit is a recorded FINDING (evidence for the operator/Verifier), never
# an action and never fed back as a trusted instruction; the gate stays the sole
# authority over what runs.
_EXPOSURES = (
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     "critical", "Private key exposed"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical", "AWS access key exposed"),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "critical", "Slack token exposed"),
    (re.compile(r"repositoryformatversion\s*=", re.I), "high", "Exposed .git repository"),
    (re.compile(r"^ref:\s*refs/heads/", re.I | re.M), "high", "Exposed .git repository"),
    (re.compile(r"(?im)^\s*(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|APP_KEY|API_KEY|"
                r"AWS_SECRET_ACCESS_KEY|JWT_SECRET|PRIVATE_KEY|MYSQL_ROOT_PASSWORD|"
                r"REDIS_PASSWORD|PASSWORD)\s*=\s*\S+"),
     "high", "Secret in exposed env/config"),
    (re.compile(r"(?:SQL syntax.*?(?:MySQL|MariaDB)|valid MySQL result|ORA-\d{5}|"
                r"SQLSTATE\[|PostgreSQL.*?ERROR|Unclosed quotation mark after|"
                r"SQLiteException|SQLITE_ERROR|Sequelize\w*Error|"
                r"near \".*?\": syntax error)", re.I),
     "high", "SQL error (possible injection)"),
    (re.compile(r"(?i)<title>\s*Index of /"), "medium", "Directory listing enabled"),
    (re.compile(r"(?i)<title>\s*phpinfo\(\)"), "medium", "phpinfo() exposed"),
    (re.compile(r"(?i)Apache Server Status\b"), "medium", "Apache server-status exposed"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}"),
     "medium", "JWT exposed in response"),
    (re.compile(r"(?:Traceback \(most recent call last\)|Exception in thread \""
                # a stack frame leaking an internal file path — Node/Python/Ruby/PHP/Java
                r"|\bat [\w.$<>\[\]]+ ?\((?:/|[A-Za-z]:\\)[^\s()]+\."
                r"(?:js|mjs|ts|py|rb|php|java|go):\d+"
                r"|\bat [\w.$]+\([\w.]+\.java:\d+\)|Fatal error:.*?on line \d+)"),
     "low", "Stack trace / debug info disclosure"),
    (re.compile(r"\"(?:swagger|openapi)\"\s*:", re.I), "info", "API schema exposed"),
)


def scan_exposures(text: str) -> list[tuple[str, str, str]]:
    """Scan a raw response/file body for exposure & info-disclosure signatures that
    `scan_output`'s scanner-oriented patterns miss (leaked secrets, `.git`/`.env`,
    keys, SQL errors, directory listings, debug traces). Returns (severity, label,
    evidence-line). Deterministic over UNTRUSTED output — flags for the operator, it
    never acts."""
    hits: list[tuple[str, str, str]] = []
    seen: set = set()
    for rx, sev, label in _EXPOSURES:
        m = rx.search(text or "")
        if m and label not in seen:
            seen.add(label)
            line = (m.group(0) or "").strip()[:160]
            hits.append((sev, label, line))
    return hits
