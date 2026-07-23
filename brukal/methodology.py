"""
methodology.py — mode-aware pentest methodology (stdlib, no egress, no LLM).

Two kinds of engagement need two different disciplines:

  * a WEB application -> the OWASP Web Security Testing Guide (WSTG) categories:
    information gathering, configuration, identity/authentication, session
    management, input validation (injection/XSS/SSTI/LFI/SSRF), authorization
    (IDOR/traversal), error handling, cryptography, business logic, client-side.
  * a BOX / host -> the machine-pentest flow: full enumeration, per-service enum,
    web enum, foothold, privilege escalation, loot the flags.

This module is deterministic STRATEGY scaffolding. It runs nothing and decides no
scope — every step is still proposed (by the model or a reflex) and disposed by the
gate. What it does is make even a weak model follow a correct, *complete* methodology
from a verified source instead of wandering: the checklist is injected as the
top-priority reference the planner reasons over, each item tagged with its WSTG id so
the resulting report is auditable against a recognised standard.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# A dotted IPv4 / bracketed-or-bare IPv6 literal -> treat as a BOX; a name/URL -> WEB.
_IPV4 = re.compile(r"\A\d{1,3}(?:\.\d{1,3}){3}\Z")
_IPV6ish = re.compile(r"\A[0-9a-fA-F:]+\Z")


@dataclass(frozen=True)
class Step:
    phase: str            # canonical phase label
    title: str            # the objective / test to perform
    ref: str = ""         # verified-source id (e.g. an OWASP WSTG category)
    hint: str = ""        # concrete tools / approach available in the cage


# ---- OWASP WSTG-aligned web methodology ------------------------------------ #
WEB_METHODOLOGY: tuple[Step, ...] = (
    Step("recon", "Fingerprint server, framework, and versions; map the whole app",
         "WSTG-INFO", "whatweb / nuclei -tags tech; crawl the site (forms, params, endpoints)"),
    Step("configuration", "Probe deployment/config: exposed files, backups, admin "
         "panels, dangerous HTTP methods, security headers", "WSTG-CONF",
         "nikto; check /.git /.env /backup; curl -I for headers; OPTIONS method"),
    Step("authentication", "Test identity & auth: user enumeration, default/weak "
         "credentials, auth bypass, lockout", "WSTG-ATHN",
         "compare login responses; try documented default creds (never rockyou brute)"),
    Step("session", "Session management: cookie flags (HttpOnly/Secure/SameSite), "
         "fixation, CSRF on state-changing forms", "WSTG-SESS",
         "inspect Set-Cookie; test CSRF token presence on POST forms"),
    Step("input-validation", "Injection & input validation on every mapped parameter/"
         "form: SQLi, XSS, command injection, SSTI, XXE, LFI/RFI, SSRF", "WSTG-INPV",
         "sqlmap / dalfox on mapped params (active -> escalate/full-send); test SSTI/LFI"),
    Step("authorization", "Access control: IDOR, path traversal, forced browsing, "
         "privilege escalation between roles", "WSTG-ATHZ",
         "tamper object ids/paths; request admin endpoints as a low-priv user"),
    Step("error-handling", "Error handling & info leaks: verbose errors, stack traces, "
         "debug pages (e.g. Laravel Ignition), version disclosure", "WSTG-ERRH",
         "trigger errors; check for debug=true / framework debug pages -> known RCEs"),
    Step("cryptography", "Transport & data protection: weak TLS, mixed content, "
         "sensitive data in responses/JS", "WSTG-CRYP", "sslscan; grep responses/JS for secrets"),
    Step("business-logic", "Business-logic flaws: workflow bypass, price/quantity "
         "tampering, race conditions", "WSTG-BUSL", "reason about the app's intended flow"),
    Step("client-side", "Client-side: DOM XSS, CORS misconfig, clickjacking, "
         "postMessage, open redirect", "WSTG-CLNT", "review JS; check CORS/ACAO headers"),
)

# ---- box / host methodology ------------------------------------------------ #
BOX_METHODOLOGY: tuple[Step, ...] = (
    Step("enumeration", "Full TCP port sweep, then service/version + default scripts "
         "on the open ports", "", "nmap -p- then nmap -sVC -p<open>"),
    Step("enumeration", "Enumerate every discovered service (web, SMB, FTP, SSH, DNS, "
         "SNMP, LDAP, RPC, databases)", "", "per-service: enum4linux, smbmap, anon FTP, "
         "whatweb, showmount, snmpwalk, ldapsearch"),
    Step("enumeration", "For any web service: crawl the site and run the web "
         "methodology (attack surface -> vuln probes)", "WSTG", "crawl + whatweb/nuclei/"
         "nikto; sqlmap/dalfox on mapped params"),
    Step("exploitation", "Get a foothold via the weakest service: known CVE, default/"
         "leaked credentials, file upload, or injection", "",
         "searchsploit the version; try leaked creds; exploit the specific finding"),
    Step("privilege-escalation", "Escalate to root/SYSTEM: sudo rights, SUID/capabilities, "
         "cron, kernel, credentials on disk", "", "sudo -l; SUID sweep; linpeas patterns; "
         "GTFOBins for any allowed binary"),
    Step("looting", "Capture the objectives: user and root flags; loot credentials for "
         "lateral movement", "", "read user.txt then root.txt; collect creds/keys"),
)


def detect_kind(target: str, mode: str | None = None) -> str:
    """Decide 'web' vs 'box'. An explicit mode wins; otherwise a URL or hostname
    target is a web engagement and a bare IP literal is a box (the default). Note a
    box run still does web testing when a web port turns up — this only sets the
    *primary* discipline."""
    if mode in ("web", "box"):
        return mode
    t = (target or "").strip()
    if t.startswith(("http://", "https://")):
        return "web"
    host = t.split("/")[0].split(":")[0]
    if _IPV4.match(host) or (":" in t and _IPV6ish.match(t.split("/")[0])):
        return "box"
    # a name with a letter (has a hostname/TLD) -> treat as a web app engagement
    return "web" if re.search(r"[A-Za-z]", host) else "box"


class Methodology:
    """The chosen methodology for an engagement: its kind and ordered checklist."""

    def __init__(self, kind: str):
        self.kind = "web" if kind == "web" else "box"
        self.steps: tuple[Step, ...] = (WEB_METHODOLOGY if self.kind == "web"
                                        else BOX_METHODOLOGY)

    def objective(self, target: str) -> str:
        if self.kind == "web":
            return (f"Systematically test the web application at {target} against the "
                    f"OWASP WSTG: fingerprint and map it, then work through injection, "
                    f"authentication, access control, and error handling to find, "
                    f"evidence, and report vulnerabilities.")
        return (f"Enumerate {target} fully, examine every service, gain a foothold, "
                f"escalate to root/SYSTEM, and capture the user and root flags.")

    def checklist_text(self) -> str:
        """The methodology rendered as the top-priority reference for the planner."""
        title = ("ENGAGEMENT METHODOLOGY — OWASP WSTG (web application). Work these "
                 "categories in order; each maps to tools in the cage:"
                 if self.kind == "web" else
                 "ENGAGEMENT METHODOLOGY — host/box pentest. Work these phases in order:")
        lines = [title]
        for i, s in enumerate(self.steps, 1):
            ref = f" [{s.ref}]" if s.ref else ""
            hint = f"  — {s.hint}" if s.hint else ""
            lines.append(f"{i}. ({s.phase}){ref} {s.title}{hint}")
        return "\n".join(lines)

    def as_plan_steps(self):
        """The methodology as PlanStep objects, to seed the plan when the model's own
        plan is empty (so a weak model still follows the full checklist)."""
        from .agents.strategist import PlanStep
        return [PlanStep(text=f"{s.title}" + (f" [{s.ref}]" if s.ref else ""),
                         phase=s.phase) for s in self.steps]
