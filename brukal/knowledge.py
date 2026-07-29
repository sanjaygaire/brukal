"""
knowledge.py — remediation / impact / CVSS / references knowledge base.

Turns a bare finding (title + severity) into a professional report entry: a CVSS 3.1
base score + vector, a one-line business IMPACT, concrete REMEDIATION, and standards
REFERENCES (OWASP / CWE). Deterministic lookup keyed by keywords in the finding title,
spanning every domain Brukal covers (web, Active Directory, cloud, mobile), with a
severity-based fallback for anything unmapped. No LLM — a curated table.
"""
from __future__ import annotations

# Each entry: keywords (all-lowercased, ANY match), then the enrichment.
# cvss = (score, vector-tail). impact / remediation are one line each. refs = list.
_KB = [
    (("sql injection", "sqli"), 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Read, modify or destroy the entire database; often a foothold to the host.",
     "Use parameterised queries / prepared statements everywhere; never build SQL from "
     "user input. Apply least-privilege DB accounts and an allowlist ORM.",
     ["OWASP A03:2021 Injection", "CWE-89"]),
    (("os command injection", "command injection"), 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Execute arbitrary OS commands as the web/service account — full host compromise.",
     "Do not pass user input to a shell. Use library calls / argv execution; if a shell "
     "is unavoidable, strictly allowlist and escape. Run the service unprivileged.",
     ["OWASP A03:2021 Injection", "CWE-78"]),
    (("file inclusion", "path traversal", "lfi"), 8.6, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
     "Read arbitrary server files (configs, keys, /etc/passwd); sometimes escalates to RCE.",
     "Never use user input in a file path. Allowlist permitted files; canonicalise and "
     "confine to a base directory; disable remote/URL includes.",
     ["OWASP A01:2021 Broken Access Control", "CWE-22", "CWE-98"]),
    (("template injection", "ssti"), 9.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Execute code via the template engine — typically remote code execution.",
     "Never render user input as a template. Use a logic-less/sandboxed engine and pass "
     "user data only as bound variables.",
     ["OWASP A03:2021 Injection", "CWE-1336", "CWE-94"]),
    (("xss",), 6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
     "Run attacker JavaScript in victims' browsers — session theft, account takeover.",
     "Context-aware output encoding on every sink; a strict Content-Security-Policy; "
     "HttpOnly + SameSite cookies; a trusted-types policy for the DOM.",
     ["OWASP A03:2021 Injection", "CWE-79"]),
    (("open redirect",), 4.3, "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
     "Send users to attacker sites from a trusted domain — phishing, OAuth token theft.",
     "Allowlist redirect destinations; never redirect to a raw user-supplied URL; use "
     "relative paths or an indirection map.",
     ["CWE-601"]),
    (("ssrf", "cloud metadata", "imds"), 9.1, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
     "Force the server to make requests — reach internal services and steal cloud "
     "instance credentials from the metadata service.",
     "Allowlist outbound hosts/schemes; block link-local (169.254.169.254) and internal "
     "ranges; enforce IMDSv2; isolate egress.",
     ["OWASP A10:2021 SSRF", "CWE-918"]),
    (("idor", "object access"), 6.5, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
     "Access or modify other users' objects by changing an identifier.",
     "Enforce per-object authorization on every request (not just authentication); use "
     "unpredictable identifiers; check ownership server-side.",
     ["OWASP A01:2021 Broken Access Control", "CWE-639", "CWE-284"]),
    # --- exposures / secrets ---------------------------------------------------
    (("private key", "service-account key", "aws access key", "github token", "gitlab token",
      "google api key", "stripe", "sendgrid", "slack token", "credentials in uri",
      "secret in exposed", "storage account key", "hardcoded cred"), 8.6,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
     "A leaked secret/key lets an attacker authenticate as the service and reach its data.",
     "Rotate the exposed credential immediately. Move secrets to a vault / secret "
     "manager; never commit or bundle them; scan CI and artifacts for secrets.",
     ["OWASP A07:2021", "CWE-798", "CWE-312"]),
    (("exposed .git", "directory listing", "phpinfo", "server-status", "stack trace",
      "debug info", "terraform state"), 5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Information disclosure — source, config, internals that aid further attack.",
     "Remove the exposed resource from the web root; disable directory listing, debug "
     "endpoints and verbose errors in production.",
     ["OWASP A05:2021 Security Misconfiguration", "CWE-200", "CWE-538"]),
    (("jwt exposed", "api schema"), 4.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "Exposed tokens/API schema widen the attack surface and may allow impersonation.",
     "Do not expose tokens client-side unnecessarily; restrict API docs; short token "
     "lifetimes and validation.",
     ["OWASP A05:2021", "CWE-200"]),
    # --- Active Directory ------------------------------------------------------
    (("kerberoast",), 8.1, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
     "Crack the service account's password offline from its TGS, then impersonate it.",
     "Use 25+ char random service passwords or gMSAs; disable RC4; monitor TGS requests.",
     ["MITRE T1558.003", "CWE-262"]),
    (("as-rep",), 8.1, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Crack a no-preauth account's password offline without any credentials.",
     "Require Kerberos pre-authentication on all accounts; strong passwords.",
     ["MITRE T1558.004"]),
    (("smb signing", "ntlm relay"), 8.1, "AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
     "Relay NTLM authentication to other hosts and act as the victim (often to a DC).",
     "Require SMB signing (and LDAP signing/channel-binding); disable NTLM where possible; "
     "enable EPA.",
     ["MITRE T1557.001", "CWE-300"]),
    (("null", "anonymous", "domain credential", "pwn3d", "host compromised", "ntlm hash dumped",
      "laps", "gmsa", "delegation", "machineaccountquota", "abusable ad acl",
      "ms17-010", "zerologon", "petitpotam"), 8.8, "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
     "A path to domain privilege escalation / compromise.",
     "Remediate the specific misconfiguration (patch, restrict anonymous access, tier "
     "admin accounts, remove unsafe delegation/ACLs, set MachineAccountQuota=0).",
     ["MITRE ATT&CK — Credential Access / Privilege Escalation"]),
    # --- cloud -----------------------------------------------------------------
    (("public s3", "public gcs", "public azure blob", "listable"), 7.5,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Anyone on the internet can list and download the bucket's objects.",
     "Block public access at the account and bucket level; use bucket policies / IAM; "
     "audit ACLs; enable access logging.",
     ["OWASP Cloud", "CWE-284", "CIS Benchmark — Storage"]),
    (("over-permissive iam", "privilege-escalation permission"), 8.2,
     "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
     "An over-broad IAM policy lets a foothold escalate to account-wide control.",
     "Apply least privilege; remove Action:* / Resource:* ; block privesc actions "
     "(PassRole, CreatePolicyVersion, AssumeRole) except where required; use SCPs.",
     ["CWE-269", "CIS Benchmark — IAM"]),
    # --- mobile ----------------------------------------------------------------
    (("exported", "content provider grants", "debuggable", "backup allowed", "cleartext",
      "deep-link", "webview", "disabled tls", "testonly"), 6.5,
     "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
     "A weak app configuration exposes components/data or weakens transport security.",
     "Set exported=false (or require a permission) on components; debuggable=false and "
     "allowBackup=false in release; enforce TLS + certificate pinning; validate deep links.",
     ["OWASP MASVS", "CWE-926", "CWE-319"]),
]

_SEV_CVSS = {"critical": (9.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
             "high": (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
             "medium": (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
             "low": (3.1, "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"),
             "info": (0.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")}


def enrich(title: str, severity: str = "medium") -> dict:
    """Return {cvss, vector, impact, remediation, refs} for a finding. Keyword-matched
    against the KB; falls back to a severity-based CVSS with generic guidance."""
    t = (title or "").lower()
    for keys, score, vec, impact, remediation, refs in _KB:
        if any(k in t for k in keys):
            return {"cvss": score, "vector": vec, "impact": impact,
                    "remediation": remediation, "refs": refs}
    score, vec = _SEV_CVSS.get(severity, _SEV_CVSS["medium"])
    return {"cvss": score, "vector": vec,
            "impact": "Weakens the security posture of the target.",
            "remediation": "Review and remediate per the referenced standard; retest.",
            "refs": ["OWASP Top 10"]}
