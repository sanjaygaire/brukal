"""
adscan.py — Active Directory / internal-network finding detector.

The AD equivalent of webprobe: deterministic signatures over the real output of the
AD/SMB/Kerberos tools the cage ships (netexec/crackmapexec/nxc, impacket-*, kerbrute,
enum4linux(-ng), ldapsearch, rpcclient, smbclient, responder). Each is a genuine
attack indicator on a Windows domain — a captured Kerberoast/AS-REP hash, SMB signing
not required (NTLM relay), a null session, valid domain creds, `Pwn3d!` admin access,
MS17-010, unconstrained delegation, a password in a user description, a non-zero
MachineAccountQuota (add-computer), readable LAPS.

Deterministic pattern-matching over UNTRUSTED tool output — a hit becomes a recorded
FINDING (evidence for the operator), never an action; every command that produced the
output already went through the one gate. No LLM here.
"""
from __future__ import annotations

import re

# (compiled regex, severity, label). Ordered most-severe first for readability.
_AD_SIGNALS = (
    # --- domain compromise / admin access --------------------------------------
    (re.compile(r"\(Pwn3d!\)"), "critical", "Local admin / host compromised"),
    (re.compile(r"\bMS17-010\b|EternalBlue", re.I), "critical", "MS17-010 (EternalBlue) vulnerable"),
    (re.compile(r"\bZerologon\b|CVE-2020-1472", re.I), "critical", "Zerologon (CVE-2020-1472) vulnerable"),
    (re.compile(r"PetitPotam|CVE-2021-36942|PrinterBug|MS-RPRN", re.I),
     "critical", "Coercion vector (PetitPotam / PrinterBug)"),
    # --- credentials -----------------------------------------------------------
    (re.compile(r"\$krb5tgs\$\d+\$"), "high", "Kerberoastable account (TGS hash captured)"),
    (re.compile(r"\$krb5asrep\$\d+\$"), "high", "AS-REP roastable account (hash captured)"),
    (re.compile(r"(?im)^\s*[\w.-]+\\[\w.$-]+:[^\s:]{3,}\s.*\bMachine\b", ), "high",
     "Machine account hash / NTLM secret dumped"),
    (re.compile(r"\b[0-9a-f]{32}:[0-9a-f]{32}:::", re.I), "high", "NTLM hash dumped (secretsdump)"),
    (re.compile(r"\[\+\]\s+[\w.-]+\\[\w.$-]+:[^\s]+\s*(?:\((?!Pwn3d)|$)"), "high",
     "Valid domain credentials"),
    (re.compile(r"(?i)description[:=].{0,60}?(?:pass(?:word)?|pwd|creds?)\b[:=\s]"),
     "high", "Password in an AD object description"),
    (re.compile(r"ms-Mcs-AdmPwd\s*[:=]\s*\S", re.I), "high", "LAPS password readable"),
    (re.compile(r"gMSA|ReadGMSAPassword|msDS-ManagedPassword", re.I),
     "high", "Readable gMSA password"),
    # --- delegation / ACL abuse paths -----------------------------------------
    (re.compile(r"TRUSTED_FOR_DELEGATION\b"), "high", "Unconstrained delegation configured"),
    (re.compile(r"msDS-AllowedToDelegateTo|constrained delegation", re.I),
     "high", "Constrained delegation configured"),
    (re.compile(r"GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword|AddMember",
                re.I), "high", "Abusable AD ACL right"),
    # --- misconfig / relay / recon --------------------------------------------
    (re.compile(r"(?i)signing\s*[:=]\s*False|signing\s*required\s*[:=]\s*False|SMB signing\s*:\s*False"),
     "high", "SMB signing not required (NTLM relay)"),
    (re.compile(r"(?i)(?:allows? sessions using|null session).{0,40}?(?:username\s*['\"]{2}|anonymous)"),
     "high", "Null / anonymous SMB session allowed"),
    (re.compile(r"(?i)anonymous (?:bind|ldap|access) (?:allowed|succeeded|successful)"),
     "medium", "Anonymous LDAP bind allowed"),
    (re.compile(r"(?i)ms-DS-MachineAccountQuota\s*[:=]\s*(?![0]\b)\d+|MachineAccountQuota:\s*(?!0\b)\d+"),
     "medium", "Non-zero MachineAccountQuota (add rogue computer)"),
    (re.compile(r"(?i)PASSWD_NOTREQD|password not required"), "medium",
     "Account with PASSWD_NOTREQD"),
    (re.compile(r"(?i)(?:pre-?auth(?:entication)? not required|DONT_REQ_PREAUTH)"),
     "medium", "Kerberos pre-auth not required (AS-REP roastable)"),
    (re.compile(r"(?i)LLMNR|NBT-NS|mDNS.*poison|Responder"), "medium",
     "LLMNR/NBT-NS poisoning surface"),
    (re.compile(r"(?i)password (?:never expires|age)\s*[:=]\s*0|MinimumPasswordLength:\s*[0-5]\b"),
     "medium", "Weak domain password policy"),
    (re.compile(r"(?i)\[SMBv1\]|SMB1\s*[:=]\s*True|SMBv1 enabled"), "medium", "SMBv1 enabled"),
)


def scan_ad_output(text: str) -> list[tuple[str, str, str]]:
    """Scan the real output of an AD/SMB/Kerberos tool for attack indicators. Returns a
    list of (severity, label, evidence-line). Deterministic; flags for the operator,
    never acts."""
    hits: list[tuple[str, str, str]] = []
    seen: set = set()
    for rx, sev, label in _AD_SIGNALS:
        for m in rx.finditer(text or ""):
            line = (m.group(0) or "").strip()[:160]
            if label not in seen:               # one finding per class per scan
                seen.add(label)
                hits.append((sev, label, line))
            break
    return hits


# Tools whose stdout this detector understands — used to decide when to run it.
AD_TOOLS = frozenset({
    "netexec", "nxc", "crackmapexec", "cme", "kerbrute", "enum4linux", "enum4linux-ng",
    "ldapsearch", "rpcclient", "smbclient", "smbmap", "responder", "bloodhound-python",
    "getuserspns.py", "getnpusers.py", "secretsdump.py", "gettgt.py", "certipy",
    "impacket-getuserspns", "impacket-getnpusers", "impacket-secretsdump",
    "impacket-ntlmrelayx", "ntlmrelayx.py", "nmap",
})


def is_ad_tool(command: str) -> bool:
    """True if the command's tool emits AD/SMB/Kerberos output worth scanning."""
    import shlex
    try:
        toks = shlex.split(command)
    except ValueError:
        return False
    if not toks:
        return False
    tool = toks[0].rsplit("/", 1)[-1].lower()
    return tool in AD_TOOLS


# A compact methodology the planner follows once a Windows/AD host is in scope. Injected
# as a REFERENCE (data, not instruction); every proposed command still hits the gate.
METHODOLOGY = (
    "ACTIVE DIRECTORY / INTERNAL METHODOLOGY (a DC or SMB/LDAP/Kerberos host is in scope):\n"
    "1. Enumerate unauthenticated: nmap -p88,135,139,389,445,636,3268,5985; "
    "netexec smb <ip> (signing, SMBv1, null session); enum4linux-ng -A <ip>; "
    "ldapsearch -x -H ldap://<ip> -s base (naming context).\n"
    "2. Valid creds → spray/auth: netexec smb <ip> -u <user> -p <pass> --shares --users "
    "--pass-pol; netexec ldap <ip> -u -p --kerberoasting out.txt --asreproast out.txt.\n"
    "3. Roast: impacket-GetUserSPNs / GetNPUsers → crack offline (hashcat).\n"
    "4. Escalate: BloodHound for ACL/delegation paths; abuse GenericAll/WriteDacl, "
    "unconstrained/constrained delegation, LAPS/gMSA reads, non-zero MachineAccountQuota.\n"
    "5. Compromise: secretsdump on Pwn3d! hosts; watch for MS17-010 / Zerologon / PetitPotam.\n"
    "One tool per step, real target IP, in scope. Cracking is offline/local; never brute "
    "an account lockout online without sign-off."
)
