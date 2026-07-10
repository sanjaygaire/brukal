"""
risk.py — Milestone 3: the SOFT risk layer (Layer 2 of the Trust Governance Plane).

Runs ONLY after the deterministic hard gate has already confirmed an action is
in-scope, allowlisted, injection-free and under the rate limit. It therefore
**cannot widen scope or overturn a hard DENY** — it can only add caution: leave a
safe action ALLOWed, raise a broad-or-irreversible one to ESCALATE (human
sign-off), or refuse one that crosses the risk ceiling (DENY).

Like the hard gate, this layer contains **no language model**. Reversibility and
blast radius are derived deterministically from the *command text itself* — never
from the agent's self-declared `intent` (invariant 3) — so the soft layer is as
untrickable as the hard one (invariant 1). Anything it cannot classify is treated
as *more* dangerous, never less (invariant 2, fail-closed).

Two scalar risk features, each in {0,1,2}, are summed into a 0–4 score:

    reversibility : reversible(0)  < unknown(1)  < irreversible(2)
    blast_radius  : host(0)        < subnet(1)   < wide(2)

    score <= THETA_LOW (0)      -> LOW    -> ALLOW
    THETA_LOW < score <= THETA_HIGH (2) -> MEDIUM -> ESCALATE
    score >  THETA_HIGH (2)     -> HIGH   -> DENY

Milestone 6 will feed an *adaptive per-agent trust* value into `assess` (lower
trust => more caution). Milestone 3 uses the neutral default `trust=1.0`, which
adds nothing, so M3's behaviour is a pure function of the command.
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass

# ---- feature vocabulary (ordered least -> most risky) ----------------------
_REVERSIBILITY = ("reversible", "unknown", "irreversible")
_BLAST = ("host", "subnet", "wide")
_REV_WEIGHT = {"reversible": 0, "unknown": 1, "irreversible": 2}
_BLAST_WEIGHT = {"host": 0, "subnet": 1, "wide": 2}

# ---- decision thresholds ----------------------------------------------------
THETA_LOW = 0    # score <= THETA_LOW              -> ALLOW
THETA_HIGH = 2   # THETA_LOW < score <= THETA_HIGH -> ESCALATE ; above -> DENY
_TRUST_SCALE = 2  # a fully-distrusted agent (trust=0) adds +2 to every score

# ---- what the current allowlist can do -------------------------------------
# Tools that observe but do not change target state. Traffic *volume* is a
# blast-radius concern (handled below), not a reversibility one.
_READ_ONLY_TOOLS = frozenset(
    {"nmap", "gobuster", "nikto", "whatweb", "curl", "wget", "dig", "host", "dnsutils",
     # read-only enumeration tools. Write-capable ones (smbclient, redis-cli,
     # ldapsearch-with-writes) are deliberately left out, so they score as
     # "unknown" and the soft layer escalates them.
     "ffuf", "feroxbuster", "wafw00f", "dirb", "wfuzz",
     "dnsrecon", "dnsenum", "fierce", "sslscan", "sslyze",
     "smbmap", "enum4linux", "enum4linux-ng", "nbtscan", "snmpwalk", "onesixtyone",
     "searchsploit", "hashid", "hash-identifier"}
)

# Tools that actively ATTACK a target (brute force, exploitation, cracking,
# shells). They are ALLOWLISTED — an operator can use them — but they are always
# IRREVERSIBLE, so the soft layer routes them to human sign-off (ESCALATE) on a
# single host and refuses them (DENY) once the blast radius widens. Capability
# grows; the safety boundary does not.
_ATTACK_TOOLS = frozenset(
    {"hydra", "medusa", "ncrack", "patator",          # credential brute force
     "sqlmap", "wpscan", "nuclei", "masscan",         # active web / mass probing
     "crackmapexec", "netexec", "nxc", "kerbrute", "responder", "evil-winrm",
     "impacket-secretsdump", "impacket-psexec", "impacket-smbexec",
     "impacket-wmiexec", "impacket-getuserspns", "impacket-getnpusers",
     "john", "hashcat",                               # offline cracking
     "msfconsole", "msfvenom", "metasploit",          # exploitation framework
     "nc", "ncat", "netcat", "socat"}                 # shells / transfer
)

# Signals that an action WRITES / ATTACKS remote state -> irreversible.
_HTTP_WRITE_METHODS = {"post", "put", "delete", "patch"}
_CURL_BODY_FLAGS = {"-d", "--data", "--data-raw", "--data-binary",
                    "--data-urlencode", "-T", "--upload-file"}
_IRREVERSIBLE_SCRIPT_CATS = {"exploit", "dos", "intrusive", "malware"}

# Signals that widen the blast radius even against a single host.
_AGGRESSIVE_TOKENS = {"-p-", "-A", "-T4", "-T5"}
_AGGRESSIVE_SCRIPT_CATS = {"vuln", "brute", "all",
                           "exploit", "dos", "intrusive", "malware"}

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/(\d{1,2})\b")
_DASH_RANGE_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\b")


@dataclass(frozen=True)
class RiskProfile:
    """Deterministic soft-risk assessment of one command."""
    reversibility: str   # "reversible" | "unknown" | "irreversible"
    blast_radius: str    # "host" | "subnet" | "wide"
    score: int           # 0..(4 + trust penalty)
    band: str            # "LOW" | "MEDIUM" | "HIGH"
    decision: str        # "ALLOW" | "ESCALATE" | "DENY"
    reason: str


def _tokens(command: str) -> list[str]:
    """Best-effort shell tokenisation. Fail-closed: unparseable -> empty list,
    which the callers treat as maximally risky (unknown + wide)."""
    try:
        return shlex.split(command)
    except ValueError:
        return []


def _script_categories(tokens: list[str]) -> set[str]:
    """Categories named in an nmap `--script <cats>` / `--script=<cats>` arg."""
    cats: set[str] = set()
    for i, tok in enumerate(tokens):
        val = None
        if tok == "--script" and i + 1 < len(tokens):
            val = tokens[i + 1]
        elif tok.startswith("--script="):
            val = tok.split("=", 1)[1]
        if val:
            for part in re.split(r"[,\s]+", val.lower()):
                if part:
                    cats.add(part)
    return cats


def derive_reversibility(command: str) -> str:
    """Does this command change remote state? Read-only recon -> reversible;
    writes / active exploitation -> irreversible; anything unrecognised ->
    unknown (fail toward caution)."""
    tokens = _tokens(command)
    if not tokens:
        return "unknown"
    tool = os.path.basename(tokens[0]).lower()

    if tool == "curl":
        low = [t.lower() for t in tokens]
        if any(f in low for f in _CURL_BODY_FLAGS):
            return "irreversible"
        for i, t in enumerate(low):
            if t in ("-x", "--request") and i + 1 < len(low):
                if low[i + 1] in _HTTP_WRITE_METHODS:
                    return "irreversible"

    if tool == "nmap":
        if _script_categories(tokens) & _IRREVERSIBLE_SCRIPT_CATS:
            return "irreversible"

    if tool in _ATTACK_TOOLS:
        return "irreversible"          # brute/exploit/shell -> always needs sign-off
    if tool in _READ_ONLY_TOOLS:
        return "reversible"
    return "unknown"


def derive_blast_radius(command: str) -> str:
    """How much surface does this command touch? One host -> host; a small
    range / several hosts -> subnet; a large network or aggressive breadth
    modifiers -> wide."""
    tokens = _tokens(command)
    idx = 0  # host

    if len({ip for ip in _IPV4_RE.findall(command)}) > 1:
        idx = max(idx, 1)  # several distinct hosts

    for prefix_s in _CIDR_RE.findall(command):
        prefix = int(prefix_s)
        idx = max(idx, 2 if prefix <= 24 else 1)  # <=/24 is wide, /25.. is subnet

    if _DASH_RANGE_RE.search(command):
        idx = max(idx, 1)

    aggressive = any(t in _AGGRESSIVE_TOKENS for t in tokens) or \
        bool(_script_categories(tokens) & _AGGRESSIVE_SCRIPT_CATS)
    if aggressive:
        idx = min(idx + 1, 2)  # bump one band, capped at wide

    return _BLAST[idx]


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def assess(command: str, *, trust: float = 1.0) -> RiskProfile:
    """Deterministically assess one command and return its RiskProfile.

    `trust` in [0,1] is the milestone-6 adaptive-trust hook: at the default 1.0
    it adds nothing; lower values add a caution penalty so a distrusted agent's
    same action lands in a higher risk band. The soft layer only ever tightens.
    """
    rev = derive_reversibility(command)
    blast = derive_blast_radius(command)
    score = _REV_WEIGHT[rev] + _BLAST_WEIGHT[blast]
    score += round((1.0 - _clamp01(trust)) * _TRUST_SCALE)

    if score <= THETA_LOW:
        band, decision = "LOW", "ALLOW"
    elif score <= THETA_HIGH:
        band, decision = "MEDIUM", "ESCALATE"
    else:
        band, decision = "HIGH", "DENY"

    reason = (f"reversibility={rev}, blast={blast}, "
              f"risk_score={score} -> {band}")
    return RiskProfile(rev, blast, score, band, decision, reason)
