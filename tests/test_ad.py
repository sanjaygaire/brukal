"""
test_ad.py — the Active Directory / internal-network detector.

Pins that adscan.scan_ad_output turns the REAL output of the AD/SMB/Kerberos tools
(netexec/crackmapexec, impacket-*, enum4linux, secretsdump, ...) into structured
findings — captured roast hashes, SMB signing off, null sessions, Pwn3d! admin, valid
domain creds, MS17-010 — with no false positives on benign output; that a session
records them as active-directory findings (definitive ones CONFIRMED); and that the AD
methodology surfaces to the planner once a Windows host is in scope. No live DC needed:
the samples are real tool-output formats.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal import adscan

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "scope.json"


def _labels(text):
    return [l for _s, l, _e in adscan.scan_ad_output(text)]


def test_detects_core_ad_attack_indicators():
    nxc = ("SMB  10.10.10.5  445  DC01  [*] Windows Server 2019 (name:DC01) "
           "(domain:corp.local) (signing:False) (SMBv1:True)\n"
           "SMB  10.10.10.5  445  DC01  [+] corp.local\\admin:Password123 (Pwn3d!)")
    L = _labels(nxc)
    assert "Local admin / host compromised" in L
    assert "SMB signing not required (NTLM relay)" in L

    assert "Kerberoastable account (TGS hash captured)" in _labels(
        "$krb5tgs$23$*svc_sql$CORP.LOCAL$corp.local/svc_sql*$a1b2c3...")
    assert "AS-REP roastable account (hash captured)" in _labels(
        "$krb5asrep$23$user@CORP.LOCAL:aabbcc...")
    assert "NTLM hash dumped (secretsdump)" in _labels(
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::")
    assert "Null / anonymous SMB session allowed" in _labels(
        "[+] Server 10.10.10.5 allows sessions using username '', password ''")
    assert "MS17-010 (EternalBlue) vulnerable" in _labels(
        "SMB  10.10.10.5  445  HOST  [+] HOST (MS17-010) vulnerable")
    assert "Unconstrained delegation configured" in _labels(
        "userAccountControl: TRUSTED_FOR_DELEGATION")
    assert "Password in an AD object description" in _labels(
        "description: default password is Summer2024!")


def test_no_false_positive_on_benign_output():
    assert adscan.scan_ad_output("Nmap done. Host is up. 3 ports open. nothing else.") == []
    assert adscan.scan_ad_output("SMB  10.10.10.5  445  DC01  (signing:True) (SMBv1:False)") == []


def test_is_ad_tool():
    assert adscan.is_ad_tool("netexec smb 10.10.10.5 -u a -p b")
    assert adscan.is_ad_tool("impacket-GetUserSPNs corp.local/user:pass")
    assert not adscan.is_ad_tool("curl http://10.10.10.5/")


def _session():
    scope = load_scope(FIXTURE)
    ex = Executor(Gate(scope), FakeKali(), AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl"))
    return AssistSession("10.10.10.5", ex, StrategistAgent(type("L", (), {
        "propose": lambda *a, **k: ""})()))


def test_session_records_confirmed_ad_finding():
    sess = _session()
    # simulate the absorb path: an AD tool ran and produced a Pwn3d! + roast hash
    out = ("SMB 10.10.10.5 445 DC01 [+] corp.local\\admin:Pw (Pwn3d!)\n"
           "$krb5tgs$23$*svc$CORP$...")
    for sev, label, line in adscan.scan_ad_output(out):
        sess._record_ad_finding("netexec smb 10.10.10.5 -u admin -p Pw", sev, label, line)
    titles = {f.title: f for f in sess.findings.all()}
    assert titles["Local admin / host compromised"].confirmed is True
    assert titles["Local admin / host compromised"].category == "active-directory"
    assert titles["Kerberoastable account (TGS hash captured)"].confirmed is True


def test_ad_methodology_surfaces_when_ad_host_detected():
    sess = _session()
    assert "ACTIVE DIRECTORY" not in sess._reference("")
    sess.highlights.append(("port", "445/tcp open microsoft-ds"))
    ref = sess._reference("")
    assert "ACTIVE DIRECTORY" in ref and "kerberoast" in ref.lower()
