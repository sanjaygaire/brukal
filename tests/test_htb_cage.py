"""
test_htb_cage.py — the HTB-ready cage calibration.

The wider enumeration allowlist is scored sensibly: read-only enum tools ALLOW,
write-capable ones (smbclient) stay conservative and escalate. And the cage runs
approved tools as the non-root user.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import assess
from brukal.kali import DockerKali


def test_read_only_enum_tools_allow():
    for cmd in ("ffuf -u http://10.10.10.5 -w list.txt",
                "feroxbuster -u http://10.10.10.5",
                "smbmap -H 10.10.10.5",
                "enum4linux 10.10.10.5",
                "sslscan 10.10.10.5"):
        p = assess(cmd)
        assert p.reversibility == "reversible", cmd
        assert p.decision == "ALLOW", cmd


def test_write_capable_tool_stays_conservative():
    p = assess("smbclient //10.10.10.5/share")
    assert p.reversibility == "unknown"        # not read-only -> soft layer escalates
    assert p.decision == "ESCALATE"


def test_dockerkali_execs_as_nonroot(monkeypatch):
    import brukal.kali as kali

    captured = {}

    class _Proc:
        returncode, stdout, stderr = 0, "ok", ""

    def fake_run(argv, **kw):
        captured["argv"] = argv
        return _Proc()

    monkeypatch.setattr(kali.subprocess, "run", fake_run)
    DockerKali(container="c").run("nmap -sV 10.10.10.5")
    assert captured["argv"][:5] == ["docker", "exec", "-u", "brukalop", "c"]
