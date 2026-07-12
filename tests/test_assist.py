"""
test_assist.py — human-assisted solving (the strategist + the session).

Proves the strategist parses RUN/MANUAL advice, and — the key property — that a
command the strategist *suggests* is not a bypass: when the operator runs it, it
still goes through the gate. An out-of-scope suggestion is denied exactly as
always, and manual/notes are recorded for the trail.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession

SCOPE = Path(__file__).resolve().parents[1] / "scope.json"


class StubLLM:
    def __init__(self, response):
        self.response = response
        self.last_user = None

    def propose(self, system, user, max_tokens=1024):
        self.last_user = user
        return self.response


def test_strategist_parses_phase_goal_run_and_manual():
    llm = StubLLM("PHASE: enumeration\n"
                  "GOAL: fingerprint the web app on port 3000\n"
                  "REASONING: Port 3000 is a web app, so enumerate it before attacking.\n"
                  "RUN: whatweb http://10.10.10.5:3000\n"
                  "MANUAL: try default creds admin:admin in the login form")
    s = StrategistAgent(llm).advise("10.10.10.5", "port 3000 open")
    assert s.command == "whatweb http://10.10.10.5:3000"
    assert s.target == "10.10.10.5"
    assert s.phase == "enumeration"
    assert "fingerprint" in s.goal
    assert "default creds" in s.manual
    assert "enumerate it" in s.rationale


def test_highlight_findings_surfaces_key_results():
    from brukal.assist import highlight_findings
    out = ("Starting Nmap...\n"
           "22/tcp open  ssh     OpenSSH 8.2p1\n"
           "80/tcp open  http    Apache httpd 2.4.41\n"
           "Nmap done: 1 IP address\n")
    hits = highlight_findings(out)
    lines = " ".join(l for _, l in hits)
    assert "22/tcp open" in lines and "80/tcp open" in lines
    assert "Nmap done" not in lines            # noise is filtered out


def test_strategist_strips_trailing_parenthetical():
    # local models often append a "(why)" note to the RUN line — it must not end
    # up in the command that gets executed.
    llm = StubLLM("REASONING: Comprehensive scan first.\n"
                  "RUN: nmap -sV -p- 10.129.51.151   (to enumerate all services)")
    s = StrategistAgent(llm).advise("10.129.51.151", "")
    assert s.command == "nmap -sV -p- 10.129.51.151"


def test_strategist_advice_only():
    s = StrategistAgent(StubLLM("Enumerate more before exploiting.")).advise("10.10.10.5", "")
    assert s.command is None and s.manual is None
    assert "Enumerate" in s.rationale


def test_suggested_command_still_goes_through_the_gate():
    scope = load_scope(SCOPE)
    tmp = tempfile.mkdtemp()
    try:
        kali = FakeKali()
        ex = Executor(Gate(scope), kali, AuditLog(Path(tmp) / "a.jsonl"))
        sess = AssistSession("10.10.10.5", ex,
                             StrategistAgent(StubLLM("RUN: nmap -sV 10.10.10.5")))

        sug = sess.advise()
        d, r, _ = sess.run(sug.command)
        assert d.verdict == "ALLOW" and r is not None
        assert kali.executed == ["nmap -sV 10.10.10.5"]

        # a suggestion pointed off-scope is STILL denied when the operator runs it
        d2, r2, _ = sess.run("nmap -sV 8.8.8.8", "8.8.8.8")
        assert d2.verdict == "DENY" and r2 is None
        assert kali.executed == ["nmap -sV 10.10.10.5"]     # not executed

        sess.note("found /admin panel")
        sess.manual("got a shell as www-data")
        assert any("found /admin" in n for n in sess.notes)
        assert any("www-data" in n for n in sess.notes)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
