"""
test_webprobe.py — turning the crawl map into governed vuln probes.

Pins the Phase-2 behaviour:

  * plan_probes() deterministically emits the right commands from a surface —
    passive fingerprint/scan per root, active injection tests per real parameter and
    form — categorised and capped.
  * the passive probes auto-run through the loop the moment the surface is known
    (deterministic coverage), while the active ones ESCALATE for sign-off and only
    run under --full-send (governance is the gate's, unchanged).
  * scan_output() flags real vulnerability signals in probe output.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope, webmap, webprobe
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession, _auto_approver, _full_send_approver
from brukal.loop import GroundedLoop

SCOPE = Path(__file__).resolve().parents[1] / "scope.json"
TARGET = "10.10.10.5"


class SeqLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.i = 0

    def propose(self, system, user, max_tokens=1024):
        r = self.responses[min(self.i, len(self.responses) - 1)]
        self.i += 1
        return r


def _surface():
    s = webmap.AttackSurface(seed="http://10.10.10.5/")
    s.pages = {"http://10.10.10.5/", "http://10.10.10.5/search?q=1"}
    s.links = {"http://10.10.10.5/search?q=1", "http://10.10.10.5/product?id=5"}
    s.params = {"http://10.10.10.5/search": {"q"}, "http://10.10.10.5/product": {"id"}}
    s.forms = [webmap.Form(action="http://10.10.10.5/login", method="POST",
                           inputs=(("user", "text"), ("pw", "password")))]
    return s


# ---- planner --------------------------------------------------------------- #

def test_plan_probes_emits_passive_per_root_and_active_per_param_and_form():
    probes = webprobe.plan_probes(_surface(), TARGET)
    passive = [p for p in probes if p.category == "passive"]
    active = [p for p in probes if p.category == "active"]

    # passive: fingerprint + read-only scanners against the one web root
    assert {p.tool for p in passive} == {"whatweb", "nuclei", "nikto"}
    assert all("http://10.10.10.5/" in p.command for p in passive)

    # active: sqlmap + dalfox against each discovered parameter, on clean single-param URLs
    cmds = " ".join(p.command for p in active)
    assert 'sqlmap -u "http://10.10.10.5/search?q=1" -p q' in cmds
    assert 'dalfox url "http://10.10.10.5/search?q=1" -p q' in cmds
    assert 'sqlmap -u "http://10.10.10.5/product?id=1" -p id' in cmds
    # the POST form is tested via its body
    assert any(p.tool == "sqlmap" and '--data "user=1"' in p.command for p in active)


def test_plan_probes_caps_active_count():
    probes = webprobe.plan_probes(_surface(), TARGET, max_active=2)
    assert sum(p.category == "active" for p in probes) <= 2


def test_plan_probes_defaults_to_target_root_without_a_crawl():
    empty = webmap.AttackSurface()
    probes = webprobe.plan_probes(empty, TARGET)
    assert any(p.command == "whatweb http://10.10.10.5/" for p in probes)
    assert not [p for p in probes if p.category == "active"]      # nothing to inject into


# ---- signal detection ------------------------------------------------------ #

def test_scan_output_flags_vulnerability_signals():
    sql = "sqlmap: parameter 'q' is injectable ... back-end DBMS: MySQL"
    hits = webprobe.scan_output(sql)
    assert any(sev == "high" for sev, _l, _line in hits)

    nuc = "[critical] apache-struts-rce CVE-2017-5638 http://h/x"
    labels = {label for _s, label, _l in webprobe.scan_output(nuc)}
    assert "nuclei finding" in labels and "known CVE" in labels

    assert webprobe.scan_output("nothing interesting here") == []


# ---- governed execution through the loop ----------------------------------- #

def _session(approver=None, **kw):
    tmp = tempfile.mkdtemp()
    kali = FakeKali()
    ex = Executor(Gate(load_scope(SCOPE)), kali, AuditLog(Path(tmp) / "a.jsonl"),
                  approver=approver)
    sess = AssistSession(TARGET, ex, StrategistAgent(SeqLLM(
        ["PHASE: recon\nGOAL: hand off\nREASONING: over.\nMANUAL: your move"])), **kw)
    return sess, kali, tmp


def test_loop_auto_runs_passive_probes_once_surface_is_known():
    sess, kali, tmp = _session()
    try:
        sess.surface = _surface()                 # pretend the crawl already ran
        loop = GroundedLoop(sess, max_steps=10)
        loop.run()
        # every passive probe ran through the gate (reversible -> ALLOW), the model
        # never had to propose them
        assert any("whatweb http://10.10.10.5/" in c for c in kali.executed)
        assert any(c.startswith("nuclei ") for c in kali.executed)
        assert any(c.startswith("nikto ") for c in kali.executed)
        # active probes are NOT auto-run
        assert not any("sqlmap" in c or "dalfox" in c for c in kali.executed)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_active_probe_escalates_when_governed_and_runs_under_full_send():
    active = [p for p in webprobe.plan_probes(_surface(), TARGET)
              if p.tool == "sqlmap"][0].command

    # governed (reversible-only) approver: an active injection probe ESCALATEs and
    # is NOT run.
    sess, kali, tmp = _session(approver=_auto_approver)
    try:
        d, r, _ = sess.run(active, agent="exploit")
        assert r is None and d.verdict == "ESCALATE"
        assert kali.executed == []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # full-send approver: the same probe runs.
    sess, kali, tmp = _session(approver=_full_send_approver)
    try:
        d, r, _ = sess.run(active, agent="exploit")
        assert r is not None
        assert any("sqlmap" in c for c in kali.executed)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_active_probes_surface_to_the_planner_as_suggestions():
    sess, kali, tmp = _session()
    try:
        sess.surface = _surface()
        text = sess._highlights_text()
        assert "SUGGESTED ACTIVE PROBES" in text
        assert "sqlmap" in text and "dalfox" in text
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
