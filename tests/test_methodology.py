"""
test_methodology.py — mode-aware methodology (OWASP WSTG for web, box flow for a host).

Pins:
  * detect_kind picks web vs box from the target (URL/hostname vs IP), with an
    explicit override winning.
  * the web methodology is OWASP-WSTG-aligned (carries WSTG ids); the box one runs
    enumeration → foothold → privesc → loot.
  * the session injects the methodology as the top-priority planner reference and
    seeds the objective, and falls back to the checklist when the model's plan is thin.
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
from brukal.methodology import BOX_METHODOLOGY, WEB_METHODOLOGY, Methodology, detect_kind

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"


class SeqLLM:
    def __init__(self, responses):
        self.responses, self.i = list(responses), 0

    def propose(self, system, user, max_tokens=1024):
        r = self.responses[min(self.i, len(self.responses) - 1)]
        self.i += 1
        return r


def test_detect_kind_web_vs_box():
    assert detect_kind("10.10.10.5") == "box"
    assert detect_kind("10.129.234.54") == "box"
    assert detect_kind("http://nexus.htb/") == "web"
    assert detect_kind("billing.nexus.htb") == "web"
    assert detect_kind("example.com/app") == "web"
    # explicit override wins over the heuristic
    assert detect_kind("10.10.10.5", mode="web") == "web"
    assert detect_kind("shop.example.com", mode="box") == "box"


def test_web_methodology_is_wstg_aligned():
    m = Methodology("web")
    assert m.kind == "web" and m.steps is WEB_METHODOLOGY
    refs = {s.ref for s in m.steps}
    assert "WSTG-INPV" in refs and "WSTG-ATHZ" in refs and "WSTG-ERRH" in refs
    text = m.checklist_text()
    assert "OWASP WSTG" in text and "injection" in text.lower()
    assert "WSTG" in m.objective("h").upper() or "wstg" in m.objective("h").lower()


def test_box_methodology_runs_enum_to_loot():
    m = Methodology("box")
    assert m.steps is BOX_METHODOLOGY
    phases = [s.phase for s in m.steps]
    assert phases[0] == "enumeration"
    assert "exploitation" in phases and "privilege-escalation" in phases
    assert phases[-1] == "looting"
    assert "flag" in m.objective("10.10.10.5").lower()


def _session(target):
    tmp = tempfile.mkdtemp()
    ex = Executor(Gate(load_scope(SCOPE)), FakeKali(), AuditLog(Path(tmp) / "a.jsonl"))
    return AssistSession(target, ex, StrategistAgent(SeqLLM(["x"]))), tmp


def test_session_sets_methodology_and_grounds_the_reference():
    sess, tmp = _session("http://target.example/")
    try:
        m = sess.set_methodology()                 # detected: web
        assert m.kind == "web"
        assert sess.objectives                      # objective was seeded
        ref = sess._reference("input validation")
        assert "ENGAGEMENT METHODOLOGY" in ref      # top-priority reference block
        assert "WSTG" in ref
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_thin_model_plan_falls_back_to_the_methodology_checklist():
    sess, tmp = _session("10.10.10.5")
    try:
        sess.set_methodology("box")
        # the strategist returns a one-line (thin) plan
        sess.strategist = StrategistAgent(SeqLLM(["1. [recon] look around"]))
        plan = sess.make_plan()
        # fell back to the full box checklist instead of the thin single step
        assert len(plan) == len(BOX_METHODOLOGY)
        assert [p.phase for p in plan][0] == "enumeration"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_auto_honours_an_explicit_web_mode(monkeypatch, tmp_path):
    """Regression: `brukal auto --web` was silently ignored. run_auto built the banner's
    display string into a variable literally named `mode`, clobbering the caller's
    web/box selector before set_methodology saw it — so detect_kind fell back to target
    detection and every IP target ran the BOX methodology, even when --web was passed."""
    import brukal.assist as A
    import brukal.loop as L
    from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
    from brukal.agents import StrategistAgent

    scope = load_scope(str(SCOPE))
    (tmp_path / "a.jsonl").touch()          # run_auto verifies the chain on the way out
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    sess = A.AssistSession("10.10.10.5", ex,
                           StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()))
    sess.plan = [type("S", (), {"text": "x", "done": True, "phase": ""})()]

    monkeypatch.setattr(A, "_prepare_session",
                        lambda *a, **k: (sess, audit, "10.10.10.5", "fake"))

    class _StubLoop:
        def __init__(self, *a, **k):
            pass

        def run(self):
            return type("R", (), {"stop_reason": "budget", "stop_detail": "",
                                  "solved": False, "steps": [], "status": "budget",
                                  "executed": 0, "blocked": 0})()

    monkeypatch.setattr(L, "GroundedLoop", _StubLoop)
    A.run_auto("10.10.10.5", fake=True, yes_authorised=True, mode="web",
               handoff_to_menu=False, max_steps=1, resume=False)
    # a bare IP would detect as 'box'; the explicit flag must win
    assert sess.methodology.kind == "web"
