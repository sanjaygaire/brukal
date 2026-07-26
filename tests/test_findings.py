"""
test_findings.py — the structured findings model + report deliverable (Phase 3).

Pins:
  * FindingStore dedupes by (title, target, param), keeps the strongest severity,
    OR-s confirmation, and persists append-only (survives a reload).
  * a vuln signal in real command output becomes a structured finding, and the
    confirmed/candidate split matches the signal strength.
  * a Verifier-confirmed success is recorded as a CRITICAL confirmed finding.
  * build_report renders findings + evidence; report.json round-trips.
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
from brukal.findings import Finding, FindingStore
from brukal.report import build_report, report_json

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"
TARGET = "10.10.10.5"


class SeqLLM:
    def __init__(self, responses):
        self.responses, self.i = list(responses), 0

    def propose(self, system, user, max_tokens=1024):
        r = self.responses[min(self.i, len(self.responses) - 1)]
        self.i += 1
        return r


# ---- store ---------------------------------------------------------------- #

def test_store_dedupes_and_keeps_strongest_severity_and_confirmation():
    s = FindingStore()
    assert s.add(Finding("SQL injection", "medium", "http://h/s", param="q"))     # new
    # same signature, stronger severity + confirmed -> merged, not a new finding
    assert not s.add(Finding("SQL injection", "high", "http://h/s", param="q",
                             confirmed=True, evidence="parameter 'q' is injectable"))
    assert len(s) == 1
    f = s.all()[0]
    assert f.severity == "high" and f.confirmed and "injectable" in f.evidence
    # a different parameter is a distinct finding
    assert s.add(Finding("SQL injection", "high", "http://h/s", param="id"))
    assert len(s) == 2


def test_store_persists_append_only_and_reloads():
    tmp = tempfile.mkdtemp()
    try:
        path = Path(tmp) / "findings.jsonl"
        s = FindingStore(path)
        s.add(Finding("known CVE", "high", "http://h/", evidence="CVE-2021-3129"))
        s.add(Finding("nikto finding", "medium", "http://h/"))
        # a fresh store over the same ledger sees both, merged
        again = FindingStore(path)
        assert len(again) == 2
        titles = {f.title for f in again.all()}
        assert {"known CVE", "nikto finding"} <= titles
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_all_is_ranked_by_severity_then_confirmation():
    s = FindingStore()
    s.add(Finding("low thing", "low", "a"))
    s.add(Finding("crit thing", "critical", "b", confirmed=True))
    s.add(Finding("med candidate", "medium", "c"))
    order = [f.title for f in s.all()]
    assert order[0] == "crit thing" and order[-1] == "low thing"


# ---- session integration -------------------------------------------------- #

def _session():
    tmp = tempfile.mkdtemp()
    ex = Executor(Gate(load_scope(SCOPE)), FakeKali(), AuditLog(Path(tmp) / "a.jsonl"))
    return AssistSession(TARGET, ex, StrategistAgent(SeqLLM(["x"]))), tmp


def test_vuln_signal_in_output_becomes_a_finding():
    sess, tmp = _session()
    try:
        # simulate a sqlmap run whose real output flags an injection
        from brukal.kali import ExecResult
        out = "sqlmap: parameter 'q' is injectable ... back-end DBMS: MySQL"
        result = ExecResult(command="sqlmap", returncode=0, stdout=out, stderr="")
        decision, _ = sess.executor.run('sqlmap -u "http://10.10.10.5/s?q=1" -p q --batch',
                                        TARGET, agent="exploit")
        # feed a crafted result through the absorber (the executor's FakeKali output is
        # empty; we exercise the finding extraction directly on real-shaped output)
        sess._absorb_shell('sqlmap -u "http://10.10.10.5/s?q=1" -p q --batch',
                           decision, result)
        titles = {f.title for f in sess.findings.all()}
        assert "SQL injection" in titles
        f = next(f for f in sess.findings.all() if f.title == "SQL injection")
        assert f.confirmed and f.param == "q" and "10.10.10.5" in f.target
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_verified_success_records_a_critical_confirmed_finding():
    sess, tmp = _session()
    try:
        class V:                              # a Verified-shaped object
            kind = "user_flag"
            evidence = "d41d8cd98f00b204e9800998ecf8427e"
            command = "cat user.txt"
        sess.record_verified_success(V())
        f = sess.findings.all()[0]
        assert f.severity == "critical" and f.confirmed and "flag" in f.title
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---- report --------------------------------------------------------------- #

def test_build_report_and_json_render_findings():
    s = FindingStore()
    s.add(Finding("SQL injection", "high", "http://10.10.10.5/s", evidence="injectable",
                  source="sqlmap ...", param="q", confirmed=True))
    s.add(Finding("nikto finding", "medium", "http://10.10.10.5/", confirmed=False))
    meta = {"target": TARGET, "engagement": "test", "cage": "fake",
            "stop_reason": "manual", "audit_intact": True, "steps": 5, "executed": 4}
    md = build_report(s, meta)
    assert "# Brukal Pentest Report" in md
    assert "Confirmed findings" in md and "Candidate findings" in md
    assert "SQL injection" in md and "sqlmap ..." in md and "🔴" not in md  # no crit here
    js = report_json(s, meta)
    assert js["total"] == 2 and js["counts"]["high"] == 1
    assert any(f["title"] == "SQL injection" and f["confirmed"] for f in js["findings"])
