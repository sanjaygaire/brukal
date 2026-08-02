"""
test_ecosystem.py — integrating Brukal with what an organisation already runs.

Two halves, and the safety argument differs for each.

  * EXPORT is pure output: SARIF for the dashboards that already read it, and a
    versioned JSON envelope for anything bespoke. Export can never change a verdict, so
    what is tested is fidelity — above all that an unconfirmed lead never leaves here
    looking like a proven finding.
  * PACKS are contributed DETECTIONS, and they are data rather than code on purpose. A
    plugin system that loaded Python would hand arbitrary code the same process as the
    gate. So the tests assert what a hostile pack CANNOT do, not merely what a friendly
    one can.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import export, packs
from brukal.findings import Finding, FindingStore

CONFIRMED = Finding(title="SQL injection (error-based)", severity="critical",
                    target="http://t/users/{id}", evidence="quote broke the query",
                    param="{id}", category="api", confirmed=True)
LEAD = Finding(title="nikto finding", severity="info", target="http://t/",
               evidence="maybe interesting", category="web", confirmed=False)


# --- SARIF ------------------------------------------------------------------------

def test_sarif_is_well_formed_and_carries_severity_for_dashboards():
    doc = export.to_sarif([CONFIRMED, LEAD], {"target": "t", "audit_chain_intact": True})
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Brukal"
    assert len(run["results"]) == 2
    rule = next(r for r in run["tool"]["driver"]["rules"]
                if r["id"] == export.rule_id(CONFIRMED.title))
    # GitHub reads security-severity to place a finding in its own bands
    assert float(rule["properties"]["security-severity"]) == 9.8
    assert rule["defaultConfiguration"]["level"] == "error"
    assert any("CWE" in t for t in rule["properties"]["tags"])
    assert "Remediation" in rule["help"]["markdown"]
    # governance travels with the run
    assert run["invocations"][0]["properties"]["auditChainIntact"] is True


def test_an_unconfirmed_lead_never_leaves_looking_proven():
    """The single distinction the whole report rests on has to survive export."""
    doc = export.to_sarif([LEAD], {})
    result = doc["runs"][0]["results"][0]
    assert result["properties"]["confirmed"] is False
    assert "UNCONFIRMED LEAD" in result["message"]["text"]
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["precision"] == "medium"


def test_fingerprints_are_stable_across_runs_but_distinguish_findings():
    """A dashboard should show one issue with a history, not a new issue every scan."""
    import copy
    later = copy.copy(CONFIRMED)
    later.ts = CONFIRMED.ts + 10_000
    later.evidence = "a differently worded evidence line"
    a = export.to_sarif([CONFIRMED], {})["runs"][0]["results"][0]
    b = export.to_sarif([later], {})["runs"][0]["results"][0]
    assert a["partialFingerprints"] == b["partialFingerprints"]
    c = export.to_sarif([LEAD], {})["runs"][0]["results"][0]
    assert c["partialFingerprints"] != a["partialFingerprints"]


def test_rule_ids_are_stable_and_readable():
    assert export.rule_id("SQL injection (error-based)") == "brukal/sql-injection-error-based"
    assert export.rule_id("") == "brukal/finding"


# --- the JSON envelope ------------------------------------------------------------

def test_json_envelope_is_versioned_and_carries_governance():
    doc = export.to_json([CONFIRMED, LEAD],
                         {"target": "t", "audit_chain_intact": True, "blocked": 3})
    assert doc["schema_version"] == export.SCHEMA_VERSION
    assert doc["governance"]["audit_chain_intact"] is True
    assert doc["governance"]["commands_blocked"] == 3
    assert doc["summary"] == {"total": 2, "confirmed": 1,
                              "by_severity": {"critical": 1, "high": 0, "medium": 0,
                                              "low": 0, "info": 1}}
    item = doc["findings"][0]
    for key in ("id", "rule", "title", "severity", "confirmed", "evidence",
                "reproduce", "cvss", "remediation", "references"):
        assert key in item, key


# --- CI gating --------------------------------------------------------------------

def test_exit_code_breaks_a_build_only_on_proven_findings():
    """A pipeline should fail on something Brukal PROVED, not on a lead nobody has
    looked at — otherwise the gate gets switched off within a week."""
    assert export.exit_code([CONFIRMED], fail_on="high") == 1
    assert export.exit_code([LEAD], fail_on="info") == 0          # unconfirmed: ignored
    assert export.exit_code([LEAD], fail_on="info", confirmed_only=False) == 1
    assert export.exit_code([], fail_on="critical") == 0
    medium = Finding(title="GraphQL introspection enabled", severity="medium",
                     confirmed=True)
    assert export.exit_code([medium], fail_on="high") == 0        # below the threshold
    assert export.exit_code([medium], fail_on="medium") == 1


def test_reports_are_written_alongside_the_human_report():
    from brukal.report import write_reports
    store = FindingStore()
    store.add(CONFIRMED)
    with tempfile.TemporaryDirectory() as tmp:
        written = write_reports(store, {"target": "t"}, tmp)
        assert "sarif" in written and "json" in written
        doc = json.loads(Path(written["sarif"]).read_text())
        assert doc["runs"][0]["results"][0]["ruleId"].startswith("brukal/")


# --- contributed signature packs --------------------------------------------------

def _pack(tmp: str, body: dict) -> str:
    p = Path(tmp) / "pack.json"
    p.write_text(json.dumps(body), encoding="utf-8")
    return str(p)


def test_a_pack_contributes_detections():
    with tempfile.TemporaryDirectory() as tmp:
        path = _pack(tmp, {"name": "acme", "signatures": [
            {"pattern": r"AcmeAuthError: token rejected", "severity": "medium",
             "title": "Acme auth service error disclosed"}]})
        sigs = packs.load_pack(path)
        assert len(sigs) == 1
        hits = packs.scan("... AcmeAuthError: token rejected ...", sigs)
        assert hits and hits[0][0] == "medium"
        assert "[acme]" in hits[0][1]              # the pack is named in the finding
        assert packs.scan("nothing to see", sigs) == []


def test_a_pack_cannot_claim_a_finding_is_confirmed():
    """Confirmation means a deterministic proof RAN. Letting contributed data assert it
    would corrupt the one distinction the report rests on."""
    with tempfile.TemporaryDirectory() as tmp:
        path = _pack(tmp, {"name": "x", "signatures": [
            {"pattern": "boom", "title": "Contributed", "confirmed": True,
             "severity": "critical"}]})
        sig = packs.load_pack(path)[0]
        assert sig.confirmed is False


def test_a_malformed_pack_is_survived_not_obeyed():
    with tempfile.TemporaryDirectory() as tmp:
        assert packs.load_pack(_pack(tmp, {"signatures": "not a list"})) == []
        assert packs.load_pack(_pack(tmp, {"signatures": [
            {"pattern": "(unclosed", "title": "bad regex"},      # uncompilable
            {"pattern": "", "title": "empty"},
            {"title": "no pattern"},
            {"pattern": "x" * 5000, "title": "absurd"},
            "not even an object",
            {"pattern": "fine", "title": "Good one", "severity": "nonsense"},
        ]})) [0].severity == "info"                              # bad severity -> info
        assert packs.load_pack(str(Path(tmp) / "missing.json")) == []
        broken = Path(tmp) / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        assert packs.load_pack(str(broken)) == []


def test_a_pack_cannot_hang_the_run_with_a_pathological_pattern():
    """A pack pattern runs against untrusted target output, so a catastrophic regex is a
    denial of service against ourselves."""
    with tempfile.TemporaryDirectory() as tmp:
        sigs = packs.load_pack(_pack(tmp, {"name": "evil", "signatures": [
            {"pattern": r"(a+)+$", "title": "catastrophic"}]}))
        assert sigs == []


def test_a_pack_carries_no_executable_surface():
    """The safety argument: a pack is data. There is no hook by which one could reach
    the cage, issue a request, or widen scope."""
    with tempfile.TemporaryDirectory() as tmp:
        sigs = packs.load_pack(_pack(tmp, {"name": "p", "signatures": [
            {"pattern": "x", "title": "T", "command": "rm -rf /",
             "target": "8.8.8.8", "scope": "0.0.0.0/0"}]}))
        sig = sigs[0]
        assert set(sig.__slots__) == {"rx", "severity", "title", "category",
                                      "confirmed", "pack"}
        for forbidden in ("command", "target", "scope"):
            assert not hasattr(sig, forbidden)


def test_load_dir_is_reproducible_and_tolerant():
    with tempfile.TemporaryDirectory() as tmp:
        for i, name in enumerate(("b.json", "a.json")):
            (Path(tmp) / name).write_text(json.dumps({"name": name, "signatures": [
                {"pattern": f"sig{i}", "title": f"T{i}"}]}), encoding="utf-8")
        (Path(tmp) / "notes.txt").write_text("ignored", encoding="utf-8")
        sigs = packs.load_dir(tmp)
        assert [s.pack for s in sigs] == ["a.json", "b.json"]     # sorted, reproducible
        assert packs.load_dir(Path(tmp) / "nope") == []


def test_contributed_signatures_reach_findings_through_the_normal_path():
    """A pack hit must arrive as an ordinary finding — deduped, soft-404-downgraded, and
    exportable — rather than through a side channel of its own."""
    import tempfile as _tf

    from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
    from brukal.agents import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.web import GovernedBrowser, WebResult

    scope_file = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
    body = "Traceback ... sqlalchemy.exc.OperationalError: boom ... Werkzeug Debugger"

    class _Cage:
        def run(self, action):
            return WebResult(status=200, url=action.url, body=body)

    with _tf.TemporaryDirectory() as tmp:
        pack = _pack(tmp, {"name": "acme", "signatures": [
            {"pattern": r"sqlalchemy\.exc\.[A-Za-z]+Error", "severity": "medium",
             "title": "Internal ORM error surfaced to the client"}]})
        scope = load_scope(str(scope_file))
        audit = AuditLog(Path(tmp) / "a.jsonl")
        sess = AssistSession("10.10.10.5", Executor(Gate(scope), FakeKali(), audit),
                             StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                             browser=GovernedBrowser(scope, _Cage(), audit))
        sess.signature_packs = packs.load_pack(pack)
        sess.scan_web_body("http://10.10.10.5/x", body)

        titles = [f.title for f in sess.findings.all()]
        assert any("Internal ORM error" in t and "[acme]" in t for t in titles), titles
        contributed = next(f for f in sess.findings.all() if "[acme]" in f.title)
        assert contributed.confirmed is False       # contributed data never claims proof
        # and it exports like any other finding
        doc = export.to_sarif([contributed], {})
        assert doc["runs"][0]["results"][0]["ruleId"].startswith("brukal/")


def test_export_carries_the_governance_fields_the_run_records():
    doc = export.to_json([CONFIRMED], {"audit_chain_intact": True,
                                       "audit_log": "runs/a.jsonl", "executed": 7})
    assert doc["governance"]["audit_chain_intact"] is True
    assert doc["governance"]["audit_log"] == "runs/a.jsonl"
    assert doc["governance"]["commands_executed"] == 7
