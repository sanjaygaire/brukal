"""test_knowledge.py — remediation/CVSS/impact enrichment for the report deliverable."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brukal import knowledge
from brukal.findings import Finding
from brukal.report import _finding_md


def test_enrich_known_classes():
    for title, cwe in [("SQL injection (boolean-based)", "CWE-89"),
                       ("OS command injection", "CWE-78"),
                       ("SSRF to cloud metadata (IMDS credential theft)", "CWE-918"),
                       ("Public S3 bucket (listable)", "CWE-284"),
                       ("Kerberoastable account (TGS hash captured)", "MITRE T1558.003"),
                       ("Exported activity without permission", "CWE-926")]:
        kb = knowledge.enrich(title, "high")
        assert kb["cvss"] > 0 and kb["remediation"] and kb["impact"]
        assert any(cwe in r for r in kb["refs"]), (title, kb["refs"])


def test_enrich_unknown_falls_back_to_severity():
    kb = knowledge.enrich("Some novel weird finding", "critical")
    assert kb["cvss"] == 9.5 and kb["remediation"] and kb["refs"]


def test_report_finding_includes_impact_remediation_cvss():
    f = Finding(title="SQL injection (boolean-based)", severity="critical",
                target="http://x/a?id=1", evidence="TRUE vs FALSE differ", source="probe",
                param="id", category="web", confirmed=True)
    md = _finding_md(f)
    assert "CVSS 9.8" in md and "Impact:" in md and "Remediation:" in md
    assert "CWE-89" in md and "parameterised" in md.lower()
