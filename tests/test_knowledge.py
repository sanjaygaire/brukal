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


def test_kb_entries_are_structurally_sound():
    """A keyword group written as ("text") is a STRING, not a tuple, so the matcher
    iterates its characters and the entry then matches almost every title. That shipped
    once and silently mis-scored unrelated findings, so the shape is checked here rather
    than trusted."""
    from brukal.knowledge import _KB

    for keys, score, vector, impact, remediation, refs in _KB:
        assert isinstance(keys, (tuple, list)), f"{keys!r} must be a tuple of keywords"
        assert keys and all(isinstance(k, str) and len(k) > 2 for k in keys), keys
        assert 0.0 <= score <= 10.0
        assert vector.startswith("AV:")
        assert impact and remediation and refs


def test_each_finding_class_enriches_to_its_own_entry():
    """Spot-check that titles land on the RIGHT entry — the symptom of the bug above was
    a low-severity token finding inheriting an unrelated high CVSS."""
    from brukal.knowledge import enrich

    assert enrich("JWT has no expiry", "medium")["cvss"] == 5.3
    assert "CWE-613" in enrich("JWT has no expiry", "medium")["refs"]
    assert enrich("Authentication bypass via forged JWT", "critical")["cvss"] == 9.8
    assert enrich("Unauthenticated access to a protected endpoint", "high")["cvss"] == 8.6
    assert enrich("SQL injection (error-based)", "critical")["cvss"] == 9.8
    assert enrich("Prompt injection (model obeyed an injected instruction)",
                  "high")["cvss"] == 8.6


def test_specific_entries_precede_general_ones():
    """The table is first-match-wins, so a specific finding placed AFTER a general one
    can never be reached. The two-identity BOLA proof (OWASP API1) initially sat below
    the generic single-identity IDOR lead and silently inherited its lower score."""
    from brukal.knowledge import enrich

    bola = enrich("Broken object-level authorization (BOLA/IDOR)", "critical")
    idor = enrich("Potential IDOR (unauthorised object access)", "medium")
    assert "API1:2023" in " ".join(bola["refs"])
    assert bola["cvss"] == 8.1
    assert idor["cvss"] == 6.5 and "A01:2021" in " ".join(idor["refs"])
    assert bola["refs"] != idor["refs"]        # genuinely different entries
