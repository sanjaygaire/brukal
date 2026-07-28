"""
test_exposures.py — raw-response exposure findings + specific blocked-command coaching.

A live full-send run showed two gaps: (1) exposures the model discovered by hand
(curl of .git/.env, a leaked key, a SQL error) produced ZERO recorded findings,
because only scanner-shaped output (nuclei/nikto/sqlmap) was ever turned into a
finding; (2) ~a quarter of the model's turns were wasted re-trying shell operators
(&&, |, $()) that the injection guard hard-DENYs, because the feedback was generic.

These pin the fixes: webprobe.scan_exposures() flags exposure signatures in a raw
body, _absorb_shell records them as findings, and an injection DENY now returns a
specific hint that steers to one-tool-per-step / a session. The gate is unchanged.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope, webprobe
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import ExecResult

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "scope.json"


class _CannedKali:
    """Cage stand-in that returns a fixed body — so we can drive the exposure
    detector with realistic response content without a real target."""
    def __init__(self, body: str):
        self.body = body
        self.executed: list[str] = []
    def run(self, command: str) -> ExecResult:
        self.executed.append(command)
        return ExecResult(command, 0, self.body, "")


class _NullLLM:
    def propose(self, system, user, max_tokens=1024):
        return ""


def _session(body: str):
    scope = load_scope(FIXTURE)
    ex = Executor(Gate(scope), _CannedKali(body),
                  AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl"))
    return AssistSession("10.10.10.5", ex, StrategistAgent(_NullLLM()))


# --- scan_exposures: detects the classes scan_output misses ----------------

def test_scan_exposures_detects_git_env_key_sql_dirlist():
    assert any(l == "Exposed .git repository"
               for _s, l, _e in webprobe.scan_exposures("[core]\nrepositoryformatversion = 0"))
    assert any(l == "Secret in exposed env/config"
               for _s, l, _e in webprobe.scan_exposures("DB_PASSWORD=sup3rs3cret\nFOO=bar"))
    assert any(s == "critical" and l == "Private key exposed"
               for s, l, _e in webprobe.scan_exposures(
                   "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB..."))
    assert any(s == "critical" and l == "AWS access key exposed"
               for s, l, _e in webprobe.scan_exposures("key=AKIAIOSFODNN7EXAMPLE"))
    assert any(l == "SQL error (possible injection)"
               for _s, l, _e in webprobe.scan_exposures(
                   "You have an error in your SQL syntax near '' at line 1 (MySQL)"))
    assert any(l == "Directory listing enabled"
               for _s, l, _e in webprobe.scan_exposures("<html><title>Index of /uploads</title>"))


def test_scan_exposures_no_false_positive_on_ordinary_html():
    ordinary = "<html><head><title>Home</title></head><body>Welcome, please log in</body></html>"
    assert webprobe.scan_exposures(ordinary) == []
    assert webprobe.scan_exposures("404 Not Found") == []
    # prose that merely contains 'at' / 'javascript' must not look like a stack frame
    assert webprobe.scan_exposures("meet me at the store; runs javascript at line 5") == []


def test_scan_exposures_catches_node_stack_trace_and_orm_error():
    # A real framework error page (Express/Sequelize) leaking internal file paths —
    # the language-agnostic stack-frame signature, calibrated against OWASP Juice Shop.
    body = ("500 Error at Query.run (/juice-shop/node_modules/sequelize/lib/"
            "dialects/sqlite/query.js:183:12) at process.")
    labels = [l for _s, l, _e in webprobe.scan_exposures(body)]
    assert "Stack trace / debug info disclosure" in labels
    assert "SequelizeDatabaseError: near \"x\": syntax error" and any(
        l == "SQL error (possible injection)"
        for _s, l, _e in webprobe.scan_exposures("SequelizeDatabaseError near foo"))


# --- the raw-command discovery now becomes a recorded FINDING ---------------

def test_absorb_shell_records_exposure_finding_from_raw_curl():
    sess = _session("[core]\nrepositoryformatversion = 0\n[remote \"origin\"]")
    sess.run("curl -s http://10.10.10.5/.git/config")
    titles = [f.title for f in sess.findings.all()]
    assert "Exposed .git repository" in titles          # was 0 findings before the fix
    f = next(f for f in sess.findings.all() if f.title == "Exposed .git repository")
    assert f.severity == "high"
    assert "curl" in f.source                            # evidence-backed by the real command


def test_leaked_private_key_is_a_critical_finding():
    sess = _session("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk...")
    sess.run("curl -s http://10.10.10.5/backup/id_rsa")
    crit = [f for f in sess.findings.all() if f.severity == "critical"]
    assert any(f.title == "Private key exposed" for f in crit)


# --- injection DENY now coaches specifically (one tool / use a session) -----

def test_injection_deny_gives_specific_coaching():
    sess = _session("irrelevant")
    # A shell-chained command: the gate hard-DENYs at the injection guard.
    dec, result, _hl = sess.run("curl -s http://10.10.10.5/ && whoami")
    assert dec.verdict == "DENY" and dec.layer == "hard:injection"
    assert result is None                                # never reached the cage
    last = sess.notes[-1].lower()
    assert "shell operator" in last and "session" in last   # actionable, steers to a session


def test_scope_deny_hint_is_distinct():
    sess = _session("irrelevant")
    sess.run("nmap -sV 8.8.8.8")                          # out of scope
    last = sess.notes[-1].lower()
    assert "out of scope" in last and "shell operator" not in last


# --- scanner output must NOT manufacture exposure findings (FP fix) ---------

def test_scanner_output_does_not_trigger_exposure_finding():
    from brukal.assist import _is_raw_fetch
    assert _is_raw_fetch("curl -s http://10.10.10.5/x") is True
    assert _is_raw_fetch("sqlmap -u http://10.10.10.5/x --batch") is False
    assert _is_raw_fetch("nikto -host http://10.10.10.5/") is False
    # sqlmap's verbose output names a technique that would trip the SQL signature —
    # but scan_exposures must not run on a scanner's report.
    sess = _session("[*] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'")
    sess.run("sqlmap -u http://10.10.10.5/api/x --batch")
    assert all(f.title != "SQL error (possible injection)" for f in sess.findings.all())


def test_raw_curl_still_triggers_exposure_finding():
    sess = _session('{"error":"SQLITE_ERROR: near \\"\'\\": syntax error"}')
    sess.run("curl -s http://10.10.10.5/api/x")
    assert any(f.title == "SQL error (possible injection)" for f in sess.findings.all())


# --- soft-404 downgrades path-scanner findings (nikto FP fix) ---------------

def test_soft_404_downgrades_path_scanner_findings():
    import brukal.webmap as webmap
    sess = _session("+ OSVDB-3092: /JAMonAdmin.jsp: admin interface (traversal)")
    sess.surface = webmap.AttackSurface(seed="http://10.10.10.5/")
    sess.surface.soft_404 = True
    sess.run("nikto -host http://10.10.10.5/")     # nikto is read-only -> runs
    nikto = [f for f in sess.findings.all() if "nikto" in f.title.lower()]
    assert nikto and all(f.severity == "info" for f in nikto)     # downgraded, not high/med
    assert any("soft-404" in f.evidence.lower() for f in nikto)   # annotated why


def test_content_tool_findings_not_downgraded_on_soft_404():
    import brukal.webmap as webmap
    sess = _session("[high] CVE-2021-1234 confirmed on the target")
    sess.surface = webmap.AttackSurface(seed="http://10.10.10.5/")
    sess.surface.soft_404 = True
    sess.run("nuclei -u http://10.10.10.5/")       # content-based, not path-discovery
    # nuclei's verdict stands even on a soft-404 host — not downgraded
    assert any(f.severity == "high" for f in sess.findings.all())
