"""
test_hygiene.py — transport and browser-side controls that are simply absent.

Added because a comparison against nuclei and nikto showed them reporting 14-21 hygiene
items per target where Brukal reported none. A client expects these in a report.

Two constraints keep them from becoming noise: severity stays low, so hygiene can never
crowd out a proven critical; and the verdict is a FACT — the header was present in an
observed response or it was not — rather than a guess.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.web import GovernedBrowser, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"

HARDENED = {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=63072000",
            "Set-Cookie": "sid=abc; Secure; HttpOnly; SameSite=Strict"}


class _Cage:
    def __init__(self, headers, status=200):
        self.headers, self.status = headers, status

    def run(self, action):
        return WebResult(status=self.status, url=action.url,
                         headers=dict(self.headers), body="<html>hi</html>")


def _session(cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    return AssistSession(TARGET, Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                         browser=GovernedBrowser(scope, cage, audit))


def test_a_bare_response_reports_each_missing_control():
    sess = _session(_Cage({}))
    n = sess.confirm_security_headers(f"http://{TARGET}/")
    titles = {f.title for f in sess.findings.all()}
    assert "Missing security header: content-security-policy" in titles
    assert "Missing security header: x-frame-options" in titles
    assert n >= 3
    # HSTS is meaningless over http and must not be demanded there
    assert "Missing security header: strict-transport-security" not in titles
    assert all(f.severity == "low" for f in sess.findings.all())


def test_a_hardened_response_reports_nothing():
    sess = _session(_Cage(HARDENED))
    assert sess.confirm_security_headers(f"https://{TARGET}/") == 0
    assert not sess.findings.all()


def test_csp_frame_ancestors_substitutes_for_x_frame_options():
    """Reporting both when one already covers framing is noise."""
    sess = _session(_Cage({"Content-Security-Policy": "frame-ancestors 'none'"}))
    sess.confirm_security_headers(f"http://{TARGET}/")
    titles = {f.title for f in sess.findings.all()}
    assert "Missing security header: x-frame-options" not in titles


def test_cookie_flags_are_read_from_the_response_that_sets_them():
    sess = _session(_Cage({"Set-Cookie": "sid=abc; Path=/"}))
    sess.confirm_security_headers(f"https://{TARGET}/")
    titles = {f.title for f in sess.findings.all()}
    assert "Cookie set without httponly" in titles
    assert "Cookie set without samesite" in titles
    assert "Cookie set without Secure" in titles


def test_hsts_is_only_expected_over_tls():
    sess = _session(_Cage({}))
    sess.confirm_security_headers(f"https://{TARGET}/")
    assert any("strict-transport-security" in f.title for f in sess.findings.all())


def test_a_broken_response_says_nothing_about_policy():
    sess = _session(_Cage({}, status=500))
    assert sess.confirm_security_headers(f"http://{TARGET}/") == 0


def test_hygiene_never_outranks_a_real_finding():
    """Severity discipline: a report sorted by severity must not lead with headers."""
    sess = _session(_Cage({}))
    sess.confirm_security_headers(f"http://{TARGET}/")
    assert all(f.severity in ("low", "info") for f in sess.findings.all())


def test_out_of_scope_header_probe_is_denied():
    sess = _session(_Cage({}))
    assert sess.confirm_security_headers("http://8.8.8.8/") == 0
