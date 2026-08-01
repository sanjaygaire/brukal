"""
test_cors.py — CORS that lets any site read authenticated responses.

The finding is a PAIR of headers, never one alone. Reflecting an arbitrary origin means
little on its own, and `*` means less — a browser refuses to send credentials to a
wildcard, which is precisely why a naive check cries wolf on the most common
configuration in the wild.
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
URL = f"http://{TARGET}/api/me"


class _Cors:
    """Answers with whatever CORS policy the test is describing."""
    def __init__(self, mode: str):
        self.mode = mode
        self.origins_seen: list[str] = []

    def run(self, action):
        origin = (action.headers or {}).get("Origin", "")
        self.origins_seen.append(origin)
        h = {}
        if self.mode == "reflect_with_credentials":
            h = {"Access-Control-Allow-Origin": origin,
                 "Access-Control-Allow-Credentials": "true"}
        elif self.mode == "reflect_no_credentials":
            h = {"Access-Control-Allow-Origin": origin}
        elif self.mode == "wildcard":
            h = {"Access-Control-Allow-Origin": "*"}
        elif self.mode == "wildcard_claiming_credentials":
            # invalid per spec; browsers refuse it, so it is not an exploitable finding
            h = {"Access-Control-Allow-Origin": "*",
                 "Access-Control-Allow-Credentials": "true"}
        elif self.mode == "null_with_credentials":
            h = ({"Access-Control-Allow-Origin": "null",
                  "Access-Control-Allow-Credentials": "true"} if origin == "null" else {})
        elif self.mode == "allowlist":
            allowed = "https://app.example"
            h = ({"Access-Control-Allow-Origin": allowed,
                  "Access-Control-Allow-Credentials": "true"}
                 if origin == allowed else {})
        return WebResult(status=200, url=action.url, headers=h, body='{"user":"me"}')


def _session(cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    return AssistSession(TARGET, Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                         browser=GovernedBrowser(scope, cage, audit))


def test_reflected_origin_with_credentials_is_confirmed():
    sess = _session(_Cors("reflect_with_credentials"))
    assert sess.confirm_cors(URL) is True
    f = next(f for f in sess.findings.all() if f.title.startswith("CORS"))
    assert f.confirmed and f.severity == "high"
    assert "brukal-probe.example" in f.evidence


def test_the_null_origin_variant_is_confirmed():
    """A sandboxed iframe produces `null` on demand, so trusting it is trusting anyone."""
    sess = _session(_Cors("null_with_credentials"))
    assert sess.confirm_cors(URL) is True
    assert "null origin" in next(f.evidence for f in sess.findings.all()
                                 if f.title.startswith("CORS"))


def test_configurations_that_are_not_exploitable_confirm_nothing():
    """Each of these is common in the wild and none allows a credentialed cross-origin
    read — reporting them would be noise, and noise is what a report dies of."""
    for mode in ("reflect_no_credentials", "wildcard", "wildcard_claiming_credentials",
                 "allowlist"):
        sess = _session(_Cors(mode))
        assert sess.confirm_cors(URL) is False, mode
        assert not sess.findings.all(), mode


def test_a_host_with_no_cors_headers_confirms_nothing():
    class _Plain:
        def run(self, action):
            return WebResult(status=200, url=action.url, body="hello")

    sess = _session(_Plain())
    assert sess.confirm_cors(URL) is False


def test_out_of_scope_cors_probe_is_denied():
    cage = _Cors("reflect_with_credentials")
    sess = _session(cage)
    assert sess.confirm_cors("http://8.8.8.8/api") is False
    assert cage.origins_seen == []
