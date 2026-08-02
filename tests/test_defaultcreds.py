"""
test_defaultcreds.py — shipped credentials that were never changed (CWE-1392).

A comparative run against nuclei found a critical default login on a target Brukal
walked straight past. It is the most common route to initial access in the real world,
and no amount of injection testing substitutes for it.

The control is the whole design: an application that accepts ANY password, or one whose
login always redirects, would otherwise report the first pair tried as a success.
"""
from __future__ import annotations

import json
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
URL = f"http://{TARGET}/users/v1/login"
# A realistic token: extraction requires a credible value, so a stub like "tok-abc"
# would have the fixture failing for a reason the product does not have.
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTc4NTYzODI3NH0.5dkY-GPWIw8xn9r5sq2jnefixM70Zpy3A04EBpbCEfk"


class _Api:
    """A JSON login. `accepts` is the set of pairs that authenticate."""
    def __init__(self, accepts=(("admin", "password"),), accept_anything=False):
        self.accepts = set(accepts)
        self.accept_anything = accept_anything
        self.attempts: list = []

    def run(self, action):
        try:
            body = json.loads(action.body or "{}")
        except Exception:
            body = {}
        u, p = body.get("username", ""), body.get("password", "")
        self.attempts.append((u, p))
        if self.accept_anything or (u, p) in self.accepts:
            return WebResult(status=200, url=action.url,
                             body=json.dumps({"auth_token": TOKEN}))
        return WebResult(status=401, url=action.url, body='{"status":"fail"}')


def _session(cage, intrusive=True):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    sess = AssistSession(TARGET, Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                         browser=GovernedBrowser(scope, cage, audit))
    sess.allow_intrusive = intrusive
    return sess


def test_a_shipped_credential_is_confirmed_critical():
    sess = _session(_Api())
    assert sess.confirm_default_credentials(URL, login_type="json") is True
    f = next(f for f in sess.findings.all() if f.title == "Default credentials accepted")
    assert f.confirmed and f.severity == "critical"
    assert "'admin'/'password'" in f.evidence


def test_an_app_that_accepts_anything_confirms_nothing():
    """Without the control, this shape reports the first pair tried as a default
    credential — a confident critical against an app with a different flaw entirely."""
    cage = _Api(accept_anything=True)
    sess = _session(cage)
    assert sess.confirm_default_credentials(URL, login_type="json") is False
    assert not sess.findings.all()
    # The GET that seeds a session is recorded too, so count only credential POSTs.
    posts = [a for a in cage.attempts if a != ("", "")]
    assert len(posts) == 1, f"it kept guessing after the control passed: {posts}"


def test_changed_credentials_confirm_nothing():
    sess = _session(_Api(accepts=(("admin", "Q7!vNp2xL9"),)))
    assert sess.confirm_default_credentials(URL, login_type="json") is False
    assert not sess.findings.all()


def test_it_will_not_guess_without_intrusive_authorisation():
    """Failed logins can lock a real account, so this must not run unattended."""
    cage = _Api()
    sess = _session(cage, intrusive=False)
    assert sess.confirm_default_credentials(URL, login_type="json") is False
    assert cage.attempts == []


def test_the_pair_list_stays_small():
    """This asks whether the documented default was changed. It is not a password
    attack, and every extra pair is another failed login against a real account."""
    assert len(AssistSession.DEFAULT_CREDENTIALS) <= 15


def test_the_live_session_survives_the_check():
    """It logs in and out repeatedly; the engagement's own session must come back."""
    sess = _session(_Api())
    sess.browser.auth_header = "Bearer live"
    sess.browser._cookies = {"SESSID": "keep"}
    sess.authenticated = True
    sess.confirm_default_credentials(URL, login_type="json")
    assert sess.browser.auth_header == "Bearer live"
    assert sess.browser._cookies == {"SESSID": "keep"}
    assert sess.authenticated is True


def test_out_of_scope_login_is_denied():
    cage = _Api()
    sess = _session(cage)
    assert sess.confirm_default_credentials("http://8.8.8.8/login",
                                            login_type="json") is False
    assert cage.attempts == []
