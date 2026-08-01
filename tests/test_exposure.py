"""
test_exposure.py — what an application hands to a stranger.

Bulk is what separates a finding from a feature. One record about the caller is their own
profile; the same fields across many principals is an exposure. Credentials in a body are
decisive on their own, whatever the volume.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope, webmap
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
URL = f"http://{TARGET}:5000/users/v1"

USERS = json.dumps({"users": [{"username": "name1", "email": "mail1@mail.com"},
                              {"username": "name2", "email": "mail2@mail.com"}]})
DEBUG = json.dumps({"users": [{"username": "name1", "email": "m1@x.com",
                               "password": "pass1", "admin": False}]})


def test_sensitive_records_grades_by_what_leaked():
    count, fields, sev = webmap.sensitive_records(DEBUG)
    assert sev == "critical" and "password" in fields and count == 1
    count, fields, sev = webmap.sensitive_records(USERS)
    assert sev == "high" and "email" in fields and count == 2
    # a single personal record is a profile, not a bulk exposure
    one = json.dumps({"user": {"username": "me", "email": "me@x.com"}})
    assert webmap.sensitive_records(one)[2] == ""
    # and ordinary payloads say nothing
    assert webmap.sensitive_records('{"books":[{"title":"a"},{"title":"b"}]}')[2] == ""
    assert webmap.sensitive_records("<html>hello</html>")[2] == ""
    assert webmap.sensitive_records("")[2] == ""


def _session(body: str, status: int = 200, soft404: bool = False):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")

    class _Cage:
        def __init__(self):
            self.auth_seen = []

        def run(self, action):
            self.auth_seen.append((action.headers or {}).get("Authorization", ""))
            return WebResult(status=status, url=action.url, body=body)

    cage = _Cage()
    sess = AssistSession(TARGET, Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                         browser=GovernedBrowser(scope, cage, audit))
    sess.surface = AttackSurface(seed=f"http://{TARGET}:5000/")
    sess.surface.soft_404 = soft404
    return sess, cage


def test_credentials_in_an_anonymous_response_are_critical():
    sess, _c = _session(DEBUG)
    assert sess.confirm_data_exposure(URL) is True
    f = next(f for f in sess.findings.all() if "exposure" in f.title)
    assert f.severity == "critical" and "credentials" in f.title


def test_bulk_personal_data_is_high():
    sess, _c = _session(USERS)
    assert sess.confirm_data_exposure(URL) is True
    f = next(f for f in sess.findings.all() if "exposure" in f.title)
    assert f.severity == "high" and "personal data" in f.title


def test_the_probe_carries_no_credentials_and_restores_the_session():
    """A 200 only means 'anyone can read this' if we asked as nobody."""
    sess, cage = _session(USERS)
    sess.browser.auth_header = "Bearer live-session"
    sess.browser._cookies = {"SESSID": "x"}
    sess.confirm_data_exposure(URL)
    assert cage.auth_seen == [""], cage.auth_seen
    assert sess.browser.auth_header == "Bearer live-session"
    assert sess.browser._cookies == {"SESSID": "x"}


def test_refused_or_meaningless_responses_confirm_nothing():
    assert _session(USERS, status=401)[0].confirm_data_exposure(URL) is False
    assert _session(USERS, soft404=True)[0].confirm_data_exposure(URL) is False
    # an endpoint whose job is issuing tokens is excluded
    sess, _c = _session(USERS)
    assert sess.confirm_data_exposure(f"http://{TARGET}:5000/users/v1/login") is False


def test_out_of_scope_exposure_probe_is_denied():
    sess, cage = _session(USERS)
    assert sess.confirm_data_exposure("http://8.8.8.8/users") is False
    assert cage.auth_seen == []


def test_state_changing_paths_are_never_fetched():
    """Brukal wiped its own test target once: /createdb was mined as an ordinary route,
    the exposure pass fetched it like any other listing, and the database was
    reinitialised mid-run. 'Read-only' is a property of the METHOD, not the endpoint."""
    from brukal.assist import AssistSession as A

    for path in ("/createdb", "/api/reset", "/admin/delete-all", "/v1/purge",
                 "/setup", "/users/logout", "/db/migrate"):
        assert A._is_destructive_path(path), path
    # ...and ordinary data endpoints must still be probed
    for path in ("/users/v1", "/books/v1", "/v1/created_at", "/api/address",
                 "/newsletter", "/users/v1/_debug", "/users/v1/{username}"):
        assert not A._is_destructive_path(path), path


def test_the_exposure_probe_refuses_a_destructive_endpoint():
    sess, cage = _session(USERS)
    assert sess.confirm_data_exposure(f"http://{TARGET}:5000/createdb") is False
    assert cage.auth_seen == [], "it fetched a state-changing endpoint"
