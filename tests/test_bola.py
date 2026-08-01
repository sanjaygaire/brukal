"""
test_bola.py — broken object-level authorization (OWASP API1) proved with TWO identities.

BOLA is the flaw a single-identity scanner cannot honestly claim: a 200 on someone
else's identifier means nothing unless you also know the object was not yours and not
public. Every leg of that argument is required here, and each is a separate test.
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

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"
TARGET = "10.10.10.5"
TPL = f"http://{TARGET}:5000/books/v1/{{book_title}}"
PARAM = "{book_title}"

OWNER = {"bookA": "alice", "bookB": "bob"}
SECRET = {"bookA": "AAA_PRIVATE_7781", "bookB": "BBB_PRIVATE_4423"}
TOKENS = {"tokA": "alice", "tokB": "bob"}


class _Books:
    """A books API. `enforce=True` checks that the caller owns the object (correct);
    `enforce=False` reproduces VAmPI's behaviour — authenticated, but any holder of any
    valid token may read any object."""
    def __init__(self, enforce: bool = False):
        self.enforce = enforce

    def run(self, action):
        who = TOKENS.get((action.headers or {}).get("Authorization", "")
                         .replace("Bearer ", ""))
        book = action.url.rsplit("/", 1)[-1]
        if who is None:
            return WebResult(status=401, url=action.url,
                             body='{"detail":"No authorization token provided"}')
        if book not in OWNER:
            return WebResult(status=404, url=action.url, body='{"detail":"not found"}')
        if self.enforce and OWNER[book] != who:
            return WebResult(status=403, url=action.url, body='{"detail":"Forbidden"}')
        return WebResult(status=200, url=action.url, body=json.dumps(
            {"book_title": book, "owner": OWNER[book], "secret": SECRET[book]}))


def _session(cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    return AssistSession(TARGET, ex, StrategistAgent(
        type("L", (), {"propose": lambda *a, **k: ""})()),
        browser=GovernedBrowser(scope, cage, audit))


def test_confirms_cross_account_read():
    sess = _session(_Books(enforce=False))
    assert sess.confirm_bola(TPL, PARAM, "bookA", "bookB", "tokA", "tokB") is True
    f = next(f for f in sess.findings.all()
             if f.title.startswith("Broken object-level authorization"))
    assert f.confirmed and f.severity == "critical" and f.category == "api"
    assert "identical to the owner's own view" in f.evidence


def test_correct_enforcement_confirms_nothing():
    sess = _session(_Books(enforce=True))
    assert sess.confirm_bola(TPL, PARAM, "bookA", "bookB", "tokA", "tokB") is False
    assert not sess.findings.all()


def test_a_public_endpoint_is_not_bola():
    """If anonymous can read it too, a 200 with A's token proves no authorization
    failure — the data was never protected."""
    class _Public:
        def run(self, action):
            book = action.url.rsplit("/", 1)[-1]
            return WebResult(status=200, url=action.url,
                             body=json.dumps({"book_title": book, "public": True}))

    sess = _session(_Public())
    assert sess.confirm_bola(TPL, PARAM, "bookA", "bookB", "tokA", "tokB") is False


def test_same_object_returned_is_not_bola():
    """Some APIs ignore the identifier and return the caller's own object. That is not a
    cross-account read, so it must not confirm."""
    class _AlwaysOwn:
        def run(self, action):
            if not (action.headers or {}).get("Authorization"):
                return WebResult(status=401, url=action.url, body='{"detail":"nope"}')
            return WebResult(status=200, url=action.url,
                             body=json.dumps({"owner": "alice", "secret": "AAA"}))

    sess = _session(_AlwaysOwn())
    assert sess.confirm_bola(TPL, PARAM, "bookA", "bookB", "tokA", "tokB") is False


def test_mismatch_with_the_owners_own_view_is_not_confirmed():
    """When B's credential is supplied, A's view must EQUAL B's own view. Anything else
    (a redacted or partial response) leaves doubt, so it is not claimed."""
    class _Redacts:
        def run(self, action):
            auth = (action.headers or {}).get("Authorization", "")
            who = TOKENS.get(auth.replace("Bearer ", ""))
            book = action.url.rsplit("/", 1)[-1]
            if who is None:
                return WebResult(status=401, url=action.url, body='{"detail":"nope"}')
            if OWNER[book] != who:               # a redacted cross-account view
                return WebResult(status=200, url=action.url,
                                 body=json.dumps({"book_title": book}))
            return WebResult(status=200, url=action.url, body=json.dumps(
                {"book_title": book, "owner": OWNER[book], "secret": SECRET[book]}))

    sess = _session(_Redacts())
    assert sess.confirm_bola(TPL, PARAM, "bookA", "bookB", "tokA", "tokB") is False


def test_session_credentials_are_suppressed_and_restored():
    """Our own logged-in session must not leak into the anonymous leg, and must survive
    the check — the same trap the JWT forgery proof fell into."""
    sess = _session(_Books(enforce=False))
    sess.browser.auth_header = "Bearer tokA"
    sess.browser._cookies = {"SESSID": "x"}
    assert sess.confirm_bola(TPL, PARAM, "bookA", "bookB", "tokA", "tokB") is True
    assert sess.browser.auth_header == "Bearer tokA"
    assert sess.browser._cookies == {"SESSID": "x"}


def test_out_of_scope_bola_probe_is_denied():
    class _Spy:
        def __init__(self):
            self.seen = []

        def run(self, action):
            self.seen.append(action.url)
            return WebResult(status=200, url=action.url, body="{}")

    cage = _Spy()
    sess = _session(cage)
    assert sess.confirm_bola("http://8.8.8.8/books/{id}", "{id}", "1", "2",
                             "tokA", "tokB") is False
    assert cage.seen == []
