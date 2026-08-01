"""
test_massassign.py — mass assignment / broken object property level authz (OWASP API3).

The finding is only meaningful against a CONTROL account: an API where every new user is
an admin is badly designed, but it is not the client controlling a property. Only a
difference between an account created WITH the injected field and one created without it
distinguishes those, and a single account cannot.

This is also the one proof that writes to the target, so the gate on it is tested too.
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
B = f"http://{TARGET}:5000"


class _Api:
    """A registration API. `honours_admin` reproduces VAmPI: an `admin` field sent by the
    client is written straight onto the new account. `everyone_admin` is the decoy — a
    badly designed API where every account is an admin regardless."""
    def __init__(self, honours_admin: bool = True, everyone_admin: bool = False):
        self.honours_admin, self.everyone_admin = honours_admin, everyone_admin
        self.users: dict = {}
        self.writes = 0

    def run(self, action):
        body = {}
        try:
            body = json.loads(action.body or "{}")
        except Exception:
            pass
        url = action.url
        if url.endswith("/register"):
            self.writes += 1
            admin = bool(self.everyone_admin or
                         (self.honours_admin and body.get("admin") is True))
            self.users[body.get("username", "")] = {"password": body.get("password"),
                                                    "admin": admin}
            return WebResult(status=200, url=url, body='{"status":"success"}')
        if url.endswith("/login"):
            u = self.users.get(body.get("username", ""))
            if not u or u["password"] != body.get("password"):
                return WebResult(status=401, url=url, body='{"status":"fail"}')
            return WebResult(status=200, url=url,
                             body=json.dumps({"auth_token": f"tok-{body['username']}"}))
        if url.endswith("/me"):
            name = (action.headers or {}).get("Authorization", "").replace("Bearer tok-", "")
            u = self.users.get(name)
            if not u:
                return WebResult(status=401, url=url, body='{"detail":"nope"}')
            return WebResult(status=200, url=url,
                             body=json.dumps({"username": name, "admin": u["admin"]}))
        return WebResult(status=404, url=url, body="{}")


def _session(cage, intrusive: bool = True):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    sess = AssistSession(TARGET, ex, StrategistAgent(
        type("L", (), {"propose": lambda *a, **k: ""})()),
        browser=GovernedBrowser(scope, cage, audit))
    sess.allow_intrusive = intrusive
    return sess


def _run(sess):
    return sess.confirm_mass_assignment(f"{B}/users/v1/register", f"{B}/users/v1/login",
                                        f"{B}/me")


def test_confirms_when_the_client_controls_the_field():
    sess = _session(_Api(honours_admin=True))
    assert _run(sess) is True
    f = next(f for f in sess.findings.all()
             if f.title == "Mass assignment of a privileged field")
    assert f.confirmed and f.severity == "critical" and f.category == "api"
    assert "control account" in f.evidence


def test_an_api_that_ignores_the_field_confirms_nothing():
    sess = _session(_Api(honours_admin=False))
    assert _run(sess) is False
    assert not sess.findings.all()


def test_an_api_where_everyone_is_admin_is_not_mass_assignment():
    """The decoy the control account exists to catch: bad defaults are not the client
    controlling a property, and without a control they look identical."""
    sess = _session(_Api(honours_admin=False, everyone_admin=True))
    assert _run(sess) is False
    assert not sess.findings.all()


def test_it_refuses_to_write_without_intrusive_authorisation():
    """It creates accounts, so it must not run unless the operator has unleashed it."""
    api = _Api(honours_admin=True)
    sess = _session(api, intrusive=False)
    assert _run(sess) is False
    assert api.writes == 0, "it registered accounts without authorisation"


def test_out_of_scope_registration_is_denied():
    api = _Api(honours_admin=True)
    sess = _session(api)
    assert sess.confirm_mass_assignment("http://8.8.8.8/register", "http://8.8.8.8/login",
                                        "http://8.8.8.8/me") is False
    assert api.writes == 0
