"""
test_jwt.py — JWT weakness analysis and the forged-token proof.

Brukal extracted a bearer token at login and carried it, but never looked at it. A JWT
states its own algorithm and principal, and its signature is only as strong as the key
behind it — so the most damaging API auth bugs are readable from the token itself,
offline, before the target is touched.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, jwtscan, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.web import GovernedBrowser, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"
TARGET = "10.10.10.5"
URL = f"http://{TARGET}:5000/me"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _token(payload: dict, secret: str = "random", alg: str = "HS256") -> str:
    h = _b64(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    p = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64(sig)}"


NOW = int(time.time())
LIVE_CLAIMS = {"exp": NOW + 600, "iat": NOW, "sub": "brukaltest"}


class _NullLLM:
    def propose(self, *a, **k):
        return ""


def _session(cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    return AssistSession(TARGET, ex, StrategistAgent(_NullLLM()),
                         browser=GovernedBrowser(scope, cage, audit))


def test_decode_and_find_tokens():
    tok = _token(LIVE_CLAIMS)
    header, payload, _si, sig = jwtscan.decode(tok)
    assert header["alg"] == "HS256" and payload["sub"] == "brukaltest" and sig
    assert jwtscan.decode("not.a.token") is None
    assert jwtscan.decode("") is None
    found = jwtscan.find_tokens(f'{{"auth_token": "{tok}", "status": "success"}}')
    assert found == [tok]


def test_cracks_a_weak_key_offline_and_leaves_a_strong_one_alone():
    """A hit is cryptographic proof: the key reproduces the token's own signature. A
    miss must stay silent — absence of evidence is not a finding."""
    assert jwtscan.crack_hmac_secret(_token(LIVE_CLAIMS, secret="random")) == "random"
    strong = _token(LIVE_CLAIMS, secret="Y8#q2vN!pL7@wZ4rT1$eM6^bK9&xC3*d")
    assert jwtscan.crack_hmac_secret(strong) is None
    assert not [l for _s, l, _e in jwtscan.scan_token(strong)
                if l == "JWT signed with a guessable secret"]


def test_scan_flags_the_weaknesses_a_token_reveals():
    labels = lambda t: [l for _s, l, _e in jwtscan.scan_token(t)]
    assert "JWT signed with a guessable secret" in labels(_token(LIVE_CLAIMS))
    assert "JWT accepts the 'none' algorithm" in labels(
        jwtscan.alg_none_variant(_token(LIVE_CLAIMS)))
    assert "JWT has no expiry" in labels(_token({"sub": "x"}, secret="unguessable-" * 4))
    assert "JWT payload contains sensitive data" in labels(
        _token({**LIVE_CLAIMS, "password": "hunter2"}))
    assert "JWT carries privilege claims" in labels({**LIVE_CLAIMS, "admin": True}
                                                    and _token({**LIVE_CLAIMS,
                                                                "admin": True}))
    # a sound token yields nothing alarming
    sound = _token({"sub": "u", "iat": NOW, "exp": NOW + 300},
                   secret="Y8#q2vN!pL7@wZ4rT1$eM6^bK9&xC3*d")
    assert "JWT signed with a guessable secret" not in labels(sound)
    assert "JWT has no expiry" not in labels(sound)


def test_session_records_a_cracked_key_as_confirmed_critical():
    sess = _session(_Accepts())
    assert sess.scan_jwt(_token(LIVE_CLAIMS), source=URL) >= 1
    f = next(f for f in sess.findings.all()
             if f.title == "JWT signed with a guessable secret")
    assert f.confirmed is True and f.severity == "critical" and f.category == "api"


class _Accepts:
    """A server that trusts any correctly-signed token: refuses anonymous, serves the
    holder of a signature it can verify — which, with a guessable key, is anyone."""
    def __init__(self, secret: str = "random"):
        self.secret = secret

    def run(self, action):
        auth = (action.headers or {}).get("Authorization", "")
        tok = auth.replace("Bearer ", "")
        parsed = jwtscan.decode(tok) if tok else None
        if parsed is None:
            return WebResult(status=401, url=action.url,
                             body='{"detail":"No authorization token provided"}')
        _h, _p, signing_input, sig = parsed
        good = hmac.new(self.secret.encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(good, sig):
            return WebResult(status=401, url=action.url, body='{"detail":"Invalid token"}')
        return WebResult(status=200, url=action.url,
                         body='{"data":{"username":"name1","admin":false}}')


def test_forged_token_is_confirmed_against_an_accepting_server():
    sess = _session(_Accepts())
    assert sess.confirm_jwt_forgery(URL, _token(LIVE_CLAIMS)) is True
    f = next(f for f in sess.findings.all()
             if f.title == "Authentication bypass via forged JWT")
    assert f.confirmed and f.severity == "critical"


def test_a_strong_key_yields_no_forgery_finding():
    strong = "Y8#q2vN!pL7@wZ4rT1$eM6^bK9&xC3*d"
    sess = _session(_Accepts(secret=strong))
    assert sess.confirm_jwt_forgery(URL, _token(LIVE_CLAIMS, secret=strong)) is False
    assert not sess.findings.all()


def test_an_endpoint_open_to_everyone_proves_nothing():
    """Acceptance is only meaningful against refusal — an endpoint that serves anonymous
    requests says nothing about whether the signature was checked."""
    class _Open:
        def run(self, action):
            return WebResult(status=200, url=action.url, body='{"data":"public"}')

    sess = _session(_Open())
    assert sess.confirm_jwt_forgery(URL, _token(LIVE_CLAIMS)) is False


def test_out_of_scope_forgery_probe_is_denied():
    class _Spy:
        def __init__(self):
            self.seen = []

        def run(self, action):
            self.seen.append(action.url)
            return WebResult(status=200, url=action.url, body="{}")

    cage = _Spy()
    sess = _session(cage)
    assert sess.confirm_jwt_forgery("http://8.8.8.8/me", _token(LIVE_CLAIMS)) is False
    assert cage.seen == []


def test_tokens_found_in_a_page_are_analysed_once():
    """A JWT in a page, bundle or API response is both a credential and a statement of
    how the app authenticates — so browser-fetched bodies are mined for them."""
    sess = _session(_Accepts())
    body = f'{{"auth_token": "{_token(LIVE_CLAIMS)}", "status": "success"}}'
    sess.scan_web_body(f"http://{TARGET}:5000/users/v1/login", body)
    titles = [f.title for f in sess.findings.all()]
    assert "JWT signed with a guessable secret" in titles
    assert sess.last_jwt                              # kept for the forgery proof
    analyses = lambda: [f for f in sess.findings.all() if f.category == "api"]
    before = len(analyses())
    sess.scan_web_body(f"http://{TARGET}:5000/again", body)
    assert len(analyses()) == before                  # analysed once, not per page


def test_a_login_response_returning_a_token_is_not_called_a_leak():
    """An auth endpoint handing the caller its own token is the design. Reporting that
    as 'JWT exposed' is a false positive, and those are what a report dies of."""
    sess = _session(_Accepts())
    body = f'{{"auth_token": "{_token(LIVE_CLAIMS)}", "status": "success"}}'
    sess.scan_web_body(f"http://{TARGET}:5000/users/v1/login", body)
    assert not [f for f in sess.findings.all() if "exposed" in f.title.lower()]
    # ...but the same token sitting in an ordinary page IS worth reporting
    sess2 = _session(_Accepts())
    sess2.scan_web_body(f"http://{TARGET}:5000/profile", body)
    assert [f for f in sess2.findings.all() if "exposed" in f.title.lower()]


def test_reflex_chains_a_refused_endpoint_into_the_forgery_proof():
    """The autonomous chain: the spec names a protected endpoint, the endpoint refuses
    us, and a token we can mint is then offered to it."""
    from brukal.webmap import AttackSurface

    sess = _session(_Accepts())
    sess.surface = AttackSurface(seed=f"http://{TARGET}:5000/")
    sess.surface.protected_routes.append(("GET", "/me"))
    sess.last_jwt = _token(LIVE_CLAIMS)
    assert sess.confirm_surface() >= 1
    assert any(f.title == "Authentication bypass via forged JWT" and f.confirmed
               for f in sess.findings.all())


def test_forgery_proof_is_valid_while_already_logged_in():
    """The browser attaches our live session to any request that lacks one, so an
    'anonymous' baseline taken while authenticated comes back 200 and the differential
    silently proves nothing. The session must be suppressed for the check — and restored
    afterwards, or the rest of the run loses its login."""
    sess = _session(_Accepts())
    sess.authenticated = True
    sess.browser.auth_header = f"Bearer {_token(LIVE_CLAIMS)}"
    sess.browser._cookies = {"SESSID": "abc"}

    assert sess.confirm_jwt_forgery(URL, _token(LIVE_CLAIMS)) is True
    assert sess.browser.auth_header.startswith("Bearer ")      # session restored
    assert sess.browser._cookies == {"SESSID": "abc"}
