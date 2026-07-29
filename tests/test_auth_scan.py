"""
test_auth_scan.py — authenticated scanning: a governed form login + a persistent
session cookie jar, so the crawl and later web actions run BEHIND the login.

Pins:
  * GovernedBrowser keeps a cookie jar — it absorbs Set-Cookie and re-attaches the
    session on later requests (so an authenticated page is reachable after login);
  * AssistSession.login() does a governed GET (to seed the session + read the CSRF/
    submit fields) then a governed POST of the credentials, and reports authenticated;
  * the gate is untouched — the '&'-laden login body goes through check_web (scope +
    scheme), never a shell, and an out-of-scope login URL is still DENIED.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.web import GovernedBrowser, WebAction, WebResult

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "scope.json"


class _LoginCage:
    """A tiny form-login site: the login page carries a CSRF token + sets a session
    cookie; a POST with the right token+cookie authenticates (302 + auth cookie); the
    protected page returns content ONLY when the auth cookie is presented."""
    def run(self, action: WebAction) -> WebResult:
        cookie = (action.headers or {}).get("Cookie", "")
        url, method = action.url, action.method
        if action.kind == "request" and method == "GET" and "login" in url:
            return WebResult(status=200, url=url,
                             headers={"Set-Cookie": "SESSID=abc123; path=/; HttpOnly"},
                             body=('<form method="POST">'
                                   '<input type="hidden" name="csrf" value="T0KEN">'
                                   '<input name="username">'
                                   '<input type="password" name="password">'
                                   '<input type="submit" name="Login" value="Login"></form>'))
        if action.kind == "request" and method == "POST" and "login" in url:
            if "csrf=T0KEN" in (action.body or "") and "SESSID=abc123" in cookie \
                    and "password=secret" in (action.body or ""):
                return WebResult(status=302, url=url,
                                 headers={"Set-Cookie": "AUTHSESS=xyz; path=/",
                                          "Location": "/index.php"})
            return WebResult(status=200, url=url,
                             body='<input type="password" name="password"> wrong creds')
        # any other page: authenticated content only if the auth cookie is present
        if "AUTHSESS=xyz" in cookie:
            return WebResult(status=200, url=url, body="<h1>Secret Admin Dashboard</h1>")
        return WebResult(status=302, url=url, headers={"Location": "/login.php"}, body="")


class _NullLLM:
    def propose(self, system, user, max_tokens=1024):
        return ""


def _session(cage=None):
    scope = load_scope(FIXTURE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    browser = GovernedBrowser(scope, cage or _LoginCage(), audit)
    return AssistSession("10.10.10.5", ex, StrategistAgent(_NullLLM()), browser=browser), browser


# --- the cookie jar persists a session across web actions -------------------

def test_browser_cookie_jar_absorbs_and_reattaches():
    _sess, browser = _session()
    # GET login page sets SESSID; the jar remembers it.
    browser.run(WebAction("request", url="http://10.10.10.5/login.php", method="GET"))
    assert browser._cookies.get("SESSID") == "abc123"
    # a later request carries the jar automatically (no Cookie set by the caller)
    a = WebAction("request", url="http://10.10.10.5/x", method="GET")
    browser.run(a)
    assert "SESSID=abc123" in a.headers.get("Cookie", "")


# --- login() authenticates and unlocks protected pages ----------------------

def test_login_authenticates_and_session_reaches_protected_page():
    sess, browser = _session()
    ok = sess.login("http://10.10.10.5/login.php", "admin", "secret")
    assert ok is True and sess.authenticated is True
    assert "AUTHSESS" in browser._cookies                # got the post-login session
    # now the protected page is reachable WITH the carried session
    _d, res = browser.run(WebAction("request", url="http://10.10.10.5/admin", method="GET"))
    assert res.status == 200 and "Secret Admin Dashboard" in res.body


def test_login_fails_cleanly_on_bad_credentials():
    sess, _b = _session()
    ok = sess.login("http://10.10.10.5/login.php", "admin", "wrongpass")
    assert ok is False and sess.authenticated is False
    assert "may have FAILED" in sess.notes[-1]


# --- the gate still governs the login (out-of-scope URL denied) -------------

def test_login_url_out_of_scope_is_denied():
    sess, browser = _session()
    ok = sess.login("http://8.8.8.8/login.php", "admin", "secret")   # out of scope
    assert ok is False
    assert not browser._cookies                          # nothing was fetched/authenticated


# --- crawl must not fetch logout (would destroy an authenticated session) ---

def test_logout_urls_excluded_from_crawl():
    from brukal.assist import _LOGOUT_RE
    for u in ["http://x/logout.php", "http://x/logoff", "http://x/user/sign-out",
              "http://x/?action=logout", "http://x/index?do=signout"]:
        assert _LOGOUT_RE.search(u), u
    for u in ["http://x/vulnerabilities/sqli/", "http://x/login.php",
              "http://x/logs/output", "http://x/about"]:
        assert not _LOGOUT_RE.search(u), u


# --- authenticated exploitation: shell tools get the session cookie ---------

def _authed_session(cookies):
    from brukal.web import GovernedBrowser
    scope = load_scope(FIXTURE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    browser = GovernedBrowser(scope, _LoginCage(), audit)
    browser._cookies = dict(cookies)
    sess = AssistSession("10.10.10.5", ex, StrategistAgent(_NullLLM()), browser=browser)
    sess.authenticated = True
    return sess


def test_single_session_cookie_injected_into_shell_web_tools():
    s = _authed_session({"PHPSESSID": "abc123"})
    assert s._session_auth_for("sqlmap -u http://10.10.10.5/x?id=1") == \
        "sqlmap -u http://10.10.10.5/x?id=1 --cookie='PHPSESSID=abc123'"
    assert "-b 'PHPSESSID=abc123'" in s._session_auth_for("curl -s http://10.10.10.5/x")
    # already carrying a cookie -> untouched
    assert s._session_auth_for("curl -b 'X=1' http://10.10.10.5/x") == \
        "curl -b 'X=1' http://10.10.10.5/x"
    # non-web tool / unknown tool -> untouched
    assert s._session_auth_for("nmap -sV 10.10.10.5") == "nmap -sV 10.10.10.5"


def test_multi_cookie_not_injected_would_break_the_gate():
    # Two cookies -> the '; ' separator would trip the injection guard, so we DON'T
    # inject (multi-cookie sessions must use WEB actions). Gate stays untouched.
    s = _authed_session({"PHPSESSID": "abc", "security": "low"})
    assert s._session_auth_for("sqlmap -u http://10.10.10.5/x") == "sqlmap -u http://10.10.10.5/x"


def test_unauthenticated_session_injects_nothing():
    s = _authed_session({"PHPSESSID": "abc123"})
    s.authenticated = False
    assert s._session_auth_for("curl http://10.10.10.5/x") == "curl http://10.10.10.5/x"


def test_planner_reference_announces_authenticated_session():
    s = _authed_session({"PHPSESSID": "abc123"})
    ref = s._reference("")
    assert "AUTHENTICATED SESSION ACTIVE" in ref and "do not log in again" in ref.lower()


# --- generalized auth: JSON/token APIs, bearer, HTTP basic (not just forms) -

class _JsonApiCage:
    """A token API: POST /api/login with JSON creds returns {access_token: JWT};
    a protected endpoint returns data only with the right Bearer header."""
    def run(self, action: WebAction) -> WebResult:
        if action.kind == "request" and action.method == "POST" and "login" in action.url:
            if '"password": "secret"' in (action.body or "") or '"password":"secret"' in (action.body or ""):
                return WebResult(status=200, url=action.url,
                                 body='{"access_token":"eyJhbGciOiJIUzI1NiJ9.PAYLOAD.SIG","ok":true}')
            return WebResult(status=401, url=action.url, body='{"error":"bad creds"}')
        if (action.headers or {}).get("Authorization") == "Bearer eyJhbGciOiJIUzI1NiJ9.PAYLOAD.SIG":
            return WebResult(status=200, url=action.url, body='{"secret":"admin data"}')
        return WebResult(status=401, url=action.url, body='{"error":"unauthorized"}')


def test_extract_token_from_various_json_shapes():
    from brukal.assist import AssistSession
    E = AssistSession._extract_token
    assert E('{"access_token":"abcdefghijkl123"}') == "abcdefghijkl123"
    assert E('{"data":{"token":"nested-tok-abcdefgh"}}') == "nested-tok-abcdefgh"
    assert E('{"jwt": "eyJ.aaaa.bbbb-cccc_dddd"}') == "eyJ.aaaa.bbbb-cccc_dddd"
    assert E('{"user":"x","role":"admin"}') == ""        # no token field
    assert E("not json but token=deadbeefcafebabe123 here") == "deadbeefcafebabe123"


def test_json_login_extracts_bearer_and_propagates_it():
    sess, browser = _session(_JsonApiCage())
    ok = sess.login("http://10.10.10.5/api/login", "admin", "secret", login_type="json")
    assert ok and sess.authenticated
    assert browser.auth_header == "Bearer eyJhbGciOiJIUzI1NiJ9.PAYLOAD.SIG"
    # a later web action carries the bearer header -> protected data
    a = WebAction("request", url="http://10.10.10.5/api/me", method="GET")
    _d, res = browser.run(a)
    assert res.status == 200 and "admin data" in res.body


def test_basic_auth_sets_header_without_a_request():
    sess, browser = _session(_JsonApiCage())
    ok = sess.login("http://10.10.10.5/", "admin", "pw", login_type="basic")
    assert ok and browser.auth_header.startswith("Basic ")


def test_bearer_session_injected_into_shell_tools():
    s = _authed_session({})
    s.browser.auth_header = "Bearer eyJ.aaa.bbb-ccc_ddd"
    out = s._session_auth_for("sqlmap -u http://10.10.10.5/api/x")
    assert out == "sqlmap -u http://10.10.10.5/api/x -H 'Authorization: Bearer eyJ.aaa.bbb-ccc_ddd'"
    assert "-H 'Authorization: Bearer" in s._session_auth_for("ffuf -u http://10.10.10.5/FUZZ")


# --- denied web-request payloads auto-route to the governed WEB path --------

class _EchoCage:
    """Echoes the request so an 'injected' payload's effect is visible — stands in
    for a target that reflects/executes the payload."""
    def run(self, action: WebAction) -> WebResult:
        return WebResult(status=200, url=action.url,
                         body=f"[{action.method}] body={action.body}\nuid=0(root) gid=0(root)")


def test_curl_to_web_action_parses_method_url_body_headers():
    sess, _b = _session()
    wa = sess._curl_to_web_action(
        "curl -s -X POST -d 'a=1&b=2' -H 'X-Foo: bar' http://10.10.10.5/x")
    assert wa.method == "POST" and wa.url == "http://10.10.10.5/x"
    assert wa.body == "a=1&b=2" and wa.headers.get("X-Foo") == "bar"
    # a non-curl command doesn't translate
    assert sess._curl_to_web_action("nmap -sV 10.10.10.5") is None


def test_denied_injection_payload_reroutes_and_runs_via_web():
    sess, _b = _session(_EchoCage())
    # ';' in a command-injection payload -> shell gate DENIES the raw command
    dec, result, hl = sess.run(
        "curl -X POST -d 'ip=127.0.0.1;whoami' http://10.10.10.5/vuln/exec")
    # ...but it ran through the governed WEB path instead, no shell involved
    assert result is not None and "uid=0(root)" in result.stdout
    assert any("reroute" in n.lower() for n in sess.notes)


def test_reroute_only_on_injection_not_scope():
    sess, browser = _session(_EchoCage())
    # an OUT-OF-SCOPE curl is denied hard:scope — must NOT reroute (stays denied)
    dec, result, hl = sess.run("curl -d 'x=1&y=2' http://8.8.8.8/x")
    assert result is None                                # not rerouted; scope wins


# --- active differential vuln confirmation (candidate -> confirmed) ---------

class _SqliCage:
    """Vulnerable endpoint: a FALSE boolean condition returns no rows; anything else
    returns the record — the classic boolean-based SQLi differential."""
    def run(self, action: WebAction) -> WebResult:
        from urllib.parse import parse_qsl, urlsplit
        idv = dict(parse_qsl(urlsplit(action.url).query)).get("id", "")   # decoded param
        false_cond = ("'1'='2" in idv or "1=2" in idv or '"1"="2' in idv)
        body = "<html>no results found</html>" if false_cond \
            else "<html>User: admin | Email: admin@corp.local | active</html>"
        return WebResult(status=200, url=action.url, body=body)


class _XssCage:
    def run(self, action: WebAction) -> WebResult:
        from urllib.parse import parse_qsl, urlsplit
        q = dict(parse_qsl(urlsplit(action.url).query))
        return WebResult(status=200, url=action.url,
                         body=f"<html>You searched for: {q.get('q','')}</html>")  # reflected raw


def test_confirm_sqli_boolean_differential():
    sess, _b = _session(_SqliCage())
    assert sess.confirm_sqli("http://10.10.10.5/vuln/sqli/?id=1", "id") is True
    f = next(f for f in sess.findings.all() if f.title == "SQL injection (boolean-based)")
    assert f.confirmed is True and f.severity == "critical" and f.param == "id"


def test_confirm_sqli_negative_on_safe_endpoint():
    class Safe:
        def run(self, a): return WebResult(status=200, url=a.url, body="<html>static page</html>")
    sess, _b = _session(Safe())
    assert sess.confirm_sqli("http://10.10.10.5/x?id=1", "id") is False


def test_confirm_reflected_xss():
    sess, _b = _session(_XssCage())
    assert sess.confirm_xss("http://10.10.10.5/search?q=hi", "q") is True
    assert any(f.title == "Reflected XSS" and f.confirmed for f in sess.findings.all())


def test_confirm_xss_negative_when_encoded():
    class Enc:
        def run(self, a):
            from urllib.parse import parse_qsl, urlsplit
            v = dict(parse_qsl(urlsplit(a.url).query)).get("q","")
            v = v.replace("<","&lt;").replace(">","&gt;")   # properly encoded output
            return WebResult(status=200, url=a.url, body=f"<html>{v}</html>")
    sess, _b = _session(Enc())
    assert sess.confirm_xss("http://10.10.10.5/s?q=x", "q") is False


def test_confirm_sqli_rejects_pure_reflection():
    # an endpoint that merely REFLECTS the id (no DB) must NOT be confirmed as SQLi:
    # after removing the reflected payload, true and false responses are identical.
    class Reflect:
        def run(self, a):
            from urllib.parse import parse_qsl, urlsplit
            idv = dict(parse_qsl(urlsplit(a.url).query)).get("id","")
            return WebResult(status=200, url=a.url, body=f"<html>you passed id={idv}</html>")
    sess, _b = _session(Reflect())
    assert sess.confirm_sqli("http://10.10.10.5/x?id=1", "id") is False


def test_confirm_surface_probes_discovered_params():
    import brukal.webmap as webmap
    sess, _b = _session(_SqliCage())
    sess.surface = webmap.AttackSurface(seed="http://10.10.10.5/")
    sess.surface.params = {"http://10.10.10.5/vuln/sqli/": {"id"}}
    n = sess.confirm_surface()
    assert n == 1
    assert any(f.title == "SQL injection (boolean-based)" and f.confirmed
               for f in sess.findings.all())
