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
    assert s._session_cookie_for("sqlmap -u http://10.10.10.5/x?id=1") == \
        "sqlmap -u http://10.10.10.5/x?id=1 --cookie='PHPSESSID=abc123'"
    assert "-b 'PHPSESSID=abc123'" in s._session_cookie_for("curl -s http://10.10.10.5/x")
    # already carrying a cookie -> untouched
    assert s._session_cookie_for("curl -b 'X=1' http://10.10.10.5/x") == \
        "curl -b 'X=1' http://10.10.10.5/x"
    # non-web tool / unknown tool -> untouched
    assert s._session_cookie_for("nmap -sV 10.10.10.5") == "nmap -sV 10.10.10.5"


def test_multi_cookie_not_injected_would_break_the_gate():
    # Two cookies -> the '; ' separator would trip the injection guard, so we DON'T
    # inject (multi-cookie sessions must use WEB actions). Gate stays untouched.
    s = _authed_session({"PHPSESSID": "abc", "security": "low"})
    assert s._session_cookie_for("sqlmap -u http://10.10.10.5/x") == "sqlmap -u http://10.10.10.5/x"


def test_unauthenticated_session_injects_nothing():
    s = _authed_session({"PHPSESSID": "abc123"})
    s.authenticated = False
    assert s._session_cookie_for("curl http://10.10.10.5/x") == "curl http://10.10.10.5/x"


def test_planner_reference_announces_authenticated_session():
    s = _authed_session({"PHPSESSID": "abc123"})
    ref = s._reference("")
    assert "AUTHENTICATED SESSION ACTIVE" in ref and "do not log in again" in ref.lower()
