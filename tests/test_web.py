"""
test_web.py — the governed web-exploitation surface.

Proves the web path enforces the SAME governance as the shell path: scope is
checked on the action's HOST (IP or authorised hostname), bad schemes and
out-of-scope hosts are DENIED before the network, page interactions require an
in-scope page first, everything is logged, and an agent given the GovernedBrowser
cannot reach the cage directly.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, load_scope
from brukal.scope import Scope
from brukal.web import (FakeWebCage, GovernedBrowser, WebAction, check_web)

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"


def _scope_with_host(host="nexus.htb"):
    base = load_scope(SCOPE)          # authorises 10.10.10.0/24 + 127.0.0.1
    return base.with_host(host)


# -- scope hostname authorisation ------------------------------------------- #

def test_scope_authorises_hostnames_without_dns():
    s = _scope_with_host("nexus.htb")
    assert s.contains_host("nexus.htb")
    assert s.contains_host("NEXUS.HTB")             # case-insensitive
    assert s.contains_host("nexus.htb:80")          # host:port
    assert s.contains_host("10.10.10.5")            # still honours CIDRs
    assert not s.contains_host("evil.com")
    assert not s.contains_host("8.8.8.8")
    assert not s.contains_host("")                  # fail-closed


def test_with_host_does_not_mutate_the_original_scope():
    base = load_scope(SCOPE)
    widened = base.with_host("nexus.htb")
    assert widened.contains_host("nexus.htb")
    assert not base.contains_host("nexus.htb")      # original untouched (immutable)


# -- the web gate ----------------------------------------------------------- #

def test_in_scope_navigate_and_request_allowed():
    s = _scope_with_host()
    assert check_web(WebAction("navigate", url="http://nexus.htb/"), s).verdict == "ALLOW"
    assert check_web(WebAction("request", url="http://nexus.htb/login",
                               method="POST", body="u=admin"), s).verdict == "ALLOW"
    assert check_web(WebAction("get", url="http://10.10.10.5/"), s).verdict == "ALLOW"


def test_out_of_scope_host_denied():
    s = _scope_with_host()
    d = check_web(WebAction("get", url="http://evil.com/"), s)
    assert d.verdict == "DENY" and d.layer == "hard:web-scope"


def test_bad_scheme_denied():
    s = _scope_with_host()
    for bad in ("javascript:alert(1)", "file:///etc/passwd", "data:text/html,x"):
        d = check_web(WebAction("navigate", url=bad), s)
        assert d.verdict == "DENY", bad


def test_page_action_needs_in_scope_page_first():
    s = _scope_with_host()
    # a click with no page loaded -> denied (fail-closed)
    assert check_web(WebAction("click", selector="#go"), s, current_url="").verdict == "DENY"
    # once an in-scope page is the current url, the interaction is allowed
    assert check_web(WebAction("fill", selector="#u", value="' OR 1=1--"), s,
                     current_url="http://nexus.htb/login").verdict == "ALLOW"
    # but if the current page is out of scope, interaction is denied
    assert check_web(WebAction("click", selector="#go"), s,
                     current_url="http://evil.com/").verdict == "DENY"


# -- the governed browser (one door) ---------------------------------------- #

def _browser(host="nexus.htb"):
    tmp = tempfile.mkdtemp()
    cage = FakeWebCage(responses={"nexus.htb/flag": "HTB{fake_flag}"})
    audit = AuditLog(Path(tmp) / "web.jsonl")
    return GovernedBrowser(_scope_with_host(host), cage, audit), cage, audit


def test_governed_browser_runs_in_scope_denies_out_of_scope():
    br, cage, audit = _browser()
    d, r = br.run(WebAction("get", url="http://nexus.htb/flag"))
    assert d.verdict == "ALLOW" and r is not None and "HTB{" in r.body
    d2, r2 = br.run(WebAction("get", url="http://evil.com/"))
    assert d2.verdict == "DENY" and r2 is None
    assert cage.actions == [WebAction("get", url="http://nexus.htb/flag")] or \
        len(cage.actions) == 1                       # the denied one never reached the cage
    assert audit.verify()


def test_navigate_then_fill_payload_flows_through_the_gate():
    br, cage, _ = _browser()
    br.run(WebAction("navigate", url="http://nexus.htb/login"))   # sets current page
    assert br.current_url == "http://nexus.htb/login"
    # a payload-bearing fill on the in-scope page is allowed (payloads aren't sanitised)
    d, r = br.run(WebAction("fill", selector="#user", value="admin' OR '1'='1"))
    assert d.verdict == "ALLOW" and r is not None
    assert cage.actions[-1].value == "admin' OR '1'='1"


def test_request_tampering_headers_and_body_reach_the_cage():
    # the interception/replay primitive: craft an arbitrary method + headers + body
    br, cage, _ = _browser()
    d, r = br.run(WebAction("request", url="http://nexus.htb/api", method="PUT",
                            headers={"X-Forwarded-For": "127.0.0.1"}, body='{"admin":true}'))
    assert d.verdict == "ALLOW"
    sent = cage.actions[-1]
    assert sent.method == "PUT" and sent.headers["X-Forwarded-For"] == "127.0.0.1"
    assert sent.body == '{"admin":true}'


def test_ensure_cage_vhosts_guards():
    # No docker needed: the guard returns [] unless the scope is ONE single-host
    # (/32) target, so the vhost->IP mapping is unambiguous (never guesses).
    from brukal.web import ensure_cage_vhosts
    base = load_scope(SCOPE)                          # a /24 + a /32, no hostnames
    assert ensure_cage_vhosts(base) == []            # no authorised hostnames
    # scope.json has TWO networks -> ambiguous even with a hostname -> no-op (safe)
    assert ensure_cage_vhosts(base.with_host("nexus.htb")) == []
    # a single /32 host scope with a hostname would map (guard passes); we don't
    # invoke docker here — just assert the guard would proceed by checking inputs.
    single = Scope("t", (__import__("ipaddress").ip_network("10.0.0.5/32"),),
                   frozenset(), 30, authorized_hosts=frozenset({"box.htb"}))
    assert len(single.authorized_networks) == 1 and single.authorized_networks[0].num_addresses == 1


def test_broad_allowlist_mode_safe_runs_dangerous_asks_human(tmp_path):
    import json

    from brukal import Gate
    from brukal.scope import load_scope
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.10.10.0/24"],
                             "allowlisted_tools": "all"}))
    scope = load_scope(str(p))
    assert scope.broad_tools and scope.tool_allowed("any-kali-tool")
    g = Gate(scope)
    T = "10.10.10.5"
    assert g.check("nmap -sV 10.10.10.5", T).verdict == "ALLOW"       # safe enum -> auto
    assert g.check("feroxbuster -u http://10.10.10.5", T).verdict == "ALLOW"
    assert g.check("hydra -l a -P w ssh://10.10.10.5", T).verdict == "ESCALATE"  # attack -> human
    assert g.check("some-unknown-tool 10.10.10.5", T).verdict == "ESCALATE"       # unknown -> human
    assert g.check("nmap -sV 8.8.8.8", "8.8.8.8").verdict == "DENY"   # scope still absolute


def test_parse_web_action_grammar():
    from brukal.web import parse_web_action
    assert parse_web_action("get http://nexus.htb/admin").kind == "get"
    assert parse_web_action("render http://nexus.htb/").kind == "get"
    assert parse_web_action("http://nexus.htb/").kind == "get"      # bare url
    a = parse_web_action("request POST http://nexus.htb/login user=admin&p=x")
    assert a.kind == "request" and a.method == "POST" and "user=admin" in a.body
    f = parse_web_action("fill #user admin' OR '1'='1")
    assert f.kind == "fill" and f.selector == "#user" and "OR '1'='1" in f.value
    assert parse_web_action("") is None


def test_composite_cage_routes_by_action_kind():
    from brukal.web import CompositeWebCage, WebResult

    class Render:
        def run(self, a): return WebResult(note="render", url=a.url)

    class Request:
        def run(self, a): return WebResult(note="request", url=a.url)

    cage = CompositeWebCage(Render(), Request())
    assert cage.run(WebAction("navigate", url="http://x/")).note == "render"
    assert cage.run(WebAction("get", url="http://x/")).note == "render"
    assert cage.run(WebAction("request", url="http://x/")).note == "request"
    # a live-interactive action returns an explanatory note, not a crash
    assert "CDP" in cage.run(WebAction("fill", selector="#a")).note


def test_web_rate_limit_denies_when_exceeded():
    tmp = tempfile.mkdtemp()
    scope = Scope("t", (), frozenset(), rate_limit_per_min=2,
                  authorized_hosts=frozenset({"nexus.htb"}))
    br = GovernedBrowser(scope, FakeWebCage(), AuditLog(Path(tmp) / "w.jsonl"))
    a = WebAction("get", url="http://nexus.htb/")
    assert br.run(a)[0].verdict == "ALLOW"
    assert br.run(a)[0].verdict == "ALLOW"
    d, r = br.run(a)                                 # third within the minute
    assert d.verdict == "DENY" and d.layer == "hard:web-rate" and r is None


def test_httpwebcage_does_not_follow_redirect_to_out_of_scope():
    # A real backend test: an in-scope host that 302s to http://evil.com/ must NOT be
    # followed — the out-of-scope target must never be reached. The cage surfaces the
    # Location so the caller can resubmit it as a fresh, gated action.
    import http.server
    import threading
    from brukal.web import HttpWebCage

    class _Redirector(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://evil.com/")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _Redirector)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        res = HttpWebCage(timeout=5).run(WebAction("get", url=f"http://127.0.0.1:{port}/"))
        assert res.status == 302                       # the redirect itself, not followed
        assert "evil.com" not in (res.url or "")       # did NOT navigate to the out-of-scope host
        assert "evil.com" in (res.note or "")          # surfaced the Location for a re-check
        assert not (res.body or "")                    # no body fetched from evil.com
    finally:
        srv.shutdown()


def test_ensure_cage_vhosts_maps_to_target_ip_under_broad_scope(monkeypatch):
    # The real bug: nexus.htb never resolved in the cage because the scope wasn't a
    # single /32. It must now map authorised vhosts -> the TARGET IP regardless of
    # scope breadth, and skip wildcards (can't be an /etc/hosts entry).
    import brukal.web as W
    calls = []
    monkeypatch.setattr(W, "map_cage_host", lambda h, ip, c="brukal-kali": calls.append((h, ip)) or True)
    scope = Scope("t", (), frozenset({"*"}), 30,
                  authorized_hosts=frozenset({"nexus.htb", "*.nexus.htb"}))
    mapped = W.ensure_cage_vhosts(scope, "brukal-kali", target_ip="10.129.61.188")
    assert mapped == ["nexus.htb"]                       # wildcard skipped
    assert calls == [("nexus.htb", "10.129.61.188")]     # mapped to the target IP


def test_map_cage_host_rejects_injection_and_bad_input():
    from brukal.web import map_cage_host
    assert map_cage_host("*.nexus.htb", "10.0.0.1", "x") is False   # wildcard
    assert map_cage_host("nexus.htb", "not-an-ip", "x") is False    # bad IP
    assert map_cage_host("a;rm -rf b", "10.0.0.1", "x") is False    # shell metachars in host
