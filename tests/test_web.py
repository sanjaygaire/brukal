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

SCOPE = Path(__file__).resolve().parents[1] / "scope.json"


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
