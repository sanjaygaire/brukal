"""
test_chrome.py — the Chrome/CDP backend action mapping (no browser needed).

Drives ChromeCage with a FakeCDP transport and asserts each WebAction produces
the right Chrome DevTools Protocol calls — navigate loads + reads the DOM, fill
sets the value with a payload (unsanitised), a request is a fetch() in page
context, interception arms the Fetch domain. Also proves the whole thing still
flows through the gate via GovernedBrowser.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog
from brukal.chrome import ChromeCage, DockerChromeCage, FakeCDP
from brukal.web import GovernedBrowser, WebAction
from brukal.scope import Scope


def test_navigate_loads_and_returns_dom():
    cdp = FakeCDP(dom="<html><body>Nexus</body></html>")
    r = ChromeCage(cdp).run(WebAction("navigate", url="http://nexus.htb/"))
    assert r.status == 200 and "Nexus" in r.body
    assert "Page.navigate" in cdp.methods() and cdp.loaded == 1


def test_fill_sets_payload_without_sanitising():
    cdp = FakeCDP()
    ChromeCage(cdp).run(WebAction("fill", selector="#user", value="admin' OR '1'='1"))
    # the SQLi payload must appear verbatim in the injected JS (it's the attack)
    evals = [p["expression"] for m, p in cdp.calls if m == "Runtime.evaluate"]
    assert any("admin' OR '1'='1" in e and "#user" in e for e in evals)


def test_click_and_eval_map_to_runtime_evaluate():
    cdp = FakeCDP(eval_value="clicked")
    cage = ChromeCage(cdp)
    cage.run(WebAction("click", selector=".btn"))
    r = cage.run(WebAction("eval", expression="document.cookie"))
    assert r.body == "clicked"
    evals = [p["expression"] for m, p in cdp.calls if m == "Runtime.evaluate"]
    assert any(".btn" in e and "click()" in e for e in evals)
    assert "document.cookie" in evals


def test_request_is_fetch_in_page_context():
    cdp = FakeCDP(eval_value="<html>ok</html>")
    ChromeCage(cdp).run(WebAction("request", url="http://nexus.htb/api", method="POST",
                                  headers={"X-Test": "1"}, body='{"a":1}'))
    evals = [p["expression"] for m, p in cdp.calls if m == "Runtime.evaluate"]
    assert any("fetch(" in e and "nexus.htb/api" in e and "POST" in e for e in evals)


def test_intercept_arms_fetch_domain():
    cdp = FakeCDP()
    ChromeCage(cdp).run(WebAction("intercept", url="http://nexus.htb/*"))
    assert "Fetch.enable" in cdp.methods()


def test_governed_browser_over_chrome_still_gates():
    tmp = tempfile.mkdtemp()
    scope = Scope("t", (), frozenset(), 60, authorized_hosts=frozenset({"nexus.htb"}))
    br = GovernedBrowser(scope, ChromeCage(FakeCDP()), AuditLog(Path(tmp) / "w.jsonl"))
    d, r = br.run(WebAction("navigate", url="http://nexus.htb/"))
    assert d.verdict == "ALLOW" and br.current_url == "http://nexus.htb/"
    # now an interaction on the loaded in-scope page is allowed
    assert br.run(WebAction("click", selector="#go"))[0].verdict == "ALLOW"
    # but an out-of-scope navigate is denied and never reaches Chrome
    assert br.run(WebAction("navigate", url="http://evil.com/"))[0].verdict == "DENY"


def test_docker_chrome_cage_rejects_interactive_actions():
    cage = DockerChromeCage()
    for kind in ("click", "fill", "eval", "intercept"):
        try:
            cage.run(WebAction(kind, url="http://nexus.htb/", selector="#x"))
            assert False, f"{kind} should need the CDP cage"
        except NotImplementedError:
            pass
