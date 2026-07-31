"""
test_webmap.py — the web attack-surface extractor + the governed crawl.

Two things are pinned here:

  * webmap.extract() turns fetched (untrusted) HTML into a structured surface —
    links, forms + their inputs, query parameters — with NO network I/O, tolerating
    malformed markup, and rejecting non-navigable schemes.
  * AssistSession.crawl() spiders the site THROUGH the gate: it follows only
    in-scope, same-host links, stays within its page/depth budget, never wanders to
    an out-of-scope host, and folds the resulting map into grounded state so the
    planner reasons over real endpoints.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.web import FakeWebCage, GovernedBrowser
from brukal import webmap

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"
TARGET = "10.10.10.5"


class SeqLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.i = 0

    def propose(self, system, user, max_tokens=1024):
        r = self.responses[min(self.i, len(self.responses) - 1)]
        self.i += 1
        return r


# ---- pure extractor -------------------------------------------------------- #

def test_extract_finds_links_forms_inputs_and_params():
    html = """
    <html><body>
      <a href="/login">Login</a>
      <a href="search?q=test&page=2">Search</a>
      <a href="mailto:a@b.c">mail</a>
      <a href="javascript:void(0)">js</a>
      <form action="/subscribe" method="POST">
        <input name="email" type="email"><input name="csrf" type="hidden">
      </form>
    </body></html>
    """
    base = "http://10.10.10.5/home"
    links, forms, params = webmap.extract(base, html)
    assert "http://10.10.10.5/login" in links
    assert "http://10.10.10.5/search?q=test&page=2" in links
    # non-navigable schemes are dropped
    assert not any("mailto" in l or "javascript" in l for l in links)
    # the form is resolved to an absolute action with its inputs
    assert any(f.action == "http://10.10.10.5/subscribe" and f.method == "POST"
               and dict(f.inputs).get("email") == "email" for f in forms)
    # query params are grouped under the base URL
    assert params.get("http://10.10.10.5/search") == {"q", "page"}


def test_normalize_url_strips_fragment_and_rejects_non_http():
    assert webmap.normalize_url("http://h/a/b", "../c#frag") == "http://h/c"
    assert webmap.normalize_url("http://h/", "ftp://h/x") == ""
    assert webmap.host_of("https://sub.nexus.htb:8080/p") == "sub.nexus.htb"


def test_malformed_html_does_not_raise():
    links, forms, params = webmap.extract("http://h/", "<a href=/x><form><input name=q>")
    assert "http://h/x" in links
    # the unclosed form + input is still captured
    assert any(dict(f.inputs).get("q") for f in forms)


# ---- governed crawl -------------------------------------------------------- #

ROOT = ("<a href='/login'>l</a> <a href='/search?q=1'>s</a> "
        "<a href='http://evil.com/out'>x</a> "
        "<form action='/subscribe' method='post'><input name='email'></form>")
LOGIN = "<form action='/login' method='post'><input name='user'><input name='pw'></form>"
SEARCH = "<a href='/search?q=2'>more</a> results"


def _session_with_site():
    tmp = tempfile.mkdtemp()
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tmp) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    cage = FakeWebCage({           # specific fragments FIRST (FakeWebCage matches substrings)
        "/login": LOGIN,
        "/search": SEARCH,
        "10.10.10.5/": ROOT,
    })
    browser = GovernedBrowser(scope, cage, audit)
    sess = AssistSession(TARGET, ex, StrategistAgent(SeqLLM(["x"])), browser=browser)
    return sess, tmp


def test_crawl_maps_in_scope_pages_and_never_leaves_scope():
    sess, tmp = _session_with_site()
    try:
        surface = sess.crawl(seeds=["http://10.10.10.5/"], max_pages=10, max_depth=2)
        # visited the root + the two in-scope links
        assert "http://10.10.10.5/" in surface.pages
        assert "http://10.10.10.5/login" in surface.pages
        assert "http://10.10.10.5/search?q=1" in surface.pages
        # NEVER fetched the out-of-scope host
        assert not any(webmap.host_of(p) == "evil.com" for p in surface.pages)
        assert not any(webmap.host_of(l) == "evil.com" for l in surface.links)
        # forms + params were captured
        assert any("login" in f.action for f in surface.forms)
        assert "q" in surface.params.get("http://10.10.10.5/search", set())
        # the map is folded into grounded state
        assert sess.surface is surface
        assert any(tag == "site-map" for tag, _ in sess.highlights)
        assert "SITE MAP" in sess._highlights_text()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_auto_loop_crawls_the_moment_a_web_port_is_known():
    # The grounded loop must reflexively CRAWL (once) when a web service appears, so
    # the model plans against the mapped surface. We seed an open :80 finding, then
    # let the strategist hand off — the crawl must have happened first.
    from brukal.loop import GroundedLoop

    sess, tmp = _session_with_site()
    try:
        sess.highlights.append(("port", "80/tcp open http"))     # a web service exists
        sess.strategist = StrategistAgent(SeqLLM([
            "PHASE: recon\nGOAL: hand off\nREASONING: over to you.\nMANUAL: your move",
        ]))
        loop = GroundedLoop(sess, max_steps=5)
        result = loop.run()
        assert sess.surface is not None
        assert "http://10.10.10.5/" in sess.surface.pages
        assert any((s.command or "").startswith("CRAWL:") for s in result.steps)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_crawl_respects_page_budget():
    sess, tmp = _session_with_site()
    try:
        surface = sess.crawl(seeds=["http://10.10.10.5/"], max_pages=1, max_depth=3)
        assert len(surface.pages) == 1        # stopped at the budget
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- API route mining (the SPA gap: endpoints live in the JS bundle) --------

def test_extract_api_routes_from_js_bundle():
    js = ('this.http.get("/rest/user/login");const p=`/api/Products`;'
          'x="/rest/products/search?q=";y=/rest\\/admin/;z="/oauth/token";'
          'ignore="/assets/img/logo.png";dup="/rest/user/login";')
    routes = webmap.extract_api_routes(js)
    assert "/rest/user/login" in routes
    assert "/api/Products" in routes
    assert "/rest/products/search" in routes
    assert "/oauth/token" in routes
    assert routes.count("/rest/user/login") == 1          # deduped
    assert "/assets/img/logo.png" not in routes           # not an API-ish path


def test_extract_api_routes_caps_and_tolerates_junk():
    blob = " ".join(f'"/api/thing{i}"' for i in range(200))
    assert len(webmap.extract_api_routes(blob, max_routes=40)) == 40
    assert webmap.extract_api_routes("") == []
    assert webmap.extract_api_routes("no routes here, just prose about apiaries") == []


def test_static_assets_are_not_mined_as_api_routes():
    """Font/image paths match the route shapes but are never endpoints, and under a cap
    they displace real ones — the live run kept three .woff2 paths and dropped the chat
    API."""
    blob = ('"/v18/pxiKyp0ihIEF2isQFJXGdg.woff2" "/products/juicy_chatbot.jpg" '
            '"/assets/main.css" "/rest/user/login"')
    routes = webmap.extract_api_routes(blob)
    assert "/rest/user/login" in routes
    assert not [r for r in routes if r.endswith((".woff2", ".jpg", ".css"))]


def test_security_relevant_routes_survive_the_cap():
    """Live-run regression: in a real SPA bundle /rest/chat was unique match 41 of 42
    with the cap at 40, so byte order alone decided the one endpoint worth testing got
    dropped. The interesting routes must be kept first, not the ones that happen to be
    minified early."""
    filler = " ".join(f'"/api/thing{i}"' for i in range(60))   # dull, and first
    blob = filler + ' "/rest/chat"'                            # interesting, and last
    routes = webmap.extract_api_routes(blob, max_routes=40)
    assert len(routes) == 40
    assert "/rest/chat" in routes
    assert routes[0] == "/rest/chat"          # ranked ahead of the filler


def test_surface_summary_lists_api_endpoints():
    s = webmap.AttackSurface(seed="http://10.10.10.5/")
    s.add_page("http://10.10.10.5/", set(), [], {})
    s.add_routes(["/rest/user/login", "/rest/admin", "/api/Products"])
    out = s.summary()
    assert "API route(s)" in out
    assert "/rest/user/login" in out and "/rest/admin" in out


def test_crawl_mines_routes_from_a_linked_js_bundle():
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    root = '<html><body><script src="/main.js"></script>nothing else</body></html>'
    js = 'r.get("/rest/user/login");q="/rest/products/search";a=`/rest/admin`;'
    # specific fragments first (FakeWebCage matches substrings)
    cage = FakeWebCage({"/main.js": js, "10.10.10.5/": root})
    browser = GovernedBrowser(scope, cage, audit)
    sess = AssistSession(TARGET, ex, StrategistAgent(SeqLLM(["x"])), browser=browser)
    surface = sess.crawl(seeds=["http://10.10.10.5/"], max_pages=10, max_depth=2)
    # the SPA's real endpoints, mined from the JS bundle the homepage links to
    assert "/rest/user/login" in surface.api_routes
    assert "/rest/products/search" in surface.api_routes
    assert "/rest/admin" in surface.api_routes


# --- the crawl trigger fires from an executed web command (not just nmap) ---

def test_web_urls_from_executed_commands():
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    sess = AssistSession(TARGET, ex, StrategistAgent(SeqLLM(["x"])))
    # No nmap "open http" highlight at all — only a web command that already ran.
    assert sess.web_urls_from_findings() == []
    sess.executed_cmds.append("whatweb http://10.10.10.5:3000")
    sess.executed_cmds.append("curl -s http://10.10.10.5:3000/rest/user/login")
    urls = sess.web_urls_from_findings()
    assert "http://10.10.10.5:3000/" in urls        # crawl can now seed from this
    assert len(urls) == 1                            # base URL deduped across commands


def test_unlabelled_app_port_still_seeds_the_crawl():
    """Live-run regression: nmap fingerprinted OWASP Juice Shop's port 3000 as "ppp?",
    so the web-surface reflex skipped it and the entire web app was invisible — the run
    fell back to a guessed port-80 URL and crawled nothing. An open COMMON web port that
    nmap could not identify is a candidate worth one fetch, not a dead end."""
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    sess = AssistSession(TARGET, ex, StrategistAgent(SeqLLM(["x"])))
    # the exact shape nmap emitted during the live run
    sess.highlights.append(("port", "open port: 3000/tcp open  ppp?    syn-ack ttl 64"))
    assert f"http://{TARGET}:3000/" in sess.web_urls_from_findings()


def test_unlabelled_port_heuristic_stays_narrow():
    """It must not turn every unidentified port into a web fetch — only the ports that
    actually carry apps, and only when nmap is unsure."""
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    sess = AssistSession(TARGET, ex, StrategistAgent(SeqLLM(["x"])))
    sess.highlights.append(("port", "22/tcp open ssh"))            # known non-web
    sess.highlights.append(("port", "12345/tcp open unknown"))     # unusual port
    sess.highlights.append(("port", "3306/tcp open mysql"))        # identified, not web
    assert sess.web_urls_from_findings() == []
    # https inferred for the TLS-ish app ports
    sess.highlights.append(("port", "8443/tcp open  tcpwrapped"))
    assert f"https://{TARGET}:8443/" in sess.web_urls_from_findings()


# --- soft-404 detection (SPA returns 200 for missing paths) -----------------

def test_soft_404_warning_in_summary():
    s = webmap.AttackSurface(seed="http://10.10.10.5/")
    s.add_page("http://10.10.10.5/", set(), [], {})
    assert "SOFT-404" not in s.summary()
    s.soft_404 = True
    out = s.summary()
    assert "SOFT-404" in out
    assert "do not trust path-discovery" in out.lower() or "does not" in out.lower()


def test_crawl_merges_a_second_web_surface():
    """A second surface (the app on another port, found after the first crawl) must ADD
    to the map, not replace it — otherwise whichever crawl ran last wins and the earlier
    one's endpoints vanish."""
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    sess = AssistSession(TARGET, ex, StrategistAgent(SeqLLM(["x"])))

    first = webmap.AttackSurface(seed=f"http://{TARGET}/")
    first.add_page(f"http://{TARGET}/", {f"http://{TARGET}/a"}, [], {})
    first.add_routes(["/rest/user/login"])
    sess.surface = first

    class _Cage:
        def run(self, action):
            from brukal.web import WebResult
            return WebResult(status=200, url=action.url,
                             body='<a href="/shop">s</a> "/rest/chat"')

    from brukal.web import GovernedBrowser
    sess.browser = GovernedBrowser(scope, _Cage(), audit)
    sess.crawl(seeds=[f"http://{TARGET}:3000/"], max_pages=2, merge=True)

    routes = sess.surface.api_routes
    assert "/rest/user/login" in routes            # the first surface survived
    assert "/rest/chat" in routes                  # and the second was folded in
    assert f"http://{TARGET}/" in sess.surface.pages


def test_bare_host_strips_url_forms():
    """nmap takes a host, not a URL: a live run lost its whole budget because the model
    sent `nmap -sV http://172.20.0.2`, which resolves nothing and finds no ports."""
    from brukal.loop import _bare_host
    assert _bare_host("http://172.20.0.2") == "172.20.0.2"
    assert _bare_host("https://shop.example.com:3000/path?q=1") == "shop.example.com"
    assert _bare_host("10.10.10.5") == "10.10.10.5"
    assert _bare_host("10.10.10.0/24") == "10.10.10.0/24"      # CIDR kept intact


def test_loop_sweeps_for_the_web_surface_when_nothing_is_known():
    """The app port must be discovered by Brukal, not left to the model's nmap syntax.
    With no web finding yet, the loop sweeps the common app ports once, itself."""
    from brukal.loop import GroundedLoop

    sess, tmp = _session_with_site()
    try:
        assert sess.web_urls_from_findings() == []      # nothing web-facing known
        sess.strategist = StrategistAgent(SeqLLM([
            "PHASE: recon\nGOAL: hand off\nREASONING: over to you.\nMANUAL: your move",
        ]))
        loop = GroundedLoop(sess, max_steps=4)
        result = loop.run()
        sweeps = [s for s in result.steps if (s.command or "").startswith("nmap -Pn")]
        assert len(sweeps) == 1                         # exactly once, not every turn
        cmd = sweeps[0].command
        assert cmd.endswith(TARGET)                     # a bare host, never a URL
        assert ",3000," in cmd and ",8080," in cmd      # the common app ports
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
