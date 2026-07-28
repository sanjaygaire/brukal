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
