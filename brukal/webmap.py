"""
webmap.py — the web attack-surface map (control-plane, stdlib-only, NO egress).

Brukal RENDERS a page through the governed browser (in the cage, whose egress is
scope-locked). This module takes the HTML that came back — untrusted DATA — and,
WITHOUT touching the network, extracts the attack surface: in-scope links to crawl
next, forms and their inputs, and query parameters. The result is a structured map
the strategist / exploit agent reasons over instead of guessing endpoints — the
single biggest lever for making a weak model methodical about coverage.

Two rules keep it safe, and they are why this file lives in the stdlib-only core:

  * It performs NO I/O. It only parses strings the cage already fetched, so it can
    never itself reach a host (in scope or out). Every fetch stays behind the gate.
  * Everything it emits is UNTRUSTED. A crawled page can carry attacker-planted
    links or labels; they become data in the map, never instructions, and every URL
    is still gate-checked before the cage is asked to fetch it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

# Link-bearing (tag, attribute) pairs we harvest for the crawl frontier + surface.
_LINK_ATTRS = {
    "a": "href", "link": "href", "area": "href",
    "script": "src", "img": "src", "iframe": "src", "source": "src",
    "form": "action",
}


@dataclass(frozen=True)
class Form:
    """One HTML form: where it submits, how, and its input names/types — the raw
    material for parameter fuzzing / injection probing later."""
    action: str
    method: str = "GET"
    inputs: tuple = ()                      # tuple of (name, type)

    def describe(self) -> str:
        names = ",".join(n for n, _t in self.inputs) or "-"
        return f"{self.method} {self.action or '(self)'} [{names}]"


class _SurfaceParser(HTMLParser):
    """Lenient HTML sweep: collect link/asset URLs and the forms + their inputs.
    Tolerates malformed markup (that's the point of html.parser) and never executes
    anything — it only reads attributes."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []
        self.forms: list[Form] = []
        self._cur: dict | None = None          # form being assembled

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in _LINK_ATTRS:
            val = a.get(_LINK_ATTRS[tag], "").strip()
            if val and not val.lower().startswith(("javascript:", "data:", "mailto:",
                                                   "tel:", "#")):
                self.hrefs.append(val)
        if tag == "form":
            # flush any un-closed previous form, then start a new one
            self._flush_form()
            self._cur = {"action": a.get("action", "").strip(),
                         "method": (a.get("method", "get") or "get").upper(),
                         "inputs": []}
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            name = a.get("name", "").strip()
            if name:
                self._cur["inputs"].append((name, a.get("type", tag).lower()))

    def handle_endtag(self, tag):
        if tag == "form":
            self._flush_form()

    def _flush_form(self):
        if self._cur is not None:
            self.forms.append(Form(action=self._cur["action"],
                                   method=self._cur["method"],
                                   inputs=tuple(self._cur["inputs"])))
            self._cur = None

    def close(self):
        super().close()
        self._flush_form()


def normalize_url(base: str, href: str) -> str:
    """Resolve `href` against `base`, drop the fragment, and canonicalise — so
    `/a`, `a`, and `http://h/a#x` from the same page collapse to one URL."""
    try:
        joined = urljoin(base, href)
        s = urlsplit(joined)
    except ValueError:
        return ""
    if s.scheme not in ("http", "https"):
        return ""
    path = s.path or "/"
    return urlunsplit((s.scheme, s.netloc, path, s.query, ""))   # fragment stripped


def host_of(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def params_of(url: str) -> set[str]:
    """Query-parameter names in a URL (an injection/IDOR surface)."""
    try:
        return {k for k, _v in parse_qsl(urlsplit(url).query, keep_blank_values=True)}
    except ValueError:
        return set()


def base_of(url: str) -> str:
    """URL without its query string — the key we group parameters under."""
    s = urlsplit(url)
    return urlunsplit((s.scheme, s.netloc, s.path or "/", "", ""))


def extract(base_url: str, html: str):
    """Parse one fetched page. Returns (links, forms, params):
      links  : set of normalised absolute URLs referenced by the page
      forms  : list[Form] with inputs resolved to absolute action URLs
      params : dict of base-URL -> set(param names) seen (from links + this URL)
    Pure parsing; no network, no scope decision (the caller filters + gates)."""
    p = _SurfaceParser()
    try:
        p.feed(html or "")
        p.close()
    except Exception:
        pass                                   # malformed HTML must never raise here

    links: set[str] = set()
    params: dict[str, set[str]] = {}

    def _record(u: str):
        if not u:
            return
        links.add(u)
        pr = params_of(u)
        if pr:
            params.setdefault(base_of(u), set()).update(pr)

    for href in p.hrefs:
        _record(normalize_url(base_url, href))
    # the current page's own query params count too
    for k in params_of(base_url):
        params.setdefault(base_of(base_url), set()).add(k)

    forms = [Form(action=normalize_url(base_url, f.action) or base_of(base_url),
                  method=f.method, inputs=f.inputs) for f in p.forms]
    return links, forms, params


# API-ish route paths embedded in a JS bundle or HTML. A single-page app (Angular/
# React/Vue) ships almost no forms in its initial HTML — the real endpoints live as
# string literals in the JS bundle. Mining them turns a "0 forms" SPA into a concrete
# list of endpoints for the planner to reason over. Untrusted data; the gate still rules.
_API_ROUTE_RE = re.compile(
    r"/(?:rest|api|graphql|v[0-9]{1,2}|actuator|admin|internal|oauth|auth|user|users|"
    r"account|token|login|logout|register|products?|orders?|search|upload|files?|"
    r"download|export|import|config|debug|metrics|swagger|api-docs)"
    r"(?:/[A-Za-z0-9_.~:{}-]{1,50}){0,5}", re.I)


def extract_api_routes(text: str, max_routes: int = 40) -> list[str]:
    """Pull distinct API-ish route paths out of a fetched body (JS bundle or HTML).
    Deterministic regex over UNTRUSTED text — the paths become leads in the site map,
    never instructions, and any request to one still goes through the gate."""
    seen: list[str] = []
    for m in _API_ROUTE_RE.finditer(text or ""):
        r = m.group(0).rstrip("/.,;:'\"")
        if 2 < len(r) <= 80 and r not in seen:
            seen.append(r)
            if len(seen) >= max_routes:
                break
    return seen


@dataclass
class AttackSurface:
    """The accumulated map of a crawl: pages actually fetched, the frontier of
    in-scope links discovered, forms, and parameterised endpoints. Untrusted data —
    a compact `summary()` of it is handed to the model as grounding."""
    seed: str = ""
    pages: set = field(default_factory=set)          # URLs fetched (visited)
    links: set = field(default_factory=set)          # in-scope URLs discovered
    forms: list = field(default_factory=list)        # list[Form] (deduped)
    params: dict = field(default_factory=dict)       # base-URL -> set(param names)
    techs: set = field(default_factory=set)          # tech fingerprints noticed
    api_routes: list = field(default_factory=list)   # API route paths mined from JS/HTML

    def add_page(self, url: str, links, forms, params) -> None:
        self.pages.add(url)
        self.links.update(links)
        for f in forms:
            if f not in self.forms:
                self.forms.append(f)
        for b, names in params.items():
            self.params.setdefault(b, set()).update(names)

    def add_routes(self, routes, cap: int = 60) -> None:
        """Fold API routes mined from a body into the map (deduped, capped)."""
        for r in routes:
            if r not in self.api_routes and len(self.api_routes) < cap:
                self.api_routes.append(r)

    @property
    def param_endpoints(self) -> int:
        return len(self.params)

    def summary(self, max_items: int = 8) -> str:
        """A compact, grounding-friendly rendering of the surface for the model."""
        host = host_of(self.seed) or self.seed
        lines = [f"SITE MAP — crawled {len(self.pages)} page(s) on {host}; "
                 f"{len(self.links)} link(s), {len(self.forms)} form(s), "
                 f"{self.param_endpoints} parameterised endpoint(s), "
                 f"{len(self.api_routes)} API route(s)."]
        if self.techs:
            lines.append("  techs: " + ", ".join(sorted(self.techs)[:8]))
        if self.api_routes:
            # The high-value grounding for a SPA/API: concrete endpoints to go after.
            lines.append("  API endpoints (probe these; auth/login/search/admin first): "
                         + ", ".join(self.api_routes[:24]))
        for f in self.forms[:max_items]:
            lines.append(f"  form: {f.describe()}")
        shown = 0
        for b, names in self.params.items():
            lines.append(f"  params: {b} ? {','.join(sorted(names))}")
            shown += 1
            if shown >= max_items:
                break
        return "\n".join(lines)
