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

import json
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


# Static assets that match the route shapes but are never an API endpoint. They cost
# nothing to match and everything to keep: under a hard cap they push real endpoints out.
_ASSET_RE = re.compile(
    r"\.(?:woff2?|ttf|otf|eot|css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|"
    r"mp4|webm|mp3|wav|pdf|zip|gz)$", re.I)
# Route substrings worth keeping FIRST when the cap bites — the security-relevant
# surface (auth, admin, money, LLM features), so a minified bundle's byte order never
# decides which endpoints the planner gets to see.
_HOT_ROUTE_RE = re.compile(
    r"chat|assistant|copilot|llm|prompt|login|logout|auth|admin|token|session|user|"
    r"account|password|reset|register|graphql|upload|download|file|search|order|"
    r"basket|cart|payment|card|wallet|coupon|key|secret|credential|config|debug|"
    r"internal|actuator|metrics|swagger|api-docs|oauth|profile|export|import|whoami",
    re.I)


# Where an API publishes its own contract. A JSON API has no HTML to crawl and no JS
# bundle to mine — its root is a bare JSON blob — so without this an entire target maps
# to zero endpoints. When one of these answers, the app hands over its whole surface.
SPEC_PATHS = ("/openapi.json", "/swagger.json", "/v2/swagger.json", "/v3/api-docs",
              "/api-docs", "/api/openapi.json", "/swagger/v1/swagger.json",
              "/api/swagger.json")


def routes_from_openapi(text: str) -> list[str]:
    """Endpoint paths declared by an OpenAPI/Swagger JSON document, prefixed with the
    document's own base path. Pure parsing of UNTRUSTED text — the paths become leads,
    and every request to one still goes through the gate."""
    try:
        doc = json.loads(text or "")
    except Exception:
        return []
    if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
        return []
    prefix = ""
    base = doc.get("basePath")
    if isinstance(base, str) and base.startswith("/"):
        prefix = base.rstrip("/")                       # Swagger 2
    else:                                               # OpenAPI 3: servers[0].url
        servers = doc.get("servers")
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            url = servers[0].get("url")
            if isinstance(url, str) and url.startswith("/"):
                prefix = url.rstrip("/")
    out: list[str] = []
    for p in doc["paths"]:
        if isinstance(p, str) and p.startswith("/"):
            r = f"{prefix}{p}" if prefix else p
            if r not in out:
                out.append(r)
    return out


# Only ever probed with SAFE methods. An API's spec also declares DELETE and PUT
# operations; discovering that a destructive one is unprotected is not worth performing
# it, so the check reads the contract and exercises reads alone.
_SAFE_METHODS = frozenset({"get", "head"})


# Fields that name an object, and fields that name who owns it. A collection endpoint
# that lists both is handing over exactly what a two-identity authorization test needs.
_ID_FIELDS = ("id", "uuid", "slug", "name", "title", "book_title", "username", "email",
              "key", "ref", "number", "code")
_OWNER_FIELDS = ("user", "owner", "username", "user_id", "owner_id", "author",
                 "created_by", "account", "customer")


def objects_with_owners(text: str) -> list[tuple[str, str]]:
    """(identifier, owner) pairs from a JSON collection listing.

    An API that lists objects alongside whose they are has disclosed the map for an
    object-authorization test: pick one that is not yours and see whether the server
    hands it over. Pure parsing of an UNTRUSTED body — the ownership claim is the app's
    own, which is why a finding built on it also has to prove the endpoint is protected
    and that the content really differs."""
    try:
        doc = json.loads(text or "")
    except Exception:
        return []
    rows: list[dict] = []

    def walk(node, depth=0):
        if depth > 4 or len(rows) > 200:
            return
        if isinstance(node, list):
            for item in node:
                if isinstance(item, dict):
                    rows.append(item)
                else:
                    walk(item, depth + 1)
        elif isinstance(node, dict):
            for value in node.values():
                walk(value, depth + 1)

    walk(doc)
    out: list[tuple[str, str]] = []
    for row in rows:
        lower = {str(k).lower(): v for k, v in row.items()}
        ident = next((str(lower[f]) for f in _ID_FIELDS
                      if isinstance(lower.get(f), (str, int)) and str(lower[f]).strip()),
                     "")
        owner = next((str(lower[f]) for f in _OWNER_FIELDS
                      if isinstance(lower.get(f), (str, int)) and str(lower[f]).strip()
                      and str(lower[f]) != ident), "")
        if ident and owner and (ident, owner) not in out:
            out.append((ident, owner))
    return out


# Fields whose presence in a response is the finding. Credentials are decisive on their
# own; personal data matters when it is served in BULK about people who are not you.
_CREDENTIAL_FIELDS = ("password", "passwd", "pwd", "pass", "secret", "api_key", "apikey",
                      "private_key", "token", "auth_token", "session", "hash",
                      "password_hash", "salt", "credit_card", "card_number", "cvv")
_PII_FIELDS = ("email", "e_mail", "mail", "phone", "mobile", "telephone", "ssn",
               "national_id", "dob", "date_of_birth", "address", "postcode", "zip",
               "first_name", "last_name", "full_name")


def sensitive_records(text: str) -> tuple[int, list[str], str]:
    """(record count, which sensitive fields, severity) for a JSON collection response.

    Bulk is the point. One record about the caller is the caller's own profile; the same
    fields repeated across many principals is a data exposure. Credentials outrank
    personal data — a password or hash in a response is decisive regardless of volume.
    Returns (0, [], "") when there is nothing to say."""
    try:
        doc = json.loads(text or "")
    except Exception:
        return 0, [], ""
    rows: list[dict] = []

    def walk(node, depth=0):
        if depth > 4 or len(rows) > 500:
            return
        if isinstance(node, list):
            for item in node:
                if isinstance(item, dict):
                    rows.append(item)
                else:
                    walk(item, depth + 1)
        elif isinstance(node, dict):
            for value in node.values():
                walk(value, depth + 1)

    walk(doc)
    if not rows:
        return 0, [], ""
    creds: set = set()
    pii: set = set()
    for row in rows:
        for key in row:
            k = str(key).lower()
            if k in _CREDENTIAL_FIELDS:
                creds.add(k)
            elif k in _PII_FIELDS:
                pii.add(k)
    if creds:
        return len(rows), sorted(creds | pii), "critical"
    if pii and len(rows) >= 2:          # bulk personal data about several principals
        return len(rows), sorted(pii), "high"
    return 0, [], ""


def graphql_schema(text: str) -> tuple[int, list[str]]:
    """(type count, notable type names) from an introspection response.

    A GraphQL endpoint that answers introspection has handed over its entire schema —
    every type, field and mutation, including the ones no client is meant to call. The
    check is structural, not textual: the response must actually contain a __schema with
    types, which is what tells a real endpoint apart from a single-page app that returns
    its index.html with status 200 for every path."""
    try:
        doc = json.loads(text or "")
    except Exception:
        return 0, []
    if not isinstance(doc, dict):
        return 0, []
    schema = ((doc.get("data") or {}).get("__schema")
              if isinstance(doc.get("data"), dict) else None)
    if not isinstance(schema, dict):
        return 0, []
    types = schema.get("types")
    if not isinstance(types, list):
        return 0, []
    names = [t.get("name") for t in types
             if isinstance(t, dict) and isinstance(t.get("name"), str)]
    real = [n for n in names if not n.startswith("__")]
    # Types worth naming in a report: the mutation surface and anything that sounds
    # administrative or personal.
    notable = [n for n in real if re.search(
        r"(?i)mutation|user|account|admin|password|token|secret|credit|payment|order|"
        r"internal|audit|import|paste", n)]
    return len(real), notable[:12]


def protected_operations(text: str) -> list[tuple[str, str]]:
    """(METHOD, path) for the operations an OpenAPI document declares as REQUIRING
    authentication — per-operation `security`, or the document-level default that an
    operation has not opted out of with `security: []`.

    The spec is the app's own statement of which endpoints must be protected, which
    makes 'declared protected, answers anyway' a deterministic, high-value check
    (OWASP API2/API5) that needs no credentials to run."""
    try:
        doc = json.loads(text or "")
    except Exception:
        return []
    if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
        return []
    prefix = ""
    base = doc.get("basePath")
    if isinstance(base, str) and base.startswith("/"):
        prefix = base.rstrip("/")
    else:
        servers = doc.get("servers")
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            url = servers[0].get("url")
            if isinstance(url, str) and url.startswith("/"):
                prefix = url.rstrip("/")
    default_sec = doc.get("security")
    out: list[tuple[str, str]] = []
    for path, ops in doc["paths"].items():
        if not isinstance(path, str) or not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if not isinstance(op, dict) or method.lower() not in _SAFE_METHODS:
                continue
            sec = op.get("security", default_sec)
            if not sec:                       # absent, or explicitly opted out with []
                continue
            entry = (method.upper(), f"{prefix}{path}" if prefix else path)
            if entry not in out:
                out.append(entry)
    return out


def extract_api_routes(text: str, max_routes: int = 40) -> list[str]:
    """Pull distinct API-ish route paths out of a fetched body (JS bundle or HTML).
    Deterministic regex over UNTRUSTED text — the paths become leads in the site map,
    never instructions, and any request to one still goes through the gate.

    Static assets are dropped, and the security-relevant routes are kept first. Both
    matter under the cap: on a real SPA bundle the chat endpoint sat at match 41 of 42
    with the cap at 40, so scanning in byte order and truncating lost precisely the
    endpoint worth testing while keeping two image paths.
    """
    seen: list[str] = []
    for m in _API_ROUTE_RE.finditer(text or ""):
        r = m.group(0).rstrip("/.,;:'\"")
        if 2 < len(r) <= 80 and r not in seen and not _ASSET_RE.search(r):
            seen.append(r)
    hot = [r for r in seen if _HOT_ROUTE_RE.search(r)]
    cold = [r for r in seen if not _HOT_ROUTE_RE.search(r)]
    return (hot + cold)[:max_routes]


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
    protected_routes: list = field(default_factory=list)  # (METHOD, path) the spec says need auth
    soft_404: bool = False                           # host answers 200 for missing paths

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
        if self.soft_404:
            lines.append("  ⚠ SOFT-404: this host returns 200 for paths that do not "
                         "exist (SPA/catch-all). A 200 from ffuf/gobuster/nikto does NOT "
                         "mean the path exists — do not trust path-discovery hits; go "
                         "after the API endpoints below, params, and injection/logic.")
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
