r"""
web.py — the GOVERNED web-exploitation surface.

Web testing (intercept a request, tamper with a header/body, replay it, fill a
field with a payload, follow a redirect to a vhost) needs a different primitive
than "run a shell tool" — but it must obey the SAME governance. So this module
mirrors executor.py exactly:

    WebAction  ->  check_web()  ->  [ALLOW] -> WebCage.run()  -> audit log
                                \->  [DENY]                    -> audit, do not run

Every web action is scope-checked in DETERMINISTIC code before it touches the
network: the action's host must be an authorised IP *or* an authorised hostname
(e.g. a HTB vhost like `nexus.htb`, set at scope time — never resolved from DNS at
runtime, so a hostile DNS answer cannot widen scope). The scheme must be http/https
(a `javascript:` / `file:` / `data:` URL is refused). Anything unparseable is
DENIED (fail-closed). No language model sits in this decision (invariant 1); the
host is re-read from the URL, not trusted from a declared field (invariant 3).

Agents are handed a `GovernedBrowser`, never a raw `WebCage` — the same structural
guarantee that makes gate-bypass impossible for shell actions (invariant 4). Two
backends: `FakeWebCage` (deterministic, for tests) and `HttpWebCage` (real crafted
HTTP requests — the interception/replay/tamper primitive). A full Chrome/CDP
backend for live browser interaction + request interception plugs in here next.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .audit import AuditLog
from .gate import Decision
from .scope import Scope

# Actions that carry their own URL (host read from it) vs. actions that operate on
# the currently-loaded page (host read from the browser's current URL).
_URL_ACTIONS = frozenset({"navigate", "get", "request"})
_PAGE_ACTIONS = frozenset({"click", "fill", "screenshot", "eval"})
_INTERCEPT_ACTIONS = frozenset({"intercept"})
_ALL_ACTIONS = _URL_ACTIONS | _PAGE_ACTIONS | _INTERCEPT_ACTIONS
_OK_SCHEMES = frozenset({"http", "https"})


@dataclass
class WebAction:
    """One governed web action the model proposes (text in, structured here)."""
    kind: str                                   # navigate|get|request|click|fill|screenshot|eval|intercept
    url: str = ""                               # for navigate/get/request (and intercept match)
    method: str = "GET"                         # for request
    headers: dict = field(default_factory=dict)  # for request / intercept-modify
    body: str = ""                              # for request / intercept-modify
    selector: str = ""                          # for click/fill
    value: str = ""                             # for fill (an attack payload, NOT sanitised)
    expression: str = ""                        # for eval (JS in page context)

    def describe(self) -> str:
        if self.kind in _URL_ACTIONS:
            m = f"{self.method} " if self.kind == "request" else ""
            return f"{self.kind}: {m}{self.url}"
        if self.kind == "fill":
            return f"fill {self.selector} = {self.value[:40]}"
        if self.kind in ("click", "eval"):
            return f"{self.kind} {self.selector or self.expression[:40]}"
        return f"{self.kind} {self.url or self.selector}".strip()


@dataclass
class WebResult:
    status: int | None = None                   # HTTP status (get/request), else None
    url: str = ""
    body: str = ""
    headers: dict = field(default_factory=dict)
    note: str = ""


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _scheme_of(url: str) -> str:
    try:
        return (urlsplit(url).scheme or "").lower()
    except ValueError:
        return ""


def check_web(action: WebAction, scope: Scope, current_url: str = "",
              agent: str = "web") -> Decision:
    """Deterministically rule on one web action. Scope is enforced on the HOST the
    action touches; the scheme must be http/https; unparseable => DENY (fail-closed).
    Returns the same Decision object the shell gate emits, so web and shell actions
    share one audit schema."""
    kind = (action.kind or "").lower()
    desc = action.describe()

    def deny(reason, layer="hard:web"):
        return Decision(verdict="DENY", action=desc, target="", agent=agent,
                        reason=reason, layer=layer)

    if kind not in _ALL_ACTIONS:
        return deny(f"unknown web action '{action.kind}'")

    # Which URL does this action touch? URL-actions carry it; page-actions inherit
    # the currently-loaded page (which only a prior gated navigate could have set).
    if kind in _URL_ACTIONS or kind in _INTERCEPT_ACTIONS:
        url = action.url
        if not url:
            return deny(f"{kind} requires a url")
    else:
        url = current_url
        if not url:
            return deny(f"{kind} needs an in-scope page loaded first (navigate)")

    scheme = _scheme_of(url)
    if scheme and scheme not in _OK_SCHEMES:
        return deny(f"scheme '{scheme}' not allowed (only http/https)", "hard:web-scheme")
    host = _host_of(url)
    if not host:
        return deny("could not parse a host from the url")
    if not scope.contains_host(host):
        return deny(f"host '{host}' is out of scope", "hard:web-scope")

    return Decision(verdict="ALLOW", action=desc, target=host, agent=agent,
                    reason=f"in-scope web {kind} on {host}", layer="web:allow")


# --------------------------------------------------------------------------- #
# cages (backends)
# --------------------------------------------------------------------------- #

class FakeWebCage:
    """Deterministic web backend for tests: records actions, returns canned
    results, and remembers interception rules — no real network or browser."""

    def __init__(self, responses: dict | None = None):
        self.actions: list[WebAction] = []
        self.intercepts: list[WebAction] = []
        self._responses = responses or {}      # url-substring -> body

    def run(self, action: WebAction) -> WebResult:
        self.actions.append(action)
        if action.kind == "intercept":
            self.intercepts.append(action)
            return WebResult(url=action.url, note=f"interception armed for {action.url}")
        if action.kind in ("get", "request"):
            body = next((b for frag, b in self._responses.items() if frag in action.url),
                        f"[fake {action.method} {action.url}]")
            return WebResult(status=200, url=action.url, body=body,
                             headers={"x-fake": "1"})
        if action.kind == "navigate":
            return WebResult(status=200, url=action.url, body="[fake page]")
        return WebResult(url=action.url, note=f"[fake {action.kind}] {action.describe()}")


_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


class _NoAutoRedirect(urllib.request.HTTPRedirectHandler):
    """Do NOT auto-follow redirects. urllib normally chases a 3xx transparently —
    which means an in-scope host that 302s to an out-of-scope host would be reached
    with NO second scope check (a real escape). Returning None from redirect_request
    makes urllib raise the 3xx as an HTTPError instead, so the cage can surface the
    Location and require the caller to resubmit the next hop as a fresh, gated
    WebAction through check_web()."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# One opener, shared: build_opener installs default handlers plus ours, so the
# no-follow behaviour applies to every HttpWebCage request.
_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoAutoRedirect)


class HttpWebCage:
    """Real crafted-HTTP-request backend (the interception/replay/tamper primitive):
    sends an arbitrary method/headers/body to an in-scope URL and returns the real
    response. Redirects are NOT auto-followed — a 3xx is surfaced with its Location so
    the next hop is re-checked by the gate (no cross-scope redirect escape). Browser-
    only actions (navigate/click/fill/intercept) raise until the Chrome/CDP backend
    lands — use FakeWebCage or the Chrome backend for those."""

    def __init__(self, timeout: int = 20, max_body: int = 20000):
        self.timeout = timeout
        self.max_body = max_body

    def run(self, action: WebAction) -> WebResult:
        if action.kind not in ("get", "request"):
            raise NotImplementedError(
                f"'{action.kind}' needs the Chrome backend; HttpWebCage does get/request")
        method = "GET" if action.kind == "get" else (action.method or "GET").upper()
        data = action.body.encode() if action.body else None
        req = urllib.request.Request(action.url, data=data, method=method,
                                     headers=action.headers or {})
        try:
            with _NO_REDIRECT_OPENER.open(req, timeout=self.timeout) as resp:
                body = resp.read(self.max_body).decode(errors="replace")
                return WebResult(status=resp.status, url=resp.geturl(), body=body,
                                 headers=dict(resp.headers))
        except urllib.error.HTTPError as e:
            if e.code in _REDIRECT_CODES:
                loc = (e.headers.get("Location") if e.headers else "") or ""
                # DO NOT follow. Surface the Location; the caller must resubmit it as a
                # new gated action so the redirect target is scope-checked.
                return WebResult(status=e.code, url=action.url,
                                 headers=dict(e.headers or {}),
                                 note=f"redirect NOT followed -> {loc} "
                                      f"(resubmit as a new gated action to re-check scope)")
            body = e.read(self.max_body).decode(errors="replace")
            return WebResult(status=e.code, url=action.url, body=body,
                             headers=dict(e.headers or {}), note="http error")
        except urllib.error.URLError as e:
            return WebResult(url=action.url, note=f"unreachable: {e.reason}")


class DockerHttpWebCage:
    """Real crafted-request backend that runs INSIDE the Kali cage, so it reaches
    targets only the cage can route to (e.g. a HTB box over the cage's VPN). The
    request is executed by a fixed python one-liner passed a safe argument vector
    (never a shell string), so there is no shell-injection surface even though the
    URL/headers/body are attacker-controlled payloads."""

    # NB: a no-follow redirect handler (class NR) is installed so a 3xx to an
    # out-of-scope host is surfaced, never chased — same guarantee as HttpWebCage.
    _SCRIPT = (
        "import sys,json,urllib.request,urllib.error\n"
        "class NR(urllib.request.HTTPRedirectHandler):\n"
        " def redirect_request(self,*a):return None\n"
        "op=urllib.request.build_opener(NR)\n"
        "u,m,b=sys.argv[1],sys.argv[2],sys.argv[3]\n"
        "h=dict(x.split(': ',1) for x in sys.argv[4:] if ': ' in x)\n"
        "rq=urllib.request.Request(u,data=b.encode() if b else None,method=m,headers=h)\n"
        "try:\n"
        " r=op.open(rq,timeout=20)\n"
        " print(json.dumps({'status':r.status,'url':r.geturl(),'headers':dict(r.headers),'body':r.read(20000).decode('utf-8','replace')}))\n"
        "except urllib.error.HTTPError as e:\n"
        " if e.code in (301,302,303,307,308):\n"
        "  loc=(e.headers.get('Location') if e.headers else '') or ''\n"
        "  print(json.dumps({'status':e.code,'url':u,'headers':dict(e.headers or {}),'note':'redirect NOT followed -> '+loc+' (resubmit as a new gated action to re-check scope)'}))\n"
        " else:\n"
        "  print(json.dumps({'status':e.code,'url':u,'headers':dict(e.headers or {}),'body':e.read(20000).decode('utf-8','replace'),'note':'http error'}))\n"
        "except Exception as e:\n"
        " print(json.dumps({'status':None,'url':u,'note':str(e)}))\n"
    )

    def __init__(self, container: str = "brukal-kali", user: str = "brukalop",
                 timeout: int = 30):
        self.container = container
        self.user = user
        self.timeout = timeout

    def run(self, action: WebAction) -> WebResult:
        import subprocess
        if action.kind not in ("get", "request"):
            raise NotImplementedError(
                f"'{action.kind}' needs the Chrome backend; this cage does get/request")
        method = "GET" if action.kind == "get" else (action.method or "GET").upper()
        argv = ["docker", "exec", "-u", self.user, self.container,
                "python3", "-c", self._SCRIPT, action.url, method, action.body or ""]
        argv += [f"{k}: {v}" for k, v in (action.headers or {}).items()]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout)
            payload = json.loads(proc.stdout.strip().splitlines()[-1])
        except Exception as e:
            return WebResult(url=action.url, note=f"cage web error: {e}")
        return WebResult(status=payload.get("status"), url=payload.get("url", action.url),
                         body=payload.get("body", ""), headers=payload.get("headers", {}),
                         note=payload.get("note", ""))


# --------------------------------------------------------------------------- #
# the one door for web
# --------------------------------------------------------------------------- #

def parse_web_action(text: str) -> "WebAction | None":
    """Parse a strategist `WEB:` line into a WebAction. Grammar (verb first):
      navigate|get|render <url>      · request <METHOD> <url> [body]
      fill <selector> <payload...>   · click <selector>   · eval <js...>
      screenshot <url>               · intercept <url-pattern>
    A bare http(s) URL is treated as `get`. Returns None if unparseable."""
    toks = (text or "").strip().split()
    if not toks:
        return None
    verb = toks[0].lower()
    rest = toks[1:]
    if verb in ("navigate", "get", "render", "screenshot", "intercept"):
        return WebAction(kind={"render": "get"}.get(verb, verb), url=rest[0] if rest else "")
    if verb == "eval":
        return WebAction(kind="eval", expression=" ".join(rest))
    if verb in ("click", "fill"):
        return WebAction(kind=verb, selector=rest[0] if rest else "",
                         value=" ".join(rest[1:]))
    if verb == "request":
        method = rest[0].upper() if rest else "GET"
        url = rest[1] if len(rest) > 1 else ""
        return WebAction(kind="request", url=url, method=method, body=" ".join(rest[2:]))
    if verb.startswith("http://") or verb.startswith("https://"):
        return WebAction(kind="get", url=verb)
    return None


class CompositeWebCage:
    """One cage that routes each action to the backend that can do it: page
    rendering (navigate/get/screenshot) to the Chrome cage, crafted requests to
    the HTTP cage. Live interactive actions (click/fill/eval/intercept) need the
    CDP backend — until that is wired live they return an explanatory note rather
    than crashing the hunt."""

    def __init__(self, render_cage, request_cage):
        self._render = render_cage
        self._request = request_cage

    def run(self, action: WebAction) -> WebResult:
        k = (action.kind or "").lower()
        if k in ("navigate", "get", "screenshot"):
            return self._render.run(action)
        if k == "request":
            return self._request.run(action)
        return WebResult(url=action.url,
                         note=f"'{k}' needs the live CDP browser (interactive) — "
                              f"not wired live yet; use navigate/get/request/screenshot")


def map_cage_host(host: str, ip: str, container: str = "brukal-kali") -> bool:
    """Best-effort: add `<ip> <host>` to the cage's /etc/hosts so a vhost resolves for
    cage-run web requests and the headless browser. `ip` is validated as an IP and
    `host` as a plain hostname before use (no shell-injection surface). Wildcards are
    skipped (they can't be /etc/hosts entries). Returns True on a mapping attempt."""
    import ipaddress
    import subprocess
    host = (host or "").strip().lower()
    ip = (ip or "").strip()
    if not host or host.startswith("*") or not re.fullmatch(r"[a-z0-9.\-]+", host):
        return False
    try:
        ipaddress.ip_address(ip)                 # reject anything that isn't a clean IP
    except ValueError:
        return False
    try:
        subprocess.run(
            ["docker", "exec", "-u", "root", container, "sh", "-c",
             f"grep -qw {host} /etc/hosts || echo '{ip} {host}' >> /etc/hosts"],
            capture_output=True, timeout=15)
        return True
    except Exception:
        return False


def ensure_cage_vhosts(scope: Scope, container: str = "brukal-kali",
                       target_ip: str = "") -> list[str]:
    """Map the scope's authorised hostnames to an IP inside the cage's /etc/hosts, so a
    vhost like `nexus.htb` actually resolves for cage-run web requests and the browser.
    The IP is `target_ip` (the host being worked — authorised vhosts belong to it), or,
    when no target is given, the single-host /32 the scope authorises. Wildcards are
    skipped. Returns the hostnames it mapped (best-effort; failures ignored)."""
    hosts = sorted(h for h in scope.authorized_hosts if not h.startswith("*"))
    ip = (target_ip or "").strip()
    if not ip:                                   # fall back to a single-host /32 scope
        nets = scope.authorized_networks
        if len(nets) == 1 and nets[0].num_addresses == 1:
            ip = str(nets[0].network_address)
    if not hosts or not ip:
        return []
    return [h for h in hosts if map_cage_host(h, ip, container)]


class GovernedBrowser:
    """The single path from a proposed web action to the network. Gate first, log
    always, run only if ALLOWed — exactly like Executor, but for the web. Agents
    receive THIS, never the raw cage."""

    def __init__(self, scope: Scope, cage, audit: AuditLog):
        self._scope = scope
        self._cage = cage
        self._audit = audit
        self._hits = deque()                   # timestamps, for the rate limit
        self.current_url = ""                  # set only by a gated, successful navigate
        self._cookies: dict = {}               # session cookie jar (name -> value)

    def _apply_cookies(self, action: "WebAction") -> None:
        """Attach the session jar to an outgoing request so authenticated pages are
        reachable after a login. Never overrides a Cookie the caller set explicitly."""
        if self._cookies and not any(k.lower() == "cookie" for k in (action.headers or {})):
            jar = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
            action.headers = {**(action.headers or {}), "Cookie": jar}

    def _absorb_cookies(self, result) -> None:
        """Fold any Set-Cookie from the response into the jar, so the session persists
        across web actions (the basis of authenticated scanning). Robust to a headers
        dict that collapsed multiple Set-Cookie values into one comma-joined string."""
        if result is None:
            return
        for k, v in (result.headers or {}).items():
            if k.lower() != "set-cookie":
                continue
            for piece in re.split(r",(?=[^;=]+=)", str(v)):
                first = piece.strip().split(";", 1)[0]
                if "=" in first:
                    name, val = first.split("=", 1)
                    name = name.strip()
                    if name and val.strip() not in ("deleted", ""):
                        self._cookies[name] = val.strip()

    def _rate_ok(self) -> bool:
        now = time.time()
        while self._hits and now - self._hits[0] > 60:
            self._hits.popleft()
        if len(self._hits) >= self._scope.rate_limit_per_min:
            return False
        self._hits.append(now)
        return True

    def run(self, action: WebAction, agent: str = "web"):
        """Judge, log, and (only if permitted) perform one web action.
        Returns (Decision, WebResult | None)."""
        decision = check_web(action, self._scope, self.current_url, agent)
        self._audit.append("web_decision", decision)
        if decision.verdict != "ALLOW":
            return decision, None
        if not self._rate_ok():
            blocked = Decision(verdict="DENY", action=decision.action, target=decision.target,
                               agent=agent, reason="web rate limit exceeded",
                               layer="hard:web-rate")
            self._audit.append("web_decision", blocked)
            return blocked, None

        self._apply_cookies(action)            # carry the session into this request
        result = self._cage.run(action)
        self._absorb_cookies(result)           # remember any Set-Cookie for the next one
        self._audit.append("web_result", {"status": result.status, "url": result.url,
                                           "note": result.note,
                                           "bytes": len(result.body or "")})
        if action.kind == "navigate" and result.status:
            self.current_url = action.url      # now interaction actions are in-scope
        return decision, result
