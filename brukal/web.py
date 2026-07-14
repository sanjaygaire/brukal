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


class HttpWebCage:
    """Real crafted-HTTP-request backend (the interception/replay/tamper primitive):
    sends an arbitrary method/headers/body to an in-scope URL and returns the real
    response. Browser-only actions (navigate/click/fill/intercept) raise until the
    Chrome/CDP backend lands — use FakeWebCage or the Chrome backend for those."""

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
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read(self.max_body).decode(errors="replace")
                return WebResult(status=resp.status, url=resp.geturl(), body=body,
                                 headers=dict(resp.headers))
        except urllib.error.HTTPError as e:
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

    _SCRIPT = (
        "import sys,json,urllib.request,urllib.error\n"
        "u,m,b=sys.argv[1],sys.argv[2],sys.argv[3]\n"
        "h=dict(x.split(': ',1) for x in sys.argv[4:] if ': ' in x)\n"
        "rq=urllib.request.Request(u,data=b.encode() if b else None,method=m,headers=h)\n"
        "try:\n"
        " r=urllib.request.urlopen(rq,timeout=20)\n"
        " print(json.dumps({'status':r.status,'url':r.geturl(),'headers':dict(r.headers),'body':r.read(20000).decode('utf-8','replace')}))\n"
        "except urllib.error.HTTPError as e:\n"
        " print(json.dumps({'status':e.code,'url':u,'headers':dict(e.headers or {}),'body':e.read(20000).decode('utf-8','replace'),'note':'http error'}))\n"
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


def ensure_cage_vhosts(scope: Scope, container: str = "brukal-kali") -> list[str]:
    """Map the scope's authorised hostnames to the target IP inside the cage's
    /etc/hosts, so a vhost like `nexus.htb` actually resolves for cage-run web
    requests. Only acts when the scope authorises exactly one single-host (/32)
    network — the common HTB case — and never invents an IP. ip + host come from
    the trusted scope, not from any target, so there is no injection surface.
    Returns the hostnames it mapped (best-effort; failures are ignored)."""
    import subprocess
    hosts = sorted(scope.authorized_hosts)
    nets = scope.authorized_networks
    # Only when the scope is ONE single-host (/32) target is the vhost->IP mapping
    # unambiguous. A base scope with several networks (or a localhost /32 alongside)
    # is left alone rather than guessing the wrong IP.
    if not hosts or len(nets) != 1 or nets[0].num_addresses != 1:
        return []
    ip = str(nets[0].network_address)
    mapped = []
    for h in hosts:
        try:
            subprocess.run(
                ["docker", "exec", "-u", "root", container, "sh", "-c",
                 f"grep -qw {h} /etc/hosts || echo '{ip} {h}' >> /etc/hosts"],
                capture_output=True, timeout=15)
            mapped.append(h)
        except Exception:
            pass
    return mapped


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

        result = self._cage.run(action)
        self._audit.append("web_result", {"status": result.status, "url": result.url,
                                           "note": result.note,
                                           "bytes": len(result.body or "")})
        if action.kind == "navigate" and result.status:
            self.current_url = action.url      # now interaction actions are in-scope
        return decision, result
