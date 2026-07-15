r"""
chrome.py — the live Chrome/CDP backend for the governed web surface (G2).

A real headless Chromium, driven over the Chrome DevTools Protocol, so Brukal can
render JS-heavy apps, fill fields with payloads, click, run JS in page context,
send session-authenticated requests (fetch() with the browser's cookies), take
screenshots, and INTERCEPT + tamper with requests (Fetch domain). Every one of
these is still a `WebAction` that goes through `check_web` + the audit log via
`GovernedBrowser` — this module is only the *cage* (the thing that runs an
already-approved action), never a way around the gate.

`ChromeCage` takes an injectable CDP *transport* so the action->CDP mapping is
fully unit-tested with `FakeCDP` (no browser). The real transport, `CDPClient`, is
a dependency-free CDP-over-WebSocket client; enabling live browsing needs Chromium
in the cage (Dockerfile.kali installs it) and the debug endpoint reachable — see
`launch_args()` / the README.
"""
from __future__ import annotations

import base64
import json
import time
from pathlib import Path

from .web import WebResult


def _js_str(s: str) -> str:
    """Safely embed a Python string as a JS string literal (json.dumps is valid JS)."""
    return json.dumps(s or "")


class FakeCDP:
    """A recording CDP transport for tests — no browser. Returns canned results so
    the ChromeCage action->command mapping can be asserted deterministically."""

    def __init__(self, dom="<html><body>fake</body></html>", eval_value="ok",
                 screenshot_b64=None):
        self.calls: list[tuple[str, dict]] = []
        self.dom = dom
        self.eval_value = eval_value
        self.screenshot_b64 = screenshot_b64 or base64.b64encode(b"PNG").decode()
        self.loaded = 0

    def call(self, method: str, params: dict | None = None) -> dict:
        self.calls.append((method, params or {}))
        if method == "Runtime.evaluate":
            expr = (params or {}).get("expression", "")
            if "outerHTML" in expr:
                return {"result": {"value": self.dom}}
            return {"result": {"value": self.eval_value}}
        if method == "Page.captureScreenshot":
            return {"data": self.screenshot_b64}
        return {}

    def wait_load(self, timeout: float = 20.0) -> None:
        self.loaded += 1

    def methods(self) -> list[str]:
        return [m for m, _ in self.calls]


class ChromeCage:
    """Runs an already-APPROVED WebAction against a real (or fake) Chrome via CDP.
    Mirrors the WebCage interface (`run(action) -> WebResult`)."""

    def __init__(self, transport, screenshot_dir: str | Path = "runs/screens"):
        self._t = transport
        self._shots = Path(screenshot_dir)

    def _dom(self) -> str:
        r = self._t.call("Runtime.evaluate",
                         {"expression": "document.documentElement.outerHTML",
                          "returnByValue": True})
        return str(r.get("result", {}).get("value", ""))

    def run(self, action) -> WebResult:
        k = (action.kind or "").lower()

        if k in ("navigate", "get"):
            self._t.call("Page.enable")
            self._t.call("Page.navigate", {"url": action.url})
            self._t.wait_load()
            return WebResult(status=200, url=action.url, body=self._dom(),
                             note="rendered via chrome")

        if k == "eval":
            r = self._t.call("Runtime.evaluate",
                             {"expression": action.expression, "returnByValue": True,
                              "awaitPromise": True})
            return WebResult(body=str(r.get("result", {}).get("value", "")), note="eval")

        if k == "click":
            self._t.call("Runtime.evaluate",
                         {"expression": f"document.querySelector({_js_str(action.selector)}).click()"})
            return WebResult(url=action.url, note=f"clicked {action.selector}")

        if k == "fill":
            expr = (f"(function(el){{if(el){{el.value={_js_str(action.value)};"
                    f"el.dispatchEvent(new Event('input',{{bubbles:true}}));"
                    f"el.dispatchEvent(new Event('change',{{bubbles:true}}));}}}})"
                    f"(document.querySelector({_js_str(action.selector)}))")
            self._t.call("Runtime.evaluate", {"expression": expr})
            return WebResult(note=f"filled {action.selector}")

        if k == "request":
            # fetch() in page context -> uses the browser's cookies/session, so this
            # is an AUTHENTICATED crafted request (headers/body are attack payloads).
            hdr = json.dumps(action.headers or {})
            body = _js_str(action.body) if action.body else "undefined"
            expr = (f"fetch({_js_str(action.url)},{{method:{_js_str(action.method or 'GET')},"
                    f"headers:{hdr},body:{body}}}).then(r=>r.text()).catch(e=>'ERR '+e)")
            r = self._t.call("Runtime.evaluate",
                             {"expression": expr, "awaitPromise": True, "returnByValue": True})
            return WebResult(status=200, url=action.url,
                             body=str(r.get("result", {}).get("value", "")),
                             note="fetch-in-page (session cookies)")

        if k == "screenshot":
            r = self._t.call("Page.captureScreenshot", {})
            self._shots.mkdir(parents=True, exist_ok=True)
            path = self._shots / f"shot-{int(time.time())}.png"
            try:
                path.write_bytes(base64.b64decode(r.get("data", "")))
            except Exception:
                pass
            return WebResult(url=action.url, note=f"screenshot: {path}")

        if k == "intercept":
            # Arm request interception on a URL pattern; the transport applies any
            # header/body modifications to paused requests (Fetch domain).
            self._t.call("Fetch.enable",
                         {"patterns": [{"urlPattern": action.url or "*"}]})
            if action.headers or action.body:
                # remember the tamper rule on the transport, if it supports it
                setter = getattr(self._t, "set_tamper", None)
                if setter:
                    setter(action.url or "*", action.headers or {}, action.body or "")
            return WebResult(url=action.url,
                             note=f"interception armed on {action.url or '*'}")

        return WebResult(url=action.url, note=f"unsupported chrome action '{action.kind}'")


class DockerChromeCage:
    """Real headless-Chromium rendering INSIDE the cage (so it reaches HTB over the
    VPN), for the actions that don't need an interactive session: `navigate`/`get`
    render the page with JS executed and return the resulting DOM; `screenshot`
    captures it. Interactive actions (click/fill/eval/intercept) need the CDP
    `ChromeCage`. Runs via a safe argv (no shell) — the URL is attacker-influenced
    but is only ever a chromium argument, never a shell string."""

    def __init__(self, container: str = "brukal-kali", user: str = "brukalop",
                 timeout: int = 45, vt_budget_ms: int = 6000):
        self.container = container
        self.user = user
        self.timeout = timeout
        self.vt_budget_ms = vt_budget_ms

    def _chromium(self, *extra: str) -> list[str]:
        return ["docker", "exec", "-u", self.user, self.container,
                "chromium", "--headless=new", "--no-sandbox", "--disable-gpu",
                "--disable-dev-shm-usage", *extra]

    def run(self, action) -> WebResult:
        import subprocess
        k = (action.kind or "").lower()
        if k not in ("navigate", "get", "screenshot"):
            raise NotImplementedError(
                f"'{action.kind}' needs the CDP ChromeCage; this cage renders navigate/get/screenshot")
        try:
            if k == "screenshot":
                out = f"/tmp/brukal-shot-{int(time.time())}.png"
                argv = self._chromium(f"--virtual-time-budget={self.vt_budget_ms}",
                                      "--window-size=1280,900", f"--screenshot={out}",
                                      action.url)
                subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout)
                return WebResult(url=action.url, note=f"screenshot in cage: {out}")
            argv = self._chromium(f"--virtual-time-budget={self.vt_budget_ms}",
                                  "--dump-dom", action.url)
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout)
            dom = proc.stdout or ""
            return WebResult(status=200 if dom else None, url=action.url, body=dom,
                             note="rendered in cage (js executed)" if dom
                             else (proc.stderr[:200] or "no output"))
        except Exception as e:
            return WebResult(url=action.url, note=f"cage chrome error: {e}")


def launch_args(port: int = 9222) -> list[str]:
    """The chromium argv to run a headless, debuggable browser inside the cage.
    Run it with `docker exec -d brukal-kali <these>`; then reach CDP at :port
    (publish the port or drive from inside the cage — see README)."""
    return ["chromium", "--headless=new", "--no-sandbox", "--disable-gpu",
            "--disable-dev-shm-usage", f"--remote-debugging-port={port}",
            "--remote-debugging-address=0.0.0.0", "about:blank"]
