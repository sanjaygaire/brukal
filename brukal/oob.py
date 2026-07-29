"""
oob.py — out-of-band interaction listener (Brukal's own in-cage "collaborator").

Confirms BLIND vulnerabilities — the ones with no in-band evidence: blind command
injection, blind SSRF, blind XXE — by making the target reach back to a listener Brukal
runs inside the cage. If a unique token lands on the listener, the target executed our
command / fetched our URL: proof, out of band.

The listener is a plain `python3 -m http.server` in the cage logging requests to a file
(no custom server, argv only). Targets on the cage's network (a lab host, an internal
box over the VPN) can reach the cage IP. This is infrastructure Brukal owns — not a
gated target action — so it starts via `docker exec` directly, like the tool probe.
"""
from __future__ import annotations

import random
import subprocess
import time


class OOBListener:
    """A one-shot HTTP interaction listener inside the cage. Requests to
    http://<cage-ip>:<port>/<token> are logged; hit(token) checks for an interaction."""

    def __init__(self, container: str, port: int | None = None):
        self.container = container
        self.port = port or random.randint(20000, 45000)
        self.log = f"/tmp/oob_{self.port}.log"
        self.ip: str = ""
        self._up = False

    def start(self) -> bool:
        """Resolve the cage IP and start the listener detached. Returns True if up."""
        try:
            self.ip = subprocess.run(
                ["docker", "inspect", self.container, "--format",
                 "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
                capture_output=True, text=True, timeout=15).stdout.strip()
            if not self.ip:
                return False
            subprocess.run(
                ["docker", "exec", "-d", self.container, "sh", "-c",
                 f"python3 -m http.server {self.port} --directory /tmp 2>>{self.log}"],
                capture_output=True, timeout=15)
            time.sleep(1)                      # let it bind
            self._up = True
            return True
        except Exception:
            return False

    def callback_url(self, token: str) -> str:
        return f"http://{self.ip}:{self.port}/{token}"

    def hit(self, token: str) -> bool:
        """True if the token has appeared in an interaction with the listener."""
        try:
            r = subprocess.run(["docker", "exec", self.container, "grep", "-c", token, self.log],
                               capture_output=True, text=True, timeout=15)
            return r.stdout.strip() not in ("", "0")
        except Exception:
            return False

    def stop(self) -> None:
        try:
            subprocess.run(["docker", "exec", self.container, "pkill", "-f",
                            f"http.server {self.port}"], capture_output=True, timeout=15)
        except Exception:
            pass
        self._up = False
