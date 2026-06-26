"""
scope.py — loads and validates the engagement policy (the authorised scope).

This module is intentionally dependency-free (Python standard library only).
The scope is the single source of truth for what Brukal is allowed to touch.
It is loaded ONCE at startup and treated as read-only thereafter: nothing in
the running system may widen it. That property is what lets us prove the
"100% scope interception" claim by construction rather than by hope.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Scope:
    """An immutable view of the engagement policy.

    frozen=True means once built, its fields cannot be reassigned — a small
    guard against accidental runtime mutation of the authorised set.
    """
    engagement: str
    authorized_networks: tuple  # tuple of ipaddress network objects
    allowlisted_tools: frozenset
    rate_limit_per_min: int

    def contains_ip(self, ip_text: str) -> bool:
        """True only if ip_text is a valid IP inside an authorised network.

        Fail-closed: anything that does not parse as an IP, or that falls
        outside every authorised network, returns False (i.e. out of scope).
        """
        try:
            ip = ipaddress.ip_address(ip_text.strip())
        except ValueError:
            return False
        return any(ip in net for net in self.authorized_networks)

    def tool_allowed(self, tool: str) -> bool:
        return tool in self.allowlisted_tools


def load_scope(path: str | Path) -> Scope:
    """Read scope.json from disk and build an immutable Scope.

    Raises on a malformed policy — we would rather refuse to start than run
    with a scope we cannot trust.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    nets = []
    for cidr in data["authorized_cidrs"]:
        # strict=False lets you write a host address like 10.10.10.5/24
        nets.append(ipaddress.ip_network(cidr, strict=False))

    return Scope(
        engagement=str(data["engagement"]),
        authorized_networks=tuple(nets),
        allowlisted_tools=frozenset(data["allowlisted_tools"]),
        rate_limit_per_min=int(data.get("rate_limit_per_min", 30)),
    )
