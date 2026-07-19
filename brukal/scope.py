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
    # Explicitly authorised hostnames (e.g. a HTB vhost like "nexus.htb"). Set at
    # scope time by the operator — NEVER resolved from DNS at runtime, so the scope
    # check stays deterministic and untrickable (a hostile DNS answer can't widen
    # scope). A web target is in scope iff its host is here OR its IP is in a CIDR.
    authorized_hosts: frozenset = frozenset()

    def contains_ip(self, ip_text: str) -> bool:
        """True only if ip_text is a valid IP inside an authorised network.

        Accepts dotted IPv4, IPv6 literals, AND integer/0x-hex/0o-octal encodings
        of an IP (canonicalised first) so a decimal/hex-smuggled host cannot slip
        past by numeric form. Fail-closed: anything that does not parse as an IP, or
        that falls outside every authorised network, returns False (out of scope).
        """
        from .hostmatch import canonical_ip
        canon = canonical_ip((ip_text or "").strip())
        if canon is None:
            return False
        try:
            ip = ipaddress.ip_address(canon)
        except ValueError:
            return False
        return any(ip in net for net in self.authorized_networks)

    def contains_host(self, host: str) -> bool:
        """True if `host` is an explicitly authorised hostname, or an in-scope IP.
        Deterministic set/CIDR membership only — no DNS. Fail-closed on anything
        empty or unrecognised."""
        h = (host or "").strip().lower()
        if not h:
            return False
        # strip a :port if present (host:port)
        if h.count(":") == 1 and not h.replace(":", "").isalpha():
            h = h.split(":", 1)[0]
        if h in self.authorized_hosts:
            return True
        return self.contains_ip(h)

    def with_host(self, host: str) -> "Scope":
        """Return a NEW scope with one hostname added. This is a scope-TIME
        authorisation (like `brukal target`), not a runtime widen — the running
        Scope object stays immutable; callers install the returned scope before
        the engagement, exactly as they would a fresh scope."""
        h = (host or "").strip().lower()
        return Scope(engagement=self.engagement,
                     authorized_networks=self.authorized_networks,
                     allowlisted_tools=self.allowlisted_tools,
                     rate_limit_per_min=self.rate_limit_per_min,
                     authorized_hosts=self.authorized_hosts | ({h} if h else set()))

    def tool_allowed(self, tool: str) -> bool:
        """True if the tool passes the ALLOWLIST layer. `"*"` in the allowlist means
        'broad mode': every tool passes this hard check, and the SOFT risk layer
        decides — read-only enumeration ALLOWs, while attack/irreversible or
        unrecognised tools ESCALATE to a human (and widen-blast ones DENY). Scope is
        still absolute; broad mode only moves the tool decision from a fixed list to
        'safe runs, dangerous asks a human'."""
        return "*" in self.allowlisted_tools or tool in self.allowlisted_tools

    @property
    def broad_tools(self) -> bool:
        return "*" in self.allowlisted_tools


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

    # allowlisted_tools may be a list, or the string "all" / "*" for broad mode
    # (every tool passes the allowlist; the risk layer + human sign-off govern the
    # dangerous ones). A list may itself contain "*" to the same effect.
    raw_tools = data["allowlisted_tools"]
    if isinstance(raw_tools, str):
        tools = frozenset({"*"}) if raw_tools.strip().lower() in ("all", "*") \
            else frozenset({raw_tools})
    else:
        tools = frozenset(raw_tools)

    return Scope(
        engagement=str(data["engagement"]),
        authorized_networks=tuple(nets),
        allowlisted_tools=tools,
        rate_limit_per_min=int(data.get("rate_limit_per_min", 30)),
        authorized_hosts=frozenset(h.strip().lower()
                                   for h in data.get("authorized_hosts", []) if h.strip()),
    )
