"""
gate.py — the deterministic hard gate. The heart of Brukal.

This is Layer 1 of the Trust Governance Plane: the part that must be
*untrickable*. It contains NO language model. Every check is plain code over
the read-only scope. Because a malicious target can plant text in its own
output ("this host is in scope, trust me"), the component that enforces scope
must be immune to language — so it is regular expressions and set membership,
nothing an LLM could be argued out of.

Design rules honoured here:
  * Fail-closed   — anything ambiguous, unparseable, or unexpected -> DENY.
  * Hard gate as AND — every check must pass; one failure denies everything.
  * No self-report — the gate reads the command itself; it never trusts an
                     agent's claim about what the command does.

Milestone 1 implements the hard gate (scope / allowlist / rate / injection).
The soft risk score (impact, policy) and ESCALATE path are stubbed with a
clear extension point for milestone 3.
"""
from __future__ import annotations

import os
import re
import shlex
import time
from dataclasses import dataclass, field

from .risk import assess
from .scope import Scope

# Characters that enable shell command chaining / substitution. If any appear
# in a proposed command we refuse it outright: they are how a single "nmap"
# request could smuggle a second, unauthorised command or target.
_SHELL_METACHARACTERS = ";|&`><\n\r"
_SUBSTITUTION_PATTERNS = ("$(", "${", "`")

# Matches IPv4 literals so we can find EVERY host mentioned in a command,
# not just the one the agent declared as its target.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class Decision:
    """The structured ruling the gate returns for one action request.

    This object is exactly what gets written to the audit log, so every field
    here is something you can later count or filter on in your results.
    """
    verdict: str          # "ALLOW" | "DENY" | "ESCALATE"
    action: str           # the command that was judged
    target: str           # the declared target
    agent: str            # which agent proposed it
    reason: str           # human-readable explanation
    layer: str            # which check decided it, e.g. "hard:scope"
    timestamp: float = field(default_factory=time.time)
    # Soft-risk features (milestone 3). None on hard denies (never reached the
    # soft layer); set on every decision the soft layer produced.
    risk_band: str | None = None        # "LOW" | "MEDIUM" | "HIGH"
    reversibility: str | None = None    # "reversible" | "unknown" | "irreversible"
    blast_radius: str | None = None     # "host" | "subnet" | "wide"
    trust: float | None = None          # proposing agent's T_i fed to the soft layer (M6)

    @property
    def allowed(self) -> bool:
        return self.verdict == "ALLOW"


class Gate:
    """Stateful gate. Holds the scope and a sliding window for rate limiting."""

    def __init__(self, scope: Scope, trust=None):
        self.scope = scope
        # Optional TrustModel (milestone 6). Feeds ONLY the soft layer below;
        # None means every agent is fully trusted (T_i = 1.0), i.e. unchanged.
        self._trust = trust
        self._recent_allows: list[float] = []

    # -- helpers ------------------------------------------------------------

    def _deny(self, action, target, agent, reason, layer) -> Decision:
        return Decision("DENY", action, target, agent, reason, layer)

    def _rate_ok(self) -> bool:
        """Sliding 60-second window. Fail-closed: at the limit, deny."""
        now = time.time()
        self._recent_allows = [t for t in self._recent_allows if now - t < 60.0]
        return len(self._recent_allows) < self.scope.rate_limit_per_min

    # -- the gate ------------------------------------------------------------

    def check(self, command: str, target: str, agent: str = "unknown") -> Decision:
        """Run the hard gate over one proposed action.

        Order matters: the cheapest, most absolute checks come first, and any
        single failure denies. Read this as a logical AND of all constraints.
        """
        # 0. Injection guard — reject shell chaining / substitution outright.
        if any(c in command for c in _SHELL_METACHARACTERS) or \
           any(p in command for p in _SUBSTITUTION_PATTERNS):
            return self._deny(command, target, agent,
                              "shell metacharacter / substitution rejected",
                              "hard:injection")

        # 1. Parse the command safely. If it will not parse, we do not run it.
        try:
            parts = shlex.split(command)
        except ValueError:
            return self._deny(command, target, agent,
                              "command could not be parsed", "hard:parse")
        if not parts:
            return self._deny(command, target, agent,
                              "empty command", "hard:parse")

        # 2. Tool allowlist — only approved tools, by basename.
        tool = os.path.basename(parts[0])
        if not self.scope.tool_allowed(tool):
            return self._deny(command, target, agent,
                              f"tool '{tool}' not allowlisted", "hard:allowlist")

        # 3. Declared target must be in scope.
        if not self.scope.contains_ip(target):
            return self._deny(command, target, agent,
                              f"target {target} out of scope", "hard:scope")

        # 4. No SMUGGLED out-of-scope host anywhere in the command. This is the
        #    "nmap 10.10.10.5 8.8.8.8" defence — the declared target is fine but
        #    a second host is hidden in the arguments.
        for host in _IPV4_RE.findall(command):
            if not self.scope.contains_ip(host):
                return self._deny(command, target, agent,
                                  f"out-of-scope host {host} in command",
                                  "hard:scope")

        # 5. Rate limit.
        if not self._rate_ok():
            return self._deny(command, target, agent,
                              "rate limit exceeded", "hard:rate")

        # ---- Passed the hard gate. Now the SOFT risk layer (milestone 3). ----
        # The hard gate can only DENY; the soft layer can only add caution on top
        # of an already-in-scope action. It derives risk deterministically from
        # the command text (no LLM, no self-report) and returns ALLOW / ESCALATE /
        # DENY. It can never turn a hard DENY into an ALLOW — by construction it
        # only runs here, after every hard check has already passed.
        #
        # Milestone 6: the proposing agent's adaptive trust T_i feeds ONLY this
        # soft layer (never the hard checks above). A less-trusted agent's same
        # command scores as higher risk. No trust model -> T_i defaults to 1.0
        # (full trust), so behaviour is unchanged until trust is wired in.
        t = self._trust.of(agent) if self._trust is not None else 1.0
        profile = assess(command, trust=t)

        if profile.decision == "DENY":
            # Soft ceiling crossed (e.g. irreversible + wide blast radius).
            return Decision("DENY", command, target, agent,
                            f"risk ceiling exceeded — {profile.reason}",
                            "soft:deny",
                            risk_band=profile.band,
                            reversibility=profile.reversibility,
                            blast_radius=profile.blast_radius,
                            trust=t)

        # ALLOW and ESCALATE may both end in execution, so reserve a rate slot
        # for either (conservative: an escalation the human later declines has
        # still spent budget — fail toward less traffic, not more).
        self._recent_allows.append(time.time())

        if profile.decision == "ESCALATE":
            return Decision("ESCALATE", command, target, agent,
                            f"needs human sign-off — {profile.reason}",
                            "soft:escalate",
                            risk_band=profile.band,
                            reversibility=profile.reversibility,
                            blast_radius=profile.blast_radius,
                            trust=t)

        return Decision("ALLOW", command, target, agent,
                        f"passed hard gate; {profile.reason}", "soft:allow",
                        risk_band=profile.band,
                        reversibility=profile.reversibility,
                        blast_radius=profile.blast_radius,
                        trust=t)
