"""
trust.py — Milestone 6: adaptive per-agent trust T_i (the paper's novel layer).

Each agent carries a trust score T_i in [0,1]. It is **not** authority — it can
never widen scope or overrule the hard gate. It feeds ONLY the soft risk layer:
a less-trusted agent's *same* proposed command lands in a higher risk band, so it
draws more scrutiny (ESCALATE) or refusal (DENY). This is the whole idea — govern
each agent in proportion to how reliable it has proven to be.

Design choices, and why:

  * **Start fully trusted (1.0), lose trust on unreliable behavior.** A fresh
    agent behaves exactly as before (trust 1.0 adds nothing to the risk score),
    so wiring trust in changes nothing until an agent misbehaves. Trust is easy
    to lose and slow to rebuild — an EMA with a learning rate.
  * **Deterministic.** T_i is a plain function of the agent's event history. No
    LLM anywhere near it — it is safe to feed the (already LLM-free) soft layer.
  * **Trust collapse is defined.** Below `collapse_floor` an agent is "collapsed":
    the trust penalty it now carries pushes even a benign action to ESCALATE and
    anything larger to DENY. The system keeps working, but nothing that agent
    proposes runs unwatched again until it recovers.

What updates trust (the orchestrator calls these):
  - clean, permitted, executed action        -> reward
  - a proposal the gate DENIED               -> penalize (it proposed the refused)
  - a malformed / empty proposal             -> penalize (hallucinated nonsense)
  - an ESCALATE a human declined             -> penalize; approved -> mild reward
  - a claim the verify agent could NOT confirm (UNSUPPORTED/UNVERIFIED)
                                             -> penalize the CLAIMING agent
    (this is the anti-hallucination loop: getting caught lying costs trust)
"""
from __future__ import annotations

from dataclasses import dataclass, field


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


@dataclass
class TrustModel:
    initial: float = 1.0            # agents start fully trusted
    alpha: float = 0.3             # EMA learning rate (how fast trust moves)
    collapse_floor: float = 0.25   # below this, the agent is "collapsed"
    _trust: dict[str, float] = field(default_factory=dict)

    # -- reads --------------------------------------------------------------- #

    def of(self, agent: str) -> float:
        return self._trust.get(agent, self.initial)

    def collapsed(self, agent: str) -> bool:
        return self.of(agent) < self.collapse_floor

    def snapshot(self) -> dict[str, float]:
        return dict(self._trust)

    # -- updates ------------------------------------------------------------- #

    def _record(self, agent: str, signal: float) -> float:
        cur = self.of(agent)
        new = _clamp01((1.0 - self.alpha) * cur + self.alpha * _clamp01(signal))
        self._trust[agent] = new
        return new

    def reward(self, agent: str) -> float:
        return self._record(agent, 1.0)

    def penalize(self, agent: str) -> float:
        return self._record(agent, 0.0)

    def record_outcome(self, agent: str, *, request_valid: bool,
                       decision, executed: bool) -> float:
        """Update `agent`'s trust from one turn's outcome. Deterministic."""
        if not request_valid:
            return self.penalize(agent)          # malformed / no proposal
        if decision is None:
            return self.of(agent)
        verdict = decision.verdict
        if verdict == "ALLOW" and executed:
            return self.reward(agent)
        if verdict == "DENY":
            return self.penalize(agent)
        if verdict == "ESCALATE":
            # approved-and-ran reads as fine; declined reads as a bad proposal.
            return self._record(agent, 1.0 if executed else 0.2)
        return self.of(agent)

    def record_verification(self, claiming_agent: str, verify_result) -> float:
        """The anti-hallucination loop: a claim the verify agent could not confirm
        costs the CLAIMING agent trust; a confirmed one rewards it."""
        if getattr(verify_result, "verdict", None) == "SUPPORTED":
            return self.reward(claiming_agent)
        return self.penalize(claiming_agent)
