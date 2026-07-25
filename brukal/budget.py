"""
budget.py — per-engagement governance caps, surfaced to the operator.

A researcher running Brukal against a real target wants a spend they can predict and a
run that won't wander forever. `EngagementBudget` puts hard ceilings on the four things
a long autonomous run consumes: LLM spend (USD), loop steps, control-plane research
fetches, and wall-clock time. The loop checks the budget at each turn; when a ceiling is
reached it hands back cleanly (stop reason `budget`) rather than being killed.

None means "no cap" for that dimension (e.g. cost is uncapped and unmeasurable against a
local/free model). Every check is deterministic arithmetic — no LLM, nothing that can be
influenced by target output. Standard library only.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class EngagementBudget:
    max_cost: float | None = None            # USD ceiling on LLM spend
    max_steps: int | None = None             # loop-step ceiling (belt-and-braces w/ loop budget)
    max_research_fetches: int | None = None  # control-plane research egress ceiling
    max_wall_seconds: float | None = None    # wall-clock ceiling
    _start: float | None = field(default=None, repr=False)

    def start(self) -> "EngagementBudget":
        self._start = time.monotonic()
        return self

    @property
    def elapsed(self) -> float:
        return 0.0 if self._start is None else time.monotonic() - self._start

    @property
    def any_cap(self) -> bool:
        return any(c is not None for c in
                   (self.max_cost, self.max_steps, self.max_research_fetches,
                    self.max_wall_seconds))

    def exceeded(self, *, cost=None, steps=None, fetches=None) -> str | None:
        """A human reason if any cap is reached, else None. An argument left None is
        simply not checked (cost is None for a local model; the wall clock is always
        checked once the budget has been start()ed)."""
        if self.max_cost is not None and cost is not None and cost >= self.max_cost:
            return f"LLM spend cap reached (~${cost:.4f} ≥ ${self.max_cost:.2f})"
        if self.max_steps is not None and steps is not None and steps >= self.max_steps:
            return f"step cap reached ({steps} ≥ {self.max_steps})"
        if (self.max_research_fetches is not None and fetches is not None
                and fetches >= self.max_research_fetches):
            return f"research-fetch cap reached ({fetches} ≥ {self.max_research_fetches})"
        if self.max_wall_seconds is not None and self.elapsed >= self.max_wall_seconds:
            return f"time cap reached ({self.elapsed:.0f}s ≥ {self.max_wall_seconds:.0f}s)"
        return None

    def status(self, *, cost=None, steps=None, fetches=None) -> str:
        """A one-line 'spent / cap' summary for the operator."""
        parts: list[str] = []
        if self.max_cost is not None:
            parts.append(f"spend ${cost or 0:.4f}/${self.max_cost:.2f}")
        if self.max_steps is not None:
            parts.append(f"steps {steps or 0}/{self.max_steps}")
        if self.max_research_fetches is not None:
            parts.append(f"research {fetches or 0}/{self.max_research_fetches}")
        if self.max_wall_seconds is not None:
            parts.append(f"time {self.elapsed:.0f}s/{self.max_wall_seconds:.0f}s")
        return " · ".join(parts) or "no caps set"
