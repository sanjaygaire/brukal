r"""
executor.py — the ONLY path from a proposed action to execution.

This is the single most important file for your safety claim. Nothing in
Brukal may run a command except by calling Executor.run(). And Executor.run()
ALWAYS consults the gate first and ALWAYS logs the decision. There is no other
door to the cage.

    propose ->  gate.check()  ->  [ALLOW] -> kali.run()  -> log result
                              \->  [DENY/ESCALATE]        -> log, do not run

When you add agents (milestone 2), they call this exact method. They are never
handed the Kali backend directly. That is what makes "the agent cannot bypass
the gate" a structural fact rather than a promise.
"""
from __future__ import annotations

from .audit import AuditLog
from .gate import Decision, Gate
from .kali import ExecResult


class Executor:
    def __init__(self, gate: Gate, kali, audit: AuditLog):
        self._gate = gate
        self._kali = kali        # FakeKali or DockerKali
        self._audit = audit

    def run(self, command: str, target: str, agent: str = "unknown"):
        """Judge, log, and (only if allowed) execute one action.

        Returns (Decision, ExecResult | None).
        """
        decision: Decision = self._gate.check(command, target, agent)
        self._audit.append("decision", decision)

        if not decision.allowed:
            return decision, None

        result: ExecResult = self._kali.run(command)
        self._audit.append("execution", result)
        return decision, result
