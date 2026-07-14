"""
orchestrator.py — Milestone 4: the sequential orchestrator.

It walks the Pentesting Task Tree, dispatches each task to the agent for that
role, feeds the agent a SCOPED slice of the blackboard (not the whole history),
DIGESTS the outcome down to a short summary, and writes that digest back to the
blackboard and the tree. Agents run one at a time (no concurrency in M4).

What the orchestrator deliberately does NOT do:
  * It never touches the Kali cage. Agents are constructed with the Executor and
    handed to the orchestrator; the orchestrator only calls `agent.run_task(...)`,
    which submits through `Executor.run()` and the gate (invariant 4).
  * It never lets raw tool output accumulate — only digests are stored, so no
    agent's context fills with scan noise (the multi-agent context-loss fix).

There is no language model in the orchestrator itself; the intelligence lives in
the agents it dispatches to.
"""
from __future__ import annotations

from .blackboard import Blackboard
from .tasktree import Task, TaskStatus, TaskTree


class Orchestrator:
    def __init__(self, task_tree: TaskTree, agents: dict, blackboard: Blackboard,
                 trust=None, skills=None, observer=None):
        # agents: {role: agent}, each agent already holding the Executor+LLM.
        self._tree = task_tree
        self._agents = agents
        self._bb = blackboard
        # Optional TrustModel (milestone 6). If present, each turn's outcome
        # updates the proposing agent's T_i, which (via the same Gate) modulates
        # that agent's FUTURE soft-risk decisions. It never touches the hard gate.
        self._trust = trust
        # Optional SkillLibrary (knowledge layer). If present, the most relevant
        # playbook is injected into the agent's context as UNTRUSTED REFERENCE.
        # It informs the agent's proposal; it never bypasses the gate.
        self._skills = skills
        # Optional observer(kind, payload) callback for live views (the TUI). It
        # is fire-and-forget telemetry — it never affects control flow, so a
        # broken observer can never change what runs.
        self._observer = observer

    def _emit(self, kind: str, **payload) -> None:
        if self._observer is not None:
            try:
                self._observer(kind, payload)
            except Exception:
                pass   # a display error must never derail the engagement

    def _digest(self, task: Task, request, outcome) -> dict:
        """Compress one turn's outcome to a short, storable summary. The raw
        tool output is truncated here so it never enters the blackboard."""
        if request is None or outcome is None:
            return {"task": task.description, "target": task.target,
                    "command": "", "verdict": "no-op", "executed": False,
                    "summary": "agent produced no valid proposal"}
        decision, result = outcome
        executed = result is not None
        if executed:
            raw = (result.stdout or "").strip()
            first = raw.splitlines()[0] if raw else "(no output)"
            summary = f"{decision.verdict}: {first[:200]}"
        else:
            summary = f"blocked at {decision.layer}: {decision.reason}"
        return {"task": task.description, "target": task.target,
                "command": decision.action, "verdict": decision.verdict,
                "executed": executed, "summary": summary}

    def run(self) -> dict:
        """Run every pending task in the tree, sequentially. Returns a small
        summary dict (executed / failed / blocked counts)."""
        executed = failed = blocked = 0
        self._emit("start")

        while (task := self._tree.next_pending()) is not None:
            agent = self._agents.get(task.agent)
            if agent is None:
                self._tree.mark(task, TaskStatus.BLOCKED)
                blocked += 1
                self._emit("turn", task=task, decision=None, result=None)
                continue

            self._tree.mark(task, TaskStatus.IN_PROGRESS)
            self._emit("task_start", task=task)

            # Scoped read: only prior findings relevant to this target.
            context = self._bb.read_context(task.agent, task.target)

            # Knowledge layer: prepend the most relevant playbook as untrusted
            # reference (guidance only — the gate still rules on what it proposes).
            # Key the lookup off the task AND the findings so far, so the playbook
            # tracks the services/tech actually discovered, not just the task title.
            if self._skills is not None:
                reference = self._skills.context_for(f"{task.description} {context}"[:600])
                if reference:
                    context = f"{reference}\n\n{context}" if context else reference

            request, outcome = agent.run_task(task.description, context)
            digest = self._digest(task, request, outcome)

            # Milestone 6: fold this turn's outcome into the agent's trust, so a
            # misbehaving agent draws more scrutiny on its next proposal.
            if self._trust is not None:
                self._trust.record_outcome(
                    task.agent,
                    request_valid=(request is not None),
                    decision=(outcome[0] if outcome else None),
                    executed=digest["executed"],
                )
                digest["trust"] = round(self._trust.of(task.agent), 3)

            self._bb.write_finding(task.agent, digest)
            self._tree.record_finding(task, digest)

            if digest["executed"]:
                self._tree.mark(task, TaskStatus.DONE)
                executed += 1
            else:
                self._tree.mark(task, TaskStatus.FAILED)
                failed += 1

            self._emit("turn", task=task,
                       decision=(outcome[0] if outcome else None),
                       result=(outcome[1] if outcome else None))

        # Persist the final tree into the vault for a human to read.
        self._bb.save_task_tree(self._tree.to_markdown())
        self._emit("end", executed=executed, failed=failed, blocked=blocked)
        return {"executed": executed, "failed": failed, "blocked": blocked}
