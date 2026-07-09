"""
tasktree.py — Milestone 4: the Pentesting Task Tree (external strategy memory).

An agent's context window is small and fills with noise; strategy must live
*outside* it. The task tree is that external memory: an ordered tree of tasks
the orchestrator walks, records outcomes against, and grows as findings suggest
follow-ups. It is plain data (no LLM), so it is deterministic, inspectable, and
renderable into the Obsidian blackboard for a human to read.

It holds strategy, never authority: nothing here can authorise an action. Every
command an agent proposes still goes through `Executor.run()` and the gate. The
tree only decides *what to try next*, never *what is allowed*.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


class TaskStatus:
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    FAILED = "failed"      # attempted, but the action did not execute (e.g. denied)
    BLOCKED = "blocked"    # no agent available for this task's role


@dataclass
class Task:
    id: str
    description: str
    target: str
    agent: str = "recon"                 # which agent ROLE should handle this
    status: str = TaskStatus.PENDING
    parent: str | None = None
    findings: list[dict] = field(default_factory=list)   # digests recorded here
    created: float = field(default_factory=time.time)


class TaskTree:
    """An ordered tree of tasks. Sequential by design (milestone 4 has no
    concurrency): `next_pending` returns tasks in insertion order."""

    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}
        self._order: list[str] = []
        self._counter = 0

    def add(self, description: str, target: str, agent: str = "recon",
            parent: str | None = None) -> Task:
        self._counter += 1
        tid = f"T{self._counter}"
        task = Task(tid, description, target, agent, parent=parent)
        self._tasks[tid] = task
        self._order.append(tid)
        return task

    def next_pending(self) -> Task | None:
        for tid in self._order:
            if self._tasks[tid].status == TaskStatus.PENDING:
                return self._tasks[tid]
        return None

    def mark(self, task: Task, status: str) -> None:
        task.status = status

    def record_finding(self, task: Task, digest: dict) -> None:
        task.findings.append(digest)

    def children(self, task: Task) -> list[Task]:
        return [self._tasks[t] for t in self._order
                if self._tasks[t].parent == task.id]

    def all_tasks(self) -> list[Task]:
        return [self._tasks[t] for t in self._order]

    # -- rendering (for the Obsidian blackboard) ---------------------------- #

    def to_markdown(self) -> str:
        lines = ["# Pentesting Task Tree", ""]
        roots = [t for t in self.all_tasks() if t.parent is None]

        def render(task: Task, depth: int) -> None:
            mark = {"done": "x", "failed": "!", "in_progress": "~",
                    "blocked": "-", "pending": " "}.get(task.status, " ")
            lines.append(f"{'  ' * depth}- [{mark}] `{task.id}` "
                         f"({task.agent}/{task.status}) {task.description} "
                         f"→ {task.target}")
            for f in task.findings:
                lines.append(f"{'  ' * (depth + 1)}- ↳ {f.get('summary', f)}")
            for child in self.children(task):
                render(child, depth + 1)

        for root in roots:
            render(root, 0)
        return "\n".join(lines) + "\n"
