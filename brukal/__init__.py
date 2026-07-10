"""Brukal — trust-governed multi-agent penetration testing.

Milestone 1: the deterministic spine (scope/gate/executor/kali/audit).
Milestone 3: the soft risk layer (risk.assess) + human-approval escalation.
Milestone 4: orchestrator + Obsidian blackboard + Pentesting Task Tree.
Milestone 6: adaptive per-agent trust (TrustModel) feeding the soft layer.
"""
from .scope import Scope, load_scope
from .gate import Gate, Decision
from .audit import AuditLog
from .kali import FakeKali, DockerKali, ExecResult
from .executor import Executor, Approver
from .risk import RiskProfile, assess
from .tasktree import TaskTree, Task, TaskStatus
from .blackboard import Blackboard, render_scope
from .orchestrator import Orchestrator
from .trust import TrustModel

__all__ = [
    "Scope", "load_scope", "Gate", "Decision",
    "AuditLog", "FakeKali", "DockerKali", "ExecResult",
    "Executor", "Approver",
    "RiskProfile", "assess",
    "TaskTree", "Task", "TaskStatus",
    "Blackboard", "render_scope", "Orchestrator",
    "TrustModel",
]
