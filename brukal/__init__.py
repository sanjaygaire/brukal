"""Brukal — trust-governed multi-agent penetration testing.

Milestone 1: the deterministic spine (scope/gate/executor/kali/audit).
Milestone 3: the soft risk layer (risk.assess) + human-approval escalation.
"""
from .scope import Scope, load_scope
from .gate import Gate, Decision
from .audit import AuditLog
from .kali import FakeKali, DockerKali, ExecResult
from .executor import Executor, Approver
from .risk import RiskProfile, assess

__all__ = [
    "Scope", "load_scope", "Gate", "Decision",
    "AuditLog", "FakeKali", "DockerKali", "ExecResult",
    "Executor", "Approver",
    "RiskProfile", "assess",
]
