"""
engagement.py — assemble and run a full orchestrated engagement.

This is the live loop a pentester actually drives: the orchestrator walks a
Pentesting Task Tree with all three agents (recon -> exploit -> verify), the soft
risk layer escalates to a human where needed, and adaptive per-agent trust folds
each outcome back in. Agents are handed the Executor, never the cage.

Both `run_engagement.py` (the script) and `brukal run` (the CLI) call `run()`.
"""
from __future__ import annotations

import sys
from pathlib import Path

from .audit import AuditLog
from .blackboard import Blackboard
from .executor import Executor
from .gate import Gate
from .kali import DockerKali, FakeKali
from .orchestrator import Orchestrator
from .scope import load_scope
from .tasktree import TaskTree
from .trust import TrustModel


def interactive_approver(decision) -> bool:
    """Ask the operator to sign off an ESCALATEd action. Fail-closed: anything
    other than an explicit 'y' (or a non-interactive session) declines."""
    print("\n  ESCALATION — human sign-off required")
    print(f"    action : {decision.action}")
    print(f"    target : {decision.target}   agent: {decision.agent}")
    print(f"    risk   : {decision.risk_band}  ({decision.reason})")
    if not sys.stdin.isatty():
        print("    -> non-interactive session; declined (fail-closed)\n")
        return False
    try:
        return input("    approve this action? [y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print("\n    -> declined (fail-closed)\n")
        return False


def run(target: str, *, fake: bool = False, yes_authorised: bool = False,
        scope_path: str = "scope.json", audit_path: str = "runs/audit.jsonl",
        vault_path: str = "runs/vault", container: str = "brukal-kali",
        model: str | None = None, approver=None) -> int:
    """Run the full engagement against `target`. Returns a process exit code."""
    try:
        from .agents import ExploitAgent, ReconAgent, VerifyAgent
        from .llm import LLMClient
    except ImportError as e:
        print(f"Agent dependencies missing ({e}). Install: pip install \"brukal[agents]\"")
        return 2

    scope = load_scope(scope_path)

    # Scope + authorisation guard (belt and braces on top of the gate).
    if not scope.contains_ip(target):
        print(f"Refused: target {target} is not inside {scope_path}.")
        print(f"Set scope first:  brukal target {target}")
        return 2
    if not fake and not yes_authorised:
        print("Refused: a live (Docker) run needs --yes-authorised to confirm you\n"
              "are authorised to test this target. (Use --fake to dry-run the wiring.)")
        return 2

    # Assemble the spine. The agents receive the EXECUTOR, never the cage.
    trust = TrustModel()
    gate = Gate(scope, trust=trust)
    kali = FakeKali() if fake else DockerKali(container=container)
    audit = AuditLog(audit_path)
    executor = Executor(gate, kali, audit, approver=approver or interactive_approver)

    try:
        llm = LLMClient(model=model)
    except Exception as e:
        print(f"Could not initialise the model client: {e}")
        print("Set ANTHROPIC_API_KEY and install anthropic (pip install \"brukal[agents]\").")
        return 2

    agents = {
        "recon": ReconAgent(llm, executor),
        "exploit": ExploitAgent(llm, executor),
        "verify": VerifyAgent(llm, executor),
    }

    blackboard = Blackboard(vault_path, scope)
    tree = TaskTree()
    t_enum = tree.add(f"Enumerate open services on {target}", target, agent="recon")
    tree.add(f"Fingerprint any web service on {target}", target, agent="recon")
    tree.add(f"Probe the most promising weakness found on {target}", target,
             agent="exploit", parent=t_enum.id)
    tree.add(f"Independently verify any claimed success on {target}", target,
             agent="verify", parent=t_enum.id)

    orch = Orchestrator(tree, agents, blackboard, trust=trust)

    print(f"\nEngagement: {scope.engagement}   target: {target}   "
          f"cage: {'fake' if fake else 'docker:' + container}")
    print(f"blackboard: {Path(vault_path).resolve()}\n")

    summary = orch.run()

    print("─" * 62)
    print(f"tasks: executed={summary['executed']} failed={summary['failed']} "
          f"blocked={summary['blocked']}")
    print(f"trust: {trust.snapshot()}")
    print(f"blackboard : {Path(vault_path).resolve()}  (open in Obsidian)")
    print(f"audit log  : {audit_path}   chain intact: {audit.verify()}\n")
    return 0
