#!/usr/bin/env python3
"""
run_engagement.py — drive the milestone-4 orchestrated loop end to end.

Where run_recon.py drove a single agent by hand, this runs the ORCHESTRATOR over
a Pentesting Task Tree, sharing findings through the Obsidian-vault blackboard:

    task tree ─► orchestrator picks a task ─► hands it to the agent for that role
              ─► agent PROPOSES (text) ─► executor.run() ─► the GATE rules
              ─► (if allowed) the CAGE runs it ─► the result is DIGESTED and
                 written to the blackboard; the tree is updated ─► next task.

Agents run one at a time (no concurrency in M4). The agent is handed the
Executor, never the cage — proposing and submitting are all it can do.

Requirements
------------
  pip install "brukal[agents]"          # anthropic + pydantic
  export ANTHROPIC_API_KEY=sk-...       # your key (only for a real, non-fake run)
  # a scope.json in the current dir whose authorized_cidrs include <target>

Usage
-----
  # smoke-test the wiring with the fake cage (no Docker, synthetic output):
  python3 run_engagement.py 10.10.10.5 --fake

  # real run against an authorised lab host (Docker cage must be up):
  python3 run_engagement.py 10.10.10.5

Only ever point this at systems you are authorised to test. See SECURITY.md.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from brukal import (AuditLog, Blackboard, DockerKali, Executor, FakeKali, Gate,
                    Orchestrator, TaskTree, load_scope)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="run_engagement",
                                description="Brukal orchestrated loop (milestone 4)")
    p.add_argument("target", help="the host to work (must be in scope)")
    p.add_argument("--fake", action="store_true", help="use the fake cage (no Docker)")
    p.add_argument("--scope", default="scope.json", help="path to scope.json")
    p.add_argument("--audit", default="runs/audit.jsonl", help="path to the audit log")
    p.add_argument("--vault", default="runs/vault", help="blackboard vault directory")
    p.add_argument("--model", default=None, help="override the model id")
    args = p.parse_args(argv)

    try:
        from brukal.agents import ReconAgent
        from brukal.llm import LLMClient
    except ImportError as e:
        print(f"Agent dependencies missing ({e}). Install: pip install \"brukal[agents]\"")
        return 2

    # Assemble the spine. The agent receives the EXECUTOR, never the cage.
    scope = load_scope(args.scope)
    gate = Gate(scope)
    kali = FakeKali() if args.fake else DockerKali()
    audit = AuditLog(args.audit)
    executor = Executor(gate, kali, audit)

    try:
        llm = LLMClient(model=args.model)
    except Exception as e:
        print(f"Could not initialise the model client: {e}")
        print("Set ANTHROPIC_API_KEY and install anthropic (pip install \"brukal[agents]\").")
        return 2

    agent = ReconAgent(llm, executor)

    # The blackboard (an Obsidian-openable folder) and the strategy tree.
    blackboard = Blackboard(args.vault, scope)
    tree = TaskTree()
    tree.add(f"Enumerate open services on {args.target}", args.target, agent="recon")
    tree.add(f"Fingerprint any web service on {args.target}", args.target, agent="recon")

    orch = Orchestrator(tree, {"recon": agent}, blackboard)

    print(f"\nEngagement: {scope.engagement}   target: {args.target}   "
          f"cage: {'fake' if args.fake else 'docker'}")
    print(f"blackboard: {Path(args.vault).resolve()}\n")

    summary = orch.run()

    print("─" * 62)
    print(f"tasks: executed={summary['executed']} failed={summary['failed']} "
          f"blocked={summary['blocked']}")
    print(f"blackboard : {Path(args.vault).resolve()}  (open in Obsidian)")
    print(f"audit log  : {args.audit}   chain intact: {audit.verify()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
