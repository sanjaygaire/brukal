#!/usr/bin/env python3
"""
run_recon.py — drive the milestone-2 recon loop end to end (Path A).

This is the first time Claude actually enters Brukal. The flow per turn:

    task -> Claude PROPOSES an Action Request (text) -> parse/validate
         -> executor.run() -> the GATE rules -> (if allowed) the CAGE runs it
         -> the result is fed back as context for the next turn.

Claude only ever produces TEXT here. Your executor is the only thing that runs
anything, and the gate guards it. That is the whole safety story, live.

Requirements
------------
  pip install "brukal[agents]"          # anthropic + pydantic
  export ANTHROPIC_API_KEY=sk-...       # your key
  # a scope.json in the current dir whose authorized_cidrs include <target>

Usage
-----
  # smoke-test the wiring with the fake cage (no Docker, synthetic output):
  python3 run_recon.py 127.0.0.1 --fake

  # real run against an authorised lab host (Docker cage must be up):
  python3 run_recon.py 10.10.10.5 --turns 3

Only ever point this at systems you are authorised to test. See SECURITY.md.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from brukal import AuditLog, DockerKali, Executor, FakeKali, Gate, load_scope


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="run_recon", description="Brukal recon loop (Path A)")
    p.add_argument("target", help="the host to enumerate (must be in scope)")
    p.add_argument("--turns", type=int, default=1, help="how many recon turns to run")
    p.add_argument("--fake", action="store_true", help="use the fake cage (no Docker)")
    p.add_argument("--scope", default="scope.json", help="path to scope.json")
    p.add_argument("--audit", default="runs/audit.jsonl", help="path to the audit log")
    p.add_argument("--model", default=None, help="override the model id")
    args = p.parse_args(argv)

    # Import the agent stack lazily so a missing SDK gives a clean message.
    try:
        from brukal.llm import LLMClient
        from brukal.agents import ReconAgent
    except ImportError as e:
        print(f"Agent dependencies missing ({e}). Install with: pip install \"brukal[agents]\"")
        return 2

    # Assemble the system. Note the wiring: the agent is handed the EXECUTOR,
    # never the cage. It can propose and submit; it cannot execute directly.
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

    print(f"\nEngagement: {scope.engagement}   target: {args.target}   "
          f"cage: {'fake' if args.fake else 'docker'}\n")

    findings: list[str] = []  # crude in-memory context; the vault comes in M4
    for turn in range(1, args.turns + 1):
        task = f"Enumerate services on {args.target}."
        context = "\n".join(findings[-3:])  # last few observations, truncated below

        print(f"── turn {turn} " + "─" * 50)
        request, outcome = agent.run_task(task, context)

        if request is None:
            print("  model produced no valid Action Request (no-op). stopping.")
            break

        print(f"  proposed : {request.command}")
        print(f"  target   : {request.target_host}    intent: {request.intent}")
        if request.justification:
            print(f"  why      : {request.justification}")

        decision, result = outcome
        print(f"  verdict  : {decision.verdict}  ({decision.reason})")

        if not decision.allowed:
            print("  gate refused this action. stopping.")
            break

        out = (result.stdout or "").strip()
        snippet = out[:400]
        print(f"  output   : {snippet}{'…' if len(out) > 400 else ''}")

        # Feed a truncated, explicitly-untrusted observation into the next turn.
        # (A dedicated summariser agent digests this properly in a later milestone.)
        findings.append(f"[{request.command}] -> {snippet[:200]}")
        print()

    print("─" * 62)
    print(f"audit log : {args.audit}")
    print(f"chain intact: {audit.verify()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
