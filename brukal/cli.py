#!/usr/bin/env python3
"""
brukal.cli — the command-line entry point (installed as the `brukal` command).

Drives the milestone-1 spine by hand: you propose a command + target, the gate
rules on it, approved commands run in the cage, everything is logged.

Scope and audit paths default to the CURRENT DIRECTORY, so you run `brukal`
from inside an engagement folder that contains its own scope.json.

Examples
--------
  brukal --fake "nmap -sV 10.10.10.5" 10.10.10.5
  brukal "nmap -sV 10.10.10.5" 10.10.10.5
  brukal --verify
"""
from __future__ import annotations

import argparse
from pathlib import Path

from brukal import AuditLog, DockerKali, Executor, FakeKali, Gate, load_scope


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="brukal", description="Trust-governed pentest gate")
    p.add_argument("command", nargs="?", help="the command to propose")
    p.add_argument("target", nargs="?", help="the declared target IP")
    p.add_argument("--scope", default="scope.json", help="path to scope.json (default: ./scope.json)")
    p.add_argument("--audit", default="runs/audit.jsonl", help="path to the audit log")
    p.add_argument("--fake", action="store_true", help="use the fake cage (no Docker)")
    p.add_argument("--agent", default="operator", help="agent name for the log")
    p.add_argument("--verify", action="store_true", help="verify the audit chain and exit")
    args = p.parse_args(argv)

    audit = AuditLog(args.audit)

    if args.verify:
        print("audit chain intact:", audit.verify())
        return 0

    if not args.command or not args.target:
        p.error("provide both a command and a target (or use --verify)")

    gate = Gate(load_scope(args.scope))
    kali = FakeKali() if args.fake else DockerKali()
    executor = Executor(gate, kali, audit)

    decision, result = executor.run(args.command, args.target, agent=args.agent)

    print(f"\n  verdict : {decision.verdict}")
    print(f"  reason  : {decision.reason}")
    print(f"  layer   : {decision.layer}")
    if result is not None:
        print(f"  exit    : {result.returncode}")
        if result.stdout:
            print("  --- stdout ---")
            print("  " + result.stdout.replace("\n", "\n  ").rstrip())
        if result.stderr:
            print("  --- stderr ---")
            print("  " + result.stderr.replace("\n", "\n  ").rstrip())
    print()
    return 0 if decision.allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())
