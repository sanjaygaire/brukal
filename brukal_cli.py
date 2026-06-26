#!/usr/bin/env python3
"""
brukal_cli.py — drive the milestone-1 spine by hand.

This is you standing in for the agents that arrive in milestone 2: you propose
a command + target, and watch the gate ALLOW or DENY it. Approved commands run
inside the Kali container; everything is written to the audit log.

Examples
--------
  # safe, no Docker needed — uses the fake cage:
  python brukal_cli.py --fake "nmap -sV 10.10.10.5" 10.10.10.5

  # against the real Kali container (after: docker compose ... up -d):
  python brukal_cli.py "nmap -sV 10.10.10.5" 10.10.10.5

  # an out-of-scope attempt — watch it get denied:
  python brukal_cli.py --fake "nmap -sV 8.8.8.8" 8.8.8.8

  # verify the audit chain has not been tampered with:
  python brukal_cli.py --verify
"""
from __future__ import annotations

import argparse
from pathlib import Path

from brukal import AuditLog, DockerKali, Executor, FakeKali, Gate, load_scope

HERE = Path(__file__).resolve().parent
SCOPE = HERE / "scope.json"
AUDIT = HERE / "runs" / "audit.jsonl"


def main():
    p = argparse.ArgumentParser(description="Brukal milestone-1 gate CLI")
    p.add_argument("command", nargs="?", help="the command to propose")
    p.add_argument("target", nargs="?", help="the declared target IP")
    p.add_argument("--fake", action="store_true",
                   help="use the fake cage (no Docker, records instead of runs)")
    p.add_argument("--agent", default="operator", help="agent name for the log")
    p.add_argument("--verify", action="store_true",
                   help="verify the audit chain and exit")
    args = p.parse_args()

    audit = AuditLog(AUDIT)

    if args.verify:
        print("audit chain intact:", audit.verify())
        return

    if not args.command or not args.target:
        p.error("provide both a command and a target (or use --verify)")

    gate = Gate(load_scope(SCOPE))
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


if __name__ == "__main__":
    main()
