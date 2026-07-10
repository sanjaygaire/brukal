#!/usr/bin/env python3
"""
run_engagement.py — drive the full Brukal engagement loop end to end.

The orchestrator walks a Pentesting Task Tree with all three agents
(recon -> exploit -> verify), the soft risk layer, human approval on escalations,
and adaptive per-agent trust. Each agent is handed the Executor, never the cage.

Requirements
------------
  pip install "brukal[agents]"          # anthropic + pydantic
  export ANTHROPIC_API_KEY=sk-...       # your key (real, non-fake runs)
  # a scope.json whose authorized_cidrs include <target>  (see `brukal target`)

Usage
-----
  # smoke-test the wiring with the fake cage (no Docker, synthetic output):
  python3 run_engagement.py 10.10.10.5 --fake

  # REAL run against an authorised lab host (Docker cage must be up):
  docker compose -f docker/docker-compose.yml up -d --build
  python3 run_engagement.py 10.10.10.5 --yes-authorised

This is identical to `brukal run`. Only ever point a live run at systems you are
authorised to test. See SECURITY.md.
"""
from __future__ import annotations

import argparse

from brukal.engagement import run


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="run_engagement",
                                description="Brukal full orchestrated engagement")
    p.add_argument("target", help="the host to work (must be in scope)")
    p.add_argument("--fake", action="store_true", help="use the fake cage (no Docker)")
    p.add_argument("--yes-authorised", action="store_true",
                   help="confirm you are authorised to test the target (live runs)")
    p.add_argument("--scope", default="scope.json", help="path to scope.json")
    p.add_argument("--audit", default="runs/audit.jsonl", help="path to the audit log")
    p.add_argument("--vault", default="runs/vault", help="blackboard vault directory")
    p.add_argument("--container", default="brukal-kali", help="cage container name")
    p.add_argument("--model", default=None, help="override the model id")
    p.add_argument("--tui", action="store_true", help="live dashboard (needs rich)")
    args = p.parse_args(argv)

    return run(args.target, fake=args.fake, yes_authorised=args.yes_authorised,
               scope_path=args.scope, audit_path=args.audit, vault_path=args.vault,
               container=args.container, model=args.model, tui=args.tui)


if __name__ == "__main__":
    raise SystemExit(main())
