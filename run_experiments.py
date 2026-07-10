#!/usr/bin/env python3
"""
run_experiments.py — Milestone 7: compute the four benchmark metrics.

By default this runs entirely against the FAKE cage: it needs no Docker, no
network, no API key, and no authorised target, because the headline metrics are
properties of the deterministic gate. That makes the paper's core results
reproducible on any laptop.

    python3 run_experiments.py                     # fake cage, all four metrics
    python3 run_experiments.py --json results.json # also dump machine-readable

A LIVE run additionally exercises the real Docker cage against a target you are
authorised to test. It is deliberately gated behind an explicit flag and never
starts on its own:

    python3 run_experiments.py --env docker --target 10.10.10.5 --yes-authorised

Only ever point a live run at systems you are authorised to test. See SECURITY.md.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from brukal import load_scope
from brukal.experiment import render, run_all


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="run_experiments",
                                description="Brukal benchmark harness (milestone 7)")
    p.add_argument("--env", choices=["fake", "docker"], default="fake",
                   help="fake cage (default, no infra) or the real Docker cage")
    p.add_argument("--target", help="authorised target (required for --env docker)")
    p.add_argument("--scope", default="scope.json", help="path to scope.json")
    p.add_argument("--json", help="also write results as JSON to this path")
    p.add_argument("--yes-authorised", action="store_true",
                   help="explicit confirmation you are authorised (required for live)")
    args = p.parse_args(argv)

    scope = load_scope(args.scope)

    if args.env == "docker":
        # A real run: refuse unless the maintainer has explicitly signed off.
        if not (args.target and args.yes_authorised):
            print("Live run refused. A Docker run requires BOTH:\n"
                  "  --target <an address inside scope.json>\n"
                  "  --yes-authorised   (you confirm you are authorised to test it)\n"
                  "Also bring the cage up first:\n"
                  "  docker compose -f docker/docker-compose.yml up -d --build")
            return 2
        if not scope.contains_ip(args.target):
            print(f"Refused: target {args.target} is not inside scope.json.")
            return 2
        from brukal.kali import DockerKali
        make_kali = DockerKali
        environment = f"docker:{args.target}"
        llm = None
        try:                                   # use a real model live, if available
            from brukal.llm import LLMClient
            llm = LLMClient()
        except Exception:
            pass                               # fall back to the scripted model
        print(f"\n⚠  LIVE run against {args.target} via the Docker cage. "
              f"Ensure you are authorised.\n")
    else:
        from brukal.kali import FakeKali
        make_kali = FakeKali
        environment = "fake"
        llm = None

    results = run_all(scope, make_kali=make_kali, environment=environment, llm=llm)
    print(render(results))

    if args.json:
        payload = [{"name": r.name, "environment": r.environment,
                    "metrics": r.metrics, "passed": r.passed, "note": r.note}
                   for r in results]
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"  wrote {args.json}")

    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
