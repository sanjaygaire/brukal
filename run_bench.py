#!/usr/bin/env python3
"""
run_bench.py — the honest live benchmark.

By default it runs a DETERMINISTIC self-test: the real governed loop over the built-in
ScenarioKali boxes (no key, no Docker, no network), so anyone can reproduce the
harness's behaviour and see the metrics it records.

    python3 run_bench.py                       # scenario self-test
    python3 run_bench.py --json bench.json      # also dump machine-readable metrics

The REAL benchmark runs the full loop against authorised targets through the Docker cage
and a real model — it runs REAL tools, so it needs your sign-off and an authorised scope:

    python3 run_bench.py --live --target 10.10.10.5 --yes-authorised \
        --model qwen2.5 --provider ollama --max-cost 0.50

scope-violations MUST be 0 in every mode; a non-zero count is a hard failure.
"""
from __future__ import annotations

import argparse
import json
import sys

from brukal.benchmark import render, run_live, run_scenarios


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="run_bench",
                                description="Brukal honest live benchmark")
    p.add_argument("--live", action="store_true",
                   help="run the real loop against authorised targets (needs a cage + model)")
    p.add_argument("--target", action="append", default=[],
                   help="an authorised target (repeatable); required with --live")
    p.add_argument("--scope", default="scope.json")
    p.add_argument("--fake", action="store_true",
                   help="with --live: use the FakeKali cage (no Docker) for a dry run")
    p.add_argument("--yes-authorised", action="store_true",
                   help="confirm you are authorised for the targets (required for --live)")
    p.add_argument("--model", default=None)
    p.add_argument("--provider", default=None)
    p.add_argument("--base-url", default=None)
    p.add_argument("--container", default="brukal-kali")
    p.add_argument("--max-steps", type=int, default=20)
    p.add_argument("--max-cost", type=float, default=None)
    p.add_argument("--json", help="also write the metrics as JSON to this path")
    args = p.parse_args(argv)

    if args.live:
        if not args.target or not args.yes_authorised:
            p.error("--live needs at least one --target and --yes-authorised")
        bench = run_live(args.target, scope_path=args.scope, fake=args.fake,
                         yes_authorised=args.yes_authorised, model=args.model,
                         provider=args.provider, base_url=args.base_url,
                         container=args.container, max_steps=args.max_steps,
                         max_cost=args.max_cost)
    else:
        bench = run_scenarios()

    print(render(bench))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(bench.to_dict(), fh, indent=2)
        print(f"  wrote {args.json}")

    # A non-zero scope violation is a hard failure exit code (for CI).
    return 1 if bench.total_scope_violations else 0


if __name__ == "__main__":
    sys.exit(main())
