#!/usr/bin/env python3
"""
run_eval.py — the capability evaluation (steps-to-foothold + scope violations).

Where `run_experiments.py` proves the GOVERNANCE claims, this proves the
CAPABILITY claim: Brukal reaches a foothold in about the same number of steps as
an ungoverned agent, while committing zero scope violations. It runs the same
scripted strategist + GroundedLoop over each simulated box twice — once through
the gate (governed) and once without it (ungated) — so the only variable is the
gate itself.

By default it runs entirely against the FAKE (scripted) box: no Docker, no
network, no API key, no target. Reproducible on any laptop.

    python3 run_eval.py                        # scripted boxes, both arms
    python3 run_eval.py --json eval.json       # also dump machine-readable

To fold in a real external baseline (e.g. PentestGPT), drop its transcript
metrics into a JSON file and pass --baseline; the numbers print alongside Brukal's.
A LIVE capability run against a real cage/target is intentionally out of scope for
this offline harness — use `brukal auto <target>` under maintainer sign-off for that.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from brukal.eval import render, run_all


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="run_eval",
                                description="Brukal capability evaluation harness")
    p.add_argument("--json", help="also write results as JSON to this path")
    p.add_argument("--baseline", help="JSON file of external-baseline metrics "
                                      "(e.g. PentestGPT) to print alongside")
    args = p.parse_args(argv)

    results = run_all(environment="fake")

    if args.baseline:
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        for r in results:
            r.external_baseline = baseline.get(r.scenario) or baseline.get("*")

    print(render(results))

    if args.json:
        Path(args.json).write_text(
            json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")
        print(f"  wrote {args.json}")

    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
