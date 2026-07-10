#!/usr/bin/env python3
"""
brukal.cli — the command-line entry point (installed as the `brukal` command).

Subcommands
-----------
  brukal target <ip|cidr>          set the engagement scope (validates + logs)
  brukal run <target>              run the full multi-agent engagement
  brukal exec "<cmd>" <target>     propose one command through the gate by hand
  brukal verify                    verify the audit chain

Scope and audit paths default to the CURRENT DIRECTORY, so you run `brukal` from
inside an engagement folder that contains its own scope.json.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import time
from pathlib import Path

from brukal import AuditLog, DockerKali, Executor, FakeKali, Gate, load_scope
from brukal.engagement import interactive_approver
from brukal.engagement import run as run_engagement

_DEFAULT_TOOLS = ["nmap", "gobuster", "nikto", "whatweb", "curl", "dig"]


def _cmd_target(args) -> int:
    """Set (or extend) the authorised scope. Validates the address, refuses to
    silently authorise a broad range, keeps the static fields, and logs it."""
    try:
        net = ipaddress.ip_network(args.cidr, strict=False)
    except ValueError as e:
        print(f"Not a valid IP or CIDR: {args.cidr}  ({e})")
        return 2

    scope_path = Path(args.scope)
    if scope_path.exists():
        data = json.loads(scope_path.read_text(encoding="utf-8"))
    else:
        data = {"engagement": "brukal-engagement", "authorized_cidrs": [],
                "allowlisted_tools": _DEFAULT_TOOLS, "rate_limit_per_min": 30}

    cidr = str(net)
    if net.num_addresses > 1 and not args.yes:
        try:
            ans = input(f"  {cidr} authorises {net.num_addresses} addresses "
                        f"(broader than one host). Proceed? [y/N] ").strip().lower()
        except (EOFError, OSError, KeyboardInterrupt):
            ans = ""   # non-interactive / interrupted -> fail-closed (treat as no)
        if ans not in ("y", "yes"):
            print("  aborted — scope unchanged.")
            return 1

    existing = data.get("authorized_cidrs", [])
    data["authorized_cidrs"] = (existing + [cidr] if args.add and cidr not in existing
                                else existing if args.add else [cidr])
    scope_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    logp = Path(args.log)
    logp.parent.mkdir(parents=True, exist_ok=True)
    with logp.open("a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')}  scope "
                f"{'+=' if args.add else '='} {cidr}  "
                f"(engagement={data.get('engagement')})\n")

    print(f"\n  engagement : {data.get('engagement')}")
    print(f"  authorised : {', '.join(data['authorized_cidrs'])}")
    print(f"  tools      : {', '.join(data.get('allowlisted_tools', _DEFAULT_TOOLS))}")
    print(f"  rate limit : {data.get('rate_limit_per_min', 30)}/min")
    print(f"  wrote {scope_path}   (logged to {logp})\n")
    return 0


def _cmd_exec(args) -> int:
    audit = AuditLog(args.audit)
    gate = Gate(load_scope(args.scope))
    kali = FakeKali() if args.fake else DockerKali(container=args.container)
    executor = Executor(gate, kali, audit, approver=interactive_approver)

    decision, result = executor.run(args.command, args.target, agent=args.agent)

    print(f"\n  verdict : {decision.verdict}")
    print(f"  reason  : {decision.reason}")
    print(f"  layer   : {decision.layer}")
    if decision.risk_band is not None:
        print(f"  risk    : {decision.risk_band} "
              f"(reversibility={decision.reversibility}, blast={decision.blast_radius})")
    if result is not None:
        print(f"  exit    : {result.returncode}")
        if result.stdout:
            print("  --- stdout ---")
            print("  " + result.stdout.replace("\n", "\n  ").rstrip())
        if result.stderr:
            print("  --- stderr ---")
            print("  " + result.stderr.replace("\n", "\n  ").rstrip())
    print()
    return 0 if result is not None else 1


def _cmd_verify(args) -> int:
    print("audit chain intact:", AuditLog(args.audit).verify())
    return 0


def _cmd_run(args) -> int:
    return run_engagement(
        args.target, fake=args.fake, yes_authorised=args.yes_authorised,
        scope_path=args.scope, audit_path=args.audit, vault_path=args.vault,
        container=args.container, model=args.model)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="brukal", description="Trust-governed pentest gate")
    sub = p.add_subparsers(dest="cmd")

    pt = sub.add_parser("target", help="set the engagement scope to an IP or CIDR")
    pt.add_argument("cidr", help="e.g. 10.10.10.5 or 10.10.10.0/24")
    pt.add_argument("--add", action="store_true", help="accumulate instead of replace")
    pt.add_argument("--yes", action="store_true", help="skip the broad-range confirmation")
    pt.add_argument("--scope", default="scope.json")
    pt.add_argument("--log", default="runs/engagement.log")
    pt.set_defaults(func=_cmd_target)

    pr = sub.add_parser("run", help="run the full multi-agent engagement")
    pr.add_argument("target")
    pr.add_argument("--fake", action="store_true", help="fake cage (no Docker)")
    pr.add_argument("--yes-authorised", action="store_true",
                    help="confirm you are authorised (required for a live run)")
    pr.add_argument("--scope", default="scope.json")
    pr.add_argument("--audit", default="runs/audit.jsonl")
    pr.add_argument("--vault", default="runs/vault")
    pr.add_argument("--container", default="brukal-kali")
    pr.add_argument("--model", default=None)
    pr.set_defaults(func=_cmd_run)

    pe = sub.add_parser("exec", help="propose one command through the gate by hand")
    pe.add_argument("command")
    pe.add_argument("target")
    pe.add_argument("--fake", action="store_true", help="fake cage (no Docker)")
    pe.add_argument("--agent", default="operator")
    pe.add_argument("--scope", default="scope.json")
    pe.add_argument("--audit", default="runs/audit.jsonl")
    pe.add_argument("--container", default="brukal-kali")
    pe.set_defaults(func=_cmd_exec)

    pv = sub.add_parser("verify", help="verify the audit chain and exit")
    pv.add_argument("--audit", default="runs/audit.jsonl")
    pv.set_defaults(func=_cmd_verify)

    args = p.parse_args(argv)
    if not getattr(args, "func", None):
        p.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
