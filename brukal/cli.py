#!/usr/bin/env python3
"""
brukal.cli — the command-line entry point (installed as the `brukal` command).

Subcommands
-----------
  brukal                           the banner + quick start
  brukal hunt                      guided engagement (prompts for key + target)
  brukal target <ip|cidr>          set the engagement scope (validates + logs)
  brukal run <target>              run the full multi-agent engagement
  brukal exec "<cmd>" <target>     propose one command through the gate by hand
  brukal verify                    verify the audit chain

Scope and audit paths default to the CURRENT DIRECTORY, so you run `brukal` from
inside an engagement folder that contains its own scope.json.
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import sys
import time
from pathlib import Path

from brukal import (AuditLog, DockerKali, Executor, FakeKali, Gate, SkillLibrary,
                    install_pack, load_scope)
from brukal.engagement import interactive_approver
from brukal.engagement import run as run_engagement

_DEFAULT_TOOLS = ["nmap", "gobuster", "nikto", "whatweb", "curl", "dig"]

_CYAN, _DIM, _OFF = "\033[36m", "\033[2m", "\033[0m"

_LOGO = r"""
 ██████╗ ██████╗ ██╗   ██╗██╗  ██╗ █████╗ ██╗
 ██╔══██╗██╔══██╗██║   ██║██║ ██╔╝██╔══██╗██║
 ██████╔╝██████╔╝██║   ██║█████╔╝ ███████║██║
 ██╔══██╗██╔══██╗██║   ██║██╔═██╗ ██╔══██║██║
 ██████╔╝██║  ██║╚██████╔╝██║  ██╗██║  ██║███████╗
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝"""


def _banner() -> str:
    return (f"{_CYAN}{_LOGO}{_OFF}\n"
            f"  trust-governed multi-agent pentest  ·  {_CYAN}let's hunt{_OFF}\n"
            f"  {_DIM}the model proposes, the deterministic gate disposes{_OFF}\n")


def _quickstart() -> str:
    return ("  Quick start:\n"
            "    brukal hunt                  guided engagement (asks for key + target)\n"
            "    brukal target <ip|cidr>      set the authorised scope\n"
            "    brukal run <target>          full multi-agent engagement\n"
            "    brukal exec \"<cmd>\" <target>  one command through the gate\n"
            "    brukal verify                check the audit chain\n\n"
            "  Add -h to any command for its options (e.g. `brukal run -h`).\n")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _load_scope_data(scope_path) -> dict:
    p = Path(scope_path)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {"engagement": "brukal-engagement", "authorized_cidrs": [],
            "allowlisted_tools": _DEFAULT_TOOLS, "rate_limit_per_min": 30}


def _write_scope(cidr_input, scope_path, log_path, *, add=False, assume_yes=False):
    """Validate + persist scope. Returns (exit_code, scope_data_or_None)."""
    try:
        net = ipaddress.ip_network(cidr_input, strict=False)
    except ValueError as e:
        print(f"Not a valid IP or CIDR: {cidr_input}  ({e})")
        return 2, None

    data = _load_scope_data(scope_path)
    cidr = str(net)
    if net.num_addresses > 1 and not assume_yes:
        try:
            ans = input(f"  {cidr} authorises {net.num_addresses} addresses "
                        f"(broader than one host). Proceed? [y/N] ").strip().lower()
        except (EOFError, OSError, KeyboardInterrupt):
            ans = ""   # non-interactive / interrupted -> fail-closed (no)
        if ans not in ("y", "yes"):
            print("  aborted — scope unchanged.")
            return 1, None

    existing = data.get("authorized_cidrs", [])
    data["authorized_cidrs"] = (existing + [cidr] if add and cidr not in existing
                                else existing if add else [cidr])
    Path(scope_path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    logp = Path(log_path)
    logp.parent.mkdir(parents=True, exist_ok=True)
    with logp.open("a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')}  scope "
                f"{'+=' if add else '='} {cidr}  (engagement={data.get('engagement')})\n")
    return 0, data


def _ensure_key() -> bool:
    """Make sure ANTHROPIC_API_KEY is set; prompt (hidden) if interactive."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        return True
    if not sys.stdin.isatty():
        return False
    try:
        key = getpass.getpass("  Anthropic API key (input hidden): ").strip()
    except (EOFError, KeyboardInterrupt):
        key = ""
    if key:
        os.environ["ANTHROPIC_API_KEY"] = key
        return True
    return False


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #

def _cmd_hunt(args) -> int:
    provider = (args.provider or os.environ.get("BRUKAL_PROVIDER", "anthropic")).lower()
    if provider == "anthropic" and not _ensure_key():
        print("  ⚠ No API key set. Set ANTHROPIC_API_KEY, or use a free local model:"
              " --provider ollama --model qwen2.5\n")

    target = args.target
    if not target:
        try:
            target = input("  Target IP or CIDR you are AUTHORISED to test: ").strip()
        except (EOFError, OSError):
            target = ""
    if not target:
        print("  No target given — nothing to do.")
        return 1

    rc, data = _write_scope(target, args.scope, args.log, assume_yes=args.yes)
    if rc != 0:
        return rc
    print(f"  scope set: {', '.join(data['authorized_cidrs'])}")

    try:
        ok = input(f"\n  Confirm you are AUTHORISED to test {target}? [y/N] ").strip().lower()
    except (EOFError, OSError):
        ok = ""
    if ok not in ("y", "yes"):
        print("  aborted — authorisation not confirmed.")
        return 1

    print()
    return run_engagement(
        target, fake=args.fake, yes_authorised=True, scope_path=args.scope,
        audit_path=args.audit, vault_path=args.vault, container=args.container,
        model=args.model, tui=args.tui, provider=args.provider, base_url=args.base_url)


def _cmd_target(args) -> int:
    rc, data = _write_scope(args.cidr, args.scope, args.log,
                            add=args.add, assume_yes=args.yes)
    if rc != 0:
        return rc
    print(f"\n  engagement : {data.get('engagement')}")
    print(f"  authorised : {', '.join(data['authorized_cidrs'])}")
    print(f"  tools      : {', '.join(data.get('allowlisted_tools', _DEFAULT_TOOLS))}")
    print(f"  rate limit : {data.get('rate_limit_per_min', 30)}/min")
    print(f"  wrote {args.scope}   (logged to {args.log})\n")
    return 0


def _cmd_run(args) -> int:
    provider = (args.provider or os.environ.get("BRUKAL_PROVIDER", "anthropic")).lower()
    if provider == "anthropic" and not args.fake and not _ensure_key():
        print("  ⚠ No key set. Set ANTHROPIC_API_KEY, or use a free local model: "
              "--provider ollama --model qwen2.5")
    return run_engagement(
        args.target, fake=args.fake, yes_authorised=args.yes_authorised,
        scope_path=args.scope, audit_path=args.audit, vault_path=args.vault,
        container=args.container, model=args.model, tui=args.tui,
        provider=args.provider, base_url=args.base_url)


def _cmd_solve(args) -> int:
    from brukal.assist import run_solve
    provider = (args.provider or os.environ.get("BRUKAL_PROVIDER", "anthropic")).lower()
    if provider == "anthropic" and not args.fake and not _ensure_key():
        print("  ⚠ No key set. Set ANTHROPIC_API_KEY, or use --provider ollama --model qwen2.5")
    return run_solve(
        args.target, fake=args.fake, yes_authorised=args.yes_authorised,
        scope_path=args.scope, audit_path=args.audit, container=args.container,
        model=args.model, provider=args.provider, base_url=args.base_url)


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


def _cmd_skills(args) -> int:
    if args.action == "add":
        if not args.source:
            print("  usage: brukal skills add <git-url>")
            return 2
        print(f"  fetching skill pack from {args.source} ...")
        try:
            count, dest = install_pack(args.source)
        except Exception as e:
            print(f"  failed: {e}")
            return 2
        print(f"  installed {count} skills into {dest}")
        return 0

    lib = SkillLibrary()
    if args.action == "search":
        hits = lib.retrieve(args.source or "", limit=5)
        if not hits:
            print("  no matching skills.")
            return 0
        for s in hits:
            print(f"  [{s.category}] {s.name}\n      {s.description[:100]}")
        return 0

    # default: list
    print(f"\n  {len(lib)} skills loaded across {len(lib.categories())} categories:")
    for cat, n in lib.categories().items():
        print(f"    {cat:<18} {n}")
    print("\n  brukal skills search \"<topic>\"   ·   brukal skills add <git-url>\n")
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="brukal", description="Brukal — trust-governed multi-agent pentest.",
        epilog="Run `brukal hunt` for a guided engagement, or `brukal <cmd> -h`.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", metavar="<command>")

    ph = sub.add_parser("hunt", help="guided engagement (prompts for key + target)")
    ph.add_argument("target", nargs="?", help="target IP/CIDR (prompted if omitted)")
    ph.add_argument("--fake", action="store_true", help="fake cage (no Docker)")
    ph.add_argument("--tui", action=argparse.BooleanOptionalAction, default=True,
                    help="live dashboard (default on; --no-tui to disable)")
    ph.add_argument("--yes", action="store_true", help="skip the broad-range prompt")
    ph.add_argument("--scope", default="scope.json")
    ph.add_argument("--audit", default="runs/audit.jsonl")
    ph.add_argument("--vault", default="runs/vault")
    ph.add_argument("--container", default="brukal-kali")
    ph.add_argument("--model", default=None, help="model id (provider-specific)")
    ph.add_argument("--provider", default=None,
                    help="anthropic (default) | ollama | openai | openrouter | groq | ...")
    ph.add_argument("--base-url", default=None, help="endpoint for openai-compatible")
    ph.set_defaults(func=_cmd_hunt)

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
    pr.add_argument("--tui", action="store_true", help="live dashboard")
    pr.add_argument("--scope", default="scope.json")
    pr.add_argument("--audit", default="runs/audit.jsonl")
    pr.add_argument("--vault", default="runs/vault")
    pr.add_argument("--container", default="brukal-kali")
    pr.add_argument("--model", default=None, help="model id (provider-specific)")
    pr.add_argument("--provider", default=None,
                    help="anthropic (default) | ollama | glm/zhipu | deepseek | "
                         "openrouter | openai | groq | lmstudio | openai-compatible")
    pr.add_argument("--base-url", default=None, help="endpoint for openai-compatible")
    pr.set_defaults(func=_cmd_run)

    psv = sub.add_parser("solve", help="interactive human-assisted box solver")
    psv.add_argument("target")
    psv.add_argument("--fake", action="store_true", help="fake cage (no Docker)")
    psv.add_argument("--yes-authorised", action="store_true",
                     help="confirm you are authorised (required for a live run)")
    psv.add_argument("--scope", default="scope.json")
    psv.add_argument("--audit", default="runs/audit.jsonl")
    psv.add_argument("--container", default="brukal-kali")
    psv.add_argument("--model", default=None)
    psv.add_argument("--provider", default=None,
                     help="anthropic (default) | ollama | openai | openrouter | ...")
    psv.add_argument("--base-url", default=None)
    psv.set_defaults(func=_cmd_solve)

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

    ps = sub.add_parser("skills", help="list / search / add offensive skill packs")
    ps.add_argument("action", nargs="?", default="list",
                    choices=["list", "search", "add"], help="default: list")
    ps.add_argument("source", nargs="?", help="query (search) or git URL (add)")
    ps.set_defaults(func=_cmd_skills)

    args = p.parse_args(argv)
    print(_banner())                       # the welcome banner shows on every call
    if not getattr(args, "func", None):
        print(_quickstart())
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
