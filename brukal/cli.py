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


def _add_login_args(p) -> None:
    """Authenticated-scanning flags: give Brukal form-login credentials so the crawl
    and web actions run BEHIND the login. Auth goes through the governed browser (WEB
    actions) — the gate is untouched."""
    p.add_argument("--login-url", default=None, metavar="URL",
                   help="form-login URL to authenticate at before scanning "
                        "(e.g. http://target/login.php) — enables authenticated scanning")
    p.add_argument("--login-user", default=None, metavar="USER", help="login username")
    p.add_argument("--login-pass", default=None, metavar="PASS", help="login password")
    p.add_argument("--login-field-user", default="username", metavar="NAME",
                   help="username form-field name (default: username)")
    p.add_argument("--login-field-pass", default="password", metavar="NAME",
                   help="password form-field name (default: password)")
    p.add_argument("--login-type", default="form", choices=["form", "json", "basic"],
                   help="auth type: form (default), json (API login → bearer token), "
                        "or basic (HTTP Basic)")


def _login_from_args(args):
    """Build the login spec dict from CLI args, or None if no --login-url was given."""
    url = getattr(args, "login_url", None)
    if not url:
        return None
    return {"url": url, "user": getattr(args, "login_user", "") or "",
            "password": getattr(args, "login_pass", "") or "",
            "user_field": getattr(args, "login_field_user", "username"),
            "pass_field": getattr(args, "login_field_pass", "password"),
            "type": getattr(args, "login_type", "form")}


def _resolve_scope(scope_arg):
    """Scope is mandatory. Use --scope when given; else ./scope.json if it exists;
    else None (refuse). Brukal never assumes a broad default scope on the operator's
    behalf — fail-closed (invariant 2)."""
    if scope_arg:
        return scope_arg
    if Path("scope.json").exists():
        return "scope.json"
    return None


def _no_scope() -> int:
    print("Refused: no authorised scope. Brukal never runs without one.\n"
          "  set one:  brukal target <ip-or-cidr>\n"
          "  or pass:  --scope <file>")
    return 2


def _cmd_run(args) -> int:
    scope_path = _resolve_scope(args.scope)
    if scope_path is None:
        return _no_scope()
    provider = (args.provider or os.environ.get("BRUKAL_PROVIDER", "anthropic")).lower()
    if provider == "anthropic" and not args.fake and not _ensure_key():
        print("  ⚠ No key set. Set ANTHROPIC_API_KEY, or use a free local model: "
              "--provider ollama --model qwen2.5")
    return run_engagement(
        args.target, fake=args.fake, yes_authorised=args.yes_authorised,
        scope_path=scope_path, audit_path=args.audit, vault_path=args.vault,
        container=args.container, model=args.model, tui=args.tui,
        provider=args.provider, base_url=args.base_url,
        parallel=args.parallel, workers=args.workers)


def _cmd_solve(args) -> int:
    # No pre-flight key nag here: when no --provider/BRUKAL_PROVIDER is set,
    # `brukal solve` asks how to run the model (and for a key) interactively.
    from brukal.assist import run_solve
    scope_path = _resolve_scope(args.scope)
    if scope_path is None:
        return _no_scope()
    return run_solve(
        args.target, fake=args.fake, yes_authorised=args.yes_authorised,
        scope_path=scope_path, audit_path=args.audit, vault_path=args.vault,
        container=args.container, hosts=args.host or (), login=_login_from_args(args),
        model=args.model, provider=args.provider, base_url=args.base_url)


def _cmd_auto(args) -> int:
    # Headless grounded agentic loop: Brukal drives the safe in-scope steps
    # itself and hands back on a manual/escalation step, a stall, or the budget.
    from brukal.assist import run_auto
    scope_path = _resolve_scope(args.scope)
    if scope_path is None:
        return _no_scope()
    return run_auto(
        args.target, fake=args.fake, yes_authorised=args.yes_authorised,
        scope_path=scope_path, audit_path=args.audit, vault_path=args.vault,
        container=args.container, max_steps=args.max_steps, hosts=args.host or (),
        model=args.model, provider=args.provider, base_url=args.base_url,
        handoff_to_menu=not args.no_handoff, single_agent=args.single_agent,
        full_send=args.full_send, mode=getattr(args, "mode", None),
        packs_dir=getattr(args, "packs", None), fail_on=getattr(args, "fail_on", None),
        no_research=args.no_research,
        max_cost=getattr(args, "max_cost", None),
        max_research=getattr(args, "max_research", None),
        max_time=getattr(args, "max_time", None),
        resume=not getattr(args, "no_resume", False),
        login=_login_from_args(args))


def _cmd_apk(args) -> int:
    # Static-analyse an Android APK: decompile in the cage, then scan the manifest +
    # source for dangerous config and hardcoded secrets. Offline analysis of a file the
    # operator supplied — no network target, so no scope needed.
    import os

    from brukal.apkscan import analyze_apk
    from brukal.kali import DockerKali, FakeKali
    kali = FakeKali() if args.fake else DockerKali(container=args.container)
    apk = args.apk
    if not args.fake and os.path.isfile(apk):          # a host file → copy it into the cage
        dest = "/tmp/brukal_target.apk"
        import subprocess
        subprocess.run(["docker", "cp", apk, f"{args.container}:{dest}"],
                       capture_output=True)
        apk = dest
    print(f"\n  Analysing APK: {args.apk}\n")
    out = analyze_apk(kali, apk)
    findings = sorted(out["findings"],
                      key=lambda f: ["critical", "high", "medium", "low", "info"].index(f[0]))
    if not findings:
        print("  No static findings (or decompiler unavailable — rebuild the cage with "
              "jadx+apktool for full coverage).")
        return 0
    print(f"  {len(findings)} finding(s):\n")
    for sev, label, ev, where in findings:
        print(f"  [{sev.upper():8}] {label}  ({where})")
        if ev:
            print(f"             {ev[:100]}")
    return 0


def _cmd_report(args) -> int:
    # Build a deliverable report from a target's persisted findings vault.
    from pathlib import Path

    from brukal.assist import _vault_for
    from brukal.findings import FindingStore
    from brukal.report import build_report, write_reports
    vault_dir = _vault_for(args.vault, args.target) if args.target else Path(args.vault)
    store = FindingStore(Path(vault_dir) / "findings.jsonl")
    meta = {"target": args.target or "-", "scope": args.target or "-",
            "engagement": "-", "cage": "-", "stop_reason": "report (regenerated)",
            "audit_intact": None}
    written = write_reports(store, meta, vault_dir)
    if not written.get("md"):
        print("No findings vault found. Run `brukal auto <target>` first.")
        return 1
    print(f"report: {written['md']}   ({len(store)} finding(s), "
          f"{len(store.confirmed())} confirmed)")
    if args.show:
        print("\n" + build_report(store, meta))
    return 0


def _cmd_web(args) -> int:
    # Send ONE governed web request (crafted method/headers/body) through the
    # web gate + audit. The web analogue of `brukal exec`.
    from brukal.web import DockerHttpWebCage, GovernedBrowser, HttpWebCage, WebAction
    scope = load_scope(args.scope)
    if args.host:                       # authorise a vhost at scope time (deliberate)
        scope = scope.with_host(args.host)
    headers = {}
    for h in (args.header or []):
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    audit = AuditLog(args.audit)
    # Default: route through the cage (reaches VPN/HTB targets). --local sends from
    # this host (only for host-reachable targets).
    if args.local:
        cage = HttpWebCage()
    elif args.chrome:                               # render via real headless Chromium
        from brukal.chrome import DockerChromeCage
        from brukal.web import ensure_cage_vhosts
        ensure_cage_vhosts(scope, args.container)
        cage = DockerChromeCage(container=args.container)
    else:
        from brukal.web import ensure_cage_vhosts
        ensure_cage_vhosts(scope, args.container)   # so vhosts like nexus.htb resolve
        cage = DockerHttpWebCage(container=args.container)
    browser = GovernedBrowser(scope, cage, audit)
    if args.chrome:                                 # a browser render (js executed)
        action = WebAction(kind="screenshot" if args.screenshot else "get", url=args.url)
    else:
        action = WebAction(kind="request", url=args.url, method=args.method.upper(),
                           headers=headers, body=args.body or "")
    decision, result = browser.run(action, agent="operator")

    print(f"\n  verdict : {decision.verdict}")
    print(f"  reason  : {decision.reason}")
    print(f"  layer   : {decision.layer}")
    if result is not None:
        print(f"  status  : {result.status}   {result.url}")
        if result.body:
            print("  --- body (first 2000 bytes) ---")
            print("  " + result.body[:2000].replace("\n", "\n  ").rstrip())
    print()
    return 0 if result is not None else 1


def _cmd_lessons(args) -> int:
    # Inspect / add to Brukal's cross-session learned lessons.
    from pathlib import Path

    from brukal.lessons import LessonStore
    store = LessonStore(Path(args.vault) / "lessons.jsonl")
    if args.add:
        tags = [t.strip() for t in (args.tags or "").split(",") if t.strip()]
        store.add(args.add, tags, kind=args.kind)
        print(f"  learned: {args.add}  {tags}")
        return 0
    items = store.retrieve(args.search, 50) if args.search else store._lessons
    if not items:
        print("  no lessons yet — Brukal learns as it hunts.")
        return 0
    print(f"  {len(items)} lesson(s):")
    for l in sorted(items, key=lambda x: -x.hits):
        print(f"    [{l.kind:>7}] (x{l.hits}) {l.text}   {l.tags}")
    return 0


def _cmd_eval(args) -> int:
    # Capability evaluation: governed vs ungated on scripted boxes — steps-to-
    # foothold + scope violations. No infra, no key (deterministic).
    from brukal.eval import render, run_all
    results = run_all(environment="fake")
    print(render(results))
    return 0 if all(r.passed for r in results) else 1


def _cmd_bench(args) -> int:
    # Honest live benchmark. Default: the real loop over scripted ScenarioKali boxes
    # (deterministic, no infra). --live: the real loop against authorised targets.
    from brukal.benchmark import render, run_live, run_scenarios
    if args.live:
        if not args.target or not args.yes_authorised:
            print("  --live needs at least one --target and --yes-authorised.")
            return 2
        bench = run_live(args.target, scope_path=args.scope, fake=args.fake,
                         yes_authorised=args.yes_authorised, model=args.model,
                         provider=args.provider, base_url=args.base_url,
                         container=args.container, max_steps=args.max_steps,
                         max_cost=args.max_cost)
    else:
        bench = run_scenarios()
    print(render(bench))
    if getattr(args, "json", None):
        import json as _json
        with open(args.json, "w", encoding="utf-8") as fh:
            _json.dump(bench.to_dict(), fh, indent=2)
        print(f"  wrote {args.json}")
    return 1 if bench.total_scope_violations else 0


def _cmd_shell(args) -> int:
    from brukal.session import run_shell
    return run_shell(
        args.target, fake=args.fake, yes_authorised=args.yes_authorised,
        scope_path=args.scope, audit_path=args.audit, container=args.container)


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
    ph.add_argument("--scope", default="scope.json",
                    help="scope file the wizard writes the confirmed target into")
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
    pr.add_argument("--parallel", action="store_true",
                    help="dispatch independent tasks to agents concurrently")
    pr.add_argument("--workers", type=int, default=4, help="parallel worker count")
    pr.add_argument("--scope", default=None, help="authorised scope file (mandatory; "
                    "falls back to ./scope.json if present)")
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
    psv.add_argument("target", nargs="?", help="target IP (omit to be prompted)")
    psv.add_argument("--fake", action="store_true", help="fake cage (no Docker)")
    psv.add_argument("--yes-authorised", action="store_true",
                     help="confirm you are authorised (skips the live-run prompt)")
    psv.add_argument("--scope", default=None, help="authorised scope file (mandatory; "
                     "falls back to ./scope.json if present)")
    psv.add_argument("--audit", default="runs/audit.jsonl")
    psv.add_argument("--vault", default="runs/vault",
                     help="Obsidian vault root for saved findings (per-target subfolder)")
    psv.add_argument("--container", default="brukal-kali")
    psv.add_argument("--host", action="append", metavar="VHOST",
                     help="authorise a web vhost at scope time (e.g. --host nexus.htb); "
                          "repeatable. Lets the hunt render/request that vhost.")
    _add_login_args(psv)
    psv.add_argument("--model", default=None)
    psv.add_argument("--provider", default=None,
                     help="anthropic (default) | ollama | openai | openrouter | ...")
    psv.add_argument("--base-url", default=None)
    psv.set_defaults(func=_cmd_solve)

    pa = sub.add_parser("auto",
                        help="autonomous grounded loop — Brukal drives the safe steps itself")
    pa.add_argument("target", nargs="?", help="target IP (omit to be prompted)")
    pa.add_argument("--fake", action="store_true", help="fake cage (no Docker)")
    pa.add_argument("--yes-authorised", action="store_true",
                    help="confirm you are authorised (skips the live-run prompt)")
    pa.add_argument("--scope", default=None, help="authorised scope file (mandatory; "
                    "falls back to ./scope.json if present)")
    pa.add_argument("--audit", default="runs/audit.jsonl")
    pa.add_argument("--vault", default="runs/vault",
                    help="Obsidian vault root for saved findings (per-target subfolder)")
    pa.add_argument("--container", default="brukal-kali")
    pa.add_argument("--host", action="append", metavar="VHOST",
                    help="authorise a web vhost at scope time (e.g. --host nexus.htb); "
                         "repeatable. Lets auto render/request that vhost.")
    _add_login_args(pa)
    pa.add_argument("--packs", default=None, metavar="DIR",
                    help="directory of contributed signature packs (*.json). Packs are "
                         "DATA: patterns and labels only, never code — they cannot act, "
                         "request, or widen scope")
    pa.add_argument("--fail-on", default=None, metavar="SEVERITY",
                    choices=["critical", "high", "medium", "low", "info"],
                    help="exit non-zero when a CONFIRMED finding of at least this "
                         "severity is recorded (for CI). Off by default")
    pa.add_argument("--max-steps", type=int, default=20,
                    help="hand back to you after this many autonomous turns")
    pa.add_argument("--no-handoff", action="store_true",
                    help="when auto hands back, stop and exit instead of dropping "
                         "into the manual menu on the same session")
    pa.add_argument("--single-agent", action="store_true",
                    help="classic single-strategist loop; default is multi-agent "
                         "(strategist plans, recon/exploit/verify specialists execute)")
    pa.add_argument("--full-send", action="store_true",
                    help="unleash: auto-approve ALL in-scope actions (incl. "
                         "irreversible/attack) instead of pausing. Scope wall stays — "
                         "out-of-scope is still DENIED.")
    pmode = pa.add_mutually_exclusive_group()
    pmode.add_argument("--web", action="store_const", dest="mode", const="web",
                       help="force the OWASP-WSTG web-app methodology")
    pmode.add_argument("--box", action="store_const", dest="mode", const="box",
                       help="force the host/box methodology (enum→foothold→privesc→loot)")
    pa.add_argument("--no-research", action="store_true",
                    help="disable control-plane internet learning (no outbound "
                         "research egress; local skills/lessons only)")
    pa.add_argument("--max-cost", type=float, default=None, metavar="USD",
                    help="stop when LLM spend reaches this many dollars "
                         "(also BRUKAL_MAX_COST; ignored for local/free models)")
    pa.add_argument("--max-research", type=int, default=None, metavar="N",
                    help="cap total control-plane research fetches this run "
                         "(also BRUKAL_MAX_RESEARCH)")
    pa.add_argument("--max-time", type=float, default=None, metavar="SECONDS",
                    help="wall-clock ceiling; hand back when reached "
                         "(also BRUKAL_MAX_TIME)")
    pa.add_argument("--no-resume", action="store_true",
                    help="ignore any saved checkpoint and start fresh "
                         "(default resumes loop-progress if a checkpoint exists)")
    pa.add_argument("--model", default=None)
    pa.add_argument("--provider", default=None,
                    help="anthropic (default) | ollama | openai | openrouter | ...")
    pa.add_argument("--base-url", default=None)
    pa.set_defaults(func=_cmd_auto)

    pk = sub.add_parser("apk", help="static-analyse an Android APK (mobile app testing)")
    pk.add_argument("apk", help="path to the .apk (a host file is copied into the cage)")
    pk.add_argument("--container", default="brukal-kali")
    pk.add_argument("--fake", action="store_true", help="dry-run the wiring (no cage)")
    pk.set_defaults(func=_cmd_apk)

    prep = sub.add_parser("report",
                          help="build a pentest report (findings + evidence) from a "
                               "target's vault")
    prep.add_argument("target", nargs="?", help="target IP (locates its findings vault)")
    prep.add_argument("--vault", default="runs/vault")
    prep.add_argument("--show", action="store_true", help="also print the report")
    prep.set_defaults(func=_cmd_report)

    pev = sub.add_parser("eval",
                         help="capability eval: governed vs ungated (steps-to-foothold)")
    pev.set_defaults(func=_cmd_eval)

    pb = sub.add_parser("bench",
                        help="honest benchmark: real loop, solve rate + steps-to-foothold "
                             "+ cost + 0 scope violations")
    pb.add_argument("--live", action="store_true",
                    help="run against authorised targets (needs a cage + model); "
                         "default is the scripted-box self-test")
    pb.add_argument("--target", action="append", default=[],
                    help="an authorised target (repeatable); required with --live")
    pb.add_argument("--scope", default="scope.json")
    pb.add_argument("--fake", action="store_true", help="with --live: FakeKali cage (no Docker)")
    pb.add_argument("--yes-authorised", action="store_true",
                    help="confirm authorisation for the targets (required for --live)")
    pb.add_argument("--model", default=None)
    pb.add_argument("--provider", default=None)
    pb.add_argument("--base-url", default=None)
    pb.add_argument("--container", default="brukal-kali")
    pb.add_argument("--max-steps", type=int, default=20)
    pb.add_argument("--max-cost", type=float, default=None)
    pb.add_argument("--json", help="also write the metrics as JSON to this path")
    pb.set_defaults(func=_cmd_bench)

    pw = sub.add_parser("web", help="send one governed web request (crafted method/headers/body)")
    pw.add_argument("url", help="target URL (host must be in scope or authorised via --host)")
    pw.add_argument("--method", default="GET")
    pw.add_argument("--header", action="append", help="'Key: Value' (repeatable)")
    pw.add_argument("--body", default="")
    pw.add_argument("--host", help="authorise this vhost at scope time (e.g. nexus.htb)")
    pw.add_argument("--local", action="store_true",
                    help="send from this host instead of the cage (host-reachable targets only)")
    pw.add_argument("--chrome", action="store_true",
                    help="render the page with real headless Chromium (JS executed) in the cage")
    pw.add_argument("--screenshot", action="store_true", help="with --chrome: capture a screenshot")
    pw.add_argument("--container", default="brukal-kali")
    pw.add_argument("--scope", default="scope.json")
    pw.add_argument("--audit", default="runs/audit.jsonl")
    pw.set_defaults(func=_cmd_web)

    pl = sub.add_parser("lessons", help="view / add Brukal's cross-session learned lessons")
    pl.add_argument("search", nargs="?", help="filter lessons by keyword/tag")
    pl.add_argument("--vault", default="runs/vault", help="vault root holding lessons.jsonl")
    pl.add_argument("--add", help="manually record a lesson")
    pl.add_argument("--tags", help="comma-separated tags for --add")
    pl.add_argument("--kind", default="tactic", choices=["pitfall", "tactic", "win"])
    pl.set_defaults(func=_cmd_lessons)

    psh = sub.add_parser("shell", help="open a governed interactive shell in the cage")
    psh.add_argument("target", help="in-scope host to work on")
    psh.add_argument("--fake", action="store_true", help="fake session (no Docker)")
    psh.add_argument("--yes-authorised", action="store_true",
                     help="confirm you are authorised (skips the live prompt)")
    psh.add_argument("--scope", default="scope.json")
    psh.add_argument("--audit", default="runs/audit.jsonl")
    psh.add_argument("--container", default="brukal-kali")
    psh.set_defaults(func=_cmd_shell)

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
        # Bare `brukal` -> the guided step-by-step wizard (target -> brain -> tool
        # policy -> auto/manual -> hunt). Non-interactive (piped) falls back to help.
        import sys as _sys
        if _sys.stdin.isatty():
            from brukal.assist import run_wizard
            return run_wizard()
        print(_quickstart())
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
