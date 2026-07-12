"""
assist.py — human-assisted box solving (v1): a governed pentest copilot.

The operator drives a menu-driven loop. The strategist proposes the next move;
the operator picks an option — run the suggested command (through the gate/cage),
run a different one, record a MANUAL step they did themselves, add a note, or ask
a question. Brukal reasons + records; the human does the ungoverned exploitation
on their own authority. Everything Brukal runs still goes through Executor.run().

A spinner shows while the strategist is thinking or a command is running (long
scans no longer look frozen). Escalations pause the spinner, prompt, and resume.

`AssistSession` holds the testable logic; `run_solve` assembles it and drives the
rich menu UI (falling back to a plain prompt if `rich` is unavailable).
"""
from __future__ import annotations

import re
from pathlib import Path

from .audit import AuditLog
from .executor import Executor
from .gate import Gate
from .kali import DockerKali, FakeKali
from .scope import load_scope
from .trust import TrustModel

_VERDICT_COLOUR = {"ALLOW": "green", "ESCALATE": "yellow", "DENY": "red"}
_PHASE_COLOUR = {"recon": "cyan", "enumeration": "cyan", "exploitation": "magenta",
                 "privilege-escalation": "red", "looting": "yellow"}

# Patterns that mark a line as an important RESULT worth surfacing to the operator.
_HIGHLIGHTS = [
    (re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+open\s+(\S+)(.*)$", re.I), "open port"),
    (re.compile(r"\b(200|301|302|401|403)\b.*(/\S*)", re.I), "web path"),
    (re.compile(r"(user(?:name)?|login|account)\s*[:=]\s*(\S+)", re.I), "credential"),
    (re.compile(r"(pass(?:word)?)\s*[:=]\s*(\S+)", re.I), "credential"),
    (re.compile(r"\b([a-f0-9]{32}|[a-f0-9]{40}|\$[0-9a-z]{1,3}\$\S+)\b", re.I), "hash"),
    (re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.I), "CVE"),
    (re.compile(r"(anonymous|guest)\s+(login|access|allowed)", re.I), "anon access"),
    (re.compile(r"(disallow|robots|/admin|/backup|\.git|\.env|phpmyadmin)", re.I), "interesting"),
]


def highlight_findings(output: str, limit: int = 12) -> list[tuple[str, str]]:
    """Pull the lines from raw tool output that a pentester actually cares about.
    Returns (tag, line) pairs — open ports, web paths, creds, hashes, CVEs, ..."""
    hits: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line or len(line) > 200:
            continue
        for rx, tag in _HIGHLIGHTS:
            if rx.search(line) and line not in seen:
                hits.append((tag, line))
                seen.add(line)
                break
        if len(hits) >= limit:
            break
    return hits


class AssistSession:
    def __init__(self, target, executor, strategist, skills=None):
        self.target = target
        self.executor = executor
        self.strategist = strategist
        self.skills = skills
        self.notes: list[str] = []     # observations: command results, manual reports, notes
        self.highlights: list[tuple[str, str]] = []   # accumulated key results
        self.objectives: list[str] = []               # what the box is asking (HTB tasks)
        self.last = None               # last Suggestion

    def add_objective(self, text: str):
        if text.strip():
            self.objectives.append(text.strip())

    def _objectives_text(self) -> str:
        return "\n".join(f"- {o}" for o in self.objectives)

    def _state(self) -> str:
        return "\n".join(self.notes[-25:]) if self.notes else "(no findings yet)"

    def advise(self, question: str = ""):
        focus = question or " ".join(self.objectives) or self.target
        ref = self.skills.context_for(focus) if self.skills else ""
        self.last = self.strategist.advise(
            self.target, self._state(), question, ref, self._objectives_text())
        return self.last

    def run(self, command: str, target: str | None = None):
        """Run a command through the gate/cage, record it, and surface the key
        results. Returns (decision, result, new_highlights)."""
        decision, result = self.executor.run(command, target or self.target,
                                             agent="strategist")
        new_hl: list[tuple[str, str]] = []
        if result is not None:
            raw = (result.stdout or "").strip()
            new_hl = highlight_findings(raw)
            self.highlights.extend(h for h in new_hl if h not in self.highlights)
            self.notes.append(f"[ran] {command}\n{decision.verdict}: {raw[:800] or '(no output)'}")
        else:
            self.notes.append(f"[ran] {command}\nNOT RUN — {decision.verdict} "
                              f"({decision.layer}: {decision.reason})")
        return decision, result, new_hl

    def note(self, text: str):
        self.notes.append(f"[note] {text}")

    def manual(self, text: str):
        """Record an out-of-cage action the operator performed themselves."""
        self.notes.append(f"[manual] {text}")


def _rich_approver(con, holder):
    """Escalation sign-off that pauses the live spinner, prompts, then resumes."""
    from rich.panel import Panel
    from rich.text import Text

    def approve(decision) -> bool:
        st = holder.get("status")
        if st is not None:
            st.stop()
        con.print(Panel(Text.assemble(
            ("ESCALATION — human sign-off required\n", "bold yellow"),
            (f"action : {decision.action}\n", "white"),
            (f"target : {decision.target}   agent: {decision.agent}\n", "white"),
            (f"risk   : {decision.risk_band}  ({decision.reason})", "grey62")),
            border_style="yellow"))
        try:
            ans = (con.input("  approve this action? [y/N] ").strip().lower()
                   if con.file.isatty() else "")
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if st is not None:
            st.start()
        return ans in ("y", "yes")

    return approve


def _show_highlights(con, Panel, Text, hits, title):
    if not hits:
        return
    body = Text()
    for i, (tag, line) in enumerate(hits):
        if i:
            body.append("\n")
        body.append(f"{tag:>11} ", style="bold yellow")
        body.append(line, style="white")
    con.print(Panel(body, title=f"[bold yellow]★ {title}[/]", border_style="yellow"))


def _menu_loop(session, audit, target, cage, con, holder):
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.text import Text

    con.print(Panel(Text.assemble(("BRUKAL — pentest companion   ", "bold cyan"),
                                   (f"target={target}   cage={cage}", "white")),
                    border_style="cyan"))

    # Ask up front what the box wants (HTB task questions) — this steers everything.
    con.print("[grey62]What is the box asking you to find? (HTB task questions, one per "
              "line — e.g. \"How many open TCP ports?\"). Enter blank to skip / finish.[/]")
    while True:
        obj = Prompt.ask("  objective", default="")
        if not obj:
            break
        session.add_objective(obj)

    def run_and_show(command):
        with con.status(f"[cyan]running:[/] {command}", spinner="dots") as st:
            holder["status"] = st
            d, r, new_hl = session.run(command)
            holder["status"] = None
        colour = _VERDICT_COLOUR.get(d.verdict, "white")
        con.print(Text.assemble(("  → ", ""), (d.verdict, f"bold {colour}"),
                                 (f"   {d.layer}", "grey50")))
        if r is not None and (r.stdout or "").strip():
            con.print(Panel(r.stdout.strip()[:1800], title="raw output", border_style="grey23"))
            _show_highlights(con, Panel, Text, new_hl, "key results")
        elif r is None:
            con.print(f"  [grey50]{d.reason}[/]")
        session.last = None   # regenerate advice from the new findings

    while True:
        if session.last is None:
            with con.status("[cyan]companion thinking…", spinner="dots"):
                session.advise()
        s = session.last

        # objectives tracker
        if session.objectives:
            ot = Text()
            for o in session.objectives:
                ot.append("? ", style="bold yellow"); ot.append(o + "\n")
            con.print(Panel(ot, title="objectives", border_style="yellow"))

        # the companion's reasoning: phase + goal + why
        head = Text()
        if s.phase:
            pc = _PHASE_COLOUR.get(s.phase.lower(), "cyan")
            head.append(f"[{s.phase.upper()}] ", style=f"bold {pc}")
        if s.goal:
            head.append(s.goal, style="bold white")
        if head.plain:
            head.append("\n\n")
        head.append(s.rationale or "—", style="grey85")
        if s.command:
            head.append(f"\n\n▶ suggested command\n  {s.command}", style="green")
        if s.manual:
            head.append(f"\n\n✋ you do this (manual)\n  {s.manual}", style="yellow")
        con.print(Panel(head, title="companion", border_style="cyan"))

        if session.highlights:
            _show_highlights(con, Panel, Text, session.highlights[-8:], "what we know so far")

        options = [
            ("1", f"Run suggested:  {s.command}" if s.command else "Run a command"),
            ("2", "Run a different command"),
            ("3", "Ask the companion something / re-plan"),
            ("4", "Add a note / paste tool output"),
            ("5", "Record a manual step you did"),
            ("6", "Add an objective the box is asking"),
            ("7", "Search the skill playbooks"),
            ("8", "Verify the audit chain"),
            ("9", "Quit"),
        ]
        grid = Table.grid(padding=(0, 2))
        for key, label in options:
            grid.add_row(Text(f"[{key}]", style="bold cyan"), Text(label))
        con.print(grid)

        choice = Prompt.ask("  choose", choices=[k for k, _ in options], default="1")
        if choice == "1":
            run_and_show(s.command or Prompt.ask("  command"))
        elif choice == "2":
            run_and_show(Prompt.ask("  command"))
        elif choice == "3":
            q = Prompt.ask("  ask / focus (e.g. 'how do I answer objective 2?')", default="")
            with con.status("[cyan]companion thinking…", spinner="dots"):
                session.advise(q)
        elif choice == "4":
            session.note(Prompt.ask("  note / paste output")); session.last = None
        elif choice == "5":
            session.manual(Prompt.ask("  what you did")); session.last = None
        elif choice == "6":
            session.add_objective(Prompt.ask("  objective")); session.last = None
        elif choice == "7":
            for sk in (session.skills.retrieve(Prompt.ask("  topic"), 4)
                       if session.skills else []):
                con.print(f"    [magenta]\\[{sk.category}][/] {sk.name}")
        elif choice == "8":
            con.print(f"  audit chain intact: [green]{audit.verify()}[/]")
        elif choice == "9":
            break


_HELP = """  commands: next/<enter>  run  run <cmd>  note <text>  manual <text>
            ask <question>  skills <topic>  verify  help  quit"""


def _plain_loop(session, audit, target, cage):
    print(f"\n  brukal solve — target {target}   cage={cage}")
    print(_HELP)
    _print_suggestion(session.advise())
    while True:
        try:
            raw = input("  brukal> ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if not raw or raw in ("next", "n"):
            _print_suggestion(session.advise())
        elif raw in ("quit", "exit", "q"):
            break
        elif raw in ("help", "?"):
            print(_HELP)
        elif raw == "verify":
            print("  audit chain intact:", audit.verify())
        elif raw == "run":
            if session.last and session.last.command:
                d, r, _ = session.run(session.last.command)
                print(f"  -> {d.verdict}" + (f"\n{(r.stdout or '').rstrip()}" if r else f" ({d.layer})"))
            else:
                print("  (no suggested command; use `run <command>`)")
        elif raw.startswith("run "):
            d, r, _ = session.run(raw[4:].strip())
            print(f"  -> {d.verdict}" + (f"\n{(r.stdout or '').rstrip()}" if r else f" ({d.layer}: {d.reason})"))
        elif raw.startswith("note "):
            session.note(raw[5:].strip()); print("  noted.")
        elif raw.startswith("manual "):
            session.manual(raw[7:].strip()); print("  recorded.")
        elif raw.startswith("ask "):
            _print_suggestion(session.advise(raw[4:].strip()))
        elif raw.startswith("skills "):
            for s in (session.skills.retrieve(raw[7:].strip(), 4) if session.skills else []):
                print(f"    [{s.category}] {s.name}")
        else:
            print("  unknown command — type `help`.")


def _print_suggestion(s):
    tag = f"[{s.phase.upper()}] " if s.phase else ""
    if s.goal:
        print(f"\n  {tag}GOAL: {s.goal}")
    print(f"  [companion] {s.rationale}")
    if s.command:
        print(f"  suggested (gated):  {s.command}")
    if s.manual:
        print(f"  manual step (you):  {s.manual}")
    print()


def run_solve(target, *, fake=False, yes_authorised=False, scope_path="scope.json",
              audit_path="runs/audit.jsonl", container="brukal-kali",
              model=None, provider=None, base_url=None) -> int:
    try:
        from .agents.strategist import StrategistAgent
        from .engagement import interactive_approver
        from .llm import LLMClient
        from .skills import SkillLibrary
    except ImportError as e:
        print(f"Agent dependencies missing ({e}). Install: pip install \"brukal[agents]\"")
        return 2

    scope = load_scope(scope_path)
    if not scope.contains_ip(target):
        print(f"Refused: target {target} is not inside {scope_path}.  (brukal target {target})")
        return 2
    if not fake and not yes_authorised:
        print("Refused: a live run needs --yes-authorised (you confirm you are authorised).")
        return 2

    audit = AuditLog(audit_path)

    # A rich console (menu UI + spinner-aware approver), or plain fallback.
    console = None
    holder: dict = {"status": None}
    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        console = None
    approver = _rich_approver(console, holder) if console is not None else interactive_approver

    executor = Executor(Gate(scope, trust=TrustModel()),
                        FakeKali() if fake else DockerKali(container=container),
                        audit, approver=approver)
    try:
        strategist = StrategistAgent(LLMClient(model=model, provider=provider,
                                               base_url=base_url))
    except Exception as e:
        print(f"Could not initialise the model client: {e}")
        print("Set a key, or use --provider ollama --model qwen2.5 (free, local).")
        return 2

    session = AssistSession(target, executor, strategist, skills=SkillLibrary())
    cage = "fake" if fake else "docker:" + container

    if console is not None:
        _menu_loop(session, audit, target, cage, console, holder)
    else:
        _plain_loop(session, audit, target, cage)

    print(f"\n  session recorded to {audit_path}  (chain intact: {audit.verify()})\n")
    return 0
