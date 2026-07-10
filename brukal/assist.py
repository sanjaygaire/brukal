"""
assist.py — human-assisted box solving (v1): a governed pentest copilot.

The operator drives an interactive loop. The strategist proposes the next move;
the operator can RUN a suggested command (through the gate/cage), record a MANUAL
step they did themselves, add a note, or ask a question. Brukal reasons + records;
the human does the ungoverned exploitation on their own authority. Everything
Brukal runs still goes through Executor.run(), and everything is logged.

`AssistSession` holds the testable logic; `run_solve` assembles it and runs the
console loop.
"""
from __future__ import annotations

import sys
from pathlib import Path

from .audit import AuditLog
from .executor import Executor
from .gate import Gate
from .kali import DockerKali, FakeKali
from .scope import load_scope
from .trust import TrustModel


class AssistSession:
    def __init__(self, target, executor, strategist, skills=None):
        self.target = target
        self.executor = executor
        self.strategist = strategist
        self.skills = skills
        self.notes: list[str] = []     # observations: command results, manual reports, notes
        self.last = None               # last Suggestion

    def _state(self) -> str:
        return "\n".join(self.notes[-25:]) if self.notes else "(no findings yet)"

    def advise(self, question: str = ""):
        ref = self.skills.context_for(question or self.target) if self.skills else ""
        self.last = self.strategist.advise(self.target, self._state(), question, ref)
        return self.last

    def run(self, command: str, target: str | None = None):
        """Run a command through the gate/cage and record the outcome."""
        decision, result = self.executor.run(command, target or self.target,
                                             agent="strategist")
        if result is not None:
            out = (result.stdout or "").strip()[:800] or "(no output)"
            self.notes.append(f"[ran] {command}\n{decision.verdict}: {out}")
        else:
            self.notes.append(f"[ran] {command}\nNOT RUN — {decision.verdict} "
                              f"({decision.layer}: {decision.reason})")
        return decision, result

    def note(self, text: str):
        self.notes.append(f"[note] {text}")

    def manual(self, text: str):
        """Record an out-of-cage action the operator performed themselves."""
        self.notes.append(f"[manual] {text}")


_HELP = """  commands:
    next / <enter>     ask the strategist for the next step
    run                run the strategist's suggested command (through the gate)
    run <command>      run a specific command through the gate/cage
    note <text>        record an observation / paste tool output
    manual <text>      record a manual step you did yourself (shell, exploit, ...)
    ask <question>     ask the strategist something
    skills <topic>     search the offensive playbooks
    verify             check the audit chain
    help / quit"""


def _print_suggestion(s):
    print(f"\n  [strategist] {s.rationale}")
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
    executor = Executor(Gate(scope, trust=TrustModel()),
                        FakeKali() if fake else DockerKali(container=container),
                        audit, approver=interactive_approver)
    try:
        strategist = StrategistAgent(LLMClient(model=model, provider=provider,
                                               base_url=base_url))
    except Exception as e:
        print(f"Could not initialise the model client: {e}")
        print("Set a key, or use --provider ollama --model qwen2.5 (free, local).")
        return 2

    session = AssistSession(target, executor, strategist, skills=SkillLibrary())

    print(f"\n  brukal solve — target {target}   "
          f"cage={'fake' if fake else 'docker:' + container}")
    print(_HELP)
    session.advise()
    _print_suggestion(session.last)

    while True:
        try:
            raw = input("  brukal> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
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
                d, r = session.run(session.last.command)
                print(f"  -> {d.verdict}"
                      + (f"\n{ (r.stdout or '').rstrip()}" if r else f" ({d.layer})"))
            else:
                print("  (no suggested command; use `run <command>`)")
        elif raw.startswith("run "):
            d, r = session.run(raw[4:].strip())
            print(f"  -> {d.verdict}"
                  + (f"\n{(r.stdout or '').rstrip()}" if r else f" ({d.layer}: {d.reason})"))
        elif raw.startswith("note "):
            session.note(raw[5:].strip()); print("  noted.")
        elif raw.startswith("manual "):
            session.manual(raw[7:].strip()); print("  recorded.")
        elif raw.startswith("ask "):
            _print_suggestion(session.advise(raw[4:].strip()))
        elif raw.startswith("skills "):
            for s in (session.skills.retrieve(raw[7:].strip(), limit=4) if session.skills else []):
                print(f"    [{s.category}] {s.name}")
        else:
            print("  unknown command — type `help`.")

    print(f"\n  session recorded to {audit_path}  (chain intact: {audit.verify()})\n")
    return 0
