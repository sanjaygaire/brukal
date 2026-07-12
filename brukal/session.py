"""
session.py — governed interactive sessions (the one door, for a live shell).

Brukal's copilot posture is "you do the exploitation." Historically that meant
the operator worked *outside* Brukal — ungoverned and unlogged. A GovernedSession
brings that work back inside the one door: it wraps a stateful cage shell so that
every line you type is ruled on by the gate (`check_session`) and written to the
hash-chained audit log BEFORE it reaches the shell, and the shell's output is
logged too. A denied line never reaches the backend.

This preserves every invariant:
  1. No LLM in the gate — `check_session` is pure code.
  2. Fail-closed — empty/ambiguous input denies; a destructive command ESCALATEs
     and runs only on explicit human sign-off (default approver refuses).
  3. Never trust a self-report — the gate re-reads the line for out-of-scope IPs.
  4. One execution path — agents/operators get the GovernedSession, never the raw
     backend; the backend's send() is only ever called for an ALLOWed line.
  5. Immutable scope + append-only audit — the session is bound to an in-scope
     target and cannot pivot out of scope; every line + result is on the ledger.

A session is a capability *added* to the copilot, not a loosening of it: work
that used to happen off-ledger now happens on it.
"""
from __future__ import annotations

from typing import Callable, Optional

from .audit import AuditLog
from .gate import Decision, Gate
from .kali import DockerSession, ExecResult, FakeSession
from .scope import load_scope


class GovernedSession:
    """A stateful shell whose every input is gated + logged. Mirrors Executor's
    discipline for interactive I/O."""

    def __init__(self, gate: Gate, backend, audit: AuditLog, target: str,
                 approver: Optional[Callable[[Decision], bool]] = None):
        self._gate = gate
        self._backend = backend           # FakeSession | DockerSession
        self._audit = audit
        self.target = target
        self._approver = approver or (lambda _d: False)   # fail-closed default

    def send(self, line: str, agent: str = "operator"):
        """Judge, log, and (only if permitted) run one line. Returns
        (Decision, ExecResult | None) — mirrors Executor.run()."""
        decision = self._gate.check_session(line, self.target, agent)
        self._audit.append("session_decision", decision)

        if decision.verdict == "ESCALATE":
            approved = bool(self._approver(decision))
            self._audit.append("approval", {
                "action": decision.action, "target": decision.target,
                "agent": decision.agent, "layer": decision.layer,
                "approved": approved,
            })
            if not approved:
                return decision, None
        elif decision.verdict != "ALLOW":
            return decision, None

        result: ExecResult = self._backend.send(line)
        self._audit.append("session_execution", result)
        return decision, result

    @property
    def alive(self) -> bool:
        return getattr(self._backend, "alive", False)

    def close(self):
        self._backend.close()


def open_session(scope_path: str, target: str, *, fake: bool = False,
                 container: str = "brukal-kali", audit_path: str = "runs/audit.jsonl",
                 trust=None, approver=None) -> Optional[GovernedSession]:
    """Validate the target against scope, then open a governed session on it.
    Returns None (and prints why) if the target is out of scope."""
    scope = load_scope(scope_path)
    if not scope.contains_ip(target):
        print(f"Refused: {target} is not in {scope_path}.  (brukal target {target})")
        return None
    backend = (FakeSession(target) if fake
               else DockerSession(container=container, target=target))
    gate = Gate(scope, trust=trust)
    return GovernedSession(gate, backend, AuditLog(audit_path), target,
                           approver=approver)


_HELP = ("  A governed shell — every line is scope-checked and logged before it "
         "runs.\n  Type shell commands normally; `exit`/`quit` to close.")


def run_shell(target, *, fake=False, yes_authorised=False, scope_path="scope.json",
              audit_path="runs/audit.jsonl", container="brukal-kali") -> int:
    """Interactive REPL over a GovernedSession (used by `brukal shell`)."""
    if not fake and not yes_authorised:
        # Confirm authorisation for a live shell, like the rest of the live paths.
        try:
            ok = input(f"  LIVE shell on {target}. Confirm you are authorised? [y/N] ")
        except (EOFError, KeyboardInterrupt):
            ok = ""
        if ok.strip().lower() not in ("y", "yes"):
            print("Refused: a live shell needs your authorisation.")
            return 2

    def _approve(decision) -> bool:
        try:
            ans = input(f"  ⚠ {decision.reason}\n    run this line anyway? [y/N] ")
        except (EOFError, KeyboardInterrupt):
            ans = ""
        return ans.strip().lower() in ("y", "yes")

    sess = open_session(scope_path, target, fake=fake, container=container,
                        audit_path=audit_path, approver=_approve)
    if sess is None:
        return 2

    _V = {"ALLOW": "\033[32m", "ESCALATE": "\033[33m", "DENY": "\033[31m"}
    print(f"\n  brukal shell — {target}   cage={'fake' if fake else container}")
    print(_HELP)
    try:
        while sess.alive:
            try:
                line = input(f"  {target}$ ")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if line.strip() in ("exit", "quit"):
                break
            if not line.strip():
                continue
            decision, result = sess.send(line)
            colour = _V.get(decision.verdict, "")
            print(f"  {colour}[{decision.verdict}]\033[0m {decision.layer}")
            if result is None:
                print(f"    {decision.reason}")
            elif (result.stdout or "").strip():
                print(result.stdout.rstrip())
    finally:
        sess.close()
    print(f"\n  session closed  ·  audit chain intact: {AuditLog(audit_path).verify()}\n")
    return 0
