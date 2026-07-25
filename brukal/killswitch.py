"""
killswitch.py — a hard stop for a running engagement.

Long autonomous runs need a way to STOP now: a wrong turn, a noisy scan, a change of
mind, or an external signal. `KillSwitch` is a thread-safe, one-way flag. Trip it —
from a signal handler (SIGINT/SIGTERM), another thread, or the operator — and every
governed loop checks it at each safe boundary, finishes as `aborted`, and closes its
live sessions (which kills the cage-side `docker exec` shells).

It deliberately does NOT interrupt a single in-flight gated action mid-syscall: that
could leave a half-written audit entry or a half-run command with no record. It stops
at the next boundary (between actions / between loop turns) and tears sessions down —
bounded, honest, and leaving the hash-chained ledger intact. Standard library only.
"""
from __future__ import annotations

import threading


class KillSwitch:
    """A one-way, thread-safe stop flag with a reason. `tripped` is checked by the
    loop; `trip()` is safe to call from a signal handler or any thread."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._reason = ""

    def trip(self, reason: str = "operator stop") -> None:
        # First reason wins (a later trip doesn't overwrite why we actually stopped).
        if not self._reason:
            self._reason = reason or "stop"
        self._event.set()

    @property
    def tripped(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str:
        return self._reason or "stop"

    def wait(self, timeout: float | None = None) -> bool:
        """Block until tripped (or the timeout elapses). Returns whether it's tripped."""
        return self._event.wait(timeout)
