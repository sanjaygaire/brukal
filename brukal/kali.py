"""
kali.py — the execution backends (the cage).

Two backends share one interface so the rest of the system never changes:

  * DockerKali — runs the command INSIDE a running, network-isolated Kali
                 container via `docker exec`. This is the real cage.
  * FakeKali   — does not run anything; it records what it was ASKED to run.
                 This lets you prove the scope-interception claim (and run the
                 whole test suite) without Docker installed, because that claim
                 is about what reaches execution, not about the tool output.

The golden rule lives one layer up in executor.py: a backend's run() is only
ever called for an ALLOWed action. A backend never sees a denied command.
"""
from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass, field


@dataclass
class ExecResult:
    command: str
    returncode: int
    stdout: str
    stderr: str


class FakeKali:
    """Records calls instead of executing. Used by tests and the demo."""

    def __init__(self):
        self.executed: list[str] = []

    def run(self, command: str) -> ExecResult:
        self.executed.append(command)
        return ExecResult(command, 0, f"[fake-exec] {command}", "")


class DockerKali:
    """Executes inside a running Kali container via `docker exec`.

    `container` is the container name from docker-compose (default: brukal-kali).
    We pass the command as an argument vector (never through a shell) so there
    is no second place for shell injection to live.
    """

    def __init__(self, container: str = "brukal-kali", timeout: int = 300):
        self.container = container
        self.timeout = timeout

    def run(self, command: str) -> ExecResult:
        argv = ["docker", "exec", self.container, *shlex.split(command)]
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=self.timeout
            )
            return ExecResult(command, proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired:
            return ExecResult(command, 124, "", "timed out")
        except FileNotFoundError:
            return ExecResult(command, 127, "", "docker not found")
