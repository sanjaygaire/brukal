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

import os
import select
import shlex
import subprocess
import time
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

    def __init__(self, container: str = "brukal-kali", timeout: int = 180,
                 user: str = "brukalop"):
        self.container = container
        self.timeout = timeout
        self.user = user   # run approved tools unprivileged; "" for the default user

    def run(self, command: str) -> ExecResult:
        inner = shlex.split(command)
        argv = ["docker", "exec"]
        if self.user:
            argv += ["-u", self.user]
        # Run the tool under the container's OWN `timeout` so it is killed INSIDE the
        # cage at self.timeout. docker exec's client-side timeout does not kill the
        # container-side process, so a long scan would otherwise keep running orphaned
        # (a 110k-entry ffuf ran 10+ min past the limit and choked the cage). `-k 5`
        # escalates to SIGKILL 5s after SIGTERM if the tool ignores it.
        argv += [self.container, "timeout", "-k", "5", str(self.timeout), *inner]
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=self.timeout + 15
            )
            if proc.returncode in (124, 137):        # coreutils timeout / SIGKILL
                return ExecResult(command, 124, proc.stdout,
                                  f"timed out — killed at {self.timeout}s (narrow the command)")
            return ExecResult(command, proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired:
            self._reap(inner)                        # host waited out too — reap any orphan
            return ExecResult(command, 124, "", "timed out")
        except FileNotFoundError:
            return ExecResult(command, 127, "", "docker not found")

    def _reap(self, inner) -> None:
        """Best-effort: kill any orphaned instance of the tool inside the container so
        a stuck scan can't linger and consume the cage."""
        tool = os.path.basename(inner[0]) if inner else ""
        if not tool:
            return
        try:
            subprocess.run(["docker", "exec", self.container, "pkill", "-9", "-f", tool],
                           capture_output=True, timeout=10)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Interactive sessions — a STATEFUL shell in the cage (cwd/env/jobs persist),
# unlike the one-shot run() above. Each line is gated one layer up (in
# GovernedSession); a session backend never sees a denied line.
# --------------------------------------------------------------------------- #


class FakeSession:
    """Records lines instead of executing; keeps a fake cwd so tests can see
    that state persists. Mirrors DockerSession's interface."""

    def __init__(self, target: str = "target"):
        self.target = target
        self.sent: list[str] = []
        self.alive = True
        self._cwd = "/root"

    def send(self, line: str) -> ExecResult:
        self.sent.append(line)
        s = line.strip()
        if s.startswith("cd "):                       # state survives across sends
            self._cwd = s[3:].strip() or "/root"
            return ExecResult(line, 0, "", "")
        if s == "pwd":
            return ExecResult(line, 0, self._cwd, "")
        return ExecResult(line, 0, f"[fake-session {self._cwd}] {line}", "")

    def close(self):
        self.alive = False


class DockerSession:
    """A persistent, stateful shell inside the cage via `docker exec -i bash`.

    State (cwd, exported vars, background jobs) survives across sends, so you can
    `cd`, set env, catch a reverse shell, and keep working — impossible with the
    one-shot DockerKali.run(). We frame each command with a sentinel so we can
    read exactly its output and exit code, and bound the read so an interactive
    or long-running command can't hang the session forever.
    """
    _SENTINEL = "__BRUKAL_DONE__"

    def __init__(self, container: str = "brukal-kali", user: str = "brukalop",
                 target: str = "", read_timeout: int = 120):
        self.container = container
        self.target = target
        self.read_timeout = read_timeout
        argv = ["docker", "exec", "-i"]
        if user:
            argv += ["-u", user]
        argv += [container, "bash"]
        try:
            self._proc = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1)
        except FileNotFoundError:
            self._proc = None
        self.alive = self._proc is not None and self._proc.poll() is None

    def send(self, line: str) -> ExecResult:
        if not self._proc or self._proc.poll() is not None:
            self.alive = False
            return ExecResult(line, 127, "", "session is not running")
        try:
            self._proc.stdin.write(line + "\n")
            self._proc.stdin.write(f'echo "{self._SENTINEL} $?"\n')
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            self.alive = False
            return ExecResult(line, 127, "", f"session write failed: {e}")

        out: list[str] = []
        rc = 0
        deadline = time.time() + self.read_timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                return ExecResult(line, 124, "".join(out).rstrip("\n"),
                                  "read timed out — command may be interactive or "
                                  "long-running (still active in the session)")
            r, _, _ = select.select([self._proc.stdout], [], [], min(remaining, 1.0))
            if not r:
                continue
            chunk = self._proc.stdout.readline()
            if chunk == "":                            # backend EOF
                self.alive = False
                break
            if chunk.startswith(self._SENTINEL):
                try:
                    rc = int(chunk.strip().split()[-1])
                except (ValueError, IndexError):
                    rc = 0
                break
            out.append(chunk)
        return ExecResult(line, rc, "".join(out).rstrip("\n"), "")

    def close(self):
        try:
            if self._proc and self._proc.poll() is None:
                self._proc.stdin.write("exit\n")
                self._proc.stdin.flush()
                self._proc.wait(timeout=5)
        except (BrokenPipeError, OSError, subprocess.TimeoutExpired):
            if self._proc:
                self._proc.kill()
        self.alive = False
