"""
verify.py — did we actually SOLVE it? Deterministic success verification.

Brukal must never report "solved" on the model's word. This module defines what
"solved" means (a captured flag, or verified foothold evidence) and confirms it
against the REAL output of a gate-executed command — never against the model's
prose. There is NO language model here: a flag is a flag because it matched a
regex in output that came through Executor.run -> gate -> cage. That is the same
"grounded, not claimed" discipline the loop already uses for progress, applied to
the finish line.

A verified success is the ONLY thing that:
  * ends the loop as `solved` (distinct from a hand-off), and
  * promotes a candidate lesson to the trusted store (the brain grows only from
    confirmed wins — see lessons.py).

Standard library only.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

# HTB-style machine flag: a 32-char hex string ALONE on a line (how user.txt /
# root.txt read). Requiring it to own the line avoids false positives on an MD5
# hash embedded in a tool's output table. Override with BRUKAL_FLAG_PATTERN.
_DEFAULT_FLAG = r"(?m)^\s*[A-Fa-f0-9]{32}\s*$"

# Strong, specific evidence of code execution on the target (id / root prompt).
_DEFAULT_FOOTHOLD = (
    r"uid=\d+\([^)]+\)\s+gid=\d+",        # `id` output
    r"root@[\w.-]+:[^\n]*#",              # a root shell prompt
)


@dataclass(frozen=True)
class SuccessCondition:
    flag_pattern: str = _DEFAULT_FLAG
    foothold_patterns: tuple = _DEFAULT_FOOTHOLD

    @classmethod
    def from_env(cls) -> "SuccessCondition":
        """BRUKAL_FLAG_PATTERN overrides the flag regex for a specific engagement
        (e.g. `HTB\\{[^}]+\\}` or a known token). Foothold patterns keep the default."""
        pat = os.environ.get("BRUKAL_FLAG_PATTERN", "").strip()
        return cls(flag_pattern=pat) if pat else cls()


@dataclass
class Verified:
    kind: str            # "flag" | "foothold"
    evidence: str        # the exact matched text (the flag / the id line)
    command: str         # the gated command whose REAL output produced it
    source: str = "shell"   # "shell" | "web"
    provenance: dict = field(default_factory=dict)


def _result_text(result) -> str:
    return getattr(result, "stdout", None) or getattr(result, "body", "") or ""


class Verifier:
    """Checks a real command outcome for a success condition. Returns a Verified on a
    confirmed flag/foothold, else None. Deterministic; never sees the model."""

    def __init__(self, condition: SuccessCondition | None = None):
        self.condition = condition or SuccessCondition.from_env()
        self._flag_re = re.compile(self.condition.flag_pattern)
        self._foothold_res = [re.compile(p) for p in self.condition.foothold_patterns]

    def check(self, command: str, result, source: str = "shell") -> Verified | None:
        """A success is confirmed ONLY from real output (result is not None). Prose
        never reaches here — the loop calls this with the executed result."""
        if result is None:
            return None
        text = _result_text(result)
        if not text:
            return None
        m = self._flag_re.search(text)
        if m:
            return Verified("flag", m.group(0).strip(), command, source)
        for rx in self._foothold_res:
            fm = rx.search(text)
            if fm:
                return Verified("foothold", fm.group(0).strip(), command, source)
        return None
