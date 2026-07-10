"""
agents/strategist.py — the advisory agent for human-assisted solving (v1).

Unlike recon/exploit/verify (which each propose one gated command), the strategist
REASONS about the whole engagement and tells the human operator the single next
best move. Its output is advice, not an execution: the human decides whether to
`run` a suggested gated command (which still goes through the gate) or to perform
a MANUAL step themselves and report the result back.

This is how Brukal becomes a governed copilot: it advises freely, but it only ever
*executes* through the same gated door. A suggestion is not a bypass — if the
operator runs a suggested command, the gate rules on it exactly as always.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..llm import LLMClient

STRATEGIST_SYSTEM = (
    "You are a penetration-testing strategist guiding a human operator through an "
    "AUTHORISED engagement. Given the findings so far, propose the SINGLE next best "
    "step, concisely. Draw on the reference playbooks if given.\n\n"
    "Format your reply as:\n"
    "  <one or two sentences of reasoning>\n"
    "  RUN: <a single recon/enumeration command Brukal can run>   (optional)\n"
    "  MANUAL: <a step the operator must do themselves, e.g. exploitation, a shell, "
    "priv-esc>   (optional)\n"
    "Give RUN for anything safe and in-scope; give MANUAL for anything intrusive or "
    "interactive. A separate gate still rules on any RUN command."
)


@dataclass
class Suggestion:
    rationale: str
    command: str | None      # a gated command Brukal can run, if any
    target: str | None       # target for that command
    manual: str | None       # a manual step for the operator, if any


def _parse(text: str, default_target: str) -> Suggestion:
    command = manual = None
    rationale: list[str] = []
    for line in (text or "").splitlines():
        s = line.strip()
        up = s.upper()
        if up.startswith("RUN:") and command is None:
            cmd = s[4:].strip().strip("`").strip('"').strip()
            if " (" in cmd:                       # drop a trailing "(...)" note
                cmd = cmd[:cmd.index(" (")].strip()
            command = cmd or None
        elif up.startswith("MANUAL:") and manual is None:
            manual = s[7:].strip()
        else:
            rationale.append(line)
    return Suggestion(
        rationale="\n".join(rationale).strip() or (text or "").strip(),
        command=command or None,
        target=default_target if command else None,
        manual=manual or None)


class StrategistAgent:
    def __init__(self, llm: LLMClient):
        self._llm = llm

    def advise(self, target: str, findings: str, notes: str = "",
               reference: str = "") -> Suggestion:
        parts = [f"TARGET: {target}", f"FINDINGS SO FAR:\n{findings or '(none yet)'}"]
        if notes:
            parts.append(f"OPERATOR NOTE:\n{notes}")
        if reference:
            parts.append(reference)   # untrusted skill reference, already labelled
        parts.append("Propose the single next best step.")
        text = self._llm.propose(STRATEGIST_SYSTEM, "\n\n".join(parts), max_tokens=700)
        return _parse(text, target)
