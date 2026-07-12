"""
agents/strategist.py — the advisory agent for human-assisted solving.

Unlike recon/exploit/verify (which each propose one gated command), the strategist
REASONS about the whole engagement like a companion sitting next to you: it names
the current PHASE, states the GOAL it is working toward, explains its REASONING
from the findings so far (and any objectives the box is asking you to answer), and
only then proposes the next move — a gated RUN command or a MANUAL step you do.

Its output is advice, not execution. If the operator runs a suggested command it
still goes through the gate. A suggestion is not a bypass.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..llm import LLMClient

STRATEGIST_SYSTEM = (
    "You are a friendly, sharp penetration-testing companion guiding a human "
    "operator through an AUTHORISED engagement (e.g. a Hack The Box machine). "
    "Talk like a teammate thinking out loud, not a tool dispatcher. Keep the human "
    "oriented: what are we doing and why. Reason from the findings and, if given, "
    "the OBJECTIVES the box is asking the operator to answer.\n\n"
    "Reply in EXACTLY this template:\n"
    "PHASE: <recon | enumeration | exploitation | privilege-escalation | looting>\n"
    "GOAL: <the concrete thing we're trying to achieve right now, one line>\n"
    "REASONING: <2-4 sentences: what we've learned, what it implies, why this next "
    "step. Reference specific ports/services/findings. If an objective can now be "
    "answered, say so.>\n"
    "RUN: <one recon/enumeration command Brukal can run>   (optional)\n"
    "MANUAL: <a step the operator does themselves — exploitation, a shell, cracking "
    "a hash, submitting a flag>   (optional)\n\n"
    "Give RUN for safe in-scope enumeration; give MANUAL for intrusive/interactive "
    "work. Prefer ONE clear next step. A separate gate still rules on any RUN."
)


STRATEGIST_PLAN_SYSTEM = (
    "You are a penetration-testing companion planning the SHORTEST path to the "
    "goal on an AUTHORISED engagement (typically the user+root flags on a Hack The "
    "Box machine, or the listed objectives). Given the target, the objectives, and "
    "the findings so far, lay out a concise ordered plan of the next concrete "
    "steps — recon → enumeration → exploitation → privilege-escalation → looting — "
    "only as many steps as actually get us there. Don't enumerate everything; "
    "enumerate what moves us toward the goal.\n\n"
    "Reply as a numbered list, ONE step per line, nothing else:\n"
    "1. [phase] <concrete step naming the tool/technique>\n"
    "2. [phase] <...>\n"
    "Keep it to 3-7 steps. If findings already answer earlier steps, start the "
    "plan from the next real move."
)


@dataclass
class PlanStep:
    text: str                 # the concrete step, e.g. "enumerate web on :3000 with feroxbuster"
    phase: str = ""           # recon / enumeration / exploitation / ...
    done: bool = False


@dataclass
class Suggestion:
    rationale: str            # the REASONING text (companion voice)
    command: str | None       # a gated command Brukal can run, if any
    target: str | None        # target for that command
    manual: str | None        # a manual step for the operator, if any
    phase: str = ""           # recon / enumeration / exploitation / ...
    goal: str = ""            # the concrete objective of this step


_PLAN_LINE = re.compile(r"^\s*\d+[.)]\s*(?:\[(?P<phase>[^\]]+)\]\s*)?(?P<text>.+?)\s*$")


def parse_plan(text: str) -> list[PlanStep]:
    """Parse a numbered plan into ordered PlanSteps. Tolerant of models that
    wrap the list in prose — it simply keeps the numbered lines."""
    steps: list[PlanStep] = []
    for line in (text or "").splitlines():
        m = _PLAN_LINE.match(line)
        if not m:
            continue
        body = m.group("text").strip().strip("`").strip()
        if body:
            steps.append(PlanStep(text=body, phase=(m.group("phase") or "").strip().lower()))
    return steps


def _field(text: str, name: str) -> str:
    m = re.search(rf"^{name}\s*:\s*(.+?)\s*$", text, re.M | re.I)
    return m.group(1).strip() if m else ""


def _parse(text: str, default_target: str) -> Suggestion:
    text = text or ""
    phase = _field(text, "PHASE")
    goal = _field(text, "GOAL")
    reasoning = _field(text, "REASONING")
    command = _field(text, "RUN") or None
    manual = _field(text, "MANUAL") or None

    if command:                                   # strip a trailing "(why)" note
        command = command.strip("`").strip('"').strip()
        if " (" in command:
            command = command[:command.index(" (")].strip()
        command = command or None
    if manual and manual.lower() in ("none", "n/a", "-"):
        manual = None

    # Fall back to the whole reply as rationale if the model ignored the template.
    if not reasoning:
        reasoning = re.sub(r"^(PHASE|GOAL|RUN|MANUAL)\s*:.*$", "", text,
                           flags=re.M | re.I).strip() or text.strip()

    return Suggestion(rationale=reasoning, command=command,
                      target=default_target if command else None, manual=manual,
                      phase=phase, goal=goal)


class StrategistAgent:
    def __init__(self, llm: LLMClient):
        self._llm = llm

    def plan(self, target: str, findings: str, objectives: str = "",
             reference: str = "") -> list[PlanStep]:
        """Lay out the shortest-path plan of concrete next steps."""
        parts = [f"TARGET: {target}"]
        if objectives:
            parts.append(f"OBJECTIVES to answer:\n{objectives}")
        parts.append(f"FINDINGS SO FAR:\n{findings or '(nothing yet — just starting)'}")
        if reference:
            parts.append(reference)               # untrusted skill reference, labelled
        parts.append("Give me the shortest-path plan as a numbered list.")
        text = self._llm.propose(STRATEGIST_PLAN_SYSTEM, "\n\n".join(parts), max_tokens=500)
        return parse_plan(text)

    def advise(self, target: str, findings: str, notes: str = "",
               reference: str = "", objectives: str = "", plan: str = "") -> Suggestion:
        parts = [f"TARGET: {target}"]
        if objectives:
            parts.append(f"OBJECTIVES the box is asking us to answer:\n{objectives}")
        if plan:
            parts.append(f"OUR PLAN (work the marked ▶ step next; keep advice on the "
                         f"shortest path):\n{plan}")
        parts.append(f"FINDINGS SO FAR:\n{findings or '(nothing yet — we just started)'}")
        if notes:
            parts.append(f"OPERATOR JUST SAID:\n{notes}")
        if reference:
            parts.append(reference)               # untrusted skill reference, labelled
        parts.append("Give me the next step in the template.")
        text = self._llm.propose(STRATEGIST_SYSTEM, "\n\n".join(parts), max_tokens=800)
        return _parse(text, target)
