"""
checkpoint.py — snapshot engagement progress so a dead run RESUMES, not restarts.

Long runs are the norm, and a crash / kill / lost connection shouldn't throw the work
away. Findings, plan and highlights already persist to the vault (see
AssistSession._load_memory); this adds the loop-progress the vault doesn't carry —
which commands already executed, what research was already fetched, the plan cursor,
how many steps were spent — as a small JSON file written after every turn.

On resume, `restore()` re-seeds that progress so the loop continues where it left off:
it doesn't re-run commands it already ran, doesn't re-fetch research it already has, and
counts the steps already spent against the budget. Purely additive and deterministic;
standard library only. A checkpoint is DATA — it never changes scope, tools, or the gate.
"""
from __future__ import annotations

import json
import time
from pathlib import Path


def snapshot(session, *, steps_done: int = 0, stop_reason: str = "") -> dict:
    meter = getattr(getattr(session.strategist, "_llm", None), "usage", None)
    return {
        "version": 1,
        "target": session.target,
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "objectives": list(session.objectives),
        "executed_cmds": list(session.executed_cmds),
        "learned": sorted(getattr(session, "_learned", set())),
        "plan_cursor": getattr(session, "plan_cursor", 0),
        "steps_done": int(steps_done),
        "stop_reason": stop_reason,
        "tokens": {
            "calls": getattr(meter, "calls", 0),
            "input": getattr(meter, "input_tokens", 0),
            "output": getattr(meter, "output_tokens", 0),
        } if meter is not None else {},
    }


def save(path, session, *, steps_done: int = 0, stop_reason: str = "") -> dict:
    """Atomically write a checkpoint for `session`. Never raises into the caller."""
    data = snapshot(session, steps_done=steps_done, stop_reason=stop_reason)
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(p)
    except Exception:
        pass                                  # a failed checkpoint must never break a run
    return data


def load(path) -> dict | None:
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None                           # a corrupt checkpoint is ignored, not fatal


def restore(session, data) -> int:
    """Re-seed loop-progress from a checkpoint onto `session` (executed_cmds, learned,
    objectives, plan_cursor) so a resumed run doesn't repeat work. Guards on the target
    matching. Returns the number of steps already spent (for the budget). Findings/plan/
    highlights are restored separately by the vault's _load_memory."""
    if not data or data.get("target") != session.target:
        return 0
    for c in data.get("executed_cmds", []):
        if c not in session.executed_cmds:
            session.executed_cmds.append(c)
    if hasattr(session, "_learned"):
        session._learned.update(data.get("learned", []))
    for o in data.get("objectives", []):
        if o not in session.objectives:
            session.objectives.append(o)
    if data.get("plan_cursor"):
        session.plan_cursor = max(getattr(session, "plan_cursor", 0),
                                  int(data["plan_cursor"]))
    session.resumed = max(getattr(session, "resumed", 0), len(data.get("executed_cmds", [])))
    return int(data.get("steps_done", 0))
