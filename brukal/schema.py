"""
schema.py — the Action Request: the structured "note" an agent slides under the
door. This is the ONLY shape an agent may use to propose touching the target.

Why structured (not free chat text)? Because you can only check, gate, log, and
count something that has named fields. This is also the boundary where a
malformed proposal dies BEFORE it ever reaches the gate — fail-closed at the
door as well as at the guard.

Requires pydantic (install with:  pip install "brukal[agents]").
"""
from __future__ import annotations

import json
import re
from typing import Optional

from pydantic import BaseModel, ValidationError

# Allowed intents. Anything outside this set is rejected — an agent cannot
# invent a new kind of action.
_INTENTS = {"enumerate", "exploit", "verify", "cleanup"}


class ActionRequest(BaseModel):
    """Exactly what an agent must emit to propose an action."""
    proposing_agent: str
    intent: str
    command: str
    target_host: str
    target_port: Optional[int] = None
    justification: str = ""

    def is_intent_valid(self) -> bool:
        return self.intent in _INTENTS


def parse_action_request(text: str) -> Optional[ActionRequest]:
    """Turn raw model text into a validated ActionRequest, or None.

    Defensive by design: models sometimes wrap JSON in prose or code fences.
    We extract the first JSON object, validate it against the schema, and
    return None on ANY problem. None means "no valid proposal" — the caller
    treats it as a no-op and never guesses what the model meant.
    """
    if not text:
        return None

    # Strip common code-fence wrappers.
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?", "", cleaned).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()

    # Grab the first {...} block if there is surrounding prose.
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        return None

    try:
        data = json.loads(match.group(0))
        req = ActionRequest(**data)
    except (json.JSONDecodeError, ValidationError, TypeError):
        return None

    if not req.is_intent_valid():
        return None
    return req
