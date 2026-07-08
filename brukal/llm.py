"""
llm.py — the thin client that talks to Claude via the Anthropic Messages API.

This is "Path A": DIRECT MODEL ACCESS. Your code owns the loop. The model does
exactly one thing here — it takes text and returns text. It has NO ability to
execute anything. That is what makes Wall 1 ("the agent emits only text") true
by construction: with the raw Messages API, the model literally cannot run a
tool. Execution is done later, by YOUR gated executor, never by the model.

Requires the anthropic SDK (install with:  pip install "brukal[agents]") and an
ANTHROPIC_API_KEY in the environment.

Docs: https://docs.claude.com/en/api/overview
"""
from __future__ import annotations

import os


class LLMClient:
    """A minimal wrapper over client.messages.create that returns plain text."""

    def __init__(self, model: str | None = None, api_key: str | None = None):
        # Imported lazily so the safety core stays importable without the SDK.
        from anthropic import Anthropic

        self._client = Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        # Model is configurable; default to a fast, capable model for proposing
        # actions. Override with BRUKAL_MODEL or the `model` argument.
        self.model = model or os.environ.get("BRUKAL_MODEL", "claude-sonnet-5")

    def propose(self, system: str, user: str, max_tokens: int = 1024) -> str:
        """Send a system + user prompt, return the model's text response.

        `system` carries the agent's role/persona; `user` carries the task,
        the scoped context, and the strict output contract.
        """
        message = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        # The response content is a list of blocks; concatenate the text blocks.
        return "".join(
            block.text for block in message.content
            if getattr(block, "type", None) == "text"
        )
