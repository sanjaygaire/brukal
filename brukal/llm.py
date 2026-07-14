"""
llm.py — the thin client the agents use to turn text into text.

The model does exactly one thing: take a system + user prompt and return text. It
has NO ability to execute anything — that is Wall 1 ("the agent emits only text"),
true by construction. Execution is done later by the gated executor, never here.

Two backends behind one `propose()` interface, so the rest of Brukal never cares
which model you use:

  * anthropic — Claude via the Anthropic SDK (needs `pip install "brukal[agents]"`
    and ANTHROPIC_API_KEY).
  * openai-compatible — ANY server that speaks the OpenAI chat API, over the
    standard library (no extra dependency): Ollama and LM Studio (free, local,
    no key), OpenAI, OpenRouter, Groq, Together, vLLM, ...

Pick with --provider / BRUKAL_PROVIDER. For a free local run:
    ollama pull qwen2.5
    brukal run <target> --provider ollama --model qwen2.5
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

# provider -> (base_url, api-key env var, default model). base_url None means the
# caller must supply --base-url (a generic OpenAI-compatible endpoint).
_PRESETS = {
    "openai":      ("https://api.openai.com/v1", "OPENAI_API_KEY", "gpt-4o-mini"),
    "ollama":      ("http://localhost:11434/v1", "OLLAMA_API_KEY", "llama3.1"),
    "lmstudio":    ("http://localhost:1234/v1", "LMSTUDIO_API_KEY", None),
    "openrouter":  ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY",
                    "z-ai/glm-4.6"),
    "groq":        ("https://api.groq.com/openai/v1", "GROQ_API_KEY",
                    "llama-3.1-8b-instant"),
    "zhipu":       ("https://api.z.ai/api/paas/v4", "ZHIPU_API_KEY", "glm-4.6"),
    "glm":         ("https://api.z.ai/api/paas/v4", "ZHIPU_API_KEY", "glm-4.6"),
    "deepseek":    ("https://api.deepseek.com", "DEEPSEEK_API_KEY", "deepseek-chat"),
    "openai-compatible": (None, "OPENAI_API_KEY", None),
}
_ANTHROPIC_DEFAULT = "claude-sonnet-5"


class _AnthropicBackend:
    def __init__(self, model: str, api_key: str | None):
        from anthropic import Anthropic   # lazy: core stays importable without the SDK
        self._client = Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self.model = model

    def propose(self, system: str, user: str, max_tokens: int) -> str:
        msg = self._client.messages.create(
            model=self.model, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": user}])
        return "".join(b.text for b in msg.content
                       if getattr(b, "type", None) == "text")


class _OpenAICompatBackend:
    """Any OpenAI chat-completions endpoint, via urllib (no dependency)."""

    def __init__(self, model: str, base_url: str, api_key: str, timeout: int = 180):
        if not base_url:
            raise ValueError("no base_url — pass --base-url or BRUKAL_BASE_URL")
        if not model:
            raise ValueError("no model — pass --model or BRUKAL_MODEL")
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.model = model
        self.api_key = api_key or "not-needed"
        self.timeout = timeout

    def propose(self, system: str, user: str, max_tokens: int) -> str:
        body = json.dumps({
            "model": self.model, "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }).encode()
        req = urllib.request.Request(
            self.url, data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "Accept": "application/json",
                     # A real User-Agent is required: some providers (Groq,
                     # OpenRouter) sit behind Cloudflare, which blocks the default
                     # "Python-urllib/x.y" signature with HTTP 403 (error 1010).
                     "User-Agent": "Brukal/1.0 (+https://github.com/sanjaygaire/brukal)",
                     "Authorization": f"Bearer {self.api_key}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            raise RuntimeError(f"{self.url} -> HTTP {e.code}: {detail}") from None
        except urllib.error.URLError as e:
            raise RuntimeError(f"cannot reach {self.url}: {e.reason}") from None
        return (data["choices"][0]["message"].get("content") or "")


class LLMClient:
    """Provider-agnostic. Same propose() for Claude or any OpenAI-compatible model."""

    def __init__(self, model: str | None = None, api_key: str | None = None,
                 provider: str | None = None, base_url: str | None = None):
        self.provider = (provider or os.environ.get("BRUKAL_PROVIDER", "anthropic")).lower()
        env_model = os.environ.get("BRUKAL_MODEL")

        if self.provider == "anthropic":
            self.model = model or env_model or _ANTHROPIC_DEFAULT
            self._backend = _AnthropicBackend(self.model, api_key)
            return

        if self.provider not in _PRESETS:
            raise ValueError(
                f"unknown provider '{self.provider}'. Choose one of: "
                f"anthropic, {', '.join(_PRESETS)}.")
        preset_url, key_env, default_model = _PRESETS[self.provider]
        self.model = model or env_model or default_model
        url = base_url or os.environ.get("BRUKAL_BASE_URL") or preset_url
        key = api_key or os.environ.get(key_env) or os.environ.get("OPENAI_API_KEY", "")
        self._backend = _OpenAICompatBackend(self.model, url, key)

    def propose(self, system: str, user: str, max_tokens: int = 1024) -> str:
        return self._backend.propose(system, user, max_tokens)
