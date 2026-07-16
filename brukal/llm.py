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

# $ per 1M tokens (input, output). Substring-matched against the model id, longest
# key first, so "claude-opus-4-8" wins over a hypothetical "claude-opus". Models not
# listed here (local Ollama/LM Studio, or a provider we haven't priced) meter their
# tokens but report cost as unknown rather than guessing. Update as prices move.
_PRICING = {
    "claude-fable-5":    (10.00, 50.00),
    "claude-opus-4-8":   (5.00, 25.00),
    "claude-opus-4-7":   (5.00, 25.00),
    "claude-opus-4-6":   (5.00, 25.00),
    "claude-sonnet-5":   (3.00, 15.00),
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-haiku-4-5":  (1.00, 5.00),
    # OpenAI-compatible clouds (approximate list prices; verify against your plan).
    # Substring match, so provider-prefixed ids like "deepseek/deepseek-chat" (via
    # OpenRouter) fall through to the bare key below automatically.
    "deepseek-reasoner": (0.55, 2.19),
    "deepseek-r1":       (0.55, 2.19),   # OpenRouter/other naming for the reasoner
    "deepseek-chat":     (0.27, 1.10),
    "deepseek":          (0.27, 1.10),   # fallback for any other deepseek-* id (approx)
    "glm-4.6":           (0.60, 2.20),
    "z-ai/glm-4.6":      (0.60, 2.20),
    "kimi-k2":           (0.60, 2.50),
    "gpt-4o-mini":       (0.15, 0.60),
    "gpt-4.1-mini":      (0.40, 1.60),
    "gpt-4o":            (2.50, 10.00),
    # Groq's hosted open models are free within the free tier -> priced at $0.
    "llama-3.1-8b-instant":     (0.0, 0.0),
    "llama-3.3-70b-versatile":  (0.0, 0.0),
    "openai/gpt-oss-120b":      (0.0, 0.0),
    "openai/gpt-oss-20b":       (0.0, 0.0),
}


def _rate_for(model: str):
    """(input, output) $/1M for a model id, or None if we have no price on file."""
    m = (model or "").lower()
    for key in sorted(_PRICING, key=len, reverse=True):
        if key in m:
            return _PRICING[key]
    return None


class UsageMeter:
    """Accumulates token usage across every propose() call and prices it. One meter
    per LLMClient, so `client.usage.summary()` is the per-hunt cost line."""

    def __init__(self, model: str):
        self.model = model
        self.calls = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.cache_read_tokens = 0   # billed at ~0.1x input where the provider reports it

    def add(self, usage: dict) -> None:
        if not usage:
            return
        self.calls += 1
        self.input_tokens += int(usage.get("input", 0) or 0)
        self.output_tokens += int(usage.get("output", 0) or 0)
        self.cache_read_tokens += int(usage.get("cache_read", 0) or 0)

    @property
    def cost(self):
        """USD spent so far, or None if the model has no price on file (e.g. local)."""
        rate = _rate_for(self.model)
        if rate is None:
            return None
        in_rate, out_rate = rate
        billed_in = max(self.input_tokens - self.cache_read_tokens, 0)
        return (billed_in / 1e6) * in_rate \
            + (self.cache_read_tokens / 1e6) * in_rate * 0.1 \
            + (self.output_tokens / 1e6) * out_rate

    def summary(self) -> str:
        toks = (f"{self.calls} call(s) · "
                f"{self.input_tokens:,} in / {self.output_tokens:,} out tokens")
        if self.cache_read_tokens:
            toks += f" ({self.cache_read_tokens:,} cached)"
        cost = self.cost
        if cost is None:
            return f"{self.model}: {toks} · cost: n/a (no price on file — local/free?)"
        return f"{self.model}: {toks} · ~${cost:.4f}"


class _AnthropicBackend:
    def __init__(self, model: str, api_key: str | None):
        from anthropic import Anthropic   # lazy: core stays importable without the SDK
        self._client = Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self.model = model
        self.last_usage: dict = {}

    def propose(self, system: str, user: str, max_tokens: int) -> str:
        msg = self._client.messages.create(
            model=self.model, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": user}])
        u = getattr(msg, "usage", None)
        self.last_usage = {
            "input": getattr(u, "input_tokens", 0),
            "output": getattr(u, "output_tokens", 0),
            "cache_read": getattr(u, "cache_read_input_tokens", 0) or 0,
        } if u is not None else {}
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
        self.last_usage: dict = {}

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
        u = data.get("usage") or {}
        self.last_usage = {
            "input": u.get("prompt_tokens", 0),
            "output": u.get("completion_tokens", 0),
            # some OpenAI-compatible providers report cached input here
            "cache_read": (u.get("prompt_tokens_details") or {}).get("cached_tokens", 0),
        }
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
            self.usage = UsageMeter(self.model)
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
        self.usage = UsageMeter(self.model)

    def propose(self, system: str, user: str, max_tokens: int = 1024) -> str:
        text = self._backend.propose(system, user, max_tokens)
        self.usage.add(getattr(self._backend, "last_usage", {}))
        return text
