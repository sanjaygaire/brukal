"""
test_llm_provider.py — the multi-provider model client.

Proves the OpenAI-compatible backend (Ollama / OpenAI / OpenRouter / Groq / ...)
builds the right request and returns the model's text, provider presets resolve,
bad configs fail loudly, and anthropic stays the default — all without a network
call or the anthropic SDK (the HTTP layer is mocked).
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import llm
from brukal.llm import LLMClient


class _FakeResp:
    def __init__(self, payload):
        self._b = json.dumps(payload).encode()

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_openai_compatible_roundtrip(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=0):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode())
        return _FakeResp({"choices": [{"message": {"content": "PROPOSED"}}]})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = LLMClient(provider="ollama", model="qwen2.5")
    out = client.propose("system-prompt", "user-prompt")

    assert out == "PROPOSED"
    assert captured["url"] == "http://localhost:11434/v1/chat/completions"
    assert captured["body"]["model"] == "qwen2.5"
    assert captured["body"]["messages"][0] == {"role": "system", "content": "system-prompt"}
    assert captured["body"]["messages"][1] == {"role": "user", "content": "user-prompt"}


def test_presets_resolve():
    assert LLMClient(provider="groq", model="x")._backend.url == \
        "https://api.groq.com/openai/v1/chat/completions"
    assert LLMClient(provider="ollama", model="x")._backend.url == \
        "http://localhost:11434/v1/chat/completions"


def test_bad_config_fails_loudly(monkeypatch):
    monkeypatch.delenv("BRUKAL_BASE_URL", raising=False)
    with pytest.raises(ValueError):
        LLMClient(provider="does-not-exist", model="x")      # unknown provider
    with pytest.raises(ValueError):
        LLMClient(provider="openai-compatible", model="x")   # no base_url
    with pytest.raises(ValueError):
        LLMClient(provider="lmstudio")                       # no model


def test_base_url_and_env_override(monkeypatch):
    monkeypatch.setenv("BRUKAL_MODEL", "envmodel")
    client = LLMClient(provider="openai-compatible", base_url="http://host:9/v1")
    assert client.model == "envmodel"
    assert client._backend.url == "http://host:9/v1/chat/completions"


def test_default_provider_is_anthropic(monkeypatch):
    seen = {}

    class _Dummy:
        def __init__(self, model, api_key):
            seen["model"] = model

        def propose(self, *a):
            return ""

    monkeypatch.setattr(llm, "_AnthropicBackend", _Dummy)
    monkeypatch.delenv("BRUKAL_PROVIDER", raising=False)
    monkeypatch.delenv("BRUKAL_MODEL", raising=False)
    client = LLMClient()
    assert client.provider == "anthropic"
    assert client.model == "claude-sonnet-5"
    assert seen["model"] == "claude-sonnet-5"
