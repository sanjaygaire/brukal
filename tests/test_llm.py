"""
test_llm.py — PHASE 1: reliably hearing the model.

Covers the fragile model-I/O paths that made Brukal look brain-dead on thinking
models: <think> stripping, reasoning_content fallback, transient-error retries, and
salvage command extraction when the model didn't give a clean RUN: line.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from brukal.llm import _OpenAICompatBackend, _strip_think
from brukal.agents.strategist import StrategistAgent, _parse, _salvage_command


class _FakeResp:
    def __init__(self, payload: str):
        self._p = payload.encode()

    def read(self):
        return self._p

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _backend():
    return _OpenAICompatBackend("some-thinking-model", "http://x/v1", "k",
                                retries=3, backoff=0.0)


# -- <think> stripping -------------------------------------------------------

def test_strip_think_removes_reasoning_but_keeps_answer():
    t = "<think>\nlots of reasoning\n</think>\nPHASE: recon\nRUN: nmap -sV 10.10.10.5"
    assert _strip_think(t).startswith("PHASE: recon")
    assert "reasoning" not in _strip_think(t)


def test_strip_think_keeps_original_when_all_reasoning():
    # a reply that is ONLY a think block -> keep it (something beats nothing)
    assert _strip_think("<think>just thinking</think>") == "<think>just thinking</think>"


# -- reasoning_content fallback + think strip (the headline PHASE-1 case) -----

def test_thinking_response_still_yields_a_parseable_command(monkeypatch):
    # content is empty; the model put its answer (wrapped in <think>) in reasoning_content
    payload = json.dumps({
        "choices": [{"message": {
            "content": "",
            "reasoning_content": "<think>ssh+http open, scan services</think>\n"
                                 "PHASE: recon\nGOAL: enumerate\nRUN: nmap -sV 10.10.10.5",
        }}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    })
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _FakeResp(payload))

    text = _backend().propose("sys", "user", 800)
    assert "<think>" not in text and text.startswith("PHASE: recon")
    # and the strategist actually gets a command out of it
    assert _parse(text, "10.10.10.5").command == "nmap -sV 10.10.10.5"


# -- retries on transient errors ---------------------------------------------

def test_transient_urlopen_error_is_retried(monkeypatch):
    calls = {"n": 0}
    ok = json.dumps({"choices": [{"message": {"content": "RUN: nmap 10.10.10.5"}}]})

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] < 3:                       # fail twice, succeed on the third
            raise urllib.error.URLError("temporarily unreachable")
        return _FakeResp(ok)

    monkeypatch.setattr(urllib.request, "urlopen", flaky)
    text = _backend().propose("sys", "user", 500)
    assert calls["n"] == 3 and "nmap" in text     # retried and eventually succeeded


def test_client_error_is_not_retried(monkeypatch):
    calls = {"n": 0}

    def bad_key(*a, **k):
        calls["n"] += 1
        raise urllib.error.HTTPError("http://x/v1", 401, "Unauthorized", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", bad_key)
    with pytest.raises(RuntimeError):
        _backend().propose("sys", "user", 500)
    assert calls["n"] == 1                         # 4xx fails fast, no retry


# -- salvage extraction ------------------------------------------------------

def test_salvage_command_from_code_fence():
    reply = ("Here's what I'd run next:\n```bash\nnmap -sV -p 22,80 10.10.10.5\n```\n"
             "That should reveal the services.")
    assert _salvage_command(reply) == "nmap -sV -p 22,80 10.10.10.5"
    # end-to-end: _parse recovers it even with no RUN: line
    assert _parse(reply, "10.10.10.5").command == "nmap -sV -p 22,80 10.10.10.5"


def test_salvage_command_from_bare_shell_line():
    reply = "I think we should enumerate the web app.\ngobuster dir -u http://10.10.10.5/ -w list.txt"
    assert _salvage_command(reply) == "gobuster dir -u http://10.10.10.5/ -w list.txt"


def test_advice_only_reply_is_not_salvaged_into_a_command():
    s = _parse("Enumerate more before exploiting; we don't have enough yet.", "10.10.10.5")
    assert s.command is None and s.manual is None


# -- truncated-command repair (max_tokens cut a command mid-quote) ------------

def test_repair_balances_a_truncated_host_header_quote():
    from brukal.agents.strategist import _repair_command
    # the exact deepseek-chat failure: an unbalanced -H "Host: ... quote
    got = _repair_command('ffuf -u http://10.0.0.1/FUZZ -w list.txt -H "Host: nexus.htb')
    assert got == 'ffuf -u http://10.0.0.1/FUZZ -w list.txt -H "Host: nexus.htb"'
    import shlex
    shlex.split(got)                                   # now parseable
    # an already-clean command is returned unchanged
    assert _repair_command("nmap -sV 10.0.0.1") == "nmap -sV 10.0.0.1"
    assert _repair_command(None) is None and _repair_command("") == ""


def test_parse_repairs_a_truncated_command_so_it_is_runnable():
    reply = ('PHASE: enumeration\nGOAL: vhost dirs\n'
             'RUN: gobuster dir -u http://10.0.0.1/ -H "Host: nexus.htb')
    s = _parse(reply, "10.0.0.1")
    assert s.command == 'gobuster dir -u http://10.0.0.1/ -H "Host: nexus.htb"'
    import shlex
    shlex.split(s.command)                             # the gate's shlex will accept it
