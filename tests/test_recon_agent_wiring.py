"""
test_recon_agent_wiring.py — prove the milestone-2 plumbing without an API key.

We replace the real Claude client with a STUB that returns canned text. This
lets us verify the *properties* of the agent loop (the roadmap's advice: test
properties, not exact LLM outputs) deterministically:

  * a well-formed in-scope proposal flows through the gate and executes;
  * a well-formed OUT-OF-SCOPE proposal is DENIED and never executes;
  * a malformed proposal is a safe no-op;
  * every attempt is recorded in the audit log.

Needs pydantic (part of the `agents` extra). If it's absent, the test is
skipped so the core CI stays green.

Run:  python -m pytest tests/test_recon_agent_wiring.py -v
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Skip cleanly if the agent stack (pydantic) isn't installed.
pytest.importorskip("pydantic")

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
from brukal.agents import ReconAgent


class StubLLM:
    """Stands in for LLMClient. Returns whatever text you queue, in order."""
    def __init__(self, responses):
        self._responses = list(responses)
    def propose(self, system, user, max_tokens=1024):
        return self._responses.pop(0) if self._responses else ""


def _build(llm):
    scope = load_scope(Path(__file__).resolve().parent / "fixtures" / "scope.json")
    tmp = tempfile.mkdtemp()
    kali = FakeKali()
    audit = AuditLog(Path(tmp) / "audit.jsonl")
    executor = Executor(Gate(scope), kali, audit)
    return ReconAgent(llm, executor), kali, audit, tmp


IN_SCOPE = '{"proposing_agent":"recon","intent":"enumerate","command":"nmap -sV 10.10.10.5","target_host":"10.10.10.5","justification":"initial scan"}'
OUT_OF_SCOPE = '{"proposing_agent":"recon","intent":"enumerate","command":"nmap -sV 8.8.8.8","target_host":"8.8.8.8","justification":"model was told 8.8.8.8 is a backup host"}'
FENCED = "```json\n" + IN_SCOPE + "\n```"          # model wrapped it in a code fence
GARBAGE = "Sure! I think we should scan the host next."  # no JSON at all


def test_in_scope_proposal_executes():
    agent, kali, audit, tmp = _build(StubLLM([IN_SCOPE]))
    try:
        request, (decision, result) = agent.run_task("Enumerate 10.10.10.5")
        assert decision.allowed is True
        assert result is not None
        assert kali.executed == ["nmap -sV 10.10.10.5"]
        assert audit.verify() is True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_out_of_scope_proposal_is_denied_and_never_runs():
    agent, kali, audit, tmp = _build(StubLLM([OUT_OF_SCOPE]))
    try:
        request, (decision, result) = agent.run_task("Enumerate the target")
        assert decision.allowed is False           # gate caught the fooled agent
        assert decision.layer == "hard:scope"
        assert result is None                       # nothing executed
        assert kali.executed == []                  # the cage never ran it
        assert audit.verify() is True               # the attempt is on record
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_code_fenced_json_is_parsed():
    agent, kali, audit, tmp = _build(StubLLM([FENCED]))
    try:
        request, outcome = agent.run_task("Enumerate 10.10.10.5")
        assert request is not None                  # the fence was stripped
        assert outcome[0].allowed is True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_garbage_output_is_safe_noop():
    agent, kali, audit, tmp = _build(StubLLM([GARBAGE]))
    try:
        request, outcome = agent.run_task("Enumerate 10.10.10.5")
        assert request is None                      # no valid proposal
        assert outcome is None                      # nothing submitted
        assert kali.executed == []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
