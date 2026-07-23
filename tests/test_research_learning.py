"""
test_research_learning.py — first-class internet learning (Part 2).

Pins:
  * the source allowlist is ON by default (verified + web) and honours an explicit
    override / off switch — never any egress when disabled.
  * DuckDuckGo (general web) results are distilled to titles+snippets.
  * ResearchProvider.learn(query) looks a specific query up (injected fetch, no real
    network) and returns snippets; the control plane has NO cage/executor reference.
  * session.learn folds the UNTRUSTED result into notes and persists it as a
    CANDIDATE lesson (never trusted -> poison-proof), deduped per query.
  * the auto-learn reflex fires on a new CVE/service+version in the findings.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.lessons import LessonStore
from brukal.loop import GroundedLoop
import brukal.research as research

SCOPE = Path(__file__).resolve().parents[1] / "scope.json"


class SeqLLM:
    def __init__(self, responses):
        self.responses, self.i = list(responses), 0

    def propose(self, system, user, max_tokens=1024):
        r = self.responses[min(self.i, len(self.responses) - 1)]
        self.i += 1
        return r


DDG_HTML = ('<a class="result__a" href="x">Laravel Ignition RCE</a>'
            '<a class="result__snippet" href="x">CVE-2021-3129 unauth RCE via debug mode</a>'
            '<a class="result__a" href="y">PoC</a>'
            '<a class="result__snippet" href="y">exploitation walkthrough</a>')


def _fake_fetch(url, timeout):
    if "duckduckgo" in url:
        return DDG_HTML
    if "nvd.nist.gov" in url:
        return ('{"vulnerabilities":[{"cve":{"id":"CVE-2021-3129",'
                '"descriptions":[{"lang":"en","value":"Ignition before 2.5.2 RCE."}]}}]}')
    return "<html><body>exploit result for query</body></html>"


# ---- source allowlist ------------------------------------------------------ #

def test_sources_default_on_and_off_switch(monkeypatch):
    monkeypatch.delenv("BRUKAL_RESEARCH_SOURCES", raising=False)
    assert {s.name for s in research._sources_from_env()} >= {"nvd", "web"}   # default incl. web
    monkeypatch.setenv("BRUKAL_RESEARCH_SOURCES", "off")
    assert research._sources_from_env() == []                                 # hard off
    monkeypatch.setenv("BRUKAL_RESEARCH_SOURCES", "nvd,gtfobins")
    assert {s.name for s in research._sources_from_env()} == {"nvd", "gtfobins"}


def test_ddg_distiller_extracts_titles_and_snippets():
    from brukal.research import _distill_ddg
    out = _distill_ddg(DDG_HTML)
    assert "Laravel Ignition RCE" in out and "CVE-2021-3129" in out


def test_provider_learn_uses_injected_fetch_and_has_no_cage_reference():
    src = [research._BUILTIN_SOURCES["nvd"], research._BUILTIN_SOURCES["web"]]
    p = research.ResearchProvider(sources=src, fetch=_fake_fetch, min_interval=0)
    snips = p.learn("Laravel Ignition")
    assert snips and any("CVE-2021-3129" in s.text for s in snips)
    # control-plane guarantee: the module cannot reach the sandbox
    for banned in ("executor", "kali", "subprocess", "docker"):
        assert not hasattr(research, banned)


# ---- session + loop -------------------------------------------------------- #

def _session(tmp, research_provider=None):
    ex = Executor(Gate(load_scope(SCOPE)), FakeKali(), AuditLog(Path(tmp) / "a.jsonl"))
    lessons = LessonStore(Path(tmp) / "lessons.jsonl")
    sess = AssistSession("10.10.10.5", ex, StrategistAgent(SeqLLM(["x"])),
                         lessons=lessons, research=research_provider)
    return sess


def test_session_learn_persists_candidate_only_and_dedupes():
    tmp = tempfile.mkdtemp()
    try:
        src = [research._BUILTIN_SOURCES["web"]]
        p = research.ResearchProvider(sources=src, fetch=_fake_fetch, min_interval=0)
        sess = _session(tmp, p)
        text = sess.learn("Laravel Ignition")
        assert "CVE-2021-3129" in text
        assert any(tag == "learned" for tag, _ in sess.highlights)
        # persisted as CANDIDATE lessons, never trusted (poison-proof)
        assert len(sess.lessons._candidates) >= 1
        assert sess.lessons._trusted == []
        # dedup: a second learn of the same query does nothing new
        assert sess.learn("Laravel Ignition") == ""
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_learn_returns_nothing_when_research_disabled():
    tmp = tempfile.mkdtemp()
    try:
        sess = _session(tmp, None)               # research off
        assert sess.learn("anything") == ""
        assert sess.research_todo() == []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_auto_learn_reflex_fires_on_a_new_service_version():
    tmp = tempfile.mkdtemp()
    try:
        src = [research._BUILTIN_SOURCES["web"]]
        p = research.ResearchProvider(sources=src, fetch=_fake_fetch, min_interval=0)
        sess = _session(tmp, p)
        sess.highlights.append(("port", "3000/tcp open http Laravel 8.4"))   # a version appears
        sess.strategist = StrategistAgent(SeqLLM([
            "PHASE: recon\nGOAL: hand off\nREASONING: over.\nMANUAL: your move"]))
        loop = GroundedLoop(sess, max_steps=6)
        result = loop.run()
        assert any((s.command or "").startswith("LEARN:") for s in result.steps)
        assert sess._learned                     # something was researched
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
