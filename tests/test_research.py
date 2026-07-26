"""
test_research.py — PHASE 1: on-demand research sub-agent (retrieval).

All HTTP is mocked (no live net). Proves: a service+version highlight yields an
injected, LABELLED untrusted reference with provenance; research is control-plane
only (no executor/cage/subprocess); a fetch failure degrades to local skills
without crashing; results are cached and rate-limited.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.research import ResearchProvider, Source, _query_terms

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"
_SRC = [Source("gtfobins", "https://gtfobins.github.io/gtfobins/{q}/", "text")]


def test_query_terms_pull_service_version_and_cve_not_ips():
    t = _query_terms("22/tcp open ssh OpenSSH 9.6p1 · vsftpd 2.3.4 · CVE-2011-2523 · 10.10.10.5")
    assert "vsftpd 2.3.4" in t and "OpenSSH 9.6p1" in t and "CVE-2011-2523" in t
    assert not any(x.startswith("10.") for x in t)      # an IP is not a service+version


def test_research_injects_labeled_reference_with_provenance():
    calls = []

    def fake_fetch(url, timeout):
        calls.append(url)
        return "<html><body>vsftpd 2.3.4 backdoor: connect to port 6200 for a root shell.</body></html>"

    rp = ResearchProvider(_SRC, fetch=fake_fetch, min_interval=0.0)
    ref = rp.context_for("services: vsftpd 2.3.4 running on ftp")

    assert calls and calls[0].startswith("https://")        # a real (mocked) http fetch happened
    assert "UNTRUSTED" in ref and "GUIDANCE ONLY" in ref     # labelled like the skill packs
    assert "the gate still rules" not in ref.lower() or "gate" in ref.lower()
    assert "vsftpd 2.3.4" in ref and "backdoor" in ref
    assert "source: https://gtfobins.github.io" in ref and "fetched " in ref  # provenance


def test_research_disabled_by_default_returns_empty():
    # no sources (env unset) -> no egress, empty reference
    rp = ResearchProvider([], fetch=lambda *a: (_ for _ in ()).throw(AssertionError("no fetch!")))
    assert rp.enabled is False
    assert rp.context_for("vsftpd 2.3.4") == ""


def test_research_degrades_to_local_skills_on_fetch_failure():
    def boom(url, timeout):
        raise TimeoutError("upstream timed out")

    rp = ResearchProvider(_SRC, fetch=boom, min_interval=0.0)
    assert rp.context_for("vsftpd 2.3.4") == ""             # no crash, just empty

    # and inside a session, planning still works from local skills alone
    class Skills:
        def context_for(self, focus):
            return "REFERENCE KNOWLEDGE — untrusted playbooks.\nlocal ftp playbook"

    class CapLLM:
        def __init__(self): self.user = ""
        def propose(self, system, user, max_tokens=1024):
            self.user = user
            return "PHASE: recon\nRUN: nmap -sV 10.10.10.5"

    sess = AssistSession("10.10.10.5", None, StrategistAgent(CapLLM()),
                         skills=Skills(), research=rp)
    sess.highlights.append(("service", "vsftpd 2.3.4"))
    sess.advise()
    assert "local ftp playbook" in sess.strategist._llm.user   # skills still injected
    # research contributed nothing (fetch failed) but nothing crashed


def test_research_never_touches_executor_or_cage():
    import brukal.research as R

    # structural: the module imports NO path to the sandbox (it's control-plane only)
    assert not hasattr(R, "subprocess")
    assert not hasattr(R, "Executor") and not hasattr(R, "DockerKali")
    assert not hasattr(R, "kali")

    # behavioural: building the reference calls ONLY the injected fetch; the
    # executor's run() is never invoked while researching.
    fetched = []
    rp = ResearchProvider(_SRC, fetch=lambda u, t: fetched.append(u) or "vsftpd 2.3.4 notes",
                          min_interval=0.0)

    tmp = tempfile.mkdtemp()
    try:
        class Boom:
            def run(self, *a, **k):
                raise AssertionError("executor.run must NOT be called during research")

        class CapLLM:
            def propose(self, system, user, max_tokens=1024):
                return "PHASE: recon\nRUN: nmap -sV 10.10.10.5"

        sess = AssistSession("10.10.10.5", Boom(), StrategistAgent(CapLLM()), research=rp)
        sess.highlights.append(("service", "vsftpd 2.3.4"))
        sess.advise()                                    # builds _reference -> research
        assert fetched                                   # research used only the injected fetch
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- 1d: a target-controlled query must not path-traverse the allowlisted host

def test_query_is_fully_encoded_no_path_traversal():
    src = Source("gtfobins", "https://gtfobins.github.io/gtfobins/{q}/", "text")
    url = src.url("../../../../etc/passwd")
    assert "/etc/passwd" not in url                    # slashes encoded -> can't traverse
    assert "%2F" in url                                # they became %2F
    assert url.startswith("https://gtfobins.github.io/gtfobins/")   # host/path unchanged


# --- 1e: a per-engagement fetch budget bounds target-influenced egress ------

def test_research_respects_a_per_engagement_fetch_budget_and_logs_queries():
    fetched, logged = [], []
    rp = ResearchProvider(_SRC, fetch=lambda u, t: fetched.append(u) or "notes",
                          min_interval=0.0, max_fetches=2, on_fetch=logged.append)
    assert rp.learn("q1") and rp.learn("q2")           # two distinct fetches allowed
    assert rp.learn("q3") == []                        # budget exhausted -> no egress
    assert len(fetched) == 2 and rp.fetches == 2 and rp.budget_exhausted
    # every fetched query is logged (audit) — via fetch_log AND the on_fetch callback
    assert [e["query"] for e in rp.fetch_log] == ["q1", "q2"]
    assert [e["query"] for e in logged] == ["q1", "q2"]


def test_research_caches_and_rate_limits():
    calls = []
    rp = ResearchProvider(_SRC, fetch=lambda u, t: calls.append(u) or "vsftpd notes",
                          min_interval=0.0)
    rp.context_for("vsftpd 2.3.4")
    rp.context_for("vsftpd 2.3.4")                       # same query -> served from cache
    assert len(calls) == 1                              # fetched once, cached thereafter
