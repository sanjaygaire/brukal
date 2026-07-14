"""
test_lessons.py — Brukal's cross-session learning.

Proves lessons are DERIVED from real outcomes (timeouts, denials, wins), tagged,
retrievable for the current context, de-duplicated (reinforced not duplicated),
and PERSISTED so the next session/engagement starts smarter than the last.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.lessons import LessonStore


def _decision(verdict, layer=""):
    return SimpleNamespace(verdict=verdict, layer=layer, reason=layer)


def _result(stdout="out", rc=0, stderr=""):
    return SimpleNamespace(stdout=stdout, returncode=rc, stderr=stderr)


def test_learns_pitfalls_from_gate_blocks():
    store = LessonStore(tempfile.mktemp())
    store.learn_from_outcome("httpx http://x", _decision("DENY", "hard:allowlist"), None)
    store.learn_from_outcome("curl http://x`", _decision("DENY", "hard:injection"), None)
    store.learn_from_outcome("nmap 8.8.8.8", _decision("DENY", "hard:scope"), None)
    texts = " ".join(l.text.lower() for l in store._lessons)
    assert "httpx" in texts and "allowlist" in texts
    assert "metacharacter" in texts or "shell" in texts
    assert "out-of-scope" in texts or "authorised host" in texts
    assert all(l.kind == "pitfall" for l in store._lessons)


def test_learns_timeout_and_win():
    store = LessonStore(tempfile.mktemp())
    store.learn_from_outcome("nmap -A -p- 10.0.0.1", _decision("ALLOW", "soft:allow"),
                             _result(stdout="", rc=124, stderr="timed out"))
    store.learn_from_outcome("gobuster dir -u http://x", _decision("ALLOW", "soft:allow"),
                             _result(stdout="/admin (200)"), tech_tags=["nginx", "http"])
    kinds = {l.kind for l in store._lessons}
    assert "pitfall" in kinds and "win" in kinds
    win = next(l for l in store._lessons if l.kind == "win")
    assert "gobuster" in win.text and "nginx" in win.tags


def test_retrieve_surfaces_relevant_lessons():
    store = LessonStore(tempfile.mktemp())
    store.learn_from_outcome("httpx http://x", _decision("DENY", "hard:allowlist"), None)
    store.learn_from_outcome("nmap -A -p- x", _decision("ALLOW"), _result(rc=124, stderr="timed out"))
    hits = store.retrieve("should I use httpx to scan")
    assert hits and "httpx" in hits[0].text
    assert "httpx" in store.context_for("httpx").lower()
    assert store.context_for("completely unrelated xyzzy") == ""   # nothing matches


def test_dedup_reinforces_instead_of_duplicating():
    store = LessonStore(tempfile.mktemp())
    for _ in range(3):
        store.learn_from_outcome("httpx http://x", _decision("DENY", "hard:allowlist"), None)
    same = [l for l in store._lessons if "httpx" in l.text]
    assert len(same) == 1 and same[0].hits == 3      # reinforced, not duplicated


def test_persists_across_sessions():
    path = tempfile.mktemp()
    s1 = LessonStore(path)
    s1.learn_from_outcome("httpx http://x", _decision("DENY", "hard:allowlist"), None)
    # a brand-new store on the same file must remember the lesson
    s2 = LessonStore(path)
    assert len(s2) == 1 and "httpx" in s2._lessons[0].text
    assert s2.retrieve("httpx")


def test_session_learns_and_injects_into_context():
    # end-to-end: a denied command teaches a lesson, and the next reference block
    # (fed to the strategist) contains it.
    import shutil

    from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
    from brukal.agents import StrategistAgent
    from brukal.assist import AssistSession

    class StubLLM:
        def propose(self, s, u, max_tokens=1024): return ""

    scope = load_scope(Path(__file__).resolve().parents[1] / "scope.json")
    tmp = tempfile.mkdtemp()
    try:
        store = LessonStore(Path(tmp) / "lessons.jsonl")
        ex = Executor(Gate(scope), FakeKali(), AuditLog(Path(tmp) / "a.jsonl"))
        sess = AssistSession("10.10.10.5", ex, StrategistAgent(StubLLM()), lessons=store)
        # metasploit isn't allowlisted -> DENY -> a lesson is learned
        sess.run("metasploit -x exploit")
        assert len(store) >= 1
        ref = sess._reference("metasploit")
        assert "LEARNED LESSONS" in ref and "metasploit" in ref.lower()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
