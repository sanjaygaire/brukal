"""
test_tui.py — the live dashboard's observer hook and rendering.

The orchestrator emits fire-and-forget events; the dashboard is a pure observer.
We prove the events are emitted (core, no rich) and that the dashboard renders
its state to text (needs rich). A broken/absent observer never affects the run.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, TaskTree, TrustModel, load_scope

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"


class StubLLM:
    def __init__(self, responses):
        self._responses = list(responses)

    def propose(self, system, user, max_tokens=1024):
        return self._responses.pop(0) if self._responses else ""


def _req(command, target):
    return json.dumps({"proposing_agent": "recon", "intent": "enumerate",
                       "command": command, "target_host": target, "justification": "t"})


def test_orchestrator_emits_observer_events():
    pytest.importorskip("pydantic")
    from brukal import Blackboard, Orchestrator
    from brukal.agents import ReconAgent

    scope = load_scope(SCOPE)
    tmp = tempfile.mkdtemp()
    try:
        events = []
        executor = Executor(Gate(scope), FakeKali(), AuditLog(Path(tmp) / "a.jsonl"))
        recon = ReconAgent(StubLLM([_req("nmap -sV 10.10.10.5", "10.10.10.5")]), executor)
        bb = Blackboard(Path(tmp) / "vault", scope)
        tree = TaskTree()
        tree.add("enumerate services", "10.10.10.5", agent="recon")

        Orchestrator(tree, {"recon": recon}, bb,
                     observer=lambda kind, payload: events.append((kind, payload))).run()

        kinds = [k for k, _ in events]
        assert kinds[0] == "start" and kinds[-1] == "end"
        assert "turn" in kinds
        turn = next(p for k, p in events if k == "turn")
        assert turn["decision"].verdict == "ALLOW"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_broken_observer_never_derails_the_run():
    pytest.importorskip("pydantic")
    from brukal import Blackboard, Orchestrator, TaskStatus
    from brukal.agents import ReconAgent

    scope = load_scope(SCOPE)
    tmp = tempfile.mkdtemp()
    try:
        executor = Executor(Gate(scope), FakeKali(), AuditLog(Path(tmp) / "a.jsonl"))
        recon = ReconAgent(StubLLM([_req("nmap -sV 10.10.10.5", "10.10.10.5")]), executor)
        bb = Blackboard(Path(tmp) / "vault", scope)
        tree = TaskTree()
        tree.add("enumerate", "10.10.10.5", agent="recon")

        def boom(kind, payload):
            raise RuntimeError("display exploded")

        summary = Orchestrator(tree, {"recon": recon}, bb, observer=boom).run()
        assert summary["executed"] == 1                    # the run finished fine
        assert tree.all_tasks()[0].status == TaskStatus.DONE
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_dashboard_renders_state_to_text():
    pytest.importorskip("rich")
    from rich.console import Console

    from brukal.tui import Dashboard

    tree = TaskTree()
    tree.add("enumerate services", "10.10.10.5", agent="recon")
    tree.add("probe weakness", "10.10.10.5", agent="exploit")
    dash = Dashboard("brukal-lab", "10.10.10.5", "fake", tree, TrustModel(), n_skills=55)

    con = Console(record=True, width=110)
    con.print(dash._render())
    out = con.export_text()
    assert "BRUKAL" in out
    assert "recon" in out and "exploit" in out
    assert "trust" in out and "task tree" in out
