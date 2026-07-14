"""
test_parallel.py — the parallel multi-agent orchestrator + concurrency safety.

Proves that running agents concurrently does NOT weaken any invariant:
  * the hash-chained audit log stays valid under many concurrent appends;
  * the parallel orchestrator actually overlaps work (faster than sequential);
  * out-of-scope proposals are still DENIED under parallelism, and nothing
    out of scope executes.
"""
from __future__ import annotations

import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import (AuditLog, Executor, FakeKali, Gate, ParallelOrchestrator,
                    TaskTree, load_scope)
from brukal.blackboard import Blackboard

SCOPE = Path(__file__).resolve().parents[1] / "scope.json"


def test_concurrent_audit_appends_keep_the_chain_valid():
    tmp = tempfile.mkdtemp()
    audit = AuditLog(Path(tmp) / "a.jsonl")
    n_threads, per = 16, 25

    def worker(i):
        for j in range(per):
            audit.append("decision", {"who": i, "seq": j})

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert audit.verify()                                  # chain intact despite races
    lines = [l for l in (Path(tmp) / "a.jsonl").read_text().splitlines() if l.strip()]
    assert len(lines) == n_threads * per                   # no lost/overwritten records


class _SleepyAgent:
    """A stub agent whose run_task does real (sleepy) I/O through the gate, so we
    can prove concurrency by wall-clock and still exercise Executor + audit."""
    def __init__(self, executor, delay=0.2, command="nmap -sV 10.10.10.5"):
        self._ex = executor
        self._delay = delay
        self._command = command

    def run_task(self, description, context):
        time.sleep(self._delay)                            # stand in for an LLM + scan
        decision, result = self._ex.run(self._command, "10.10.10.5", agent="recon")
        request = {"command": self._command}
        return request, (decision, result)


def _engagement(agent, n_tasks=4, workers=4):
    tmp = tempfile.mkdtemp()
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tmp) / "audit.jsonl")
    executor = Executor(Gate(scope), FakeKali(), audit)
    bb = Blackboard(Path(tmp) / "vault", scope)
    tree = TaskTree()
    for i in range(n_tasks):
        tree.add(f"recon task {i}", "10.10.10.5", agent="recon")
    orch = ParallelOrchestrator(tree, {"recon": agent(executor)}, bb,
                                max_workers=workers)
    return orch, audit, tmp


def test_parallel_orchestrator_overlaps_work_and_stays_valid():
    delay, n = 0.2, 4
    orch, audit, _ = _engagement(lambda ex: _SleepyAgent(ex, delay=delay), n_tasks=n,
                                 workers=n)
    start = time.time()
    summary = orch.run()
    elapsed = time.time() - start

    assert summary["executed"] == n and summary["parallel"] is True
    # 4 tasks x 0.2s each: sequential would be >=0.8s; parallel should be well under.
    assert elapsed < delay * n * 0.75, f"not parallel enough: {elapsed:.2f}s"
    assert audit.verify()                                  # audit intact under parallelism


class _OutOfScopeAgent:
    def __init__(self, executor):
        self._ex = executor

    def run_task(self, description, context):
        # every agent tries to wander off-scope; the gate must stop all of them
        decision, result = self._ex.run("nmap -sV 8.8.8.8", "8.8.8.8", agent="recon")
        return {"command": "nmap -sV 8.8.8.8"}, (decision, result)


def test_parallel_still_denies_out_of_scope():
    orch, audit, _ = _engagement(_OutOfScopeAgent, n_tasks=6, workers=6)
    kali_executed = orch._agents["recon"]._ex._kali.executed
    summary = orch.run()
    assert summary["executed"] == 0 and summary["failed"] == 6   # all denied
    assert kali_executed == []                                    # nothing ran off-scope
    assert audit.verify()
