"""
test_verify.py — the verification step: 'solved' is CONFIRMED, never claimed.

Proves a success ends the loop as `solved` ONLY when a flag/foothold appears in the
REAL output of a gate-executed command, that a prose claim never counts, and that a
verified success promotes a trusted lesson (the brain grows only from confirmed wins).
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import ExecResult
from brukal.lessons import LessonStore
from brukal.loop import GroundedLoop
from brukal.verify import SuccessCondition, Verifier

SCOPE = Path(__file__).resolve().parents[1] / "scope.json"
_FLAG = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"


class SeqLLM:
    def __init__(self, responses): self.responses = list(responses); self.i = 0
    def propose(self, system, user, max_tokens=1024):
        r = self.responses[min(self.i, len(self.responses) - 1)]; self.i += 1; return r


def _adv(goal, run=None, manual=None, phase="recon"):
    lines = [f"PHASE: {phase}", f"GOAL: {goal}", f"REASONING: {goal}."]
    if run:
        lines.append(f"RUN: {run}")
    if manual:
        lines.append(f"MANUAL: {manual}")
    return "\n".join(lines)


class FlagKali:
    """A cage stand-in that returns a flag ONLY for a flag-reading command."""
    def __init__(self): self.executed = []
    def run(self, command):
        self.executed.append(command)
        if "flag" in command or "user.txt" in command:
            return ExecResult(command, 0, f"{_FLAG}\n", "")
        return ExecResult(command, 0, "80/tcp open http nginx", "")


def _session(responses, kali, tmp, lessons=None):
    ex = Executor(Gate(load_scope(SCOPE)), kali, AuditLog(Path(tmp) / "a.jsonl"))
    return AssistSession("10.10.10.5", ex, StrategistAgent(SeqLLM(responses)), lessons=lessons)


# -- unit: the Verifier ------------------------------------------------------

def test_verifier_matches_flag_alone_on_a_line_only():
    v = Verifier()
    assert v.check("cat user.txt", ExecResult("x", 0, f"{_FLAG}\n", "")).kind == "flag"
    # a 32-hex EMBEDDED in a line (e.g. an MD5 in a table) must NOT count as a flag
    assert v.check("nmap", ExecResult("x", 0, f"hash: {_FLAG} file.bak", "")) is None
    # prose / no real output never verifies
    assert v.check("cat", None) is None
    assert v.check("echo", ExecResult("x", 0, "we definitely got the flag, trust me", "")) is None


def test_verifier_confirms_foothold_evidence():
    v = Verifier()
    got = v.check("id", ExecResult("x", 0, "uid=0(root) gid=0(root) groups=0(root)", ""))
    assert got is not None and got.kind == "foothold"


def test_flag_pattern_is_configurable(monkeypatch):
    monkeypatch.setenv("BRUKAL_FLAG_PATTERN", r"HTB\{[^}]+\}")
    v = Verifier(SuccessCondition.from_env())
    assert v.check("cat", ExecResult("x", 0, "HTB{pwned_the_box}", "")).evidence == "HTB{pwned_the_box}"


# -- loop integration --------------------------------------------------------

def test_loop_ends_solved_when_a_flag_appears_in_real_output():
    tmp = tempfile.mkdtemp()
    try:
        store = LessonStore(Path(tmp) / "lessons.jsonl")
        kali = FlagKali()
        sess = _session([
            "1. [recon] scan",
            _adv("read the flag", run="curl http://10.10.10.5/flag.txt"),
        ], kali, tmp, lessons=store)
        sess.make_plan()
        result = GroundedLoop(sess, verifier=Verifier()).run()

        assert result.stop_reason == "solved" and result.solved is True
        assert _FLAG in result.stop_detail
        # the brain grew: a VERIFIED win was promoted to the trusted store
        assert store.retrieve("curl") and store._trusted
        assert store._trusted[0].kind == "win" and store._trusted[0].provenance["target"] == "10.10.10.5"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_loop_does_not_solve_on_a_prose_claim():
    tmp = tempfile.mkdtemp()
    try:
        store = LessonStore(Path(tmp) / "lessons.jsonl")
        kali = FlagKali()
        sess = _session([
            "1. [recon] scan",
            _adv("scan services", run="nmap -sV 10.10.10.5"),      # real output, NO flag
            _adv("we captured the flag!", manual="the flag is ours"),  # prose-only claim
        ], kali, tmp, lessons=store)
        sess.make_plan()
        result = GroundedLoop(sess, verifier=Verifier()).run()

        assert result.stop_reason == "manual" and result.solved is False   # handed off, not solved
        assert not store._trusted                                          # no verified win promoted
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_no_verifier_means_no_solved_stop():
    # without a verifier the loop behaves exactly as before (no 'solved')
    tmp = tempfile.mkdtemp()
    try:
        kali = FlagKali()
        sess = _session([
            "1. [recon] scan",
            _adv("read flag", run="curl http://10.10.10.5/flag.txt"),
            _adv("done", manual="wrap up"),
        ], kali, tmp)
        sess.make_plan()
        result = GroundedLoop(sess).run()          # no verifier
        assert result.stop_reason != "solved"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
