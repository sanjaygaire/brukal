"""
test_cage_tools.py — grounding the planner in the cage's REAL toolset.

A live DeepSeek run wasted five turns inventing `git-dumper` invocations
(`git-dumper`, `python3 /opt/git-tools/git-dumper.py`, ...) — a tool the cage does
not have, while `git` and `curl` (which it does have) sat unused. `_probe_cage_tools`
asks the cage once (read-only `which`) what is installed, and `_reference` leads the
planner with that list so it stops guessing. Introspects OUR cage, not the target;
the agent never receives the kali, only the list.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession, _probe_cage_tools
from brukal.kali import ExecResult

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "scope.json"


class _WhichKali:
    """Returns a canned `which` result: only the listed tools have a path."""
    def __init__(self, present):
        self.present = present
    def run(self, command: str) -> ExecResult:
        out = "\n".join(f"/usr/bin/{t}" for t in self.present)
        return ExecResult(command, 0, out, "")


class _NullLLM:
    def propose(self, system, user, max_tokens=1024):
        return ""


def _session():
    scope = load_scope(FIXTURE)
    ex = Executor(Gate(scope), FakeKali(),
                  AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl"))
    return AssistSession("10.10.10.5", ex, StrategistAgent(_NullLLM()))


def test_probe_returns_only_installed_candidates():
    kali = _WhichKali(["nmap", "sqlmap", "git", "curl"])
    found = _probe_cage_tools(kali)
    assert set(found) == {"nmap", "sqlmap", "git", "curl"}
    assert "git-dumper" not in found          # the tool the model kept guessing


def test_probe_ignores_non_candidate_paths():
    # A path whose basename isn't a candidate (e.g. a shell builtin echoed) is dropped.
    kali = _WhichKali(["nmap", "definitely-not-a-pentest-tool"])
    assert _probe_cage_tools(kali) == ["nmap"]


def test_probe_is_best_effort_on_failure():
    class _Boom:
        def run(self, command):
            raise RuntimeError("cage down")
    assert _probe_cage_tools(_Boom()) == []


def test_reference_leads_with_installed_tools():
    sess = _session()
    sess.cage_tools = ["nmap", "sqlmap", "git"]
    ref = sess._reference("")
    assert "CAGE TOOLS INSTALLED" in ref
    assert "nmap, sqlmap, git" in ref
    assert "NOT installed" in ref              # the constraint the model must honour


def test_reference_has_no_tools_section_when_unprobed():
    sess = _session()                          # cage_tools defaults to []
    assert "CAGE TOOLS INSTALLED" not in sess._reference("")
