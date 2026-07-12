"""
blackboard.py — Milestone 4: the shared blackboard, backed by an Obsidian vault.

The blackboard is how agents share what they have learned WITHOUT pouring raw
tool output into each other's context. It is a directory (a folder Obsidian can
open) with a fixed shape:

    vault/
      scope/scope.md          read-only MIRROR of the engagement scope
      agents/<role>/          each agent writes its own DIGESTED findings here
      findings.jsonl          machine-readable append-only stream of all digests

Three properties matter for the paper's safety argument:

  * **Per-agent folders** — each agent owns a folder; agents read *scoped
    slices*, not the whole history (the context-loss fix).
  * **Digests, not dumps** — only short structured summaries are stored, so a
    huge nmap output never accumulates in anyone's context.
  * **Read-only scope mirror** — agents get a human-readable copy of the scope
    for situational awareness, but this file is NEVER read by the gate. Scope is
    enforced by the immutable `Scope` object alone (invariants 1 & 5). Editing
    the mirror — even to add a public IP — cannot widen what the gate allows.
    The mirror is therefore *reference*, never *authority*.

No language model lives here. This is plain file I/O over a directory.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .scope import Scope


def render_scope(scope: Scope) -> str:
    """A human/agent-readable rendering of the immutable scope."""
    nets = ", ".join(str(n) for n in scope.authorized_networks)
    tools = ", ".join(sorted(scope.allowlisted_tools))
    return (
        f"# Scope (read-only mirror)\n\n"
        f"- engagement: **{scope.engagement}**\n"
        f"- authorized networks: `{nets}`\n"
        f"- allowlisted tools: `{tools}`\n"
        f"- rate limit: {scope.rate_limit_per_min}/min\n\n"
        f"> ⚠️ READ-ONLY REFERENCE. The gate enforces the immutable `Scope`\n"
        f"> object loaded at startup — **not** this file. Editing this file\n"
        f"> cannot widen scope or authorise anything.\n"
    )


class Blackboard:
    """Directory-backed shared memory. `vault_dir` is a folder you can open in
    Obsidian; everything here is just files."""

    def __init__(self, vault_dir: str | Path, scope: Scope):
        self.root = Path(vault_dir)
        self._scope = scope
        (self.root / "agents").mkdir(parents=True, exist_ok=True)
        (self.root / "scope").mkdir(parents=True, exist_ok=True)
        self._findings_path = self.root / "findings.jsonl"
        # Resume-safe: continue the sequence past any notes a prior session wrote,
        # so re-opening a vault never overwrites earlier findings.
        self._seq = max((r.get("seq", 0) for r in self._read_findings()), default=0)
        self._write_scope_mirror()

    # -- scope mirror (reference only) -------------------------------------- #

    def _write_scope_mirror(self) -> None:
        path = self.root / "scope" / "scope.md"
        # A prior session may have left this 0o444; make it writable so RESUMING
        # a vault refreshes the mirror instead of crashing on a read-only file.
        if path.exists():
            try:
                os.chmod(path, 0o644)
            except OSError:
                pass
        path.write_text(render_scope(self._scope), encoding="utf-8")
        # Best-effort read-only on disk. Even where the filesystem ignores this
        # (e.g. Windows/DrvFs), the real guarantee is that the gate never reads
        # this file — so it cannot be a channel for widening scope.
        try:
            os.chmod(path, 0o444)
        except OSError:
            pass

    def scope_mirror_path(self) -> Path:
        return self.root / "scope" / "scope.md"

    # -- per-agent findings ------------------------------------------------- #

    def agent_dir(self, agent: str) -> Path:
        d = self.root / "agents" / agent
        d.mkdir(parents=True, exist_ok=True)
        return d

    def write_finding(self, agent: str, finding: dict) -> None:
        """Record one DIGESTED finding for `agent`. Stored both as a readable
        markdown note in the agent's folder and appended to the shared JSONL
        stream. `finding` is expected to be a short summary, never a raw dump."""
        self._seq += 1
        record = {"ts": time.time(), "seq": self._seq, "agent": agent, **finding}

        # machine-readable shared stream (append-only)
        with self._findings_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

        # human-readable per-agent note (seq guarantees a unique filename)
        note = self.agent_dir(agent) / f"{self._seq:05d}.md"
        target = finding.get("target", "")
        summary = finding.get("summary", "")
        command = finding.get("command", "")
        note.write_text(
            f"# {agent} finding — {target}\n\n"
            f"- task: {finding.get('task', '')}\n"
            f"- command: `{command}`\n"
            f"- verdict: {finding.get('verdict', '')}\n\n"
            f"{summary}\n",
            encoding="utf-8",
        )

    def _read_findings(self) -> list[dict]:
        if not self._findings_path.exists():
            return []
        out: list[dict] = []
        for line in self._findings_path.read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def all_findings(self, target: str | None = None) -> list[dict]:
        """Every digested finding (optionally filtered to one target), oldest
        first. Used to RESUME a session with the memory of prior ones."""
        recs = self._read_findings()
        return [r for r in recs if target is None or r.get("target") == target]

    def write_page(self, filename: str, markdown: str) -> None:
        """Write a human-readable page (plan, engagement notebook) at the vault
        root. Plain file I/O — no authority, just a note a human can open."""
        (self.root / filename).write_text(markdown, encoding="utf-8")

    def read_page(self, filename: str) -> str:
        path = self.root / filename
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def read_context(self, agent: str, target: str, limit: int = 5) -> str:
        """Return a SCOPED slice of prior findings relevant to `target` — the
        most recent `limit`, as short text — NOT the whole history. This is the
        deliberate anti-context-bloat read: an agent sees only what is relevant
        to the task in front of it."""
        if not self._findings_path.exists():
            return ""
        relevant: list[dict] = []
        for line in self._findings_path.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("target") == target:
                relevant.append(rec)
        relevant = relevant[-limit:]
        if not relevant:
            return ""
        lines = [f"Prior findings for {target} (most recent {len(relevant)}):"]
        for rec in relevant:
            lines.append(f"- [{rec.get('agent')}] {rec.get('summary', '')}")
        return "\n".join(lines)

    def save_task_tree(self, markdown: str) -> None:
        (self.root / "task_tree.md").write_text(markdown, encoding="utf-8")
