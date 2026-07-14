"""
lessons.py — Brukal's cross-session memory: what worked, what failed, what to
avoid. This is how Brukal *learns over time* rather than repeating the same
mistakes on every engagement.

Where the skill packs (`skills.py`) are STATIC, untrusted reference, lessons are
Brukal's OWN accumulated experience, derived automatically from real outcomes:

  * a command that TIMED OUT      -> "prefer a faster/narrower variant"
  * a tool DENIED (not allowlisted) -> "use an allowlisted equivalent instead"
  * a shell-injection DENY        -> "run one tool, no pipes/redirects/backticks"
  * a productive move (findings)  -> "<tool> surfaced <what> on <tech>"

Lessons are tagged (by tool / tech / failure-mode) and retrieved for the current
context, so the relevant ones are injected into the strategist's prompt on the
next engagement. They are safe to trust: each lesson is derived from *our own
command and the gate's deterministic decision*, never from raw target output, so
a hostile target cannot write a lesson (invariant 1/3 preserved at the memory
layer too).

Persisted as JSONL in the vault so it survives across sessions and — with the
vault bind-mounted into the cage — travels with the cage.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

_WORD = re.compile(r"[a-z0-9][a-z0-9.\-]+")
_MAX_LESSONS = 500          # cap the store; evict the least-reinforced when full


@dataclass
class Lesson:
    text: str                       # the generalised lesson, one line
    tags: list[str] = field(default_factory=list)   # tool / tech / failure-mode
    kind: str = "tactic"            # "pitfall" | "tactic" | "win"
    hits: int = 1                   # times reinforced (confidence)
    ts: float = field(default_factory=time.time)

    def signature(self) -> str:
        """Identity for de-duplication: kind + sorted tags (not the exact text,
        so re-phrasings of the same lesson reinforce rather than duplicate)."""
        return self.kind + "|" + ",".join(sorted(t.lower() for t in self.tags))


def _tool_of(command: str) -> str:
    parts = (command or "").split()
    return os.path.basename(parts[0]).lower() if parts else ""


class LessonStore:
    """A small, growing, retrievable store of learned lessons, JSONL-backed."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lessons: list[Lesson] = []
        self._load()

    # -- persistence -------------------------------------------------------- #

    def _load(self) -> None:
        if not self.path.exists():
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                self._lessons.append(Lesson(text=d["text"], tags=list(d.get("tags", [])),
                                            kind=d.get("kind", "tactic"),
                                            hits=int(d.get("hits", 1)),
                                            ts=float(d.get("ts", time.time()))))
            except Exception:
                continue        # a corrupt line is skipped, never fatal

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text("\n".join(json.dumps(asdict(l)) for l in self._lessons) + "\n",
                       encoding="utf-8")
        tmp.replace(self.path)

    def __len__(self) -> int:
        return len(self._lessons)

    # -- writing ------------------------------------------------------------ #

    def add(self, text: str, tags, kind: str = "tactic") -> Lesson:
        """Record a lesson, reinforcing (bumping hits) an existing one with the
        same signature instead of duplicating it."""
        lesson = Lesson(text=text.strip(), tags=[t.lower() for t in tags if t], kind=kind)
        for existing in self._lessons:
            if existing.signature() == lesson.signature():
                existing.hits += 1
                existing.ts = time.time()
                if len(text) > len(existing.text):
                    existing.text = text.strip()      # keep the clearer phrasing
                self._save()
                return existing
        self._lessons.append(lesson)
        if len(self._lessons) > _MAX_LESSONS:          # evict least-reinforced
            self._lessons.sort(key=lambda l: (l.hits, l.ts))
            self._lessons = self._lessons[-_MAX_LESSONS:]
        self._save()
        return lesson

    def learn_from_outcome(self, command: str, decision, result, tech_tags=None) -> None:
        """Derive a generalisable lesson from one command's real outcome. Called
        after every gated run so the store grows with experience."""
        tech_tags = [t.lower() for t in (tech_tags or [])]
        tool = _tool_of(command)
        verdict = getattr(decision, "verdict", "")
        layer = getattr(decision, "layer", "") or ""

        if result is not None:
            timed_out = (getattr(result, "returncode", 0) == 124
                         or "timed out" in (getattr(result, "stderr", "") or "").lower())
            if timed_out and tool:
                self.add(f"`{tool}` with broad options times out in the cage — run a "
                         f"faster, narrower variant first.", [tool, "timeout"], "pitfall")
            elif (result.stdout or "").strip() and tech_tags and tool:
                self.add(f"`{tool}` was productive against {'/'.join(tech_tags[:3])}.",
                         [tool, *tech_tags], "win")
            return

        # not executed -> a gate block; learn what to avoid
        if "allowlist" in layer and tool:
            self.add(f"`{tool}` is not in the allowlist — use an allowlisted "
                     f"equivalent instead of `{tool}`.", [tool, "not-allowlisted"], "pitfall")
        elif "injection" in layer:
            self.add("Shell metacharacters (| > < ; && `backticks` $()) are rejected — "
                     "run a single tool with no shell features.", ["injection", "shell"],
                     "pitfall")
        elif "scope" in layer:
            self.add("Stay on the authorised host — out-of-scope targets are always "
                     "denied.", ["scope"], "pitfall")

    # -- reading ------------------------------------------------------------ #

    def retrieve(self, query: str, limit: int = 4) -> list[Lesson]:
        q = set(_WORD.findall((query or "").lower()))
        if not q or not self._lessons:
            return []
        scored: list[tuple[float, Lesson]] = []
        for l in self._lessons:
            tagset = {t.lower() for t in l.tags}
            textset = set(_WORD.findall(l.text.lower()))
            score = 3 * len(q & tagset) + len(q & textset)
            if score:
                scored.append((score + min(l.hits, 5) * 0.1, l))   # confidence tiebreak
        scored.sort(key=lambda x: (-x[0], -x[1].hits))
        return [l for _, l in scored[:limit]]

    def context_for(self, query: str, limit: int = 4) -> str:
        """Render the most relevant learned lessons as a trusted guidance block for
        the strategist (these are Brukal's own experience, not untrusted input)."""
        hits = self.retrieve(query, limit)
        if not hits:
            return ""
        lines = ["LEARNED LESSONS (Brukal's own experience from past engagements — "
                 "apply them; they are trusted guidance):"]
        icon = {"pitfall": "avoid", "win": "worked", "tactic": "tip"}
        for l in hits:
            lines.append(f"- [{icon.get(l.kind, 'tip')}] {l.text}")
        return "\n".join(lines)
