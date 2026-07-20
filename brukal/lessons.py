"""
lessons.py — Brukal's cross-session memory, as a TWO-TIER store so the "brain"
grows only from VERIFIED experience.

  * CANDIDATE pool — anything tried/observed. Recorded, but NEVER retrieved for
    planning. A candidate cannot influence what the model proposes, so a wrong or
    injected "lesson" cannot poison future engagements just by being written.
  * TRUSTED store — retrievable; injected into planning. A lesson reaches here only
    by promotion, and a "win" (an action that worked) is promoted ONLY after a
    verification step confirmed it, with provenance (target/service/command/verified
    outcome/when). Optional BRUKAL_LESSON_REVIEW=1 requires human sign-off first.

Pitfalls derived from the gate's OWN deterministic decision (not-allowlisted,
injection, scope, timeout) are trusted-by-construction — they come from our command
+ the gate's ruling, never from target output (invariant 1/3), and they are
avoidance guidance, not action suggestions.

Everything here is DATA. Lessons are reloaded read-only and injected clearly
labelled as guidance; no lesson can widen scope or change gate/tool policy — the
deterministic gate rules on every action regardless of what any lesson says.

Persisted as JSONL in the vault (trusted + candidate files) so it survives across
sessions and travels with the bind-mounted cage.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

_WORD = re.compile(r"[a-z0-9][a-z0-9.\-]+")
_MAX_LESSONS = 500          # cap per tier; evict the least-reinforced when full


@dataclass
class Lesson:
    text: str                       # the generalised lesson, one line
    tags: list[str] = field(default_factory=list)   # tool / tech / failure-mode
    kind: str = "tactic"            # "pitfall" | "tactic" | "win"
    hits: int = 1                   # times reinforced (confidence)
    ts: float = field(default_factory=time.time)
    tier: str = "candidate"         # "candidate" (not retrieved) | "trusted" (retrieved)
    provenance: dict = field(default_factory=dict)  # target/service/command/outcome/when

    def signature(self) -> str:
        """Identity for de-duplication: kind + sorted tags (not the exact text,
        so re-phrasings of the same lesson reinforce rather than duplicate)."""
        return self.kind + "|" + ",".join(sorted(t.lower() for t in self.tags))


def _tool_of(command: str) -> str:
    parts = (command or "").split()
    return os.path.basename(parts[0]).lower() if parts else ""


def _result_text(result) -> str:
    """Output text of a result, whether a shell ExecResult (.stdout) or a web
    WebResult (.body)."""
    return getattr(result, "stdout", None) or getattr(result, "body", "") or ""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class LessonStore:
    """A two-tier, growing, retrievable store of learned lessons, JSONL-backed.
    Retrieval draws ONLY from the trusted tier."""

    def __init__(self, path: str | Path):
        self.path = Path(path)                    # TRUSTED file (back-compat)
        self._cand_path = self.path.parent / (self.path.stem + ".candidates" + self.path.suffix)
        self._trusted: list[Lesson] = []
        self._candidates: list[Lesson] = []
        self._load()

    # -- persistence -------------------------------------------------------- #

    def _load_file(self, p: Path, default_tier: str) -> None:
        if not p.exists():
            return
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                kind = d.get("kind", "tactic")
                # honour a stored tier; else default (a win with no tier -> candidate,
                # so old wins stop feeding planning until verified — the safe migration).
                tier = d.get("tier") or ("candidate" if kind == "win" else default_tier)
                lesson = Lesson(text=d["text"], tags=list(d.get("tags", [])), kind=kind,
                                hits=int(d.get("hits", 1)),
                                ts=float(d.get("ts", time.time())), tier=tier,
                                provenance=dict(d.get("provenance", {})))
                (self._trusted if tier == "trusted" else self._candidates).append(lesson)
            except Exception:
                continue        # a corrupt line is skipped, never fatal

    def _load(self) -> None:
        self._load_file(self.path, "trusted")
        self._load_file(self._cand_path, "candidate")

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for p, lessons in ((self.path, self._trusted), (self._cand_path, self._candidates)):
            tmp = p.with_suffix(p.suffix + ".tmp")
            tmp.write_text("\n".join(json.dumps(asdict(l)) for l in lessons) + "\n",
                           encoding="utf-8")
            tmp.replace(p)

    @property
    def _lessons(self) -> list[Lesson]:
        """Combined read-only view of both tiers (for inspection / CLI listing)."""
        return self._trusted + self._candidates

    def __len__(self) -> int:
        return len(self._trusted) + len(self._candidates)

    # -- writing ------------------------------------------------------------ #

    def add(self, text: str, tags, kind: str = "tactic", tier: str | None = None) -> Lesson:
        """Record a lesson into a tier, reinforcing (bumping hits) an existing one
        with the same signature in that tier instead of duplicating it. Default tier:
        a 'win' is a CANDIDATE (needs verification); a pitfall/tactic is TRUSTED
        (gate-derived avoidance guidance, safe by construction)."""
        if tier is None:
            tier = "candidate" if kind == "win" else "trusted"
        lst = self._trusted if tier == "trusted" else self._candidates
        lesson = Lesson(text=text.strip(), tags=[t.lower() for t in tags if t],
                        kind=kind, tier=tier)
        for existing in lst:
            if existing.signature() == lesson.signature():
                existing.hits += 1
                existing.ts = time.time()
                if len(text) > len(existing.text):
                    existing.text = text.strip()      # keep the clearer phrasing
                self._save()
                return existing
        lst.append(lesson)
        if len(lst) > _MAX_LESSONS:                    # evict least-reinforced in this tier
            lst.sort(key=lambda l: (l.hits, l.ts))
            del lst[:-_MAX_LESSONS]
        self._save()
        return lesson

    def learn_from_outcome(self, command: str, decision, result, tech_tags=None) -> None:
        """Derive a lesson from one command's real outcome. Pitfalls (gate-derived)
        go to the TRUSTED tier; a 'win' goes to the CANDIDATE pool and is NOT
        retrievable until a verification step promotes it."""
        tech_tags = [t.lower() for t in (tech_tags or [])]
        tool = _tool_of(command)
        layer = getattr(decision, "layer", "") or ""

        if result is not None:
            timed_out = (getattr(result, "returncode", 0) == 124
                         or "timed out" in (getattr(result, "stderr", "") or "").lower())
            if timed_out and tool:
                self.add(f"`{tool}` with broad options times out in the cage — run a "
                         f"faster, narrower variant first.", [tool, "timeout"], "pitfall")
            elif _result_text(result).strip() and tech_tags and tool:
                # a productive move is only a CANDIDATE — "productive" != "verified".
                self.add(f"`{tool}` was productive against {'/'.join(tech_tags[:3])}.",
                         [tool, *tech_tags], "win")
            return

        # not executed -> a gate block; learn what to avoid (trusted, gate-derived)
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

    # -- promotion (candidate -> trusted, verified only) -------------------- #

    def _review_ok(self, reviewed) -> bool:
        """When BRUKAL_LESSON_REVIEW is set, a promotion needs explicit human sign-off
        (reviewed=True). Otherwise verification alone suffices."""
        return (not os.environ.get("BRUKAL_LESSON_REVIEW")) or bool(reviewed)

    def promote(self, signature: str, *, target: str = "", service: str = "",
                command: str = "", outcome: str = "", verified: bool = False,
                reviewed=None) -> bool:
        """Promote a CANDIDATE with this signature to the TRUSTED tier — ONLY when
        `verified` is True (the verification step confirmed it worked) and, if
        BRUKAL_LESSON_REVIEW is set, `reviewed` is True. Attaches provenance. Returns
        True on promotion, False if withheld (unverified / awaiting review / no match)."""
        if not verified or not self._review_ok(reviewed):
            return False
        for i, c in enumerate(self._candidates):
            if c.signature() == signature:
                c.tier = "trusted"
                c.provenance = {"target": target, "service": service, "command": command,
                                "outcome": outcome, "verified_at": _now()}
                self._candidates.pop(i)
                for t in self._trusted:               # merge if already present
                    if t.signature() == c.signature():
                        t.hits += c.hits
                        self._save()
                        return True
                self._trusted.append(c)
                self._save()
                return True
        return False

    def record_verified_success(self, *, target: str, service: str, command: str,
                                outcome: str, tags, text: str | None = None,
                                reviewed=None) -> Lesson | None:
        """Called by the verification step when an action is CONFIRMED to have worked.
        Records a 'win' as TRUSTED with provenance — unless BRUKAL_LESSON_REVIEW is set
        and not yet reviewed, in which case it is held as a candidate awaiting sign-off."""
        tool = _tool_of(command)
        body = text or f"`{tool}` worked against {service} — {outcome}.".strip()
        if not self._review_ok(reviewed):
            return self.add(body, list(tags), "win", tier="candidate")
        lesson = self.add(body, list(tags), "win", tier="trusted")
        lesson.provenance = {"target": target, "service": service, "command": command,
                             "outcome": outcome, "verified_at": _now()}
        self._save()
        return lesson

    # -- reading (TRUSTED tier only) ---------------------------------------- #

    def retrieve(self, query: str, limit: int = 4) -> list[Lesson]:
        """The most relevant TRUSTED lessons for the query. Candidates are NEVER
        returned — they cannot influence planning."""
        q = set(_WORD.findall((query or "").lower()))
        if not q or not self._trusted:
            return []
        scored: list[tuple[float, Lesson]] = []
        for l in self._trusted:
            tagset = {t.lower() for t in l.tags}
            textset = set(_WORD.findall(l.text.lower()))
            score = 3 * len(q & tagset) + len(q & textset)
            if score:
                scored.append((score + min(l.hits, 5) * 0.1, l))   # confidence tiebreak
        scored.sort(key=lambda x: (-x[0], -x[1].hits))
        return [l for _, l in scored[:limit]]

    def context_for(self, query: str, limit: int = 4) -> str:
        """Render the most relevant TRUSTED lessons as a labelled guidance block. This
        is DATA the model may use to propose; the gate still rules on every action and
        no lesson can widen scope or change tools."""
        hits = self.retrieve(query, limit)
        if not hits:
            return ""
        lines = ["LEARNED LESSONS (Brukal's own VERIFIED experience — guidance only; "
                 "the gate still rules on every action, and no lesson can widen scope "
                 "or change tools):"]
        icon = {"pitfall": "avoid", "win": "worked", "tactic": "tip"}
        for l in hits:
            lines.append(f"- [{icon.get(l.kind, 'tip')}] {l.text}")
        return "\n".join(lines)
