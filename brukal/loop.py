"""
loop.py — the grounded agentic loop (the "smarter copilot" engine).

This is the autonomous reason -> propose -> gate -> run -> OBSERVE -> re-plan
cycle. The word that matters is *grounded*: every proposal the strategist makes
is fed only what actually happened — the real, gate-executed tool output — never
a claimed or imagined result. That is what stops the two documented failure
modes of autonomous LLM pentesters: hallucinated success (the model "decides" it
got a shell) and aimless spinning (the model re-runs the same command forever).

How the loop stays honest and bounded:

  * **Grounding.** The loop reads the next step from `AssistSession.advise()`,
    which reasons over `session.notes` + `session.highlights` — and those are
    populated ONLY by `session.run()`, i.e. by real output from the governed
    executor. A step is "progress" only if a command actually executed through
    the gate. A lie in the model's prose can stop the loop (safe) but can never
    advance it (which would need a real, in-scope, gate-approved execution).

  * **No spinning.** A command the model re-proposes after it already ran, or a
    run of consecutive proposals that the gate blocks, ends the loop as
    `stalled` instead of looping.

  * **Clean hand-back.** The loop drives only the SAFE, autonomous part of the
    engagement. It pauses and returns control to the human on:
      - a MANUAL step (intrusive/interactive exploitation — the operator's job),
      - an ESCALATE decision (needs human sign-off; the loop never self-approves),
      - a stall (nothing new to safely do), or
      - the step budget.

  * **Containment is unchanged.** The loop touches the cage only through
    `session.run()` -> `Executor.run()` -> the gate. An out-of-scope proposal is
    DENIED and never executes, exactly as everywhere else. The loop adds
    autonomy; it removes none of the governance.

`GroundedLoop` is deliberately UI-free and deterministic (given a deterministic
model + FakeKali) so the evaluation harness can drive it to measure
steps-to-foothold and scope-violations (which are 0 by construction).
"""
from __future__ import annotations

from dataclasses import dataclass, field


def _norm_cmd(command: str | None) -> str:
    """Whitespace-normalised form of a command, for repeat detection."""
    return " ".join((command or "").split())


def _sig(command: str | None) -> tuple:
    """A coarse signature (tool + the host/URL/path-ish tokens, flags dropped) so
    near-duplicate commands — `nmap -sV -p 80 X` vs `nmap -sVC -p 80 X` — collapse to
    the same key. This is what stops a weak model cycling on trivially-different
    scans of the same target (observed live on Nexus)."""
    toks = _norm_cmd(command).split()
    if not toks:
        return ("", ())
    tool = toks[0].lower()
    targets = tuple(sorted(t for t in toks[1:]
                           if ("." in t or "/" in t) and not t.startswith("-")))
    return (tool, targets)


# Phase/goal -> specialist role. Checked in order (exploit before recon so a
# "probe the weakness" exploitation step routes to exploit, not recon); anything
# unmatched falls through to recon, the safe default (read-only enumeration).
_ROLE_KEYWORDS = (
    ("exploit", ("exploit", "attack", "foothold", "cred", "brute", "hydra", "rce",
                 "shell", "payload", "upload", "inject", "cve", "privesc",
                 "privilege", "escalat")),
    ("verify", ("verif", "confirm", "validate", "proof", "double-check")),
    ("recon", ("recon", "enum", "scan", "discover", "fingerprint", "map", "probe",
               "nmap", "gobuster", "ffuf", "whatweb")),
)


def _route_role(phase: str, goal: str) -> str:
    """Deterministically pick the specialist role for a planned step. No LLM here —
    a plain keyword match, so routing can't be prompt-injected by target text. The
    PHASE is the planner's authoritative signal, so it decides first (a
    'verification' step whose goal happens to mention a 'shell' is still verify);
    only an inconclusive phase falls back to keywords in the goal."""
    p = (phase or "").lower()
    if "verif" in p:
        return "verify"
    if any(k in p for k in ("exploit", "privesc", "privilege", "escalat",
                            "loot", "post-exp")):
        return "exploit"
    if any(k in p for k in ("recon", "enum", "discover", "scan", "fingerprint")):
        return "recon"
    # phase inconclusive -> fall back to keywords across phase + goal
    text = f"{p} {goal}".lower()
    for role, kws in _ROLE_KEYWORDS:
        if any(k in text for k in kws):
            return role
    return "recon"


@dataclass
class LoopStep:
    """One turn of the loop: what the model proposed and what really happened."""
    index: int
    phase: str
    goal: str
    rationale: str
    command: str | None
    verdict: str | None                       # gate verdict, if a command was judged
    executed: bool                            # did it actually run through the cage?
    summary: str                              # short digest of the outcome
    highlights: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class LoopResult:
    """The outcome of a whole autonomous run."""
    steps: list[LoopStep]
    stop_reason: str          # solved | manual | escalation | stalled | exhausted | done
    stop_detail: str

    @property
    def executed(self) -> int:
        return sum(1 for s in self.steps if s.executed)

    @property
    def blocked(self) -> int:
        return sum(1 for s in self.steps if s.verdict is not None and not s.executed)

    @property
    def paused_for_human(self) -> bool:
        return self.stop_reason in ("manual", "escalation")

    @property
    def solved(self) -> bool:
        """True only when a success condition was CONFIRMED from real gated output
        (never the model's prose)."""
        return self.stop_reason == "solved"


class GroundedLoop:
    """Drive an AssistSession autonomously over its safe, in-scope steps.

    Parameters
    ----------
    session   : the AssistSession (holds the executor, strategist, grounded state).
    max_steps : hard budget — hand back to the human after this many turns.
    max_stalls: how many consecutive *blocked* (non-executing) proposals to
                tolerate before giving up as `stalled`.
    observer  : optional observer(kind, payload) for live views. Pure telemetry —
                a broken observer can never change what the loop runs.
    """

    def __init__(self, session, *, max_steps: int = 20, max_stalls: int = 4,
                 max_similar: int = 4, max_coach: int = 3, observer=None, verifier=None,
                 agents=None, trust=None):
        self.session = session
        self._verifier = verifier             # optional Verifier: confirms 'solved'
        # Multi-agent mode: {role: agent} for recon/exploit/verify. When present, the
        # strategist stays the PLANNER (it sets the phase + goal each turn) but the
        # concrete command is generated by the phase's SPECIALIST agent, executed
        # through the SAME one door (session.run -> Executor.run -> gate). `trust` is
        # the shared TrustModel the gate reads, so a specialist's outcome updates its
        # T_i and modulates its future soft-risk scoring. Absent -> single-strategist
        # loop, unchanged.
        self._agents = dict(agents or {})
        self._trust = trust
        self.max_steps = max_steps
        self.max_stalls = max_stalls
        self.max_similar = max_similar        # how many near-duplicate moves to tolerate
        self.max_coach = max_coach            # coach a repeat this many times before stalling
        self._observer = observer
        self.steps: list[LoopStep] = []
        self._ran: set[str] = set()           # commands that have really executed
        self._sig_counts: dict = {}           # near-duplicate signature -> count
        self._stalls = 0                      # consecutive blocked proposals
        self._coach_streak = 0                # consecutive coached repeats without a new move
        self._probe_queue = None              # passive vuln probes to drain after the crawl

    def _emit(self, kind: str, **payload) -> None:
        if self._observer is not None:
            try:
                self._observer(kind, payload)
            except Exception:
                pass                          # a display error must not derail a run

    def _finish(self, reason: str, detail: str) -> LoopResult:
        result = LoopResult(steps=self.steps, stop_reason=reason, stop_detail=detail)
        self._emit("stop", reason=reason, detail=detail, result=result)
        return result

    def _check_solved(self, command, result, source):
        """If the REAL output of an executed command satisfies the success condition
        (a captured flag / verified foothold), finish as `solved` and promote the win
        to the trusted lesson store. Grounded: prose can never trigger this — only
        gate-executed output reaches here. Returns a LoopResult on solve, else None."""
        if self._verifier is None or result is None:
            return None
        verified = self._verifier.check(command, result, source)
        if verified is None:
            return None
        try:
            self.session.record_verified_success(verified)   # brain grows only on a confirmed win
        except Exception:
            pass                                             # promotion must never break the finish
        self._emit("solved", verified=verified)
        return self._finish(
            "solved", f"{verified.kind} verified from real gated output "
                      f"[{verified.source}] `{verified.command}`: {verified.evidence[:64]}")

    def run(self) -> LoopResult:
        """Run until a terminal condition and return the trace + why it stopped."""
        self._emit("start", target=self.session.target, budget=self.max_steps)

        while len(self.steps) < self.max_steps:
            # REFLEX 0: the FIRST time a web service is known, CRAWL it (bounded,
            # governed) to build the attack-surface map — forms, params, endpoints —
            # so every later decision reasons over the real site instead of guessing.
            # Runs once (surface stays set afterwards); each fetch still goes through
            # the gate, and it never leaves scope.
            if (self.session.surface is None
                    and getattr(self.session, "browser", None) is not None
                    and self.session.web_urls_from_findings()):
                self._emit("crawling", note="mapping the web attack surface")
                try:
                    surface = self.session.crawl(
                        observer=lambda kind, **p: self._emit("crawl", **p))
                except Exception:
                    surface = None
                if surface is not None and surface.pages:
                    step = LoopStep(
                        index=len(self.steps) + 1, phase="enumeration",
                        goal="map the web attack surface (governed crawl)",
                        rationale="a web port is open — crawling to enumerate forms, "
                                  "parameters and endpoints before probing",
                        command=f"CRAWL: {surface.seed}",
                        verdict="ALLOW", executed=True,
                        summary=surface.summary().splitlines()[0],
                        highlights=[("site-map", surface.summary().splitlines()[0])])
                    self.steps.append(step)
                    self._emit("step", step=step)
                    continue                     # re-plan with the full site map in hand

            # REFLEX 1: after the crawl, drain the PASSIVE vuln probes (whatweb /
            # nuclei / nikto against each mapped root) — one per turn so they interleave
            # with the live view and the step budget. Deterministic coverage the model
            # would forget; each still goes through the gate (these score reversible ->
            # auto-run). Active probes (sqlmap/dalfox) are NOT auto-run — they're offered
            # to the planner and ESCALATE for sign-off (or run under --full-send).
            surface = self.session.surface
            if surface is not None and surface.pages:
                if self._probe_queue is None:
                    self._probe_queue = [p for p in self.session.web_probes()
                                         if p.category == "passive"]
                if self._probe_queue:
                    probe = self._probe_queue.pop(0)
                    self._emit("running", action=probe.command, web=False, agent="recon",
                               phase="enumeration", goal=f"vuln probe ({probe.tool})")
                    decision, result, highlights = self.session.run(probe.command,
                                                                    agent="recon")
                    step = LoopStep(
                        index=len(self.steps) + 1, phase="enumeration",
                        goal=f"vuln probe ({probe.tool})", rationale=probe.rationale,
                        command=probe.command,
                        verdict=(decision.verdict if decision else "NOOP"),
                        executed=(result is not None),
                        summary=self._summarise(decision, result, highlights) if decision
                        else "probe could not run",
                        highlights=list(highlights))
                    self.steps.append(step)
                    self._emit("step", step=step)
                    if result is not None:
                        solved = self._check_solved(probe.command, result, "shell")
                        if solved is not None:
                            return solved
                        self._ran.add(_norm_cmd(probe.command))
                    continue                     # re-plan (or drain the next probe)

            # REFLEX: the moment a web service is found, look at the site with the
            # real browser (Chrome) — deterministic, still governed. This runs
            # before asking the model, so the rendered page feeds the next decision.
            reflex = self.session.auto_web_action()
            if reflex is not None:
                self._emit("running", action=f"WEB: {reflex}", web=True,
                           note="auto-render (web service found)")
                decision, result, highlights = self.session.run_web(reflex)
                step = LoopStep(
                    index=len(self.steps) + 1, phase="enumeration",
                    goal="look at the discovered web service (auto Chrome render)",
                    rationale="a web port is open — rendering the site to see what it hosts",
                    command=f"WEB: {reflex}",
                    verdict=(decision.verdict if decision else "NOOP"),
                    executed=(result is not None),
                    summary=self._summarise(decision, result, highlights) if decision
                    else "render could not run",
                    highlights=list(highlights))
                self.steps.append(step)
                self._emit("step", step=step)
                if result is not None:
                    solved = self._check_solved(f"WEB: {reflex}", result, "web")
                    if solved is not None:
                        return solved            # the rendered page contained the flag
                    continue                     # re-plan with the rendered page in hand

            self._emit("thinking")
            suggestion = self.session.advise()

            # The next action is a shell RUN or a WEB action (both governed). No
            # action -> either the operator's move (MANUAL) or nothing left to do.
            is_web = bool(suggestion.web and not suggestion.command)
            action = suggestion.command or suggestion.web
            if not action:
                if suggestion.manual:
                    return self._finish("manual", suggestion.manual)
                return self._finish("done", suggestion.goal or
                                    (suggestion.rationale or "").strip()[:160])

            # Multi-agent routing (only when agents are wired). The strategist has
            # PLANNED this step (phase + goal); the phase's SPECIALIST agent now
            # generates the concrete command with its own prompt + the SAME grounded
            # context. It runs through the same one door below (session.run), just
            # attributed to the specialist's role so per-agent trust applies. Web and
            # manual steps are never routed — those stay the strategist's/operator's.
            acting_agent = None
            if self._agents and not is_web and suggestion.command:
                role = _route_role(suggestion.phase, suggestion.goal)
                agent = self._agents.get(role)
                if agent is not None:
                    task = (suggestion.goal or suggestion.rationale
                            or "advance the engagement toward the flag")
                    task += (f"\n\nThe lead analyst suggests `{suggestion.command}` — "
                             f"refine or replace it with the single best {role} command.")
                    self._emit("thinking", agent=role, goal=suggestion.goal)
                    try:
                        req = agent.propose(task, self.session.plan_context())
                    except Exception:
                        req = None
                    if req is not None and (req.command or "").strip():
                        action = req.command          # the specialist's concrete command
                        acting_agent = role
                    elif self._trust is not None:
                        # specialist produced nothing valid -> a miss on its trust record
                        self._trust.record_outcome(role, request_valid=False,
                                                   decision=None, executed=False)

            # Grounding guard: a repeat or over-explored near-duplicate is NOT an
            # instant abort. COACH the model ("you already ran that — pick a
            # genuinely different move") and let it retry; only stall after it keeps
            # failing to produce a new move (real, repeated non-progress).
            sig = _sig(action)
            repeated = _norm_cmd(action) in self._ran
            over_similar = self._sig_counts.get(sig, 0) >= self.max_similar
            if repeated or over_similar:
                self._coach_streak += 1
                if self._coach_streak > self.max_coach:
                    what = ("already-run commands" if repeated
                            else f"near-duplicate `{sig[0]}` moves")
                    return self._finish(
                        "stalled", f"kept proposing {what} despite coaching "
                                   f"({self._coach_streak - 1} nudges) — no genuinely new move")
                coach = (
                    f"You already ran `{action}` and its result is in the findings — do "
                    f"NOT run it again. Choose a GENUINELY DIFFERENT next move: a "
                    f"different tool, port, path, or advance to the next phase."
                    if repeated else
                    f"You have already tried several `{sig[0]}` variants against this "
                    f"target with no new result. Switch approach — a different tool or "
                    f"the next phase, not another `{sig[0]}` tweak.")
                self.session.note(coach)
                self._emit("coached", action=action, note=coach,
                           streak=self._coach_streak)
                continue
            self._coach_streak = 0        # a genuinely new move — reset the coach counter

            # The one door: propose -> gate -> (maybe) run -> observe real output.
            self._emit("running", action=action, web=is_web, agent=acting_agent,
                       phase=suggestion.phase, goal=suggestion.goal)
            if is_web:
                decision, result, highlights = self.session.run_web(action)
            else:
                decision, result, highlights = self.session.run(
                    action, agent=acting_agent or "strategist")
            executed = result is not None
            verdict = decision.verdict if decision is not None else "NOOP"
            # Fold this outcome into the specialist's trust, so a role that keeps
            # getting blocked/denied draws more soft-risk scrutiny on its next move.
            if self._trust is not None and acting_agent is not None:
                self._trust.record_outcome(acting_agent, request_valid=True,
                                           decision=decision, executed=executed)
            step = LoopStep(
                index=len(self.steps) + 1,
                phase=suggestion.phase, goal=suggestion.goal,
                rationale=suggestion.rationale, command=action,
                verdict=verdict, executed=executed,
                summary=self._summarise(decision, result, highlights) if decision
                else "web action could not run",
                highlights=list(highlights),
            )
            self.steps.append(step)
            self._emit("step", step=step)

            if executed:
                solved = self._check_solved(action, result, "web" if is_web else "shell")
                if solved is not None:
                    return solved                # success CONFIRMED from real output
                self._ran.add(_norm_cmd(action))
                self._sig_counts[sig] = self._sig_counts.get(sig, 0) + 1
                self._stalls = 0
                continue

            # Not executed. ESCALATE needs human sign-off — the loop never
            # self-approves, so it pauses. A DENY/NOOP is fed back; a run of blocks
            # means it's stuck.
            if verdict == "ESCALATE":
                return self._finish("escalation", f"needs human sign-off: {action}")
            self._stalls += 1
            if self._stalls > self.max_stalls:
                reason = decision.reason if decision is not None else "web action could not run"
                return self._finish("stalled",
                                    f"{self._stalls} blocked proposals in a row (last: {reason})")

        return self._finish("exhausted", f"reached the {self.max_steps}-step budget")

    @staticmethod
    def _summarise(decision, result, highlights) -> str:
        if result is None:
            return f"{decision.verdict} — {decision.layer}: {decision.reason}"
        if highlights:
            return "; ".join(f"{tag}: {line}" for tag, line in highlights[:4])
        # shell results carry .stdout; web results carry .body
        raw = (getattr(result, "stdout", None) or getattr(result, "body", "") or "").strip()
        return (raw.splitlines()[0][:160] if raw else (getattr(result, "note", "") or "(no output)"))
