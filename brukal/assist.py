"""
assist.py — human-assisted box solving (v1): a governed pentest copilot.

The operator drives a menu-driven loop. The strategist proposes the next move;
the operator picks an option — run the suggested command (through the gate/cage),
run a different one, record a MANUAL step they did themselves, add a note, or ask
a question. Brukal reasons + records; the human does the ungoverned exploitation
on their own authority. Everything Brukal runs still goes through Executor.run().

A spinner shows while the strategist is thinking or a command is running (long
scans no longer look frozen). Escalations pause the spinner, prompt, and resume.

`AssistSession` holds the testable logic; `run_solve` assembles it and drives the
rich menu UI (falling back to a plain prompt if `rich` is unavailable).
"""
from __future__ import annotations

import getpass
import os
import re
import sys
from pathlib import Path

from .audit import AuditLog
from .executor import Executor
from .gate import Gate
from .kali import DockerKali, FakeKali
from .scope import load_scope
from .trust import TrustModel

_VERDICT_COLOUR = {"ALLOW": "green", "ESCALATE": "yellow", "DENY": "red"}
_PHASE_COLOUR = {"recon": "cyan", "enumeration": "cyan", "exploitation": "magenta",
                 "privilege-escalation": "red", "looting": "yellow"}

# Patterns that mark a line as an important RESULT worth surfacing to the operator.
_HIGHLIGHTS = [
    (re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+open\s+(\S+)(.*)$", re.I), "open port"),
    (re.compile(r"\b(200|301|302|401|403)\b.*(/\S*)", re.I), "web path"),
    (re.compile(r"(user(?:name)?|login|account)\s*[:=]\s*(\S+)", re.I), "credential"),
    (re.compile(r"(pass(?:word)?)\s*[:=]\s*(\S+)", re.I), "credential"),
    (re.compile(r"\b([a-f0-9]{32}|[a-f0-9]{40}|\$[0-9a-z]{1,3}\$\S+)\b", re.I), "hash"),
    (re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.I), "CVE"),
    (re.compile(r"(anonymous|guest)\s+(login|access|allowed)", re.I), "anon access"),
    (re.compile(r"(disallow|robots|/admin|/backup|\.git|\.env|phpmyadmin)", re.I), "interesting"),
]


# Open web-service ports in an nmap highlight line ("80/tcp open http ...").
_WEB_PORT_RE = re.compile(r"(\d{1,5})/tcp\s+open\s+(\S+)", re.I)

# Services / technologies worth pulling a red-team playbook for, mined from the
# highlights so skill retrieval follows what we've actually discovered on the box.
_TECH_HINTS = re.compile(
    r"\b(http|https|ssh|ftp|smtp|smb|nfs|rpc|snmp|dns|ldap|kerberos|rdp|winrm|"
    r"nginx|apache|tomcat|iis|jetty|node|express|php|jsp|aspx|python|ruby|"
    r"mysql|mssql|postgres|postgresql|oracle|redis|mongodb|memcached|elastic|"
    r"wordpress|drupal|joomla|jenkins|gitlab|jira|confluence|struts|spring|"
    r"api|graphql|jwt|oauth|saml|upload|login|admin|cms|webdav|cgi)\b", re.I)


def _outcome_feedback(decision, result, raw: str) -> str:
    """Digest an executed command's outcome into a note the strategist can learn
    from — a timeout or empty result becomes an explicit 'do it differently' cue."""
    timed_out = (getattr(result, "returncode", 0) == 124
                 or "timed out" in (getattr(result, "stderr", "") or "").lower())
    if timed_out:
        return (f"{decision.verdict}: TIMED OUT — the command was too slow and got "
                f"killed with no result. Use a FASTER, more targeted command "
                f"(fewer ports, drop -A/-p-).")
    if not raw:
        return (f"{decision.verdict}: (no output — this returned nothing useful; "
                f"try a different tool or target)")
    return f"{decision.verdict}: {raw[:800]}"


def highlight_findings(output: str, limit: int = 12) -> list[tuple[str, str]]:
    """Pull the lines from raw tool output that a pentester actually cares about.
    Returns (tag, line) pairs — open ports, web paths, creds, hashes, CVEs, ..."""
    hits: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line or len(line) > 200:
            continue
        for rx, tag in _HIGHLIGHTS:
            if rx.search(line) and line not in seen:
                hits.append((tag, line))
                seen.add(line)
                break
        if len(hits) >= limit:
            break
    return hits


class AssistSession:
    def __init__(self, target, executor, strategist, skills=None, blackboard=None,
                 lessons=None, browser=None, research=None):
        self.target = target
        self.executor = executor
        self.strategist = strategist
        self.browser = browser         # optional GovernedBrowser for WEB actions
        self.skills = skills
        self.blackboard = blackboard   # Obsidian-backed persistence (optional)
        self.lessons = lessons         # cross-session LessonStore (optional)
        self.research = research        # optional control-plane ResearchProvider (untrusted web)
        self.notes: list[str] = []     # observations: command results, manual reports, notes
        self.highlights: list[tuple[str, str]] = []   # accumulated key results
        self.objectives: list[str] = []               # what the box is asking (HTB tasks)
        self.plan: list = []           # list[PlanStep] — the shortest-path plan
        self.plan_cursor = 0           # index of the step we're working on
        self.last = None               # last Suggestion (the top-ranked one)
        self.option_list: list = []    # last ranked list of next-move options
        self._rendered: set = set()    # web URLs already auto-rendered (reflex de-dup)
        self.executed_cmds: list = []  # commands that really ran (fed back as ALREADY TRIED)
        self.resumed = 0               # how many prior findings we loaded
        if blackboard is not None:
            self._load_memory()

    # -- objectives --------------------------------------------------------- #

    def add_objective(self, text: str):
        if text.strip():
            self.objectives.append(text.strip())
            self._write_notebook()

    def _objectives_text(self) -> str:
        return "\n".join(f"- {o}" for o in self.objectives)

    def _state(self) -> str:
        return "\n".join(self.notes[-25:]) if self.notes else "(no findings yet)"

    # -- planning (the shortest path, made visible) ------------------------- #

    def _skill_focus(self, extra: str = "") -> str:
        """Build the query used to pull red-team playbooks from the LIVE state, not
        a fixed string. Keys off the current phase + the services/tech we've actually
        discovered (nginx, ssh, http, mysql, …), mined from the highlights and the
        objectives — NOT the raw objective prose, whose generic words ("find", "path")
        spuriously match unrelated playbooks. This is what makes the skill library
        track the engagement and inform each decision instead of returning the same
        irrelevant playbook every turn (or nothing at all for a bare IP)."""
        phase = ""
        if self.last is not None and self.last.phase:
            phase = self.last.phase
        elif self._current_step() is not None:
            phase = self._current_step().phase or ""
        # Mine service/tech terms from what we've seen + the objectives + the ask.
        corpus = " ".join(line for _tag, line in self.highlights[-12:])
        corpus += " " + " ".join(self.objectives) + " " + extra
        tech = sorted({m.lower() for m in _TECH_HINTS.findall(corpus)})
        terms = ([extra] if extra else []) + ([phase] if phase else []) + tech
        if not tech:                        # nothing found yet -> steer to recon packs
            terms += ["reconnaissance", "enumeration", "port", "scan", "service"]
        return " ".join(terms).strip() or self.target

    def _reference(self, focus: str) -> str:
        """The guidance block fed to the strategist. Order = priority:
          1. LEARNED LESSONS  — Brukal's own verified experience (trusted).
          2. LOCAL SKILL PACKS — vendored red-team playbooks (untrusted).
          3. FRESH WEB RESEARCH — on-demand retrieval (untrusted), LAST so local/
             verified knowledge ranks above fresh web. Control-plane egress only;
             degrades to "" on any failure. Everything here is guidance the model may
             use to PROPOSE — the gate still rules on every action."""
        parts = []
        if self.lessons is not None:
            parts.append(self.lessons.context_for(focus))
        if self.skills is not None:
            parts.append(self.skills.context_for(focus))
        if self.research is not None:
            # feed research the highlight text too — it carries service+version/CVE
            # that the distilled skill-focus string drops.
            rq = (self._highlights_text() + " " + focus).strip()
            try:
                parts.append(self.research.context_for(rq))
            except Exception:
                pass                          # research must never break planning
        return "\n\n".join(p for p in parts if p)

    def make_plan(self):
        """Ask the strategist for the shortest-path plan, keep completed steps
        marked, and persist it so a human can watch (and edit) the route."""
        ref = self._reference(self._skill_focus())
        new = self.strategist.plan(self.target, self._state(),
                                   self._objectives_text(), ref)
        done = self.plan_cursor                    # preserve progress across a re-plan
        self.plan = new
        self.plan_cursor = min(done, len(self.plan))
        for i in range(self.plan_cursor):
            if i < len(self.plan):
                self.plan[i].done = True
        self._persist_plan()
        return self.plan

    def _current_step(self):
        return self.plan[self.plan_cursor] if self.plan_cursor < len(self.plan) else None

    def _advance_plan(self):
        """Mark the current plan step done and move to the next."""
        step = self._current_step()
        if step is not None:
            step.done = True
            self.plan_cursor += 1
            self._persist_plan()

    def _plan_text(self) -> str:
        """The plan rendered with a ▶ on the step we're working on."""
        if not self.plan:
            return ""
        lines = []
        for i, st in enumerate(self.plan):
            mark = "x" if st.done else (">" if i == self.plan_cursor else " ")
            ph = f"[{st.phase}] " if st.phase else ""
            lines.append(f"{i + 1}. [{mark}] {ph}{st.text}")
        return "\n".join(lines)

    def _highlights_text(self) -> str:
        return "\n".join(f"{t}: {l}" for t, l in self.highlights) if self.highlights else ""

    def _tried_text(self, limit: int = 15) -> str:
        """The recent commands that actually executed — fed to the planner as
        ALREADY TRIED so it stops re-proposing them. De-duped, most recent last."""
        seen, out = set(), []
        for c in self.executed_cmds:
            if c not in seen:
                seen.add(c); out.append(c)
        return "\n".join(f"- {c}" for c in out[-limit:])

    def record_verified_success(self, verified):
        """A success was CONFIRMED from real gated output (see verify.py). Promote it
        to the trusted lesson store with provenance, so the brain grows only from
        verified wins. No-op if there's no lesson store."""
        if self.lessons is None:
            return None
        tech = sorted({m.lower() for m in _TECH_HINTS.findall(self._highlights_text())})
        tool = (verified.command.split() or [""])[0].lstrip("`").split("/")[-1].lower()
        service = ", ".join(tech[:3]) or self.target
        tags = [t for t in ([tool] + tech) if t]
        return self.lessons.record_verified_success(
            target=self.target, service=service, command=verified.command,
            outcome=f"{verified.kind}: {verified.evidence[:80]}", tags=tags)

    def ask(self, question: str) -> str:
        """Answer the operator's question about the hunt, grounded in real findings.
        A conversational reply — runs nothing, changes no state."""
        ref = self._reference(self._skill_focus(question))
        return self.strategist.answer(
            self.target, question, self._state(), self._highlights_text(),
            plan=self._plan_text(), reference=ref)

    def advise(self, question: str = ""):
        ref = self._reference(self._skill_focus(question))
        self.last = self.strategist.advise(
            self.target, self._state(), question, ref, self._objectives_text(),
            self._plan_text(), known=self._highlights_text(), tried=self._tried_text())
        return self.last

    def advise_options(self, question: str = "", n: int = 3):
        """Ask for a RANKED list of next moves so the operator can pick one, tweak
        it, or give their own instruction. Falls back to a single-item list."""
        ref = self._reference(self._skill_focus(question))
        opts = self.strategist.options(
            self.target, self._state(), question, ref, self._objectives_text(),
            self._plan_text(), n=n, known=self._highlights_text(), tried=self._tried_text())
        if not opts:                       # never leave the operator with nothing
            opts = [self.advise(question)]
        self.option_list = opts
        self.last = opts[0]
        return opts

    # -- doing / recording (persisted to the vault) ------------------------- #

    def run(self, command: str, target: str | None = None):
        """Run a command through the gate/cage, record it, and surface the key
        results. Returns (decision, result, new_highlights)."""
        decision, result = self.executor.run(command, target or self.target,
                                             agent="strategist")
        return self._absorb_shell(command, decision, result)

    def _absorb_shell(self, command, decision, result):
        """Fold one shell outcome into session state (notes/highlights/lessons/
        vault). Split out from `run` so the parallel runner can EXECUTE in worker
        threads (thread-safe backends) and ABSORB here on the main thread only —
        keeping session state single-threaded."""
        new_hl: list[tuple[str, str]] = []
        if result is not None:
            self.executed_cmds.append(command)   # fed back as ALREADY TRIED next turn
            raw = (result.stdout or "").strip()
            new_hl = highlight_findings(raw)
            self.highlights.extend(h for h in new_hl if h not in self.highlights)
            # Turn a failure into an actionable LESSON the model sees next turn, so a
            # weak model course-corrects instead of repeating a bad move.
            feedback = _outcome_feedback(decision, result, raw)
            self.notes.append(f"[ran] {command}\n{feedback}")
            summary = ("; ".join(f"{t}: {l}" for t, l in new_hl[:6])
                       or feedback[:200])
            self._persist_finding("ran", command, decision.verdict, summary, new_hl)
            self._advance_plan()       # this step is done; move to the next
        else:
            # Blocked by the gate — tell the model WHY and what to do instead.
            hint = ("that target/tool is out of scope or not allowed — stay on the "
                    "authorised host and use an allowlisted tool"
                    if decision.layer.startswith("hard")
                    else "this needs sign-off; a lighter, more targeted command may pass")
            self.notes.append(f"[ran] {command}\nNOT RUN — {decision.verdict} "
                              f"({decision.layer}: {decision.reason}). {hint}")
            self._persist_finding("blocked", command, decision.verdict,
                                  f"{decision.layer}: {decision.reason}", [])
        # Learn from this outcome for FUTURE engagements (cross-session memory).
        if self.lessons is not None:
            tech = sorted({m.lower() for _t, ln in new_hl for m in _TECH_HINTS.findall(ln)})
            self.lessons.learn_from_outcome(command, decision, result, tech)
        return decision, result, new_hl

    def web_urls_from_findings(self) -> list[str]:
        """Deterministically pull web-service URLs out of the findings — open
        http/https ports (nmap) and web-server fingerprints — so a browser render
        can be triggered automatically the moment a web surface appears."""
        urls: list[str] = []
        for _tag, line in self.highlights:
            for m in _WEB_PORT_RE.finditer(line):
                port, svc = m.group(1), m.group(2).lower()
                if "http" not in svc and svc not in ("https", "ssl/http", "http-alt",
                                                     "http-proxy", "www"):
                    continue
                https = ("https" in svc or "ssl" in svc or port in ("443", "8443"))
                scheme = "https" if https else "http"
                if (not https and port == "80") or (https and port == "443"):
                    urls.append(f"{scheme}://{self.target}/")
                else:
                    urls.append(f"{scheme}://{self.target}:{port}/")
        seen, out = set(), []
        for u in urls:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def auto_web_action(self) -> str | None:
        """If a web service has been found but not yet rendered, return the WEB
        render action for it — the 'web port open → look at the site with the real
        browser' reflex. Deterministic; still governed when run."""
        if self.browser is None:
            return None
        for url in self.web_urls_from_findings():
            if url not in self._rendered:
                return f"render {url}"
        return None

    def run_web(self, web_text: str):
        """Run a WEB action through the GOVERNED BROWSER (same gate + audit as a
        shell command, but it renders JS and can tamper requests). Records the
        outcome and learns from it exactly like `run`. Returns (decision, result,
        new_highlights)."""
        from .web import parse_web_action
        action = parse_web_action(web_text)
        if action is None or self.browser is None:
            why = "no browser wired" if self.browser is None else "unparseable web action"
            self.notes.append(f"[web] {web_text}\nNOT RUN — {why}")
            return None, None, []
        decision, result = self.browser.run(action, agent="strategist")
        return self._absorb_web(action, decision, result)

    def _absorb_web(self, action, decision, result):
        """Fold one WEB outcome into session state (main-thread counterpart to the
        thread-safe browser.run, used by the parallel runner)."""
        if action is not None and action.kind in ("navigate", "get") and action.url:
            self._rendered.add(action.url)     # don't auto-render the same page twice
        new_hl: list[tuple[str, str]] = []
        if result is not None:
            body = (result.body or "").strip()
            new_hl = highlight_findings(body)
            self.highlights.extend(h for h in new_hl if h not in self.highlights)
            head = f"{decision.verdict}: {result.note or ''} status={result.status}".strip()
            self.notes.append(f"[web] {action.describe()}\n{head}\n{body[:600]}")
            summary = ("; ".join(f"{t}: {l}" for t, l in new_hl[:6])
                       or f"{head} ({len(body)}B)")
            self._persist_finding("web", action.describe(), decision.verdict, summary, new_hl)
            self._advance_plan()
        else:
            self.notes.append(f"[web] {action.describe()}\nNOT RUN — {decision.verdict} "
                              f"({decision.layer}: {decision.reason})")
            self._persist_finding("web-blocked", action.describe(), decision.verdict,
                                  f"{decision.layer}: {decision.reason}", [])
        if self.lessons is not None:
            tech = sorted({m.lower() for _t, ln in new_hl for m in _TECH_HINTS.findall(ln)})
            self.lessons.learn_from_outcome(action.describe(), decision, result, tech)
        return decision, result, new_hl

    def run_options_parallel(self, options, max_workers: int = 4):
        """Fan out: run the SAFE (gate-ALLOW) enumeration options CONCURRENTLY —
        the 'main agent dispatches sub-tasks in parallel' idea, inside solve/auto.
        Only actions the gate would ALLOW run in parallel (escalations/denials are
        left for sequential handling, since they need approval / are unproductive).
        Executes in worker threads (thread-safe backends + locked audit), then
        absorbs every outcome on THIS thread, so session state stays single-threaded.
        Returns a list of (label, decision, result, highlights); skipped options are
        reported with decision=None."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        from .web import check_web, parse_web_action

        runnable, skipped = [], []
        for o in options:
            if o.command:
                d = self.executor._gate.check(o.command, self.target, "strategist")
                (runnable if d.verdict == "ALLOW" else skipped).append(
                    ("shell", o.command, o.command, d))
            elif o.web and self.browser is not None:
                a = parse_web_action(o.web)
                if a is None:
                    continue
                d = check_web(a, self.browser._scope, self.browser.current_url, "strategist")
                (runnable if d.verdict == "ALLOW" else skipped).append(
                    ("web", o.web, a, d))

        results = []
        if runnable:
            def _exec(kind, payload):
                if kind == "shell":
                    return self.executor.run(payload, self.target, agent="strategist")
                return self.browser.run(payload, agent="strategist")

            raw = {}
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futs = {pool.submit(_exec, kind, payload): (kind, label)
                        for kind, label, payload, _d in runnable}
                for f in as_completed(futs):
                    raw[futs[f]] = f.result()
            # absorb sequentially on the main thread (session state single-threaded)
            for (kind, label), (decision, result) in raw.items():
                if kind == "shell":
                    d, r, hl = self._absorb_shell(label, decision, result)
                else:
                    d, r, hl = self._absorb_web(parse_web_action(label), decision, result)
                results.append((label, d, r, hl))

        for kind, label, _payload, d in skipped:
            results.append((label, d, None, []))    # e.g. ESCALATE/DENY -> handle sequentially
        self.option_list = []
        return results

    def note(self, text: str):
        self.notes.append(f"[note] {text}")
        self._persist_finding("note", "", "", text, [])

    def manual(self, text: str):
        """Record an out-of-cage action the operator performed themselves."""
        self.notes.append(f"[manual] {text}")
        self._persist_finding("manual", "", "", text, [])

    # -- persistence + resume ---------------------------------------------- #

    def _persist_finding(self, kind, command, verdict, summary, highlights):
        if self.blackboard is None:
            return
        self.blackboard.write_finding("strategist", {
            "target": self.target, "task": kind, "command": command,
            "verdict": verdict, "summary": summary,
            "highlights": [list(h) for h in highlights],
        })
        self._write_notebook()

    def _persist_plan(self):
        if self.blackboard is None:
            return
        body = self._plan_text() or "_(no plan yet)_"
        self.blackboard.write_page(
            "plan.md",
            f"# Plan — {self.target}\n\n"
            f"> Shortest path to the goal. `x` done · `>` current · ` ` pending. "
            f"Edit freely; Brukal re-plans from findings.\n\n{body}\n")
        self._write_notebook()

    def _write_notebook(self):
        """A single human-readable engagement page: objectives, plan, what we
        know, and the timeline — the thing you open in Obsidian to see the story."""
        if self.blackboard is None:
            return
        parts = [f"# Engagement — {self.target}\n"]
        if self.objectives:
            parts.append("## Objectives\n" +
                         "\n".join(f"- [ ] {o}" for o in self.objectives) + "\n")
        if self.plan:
            parts.append("## Plan (shortest path)\n" + self._plan_text() + "\n")
        if self.highlights:
            parts.append("## What we know\n" +
                         "\n".join(f"- **{t}** — {l}" for t, l in self.highlights[-20:]) + "\n")
        if self.notes:
            parts.append("## Timeline\n" +
                         "\n".join(f"- {n.splitlines()[0]}" for n in self.notes[-40:]) + "\n")
        self.blackboard.write_page("engagement.md", "\n".join(parts))

    def _load_memory(self):
        """Resume: pull prior findings + plan for this target back into context."""
        prior = self.blackboard.all_findings(self.target)
        for rec in prior:
            summ = rec.get("summary", "")
            self.notes.append(f"[{rec.get('task', 'note')}] {summ}")
            for h in rec.get("highlights", []):
                pair = tuple(h)
                if len(pair) == 2 and pair not in self.highlights:
                    self.highlights.append(pair)
        self.resumed = len(prior)
        self.plan = _parse_saved_plan(self.blackboard.read_page("plan.md"))
        self.plan_cursor = sum(1 for st in self.plan if st.done)


# A saved plan line is "N. [mark] [phase] text" where mark is x (done), > (current)
# or blank (pending) — distinct from the strategist's fresh "N. [phase] text".
_SAVED_PLAN_LINE = re.compile(
    r"^\s*\d+\.\s*\[(?P<mark>[x> ])\]\s*(?:\[(?P<phase>[^\]]+)\]\s*)?(?P<text>.+?)\s*$")


def _parse_saved_plan(text: str) -> list:
    from .agents.strategist import PlanStep
    steps: list = []
    for line in (text or "").splitlines():
        m = _SAVED_PLAN_LINE.match(line)
        if not m:
            continue
        steps.append(PlanStep(text=m.group("text").strip(),
                              phase=(m.group("phase") or "").strip().lower(),
                              done=m.group("mark") == "x"))
    return steps


def _show_tool_policy(console, vhost=""):
    """Show which tools run automatically vs which pause for a human — the broad
    Kali policy: safe enumeration auto-runs, attack/irreversible/unknown ask you."""
    from .risk import _ATTACK_TOOLS, _READ_ONLY_TOOLS
    auto = ", ".join(sorted(_READ_ONLY_TOOLS)[:26]) + " …"
    human = ", ".join(sorted(_ATTACK_TOOLS)[:24]) + " …"
    if console is not None:
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
        t = Table.grid(padding=(0, 2))
        t.add_column(); t.add_column()
        t.add_row(Text("✅ AUTO-RUN", style="bold green"),
                  Text("safe read-only enumeration\n" + auto, style="grey70"))
        t.add_row(Text("🔒 ASKS YOU", style="bold yellow"),
                  Text("attack / irreversible / unknown tools — you approve (y/N)\n" + human,
                       style="grey70"))
        t.add_row(Text("🚫 DENIED", style="bold red"),
                  Text("anything outside the authorised scope — always, by construction",
                       style="grey70"))
        console.print(Panel(t, title="[bold]tool policy — broad Kali mode[/]",
                            border_style="cyan"))
    else:
        print("  AUTO-RUN (safe enum):", auto)
        print("  ASKS YOU (attack/unknown):", human)
        print("  DENIED: anything out of scope")


def run_wizard(fake: bool = False, container: str = "brukal-kali") -> int:
    """The guided `brukal` experience: ask the target, pick the brain, show the
    tool policy + loaded playbooks, choose auto/manual, then hunt — all governed."""
    import ipaddress
    import json

    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        console = None

    _emit(console, "\n  Let's set up a governed hunt — a few quick questions.\n",
          "\n  [bold cyan]Let's set up a governed hunt[/] — a few quick questions.\n")

    # 1) target
    target = _ask(console, "  1) Target IP you are AUTHORISED to test").strip()
    if not target:
        print("  no target — bye."); return 1
    try:
        net = ipaddress.ip_network(f"{target}/32", strict=False)
    except ValueError:
        print(f"  '{target}' is not a valid IP."); return 1

    # 2) optional web vhost (HTB boxes often route by hostname)
    vhost = _ask(console, "  2) Known web vhost, e.g. nexus.htb (blank to skip)", "").strip()

    # 3) the brain — all options (Claude / Ollama / Groq / OpenAI-compatible)
    _emit(console, "  3) Choose the brain:")
    provider, model, base_url = choose_brain(console)

    # build a broad-mode scope for just this host (all tools; dangerous -> human)
    Path("runs").mkdir(parents=True, exist_ok=True)
    scope_path = "runs/wizard_scope.json"
    Path(scope_path).write_text(json.dumps({
        "engagement": f"brukal-hunt-{target}",
        "authorized_cidrs": [str(net)],
        "authorized_hosts": [vhost.lower()] if vhost else [],
        "allowlisted_tools": "all",
        "rate_limit_per_min": 60,
    }, indent=2), encoding="utf-8")

    # 4) show the tool policy (auto vs human) + the skill library
    _emit(console, "\n  4) Tool policy for this hunt:")
    _show_tool_policy(console, vhost)
    try:
        from .skills import SkillLibrary
        lib = SkillLibrary()
        hits = lib.retrieve(vhost or target, 3)
        rel = ("; relevant: " + ", ".join(s.name for s in hits)) if hits else ""
        _emit(console, f"  📚 {len(lib)} red-team playbooks loaded{rel} "
                       f"(used automatically while hunting).")
    except Exception:
        pass

    # 5) auto or manual
    _emit(console, "\n  5) How should Brukal work?")
    auto = choose_run_mode(console)

    if not fake and not _confirm(console, f"\n  Ready. Confirm you are AUTHORISED to "
                                          f"test {target}?"):
        print("  aborted — authorisation not confirmed."); return 1

    _emit(console, f"\n  🚀 hunting {target} — {'AUTO' if auto else 'MANUAL'} mode. "
                   f"Dangerous steps will pause for your OK.\n",
          f"\n  [bold green]🚀 hunting {target}[/] — {'AUTO' if auto else 'MANUAL'} mode. "
          f"Dangerous steps will pause for your OK.\n")

    common = dict(yes_authorised=True, scope_path=scope_path, fake=fake,
                  container=container, provider=provider, model=model, base_url=base_url,
                  vault_path="runs/vault")
    if auto:
        return run_auto(target, **common)
    return run_solve(target, auto=False, **common)


def _auto_approver(decision) -> bool:
    """Auto-mode approver: keep the hunt moving on REVERSIBLE escalations (an
    aggressive-but-read-only scan like `nmap -T4 --top-ports`), but PAUSE on
    anything IRREVERSIBLE or unclassified — reverse shells, credential attacks,
    `sqlmap --dump`, writes, unknown tools. That is 'safe/aggressive-but-reversible
    runs itself; dangerous asks a human', which the operator approves in `brukal
    solve`. Scope + audit are untouched; this only tunes the soft escalation."""
    return getattr(decision, "reversibility", None) == "reversible"


class _AutoLiveView:
    """A live, animated terminal view of the autonomous hunt: a spinner that shows
    what Brukal is doing right now (thinking / running a tool / rendering a site),
    running tallies, and a scrolling step log with colour-coded verdicts. Uses rich
    Live's background refresh so the spinner keeps moving during a blocking scan."""

    def __init__(self, console, target, cage, budget, objective=""):
        self.con = console
        self.target = target
        self.cage = cage
        self.budget = budget
        self.objective = objective
        self.status = "starting…"
        self.steps: list = []                 # (idx, phase, verdict, action, summary)
        self.tally = {"ran": 0, "blocked": 0, "escalated": 0, "web": 0}
        self._live = None

    def set_status(self, text):
        self.status = text
        if self._live is not None:
            self._live.update(self._render())

    def _render(self):
        from rich.console import Group
        from rich.panel import Panel
        from rich.spinner import Spinner
        from rich.table import Table
        from rich.text import Text

        t = self.tally
        header = Text.assemble(
            ("🎯 ", ""), (self.target, "bold cyan"), (f"  ({self.cage})   ", "grey50"),
            (f"{t['ran']} ran", "green"), (" · ", "grey42"),
            (f"{t['escalated']} escalated", "yellow"), (" · ", "grey42"),
            (f"{t['blocked']} blocked", "red"), (" · ", "grey42"),
            (f"{t['web']} web", "magenta"),
            (f"   step {len(self.steps)}/{self.budget}", "grey62"))
        obj = Text(f"🏁 {self.objective}", style="grey58") if self.objective else Text("")
        spin = Spinner("dots", text=Text(self.status, style="bold yellow"))

        log = Table.grid(padding=(0, 1))
        log.add_column(justify="right"); log.add_column(); log.add_column(); log.add_column()
        for idx, phase, verdict, action, summ in self.steps[-9:]:
            c = _VERDICT_COLOUR.get(verdict, "grey50")
            log.add_row(Text(f"{idx}", style="grey42"),
                        Text((phase or "").upper()[:5], style="cyan"),
                        Text(f"{verdict:<9}", style=f"bold {c}"),
                        Text(action[:58], style="white"))
        body = Group(header, obj, Text(""), spin, Text(""), log)
        return Panel(body, title="[bold cyan]brukal — governed autonomous hunt[/]",
                     border_style="cyan")

    def on(self, kind, payload):
        if kind == "thinking":
            self.status = "🧠 thinking… (planning the next move)"
        elif kind == "running":
            a = payload.get("action", "")
            if payload.get("web"):
                self.status = f"🌐 browser: {a[:56]}"
            else:
                tool = (a.split() or [""])[0]
                self.status = f"⚙  running {tool} …  ({a[:48]})"
        elif kind == "step":
            s = payload["step"]
            v = s.verdict or "-"
            if s.executed:
                self.tally["ran"] += 1
                if (s.command or "").startswith("WEB:"):
                    self.tally["web"] += 1
            elif v == "ESCALATE":
                self.tally["escalated"] += 1
            else:
                self.tally["blocked"] += 1
            self.steps.append((s.index, s.phase, v, s.command or "", s.summary))
            self.status = "observing the result…"
        elif kind == "stop":
            self.status = f"⏹ stopped: {payload.get('reason', '')}"
        if self._live is not None:
            self._live.update(self._render())

    def start(self):
        from rich.live import Live
        self._live = Live(self._render(), console=self.con, refresh_per_second=10,
                          transient=False)
        return self._live


def _rich_approver(con, holder):
    """Escalation sign-off that pauses the live spinner, prompts, then resumes."""
    from rich.panel import Panel
    from rich.text import Text

    def approve(decision) -> bool:
        st = holder.get("status")
        if st is not None:
            st.stop()
        con.print(Panel(Text.assemble(
            ("ESCALATION — human sign-off required\n", "bold yellow"),
            (f"action : {decision.action}\n", "white"),
            (f"target : {decision.target}   agent: {decision.agent}\n", "white"),
            (f"risk   : {decision.risk_band}  ({decision.reason})", "grey62")),
            border_style="yellow"))
        try:
            ans = (con.input("  approve this action? [y/N] ").strip().lower()
                   if con.file.isatty() else "")
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if st is not None:
            st.start()
        return ans in ("y", "yes")

    return approve


def _show_highlights(con, Panel, Text, hits, title):
    if not hits:
        return
    body = Text()
    for i, (tag, line) in enumerate(hits):
        if i:
            body.append("\n")
        body.append(f"{tag:>11} ", style="bold yellow")
        body.append(line, style="white")
    con.print(Panel(body, title=f"[bold yellow]★ {title}[/]", border_style="yellow"))


_AUTO_CAP = 20   # in auto mode, hand back to the human after this many auto-runs


def _menu_loop(session, audit, target, cage, con, holder, auto=False):
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.text import Text

    flags = {"auto": auto}
    auto_steps = 0

    con.print(Panel(Text.assemble(("BRUKAL — pentest companion   ", "bold cyan"),
                                   (f"target={target}   cage={cage}   "
                                    f"mode={'AUTO' if auto else 'MANUAL'}", "white")),
                    border_style="cyan"))

    if session.resumed:
        con.print(f"[green]↻ resumed[/] — loaded [bold]{session.resumed}[/] prior "
                  f"finding(s) for {target}; picking up where we left off.")

    # Ask up front what the box wants (HTB task questions) — this steers everything.
    con.print("[grey62]What is the box asking you to find? (HTB task questions, one per "
              "line — e.g. \"How many open TCP ports?\"). Enter blank to skip / finish.[/]")
    while True:
        try:
            obj = Prompt.ask("  objective", default="")
        except (EOFError, KeyboardInterrupt):
            break
        if not obj:
            break
        session.add_objective(obj)

    # Lay out the shortest-path plan up front so the operator sees the route.
    if not session.plan:
        with con.status("[cyan]companion planning the route…", spinner="dots"):
            session.make_plan()

    def show_plan():
        pt = session._plan_text()
        if pt:
            con.print(Panel(pt, title="[bold]plan — shortest path[/]", border_style="blue"))

    def run_and_show(command):
        with con.status(f"[cyan]running:[/] {command}", spinner="dots") as st:
            holder["status"] = st
            d, r, new_hl = session.run(command)
            holder["status"] = None
        colour = _VERDICT_COLOUR.get(d.verdict, "white")
        con.print(Text.assemble(("  → ", ""), (d.verdict, f"bold {colour}"),
                                 (f"   {d.layer}", "grey50")))
        if r is not None and (r.stdout or "").strip():
            con.print(Panel(r.stdout.strip()[:1800], title="raw output", border_style="grey23"))
            _show_highlights(con, Panel, Text, new_hl, "key results")
        elif r is None:
            con.print(f"  [grey50]{d.reason}[/]")
        session.last = None   # regenerate advice from the new findings

    while True:
        # objectives tracker + the plan, shown every turn
        if session.objectives:
            ot = Text()
            for o in session.objectives:
                ot.append("? ", style="bold yellow"); ot.append(o + "\n")
            con.print(Panel(ot, title="objectives", border_style="yellow"))
        show_plan()

        # AUTO: take the single top move itself, pausing on manual/escalation/cap.
        if flags["auto"]:
            if session.last is None:
                with con.status("[cyan]companion thinking…", spinner="dots"):
                    session.advise()
            s = session.last
            if s.command and auto_steps < _AUTO_CAP:
                con.print(f"[grey62]▶ auto — running:[/] {s.command} [grey62](Ctrl-C to pause)[/]")
                try:
                    run_and_show(s.command); session.option_list = []
                    auto_steps += 1
                    continue
                except KeyboardInterrupt:
                    con.print("\n[yellow]paused — back to manual.[/]")
                    flags["auto"] = False
            else:
                why = ("hit the auto-step limit" if auto_steps >= _AUTO_CAP
                       else "the next step is yours (manual)" if s.manual
                       else "no safe command to run")
                con.print(f"[yellow]⏸ auto paused — {why}. Over to you.[/]")
                flags["auto"] = False

        # MANUAL: present a RANKED list of moves — pick one, run your own, or steer.
        if not session.option_list:
            with con.status("[cyan]companion weighing the best moves…", spinner="dots"):
                session.advise_options(n=3)
        opts = session.option_list

        read = getattr(session.strategist, "last_read", "") if session.strategist else ""
        if read:
            con.print(Text.assemble(("  🧠 Brukal: ", "bold cyan"), (read, "white")))

        body = Text()
        for i, o in enumerate(opts, 1):
            pc = _PHASE_COLOUR.get((o.phase or "").lower(), "cyan")
            body.append(f"[{i}] ", style="bold cyan")
            if o.phase:
                body.append(f"{o.phase.upper()}  ", style=f"bold {pc}")
            body.append(o.goal or (o.rationale or "")[:60] or "next move", style="white")
            if o.command:
                body.append(f"\n     RUN: {o.command}", style="green")
            elif o.manual:
                body.append(f"\n     MANUAL: {o.manual}", style="yellow")
            if i < len(opts):
                body.append("\n")
        con.print(Panel(body, title="[bold]next moves — pick a number, or type your own[/]",
                        border_style="cyan"))
        if session.highlights:
            _show_highlights(con, Panel, Text, session.highlights[-8:], "what we know so far")

        actions = [("c", "type your own command (gated)"),
                   ("?", "ask Brukal about the hunt (what did you find? why?)"),
                   ("i", "give an instruction / re-plan the options"),
                   ("p", "run all the SAFE options in PARALLEL"),
                   ("a", f"switch to {'MANUAL' if flags['auto'] else 'AUTO'} mode"),
                   ("t", "add a note"), ("m", "record a manual step you did"),
                   ("o", "add an objective"), ("k", "search skill playbooks"),
                   ("v", "verify audit chain"), ("q", "quit")]
        grid = Table.grid(padding=(0, 2))
        for key, label in actions:
            grid.add_row(Text(f"[{key}]", style="bold cyan"), Text(label))
        con.print(grid)

        nums = [str(i) for i in range(1, len(opts) + 1)]
        try:
            choice = Prompt.ask("  pick a number or action",
                                choices=nums + [k for k, _ in actions], default="1")
        except (EOFError, KeyboardInterrupt):
            break

        if choice in nums:
            opt = opts[int(choice) - 1]
            if opt.command:
                run_and_show(opt.command)
            elif opt.manual:
                session.manual(opt.manual)
                con.print(f"  [yellow]recorded manual:[/] {opt.manual}")
            session.option_list = []
        elif choice == "c":
            run_and_show(Prompt.ask("  your command")); session.option_list = []
        elif choice == "?":
            q = Prompt.ask("  your question about the hunt", default="")
            if q.strip():
                with con.status("[cyan]Brukal is reviewing the findings…", spinner="dots"):
                    ans = session.ask(q.strip())
                con.print(Panel(ans, title="[bold cyan]🧠 Brukal[/]", border_style="cyan"))
        elif choice == "i":
            instr = Prompt.ask("  your instruction (what should we try / focus on?)",
                               default="")
            with con.status("[cyan]re-planning the options…", spinner="dots"):
                session.advise_options(instr, n=3)
        elif choice == "p":
            with con.status("[cyan]running the safe options in parallel…", spinner="dots") as st:
                holder["status"] = st
                batch = session.run_options_parallel(session.option_list)
                holder["status"] = None
            for label, d, r, _hl in batch:
                v = d.verdict if d is not None else "SKIP"
                colour = _VERDICT_COLOUR.get(v, "grey50")
                con.print(Text.assemble(("  → ", ""), (v, f"bold {colour}"), (f"  {label}", "white")))
        elif choice == "a":
            flags["auto"] = not flags["auto"]; auto_steps = 0
            con.print(f"  mode → [bold]{'AUTO' if flags['auto'] else 'MANUAL'}[/]")
        elif choice == "t":
            session.note(Prompt.ask("  note / paste output")); session.option_list = []
        elif choice == "m":
            session.manual(Prompt.ask("  what you did")); session.option_list = []
        elif choice == "o":
            session.add_objective(Prompt.ask("  objective")); session.option_list = []
        elif choice == "k":
            for sk in (session.skills.retrieve(Prompt.ask("  topic"), 4)
                       if session.skills else []):
                con.print(f"    [magenta]\\[{sk.category}][/] {sk.name}")
        elif choice == "v":
            con.print(f"  audit chain intact: [green]{audit.verify()}[/]")
        elif choice == "q":
            break


_HELP = """  pick a NUMBER to take that move, or type your own:
    <cmd>  run any command (through the gate)      <instruction>  steer the options
    ask <question>   ask Brukal about the hunt (e.g. "what did you find?", "why ssh?")
    p  run all the SAFE options in PARALLEL        note <text>   manual <text>
    host <name>  authorise a vhost (e.g. host nexus.htb) so web/Host-header hits pass
    plan   auto   manual-mode   skills <topic>   verify   quit
    (a question — ending in '?' or starting with what/why/how… — is answered, not run;
     `auto` runs the safe steps itself; risky/irreversible moves still pause for y/N)"""


def _looks_like_command(text: str) -> bool:
    """Heuristic: does the operator's free text look like a command to RUN (vs an
    instruction to steer with)? First token is a known/allowlisted-ish tool name."""
    first = (text.split() or [""])[0].lower()
    return bool(re.match(r"^[a-z][a-z0-9._-]*$", first)) and first in _COMMON_TOOLS


_QUESTION_WORDS = frozenset({
    "what", "whats", "why", "how", "where", "when", "which", "who", "whose",
    "is", "are", "was", "were", "did", "does", "do", "can", "could", "should",
    "would", "will", "has", "have", "tell", "explain", "show", "describe",
    "summarise", "summarize", "recap"})


def _looks_like_question(text: str) -> bool:
    """Is the operator ASKING about the hunt (answer it) rather than instructing a
    re-plan? A trailing '?' or a leading interrogative word means a question."""
    t = (text or "").strip()
    if not t:
        return False
    if t.endswith("?"):
        return True
    first = re.sub(r"[^a-z]", "", t.split()[0].lower())
    return first in _QUESTION_WORDS


_COMMON_TOOLS = frozenset({
    "nmap", "masscan", "gobuster", "ffuf", "feroxbuster", "dirb", "wfuzz", "nikto",
    "whatweb", "wafw00f", "nuclei", "curl", "wget", "dig", "host", "dnsrecon",
    "sslscan", "smbclient", "smbmap", "enum4linux", "enum4linux-ng", "nbtscan",
    "snmpwalk", "ldapsearch", "redis-cli", "hydra", "medusa", "ncrack", "sqlmap",
    "wpscan", "john", "hashcat", "searchsploit", "crackmapexec", "netexec", "nxc",
    "kerbrute", "evil-winrm", "nc", "ncat", "netcat", "socat", "ssh", "ping"})


def _show_highlights_plain(hits, title="what Brukal found"):
    """Plain-text version of the rich highlights panel — the 'what did that command
    tell us' line, so a run visibly produces knowledge, not just raw text."""
    if not hits:
        return
    print(f"  ★ {title}:")
    for tag, line in hits:
        print(f"      {tag:>11}  {line}")


def _print_options(opts):
    print("\n  NEXT MOVES — pick a number, or type your own command/instruction:")
    for i, o in enumerate(opts, 1):
        tag = f"[{o.phase}] " if o.phase else ""
        # next(iter(...), "") is empty-safe: an option with no goal AND no rationale
        # (a weak/misbehaving model) must not IndexError on ""splitlines()[0].
        first_line = next(iter((o.rationale or "").splitlines()), "")
        label = o.goal or first_line[:70] or "next move"
        print(f"    [{i}] {tag}{label}")
        # Show WHY (the strategist's reasoning) so the operator sees Brukal thinking
        # about the findings, not just a bare command list.
        why = (o.rationale or "").strip()
        if why and why != label:
            print(f"         why: {why.splitlines()[0][:110]}")
        if o.command:
            print(f"         RUN: {o.command}")
        elif o.web:
            print(f"         WEB: {o.web}")
        elif o.manual:
            print(f"         MANUAL (you): {o.manual}")
    print("    [type a command to run it · type an instruction to re-plan · "
          "host <name> to authorise a vhost · help · quit]")


def _report(d, r):
    # Make the OUTCOME of a run visible, not just a raw dump: a timed-out command
    # (returncode 124 / "timed out") otherwise prints only its startup banner and
    # looks like it "did nothing". Always tell the operator what actually happened.
    if r is None:
        print(f"  -> {d.verdict}  ({d.layer}: {d.reason})")
        return
    rc = getattr(r, "returncode", 0)
    out = (getattr(r, "stdout", "") or "").rstrip()
    stderr = (getattr(r, "stderr", "") or "")
    if rc == 124 or "timed out" in stderr.lower():
        print(f"  -> {d.verdict}  ⏱ TIMED OUT — killed before it finished, so NO usable "
              f"result. Re-run narrower: a small wordlist (not rockyou), fewer ports, "
              f"or a single service.")
    elif rc not in (0, None):
        print(f"  -> {d.verdict}  (exit {rc})")
    else:
        print(f"  -> {d.verdict}")
    if out:
        for line in out.splitlines():
            print(f"     {line}")
    # On a failure/empty run, show stderr so the reason is visible (e.g. a wordlist
    # that doesn't exist prints "no such file" to stderr — otherwise it looks silent).
    err = stderr.rstrip()
    if err and (not out or rc not in (0, None)):
        for line in err.splitlines()[:8]:
            print(f"     ! {line}")
    elif not out and rc == 0:
        print("     (ran, no output)")


def _deny_hint(d):
    """After a DENY, tell the operator how to unblock it when it's a fixable case
    (an out-of-scope vhost they can authorise, or shell metacharacters to drop)."""
    reason = (getattr(d, "reason", "") or "").lower()
    if "out of scope" in reason or "out-of-scope host" in reason:
        print("     ↪ if that host is a real vhost of your target, authorise it: "
              "type  host <name>  (e.g.  host nexus.htb)")
    elif "metacharacter" in reason or "injection" in reason:
        print("     ↪ drop shell operators (| > 2>/dev/null && ;) — send the bare "
              "command; output is captured for you.")


def _authorise_vhost(session, name: str) -> bool:
    """Operator authorises a virtual host (e.g. nexus.htb) for this session — a
    deliberate scope-TIME act (same as `brukal target`/`brukal web --host`), NOT a
    runtime widen by an agent. Installs a new Scope (with the vhost added) on both the
    shell gate and the web browser, so subsequent web renders and Host-header requests
    to that vhost pass the gate. Returns False if nothing to update."""
    name = (name or "").strip().lower()
    if not name:
        return False
    # Authorise the host AND, for a bare domain, its vhosts (*.domain) — so vhost
    # fuzzing (Host: FUZZ.domain against the in-scope IP) is not blocked. A wildcard
    # only widens the *hostname* set; the network destination is still the in-scope
    # IP (URL/CIDR check + nftables), so this cannot reach an out-of-scope host.
    names = _vhost_names(name)
    updated = False
    gate = getattr(session.executor, "_gate", None)
    for n in names:
        if gate is not None:
            gate.scope = gate.scope.with_host(n)
            updated = True
        if getattr(session, "browser", None) is not None:
            session.browser._scope = session.browser._scope.with_host(n)
            updated = True
    return updated


def _vhost_names(name: str) -> list[str]:
    """A host to authorise, plus its `*.domain` wildcard when it's a bare domain
    (has a dot, isn't already a wildcard, isn't an IP) — so its vhosts are in scope."""
    name = (name or "").strip().lower()
    if not name:
        return []
    names = [name]
    if "." in name and not name.startswith("*.") and not name.replace(".", "").isdigit():
        names.append("*." + name)
    return names


def _take_option(session, opt):
    """Execute a chosen option: a RUN/WEB goes through the gate; a MANUAL is recorded.
    Narrate the result so the operator sees Brukal *hunt* — run, learn, react."""
    if opt.command:
        d, r, hl = session.run(opt.command)
        _report(d, r); _deny_hint(d); _show_highlights_plain(hl)
    elif opt.web:
        d, r, hl = session.run_web(opt.web)
        _report(d, r); _deny_hint(d); _show_highlights_plain(hl)
    elif opt.manual:
        session.manual(opt.manual)
        print(f"  recorded manual step: {opt.manual}")
    session.option_list = []          # regenerate from the new findings next turn


def _show_plan_plain(session):
    pt = session._plan_text()
    if pt:
        print("\n  PLAN (shortest path):")
        for line in pt.splitlines():
            print(f"    {line}")
        print()


def _plain_loop(session, audit, target, cage, auto=False):
    print(f"\n  brukal solve — target {target}   cage={cage}   "
          f"mode={'AUTO' if auto else 'MANUAL'}")
    if session.resumed:
        print(f"  ↻ resumed — loaded {session.resumed} prior finding(s) for {target}.")
    print(_HELP)
    if not session.plan:
        print("  planning the route…")
        session.make_plan()
    _show_plan_plain(session)
    flags = {"auto": auto}
    auto_steps = 0
    if flags["auto"]:
        session.advise()                    # seed the top move for the auto branch
    while True:
        # AUTO: run the safe top move itself, pausing on manual/cap/Ctrl-C.
        if flags["auto"]:
            s = session.last
            if s and s.command and auto_steps < _AUTO_CAP:
                print(f"  [auto] running: {s.command}")
                try:
                    d, r, _ = session.run(s.command)
                    _report(d, r)
                    auto_steps += 1
                    session.advise()
                    continue
                except KeyboardInterrupt:
                    print("\n  paused — manual mode.")
                    flags["auto"] = False
            else:
                print("  [auto] paused — over to you (type `auto` to resume).")
                flags["auto"] = False

        # MANUAL: present a ranked list of moves; the operator picks one, runs their
        # own command, or gives an instruction to re-plan the options.
        if not session.option_list:
            print("  thinking…")
            session.advise_options(n=3)
        read = getattr(session.strategist, "last_read", "") if session.strategist else ""
        if read:
            print(f"\n  🧠 Brukal: {read}")     # conversational take on the last result
        _print_options(session.option_list)
        try:
            raw = input("  brukal> ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); break

        if raw.isdigit() and 1 <= int(raw) <= len(session.option_list):
            _take_option(session, session.option_list[int(raw) - 1])
        elif raw == "" and session.option_list:
            _take_option(session, session.option_list[0])       # enter = top move
        elif raw in ("quit", "exit", "q"):
            break
        elif raw in ("help", "?"):
            print(_HELP)
        elif raw == "auto":
            flags["auto"] = True; auto_steps = 0; session.advise(); print("  mode → AUTO")
        elif raw in ("manual-mode", "manual_mode"):
            flags["auto"] = False; print("  mode → MANUAL")
        elif raw == "verify":
            print("  audit chain intact:", audit.verify())
        elif raw in ("p", "par", "parallel"):
            print("  running the safe options in parallel…")
            for label, d, r, _hl in session.run_options_parallel(session.option_list):
                v = d.verdict if d is not None else "SKIP"
                print(f"    [{v}] {label}")
                if r is not None and (r.stdout if hasattr(r, 'stdout') else getattr(r, 'body', '')):
                    body = getattr(r, 'stdout', None) or getattr(r, 'body', '') or ''
                    print(f"        {body.strip()[:120]}")
        elif raw == "plan":
            print("  re-planning the route…")
            session.make_plan(); _show_plan_plain(session); session.option_list = []
        elif raw.split(None, 1)[0] in ("host", "scope", "authorise", "authorize") \
                and len(raw.split(None, 1)) == 2:
            name = raw.split(None, 1)[1].strip()
            if _authorise_vhost(session, name):
                print(f"  ✓ authorised vhost {name} (scope-time). It's now in scope for "
                      f"web + shell against this target.")
            session.option_list = []
        elif raw.startswith("note "):
            session.note(raw[5:].strip()); session.option_list = []; print("  noted.")
        elif raw.startswith("manual "):
            session.manual(raw[7:].strip()); session.option_list = []; print("  recorded.")
        elif raw.startswith("skills "):
            for s in (session.skills.retrieve(raw[7:].strip(), 4) if session.skills else []):
                print(f"    [{s.category}] {s.name}")
        elif raw.startswith("run "):
            d, r, hl = session.run(raw[4:].strip())
            _report(d, r); _deny_hint(d); _show_highlights_plain(hl); session.option_list = []
        elif raw.startswith("ask ") or raw.startswith("? "):
            q = raw.split(None, 1)[1].strip()                    # explicit question
            print(f"\n  🧠 Brukal: {session.ask(q)}\n")
        elif _looks_like_command(raw):
            d, r, hl = session.run(raw)                          # custom command
            _report(d, r); _deny_hint(d); _show_highlights_plain(hl); session.option_list = []
        elif _looks_like_question(raw):
            # a question about the hunt -> answer it conversationally (runs nothing)
            print(f"\n  🧠 Brukal: {session.ask(raw)}\n")
        else:
            print("  re-planning around that…")
            session.advise_options(raw, n=3)     # free text = an instruction to steer


def _print_suggestion(s):
    tag = f"[{s.phase.upper()}] " if s.phase else ""
    if s.goal:
        print(f"\n  {tag}GOAL: {s.goal}")
    print(f"  [companion] {s.rationale}")
    if s.command:
        print(f"  suggested (gated):  {s.command}")
    if s.manual:
        print(f"  manual step (you):  {s.manual}")
    print()


def _ask(console, prompt: str, default: str = "") -> str:
    """One-line prompt that works with or without rich; fail-closed on EOF."""
    try:
        if console is not None:
            from rich.prompt import Prompt
            return Prompt.ask(prompt, default=default)
        return input(f"{prompt} ").strip() or default
    except (EOFError, KeyboardInterrupt, OSError):
        return default


def _confirm(console, prompt: str) -> bool:
    """Yes/No confirmation, fail-closed (default No, No on EOF/non-tty)."""
    ans = _ask(console, f"{prompt} [y/N]", "").strip().lower()
    return ans in ("y", "yes")


def _emit(console, plain: str, markup: str | None = None):
    if console is not None:
        console.print(markup if markup is not None else plain)
    else:
        print(plain)


def _spend_line(session) -> str:
    """One-line LLM token/cost tally for a finished hunt, read from the strategist's
    client meter. Reachable because the strategist is the only thing that calls the
    model, so its meter is the whole engagement's spend."""
    try:
        meter = session.strategist._llm.usage
    except AttributeError:
        return ""
    if not meter.calls:
        return "  brain: no model calls (fully deterministic run)"
    return f"  brain spend — {meter.summary()}"


def _ensure_key_env(var: str, label: str) -> bool:
    """Ensure an API-key env var is set; prompt (hidden) if interactive."""
    if os.environ.get(var):
        return True
    if not sys.stdin.isatty():
        return False
    try:
        val = getpass.getpass(f"  {label} (input hidden, blank to skip): ").strip()
    except (EOFError, KeyboardInterrupt):
        val = ""
    if val:
        os.environ[var] = val
        return True
    return False


def choose_brain(console):
    """Ask the operator HOW to run Brukal's brain and return (provider, model,
    base_url), ensuring any needed API key is set. Returns (None, None, None) when
    non-interactive (fall back to defaults/env)."""
    from .llm import _ANTHROPIC_DEFAULT, _PRESETS
    if not sys.stdin.isatty():
        return None, None, None

    _emit(console, "\n  How should Brukal think? Pick the model it runs on:",
          "\n  [bold]How should Brukal think? Pick the model it runs on:[/]")
    for k, label in (
        ("1", "Claude API (Anthropic) — best quality, needs an API key"),
        ("2", "Local model via Ollama — free, private, no key (e.g. qwen2.5)"),
        ("3", "Groq — FREE api key, very fast, strong models (e.g. llama-3.3-70b)"),
        ("4", "Other OpenAI-compatible — OpenAI / OpenRouter / DeepSeek / GLM / LM Studio"),
        ("5", "Advanced — type provider / model / base-url yourself"),
    ):
        _emit(console, f"    [{k}] {label}", f"    [cyan]\\[{k}][/] {label}")
    choice = (_ask(console, "  choose", "1") or "1").strip()

    if choice == "2":                                        # free local Ollama
        model = (_ask(console, "  Ollama model", "qwen2.5") or "qwen2.5").strip()
        base = (_ask(console, "  Ollama base URL", "http://localhost:11434/v1") or "").strip()
        _emit(console, "  (WSL note: if Ollama runs on Windows, use the Windows host IP, "
              "e.g. http://172.x.x.x:11434/v1, and start Ollama with OLLAMA_HOST=0.0.0.0)")
        return "ollama", model, base or None

    if choice == "3":                                        # Groq (free, fast)
        _emit(console, "  Get a free key at console.groq.com/keys (starts with gsk_).")
        default_model = "llama-3.3-70b-versatile"
        model = (_ask(console, "  Groq model", default_model) or default_model).strip()
        if not _ensure_key_env("GROQ_API_KEY", "Groq API key (GROQ_API_KEY)"):
            _emit(console, "  ⚠ no GROQ_API_KEY set — calls will fail until you provide it.")
        return "groq", model, None

    if choice == "4":                                        # other OpenAI-compatible preset
        prov = (_ask(console, "  provider (openai/openrouter/deepseek/glm/lmstudio)",
                     "openai") or "openai").strip().lower()
        if prov not in _PRESETS:
            _emit(console, f"  unknown provider '{prov}', using openai.")
            prov = "openai"
        _, key_env, default_model = _PRESETS[prov]
        model = (_ask(console, "  model", default_model or "") or "").strip() or default_model
        if prov != "lmstudio" and not _ensure_key_env(key_env, f"{prov} API key ({key_env})"):
            _emit(console, f"  ⚠ no {key_env} set — calls will fail until you export it.")
        return prov, model, None

    if choice == "5":                                        # advanced
        prov = (_ask(console, "  provider", "openai") or "openai").strip().lower()
        model = (_ask(console, "  model (blank = provider default)", "") or "").strip() or None
        base = (_ask(console, "  base URL (blank = preset)", "") or "").strip() or None
        return prov, model, base

    # default: Claude API
    if not _ensure_key_env("ANTHROPIC_API_KEY", "Anthropic API key"):
        _emit(console, "  ⚠ no ANTHROPIC_API_KEY — Claude calls will fail. "
              "Tip: option 2 runs a free local model instead.")
    model = (_ask(console, "  Claude model", _ANTHROPIC_DEFAULT) or _ANTHROPIC_DEFAULT).strip()
    return "anthropic", model, None


def choose_run_mode(console) -> bool:
    """Ask how to work the plan. Returns True for AUTO, False for MANUAL."""
    if not sys.stdin.isatty():
        return False
    _emit(console, "\n  How should I work through the plan?",
          "\n  [bold]How should I work through the plan?[/]")
    _emit(console, "    [1] Manual — you approve each step (recommended)",
          "    [cyan]\\[1][/] Manual — you approve each step (recommended)")
    _emit(console, "    [2] Auto — I run the safe (ALLOW) steps myself, and pause for "
                   "anything risky or manual",
          "    [cyan]\\[2][/] Auto — I run the safe (ALLOW) steps myself, and pause for "
          "anything risky or manual")
    return (_ask(console, "  choose", "1") or "1").strip() == "2"


def _authorise_host(scope, target: str):
    """Build a session Scope narrowed to a single /32 host, reusing the loaded
    scope's tool allowlist and rate limit. This SETS scope before the engagement
    (like `brukal target`) — it does not widen a running scope (invariant 5)."""
    import ipaddress

    from .scope import Scope
    net = ipaddress.ip_network(f"{target.strip()}/32", strict=False)
    return Scope(engagement=f"{scope.engagement}-solve",
                 authorized_networks=(net,),
                 allowlisted_tools=scope.allowlisted_tools,
                 rate_limit_per_min=scope.rate_limit_per_min)


def _vault_for(vault_root, target: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target.strip()) or "target"
    return Path(vault_root) / safe


def _prepare_session(target, *, fake, yes_authorised, scope_path, audit_path,
                     vault_path, container, model, provider, base_url,
                     console, holder, hosts=()):
    """Shared setup for `solve` and `auto`: resolve the target, authorise scope,
    take the live-run sign-off, pick the brain, and build a grounded
    AssistSession wired to the governed executor + per-target vault.

    Returns (session, audit, target, cage) on success, or an int exit code."""
    try:
        from .agents.strategist import StrategistAgent
        from .blackboard import Blackboard
        from .engagement import interactive_approver
        from .llm import LLMClient
        from .skills import SkillLibrary
    except ImportError as e:
        print(f"Agent dependencies missing ({e}). Install: pip install \"brukal[agents]\"")
        return 2

    # 1) The target — ask for it if it wasn't given on the command line.
    if not target:
        target = _ask(console, "  target IP to work on").strip()
    if not target:
        print("No target given.")
        return 2

    # 2) Scope — use the file if it already authorises this host, else offer to
    #    authorise just this one host for the session (a deliberate, confirmed act).
    scope = load_scope(scope_path)
    if scope.contains_ip(target):
        session_scope = scope
    else:
        msg = (f"  ⚠ {target} is not in {scope_path}. Authorise this single host "
               f"({target}/32) for this session?")
        if not _confirm(console, msg):
            print(f"Refused: {target} is out of scope.  (or run: brukal target {target})")
            return 2
        session_scope = _authorise_host(scope, target)
        yes_authorised = True          # explicitly authorising the host is the sign-off

    # 2b) Pre-authorise any vhosts the operator named (--host nexus.htb). A deliberate
    #     scope-time act: it lets auto-mode render vhost-gated web apps and Host-header
    #     requests without a mid-hunt `host` command, and ensure_cage_vhosts (below)
    #     maps each to the target IP in the cage so it actually resolves.
    for h in hosts or ():
        for n in _vhost_names(h):              # the host + its *.domain (vhost fuzzing)
            if n and n not in session_scope.authorized_hosts:
                session_scope = session_scope.with_host(n)
                _emit(console, f"  ✓ authorised vhost {n} (scope-time).")

    # 3) Live-run sign-off (fake cage needs none). Confirm interactively if a
    #    tty is available; otherwise the --yes-authorised flag is required.
    if not fake and not yes_authorised:
        if not _confirm(console, f"  LIVE run against {target}. Confirm you are "
                                 f"authorised to test it?"):
            print("Refused: a live run needs your authorisation (--yes-authorised).")
            return 2

    # 4) The brain — ask how to run the model, unless it was set on the CLI/env.
    if provider is None and not os.environ.get("BRUKAL_PROVIDER"):
        provider, model, base_url = choose_brain(console)

    audit = AuditLog(audit_path)
    approver = _rich_approver(console, holder) if console is not None else interactive_approver

    executor = Executor(Gate(session_scope, trust=TrustModel()),
                        FakeKali() if fake else DockerKali(container=container),
                        audit, approver=approver)
    try:
        strategist = StrategistAgent(LLMClient(model=model, provider=provider,
                                               base_url=base_url))
    except Exception as e:
        print(f"Could not initialise the model client: {e}")
        print("Set a key, or choose Ollama (free, local) when asked.")
        return 2

    # Per-target Obsidian vault → persistence + resume across sessions.
    vault_dir = _vault_for(vault_path, target)
    blackboard = Blackboard(vault_dir, session_scope)
    # Cross-session lessons live at the VAULT ROOT (shared across every target), so
    # Brukal carries what it learned from one box to the next.
    from .lessons import LessonStore
    lessons = LessonStore(Path(vault_path) / "lessons.jsonl")

    # A GOVERNED BROWSER for WEB actions (same scope gate + audit). Fake cage in
    # test mode; else render via headless Chromium + craft requests, both in-cage.
    from .web import GovernedBrowser
    if fake:
        from .web import FakeWebCage
        web_cage = FakeWebCage()
    else:
        from .chrome import DockerChromeCage
        from .web import CompositeWebCage, DockerHttpWebCage, ensure_cage_vhosts
        ensure_cage_vhosts(session_scope, container)
        web_cage = CompositeWebCage(DockerChromeCage(container=container),
                                    DockerHttpWebCage(container=container))
    browser = GovernedBrowser(session_scope, web_cage, audit)

    # On-demand research (control-plane egress only; disabled unless
    # BRUKAL_RESEARCH_SOURCES names allowlisted sources). Never touches the cage.
    from .research import ResearchProvider
    research = ResearchProvider()
    session = AssistSession(target, executor, strategist, skills=SkillLibrary(),
                            blackboard=blackboard, lessons=lessons, browser=browser,
                            research=research if research.enabled else None)
    cage = "fake" if fake else "docker:" + container
    return session, audit, target, cage


def run_solve(target=None, *, fake=False, yes_authorised=False, scope_path="scope.json",
              audit_path="runs/audit.jsonl", vault_path="runs/vault",
              container="brukal-kali", model=None, provider=None, base_url=None,
              auto=None, hosts=()) -> int:
    # A rich console (menu UI + spinner-aware approver), or plain fallback.
    holder: dict = {"status": None}
    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        console = None

    prep = _prepare_session(
        target, fake=fake, yes_authorised=yes_authorised, scope_path=scope_path,
        audit_path=audit_path, vault_path=vault_path, container=container,
        model=model, provider=provider, base_url=base_url,
        console=console, holder=holder, hosts=hosts)
    if isinstance(prep, int):
        return prep
    session, audit, target, cage = prep

    # How to work the plan — manual (approve each step) or auto (run safe steps).
    if auto is None:
        auto = choose_run_mode(console)

    try:
        if console is not None:
            _menu_loop(session, audit, target, cage, console, holder, auto=auto)
        else:
            _plain_loop(session, audit, target, cage, auto=auto)
    except KeyboardInterrupt:
        print()
    except Exception as e:
        if os.environ.get("BRUKAL_DEBUG"):
            raise
        print(f"\n  ⚠ model/cage error: {e}")
        print("  Check the model is reachable (key set, or Ollama running with "
              "`ollama serve`) and the cage is up. Set BRUKAL_DEBUG=1 for the trace.")
        return 1

    print(f"\n  session recorded to {audit_path}  ·  notes in {_session_vault(session)}"
          f"  ·  chain intact: {audit.verify()}\n")
    return 0


def _session_vault(session):
    """The vault directory a session persists to (for the closing summary line)."""
    return getattr(getattr(session, "blackboard", None), "root", "runs/vault")


def run_auto(target=None, *, fake=False, yes_authorised=False, scope_path="scope.json",
             audit_path="runs/audit.jsonl", vault_path="runs/vault",
             container="brukal-kali", model=None, provider=None, base_url=None,
             max_steps=20, handoff_to_menu=True, hosts=()) -> int:
    """Headless grounded agentic loop: Brukal autonomously drives the SAFE,
    in-scope enumeration. When it hands back (manual/escalation/stall/budget), and
    a human is present at a terminal, it drops straight into the interactive menu on
    the SAME session — no state lost, no need to re-launch `brukal solve`. Every
    command still goes through the gate; nothing out of scope runs. Set
    handoff_to_menu=False (or BRUKAL_NO_HANDOFF=1) to keep the old stop-and-exit
    behaviour. This is the engine `solve --auto` wraps, plus the live view."""
    from .loop import GroundedLoop

    holder: dict = {"status": None}
    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        console = None

    prep = _prepare_session(
        target, fake=fake, yes_authorised=yes_authorised, scope_path=scope_path,
        audit_path=audit_path, vault_path=vault_path, container=container,
        model=model, provider=provider, base_url=base_url,
        console=console, holder=holder, hosts=hosts)
    if isinstance(prep, int):
        return prep
    session, audit, target, cage = prep
    # In headless auto, an ESCALATE cleanly PAUSES the hunt (the loop hands back)
    # rather than prompting mid-live-view: dangerous/irreversible moves are approved
    # interactively in `brukal solve`. Fail-closed keeps the invariant intact.
    session.executor._approver = _auto_approver

    _emit(console, f"\n  brukal auto — target {target}   cage={cage}   "
                   f"budget={max_steps} steps",
          f"\n  [bold cyan]brukal auto[/] — target [bold]{target}[/]   "
          f"cage={cage}   budget={max_steps} steps")
    if session.resumed:
        _emit(console, f"  resumed — loaded {session.resumed} prior finding(s).")

    if not session.objectives:              # steer the autonomous hunt toward the goal
        session.add_objective(f"Enumerate {target}; examine any web service with the "
                              f"browser; find a way to a foothold (SSH/FTP/web) and "
                              f"capture the user and root flags.")

    view = _AutoLiveView(console, target, cage, max_steps,
                         session.objectives[0] if session.objectives else "") \
        if console is not None else None

    def observer(kind, payload):
        if view is not None:
            view.on(kind, payload)
        elif kind == "step":
            st = payload["step"]
            print(f"  [{st.index}] {(st.phase or '').upper():<12} {st.verdict or '-':<9} "
                  f"{(st.command or '')[:70]}\n        {st.summary[:100]}")

    from .verify import Verifier
    loop = GroundedLoop(session, max_steps=max_steps, observer=observer,
                        verifier=Verifier())      # confirm 'solved' from real output

    try:
        if not session.plan:
            if view is not None:
                view.set_status("🗺  planning the route…")
            session.make_plan()             # lay out the route before driving it
        if view is not None:
            with view.start():
                result = loop.run()
        else:
            result = loop.run()
    except KeyboardInterrupt:
        print("\n  paused.")
        return 0
    except Exception as e:
        if os.environ.get("BRUKAL_DEBUG"):
            raise
        print(f"\n  ⚠ model/cage error: {e}")
        print("  Check the model is reachable (key set, or Ollama running) and the "
              "cage is up. Set BRUKAL_DEBUG=1 for the trace.")
        return 1

    handoff = {
        "solved": "SOLVED — success verified from real gated output",
        "manual": "the next step is yours (intrusive/interactive exploitation)",
        "escalation": "a step needs your sign-off (ESCALATE)",
        "stalled": "no safe next step — over to you",
        "exhausted": "hit the step budget",
        "done": "nothing left to safely automate",
    }.get(result.stop_reason, result.stop_reason)
    spend = _spend_line(session)

    # Hand the wheel to the operator IN THE SAME SESSION when a human is present.
    # Auto stops because it ran out of *safe autonomous* moves — not because the
    # engagement is over. Dropping into the menu keeps every note/highlight/plan and
    # lets the human supply the next insight (the vhost leap, an exploit) without
    # re-launching. Skip only when non-interactive (piped/CI) or explicitly opted out.
    to_menu = (handoff_to_menu and not os.environ.get("BRUKAL_NO_HANDOFF")
               and sys.stdin.isatty())
    if to_menu:
        _emit(console,
              f"\n  ⏹ auto handed back: {handoff}\n     {result.stop_detail}\n"
              f"  ran {result.executed} command(s), {result.blocked} blocked · "
              f"{spend}\n  ↪ switching to MANUAL — you drive now (same session; "
              f"'q' to quit).\n",
              f"\n  [bold yellow]⏹ auto handed back:[/] {handoff}\n"
              f"     [grey70]{result.stop_detail}[/]\n"
              f"  ran [bold]{result.executed}[/] command(s), {result.blocked} blocked · "
              f"{spend}\n  [bold cyan]↪ switching to MANUAL[/] — you drive now "
              f"(same session; 'q' to quit).\n")
        # Restore the interactive approver (auto swapped in the auto one), so an
        # ESCALATE the operator picks prompts y/N instead of auto-deciding.
        from .engagement import interactive_approver
        session.executor._approver = _rich_approver(console, holder) if console \
            else interactive_approver
        try:
            if console is not None:
                _menu_loop(session, audit, target, cage, console, holder, auto=False)
            else:
                _plain_loop(session, audit, target, cage, auto=False)
        except KeyboardInterrupt:
            print()
        except Exception as e:
            if os.environ.get("BRUKAL_DEBUG"):
                raise
            print(f"\n  ⚠ model/cage error: {e}")
            return 1
        print(f"\n  session recorded to {audit_path} · chain intact: {audit.verify()}\n")
        return 0

    _emit(console,
          f"\n  ⏹ stopped: {handoff}\n     {result.stop_detail}\n"
          f"  ran {result.executed} command(s), {result.blocked} blocked · "
          f"continue in: brukal solve {target}\n"
          f"  session recorded to {audit_path} · chain intact: {audit.verify()}\n"
          f"{spend}\n",
          f"\n  [bold yellow]⏹ stopped:[/] {handoff}\n     [grey70]{result.stop_detail}[/]\n"
          f"  ran [bold]{result.executed}[/] command(s), {result.blocked} blocked · "
          f"continue in: [cyan]brukal solve {target}[/]\n"
          f"  session recorded to {audit_path} · chain intact: "
          f"[green]{audit.verify()}[/]\n{spend}\n")
    return 0
