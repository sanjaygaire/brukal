"""
test_assist.py — human-assisted solving (the strategist + the session).

Proves the strategist parses RUN/MANUAL advice, and — the key property — that a
command the strategist *suggests* is not a bypass: when the operator runs it, it
still goes through the gate. An out-of-scope suggestion is denied exactly as
always, and manual/notes are recorded for the trail.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession

SCOPE = Path(__file__).resolve().parents[1] / "scope.json"


class StubLLM:
    def __init__(self, response):
        self.response = response
        self.last_user = None

    def propose(self, system, user, max_tokens=1024):
        self.last_user = user
        return self.response


def test_strategist_parses_phase_goal_run_and_manual():
    llm = StubLLM("PHASE: enumeration\n"
                  "GOAL: fingerprint the web app on port 3000\n"
                  "REASONING: Port 3000 is a web app, so enumerate it before attacking.\n"
                  "RUN: whatweb http://10.10.10.5:3000\n"
                  "MANUAL: try default creds admin:admin in the login form")
    s = StrategistAgent(llm).advise("10.10.10.5", "port 3000 open")
    assert s.command == "whatweb http://10.10.10.5:3000"
    assert s.target == "10.10.10.5"
    assert s.phase == "enumeration"
    assert "fingerprint" in s.goal
    assert "default creds" in s.manual
    assert "enumerate it" in s.rationale


def test_highlight_findings_surfaces_key_results():
    from brukal.assist import highlight_findings
    out = ("Starting Nmap...\n"
           "22/tcp open  ssh     OpenSSH 8.2p1\n"
           "80/tcp open  http    Apache httpd 2.4.41\n"
           "Nmap done: 1 IP address\n")
    hits = highlight_findings(out)
    lines = " ".join(l for _, l in hits)
    assert "22/tcp open" in lines and "80/tcp open" in lines
    assert "Nmap done" not in lines            # noise is filtered out


def test_strategist_strips_trailing_parenthetical():
    # local models often append a "(why)" note to the RUN line — it must not end
    # up in the command that gets executed.
    llm = StubLLM("REASONING: Comprehensive scan first.\n"
                  "RUN: nmap -sV -p- 10.129.51.151   (to enumerate all services)")
    s = StrategistAgent(llm).advise("10.129.51.151", "")
    assert s.command == "nmap -sV -p- 10.129.51.151"


def test_strategist_strips_wrapping_backticks():
    # qwen wraps commands in backticks; a trailing "` " (backtick + space) must not
    # survive into the command (it would be denied as shell injection, as seen live
    # against Nexus). Both wrapped and trailing-only forms must come out clean.
    for raw in ("RUN: `curl -I http://10.129.234.54`",
                "RUN: curl -I http://10.129.234.54` ",
                # a trailing "(note)" AFTER the backtick must not re-expose it
                "RUN: curl -I http://10.129.234.54` (to grab headers)"):
        s = StrategistAgent(StubLLM(raw)).advise("10.129.234.54", "")
        assert s.command == "curl -I http://10.129.234.54"
        assert "`" not in s.command


def test_strategist_advice_only():
    s = StrategistAgent(StubLLM("Enumerate more before exploiting.")).advise("10.10.10.5", "")
    assert s.command is None and s.manual is None
    assert "Enumerate" in s.rationale


def test_suggested_command_still_goes_through_the_gate():
    scope = load_scope(SCOPE)
    tmp = tempfile.mkdtemp()
    try:
        kali = FakeKali()
        ex = Executor(Gate(scope), kali, AuditLog(Path(tmp) / "a.jsonl"))
        sess = AssistSession("10.10.10.5", ex,
                             StrategistAgent(StubLLM("RUN: nmap -sV 10.10.10.5")))

        sug = sess.advise()
        d, r, _ = sess.run(sug.command)
        assert d.verdict == "ALLOW" and r is not None
        assert kali.executed == ["nmap -sV 10.10.10.5"]

        # a suggestion pointed off-scope is STILL denied when the operator runs it
        d2, r2, _ = sess.run("nmap -sV 8.8.8.8", "8.8.8.8")
        assert d2.verdict == "DENY" and r2 is None
        assert kali.executed == ["nmap -sV 10.10.10.5"]     # not executed

        sess.note("found /admin panel")
        sess.manual("got a shell as www-data")
        assert any("found /admin" in n for n in sess.notes)
        assert any("www-data" in n for n in sess.notes)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_skill_focus_tracks_discovered_tech_not_static_string():
    # The query that pulls red-team playbooks must follow the LIVE state: recon
    # defaults before findings, then the actual services once discovered — and it
    # must NOT be dominated by the raw objective prose.
    scope = load_scope(SCOPE)
    tmp = tempfile.mkdtemp()
    try:
        from brukal.skills import SkillLibrary
        ex = Executor(Gate(scope), FakeKali(), AuditLog(Path(tmp) / "a.jsonl"))
        sess = AssistSession("10.129.234.54", ex, StrategistAgent(StubLLM("")),
                             skills=SkillLibrary())
        sess.add_objective("find the path to a foothold and the user flag")
        # before any findings -> recon-oriented default query (never empty/just the IP)
        early = sess._skill_focus()
        assert "reconnaissance" in early and "10.129" not in early
        # after discovering services -> the query names the actual tech
        sess.highlights += [("open port", "80/tcp open http nginx 1.24.0"),
                            ("open port", "22/tcp open ssh OpenSSH 9.6p1")]
        focus = sess._skill_focus()
        assert "nginx" in focus and "http" in focus and "ssh" in focus
        assert "reconnaissance" not in focus       # defaults drop out once tech is known
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_timeout_produces_learnable_feedback_note():
    # A command that times out in the cage must be recorded as an actionable
    # lesson ("TIMED OUT ... use a faster command"), not a bare verdict, so a weak
    # model course-corrects on the next turn.
    from brukal.kali import ExecResult

    class TimeoutKali:
        executed: list = []
        def run(self, command):
            return ExecResult(command, 124, "", "timed out")

    scope = load_scope(SCOPE)
    tmp = tempfile.mkdtemp()
    try:
        ex = Executor(Gate(scope), TimeoutKali(), AuditLog(Path(tmp) / "a.jsonl"))
        sess = AssistSession("10.10.10.5", ex, StrategistAgent(StubLLM("")))
        d, r, _ = sess.run("nmap -sV 10.10.10.5")           # ALLOWs, then times out
        assert d.verdict == "ALLOW" and r is not None       # it ran, just timed out
        assert any("TIMED OUT" in n and "faster" in n.lower() for n in sess.notes)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_strategist_parses_web_field():
    llm = StubLLM("PHASE: exploitation\nGOAL: tamper the login\n"
                  "REASONING: try SQLi.\nWEB: request POST http://nexus.htb/login u=admin")
    s = StrategistAgent(llm).advise("nexus.htb", "login page found")
    assert s.web == "request POST http://nexus.htb/login u=admin"
    assert s.command is None


def test_auto_web_action_reflex_on_open_web_port():
    from brukal import FakeWebCage, GovernedBrowser
    tmp = tempfile.mkdtemp()
    try:
        scope = load_scope(SCOPE)                       # authorises 10.10.10.0/24
        audit = AuditLog(Path(tmp) / "a.jsonl")
        ex = Executor(Gate(scope), FakeKali(), audit)
        browser = GovernedBrowser(scope, FakeWebCage(responses={"10.10.10.5": "<h1>App</h1>"}),
                                  audit)
        sess = AssistSession("10.10.10.5", ex, StrategistAgent(StubLLM("")), browser=browser)

        assert sess.auto_web_action() is None           # nothing found yet
        sess.highlights.append(("open port", "80/tcp open  http    nginx 1.24.0"))
        assert sess.auto_web_action() == "render http://10.10.10.5/"   # reflex fires
        sess.run_web("render http://10.10.10.5/")
        assert sess.auto_web_action() is None           # not rendered twice
        # an https service maps to https + its port
        sess.highlights.append(("open port", "8443/tcp open  ssl/http"))
        assert sess.auto_web_action() == "render https://10.10.10.5:8443/"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_run_web_routes_through_the_governed_browser():
    from brukal import FakeWebCage, GovernedBrowser
    tmp = tempfile.mkdtemp()
    try:
        scope = load_scope(SCOPE).with_host("nexus.htb")
        audit = AuditLog(Path(tmp) / "a.jsonl")
        ex = Executor(Gate(scope), FakeKali(), audit)
        cage = FakeWebCage(responses={"nexus.htb/flag": "HTB{web_flag}"})
        browser = GovernedBrowser(scope, cage, audit)
        sess = AssistSession("nexus.htb", ex, StrategistAgent(StubLLM("")), browser=browser)

        d, r, hl = sess.run_web("get http://nexus.htb/flag")
        assert d.verdict == "ALLOW" and r is not None and "HTB{" in r.body
        # an out-of-scope WEB action is denied and never reaches the cage
        d2, r2, _ = sess.run_web("get http://evil.com/")
        assert d2.verdict == "DENY" and r2 is None
        assert len(cage.actions) == 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_parse_plan_reads_numbered_steps_with_phase():
    from brukal.agents.strategist import parse_plan
    steps = parse_plan("Here's the route:\n"
                       "1. [recon] full TCP port scan with nmap -p-\n"
                       "2. [enumeration] enumerate web on :3000\n"
                       "3. exploit the login form\n"
                       "not a step line")
    assert len(steps) == 3
    assert steps[0].phase == "recon" and "port scan" in steps[0].text
    assert steps[1].phase == "enumeration"
    assert steps[2].phase == "" and "login" in steps[2].text


def test_parse_plan_recovers_phase_without_brackets():
    # qwen2.5 and other small models often skip the [phase] brackets and write
    # "1. recon nmap ..." or "1. **Exploit**: ..." — the phase must still be found.
    from brukal.agents.strategist import parse_plan
    steps = parse_plan("1. recon nmap -sV -p- 10.129.51.168\n"
                       "2. **Enumeration**: feroxbuster the web app\n"
                       "3. Exploit - the vulnerable login form\n")
    assert [s.phase for s in steps] == ["recon", "enumeration", "exploitation"]
    assert steps[0].text == "nmap -sV -p- 10.129.51.168"      # phase word peeled off
    assert steps[1].text == "feroxbuster the web app"
    assert steps[2].text == "the vulnerable login form"


def test_strategist_plan_returns_ordered_steps():
    llm = StubLLM("1. [recon] nmap -p- 10.10.10.5\n2. [enumeration] enum web\n")
    steps = StrategistAgent(llm).plan("10.10.10.5", "port 3000 open", "objective")
    assert [s.phase for s in steps] == ["recon", "enumeration"]


def _session_with_vault(vault_dir, target="10.10.10.5", plan_resp=None):
    """An AssistSession backed by a real Blackboard vault (for persistence tests)."""
    from brukal.blackboard import Blackboard
    scope = load_scope(SCOPE)
    kali = FakeKali()
    ex = Executor(Gate(scope), kali, AuditLog(Path(vault_dir).parent / "a.jsonl"))
    bb = Blackboard(vault_dir, scope)
    llm = StubLLM(plan_resp or "1. [recon] nmap -sV 10.10.10.5\n2. [enumeration] enum web")
    sess = AssistSession(target, ex, StrategistAgent(llm), blackboard=bb)
    return sess, kali


def test_session_persists_findings_and_plan_to_vault():
    tmp = tempfile.mkdtemp()
    try:
        vault = Path(tmp) / "vault" / "10.10.10.5"
        sess, kali = _session_with_vault(vault)
        sess.make_plan()
        d, r, _ = sess.run("nmap -sV 10.10.10.5")
        assert d.verdict == "ALLOW"

        # findings written to the shared markdown stream + a per-agent note
        assert (vault / "findings.jsonl").exists()
        assert (vault / "engagement.md").exists()
        assert "shortest path" in (vault / "plan.md").read_text().lower()
        agent_notes = list((vault / "agents" / "strategist").glob("*.md"))
        assert agent_notes, "a per-agent finding note should be written"
        # running the suggested first step advances the plan cursor
        assert sess.plan_cursor == 1 and sess.plan[0].done
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_session_resumes_prior_findings_from_vault():
    tmp = tempfile.mkdtemp()
    try:
        vault = Path(tmp) / "vault" / "10.10.10.5"
        s1, _ = _session_with_vault(vault)
        s1.make_plan()
        s1.run("nmap -sV 10.10.10.5")           # produces a finding + advances plan
        s1.note("22/tcp open ssh")

        # a brand-new session on the same vault must remember the last one
        s2, _ = _session_with_vault(vault)
        assert s2.resumed >= 2                    # prior findings loaded
        assert s2.plan and s2.plan[0].done        # completed step reloaded as done
        assert s2.plan_cursor >= 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_wizard_is_noninteractive_safe():
    # piped/non-tty: the wizard must not hang — it gets an empty target and exits.
    from brukal.assist import run_wizard
    assert run_wizard(fake=True) == 1


def test_tool_policy_panel_renders_without_console():
    from brukal.assist import _show_tool_policy
    _show_tool_policy(None)                 # plain-text branch must not raise


def test_pickers_are_noninteractive_safe():
    # Under pytest stdin is not a tty: the brain picker falls back to defaults and
    # the mode picker to MANUAL — neither may block waiting for input.
    from brukal.assist import choose_brain, choose_run_mode
    assert choose_brain(None) == (None, None, None)
    assert choose_run_mode(None) is False


def test_choose_brain_groq_option(monkeypatch):
    # Groq is a first-class menu entry (option 3): pick it, get the groq provider
    # and a strong default model, with GROQ_API_KEY prompted/ensured.
    import brukal.assist as a
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test")
    monkeypatch.setattr(a.sys.stdin, "isatty", lambda: True)
    answers = iter(["3", ""])          # choose Groq, accept the default model
    monkeypatch.setattr(a, "_ask", lambda console, prompt, default="": next(answers, default))
    assert a.choose_brain(None) == ("groq", "llama-3.3-70b-versatile", None)


class SeqLLM:
    """Returns scripted responses in order, then repeats the last one."""
    def __init__(self, responses):
        self.responses = list(responses)
        self.i = 0

    def propose(self, system, user, max_tokens=1024):
        r = self.responses[min(self.i, len(self.responses) - 1)]
        self.i += 1
        return r


_OPTIONS_REPLY = (
    "OPTION: scan services\nPHASE: recon\nGOAL: fingerprint the services\n"
    "REASONING: 22/80 open.\nRUN: nmap -sV 10.10.10.5\n"
    "---\n"
    "OPTION: brute ssh\nPHASE: exploitation\nGOAL: get ssh creds\n"
    "REASONING: try creds.\nRUN: hydra -l root -P rockyou.txt ssh://10.10.10.5")


def test_strategist_options_parses_ranked_list():
    from brukal.agents.strategist import StrategistAgent
    opts = StrategistAgent(StubLLM(_OPTIONS_REPLY)).options("10.10.10.5", "ports open")
    assert len(opts) == 2
    assert opts[0].command == "nmap -sV 10.10.10.5" and opts[0].phase == "recon"
    assert opts[1].command.startswith("hydra") and opts[1].phase == "exploitation"


def test_print_options_survives_empty_goal_and_rationale():
    # Regression: a weak/misbehaving model returned an option with no goal AND no
    # rationale; _print_options did "".splitlines()[0] -> IndexError and crashed the
    # manual menu. It must render (as "next move") without raising.
    from brukal.agents.strategist import Suggestion
    from brukal.assist import _print_options
    opt = Suggestion(rationale="", command="gobuster dir -u http://x/",
                     target="10.10.10.5", manual=None, phase="", goal="")
    _print_options([opt])          # would raise IndexError before the fix


def test_options_capture_conversational_read_before_the_moves():
    # The strategist must lead with a plain-English READ of the last result (so the
    # hunt reads like an analyst talking), and it must NOT bleed into the options.
    from brukal.agents.strategist import StrategistAgent, parse_read
    reply = ("READ: gobuster returned nothing and exited 1 — the wordlist path is "
             "wrong, so no dirs were actually tested. Let me fingerprint the app.\n"
             "OPTION: fingerprint\nRUN: whatweb http://10.10.10.5/\n---\n"
             "OPTION: ssh version\nRUN: nmap -sV -p 22 10.10.10.5")
    assert parse_read(reply).startswith("gobuster returned nothing")
    ag = StrategistAgent(StubLLM(reply))
    opts = ag.options("10.10.10.5", "findings")
    assert ag.last_read.startswith("gobuster returned nothing")   # captured
    assert [o.command for o in opts] == ["whatweb http://10.10.10.5/",
                                         "nmap -sV -p 22 10.10.10.5"]


def test_advise_options_falls_back_to_single_when_unformatted():
    # a model that ignores the ranked format still yields one usable option
    sess = AssistSession("10.10.10.5", None,
                         StrategistAgent(StubLLM("RUN: nmap -sV 10.10.10.5")))
    opts = sess.advise_options()
    assert len(opts) == 1 and opts[0].command == "nmap -sV 10.10.10.5"
    assert sess.last is opts[0]


def test_authorise_vhost_is_scope_time_and_covers_web_and_shell():
    # A vhost the operator authorises must become in-scope for BOTH the shell gate and
    # the web browser — a deliberate scope-time act, generalisable to any lab with
    # virtual hosts (not a Nexus special-case). Before: out of scope -> DENY.
    from brukal.assist import _authorise_vhost
    from brukal.web import FakeWebCage, GovernedBrowser, WebAction, check_web
    tmp = tempfile.mkdtemp()
    try:
        scope = load_scope(SCOPE)
        audit = AuditLog(Path(tmp) / "a.jsonl")
        ex = Executor(Gate(scope), FakeKali(), audit)
        br = GovernedBrowser(scope, FakeWebCage(), audit)
        sess = AssistSession("10.10.10.5", ex, None, browser=br)

        nav = WebAction(kind="navigate", url="http://vhost.lab/")
        assert check_web(nav, br._scope).verdict == "DENY"       # before: out of scope
        assert _authorise_vhost(sess, "vhost.lab") is True
        assert check_web(nav, br._scope).verdict == "ALLOW"      # after: authorised
        assert ex._gate.scope.contains_host("vhost.lab")         # shell gate too
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_plain_loop_option_pick_runs_through_gate():
    import io
    tmp = tempfile.mkdtemp()
    try:
        from brukal.assist import _plain_loop
        scope = load_scope(SCOPE)
        kali = FakeKali()
        audit = AuditLog(Path(tmp) / "a.jsonl")
        ex = Executor(Gate(scope), kali, audit)
        sess = AssistSession("10.10.10.5", ex,
                             StrategistAgent(SeqLLM(["1. [recon] scan", _OPTIONS_REPLY])))
        old = sys.stdin
        sys.stdin = io.StringIO("1\nquit\n")           # pick option 1 (the nmap)
        try:
            _plain_loop(sess, audit, "10.10.10.5", "fake")
        finally:
            sys.stdin = old
        assert kali.executed == ["nmap -sV 10.10.10.5"]   # option ran via the gate
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_plain_loop_custom_command_still_gated():
    # typing your own command runs it through the gate; out-of-scope is denied.
    import io
    tmp = tempfile.mkdtemp()
    try:
        from brukal.assist import _plain_loop, _looks_like_command
        assert _looks_like_command("nmap -sV 10.10.10.5")
        assert not _looks_like_command("focus on the web app")   # instruction, not cmd
        scope = load_scope(SCOPE)
        kali = FakeKali()
        audit = AuditLog(Path(tmp) / "a.jsonl")
        ex = Executor(Gate(scope), kali, audit)
        sess = AssistSession("10.10.10.5", ex,
                             StrategistAgent(SeqLLM(["1. [recon] scan", _OPTIONS_REPLY])))
        old = sys.stdin
        sys.stdin = io.StringIO("nmap -sV 8.8.8.8\nquit\n")   # custom, out-of-scope
        try:
            _plain_loop(sess, audit, "10.10.10.5", "fake")
        finally:
            sys.stdin = old
        assert kali.executed == []                      # out-of-scope custom cmd denied
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_run_options_parallel_runs_safe_and_skips_unsafe():
    # fan-out: safe (ALLOW) options run concurrently; an out-of-scope one is skipped
    # (not run in a worker), and everything is absorbed into session state.
    from brukal.agents.strategist import Suggestion
    tmp = tempfile.mkdtemp()
    try:
        scope = load_scope(SCOPE)
        kali = FakeKali()
        ex = Executor(Gate(scope), kali, AuditLog(Path(tmp) / "a.jsonl"))
        sess = AssistSession("10.10.10.5", ex, StrategistAgent(StubLLM("")))
        opts = [
            Suggestion("", "nmap -sV 10.10.10.5", "10.10.10.5", None),      # ALLOW
            Suggestion("", "whatweb http://10.10.10.5", "10.10.10.5", None),  # ALLOW
            Suggestion("", "nmap -sV 8.8.8.8", "8.8.8.8", None),           # out of scope
        ]
        results = sess.run_options_parallel(opts)
        ran = sorted(kali.executed)
        assert ran == ["nmap -sV 10.10.10.5", "whatweb http://10.10.10.5"]
        # the out-of-scope one was skipped (never executed), reported with a verdict
        labels = {label: (d.verdict if d else None) for label, d, r, _ in results}
        assert labels["nmap -sV 8.8.8.8"] == "DENY"
        assert any("[ran] nmap -sV 10.10.10.5" in n for n in sess.notes)   # absorbed
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_auto_mode_runs_the_safe_step_by_itself():
    import io
    tmp = tempfile.mkdtemp()
    try:
        from brukal.assist import _plain_loop
        scope = load_scope(SCOPE)
        kali = FakeKali()
        audit = AuditLog(Path(tmp) / "a.jsonl")
        ex = Executor(Gate(scope), kali, audit)
        llm = SeqLLM([
            "1. [recon] nmap -sV 10.10.10.5",                       # the plan
            "PHASE: recon\nGOAL: scan\nREASONING: go.\nRUN: nmap -sV 10.10.10.5",
            "PHASE: recon\nGOAL: think\nREASONING: enumerate more, nothing to run.",
        ])
        sess = AssistSession("10.10.10.5", ex, StrategistAgent(llm))
        old = sys.stdin
        sys.stdin = io.StringIO("quit\n")     # after auto pauses, we quit
        try:
            _plain_loop(sess, audit, "10.10.10.5", "fake", auto=True)
        finally:
            sys.stdin = old
        # the command ran WITHOUT the operator typing `run`
        assert kali.executed == ["nmap -sV 10.10.10.5"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_authorise_host_scopes_to_a_single_ip():
    from brukal.assist import _authorise_host, _vault_for
    scope = load_scope(SCOPE)
    narrowed = _authorise_host(scope, "10.129.51.168")
    assert narrowed.contains_ip("10.129.51.168")
    assert not narrowed.contains_ip("10.129.51.169")   # only the one /32
    assert narrowed.allowlisted_tools == scope.allowlisted_tools
    assert _vault_for("runs/vault", "10.129.51.168").name == "10.129.51.168"
