"""
agents/strategist.py — the advisory agent for human-assisted solving.

Unlike recon/exploit/verify (which each propose one gated command), the strategist
REASONS about the whole engagement like a companion sitting next to you: it names
the current PHASE, states the GOAL it is working toward, explains its REASONING
from the findings so far (and any objectives the box is asking you to answer), and
only then proposes the next move — a gated RUN command or a MANUAL step you do.

Its output is advice, not execution. If the operator runs a suggested command it
still goes through the gate. A suggestion is not a bypass.
"""
from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass

from ..llm import LLMClient

log = logging.getLogger(__name__)

# Tool basenames used to recognise a shell-looking line during salvage extraction.
# These are TOOL names (provider-agnostic), never model/provider names.
_TOOLISH = frozenset({
    "nmap", "masscan", "gobuster", "ffuf", "feroxbuster", "dirb", "wfuzz", "nikto",
    "whatweb", "wafw00f", "nuclei", "curl", "wget", "dig", "host", "dnsrecon",
    "dnsenum", "fierce", "sslscan", "smbclient", "smbmap", "enum4linux",
    "enum4linux-ng", "nbtscan", "snmpwalk", "onesixtyone", "ldapsearch", "redis-cli",
    "hydra", "medusa", "ncrack", "sqlmap", "wpscan", "john", "hashcat", "searchsploit",
    "crackmapexec", "netexec", "nxc", "kerbrute", "evil-winrm", "nc", "ncat", "netcat",
    "socat", "ssh", "ping", "python3", "php", "ruby", "perl"})

_FENCE_RE = re.compile(r"```[a-zA-Z0-9]*\s*\n?(.+?)```", re.S)


def _shell_ish(line: str) -> bool:
    line = line.strip().strip("`$ ").strip()
    if not line or line.startswith("#"):
        return False
    first = line.split()[0].lower().rsplit("/", 1)[-1]   # basename of a path-y tool
    return first in _TOOLISH


def _repair_command(cmd: "str | None") -> "str | None":
    """A command truncated by max_tokens leaves an unbalanced quote that the gate's
    shlex parse rejects (`hard:parse`). Balance a single trailing quote so the common
    cut-off `-H \"Host: nexus.htb` case survives; if it still won't parse, return None
    so an unrunnable command is never proposed. The gate re-validates the result, so
    this only recovers intent — it can't smuggle anything past scope/injection."""
    if not cmd:
        return cmd
    try:
        shlex.split(cmd)
        return cmd                                  # already parseable
    except ValueError:
        pass
    for q in ('"', "'"):
        if cmd.count(q) % 2 == 1:                    # odd count -> a dangling quote
            try:
                shlex.split(cmd + q)
                return cmd + q                       # balancing fixed it
            except ValueError:
                continue
    return None                                      # unrepairable -> drop it


def _salvage_command(text: str) -> "str | None":
    """Last-resort command extraction when the model gave no clean `RUN:` line — look
    inside a fenced code block first, then for the first shell-looking line in prose.
    Keeps a mis-formatted-but-usable reply from wasting the whole turn."""
    m = _FENCE_RE.search(text or "")
    if m:
        for line in m.group(1).splitlines():
            if _shell_ish(line):
                return line.strip().strip("`$ ").strip()
    for line in (text or "").splitlines():
        if _shell_ish(line):
            return line.strip().strip("`$ ").strip()
    return None

STRATEGIST_SYSTEM = (
    "You are a friendly, sharp penetration-testing companion guiding a human "
    "operator through an AUTHORISED engagement (e.g. a Hack The Box machine). "
    "Talk like a teammate thinking out loud, not a tool dispatcher. Keep the human "
    "oriented: what are we doing and why. Reason from the findings and, if given, "
    "the OBJECTIVES the box is asking the operator to answer.\n\n"
    "Reply in EXACTLY this template:\n"
    "PHASE: <recon | enumeration | exploitation | privilege-escalation | looting>\n"
    "GOAL: <the concrete thing we're trying to achieve right now, one line>\n"
    "REASONING: <2-4 sentences: what we've learned, what it implies, why this next "
    "step. Reference specific ports/services/findings. If an objective can now be "
    "answered, say so.>\n"
    "RUN: <one recon/enumeration command Brukal can run>   (optional)\n"
    "WEB: <a governed browser action for web-app testing>   (optional)\n"
    "MANUAL: <a step the operator does themselves — exploitation, a shell, cracking "
    "a hash, submitting a flag>   (optional)\n\n"
    "For WEB-APP work prefer a WEB action over a shell tool — it goes through the "
    "same gate but renders JS and can tamper requests. WEB grammar (verb first):\n"
    "  WEB: get <url>            fetch a URL (crafted request)\n"
    "  WEB: render <url>         load with a REAL headless browser (JS executed)\n"
    "  WEB: request <METHOD> <url> <body>   craft/tamper an HTTP request\n"
    "  WEB: fill <css-selector> <payload>   type a payload into a field\n"
    "  WEB: click <css-selector> · WEB: screenshot <url> · WEB: intercept <url>\n"
    "Payloads (SQLi/XSS) go straight in — that is the attack; the gate only checks "
    "the host is in scope.\n\n"
    "Give RUN for safe in-scope enumeration; give MANUAL for intrusive/interactive "
    "work. Prefer ONE clear next step. A separate gate still rules on any RUN.\n\n"
    "TACTICS — you run on a time budget, and any command that takes too long is "
    "KILLED and yields nothing, so work FAST and TARGETED:\n"
    "- First contact is a QUICK port scan, never a slow one. Use "
    "`nmap -Pn -T4 --top-ports 100 <ip>` (targets drop ping, so ALWAYS -Pn). Do NOT "
    "open with `nmap -A -p-`, `-sC -sV -p-`, or any all-65535-port/aggressive sweep — "
    "it TIMES OUT and you learn nothing.\n"
    "- Once you know the open ports, run ONE focused follow-up per service (e.g. "
    "`nmap -sVC -p 22,80 <ip>`, a `gobuster`/`ffuf` dir scan on the exact web port, "
    "`whatweb` on the web port).\n"
    "- WEB DIR/VHOST SCANS — get clean, bounded output or you learn nothing:\n"
    "    * ffuf: ALWAYS use `-s` (silent — prints only results, not a progress bar) and "
    "bound it with `-maxtime 120`. Example: "
    "`ffuf -s -maxtime 120 -w <small-list> -u http://<ip>/FUZZ`\n"
    "    * gobuster: use `-q` (quiet). Example: "
    "`gobuster dir -q -u http://<ip>/ -w <small-list>`\n"
    "    * WORDLIST: use a SMALL list — `/usr/share/seclists/Discovery/Web-Content/"
    "common.txt` (~4700) or `raft-small-words.txt`. NEVER `directory-list-2.3-medium` "
    "(~220k) — it runs for many minutes and is KILLED with no result.\n"
    "    * If the app is VHOST-ROUTED (a redirect to a hostname, e.g. nexus.htb), the "
    "raw IP serves only the default page — dir-scan WITH the Host header: "
    "`gobuster dir -q -u http://<ip>/ -H \"Host: <vhost>\" -w common.txt`. Scanning the "
    "bare IP will keep returning nothing.\n"
    "- If the FINDINGS say a previous command TIMED OUT or returned nothing, do NOT "
    "repeat it — choose a faster, narrower command.\n"
    "- ONLINE credential attacks (hydra/ncrack/medusa on ssh/ftp/http) with a HUGE "
    "wordlist like rockyou.txt (14M) can NEVER finish in the budget — it is KILLED and "
    "yields nothing. NEVER propose `-P .../rockyou.txt` for an online brute. Instead: "
    "try DEFAULT/known creds first, then a SMALL list (a few hundred lines) such as "
    "`/usr/share/seclists/Passwords/Common-Credentials/500-worst-passwords.txt` or "
    "`.../top-passwords-shortlist.txt`. If a small brute returns nothing, MOVE ON to "
    "another vector (web enum, a found service) rather than a bigger list.\n"
    "- Use ONLY real installed tools (nmap, whatweb, gobuster, ffuf, nikto, curl, "
    "smbclient, enum4linux, etc.). Never invent module paths, script files, or "
    "`msfconsole -r <made-up-file>` — those don't exist and will be rejected.\n"
    "- A RUN command is ONE tool run directly, with NO shell features. The cage "
    "captures the FULL output for you automatically, so you NEVER need to trim, pipe, "
    "or redirect. These are ALL rejected as injection — do NOT use any of them: "
    "`| head`, `| grep`, `| tail`, any pipe '|'; `2>/dev/null`, `2>&1`, `>`, `<`, "
    "`>>`; `&&`, `||`, `;`; backticks or `$(...)`; and `-o file`. If you catch "
    "yourself adding `| head` or `2>/dev/null`, STOP and send the bare command — the "
    "output is already captured and shown in full. Example: send "
    "`curl -sv http://target/` NOT `curl -sv http://target/ 2>&1 | head -50`.\n"
    "- Do NOT query external DNS servers (e.g. `dig @1.1.1.1`, `@8.8.8.8`) or any host "
    "that is not the target — they are out of scope and DENIED.\n"
    "- You NEVER need to edit /etc/hosts or resolve a vhost yourself — Brukal maps "
    "authorised vhosts to the target IP inside the cage automatically. To hit a vhost, "
    "just send the tool's Host-header option against the TARGET IP, as ONE clean "
    "command (close every quote):\n"
    "    virtual-host discovery: "
    "`ffuf -w <wordlist> -u http://<target-ip>/ -H \"Host: FUZZ.<domain>\" -fs 0`\n"
    "    hit a known vhost:      "
    "`gobuster dir -u http://<target-ip>/ -H \"Host: <vhost>\" -w <wordlist>`\n"
    "  Propose ONE tool per move. To test several things, give them as SEPARATE ranked "
    "options — NEVER chain with `&&`, `;`, or a loop; chaining is rejected as injection.\n"
    "- Brukal HUNTS AUTONOMOUSLY end to end. Propose the next concrete action as a "
    "RUN command, INCLUDING exploitation: credential attacks (hydra/ncrack/medusa), "
    "sqlmap, known-CVE exploits, nuclei templates, impacket, catching data. The gate "
    "runs safe steps automatically and PAUSES risky/irreversible ones for the "
    "operator's one-tap sign-off, so don't hold back — propose the real attack that "
    "moves toward the flag. Use MANUAL ONLY for steps the cage truly cannot do as a "
    "single non-interactive command: an interactive password/shell prompt (use "
    "`brukal shell` or the governed session instead), a GUI/browser step, or human "
    "judgement."
)


STRATEGIST_OPTIONS_SYSTEM = (
    STRATEGIST_SYSTEM
    + "\n\nYou are talking to the operator like a teammate at the keyboard, not a "
    "command generator. FIRST, react to the MOST RECENT result in the findings: begin "
    "your reply with a single line starting `READ:` — 1-2 plain-English sentences "
    "saying what the last command actually told us (or, if it failed/timed out/returned "
    "nothing, say so and why) and what that implies for the next move. Talk like a "
    "human analyst, not a template.\n"
    "THEN give a RANKED SHORT LIST of the best 2-4 next moves, BEST FIRST — genuinely "
    "different approaches, not the same command reworded. Separate each option with a "
    "line containing only '---', and start each with a one-line label:\n"
    "OPTION: <short label of the move>\n"
    "PHASE: ...\nGOAL: ...\nREASONING: ...\nRUN: <command>   (or)   MANUAL: <step>\n"
    "---\n"
    "OPTION: <next label>\n...\n"
    "Rank by what most likely moves us toward the flag right now. A RUN option must be "
    "a real command to execute, never a placeholder like '(need to see the form first)'."
)


STRATEGIST_PLAN_SYSTEM = (
    "You are a penetration-testing companion planning the SHORTEST path to the "
    "goal on an AUTHORISED engagement (typically the user+root flags on a Hack The "
    "Box machine, or the listed objectives). Given the target, the objectives, and "
    "the findings so far, lay out a concise ordered plan of the next concrete "
    "steps — recon → enumeration → exploitation → privilege-escalation → looting — "
    "only as many steps as actually get us there. Don't enumerate everything; "
    "enumerate what moves us toward the goal.\n\n"
    "Reply as a numbered list, ONE step per line, nothing else:\n"
    "1. [phase] <concrete step naming the tool/technique>\n"
    "2. [phase] <...>\n"
    "Keep it to 3-7 steps. If findings already answer earlier steps, start the "
    "plan from the next real move.\n\n"
    "TACTICS: step 1 is ALWAYS a FAST targeted port scan "
    "(`nmap -Pn -T4 --top-ports 100 <ip>`), never `nmap -A -p-` or a full/aggressive "
    "all-port sweep (those TIME OUT). Later steps do focused per-service enumeration. "
    "One real, installed tool per step; never invent module/script file paths."
)


STRATEGIST_ANSWER_SYSTEM = (
    "You are Brukal, a penetration-testing companion, answering the operator's "
    "QUESTION about the engagement you are BOTH looking at right now — like a "
    "teammate at the keyboard, the way Claude Code answers questions about a task.\n"
    "Answer conversationally and concretely, grounded ONLY in the FINDINGS, KEY "
    "RESULTS, and NOTES provided (these are the real, gate-executed results). Cite "
    "the actual ports, services, versions, hosts, paths, and credentials that appear "
    "there. Be specific and brief — a few sentences, not an essay.\n"
    "If the findings do NOT contain the answer, SAY SO plainly ('we haven't found "
    "that yet') and, if useful, name the one command that would find it — but do NOT "
    "run anything and do NOT invent a result you have no evidence for. Never fabricate "
    "a flag, a shell, or a credential. If asked 'why' you did something, explain your "
    "reasoning from the findings. Plain prose; no rigid template."
)


@dataclass
class PlanStep:
    text: str                 # the concrete step, e.g. "enumerate web on :3000 with feroxbuster"
    phase: str = ""           # recon / enumeration / exploitation / ...
    done: bool = False


@dataclass
class Suggestion:
    rationale: str            # the REASONING text (companion voice)
    command: str | None       # a gated shell command Brukal can run, if any
    target: str | None        # target for that command
    manual: str | None        # a manual step for the operator, if any
    phase: str = ""           # recon / enumeration / exploitation / ...
    goal: str = ""            # the concrete objective of this step
    web: str | None = None    # a gated WEB action (navigate/get/request/fill/...), if any


_PLAN_LINE = re.compile(r"^\s*\d+[.)]\s*(?:\[(?P<phase>[^\]]+)\]\s*)?(?P<text>.+?)\s*$")

# Canonical phase names, and the aliases smaller models emit without brackets
# (e.g. qwen2.5 writes "1. recon nmap ..." or "1. **Exploit**: ...").
_PHASE_ALIASES = {
    "recon": "recon", "reconnaissance": "recon",
    "enum": "enumeration", "enumeration": "enumeration", "enumerate": "enumeration",
    "exploit": "exploitation", "exploitation": "exploitation",
    "privesc": "privilege-escalation", "priv-esc": "privilege-escalation",
    "privilege": "privilege-escalation", "privilege-escalation": "privilege-escalation",
    "escalate": "privilege-escalation", "escalation": "privilege-escalation",
    "loot": "looting", "looting": "looting",
    "post": "looting", "post-exploitation": "looting",
}
# Nouns that are safe to peel off even with just a space ("recon nmap ..."). Verbs
# (exploit, loot, escalate, enumerate) are NOT here — "exploit the login form" is a
# real step, not a phase label — so they only count when a separator makes the
# label explicit ("Exploit: ...", "Exploit - ...").
_BARE_PHASE_NOUNS = {
    "recon", "reconnaissance", "enum", "enumeration", "exploitation",
    "privesc", "priv-esc", "privilege", "privilege-escalation", "escalation",
    "looting", "post", "post-exploitation",
}
_LEAD_PHASE_SEP = re.compile(r"^([A-Za-z][A-Za-z-]*)\s*[:\-–—)]\s+(.*)$")
_LEAD_PHASE_BARE = re.compile(r"^([A-Za-z][A-Za-z-]*)\s+(.*)$")


def _normalise_phase(phase: str, body: str) -> tuple[str, str]:
    """Return (canonical_phase, body). If no bracketed phase was given, peel a
    leading phase word off the body (how models without [brackets] format it)."""
    phase = _PHASE_ALIASES.get(phase.strip().lower(), phase.strip().lower())
    if phase:
        return phase, body
    sep = _LEAD_PHASE_SEP.match(body)                 # "recon: ..."  /  "Exploit - ..."
    if sep and sep.group(1).lower() in _PHASE_ALIASES and sep.group(2).strip():
        return _PHASE_ALIASES[sep.group(1).lower()], sep.group(2).strip()
    bare = _LEAD_PHASE_BARE.match(body)               # "recon nmap ..." (nouns only)
    if bare and bare.group(1).lower() in _BARE_PHASE_NOUNS and bare.group(2).strip():
        return _PHASE_ALIASES[bare.group(1).lower()], bare.group(2).strip()
    return phase, body


def parse_plan(text: str) -> list[PlanStep]:
    """Parse a numbered plan into ordered PlanSteps. Tolerant of models that
    wrap the list in prose, use markdown, or drop the [phase] brackets."""
    steps: list[PlanStep] = []
    for line in (text or "").splitlines():
        m = _PLAN_LINE.match(line)
        if not m:
            continue
        body = m.group("text").strip().strip("`").replace("**", "").strip()
        phase, body = _normalise_phase(m.group("phase") or "", body)
        if body:
            steps.append(PlanStep(text=body, phase=phase))
    return steps


def _field(text: str, name: str) -> str:
    m = re.search(rf"^{name}\s*:\s*(.+?)\s*$", text, re.M | re.I)
    return m.group(1).strip() if m else ""


def parse_read(text: str) -> str:
    """Extract the leading `READ:` line — the strategist's plain-English take on the
    latest result (what just happened + what it implies), shown to the operator before
    the options so the hunt reads like an analyst talking, not a command menu."""
    read = _field(text or "", "READ")
    return read.strip().strip("`*").strip()


def parse_options(text: str, default_target: str, limit: int = 4) -> list[Suggestion]:
    """Parse a ranked list of next-move options. Tolerant of models that use
    '---' separators, 'OPTION:' markers, both, or neither (then it's one option)."""
    text = text or ""
    if re.search(r"(?im)^\s*OPTION\b", text):
        chunks = re.split(r"(?im)^\s*OPTION\b\s*[:).\-]?\s*", text)
    else:
        chunks = re.split(r"(?m)^\s*-{3,}\s*$", text)
    out: list[Suggestion] = []
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        s = _parse(chunk, default_target)
        if not (s.command or s.manual):
            continue                              # a block with no actionable move
        if not s.goal:                            # use the option's label line as the goal
            first = chunk.splitlines()[0].strip(" :-*`")
            if first and not re.match(r"(?i)(phase|goal|reasoning|run|manual)\s*:", first):
                s.goal = first[:80]
        out.append(s)
        if len(out) >= limit:
            break
    if not out:                                   # model ignored the format -> single move
        single = _parse(text, default_target)
        if single.command or single.manual or single.rationale:
            out = [single]
    return out


def _parse(text: str, default_target: str) -> Suggestion:
    text = text or ""
    phase = _field(text, "PHASE")
    goal = _field(text, "GOAL")
    reasoning = _field(text, "REASONING")
    command = _field(text, "RUN") or None
    manual = _field(text, "MANUAL") or None
    web = _field(text, "WEB") or None

    if web:
        web = web.strip().strip("`\"'").strip()
        if " (" in web:
            web = web[:web.index(" (")].strip()
        web = web.strip("`\"'").strip() or None

    if command:                                   # strip a trailing "(why)" note
        # Peel wrapping whitespace AND quotes/backticks in any order — models often
        # emit `cmd` or "cmd" or `cmd ` (a trailing backtick after a space survives a
        # naive strip("`") and then gets denied as injection, wasting a turn).
        command = command.strip().strip("`\"'").strip()
        if " (" in command:
            command = command[:command.index(" (")].strip()
        command = command.strip("`\"'").strip()   # re-peel: the paren trim can re-expose a backtick
        command = _repair_command(command or None)  # balance a truncated trailing quote
    if manual and manual.lower() in ("none", "n/a", "-"):
        manual = None

    # No clean RUN/WEB/MANUAL parsed -> try to salvage a command from a code fence or
    # a shell-looking line before giving up. Only warn if the model clearly TRIED to
    # propose an action (used a marker/fence) but we couldn't parse it — a deliberate
    # advice-only reply is legitimate and stays quiet.
    if command is None and manual is None and web is None:
        salvaged = _salvage_command(text)
        if salvaged:
            command = salvaged
        elif re.search(r"(?im)^\s*(RUN|WEB|MANUAL)\s*:|```", text):
            log.warning("strategist: could not extract an action from model reply: %r",
                        (text[:200] + "…") if len(text) > 200 else text)

    # Fall back to the whole reply as rationale if the model ignored the template.
    if not reasoning:
        reasoning = re.sub(r"^(PHASE|GOAL|RUN|MANUAL|WEB)\s*:.*$", "", text,
                           flags=re.M | re.I).strip() or text.strip()

    return Suggestion(rationale=reasoning, command=command,
                      target=default_target if command else None, manual=manual,
                      phase=phase, goal=goal, web=web)


class StrategistAgent:
    def __init__(self, llm: LLMClient):
        self._llm = llm
        self.last_read = ""      # the conversational "what just happened" from options()

    def plan(self, target: str, findings: str, objectives: str = "",
             reference: str = "") -> list[PlanStep]:
        """Lay out the shortest-path plan of concrete next steps."""
        parts = [f"TARGET: {target}"]
        if objectives:
            parts.append(f"OBJECTIVES to answer:\n{objectives}")
        parts.append(f"FINDINGS SO FAR:\n{findings or '(nothing yet — just starting)'}")
        if reference:
            parts.append(reference)               # untrusted skill reference, labelled
        parts.append("Give me the shortest-path plan as a numbered list.")
        text = self._llm.propose(STRATEGIST_PLAN_SYSTEM, "\n\n".join(parts), max_tokens=500)
        return parse_plan(text)

    def _context_parts(self, target, findings, notes, reference, objectives, plan,
                       known="", tried=""):
        parts = [f"TARGET: {target}"]
        if objectives:
            parts.append(f"OBJECTIVES the box is asking us to answer:\n{objectives}")
        if plan:
            parts.append(f"OUR PLAN (work the marked ▶ step next; keep advice on the "
                         f"shortest path):\n{plan}")
        # State block. LEAD with the confirmed structured facts, then what we've
        # already tried (so the model builds on knowledge and stops re-running the
        # same move), then the raw recent activity, then an explicit "advance" cue.
        if known:
            parts.append(f"KNOWN — confirmed facts so far (build on these, don't "
                         f"re-discover them):\n{known}")
        if tried:
            parts.append(f"ALREADY TRIED — do NOT repeat any of these; pick a "
                         f"GENUINELY DIFFERENT move (new tool, port, path, or the next "
                         f"phase):\n{tried}")
        parts.append(f"RECENT ACTIVITY (latest command output):\n"
                     f"{findings or '(nothing yet — we just started)'}")
        parts.append("UNKNOWN / NEXT: advance the current phase toward the objective. "
                     "If the last move returned nothing or was blocked, change tactic "
                     "— do not retry the same thing.")
        if notes:
            parts.append(f"OPERATOR JUST SAID:\n{notes}")
        if reference:
            parts.append(reference)               # untrusted skill reference, labelled
        return parts

    def options(self, target: str, findings: str, notes: str = "", reference: str = "",
                objectives: str = "", plan: str = "", n: int = 3,
                known: str = "", tried: str = "") -> list[Suggestion]:
        """Return a RANKED list of the best next moves (best first), so the operator
        can pick one, tweak it, or give their own instruction instead."""
        parts = self._context_parts(target, findings, notes, reference, objectives,
                                    plan, known=known, tried=tried)
        parts.append(f"Give me up to {n} ranked next-move options in the format.")
        # 1600 (was 1000): a verbose model (e.g. deepseek-chat) writing 3 options with
        # long reasoning could overrun 1000 and get its LAST command CUT OFF mid-quote,
        # which then failed the gate's parse. More headroom stops that truncation.
        text = self._llm.propose(STRATEGIST_OPTIONS_SYSTEM, "\n\n".join(parts),
                                 max_tokens=1600)
        self.last_read = parse_read(text)     # the "what just happened" line, shown first
        return parse_options(text, target, limit=n)

    def answer(self, target: str, question: str, findings: str, highlights: str = "",
               notes: str = "", plan: str = "", reference: str = "") -> str:
        """Answer the operator's free-text QUESTION about the hunt, grounded in the
        real findings — a conversational reply, not a move to run. Never fabricates
        results it has no evidence for (the anti-hallucination rule holds here too)."""
        parts = [f"TARGET: {target}"]
        if plan:
            parts.append(f"PLAN:\n{plan}")
        if highlights:
            parts.append(f"KEY RESULTS (what we've confirmed):\n{highlights}")
        parts.append(f"FINDINGS / what we've done so far:\n"
                     f"{findings or '(nothing yet — we just started)'}")
        if reference:
            parts.append(reference)
        parts.append(f"OPERATOR'S QUESTION:\n{question}\n\nAnswer it directly.")
        return self._llm.propose(STRATEGIST_ANSWER_SYSTEM, "\n\n".join(parts),
                                 max_tokens=700).strip()

    def advise(self, target: str, findings: str, notes: str = "",
               reference: str = "", objectives: str = "", plan: str = "",
               known: str = "", tried: str = "") -> Suggestion:
        parts = self._context_parts(target, findings, notes, reference, objectives,
                                    plan, known=known, tried=tried)
        parts.append("Give me the next step in the template.")
        text = self._llm.propose(STRATEGIST_SYSTEM, "\n\n".join(parts), max_tokens=800)
        return _parse(text, target)
