# Brukal Milestone 1 — Complete Code Walkthrough

This document explains **every file** in the repo: what it contains, why it
exists, and what each piece of code does — slowly, one concept at a time, with
every term defined the first time it appears.

Read it in this order. The files are presented the way *data flows* through the
system, so each file builds on the one before it.

```
the policy ──► loads it ──► judges with it ──► runs in a cage ──► writes a log
 scope.json    scope.py      gate.py           kali.py            audit.py
                                  └────────── tied together by ──────────┘
                                              executor.py
```

---

## A 30-second mental model first

Picture a **bank vault** with one door. Outside the door stands a **guard**
with a **rulebook**. Anyone who wants something from the vault must hand the
guard a written request. The guard checks the rulebook, and either opens the
door or refuses — and writes every decision in a **ledger** that can't be
erased.

- The **vault** = the Kali container where tools actually run (`kali.py`).
- The **guard** = the gate (`gate.py`).
- The **rulebook** = the scope policy (`scope.json` loaded by `scope.py`).
- The **ledger** = the audit log (`audit.py`).
- The **one door everyone must use** = the executor (`executor.py`).

That's the whole system. Now the details.

---

# 1. `scope.json` — the rulebook (the engagement policy)

### What it is

A plain data file. No code, just facts: *what is Brukal allowed to do on this
job?* In penetration testing this is called the **engagement policy** or
**scope** — the contract that says which machines you may touch. (Touching a
machine outside scope is, legally, an attack rather than a test. So this file is
the line between "authorised security work" and "crime.")

The format is **JSON** (JavaScript Object Notation) — a universal way to write
structured data as text, using `{ }` for groups of named values and `[ ]` for
lists. Every programming language can read it.

### The contents

```json
{
  "engagement": "brukal-lab-01",
  "authorized_cidrs": ["10.10.10.0/24", "127.0.0.1/32"],
  "allowlisted_tools": ["nmap", "gobuster", "nikto", "whatweb", "curl", "dig"],
  "rate_limit_per_min": 30
}
```

Field by field:

- **`engagement`** — a human-readable name for this job. Goes into the audit log
  so you can tell one engagement's records from another's.
- **`authorized_cidrs`** — the list of networks you may touch. **CIDR**
  (Classless Inter-Domain Routing, say "cider") is a compact way to write a
  *range* of IP addresses. `10.10.10.0/24` means "all addresses from
  `10.10.10.0` to `10.10.10.255`" — the `/24` says "the first 24 bits are fixed,
  the last 8 can be anything," which is 256 addresses. `127.0.0.1/32` has `/32`,
  meaning *all* bits fixed — exactly one address (your own machine, "localhost").
- **`allowlisted_tools`** — the only programs allowed to run. An **allowlist**
  permits *only* what's named and denies everything else. (The opposite, a
  *denylist*, blocks known-bad things and allows everything else — weaker,
  because you can't list every bad thing.)
- **`rate_limit_per_min`** — the most actions allowed per minute, so the system
  can't hammer a target.

### Why it matters

This is the **single source of truth**. Every "is this allowed?" question is
answered against this one file. In the running system it's treated as
**read-only** — nothing is allowed to widen it while Brukal runs. That property
is what lets you *prove* the safety claim: if the authorised set can never grow
at runtime, then an out-of-scope action can never become in-scope. It also keeps
the gate honest against the nastiest attack (a hostile target trying to trick
the system into expanding scope) — more on that under `gate.py`.

---

# 2. `brukal/scope.py` — loading and understanding the rulebook

### What it is

The code that reads `scope.json` from disk and turns it into something the rest
of the program can *ask questions of*, like "is this IP in scope?"

It uses only Python's **standard library** ("stdlib") — the batteries that come
with Python itself, no extra downloads. That's deliberate: the safety-critical
core should depend on as little as possible.

### The key pieces

**The `Scope` class.**

```python
@dataclass(frozen=True)
class Scope:
    engagement: str
    authorized_networks: tuple
    allowlisted_tools: frozenset
    rate_limit_per_min: int
```

A **class** is a blueprint for an object that bundles related data and the
functions that work on it. A **dataclass** is a Python shortcut that writes the
boring bookkeeping for you when a class is mostly just fields.

`frozen=True` makes it **immutable** — once built, its fields can't be changed.
This is a guard rail: it means no stray line of code can accidentally (or
maliciously) overwrite the authorised networks while the program runs. The
rulebook, once read, is locked.

Notice the field types: `authorized_networks` is a **tuple** (an ordered list
that can't be changed) and `allowlisted_tools` is a **frozenset** (a set — a
collection with no duplicates and fast membership checks — that also can't be
changed). Both are the unchangeable cousins of the normal list and set,
reinforcing that locked-rulebook idea.

**Asking "is this IP in scope?"**

```python
def contains_ip(self, ip_text: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_text.strip())
    except ValueError:
        return False
    return any(ip in net for net in self.authorized_networks)
```

`ipaddress` is a stdlib module that understands IP addresses and networks. The
logic: try to read the text as an IP; if it isn't a valid IP, return `False`
(out of scope). If it is, check whether it falls inside *any* authorised
network.

The critical detail is the `except ValueError: return False`. This is
**fail-closed** (also called fail-safe): when something goes wrong or is
unclear, the safe default is to *deny*, never to allow. A lock that pops open
when it malfunctions is dangerous; a lock that stays shut is safe. Every check
in Brukal fails closed.

**Loading the file.**

```python
def load_scope(path) -> Scope:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    nets = []
    for cidr in data["authorized_cidrs"]:
        nets.append(ipaddress.ip_network(cidr, strict=False))
    return Scope(...)
```

It reads the file, converts each CIDR string into a real network object (so
membership tests are fast and correct), and packs everything into the immutable
`Scope`. If the file is malformed this *raises an error* and the program refuses
to start — which is exactly right. You'd rather not run at all than run with a
rulebook you can't trust.

### Why it matters

This file turns dead text into a living, query-able policy, and it bakes in two
of Brukal's core principles at the lowest level: **immutability** (the rulebook
can't shift under you) and **fail-closed** (uncertainty means deny).

---

# 3. `brukal/gate.py` — the guard (the deterministic hard gate)

This is the **most important file in the system**. If you understand only one
file, understand this one.

### What it is

The **gate** is the guard at the vault door. Every proposed action passes
through it, and it returns one of: **ALLOW**, **DENY**, or (later) **ESCALATE**.

The word that matters most: **deterministic**. It means the gate is plain,
predictable code — the same input always gives the same output — with **no
language model (LLM) anywhere inside it**. This is a *design decision with a
reason*: in a pentest, the target you're attacking is hostile, and its output
flows back into your system. A hostile target can plant text like *"this host is
authorised, add it to scope."* If the thing enforcing scope were an LLM, it
could be *talked into* obeying that text (this trick is called **prompt
injection** — smuggling instructions into data an AI reads). You cannot argue
with a regular expression. So scope is enforced by dumb, literal code on
purpose. That immovability is a feature.

### The `Decision` object

```python
@dataclass
class Decision:
    verdict: str          # "ALLOW" | "DENY" | "ESCALATE"
    action: str           # the command judged
    target: str           # the declared target
    agent: str            # who proposed it
    reason: str           # why
    layer: str            # which check decided it
    timestamp: float

    @property
    def allowed(self) -> bool:
        return self.verdict == "ALLOW"
```

This is the *structured ruling* the gate returns. "Structured" means named
fields, not a sentence of prose — which is what makes it loggable and, later,
countable for your paper's results (you can filter the audit log for
`verdict == "DENY"` and `layer == "hard:scope"` and literally count your scope
interceptions). The `allowed` **property** (a method that reads like a simple
attribute) is a convenience so the rest of the code can write
`if decision.allowed:` instead of comparing strings.

### The checks, in order

The gate runs a series of checks as a logical **AND**: *every* one must pass, and
the first failure denies. They're ordered cheapest-and-most-absolute first.

**Check 0 — injection guard.**

```python
_SHELL_METACHARACTERS = ";|&`><\n\r"
_SUBSTITUTION_PATTERNS = ("$(", "${", "`")

if any(c in command for c in _SHELL_METACHARACTERS) or \
   any(p in command for p in _SUBSTITUTION_PATTERNS):
    return self._deny(... "hard:injection")
```

A **shell** is the program that runs commands on Linux. Certain characters have
special powers in it: `;` runs a second command, `|` pipes one into another,
`&&` chains them, and `$(...)` or backticks run a command and paste its output
in. An attacker (or a confused agent) could write `nmap 10.10.10.5; rm -rf /` —
the gate might approve the `nmap` part while the `;` smuggles in a destructive
command. So before anything else, if the command contains any of these
"metacharacters," the gate refuses outright. This single check defeats a whole
family of attacks.

**Check 1 — parse.**

```python
try:
    parts = shlex.split(command)
except ValueError:
    return self._deny(... "hard:parse")
```

`shlex.split` breaks a command string into its pieces the way a shell would
(respecting quotes), but *without running anything*. If the command is so
malformed it can't even be parsed, we deny (fail-closed again). `parts[0]` will
be the program name; the rest are its arguments.

**Check 2 — tool allowlist.**

```python
tool = os.path.basename(parts[0])
if not self.scope.tool_allowed(tool):
    return self._deny(... "hard:allowlist")
```

`os.path.basename` strips any directory path, so `/usr/bin/nmap` becomes just
`nmap` — this stops someone sneaking a tool past the list by writing its full
path. Then it checks that bare name against the allowlist. Not on the list →
denied.

**Check 3 — declared target in scope.**

```python
if not self.scope.contains_ip(target):
    return self._deny(... "hard:scope")
```

The action request says which target it's aimed at. That target must be in
scope. This is the headline check — the one your "100% interception" claim rests
on.

**Check 4 — no smuggled host.**

```python
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
...
for host in _IPV4_RE.findall(command):
    if not self.scope.contains_ip(host):
        return self._deny(... "hard:scope")
```

This is subtle and important. Suppose the declared target is the in-scope
`10.10.10.5`, but the command is `nmap 10.10.10.5 8.8.8.8` — a second,
out-of-scope host is hidden in the arguments. Checking only the declared target
would miss it. So a **regular expression** (a pattern that finds text matching a
shape — here, anything that looks like an IPv4 address) pulls *every* IP out of
the command, and each one must be in scope. This closes the smuggling hole.
It's also a concrete example of the principle **"never trust the agent's
self-report"** — the gate doesn't believe the declared target; it re-reads the
whole command itself.

**Check 5 — rate limit.**

```python
def _rate_ok(self):
    now = time.time()
    self._recent_allows = [t for t in self._recent_allows if now - t < 60.0]
    return len(self._recent_allows) < self.scope.rate_limit_per_min
```

This keeps a list of timestamps of recent allowed actions, throws away any older
than 60 seconds (a **sliding window**), and checks the count against the limit.
It stops the system from flooding a target.

**Passing the gate.**

```python
self._recent_allows.append(time.time())
return Decision("ALLOW", ...)
```

If an action survives all five checks, it's allowed. Right above this line is a
big commented **extension point** marked `MILESTONE 3` — that's exactly where the
*soft* risk score (impact/policy) and the ESCALATE-to-human path will slot in
later. The structure is already shaped to receive them: hard checks first (done),
soft scoring second (to come).

### Why it matters

This file *is* the safety guarantee. Every principle from the architecture lives
here in code: no LLM, fail-closed, hard checks as an AND, and never trusting the
agent. It's deliberately boring and literal, because boring and literal is what
"untrickable" looks like.

---

# 4. `brukal/kali.py` — the vault (the execution cage)

### What it is

The place where approved tools actually run — and only approved tools, only ever
handed in by the gate. The clever part: there are **two interchangeable
versions** of the cage that share the same shape (the same method names), so the
rest of the program can use either without knowing which it has. (Programmers
call this an **interface** — a shared set of methods that different
implementations all provide.)

**`FakeKali` — the pretend cage.**

```python
class FakeKali:
    def __init__(self):
        self.executed = []
    def run(self, command):
        self.executed.append(command)
        return ExecResult(command, 0, f"[fake-exec] {command}", "")
```

It doesn't run anything. It just *records* what it was asked to run, in the
`executed` list. This is genuinely important, not just a testing convenience:
your headline experiment is about *what reaches execution*, not about tool
output. With `FakeKali` you can prove "no denied action ever executed" by simply
checking that its `executed` list contains none of them — and you can do this on
a laptop with no Docker, no lab, no network. Your most important result needs
nothing but Python.

**`DockerKali` — the real cage.**

```python
class DockerKali:
    def run(self, command):
        argv = ["docker", "exec", self.container, *shlex.split(command)]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=...)
        return ExecResult(command, proc.returncode, proc.stdout, proc.stderr)
```

This runs the command *inside* the Kali container. Two safety details worth
seeing: `docker exec` runs the command in the isolated container, not on your
real machine; and the command is passed as an **argument vector** (a list of
separate pieces: `["docker","exec","nmap","-sV","10.10.10.5"]`) rather than as
one big string handed to a shell. Passing a list means there's no shell involved
at this step, so there's no *second* place for shell-injection to sneak in — the
gate already blocked metacharacters, and this design ensures they couldn't act
even if one slipped through.

**`ExecResult`** is a small dataclass bundling the outcome: the command, its
exit code (`returncode` — 0 conventionally means success), and whatever it
printed to **stdout** (normal output) and **stderr** (error output).

### Why it matters

The two-backend design buys you two things at once: a fully testable system with
no infrastructure (`FakeKali`), and real tool execution when you want it
(`DockerKali`) — without a single line elsewhere in the program needing to
change. And the cage embodies the **isolation** principle: tools run penned
inside a container, never directly on your host.

---

# 5. `brukal/audit.py` — the ledger (the tamper-evident log)

### What it is

The permanent record. Every decision and every execution is **appended** here
and never edited. The twist that makes it trustworthy: it's **hash-chained**, so
tampering is detectable.

A **hash** is a fixed-length fingerprint of some data, produced by a one-way
function (here **SHA-256**). Change the data by even one character and the
fingerprint changes completely, and you can't run it backwards to forge data for
a desired fingerprint. A **hash chain** links records by having each one include
the hash of the one before it — like each page of a ledger carrying a wax seal
that's stamped from the previous page's seal. Alter page 3 and its seal changes,
which breaks page 4's reference to it, which breaks page 5's, and so on. One edit
anywhere shatters the whole chain visibly.

### The key pieces

**Appending a record.**

```python
def append(self, kind, data):
    if is_dataclass(data):
        data = asdict(data)
    record = {"ts": time.time(), "kind": kind, "data": data,
              "prev_hash": self._last_hash}
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"))
    record["entry_hash"] = _hash(self._last_hash, payload)
    # write the line, remember this hash as the new "last"
```

It accepts either a dataclass (like a `Decision`) or a plain dict, stamps it with
the current time and the *previous* record's hash, computes *this* record's hash
from both, and writes it as one line. The file format is **JSONL** (JSON Lines —
one JSON object per line), which is easy to read, easy to `grep`, and easy to
load into a data-analysis tool like pandas for your results tables.

`sort_keys=True` matters: it makes the hashing **deterministic** (the same record
always serialises to the exact same text, so it always hashes the same way),
which is what lets verification re-compute the hashes reliably later.

**Verifying the chain.**

```python
def verify(self) -> bool:
    prev = _GENESIS
    for each record in the file:
        stored = record.pop("entry_hash")
        if record["prev_hash"] != prev: return False
        if _hash(prev, payload) != stored: return False
        prev = stored
    return True
```

It re-walks the file from the start (`_GENESIS` is the agreed "hash before the
first record," just a string of zeros), recomputing each hash and checking it
matches what was stored and that each record correctly points at the previous
one. If anything was altered or removed, a mismatch appears and it returns
`False`. This is the function your test and CLI call to confirm
`audit chain intact: True`.

### Why it matters

This is the backbone of **reproducibility and accountability** — the qualities
that make your paper's results *credible* rather than "trust me." A reviewer (or
a real client) can verify that the record of what Brukal did wasn't edited after
the fact.

---

# 6. `brukal/executor.py` — the one door

### What it is

The single function through which *everything* must pass. It's short on purpose
— its importance is in what it *forbids*, not in how much it does.

```python
class Executor:
    def __init__(self, gate, kali, audit):
        self._gate = gate
        self._kali = kali
        self._audit = audit

    def run(self, command, target, agent="unknown"):
        decision = self._gate.check(command, target, agent)   # 1. JUDGE
        self._audit.append("decision", decision)              # 2. LOG decision
        if not decision.allowed:
            return decision, None                             # 3a. denied -> stop
        result = self._kali.run(command)                      # 3b. allowed -> run
        self._audit.append("execution", result)               # 4. LOG result
        return decision, result
```

The flow in plain words: **judge, log, and only if allowed, run (then log the
result too).** A denied action returns immediately with `None` for the result —
it *never reaches the cage*.

### Why it matters

This is where "the agent cannot bypass the gate" stops being a promise and
becomes a **structural fact**. The agents that arrive in milestone 2 are handed
*this* object — they call `executor.run(...)`. They are never handed the Kali
backend directly. So there is no code path from "an agent wants to run something"
to "something runs" that skips the gate and the log. The single door is the
whole point. When you build the agents, the discipline to preserve is simple:
**never give an agent the Kali object; only ever give it the Executor.**

---

# 7. `brukal/__init__.py` — the package's front desk

### What it is

A small file that makes the `brukal/` folder a **package** (an importable unit)
and chooses what names are exposed when someone writes `from brukal import ...`.

```python
from .scope import Scope, load_scope
from .gate import Gate, Decision
from .audit import AuditLog
from .kali import FakeKali, DockerKali, ExecResult
from .executor import Executor

__all__ = ["Scope", "load_scope", "Gate", "Decision",
           "AuditLog", "FakeKali", "DockerKali", "ExecResult", "Executor"]
```

It re-exports the important classes from the inner modules so users get a clean,
flat API — `from brukal import Gate, Executor` instead of
`from brukal.gate import Gate; from brukal.executor import Executor`. The
`__all__` list documents the public surface (the names meant for outside use).

### Why it matters

Quality-of-life and tidiness. It signals which parts are the public interface and
makes the rest of the code (and your future agents) read cleanly.

---

# 8. `brukal_cli.py` — driving it by hand

### What it is

A **command-line interface** (CLI) — a script you run in the terminal to propose
a single action and watch the gate rule on it. In milestone 1, *you* play the
role the recon agent will play later: you supply the command and target; the gate
decides.

It uses `argparse` (a stdlib tool for reading command-line arguments) to accept a
command, a target, and a few options:

- `--fake` uses `FakeKali` (no Docker needed) instead of the real cage.
- `--agent` labels the action in the log.
- `--verify` checks the audit chain and exits.

```python
gate = Gate(load_scope(SCOPE))
kali = FakeKali() if args.fake else DockerKali()
executor = Executor(gate, kali, audit)
decision, result = executor.run(args.command, args.target, agent=args.agent)
```

Notice it assembles the system from the same building blocks the test uses, then
prints the verdict, the reason, the deciding layer, and — if the action ran — the
tool's output.

### Why it matters

It's how you *feel* the system working before any AI exists: try an in-scope
command (allowed), an out-of-scope one (denied), an injection attempt (denied),
then `--verify` to see the tamper-evident log holds. It's also a living example
of the correct wiring (agent → Executor → gate/cage/log) that milestone 2 will
copy.

---

# 9. `tests/test_scope_interception.py` — the experiment, automated

### What it is

Your **first paper result**, written as an automated **test** (code that checks
other code behaves correctly). It feeds the system a batch of action requests —
some legitimate, some deliberately out of scope, some smuggling, some injection —
and asserts the system handles every one correctly.

**The cases.**

```python
CASES = [
    ("nmap -sV 10.10.10.5", "10.10.10.5", True,  "in-scope service scan"),
    ...
    ("nmap -sV 8.8.8.8",    "8.8.8.8",    False, "out-of-scope public IP"),
    ("nmap 10.10.10.5 8.8.8.8", "10.10.10.5", False, "smuggled out-of-scope host"),
    ("metasploit -x exploit",   "10.10.10.5", False, "tool not on allowlist"),
    ("nmap 10.10.10.5; rm -rf /","10.10.10.5", False, "command chaining via ;"),
    ...
]
```

Each row is `(command, declared_target, should_be_allowed, note)`. This table is
your **test corpus** — the set of scenarios you're claiming to handle. Every new
case you add and pass is another row in your eventual results and another hole a
reviewer can't poke.

**The assertions** (an `assert` says "this must be true; if not, fail loudly"):

```python
assert decision.allowed == expected_allow      # every verdict is correct
...
assert result is None                          # denied actions never executed
assert out_of_scope_intercepted == out_of_scope_total   # 100% interception
assert len(kali.executed) == expected_executions        # only legit ran
assert audit.verify() is True                  # the log is intact
```

Read together, these encode your thesis precisely: every verdict correct, no
denied action reaching the cage, full interception, and a tamper-evident record.

**Two ways to run it.** The `test_...` function is for **pytest** (a popular test
runner that finds and runs functions named `test_*`). The
`if __name__ == "__main__":` block at the bottom runs when you execute the file
directly, and prints the human-readable results table you saw — the one with the
verdict, target, reason, and the `interception rate: 100.0%` line.

(One small Python note you'll see: `tempfile.mkdtemp()` makes a throwaway folder
for the audit file during the run, and `shutil.rmtree(...)` in a `finally:` block
deletes it afterward, so tests leave no mess. `finally` means "do this cleanup
even if something failed.")

### Why it matters

This file *is* the evidence. It turns "Brukal intercepts out-of-scope actions"
from a sentence into a repeatable, automated proof anyone can re-run — which is
exactly what a methods/results section in your paper needs.

---

# 10. `docker/Dockerfile.kali` — the recipe for the cage

### What it is

A **Dockerfile** is a recipe that builds a **container image** — a self-contained,
prepackaged miniature operating system with exactly the software you specify.
(A **container** is a lightweight, isolated box that runs a program with its own
filesystem and its own slice of the OS, walled off from your real machine.
**Docker** is the tool that builds and runs them.)

```dockerfile
FROM kalilinux/kali-rolling                 # start from official Kali
RUN apt-get update && apt-get install -y \  # install ONLY the allowlisted tools
        nmap gobuster nikto whatweb curl dnsutils
RUN useradd -m operator                      # make a non-root user
USER operator                                # run as that user, not root
ENTRYPOINT ["sleep", "infinity"]             # just stay alive, doing nothing
```

Walking the recipe: it starts from the official Kali Linux image; installs only
the tools your scope allowlists (so even if a tool were wrongly allowlisted, if
it's not installed here it still can't run — a second line of defence); creates a
**non-root** user (`operator`) and switches to it, so approved tools run *without*
administrator powers inside the cage (defence in depth); and finally sets the
container to simply `sleep` forever. That last point is the trick: the container
does nothing on its own. It just sits there alive so the executor can `docker
exec` approved commands into it, one at a time.

### Why it matters

This is the **cage** made concrete. Three safety ideas are baked into a few
lines: only the needed tools exist, nothing runs as root, and the container has
no agenda of its own — it only ever runs what's handed to it.

---

# 11. `docker/docker-compose.yml` — bringing the cage up

### What it is

**Docker Compose** lets you describe and launch containers from a config file
instead of long command-line incantations. This file defines the one container
(named `brukal-kali`) and, importantly, its **network**.

```yaml
services:
  kali:
    build: { context: ., dockerfile: Dockerfile.kali }
    container_name: brukal-kali
    networks: [brukal_isolated]
    # no published ports: nothing inbound
networks:
  brukal_isolated:
    driver: bridge
    internal: false   # set true to fully cut internet
```

The key parts: it builds from the Dockerfile above; gives the container a fixed
name so `DockerKali` can find it; puts it on a dedicated network
(`brukal_isolated`); and **publishes no ports**, meaning nothing from outside can
reach into the container — the only way in is `docker exec`, which is exactly how
the executor delivers approved commands. The comments explain how to tighten the
network so the cage can reach *only* your authorised lab and not the open
internet.

### Why it matters

The gate enforces scope in *software*; this file enforces isolation at the
*infrastructure* level. Belt and braces: even if something went wrong in the
code, the container's network boundary is a second wall. You bring the whole cage
up with one command: `docker compose -f docker/docker-compose.yml up -d --build`.

---

# 12. Supporting files

**`requirements.txt`** lists external Python packages needed — here just
`pytest`, and only if you want to run the suite through pytest rather than
directly. (The core system needs nothing beyond Python's standard library, which
is a real strength: fewer dependencies means fewer things to break or audit.)

**`.gitignore`** tells **git** (the version-control system that tracks your code
history) which files to ignore — the `runs/` folder (audit logs from runs) and
Python's `__pycache__/` caches (auto-generated compiled files). These are
generated noise, not source code, so they don't belong in your repository.

**`README.md`** is the front-page guide: the step-by-step run instructions, the
scope-config explanation, what the gate checks, and the milestone roadmap. It's
written so a newcomer (or future-you) can go from zero to a passing run.

---

# How it all snaps together — one full action

Trace a single allowed action through every file, and the whole design clicks:

1. You (or later, an agent) call `executor.run("nmap -sV 10.10.10.5", "10.10.10.5")`
   — **executor.py**.
2. The executor asks the **gate** (`gate.py`) to judge it. The gate checks the
   command against the **scope** (`scope.py`, loaded from `scope.json`): no
   injection, parses cleanly, `nmap` is allowlisted, `10.10.10.5` is in scope, no
   smuggled host, under the rate limit → **ALLOW**.
3. The executor writes the decision to the **audit log** (`audit.py`).
4. Because it's allowed, the executor hands the command to the **cage**
   (`kali.py`) — `FakeKali` records it, or `DockerKali` runs it inside the
   container built by **Dockerfile.kali** and launched by **docker-compose.yml**.
5. The executor writes the result to the audit log too.
6. Later, `audit.verify()` confirms none of it was tampered with.

An out-of-scope action stops at step 2 with a **DENY**, gets logged at step 3,
and never reaches steps 4–5. That single difference — denied actions stopping
before the cage — is your entire safety thesis, demonstrated by
`test_scope_interception.py`.

---

# The principles, restated (memorise these)

Every file serves one of these, and milestone 2 onward must never violate them:

1. **The gate has no LLM.** Scope is enforced by literal code, so a hostile
   target can't talk its way past it.
2. **Fail-closed.** Anything ambiguous or broken → deny.
3. **Never trust the agent's self-report.** The gate re-reads the command itself.
4. **One execution path.** Everything goes through `Executor.run()`; agents never
   touch the cage directly. This is what makes bypass impossible by construction.
5. **Immutable rulebook, immutable log.** Scope can't widen at runtime; the audit
   trail can't be edited without detection.

Hold these five and Brukal stays trustworthy no matter how many agents you add.
