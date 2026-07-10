# Brukal — trust-governed multi-agent penetration testing

Brukal is a **trust-governed, multi-agent LLM penetration-testing system**. Large
language models can plan and drive an engagement, but every action they propose
is ruled on by a **deterministic safety gate** before anything runs — so the
model *proposes* and the code *disposes*.

It is the reference implementation for the paper
*"Trust-Governed Multi-Agent Large Language Model Penetration Testing with
Risk-Constrained Action Gating."*

> **The core idea:** an LLM is untrusted input, not a trusted operator. Put a
> small, boring, prompt-injection-proof gate between the agents and the tools,
> govern each agent in proportion to how reliable it has proven to be, and you
> get autonomy you can actually account for.

---

## Headline results

Reproduce them on any laptop — no Docker, network, API key, or target required:

```bash
python run_experiments.py
```

| Benchmark | Result |
|---|---|
| **Scope interception** | **100%** — every out-of-scope action denied before the cage (0 unsafe executions) |
| **Governed vs. ungated** | the gate prevents **every** unsafe execution an ungated agent would perform |
| **Multi-agent vs. single** | the verify agent catches hallucinated success; digests cut context by **~97%** |
| **Adaptive vs. fixed trust** | a proven-bad agent's *benign* action is ESCALATEd under adaptive trust, ALLOWed under fixed |

These headline metrics are properties of the deterministic gate, so they compute
identically in the fake cage or a live lab.

---

## The five safety invariants

Everything in this repo exists to hold these five lines true:

1. **No LLM inside the gate.** Scope is enforced by deterministic code (string
   parsing, set membership, CIDR arithmetic, regex). A regex cannot be
   prompt-injected; an LLM guard could.
2. **Fail-closed.** Anything ambiguous, unparseable, or malformed is **DENIED**.
3. **Never trust an agent's self-report.** The gate re-reads the command itself —
   e.g. it re-scans *every* IP in the command, not just the declared target.
4. **One execution path.** Everything runs through `Executor.run()`, which gates
   first and logs always. Agents are handed the **Executor**, never the cage.
5. **Immutable scope, append-only audit.** Scope cannot widen at runtime; the
   hash-chained audit log cannot be edited undetectably.

---

## Architecture

```
scope.json ─► scope.py ─► gate.py ─► executor.py ─► kali.py ─► audit.py
(immutable   (frozen    (determin-  (THE ONE       (FakeKali/  (hash-
 policy)      Scope)     istic       DOOR:          DockerKali  chained
                        ALLOW/DENY/  gate→log→run)  cage,       ledger)
                        ESCALATE)                   no shell)
```

An agent emits **only text**: a schema-validated *Action Request*. The gate rules
on it in two stages:

- **Hard gate (deterministic, no LLM):** a logical AND of injection guard → parse
  → tool allowlist → target-in-scope → no-smuggled-host → rate-limit. It can only
  **DENY**, never widen.
- **Soft risk layer:** scores reversibility × blast-radius and, for a moderate
  action, **ESCALATEs** to a human for sign-off; an intrusive one is **DENIED**.

On top of that spine:

- **Multi-agent orchestration** (`orchestrator.py`) runs recon / exploit / verify
  agents sequentially over a **Pentesting Task Tree**, sharing findings through an
  Obsidian-vault **blackboard** that stores *digests, not raw dumps*.
- **The verify agent** (`agents/verify.py`) exists to catch *hallucinated success*:
  a claim is only `SUPPORTED` when an in-scope command actually executed and its
  real output backs it — otherwise it fails closed to `UNVERIFIED`.
- **Adaptive per-agent trust** (`trust.py`) — the paper's novel layer. Each agent
  carries a trust score `T_i ∈ [0,1]` that it *loses* on unreliable behaviour.
  `T_i` feeds **only the soft layer**, so a less-trusted agent's same command draws
  more scrutiny. It can never widen scope or touch the hard gate.

---

## Quickstart

```bash
# 1. install (agent extras pull in anthropic + pydantic)
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # or:  pip install -e ".[agents]"

# 2. run the test suite (40 tests, no infra needed)
python -m pytest -q

# 3. reproduce the benchmark metrics (fake cage)
python run_experiments.py

# 4. drive the spine by hand against the fake cage
python brukal_cli.py --fake "nmap -sV 10.10.10.5" 10.10.10.5
```

A **live run** against a real target you are authorised to test uses the Docker
cage and is deliberately gated behind an explicit flag — see
[`SECURITY.md`](SECURITY.md):

```bash
docker compose -f docker/docker-compose.yml up -d --build
python run_experiments.py --env docker --target 10.10.10.5 --yes-authorised
```

---

## Configuring scope

`scope.json` is the single source of truth, read once at startup and treated as
read-only while running:

```json
{
  "engagement": "brukal-lab-01",
  "authorized_cidrs": ["10.10.10.0/24", "127.0.0.1/32"],
  "allowlisted_tools": ["nmap", "gobuster", "nikto", "whatweb", "curl", "dig"],
  "rate_limit_per_min": 30
}
```

Keep `allowlisted_tools` in sync with the tools installed in
`docker/Dockerfile.kali`.

---

## Repository layout

```
brukal/
├── scope.py          # frozen engagement policy; stdlib CIDR matching
├── gate.py           # deterministic hard gate + soft risk layer (+ trust hook)
├── risk.py           # reversibility × blast-radius scoring
├── executor.py       # THE ONE DOOR: gate → log → (maybe) run
├── kali.py           # FakeKali / DockerKali cage — no shell
├── audit.py          # SHA-256 hash-chained, tamper-evident log
├── trust.py          # adaptive per-agent trust T_i  (feeds only the soft layer)
├── schema.py         # the Action Request the model must emit
├── llm.py            # thin Anthropic client (agents propose text only)
├── orchestrator.py   # sequential multi-agent driver
├── blackboard.py     # Obsidian-vault shared memory (digests, scoped reads)
├── tasktree.py       # the Pentesting Task Tree
├── experiment.py     # the four-metric benchmark harness
└── agents/           # recon · exploit · verify
tests/                # 40 tests — the invariants, in code
docker/               # the Kali cage (Dockerfile + compose)
run_experiments.py · run_engagement.py · run_recon.py · brukal_cli.py
HOW_IT_WORKS.md · CODE_WALKTHROUGH.md · BUILD_ROADMAP.md · SECURITY.md
```

---

## How it was built

Brukal was built in seven runnable milestones, each adding exactly one idea and
each keeping every prior test green:

| # | Milestone | Adds |
|---|-----------|------|
| 1 | The deterministic spine | gate + cage + audit; proves 100% interception |
| 2 | One recon agent | an LLM that *proposes* to the gate |
| 3 | Soft score + escalate | the gate's risk layer + human-approval path |
| 4 | Orchestrator + blackboard | planner + Obsidian-vault memory + task tree |
| 5 | Exploit + verify agents | genuinely multi-agent; catches hallucinated success |
| 6 | Adaptive trust | the per-agent `T_i` loop — the novel layer |
| 7 | The four experiments | the benchmark harness behind the headline results |

See [`BUILD_ROADMAP.md`](BUILD_ROADMAP.md), [`HOW_IT_WORKS.md`](HOW_IT_WORKS.md),
and [`CODE_WALKTHROUGH.md`](CODE_WALKTHROUGH.md) for the full story.

---

## Safety & responsible use

Brukal is for **authorised** security testing only — your own lab, or an
engagement you are explicitly contracted for. The design assumes you never point
a live run at a system you are not permitted to test, and the gate exists to keep
an autonomous agent inside that authorisation, not to grant it. Read
[`SECURITY.md`](SECURITY.md) before any live run.

## License

See [`LICENSE`](LICENSE).
