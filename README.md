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

## Prerequisites

| You want to… | You need |
|---|---|
| Run the tests, the benchmarks, or the fake cage | **Python 3.10+** and `pip`. Nothing else. |
| Drive real tools against a live target | **Docker** (Desktop or Engine) for the Kali cage |
| Use Claude as the brain | an **Anthropic API key** (`ANTHROPIC_API_KEY`) |
| Use a paid OpenAI-compatible brain | that provider's key (OpenAI, OpenRouter, Groq, DeepSeek, GLM…) |
| Use a **free, local, no-key** brain | **[Ollama](https://ollama.com)** with a model pulled (e.g. `ollama pull qwen2.5`) |

You only need a model to run the *agents* (`run` / `hunt` / `solve`). The gate,
the tests, the benchmarks, and `brukal exec` need no model and no key at all.

## Install

```bash
git clone https://github.com/sanjaygaire/brukal.git && cd brukal
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[agents]"                            # installs the `brukal` command + agent deps
```

`pip install -e ".[agents]"` pulls in `anthropic` + `pydantic` and puts `brukal`
on your PATH. Add the `[tui]` extra for the live dashboard: `pip install -e ".[agents,tui]"`.
(Prefer not to install? Every command also works as `python brukal_cli.py <cmd> …`.)

## Quickstart

```bash
# 1. run the test suite (75 tests, no infra, no key needed)
python -m pytest -q

# 2. reproduce the benchmark metrics (fake cage)
python run_experiments.py

# 3. drive the gate by hand against the fake cage — no model, no key
brukal exec --fake "nmap -sV 10.10.10.5" 10.10.10.5
```

### Running a live engagement

A live run executes real tools inside an isolated Kali container and is
deliberately gated behind an explicit authorisation flag — only ever point it at
systems you are authorised to test (see [`SECURITY.md`](SECURITY.md)).

```bash
# 1. bring up the cage (a Kali container with only the allowlisted tools)
docker compose -f docker/docker-compose.yml up -d --build

# 2. set scope to your authorised target (a bare host becomes /32; a CIDR
#    broader than one host asks for confirmation) and check it end to end
brukal target 10.10.10.5
brukal exec "nmap -sS -sV -Pn 10.10.10.5" 10.10.10.5     # one command, by hand

# 3. run the full multi-agent engagement (recon → exploit → verify, adaptive
#    trust, human sign-off on escalations). Needs ANTHROPIC_API_KEY.
export ANTHROPIC_API_KEY=sk-...
brukal run 10.10.10.5 --yes-authorised --tui    # --tui = live dashboard

# 4. review the audit trail and findings
brukal verify
#    findings + task tree land in runs/vault/  (open it in Obsidian)
```

> `brukal` is installed via `pip install -e .`; without installing, use
> `python brukal_cli.py <subcommand> ...`. To reach a lab target, attach your lab
> network to `brukal_isolated` in `docker/docker-compose.yml` and keep the cage
> off any internet-facing network.

### Choosing the model (the brain)

Agents talk to a model through one small `propose()` interface, so Brukal runs on
Claude **or any OpenAI-compatible model** — including free local ones — with no
extra dependency. You don't have to remember flags: **`brukal solve` just asks.**

```
How should Brukal think? Pick the model it runs on:
  [1] Claude API (Anthropic) — best quality, needs an API key
  [2] Local model via Ollama — free, private, no key (e.g. qwen2.5)
  [3] OpenAI-compatible API — OpenAI / OpenRouter / Groq / DeepSeek / GLM / LM Studio
  [4] Advanced — type provider / model / base-url yourself
```

Pick 1 and it prompts (hidden) for your key if it isn't already set; pick 2 and it
asks which local model. To skip the prompt (e.g. in scripts), pass `--provider` /
`--model` or set `BRUKAL_PROVIDER` / `BRUKAL_MODEL` and it uses those instead.

**Option A — Claude API (best quality).** Get a key from the Anthropic console and
export it:

```bash
export ANTHROPIC_API_KEY=sk-ant-...        # Windows PowerShell: $env:ANTHROPIC_API_KEY="sk-ant-..."
brukal solve                               # pick [1]; default model claude-sonnet-5
```

**Option B — free local model, no key (Ollama).** Nothing leaves your machine:

```bash
# 1. install Ollama from https://ollama.com, then pull a model:
ollama pull qwen2.5
# 2. run Brukal and pick [2] (default model qwen2.5), or non-interactively:
brukal solve <target> --provider ollama --model qwen2.5
```

> **WSL note:** if Ollama runs on Windows but you run Brukal inside WSL, WSL's
> `localhost` isn't Windows'. Start Ollama with `OLLAMA_HOST=0.0.0.0` and point
> Brukal at the Windows host IP: `--base-url http://<windows-ip>:11434/v1` (or
> just install Ollama inside WSL).

**Option C — other hosted providers.** Pick `[3]` and it asks for the provider and
key, or set them yourself:

```bash
export OPENROUTER_API_KEY=...   ; brukal solve <target> --provider openrouter --model z-ai/glm-4.6
export OPENAI_API_KEY=...       ; brukal solve <target> --provider openai     --model gpt-4o-mini
export GROQ_API_KEY=...         ; brukal solve <target> --provider groq       --model llama-3.1-8b-instant
```

Supported providers: `anthropic` (default), `ollama`, `lmstudio` (both free/local,
no key), `openai`, `openrouter`, `groq`, `deepseek`, `glm`/`zhipu`, and
`openai-compatible` (any endpoint via `--base-url`). Everything is also settable
via `BRUKAL_PROVIDER` / `BRUKAL_MODEL` / `BRUKAL_BASE_URL`.

### Human-assisted solving (governed copilot)

`brukal solve` is an interactive loop that acts like a teammate, not a tool
dispatcher. Run it with no target and it **asks** for one (offering to authorise
a single out-of-scope host for the session), then **asks which model** to use
(§ Choosing the model) and **how to work the plan**:

- **Manual** (default) — Brukal proposes each step; **you** approve every command.
- **Auto** — Brukal **runs the safe (ALLOW) enumeration steps itself** and pauses
  for anything the gate escalates or that needs your hands (exploitation, a shell,
  a flag). Toggle any time with `a` (menu) or `auto` / `manual-mode` (typed);
  Ctrl-C during an auto run drops you back to manual.

It lays out a **shortest-path plan** — recon → enumeration → exploitation →
priv-esc — and works it step by step, naming the current PHASE and GOAL and
reasoning from what it has learned. You `run` a suggested command (through the
gate), record a `manual` step you did yourself, add a `note`, `ask` a question, or
re-`plan`. Brukal reasons and logs; you do the ungoverned exploitation on your own
authority — a suggested command is **never** a bypass, it still goes through the
gate.

Every finding is written to a per-target **Obsidian vault** (`runs/vault/<target>/`
— `engagement.md`, `plan.md`, per-agent notes, `findings.jsonl`), so a later
`brukal solve <target>` **resumes with memory** instead of asking from scratch.
Works with any provider, so you can copilot a box on a free local model:

```bash
brukal solve                       # asks target → model → manual/auto, plans, walks it
brukal solve 172.20.0.3 --yes-authorised --scope runs/juice.json \
    --provider ollama --model qwen2.5     # flags skip the model prompt
```

### HTB / lab boxes (VPN-connected cage)

The cage ships with a wider **enumeration** allowlist (`ffuf`, `feroxbuster`,
`smbmap`, `enum4linux`, `snmpwalk`, `sslscan`, …) and an OpenVPN client so it can
reach a VPN-gated lab. Drop your HackTheBox `.ovpn` at `docker/vpn/config.ovpn`
(gitignored), rebuild, and the cage brings the tunnel up automatically:

```bash
cp ~/Downloads/lab.ovpn docker/vpn/config.ovpn
docker compose -f docker/docker-compose.yml up -d --build     # cage connects the VPN
brukal target 10.10.10.5 --scope scope.htb.json               # scope to YOUR box
brukal solve 10.10.10.5 --yes-authorised --scope scope.htb.json --provider ollama --model qwen2.5
```

It's a **governed recon/enum copilot**, not an autopwn tool — enumeration runs in
the cage (gated), and you do the exploitation yourself and report back. Use
`scope.htb.json` and narrow `authorized_cidrs` to the single box you're testing.

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
