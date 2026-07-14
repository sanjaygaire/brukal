# Brukal vs. other tools — an honest comparison

> **How to read this.** Brukal's axis is **governed autonomy**: full-capability
> autonomous pentesting that is *provably contained and accountable*, on any model
> you choose. It does not claim to out-pwn a top proprietary agent on raw capability.
> The numbers below marked *(measured)* come from Brukal's own reproducible harness
> (`run_experiments.py`, `run_eval.py`) — they are **ablations of Brukal against
> itself** (gate on vs off, weak model vs strong), not head-to-head runs of other
> products. A true head-to-head needs those products run in the same lab; the eval
> harness has a `--baseline` slot for dropping their transcript metrics in.

---

## The one-paragraph version

Most LLM pentest tools are either **assistants** (PentestGPT — the model advises,
you act, nothing is enforced) or **closed autonomous agents** (XBOW — powerful, but
proprietary, unauditable, and not something you can point at your own scope with a
guarantee). Classic tools (**Burp**, **Metasploit**) are deep but fully manual.
**Brukal is the only one where every action an autonomous agent takes is checked by
deterministic code against an immutable scope, logged to a tamper-evident ledger,
and structurally unable to bypass the gate** — while still exploiting, learning
across engagements, running agents in parallel, and driving a real browser. You can
run it on a free local model and read the receipt for everything it did.

---

## Capability matrix

| | **Brukal** | PentestGPT | XBOW / autonomous SaaS | Burp Suite | Metasploit | Manual pentester |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| Autonomous (acts, not just advises) | ✅ | ⚠️ advisory | ✅ | ❌ manual | ⚠️ semi | ✅ |
| **Deterministic scope enforcement** | ✅ **in code** | ❌ | ⚠️ opaque | ❌ | ❌ | 🧠 human |
| **Tamper-evident audit of every action** | ✅ hash-chained | ❌ | ❌ | ⚠️ project log | ⚠️ logs | ❌ |
| **Gate-bypass structurally impossible** | ✅ one door | ❌ | ❌ | — | ❌ | — |
| Human-in-the-loop on risky actions | ✅ escalation | ⚠️ all manual | ⚠️ | ✅ all manual | ✅ | ✅ |
| Learns across engagements | ✅ lessons store | ❌ | ⚠️ closed | ❌ | ❌ | 🧠 human |
| Multi-agent, parallel | ✅ | ❌ | ✅ | ❌ | ❌ | 👥 team |
| Governed web testing (render + tamper) | ✅ Chrome + HTTP | ❌ | ✅ | ✅ **deepest** | ⚠️ | ✅ |
| Runs on ANY model (incl. free local) | ✅ | ⚠️ OpenAI-ish | ❌ closed | — | — | — |
| Self-hostable / open | ✅ MIT | ✅ | ❌ | ⚠️ licensed | ✅ | — |
| Reproducible eval harness | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Raw exploitation depth | ⚠️ growing | ⚠️ | ✅ **highest** | ✅ web | ✅ **highest** | ✅ |

Legend: ✅ yes · ⚠️ partial/qualified · ❌ no · 🧠 relies on the human · — n/a

---

## What only Brukal does

1. **The agent cannot bypass the gate — by construction, not by policy.** Agents
   receive an `Executor`/`GovernedBrowser`, never the cage. Every command and every
   web action passes `scope → deterministic gate → audit → run`. There is no second
   door. A prompt-injected agent, or a hostile target's output, cannot talk its way
   past a regex + CIDR check. *(This is the property PentestGPT and closed SaaS
   agents cannot offer: their scope, if any, is advisory.)*

2. **A verifiable receipt for everything.** The audit log is SHA-256 hash-chained:
   altering or dropping any past record breaks the chain and is detectable
   (`brukal verify`). Under the parallel orchestrator the chain stays valid because
   every append is atomic. This is what turns "trust me, it stayed in scope" into
   "here is the proof."

3. **Governed autonomy.** Read-only enumeration runs automatically; irreversible/
   attack actions (reverse shells, `sqlmap --dump`, credential attacks) are
   classified in code and **escalated for one-tap human sign-off**, and denied
   outright once the blast radius widens. Capability grows; the safety boundary does
   not move.

4. **Model-agnostic, including free + local.** The same governance rides Claude,
   Groq (free 70B), OpenAI/OpenRouter/DeepSeek/GLM, or a local Ollama model. The
   guarantees are a property of the *code around* the model, so a weak model is
   *contained*, not *trusted*.

5. **Learns over time.** A cross-session lessons store derives generalisable lessons
   from real outcomes (a timeout → "go narrower"; a blocked tool → "use an
   allowlisted one"; a productive move → a tagged win) and injects the relevant ones
   into the next engagement — safely, since lessons come from *our* command + the
   gate's decision, never raw target output.

---

## Measured evidence (Brukal's own reproducible harness)

Run on any laptop, no target needed (`python run_experiments.py`, `python run_eval.py`):

| Claim | Result *(measured, fake cage)* |
|---|---|
| Scope interception | **100%** — every out-of-scope action denied before the cage (0 unsafe) |
| Governance cost | the gate prevents **every** unsafe execution an ungated agent performs |
| Governance is not a capability tax | governed arm reaches the foothold in **≤** the steps of an ungated arm, with **0** scope violations vs the ungated arm's **1–2** |
| Verify catches hallucinated success | multi-agent verify rejects a fabricated "I got a shell"; single-agent doesn't |
| Adaptive trust | a proven-bad agent's later benign action is escalated (adaptive) vs allowed (fixed) |
| Concurrency safety | 16 threads × 25 appends → audit chain **valid**, 0 lost records |

**Live capability ceiling (HTB Nexus, real engagement):** the *same governed harness*
with a 70B model (Groq `llama-3.3-70b`) inferred the box's `nexus.htb` vhost from a
302 and drove a coherent web-enumeration methodology; a 7B local model did not.
Governance was identical for both (0 scope violations, every action gated, audit
intact). Capability scales with the model; governance is constant.

---

## When to use what (honest guidance)

- **Reach for Burp Suite** when you want a human to manually, deeply intercept and
  hand-craft web traffic — it's the deepest web proxy and Brukal doesn't replace it.
- **Reach for Metasploit** for a mature, hand-driven exploitation framework with the
  widest module set.
- **Reach for a proprietary autonomous agent** if you only care about raw
  capability on a benchmark and can accept a closed, unauditable process.
- **Reach for Brukal** when you need an autonomous (or copilot) pentester you can
  **safely point at a defined scope, on a model you control, and prove exactly what
  it did afterwards** — for authorised engagements, research, teaching, CTFs, or any
  context where accountability is not optional.

---

## Where Brukal is still growing (no spin)

- Raw exploitation depth is behind mature frameworks; the exploit library grows as
  the governed autonomy matures.
- Live in-browser request *interception* (click/fill/tamper via CDP over WebSocket)
  is implemented and unit-tested against a fake CDP transport; live rendering and
  crafted-request tampering are validated end-to-end, but live interactive CDP
  driving needs the cage debug endpoint wired.
- Head-to-head numbers vs PentestGPT/XBOW require running those tools in the same
  lab — Brukal ships the harness and a `--baseline` slot for it, but does not
  fabricate their scores.
