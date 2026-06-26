# Brukal — Milestone 1: the spine

A trust-governed, multi-agent penetration-testing system. This repository is
**milestone 1**: the deterministic safety spine, built *before* any AI agents.
It already proves the project's headline claim — **100% interception of
out-of-scope actions** — with no language model involved.

> Why build this first? Because your strongest result needs no AI. A
> deterministic gate plus a list of test targets demonstrates the core thesis
> today, and every later milestone bolts onto a foundation that already stands.

---

## What is here

```
brukal/
├── scope.json                 # the engagement policy (authorised CIDRs, tools, rate)
├── brukal/
│   ├── scope.py               # loads the policy; stdlib CIDR matching
│   ├── gate.py                # THE HARD GATE — deterministic, fail-closed, no LLM
│   ├── audit.py               # append-only, hash-chained audit log (tamper-evident)
│   ├── kali.py                # execution backends: FakeKali (tests) + DockerKali (real)
│   └── executor.py            # the ONLY path to execution: propose -> gate -> run -> log
├── tests/
│   └── test_scope_interception.py   # the headline experiment, as an automated test
├── docker/
│   ├── Dockerfile.kali        # the cage: Kali + only the allowlisted tools
│   └── docker-compose.yml     # brings up the isolated `brukal-kali` container
├── brukal_cli.py              # drive the gate by hand (stand-in for the agents)
└── requirements.txt
```

The one rule the whole design rests on: **nothing executes except through
`Executor.run()`, which always calls the gate first and always logs.** There is
no other door to the cage.

---

## Step 1 — prove the claim (no Docker needed)

The scope-interception result is about *what reaches execution*, so it runs with
a fake cage — no Docker required.

```bash
cd brukal
python3 tests/test_scope_interception.py
```

You should see every out-of-scope, smuggled, disallowed-tool, and injection
attempt **DENIED**, only the legitimate actions reaching the cage, a **100.0%**
interception rate, and `audit chain intact: True`. That table is your first
figure.

If you have `pytest`:

```bash
pip install -r requirements.txt
python3 -m pytest tests/ -v
```

---

## Step 2 — drive it by hand

`brukal_cli.py` lets you play the role the agents will play in milestone 2.

```bash
# allowed (fake cage):
python3 brukal_cli.py --fake "nmap -sV 10.10.10.5" 10.10.10.5

# denied — out of scope:
python3 brukal_cli.py --fake "nmap -sV 8.8.8.8" 8.8.8.8

# denied — injection attempt:
python3 brukal_cli.py --fake "nmap 10.10.10.5; rm -rf /" 10.10.10.5

# check the audit log has not been tampered with:
python3 brukal_cli.py --verify
```

---

## Step 3 — stand up the real cage (Docker)

This builds a Kali container holding only the allowlisted tools. Approved
commands run *inside* it; no agent ever gets a shell there.

```bash
docker compose -f docker/docker-compose.yml up -d --build
docker ps   # you should see brukal-kali running
```

Now drop `--fake` to execute for real:

```bash
python3 brukal_cli.py "nmap -sV 10.10.10.5" 10.10.10.5
```

> **Targets and isolation.** Point `authorized_cidrs` in `scope.json` at a lab
> you own and are authorised to test (a local Metasploitable/DVWA VM, or an HTB
> machine you have an active connection to). Attach that lab network to the
> `brukal_isolated` network in `docker-compose.yml`, and keep the container off
> any network that reaches the open internet. The gate enforces scope in
> software; the network boundary is defence in depth.

Tear down with:

```bash
docker compose -f docker/docker-compose.yml down
```

---

## Configuring scope

Edit `scope.json`. It is the single source of truth and is read once at
startup (treat it as read-only while running):

```json
{
  "engagement": "brukal-lab-01",
  "authorized_cidrs": ["10.10.10.0/24", "127.0.0.1/32"],
  "allowlisted_tools": ["nmap", "gobuster", "nikto", "whatweb", "curl", "dig"],
  "rate_limit_per_min": 30
}
```

Keep `allowlisted_tools` in sync with the tools installed in `Dockerfile.kali`.

---

## What the gate checks (milestone 1)

Every proposed action passes through these, in order, as a logical AND — one
failure denies, and the design is fail-closed (anything ambiguous is denied):

1. **Injection guard** — rejects shell metacharacters and command substitution
   (`;  |  &  > <  $(  ${  ` `` `).
2. **Parse** — must parse as a clean argument vector.
3. **Tool allowlist** — only tools named in `scope.json`.
4. **Declared target in scope** — strict CIDR membership.
5. **No smuggled host** — every IP found anywhere in the command must be in
   scope (defeats `nmap 10.10.10.5 8.8.8.8`).
6. **Rate limit** — sliding 60-second window.

The soft risk score (impact/policy) and the **ESCALATE** path are stubbed in
`gate.py` with a clearly marked extension point — that is milestone 3.

---

## The audit log

`runs/audit.jsonl` is append-only. Each record stores the SHA-256 of the
previous one, so editing or deleting any past record breaks the chain.
`AuditLog.verify()` re-walks the file and returns `True` only if it is intact.
This is the reproducibility/accountability backbone for the paper.

---

## Roadmap — where this is going

You are at milestone 1. Each step is runnable before the next and adds exactly
one idea:

| # | Milestone | Adds |
|---|-----------|------|
| **1** | **The spine (this repo)** | gate + cage + audit; proves 100% interception |
| 2 | One recon agent | an LLM that *proposes* to the gate instead of you typing |
| 3 | Soft score + escalate | the gate's second layer + human-approval path |
| 4 | Orchestrator + blackboard | planner + Obsidian-vault memory + task tree |
| 5 | Exploit + verify agents | genuinely multi-agent |
| 6 | Adaptive trust | the per-agent `Tᵢ` loop (needs outcomes to learn from) |
| 7 | The four experiments | scope interception · governed-vs-ungated · multi-vs-single · adaptive-vs-fixed |

Milestones 1–3 alone are a defensible workshop-paper core.

---

## Design principles (so future-you does not break them)

- **The gate has no LLM.** Scope is enforced by code so a malicious target
  cannot talk its way past it.
- **Fail-closed.** When in doubt, deny.
- **The gate never trusts the agent's self-report.** It reads the command
  itself.
- **One execution path.** Agents call `Executor.run()`; they never touch the
  Kali backend directly. That is what makes "the agent cannot bypass the gate"
  a structural fact.
