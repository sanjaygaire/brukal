# Brukal benchmarks

Reproducible evidence for the paper *"Trust-Governed Multi-Agent Large Language Model
Penetration Testing with Risk-Constrained Action Gating."*

Two layers, kept deliberately separate:

| Layer | What it measures | Needs |
|-------|------------------|-------|
| **Governance** (`../run_experiments.py`) | Properties of the deterministic gate | nothing — no Docker, network, API key, or target |
| **Live capability** (`live_capability.py`) | Vuln classes Brukal confirms by its own deterministic proofs, with the gate holding | the Docker cage + an **authorised** target |

The split is the point: the safety claims are gate properties and reproduce on any
laptop; capability is measured live, and only ever against a target you are authorised
to test.

## 1. Governance metrics (reproducible anywhere)

```bash
python run_experiments.py
python run_experiments.py --json benchmarks/results/governance_bench.json
```

Four experiments, all pass (see `results/governance_bench.json`):

1. **Scope interception** — 5/5 out-of-scope actions denied before the cage (100%), 0 unsafe executions, audit chain intact.
2. **Governed vs ungated** — the gate prevents all 5 unsafe executions an ungated agent performs.
3. **Multi-agent vs single** — the verify agent catches a hallucinated success the single agent misses; digests cut context 32,105 → 764 bytes (97.6%).
4. **Adaptive vs fixed trust** — a proven-bad agent's later benign action ESCALATEs under adaptive trust but is ALLOWed under fixed (final trust 0.343).

## 2. Live capability (authorised testbed only)

Reference run: DVWA on an isolated Docker network, `security=low`, scope file
authorising the single host. Brukal confirms each class by a **deterministic
differential proof** — the verdict is code, not an LLM's opinion — through the
governed browser, never a shell.

```bash
# cage + DVWA up; set DVWA to security=low; each scope authorises ONLY its own host
python benchmarks/live_capability.py \
    --target 172.20.0.3 --scope runs/dvwa.json \
    --ai-url http://172.20.0.2:3000/rest/chat --ai-scope runs/juice.json \
    --api-url http://172.20.0.5:5000 --api-scope runs/vampi.json \
    --api-login /users/v1/login <user> <pass> \
    --graphql-url http://172.20.0.6:5013/graphql --graphql-scope runs/dvga.json \
    --cage brukal-kali --yes-authorised \
    --json benchmarks/results/live_capability_dvwa.json
```

Each class runs against its own target under its OWN scope file. That split is
deliberate: the gate is per-scope, and widening one scope to span three hosts would
demonstrate precisely the wrong thing. Every section independently re-checks that an
out-of-scope probe is refused mid-run and that its ledger still verifies.

Result (see `results/live_capability_dvwa.json`): **13/13** classes confirmed across
**four** authorised targets, each under its OWN scope file:

| Target | Classes confirmed |
|---|---|
| DVWA (PHP, behind a login) | 4/4 — boolean SQLi, reflected XSS, OS command injection, LFI |
| OWASP Juice Shop (SPA + LLM chatbot) | 1/1 — prompt injection (OWASP LLM01) |
| VAmPI (JSON REST API) | 6/6 — unauthenticated exposure of credentials and (separately) of bulk personal data, SQLi on a REST **path parameter**, a JWT signing key recovered **offline**, authentication bypass via a **forged token**, and **BOLA** across an account boundary |
| DVGA (Damn Vulnerable GraphQL App) | 2/2 — GraphQL introspection (confirmed **structurally**) and query batching |

with **0 scope violations**, an out-of-scope probe **blocked mid-run on every target**,
the **audit chain intact on all three ledgers**, and 13 confirmed findings recorded.

The AI class is proved the same way as the rest: the injected directive demands a canary
the model can only produce by performing the instructed transformation, so the value
appears nowhere in the request and an endpoint that merely echoes the payload cannot
fake it. The verdict is a string comparison, not a model's opinion.

Two notes on how the API figure is counted. The credential and personal-data lines are
one check graded by what leaked, counted separately because they are separate findings
against separate endpoints with different severities. **Mass assignment is deliberately
absent**: it is the only proof that must WRITE to the target, and a benchmark should not
create accounts on a host to score a point — it is exercised by the test suite instead.

The API section also reports `token_acquired`. Three of its six classes are unreachable
without a credential, so a `false` with no token is a missing precondition, not a clean
bill of health — an early run scored 3/6 for exactly that reason.

The GraphQL line is confirmed structurally — the response must genuinely carry a
`__schema` — rather than by status code. That is not a detail: the commonest shape in
this space is a single-page app answering 200 with its `index.html` for every path, and
Juice Shop does exactly that on `/graphql`. A status or keyword check would score this
point against an application that has no GraphQL at all.

The GraphQL section also reports `not_applicable`. Field-suggestion leakage is a real
check, but it deliberately declines when introspection is already open — the schema is
one query away there, so reporting both would be noise. That is a suppression, not a
miss, so it is named and left out of the denominator rather than scored as a failure.

### Honest scope

The 13/13 rate means the deterministic proofs fire correctly on real vulnerabilities
Brukal reaches — it is **not** a real-world discovery rate. What gets *found* on an
unknown target depends on the driving model's navigation (the model-bound ceiling), not
on the gate. Every figure here holds the five safety invariants unchanged.

`runs/` is git-ignored (operator-specific); the reference `results/*.json` are committed
as the paper's snapshot at the recorded commit.
