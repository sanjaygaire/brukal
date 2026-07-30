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
# cage + DVWA up; set DVWA to security=low; scope authorises ONLY the target
python benchmarks/live_capability.py --target 172.20.0.4 \
    --scope runs/dvwa.json --yes-authorised \
    --json benchmarks/results/live_capability_dvwa.json
```

Result (see `results/live_capability_dvwa.json`): **4/4** classes confirmed — SQLi,
reflected XSS, OS command injection, LFI — with **0 scope violations**, an out-of-scope
probe **blocked mid-run**, the **audit chain intact**, and 4 confirmed findings recorded.

### Honest scope

The 4/4 rate means the deterministic proofs fire correctly on real vulnerabilities
Brukal reaches — it is **not** a real-world discovery rate. What gets *found* on an
unknown target depends on the driving model's navigation (the model-bound ceiling), not
on the gate. Every figure here holds the five safety invariants unchanged.

`runs/` is git-ignored (operator-specific); the reference `results/*.json` are committed
as the paper's snapshot at the recorded commit.
