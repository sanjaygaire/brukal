# CLAUDE.md — Binding rules for every session on Brukal

Brukal is a **trust-governed multi-agent LLM penetration-testing system**, and the
basis of the paper *"Trust-Governed Multi-Agent Large Language Model Penetration
Testing with Risk-Constrained Action Gating."*

This file is **law**. Read it at the start of every session. Cross-session memory
lives in the Obsidian vault note **`Brukal.md`** — read it at the start of each
session and update its running log at the end.

---

## THE FIVE SAFETY INVARIANTS
**Never violate. If any change would weaken one, STOP and ask the maintainer first.**

1. **No LLM inside the gate.** Scope is enforced by deterministic code (string
   parsing, set membership, CIDR arithmetic, regex) so a hostile target cannot
   talk its way past it. A regex cannot be prompt-injected; an LLM guard could.
2. **Fail-closed.** Anything ambiguous, unparseable, malformed, or broken is
   **DENIED**. The safe default is always refuse.
3. **Never trust an agent's self-report.** The gate re-reads the command itself
   (e.g. it re-scans every IP in the command, not just the declared `target`).
4. **One execution path.** Everything runs through `Executor.run()`, which gates
   first and logs always. Agents are handed the **Executor**, *never* the Kali
   cage. **Never give an agent the `kali` object.**
5. **Immutable scope, append-only audit.** Scope cannot widen at runtime; the
   hash-chained audit log cannot be edited undetectably.

The single rule that protects all five in code: **never give an agent the `kali`
object — only ever give it a way to call `executor.run`.**

---

## Architecture (the load-bearing shape — do not break it)

```
scope.json ─► scope.py ─► gate.py ─► executor.py ─► kali.py ─► audit.py
(immutable   (frozen    (determin-  (THE ONE      (FakeKali/  (hash-
 policy)      Scope)     istic       DOOR:         DockerKali  chained
                        ALLOW/DENY/  gate→log→run) cage, no    ledger)
                        ESCALATE)                  shell)
```

- Agents (recon / exploit / verify) emit **only text** — a schema-validated
  Action Request. The model *proposes*; the code *disposes*.
- The gate runs hard checks as a logical AND (injection → parse → allowlist →
  target-in-scope → no-smuggled-host → rate-limit), then (M3+) a soft risk score
  that can ESCALATE to a human. Hard checks can only DENY, never widen.

---

## Build discipline

- **One milestone at a time**; each runnable before the next begins.
- **Keep every existing test green**; add tests for all new code. Definition of
  Done per milestone is a gate, not a suggestion.
- **Commit per milestone** with a clear message; **update `Brukal.md`** at the
  end of every session.
- **Do NOT over-build** — three agents plus a verifier is the whole system.
- Run agents **sequentially** for now (no concurrency until explicitly told).

## Rules of engagement (safety)

- **Do NOT run any live pentest** without ALL of: explicit per-session
  authorization from the maintainer, the Docker cage up, and `scope.json` matching
  the authorized target. **Build and self-test only; pause for sign-off before any
  live execution.**
- Only ever run real tools against targets the maintainer explicitly authorizes.
- Session scope is set via `brukal target <ip-or-cidr>` (validates, prints what it
  will authorize, confirms anything broader than a single host, logs to the
  engagement log). Replaces scope by default; `--add` accumulates.

## Working copy (verify before editing)

- **The ONLY repo to edit:** `C:\Users\ashis\Desktop\Brukal\brukal\` (after the
  2026-07-10 reorg). If the reorg hasn't happened yet, it is still nested at
  `...\Brukal\brukal_milestone1\brukal\brukal_updated\brukal\`. Either way, the
  real repo is the one with a `.git` — confirm with `git status` (remote
  `github.com/sanjaygaire/brukal`, branch `main`).
- Any `brukal_milestone1\` / `_stale_delete_me\` tree is a **stale copy — never
  edit it.**
- Test env (WSL): `/home/brute/brukal-venv` (pytest, anthropic, pydantic). Run
  from the repo root: `/home/brute/brukal-venv/bin/python -m pytest`.

## Verified state (as of 2026-07-09 — see Brukal.md for the live log)

- M1 (deterministic spine) ✅ · M2 seed (recon agent + schema + llm) ✅
- **M3 (soft risk layer) is NOT built** — no `risk.py`, no `test_soft_gate.py`;
  the gate's `MILESTONE 3` extension point is still a stub. (The prior
  "milestones 1–3 complete / 15 tests" summary was inaccurate for this repo.)
- **5 tests pass** (4 recon-wiring + 1 scope-interception). M3 must be built
  before M4's orchestrator can integrate the risk layer.
