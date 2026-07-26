# Contributing to Brukal

Thanks for looking at Brukal. It is a research system with a small, deliberately
un-clever **safety core** and a larger, fast-moving capability layer around it. The
whole design rests on one asymmetry: **capability lives *above* the gate; trust and
enforcement live *below* it.** Contributions are welcome as long as they preserve
that shape.

## The five safety invariants (please don't break these)

1. **No LLM inside the gate.** Scope is enforced by deterministic code (string
   parsing, set membership, CIDR arithmetic, regex) so a hostile target cannot talk
   its way past it.
2. **Fail-closed.** Anything ambiguous, unparseable, malformed, or expired is
   DENIED. The safe default is always refuse.
3. **Never trust an agent's self-report.** The gate re-reads the command itself
   (every host in the command, not the declared `target`).
4. **One execution path.** Everything runs through `Executor.run()`, which gates
   first and logs always. Agents get the Executor, never the Kali cage.
5. **Immutable scope, append-only audit.** Scope cannot widen at runtime; the
   hash-chained audit log cannot be edited undetectably.

A change that would weaken any of these needs to be discussed first, not merged.
Capability features are fine — but a feature that only works with a *gate exception*
is not the feature we want. There is no `--no-gate`, and there never will be.

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"      # pytest + pydantic + rich — a clean checkout runs green
python -m pytest             # the whole suite, no Docker / key / network needed
```

The suite is the specification for the invariants. **Every existing test must stay
green, and new code needs new tests** — that is a merge gate, not a suggestion. The
safety core (`scope.py`, `gate.py`, `risk.py`, `executor.py`, `audit.py`,
`hostmatch.py`) is standard-library-only on purpose; please keep it that way.

## Here's the gate — try to break it

The most valuable contribution is an adversarial one. If you can make Brukal run a
command it should have refused, that is a **safety bug** and we want it. The core
you are attacking is tiny and readable:

- `scope.py` — the frozen policy, CIDR / hostname matching, the authorization/expiry
  artifact.
- `hostmatch.py` — extracts *every* host from a command (URLs, IPv4/IPv6 literals,
  and decimal/hex/octal IP encodings). Smuggling a host past this is exactly the
  kind of bug worth reporting.
- `gate.py` — the hard checks (injection → parse → allowlist → target-in-scope →
  no-smuggled-host → rate-limit) as a logical AND, then the soft risk layer.
- `executor.py` — the one door: gate → log → (maybe) run.
- `audit.py` — the hash-chained ledger (`verify()` must reject any edit).

Concrete things to try:

- Get an **out-of-scope host** executed — a second IP after a pipe/`;`, an encoded
  IP (`nmap 0x0a0a0a05`), an IPv6 form, a URL whose host differs from the declared
  target, a redirect to an out-of-scope host.
- Get a **shell metacharacter** or a second command through the parse layer.
- Make the **soft risk layer** ALLOW something irreversible/attack-shaped that
  should ESCALATE, or make **trust** rescue a hard DENY (it must not — trust only
  ever tightens the soft layer).
- Make `AuditLog.verify()` pass after you have altered a past record.
- Get a run to start against an **expired** scope, or make a poisoned/target-derived
  "lesson" reach the retrieved (trusted) tier without a shell-confirmed success.

If you find one, please open an issue (see [`SECURITY.md`](SECURITY.md) for anything
you consider sensitive) with a failing test that demonstrates it — a red test is the
best possible bug report here.

## Style

- Match the surrounding code: comment density, naming, stdlib-first in the core.
- One idea per change; keep the diff reviewable.
- Never point a live run at a system you are not authorised to test — the same rule
  that governs the tool governs its development.
