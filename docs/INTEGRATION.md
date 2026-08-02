# Integrating Brukal

Brukal is meant to sit inside whatever an organisation already runs, not beside it.
There are three seams: **output** other systems ingest, **detections** anyone can
contribute, and a **pipeline gate**. All three are deliberately narrow — see
[What a pack cannot do](#what-a-pack-cannot-do) for why.

---

## 1. Output: SARIF and a versioned JSON envelope

Every run writes both, next to the human report, in the engagement's vault directory:

```
runs/vault/<target>/
  report.md        report.json        # for people
  brukal.sarif     findings.json      # for machines
```

### SARIF 2.1.0 — `brukal.sarif`

The interchange format GitHub code scanning, GitLab, Azure DevOps, DefectDojo and most
dashboards already read. No integration code required.

```yaml
# .github/workflows/security.yml
- name: Upload Brukal findings
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: runs/vault/10.0.0.5/brukal.sarif
```

What it carries beyond the basics:

| Field | Why it is there |
|---|---|
| `properties.security-severity` | The CVSS number GitHub uses to place a finding in its own bands |
| `partialFingerprints` | Stable across runs, so a dashboard shows **one issue with a history** rather than a new issue every scan |
| `properties.confirmed` | Whether a deterministic proof ran — see below |
| `invocations[].properties.auditChainIntact` | Governance travels **with** the findings |

**Confirmed vs lead.** An unconfirmed finding exports with `confirmed: false`, rule
precision `medium`, and a message that begins `UNCONFIRMED LEAD`. A reviewer deciding
what to action needs to know which results carry a proof and which are hypotheses, and
that distinction is the one thing a report cannot afford to blur.

### `findings.json`

A versioned envelope for anything bespoke — a triage script, a notebook, a warehouse.
`schema_version` is the contract: fields are added, never repurposed.

```json
{
  "schema_version": "1.0",
  "governance": { "audit_chain_intact": true, "commands_blocked": 3 },
  "summary": { "total": 6, "confirmed": 6, "by_severity": { "critical": 5 } },
  "findings": [ { "id": "...", "rule": "brukal/sql-injection-error-based",
                  "confirmed": true, "cvss": 9.8, "remediation": "...",
                  "references": ["OWASP A03:2021 Injection", "CWE-89"] } ]
}
```

---

## 2. Contributed detections: signature packs

A researcher who finds a new pattern, or an organisation whose internal services emit
error strings nobody else would recognise, should not have to fork Brukal.

```bash
brukal auto 10.0.0.5 --scope scope.json --packs ./our-packs --yes-authorised
```

A pack is one JSON file:

```json
{
  "name": "acme-internal",
  "description": "error strings from Acme's internal services",
  "signatures": [
    { "pattern": "sqlalchemy\\.exc\\.[A-Za-z]+Error",
      "severity": "medium",
      "title": "Internal ORM error surfaced to the client",
      "category": "web" }
  ]
}
```

Hits arrive as ordinary findings tagged with the pack name — deduplicated, soft-404
downgraded, and exported exactly like a built-in detection:

```
[medium] Internal ORM error surfaced to the client [acme-internal]
```

### What a pack cannot do

This is the design, not a limitation to be lifted later.

- **It cannot execute.** A plugin system that loaded Python would hand arbitrary code
  the same process as the gate, and Brukal's entire safety argument rests on agents
  being unable to reach the cage except through `Executor.run`.
- **It cannot act, request, or widen scope.** A pack says *"this text means this
  finding"*. There is no hook for anything else.
- **It cannot claim a finding is confirmed.** Confirmation means a deterministic proof
  ran and was observed. Contributed data asserting it would corrupt the one distinction
  the report rests on, so `confirmed` is forced to `false` on load.
- **It cannot hang the run.** Patterns are length-capped and a catastrophic-backtracking
  shape is refused, because pack patterns run against untrusted target output.

A malformed pack is survived, never obeyed: a bad signature is skipped, a bad file
contributes nothing, and the engagement continues.

---

## 3. Pipeline gate

```bash
brukal auto 10.0.0.5 --scope scope.json --yes-authorised --fail-on high
echo $?    # 1 when a CONFIRMED finding at or above 'high' was recorded
```

`--fail-on` counts **confirmed findings only**. A build should break on something Brukal
proved, not on a lead nobody has triaged — a gate that cries wolf gets switched off
within a week, and then it protects nothing.

---

## 4. What does not change

Integration adds seams; it removes no governance.

- Scope is still enforced by deterministic code before anything reaches the cage.
- Every action is still hash-chained into the audit ledger, and the export carries
  whether that chain verified.
- Exporting is a pure function of the finding store: it has no I/O into the engagement
  and cannot alter a verdict.
