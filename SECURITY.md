# Security & Responsible Use

Brukal is a **penetration-testing** tool. It is designed to run real
reconnaissance and (in later milestones) exploitation commands against network
targets. That power carries responsibility, and this document is not optional
reading.

## Authorised use only

**Only use Brukal against systems you own or have explicit, written permission
to test.** Unauthorised access to computer systems is a crime in most
jurisdictions (for example the Computer Misuse Act, the CFAA, and equivalents
worldwide). Running this tool against a system without authorisation may be
illegal regardless of intent.

Before any engagement:

- Confirm the target is in scope and that you have written authorisation.
- Record that authorisation (date, targets, permitting party).
- Configure `scope.json` to match the authorised scope exactly.

Brukal is built to *help* you stay lawful — its deterministic gate refuses any
action outside the configured scope, and its audit log records every decision —
but the tool cannot verify that your authorisation is genuine. That
responsibility is yours.

## Design intent: safety by construction

Brukal's whole architecture exists to keep automated testing inside its
authorised bounds:

- A deterministic **scope gate** intercepts every action; out-of-scope actions
  are refused in code (no AI is involved in that decision).
- Execution happens only inside a **sandboxed, network-isolated container**.
- An **append-only, hash-chained audit log** makes every action accountable.

Please do not modify the project to remove or weaken these safeguards. They are
the point.

## Reporting a vulnerability in Brukal

If you find a security issue in Brukal itself (for example a way for an agent to
bypass the gate), please report it privately by opening a
[GitHub security advisory](https://docs.github.com/en/code-security/security-advisories)
on the repository rather than a public issue, so it can be fixed before
disclosure. Include steps to reproduce and the affected version.

## No warranty

This software is provided "as is," without warranty of any kind (see LICENSE).
You are responsible for how you use it.
