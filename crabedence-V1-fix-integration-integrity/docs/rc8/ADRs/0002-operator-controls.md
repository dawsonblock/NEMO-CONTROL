# ADR-0002: Operator Release Controls as a Signed Append-Only Ledger

- Status: Implemented (PR-03 — `internal/releasectl`, dispatch gate, `crabbox control` CLI)
- Date: 2026-10-24
- Related: INV-3, INV-4, D-02, D-03, G3

## Context

Main's `internal/releasectl` models release control as filesystem artifacts:

- `Verify` accepts any cryptographically valid embedded key when the
  trusted-fingerprint map is empty — a self-signed operator passes.
- `Resume`, `Unrevoke`, and `ClearStage` delete marker files. A halt state
  disappears by `unlink`, performable by any process with write access —
  including a kernel-compromised one.

INV-4 requires an independently pinned signer; G3 requires that a
kernel-level compromise cannot erase an authorized halt.

## Decision

1. Replace file-presence semantics with an **append-only, operator-signed
   control-event ledger**. Event kinds: `halt`, `resume`, `revoke`,
   `unrevoke`, `stage`, `stage-clear`.
2. Every event binds: release digest, deployment/tenant identity,
   sequence/epoch, previous-state digest, signer role, reason, policy version.
   `resume`/`unrevoke`/`stage-clear` require a valid operator signature;
   `halt`/`revoke` remain unauthenticated-but-audited so emergency stop never
   waits on key availability, and an unsigned `halt` can only tighten state.
3. Effective state = fold of verified events over a monotonic authorized
   checkpoint. Missing, corrupted, rolled-back, or equivocal state fails
   closed.
4. Production requires a **nonempty, separately provisioned** trusted-signer
   allowlist. Unsigned/self-consistent mode is an explicit development flag
   that cannot be selected unintentionally in production builds/config.
5. Operator private keys live outside kernel process ownership: OS ACLs, an
   isolated control service, or an externally controlled append-only store,
   per deployment.
6. Emergency behavior on control-store outage/restart: refuse stale
   replay/resume/restore; documented multi-party or break-glass recovery with
   its own strong authorization — never unsigned deletion.
7. Stage transitions (canary→majority→full) bind qualification evidence and
   release identity; absent records never read as approval.
8. **Trust-root rotation is epoch-scoped.** An event is authorized against
   the root set of its own epoch, so a rotation retires an epoch of signers
   without invalidating the history that generation signed (`<epoch>:
   <fingerprint>` entries in the allowlist; bare fingerprints trust at
   every epoch). Removing a fingerprint altogether remains a deliberate
   freeze: every relaxation that key ever signed fails verification on
   next open — recovery is a new epoch event signed by a surviving or
   newly-epoch'd root, never truncation of history. New events are
   rejected below the chain's maximum epoch.
9. **The checkpoint is the operator-held anchor.** It must be configured
   explicitly in production and placed outside the writable runtime's
   authority (separate storage, ownership, or an operator-held host) — a
   checkpoint deletable with the ledger is precisely the loss a halt is
   meant to survive. Production also refuses to mint a missing ledger at
   startup: delete-then-restart must never read as "no restrictions".
10. **Checkpoint advance is deliberate.** An append advances the
    checkpoint over the entire chain, so the CLI warns when a pending
    relaxation written by another operator would be authorized by the
    append — checkpoint writes are the authorization act, not a side
    effect.

## Consequences

- `internal/releasectl` from Main is **not** imported as-is; its API shape and
  test skeleton are ported onto ledger semantics.
- Deployments must provision operator keys and the trust root before enabling
  production mode; absence fails closed (documented operator path).
- Ledger storage choice is deployment-pluggable behind a small interface;
  the default local implementation must still verify signatures on read, so
  tampering is detected rather than trusted.
- Production deployments provision the ledger (`crabbox control`) and the
  checkpoint path *before* first boot — the service never creates either.
- Signer rotation = bump the epoch and re-scope roots; no ledger rewrite,
  no downtime beyond a service restart to reload the allowlist.
- Concurrent writers serialize on an O_EXCL lockfile; a stale lock denies
  appends (fail closed) and is removed manually — deletion can only deny,
  never clear restrictions.
