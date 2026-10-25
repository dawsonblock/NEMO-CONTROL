# RC8.2 Operator Deployment — Custody, Release Identity, Assurance Profile

This document covers the RC8.2 deployment knobs added by PR-10. It is
additive to `docs/rc8/ADRs/0003-custody-contracts.md` and the existing
`CRABEDENCE_*` reference; nothing here replaces the production-mode
prerequisites (`CRABBOX_MODE=production` still requires the control
ledger, trust roots, deployment identity, attestation, and peer auth).

## Assurance profile

`CRABEDENCE_ASSURANCE_PROFILE` declares the deployment's custody
posture. It is verified at startup — a declaration that fails its
prerequisites is a startup error, never a silent downgrade.

| Value | Meaning | Prerequisites |
|---|---|---|
| `development` | Test operation. Custody optional/local; no release attestation. | none (refused under `CRABBOX_MODE=production`) |
| `reduced` | Production floor. Custody may be same-host; CRITICAL work still requires verified custody when custody is configured. | `CRABBOX_MODE=production` |
| `high-assurance` | Independently custodied production. | production + separate-host witness (`CRABEDENCE_WITNESS_TLS` + `CRABEDENCE_WITNESS_TLS_KEY`) + verified signed release manifest + the running binary proves it IS the declared artifact |

Unset resolves to the weakest profile the mode tolerates: development
mode → `development`; production mode → `reduced`. `high-assurance`
must be declared explicitly — and "production" is not a valid profile
value.

The resolved profile prints on the startup configuration report and
is never downgraded at runtime: a custody failure degrades the custody
state (the gate denies CRITICAL work), not the declared profile.

## Custody states and verified readiness

`witness.Sender` reports a durable custody state:

- `UNVERIFIED_STARTUP` — no verified drain has completed this boot.
  A fresh sender is never healthy on optimism.
- `HEALTHY` — the last drain completed inside the freshness bound
  (witness reachable, signed checkpoint verified under the pinned
  custodian set, obligation rescan clean, no backlog, no open
  degraded/repair markers).
- `DEGRADED` — backlog pending, readiness stale, or a durable
  obligation-failure marker awaiting verified repair.
- `REPAIR_REQUIRED` — a recorded evidence contradiction (fork,
  conflicting ack, contradictory obligation). Sticky: only
  `Sender.OperatorRepair` after a verified pass clears it, and the
  operator's evidence note lands in the audit log.

`CRABEDENCE_WITNESS_READINESS_TTL` bounds how old a verified
drain may be before readiness is stale (default 5s; the sender's own
floor is `DefaultReadinessTTL` = 30s when unset). The CRITICAL
admission gate requires `HEALTHY` — a state that no longer exists the
moment the freshness bound lapses or any durable marker opens.

## Durable custody obligations

Every committed terminal action owes a custody obligation. Obligations
live in the outbox (`custody_outbox`) with stable identities
(`execution_id`, unique) and are chain-linked by envelope hash.
Obligation state persists in `outbox_meta` (`degraded_reason`,
`repair_reason`, `obligation_hwm`) and every transition is recorded in
the `custody_events` audit table.

The obligation replay scanner runs at the head of every drain pass:
it enumerates the effect store's `terminal_seq` ledger, restores any
missing obligation with the byte-identical canonical payload
(`TerminalReceipt.CustodyPayload()` — the signed evidence receipt for
CRITICAL, the canonical preimage otherwise), verifies stored payload
bytes for present rows, and advances `obligation_hwm` only past a
fully covered prefix. A crash between terminalization and enqueue is
repaired by the next pass; a fork between the stores escalates to
`REPAIR_REQUIRED` and is never overwritten.

An enqueue failure durably marks custody `DEGRADED` — it survives
restart and is discharged only by a verified repair
(`Outbox.RepairDegraded`), which records the repair evidence in the
audit log. An empty payload is refused at `Enqueue` as an evidence
fault — an envelope with no content is never an obligation.

## Signed release manifest (`release-manifest-v1`)

Production custody envelopes bind the exact authorized release:

- `CRABEDENCE_RELEASE_MANIFEST` — path to the signed
  `release-manifest-v1` JSON document.
- `CRABEDENCE_RELEASE_SIGNERS` — path to the pinned release-authority
  key set: `{"version":1,"signers":[{"fingerprint":"<hex>","public_key":"<b64 ed25519>"}]}`.
  Declared fingerprints are verified against the key bytes — a
  false fingerprint is a fault.

The manifest carries: `version`, `source_commit` (40-hex commit or
64-hex source-tree identity), `artifact_sha256`, `artifact_kind`
(`binary` or `source-archive`), `policy_digest`, `registry_digest`,
`custody_protocol`, `signer_fingerprint`, `signature` (Ed25519 over
the domain-separated field vector).

Rules enforced at load:

- Either variable without the other is a startup error.
- An unsigned, malformed, wrongly-signed, or unauthorized-signed
  manifest is a startup error.
- `CRABEDENCE_POLICY_DIGEST` contradicting the manifest's
  `policy_digest` is a startup error; when the manifest is present
  its digest is the one the envelopes bind.
- `high-assurance` additionally requires `artifact_kind=binary` and
  the running executable's own SHA-256 to equal `artifact_sha256` —
  the deployment attestation that this binary *is* the signed release.
  (`source-archive` cannot self-verify and tops out at `reduced`.)

Envelope release binding carries `version`, `source_commit`,
`artifact_sha256`, and `registry_digest`; verification pins
`registry_digest` alongside the existing fields
(`custody.VerifyOptions.ReleaseIdentity`).

## Env summary

| Variable | Default | Notes |
|---|---|---|
| `CRABEDENCE_ASSURANCE_PROFILE` | `development`/`reduced` by mode | `development` refused in production |
| `CRABEDENCE_WITNESS_READINESS_TTL` | `5s` | freshness bound on verified readiness |
| `CRABEDENCE_WITNESS_DRAIN_INTERVAL` | `2s` | outbox retry cadence |
| `CRABEDENCE_RELEASE_MANIFEST` | — | signed `release-manifest-v1` path |
| `CRABEDENCE_RELEASE_SIGNERS` | — | pinned release-authority key file |
| `CRABEDENCE_POLICY_DIGEST` | — | must equal the manifest's digest when both are set |
