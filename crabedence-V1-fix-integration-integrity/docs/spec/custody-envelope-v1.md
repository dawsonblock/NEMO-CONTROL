# custody-envelope-v1 — Versioned Custody Evidence Contract (proposed)

Status: implemented at PR-04 (`internal/custody`, `internal/witness`,
`cmd/witnessd`, `internal/execution` custody wiring). Governs evidence
exchange between the Crabedence kernel, receipt witnesses, and sandbox
custodians.

## 1. Purpose

Unify verification semantics for three evidence families without collapsing
the distinct wire protocols that produce them:

| Family | Producer protocol | Carries |
|---|---|---|
| `receipt` | `internal/witness` (length-prefixed JSON frames) | per-execution terminal/ambiguous effect receipts and custody acknowledgements |
| `sandbox_archive` | `internal/sandboxcustody` (newline-delimited JSON) | sandbox payload archives bound to a job |
| `recovery_checkpoint` | `internal/sandboxcustody` (newline-delimited JSON) | recovery checkpoints for interrupted jobs |

The contract is a typed semantic envelope. Producers keep their native wire
formats; adapters map each native record to an envelope for verification,
indexing, and cross-checking. Neither protocol is re-encoded into the other.

## 2. Envelope

```jsonc
{
  "envelope": "custody-envelope-v1",
  "family": "receipt" | "sandbox_archive" | "recovery_checkpoint",
  "deployment_id": "string",            // deployment identity; foreign deployments rejected
  "release_identity": {
    "source_commit": "hex-40",
    "version": "semver",
    "artifact_sha256": "hex-64"          // when bound to a packaged artifact
  },
  "policy_digest": "hex-64",             // digest of active policy
  "subject": {
    "effect_id": "string",               // receipt family
    "execution_id": "string",
    "job_id": "string",                  // sandbox families
    "sandbox_uid": "string"
  },
  "sequence": {
    "domain": "family-scoped",           // each family has an independent monotone domain
    "epoch": 0,
    "index": 0,
    "previous_checkpoint_hash": "hex-64" // immutable linkage where relevant
  },
  "content": {
    "hash": "hex-64",                    // hash of the native record bytes
    "encoding": "witness-frame-v1" | "sandboxcustody-ndjson-v1",
    "bytes_b64": "string"                // original event bytes — retained verbatim
  },
  "signer": {
    "role": "custodian" | "kernel-relay",
    "key_id": "string"                   // resolved against pinned trust config only
  },
  "signature": "base64"
}
```

## 3. Signature domain separation

The signature preimage is:

```
"custody-envelope-v1" || 0x00 || family || 0x00 || canonical-jcs(envelope-without-"signature")
```

`family` is literal and mandatory; a `receipt` signature can never verify as
`sandbox_archive` and vice versa. Canonicalization uses JCS (RFC 8785) over
the envelope minus the `signature` field.

## 4. Trust model

- Verification keys are resolved **only** from externally maintained trust
  configuration (`key_id` → pinned key, scoped by `role` and
  `deployment_id`). Key material inside a received record is ignored.
- Custodian keys are a third key class: disjoint from kernel keys and from
  release-control operator keys (ADR-0002).
- An empty trust set for a family fails closed: every record is unverifiable.
- Key rotation: a rotation record signed by the outgoing key *and* pre-authorized
  in trust config; records signed by retired keys verify only for
  sequence indexes below the rotation point.

## 5. Sequence rules

- `sequence.index` is strictly monotone per `(family, deployment_id,
  subject-stream)`; gaps and duplicates are detected and surfaced.
- `epoch` increments only via a signed epoch-advance event; replays from a
  prior epoch are rejected.
- `previous_checkpoint_hash` chains checkpoints; a contradictory checkpoint
  (same index, different hash) is an equivocation and fails closed.

## 6. Acknowledgement semantics

- A submission is complete only when a signed acknowledgement from the
  custodian verifies at the recording boundary. Witness downtime can never
  produce a verified terminal custody success (INV-3, G4).
- Redelivery is idempotent: the custodian re-acks a duplicate rather than
  recording twice.
- On restart or cold restore, the outbox reconciles: unacknowledged
  submissions are redelivered; acknowledged ones are not re-executed.

## 7. Transport

- Local Unix-domain sockets are a **local** transport only.
- Separate-host custody requires mutual authentication and an encrypted
  channel; the peer authenticates as a specific `deployment_id` + `role`.
- Partitions fail closed for verification-dependent state; submissions queue
  in the durable outbox and reconcile on reconnect.

## 8. Verification obligations

A verifier must check, in order: envelope version → family allowlist →
deployment identity → release identity binding → policy digest → sequence
(monotone, epoch, checkpoint linkage) → content hash matches bytes →
signature under the family domain with a pinned key. Any failure is a
reject with a typed reason — never a downgrade.

## 9. Out of scope

Payload semantics inside `content.bytes` are family-defined; the envelope
carries them opaquely. Promotion/admission decisions consume *verified*
envelopes through other gates — the envelope proves custody, not approval.
