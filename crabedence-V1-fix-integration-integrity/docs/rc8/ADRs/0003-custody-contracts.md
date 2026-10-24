# ADR-0003: Distinct Custody Protocols Behind a Versioned Evidence Contract

- Status: Implemented (PR-04)
- Date: 2026-10-24
- Related: INV-3, INV-4, D-04, D-05, G4, `docs/spec/custody-envelope-v1.md`

## Context

Two real custody protocols exist and are **not** wire-compatible:

- `internal/sandboxcustody` (RC7.6): newline-delimited JSON for payload
  archives and recovery checkpoints.
- `internal/witness` (Main): length-prefixed JSON for per-execution receipt
  custody.

Merging them into one format, renaming one into the other, or sharing a
signature domain would let evidence from one protocol masquerade as the other
and collapse their independent audit trails.

## Decision

1. Define `custody-envelope-v1`: a versioned typed contract with three
   evidence families — `receipt`, `sandbox_archive`, `recovery_checkpoint`.
   Each family has a domain-separated signature preimage and an independent
   sequence domain.
2. Neither protocol is re-encoded into the other. Adapters translate at the
   semantic contract layer; original event bytes are retained alongside the
   normalized envelope linkage.
3. Every record binds: deployment identity, release/source identity, policy
   digest, sequence/epoch, effect/execution identity, content hash, signer
   role, and immutable previous-checkpoint hash where relevant.
4. Durable submission outbox + independently verified signed acknowledgement
   at the recording boundary; idempotent redelivery; restart/cold-restore
   reconciliation; monotone checkpoint recovery.
5. Custodian signer is a third key class — separate from kernel keys and from
   release-control operator keys. Witness/custodian keys are pinned from
   externally maintained configuration, never from the received record.
6. Local Unix sockets remain a *local* transport. Separate-host custody
   requires mutual authentication, encrypted channel, access control,
   offline/read-only verification, key rotation, and explicit partition
   behavior.
7. Capability negotiation is explicit: a peer that cannot speak
   `custody-envelope-v1` is not silently downgraded.

## Consequences

- `internal/witness` is ported behind the contract with a `receipt` adapter;
  `internal/sandboxcustody` gains `sandbox_archive`/`recovery_checkpoint`
  adapters. A shared `internal/custody` (or equivalent) layer holds envelope
  types, verification, and outbox mechanics.
- G4 tests must prove cross-family signature confusion fails
  (`TestWitnessCrossFamilyConfusion`) and that custodian outage cannot
  produce terminal verified state.
- Independent custody in G8 means a separately administered host with
  separately controlled keys — local-mode deployments stay development-only.

## Implementation notes (PR-04)

- `internal/custody` holds the contract: `Envelope`, canonical JSON
  (RFC 8785-profile serialization for this schema), domain-separated
  `SigningBytes`, the §8 `Verify` pipeline with typed rejections, and
  `TrustSet` — role- and deployment-scoped pinned keys with
  sequence-index validity windows. Rotation successors must carry the
  incumbent's `custody-key-rotation-v1` authorization; the trust file
  loader is owner-only and refuses silent succession.
- `internal/witness` is the receipt family: length-prefixed framed ops
  (`submit`/`checkpoint`/`status`), an append-only SQLite custody log
  (`PRIMARY KEY (deployment_id, seq)`, `UNIQUE (deployment_id,
  execution_id)`), signed acknowledgements under
  `custody-witness-ack-v1`, and signed checkpoint heads under
  `custody-witness-checkpoint-v1` — a forged or replayed realignment
  cannot truncate the sender. Idempotent resend returns the stored ack;
  a divergent record at a custodied index is a contradictory checkpoint
  and fails closed.
- The kernel-side `Outbox` builds, chains, and signs each envelope
  inside the enqueue transaction (`previous_checkpoint_hash` links each
  record to the prior head), so signed position equals durable
  position. `Sender` drains with verified-checkpoint realignment and
  boundary ack verification; `CustodyHealthy` feeds the fail-closed
  CRITICAL admission gate. Provider-terminal state and custody-ack
  state stay distinct — an outage delays custody, it never fabricates
  it.
- Separate-host custody is mutually authenticated TLS where each peer's
  certificate carries its Ed25519 custody key and the peer's key
  fingerprint is pinned (`witness.ServerTLSConfig`/`ClientTLSConfig`);
  unix sockets remain local-only. `cmd/witnessd` is the standalone
  service entrypoint; `CRABEDENCE_WITNESS_*` envs wire the kernel side
  (`config.go`, `serve.go`). Configured custody is complete-or-refused
  at load.
- A configured boundary mandates the custody gate for every CRITICAL
  admission; sandbox-archive and recovery-checkpoint envelope adapters
  for `internal/sandboxcustody` remain the tracked follow-on — the
  envelope contract supports them without touching either wire format.
