# ADR-0003: Distinct Custody Protocols Behind a Versioned Evidence Contract

- Status: Proposed (PR-00 record; implementation PR-04)
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
