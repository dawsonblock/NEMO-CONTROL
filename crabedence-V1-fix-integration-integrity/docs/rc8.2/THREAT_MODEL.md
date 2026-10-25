# RC8.2 Threat Model

Scope: the Crabedence authority → dispatch → terminalization → custody
pipeline, the sandbox executor cleanup path, and the release/provenance
pipeline. NEMO (the reasoning runtime) is out of scope as an authority
source: it never authorizes mutation; this model covers the boundaries
that keep it that way.

## Adversaries

| Class | Capability |
|---|---|
| A1 — Compromised runtime/agent | Arbitrary requests to the execution socket; may supply forged principals, evidence, receipts, mediation claims. Cannot hold kernel signing keys. |
| A2 — Compromised kernel process | Reads/writes its own address space and filesystem under the service UID; can delay, drop, reorder its own evidence writes; can corrupt its in-memory health state. Cannot forge signatures under operator, custodian, or release keys it does not hold. |
| A3 — Network adversary | Delays, drops, replays, forks custody traffic between kernel and witness; cannot mint Ed25519 signatures. |
| A4 — Malicious or failed witness | Returns forged checkpoints, fabricated acknowledgements, contradictory heads, wrong-identity responses, stale signer epochs. |
| A5 — Shared-runtime tenant | Races sandbox create/inspect/delete; replaces sandbox objects between inspection and removal; reuses visible names/handles. |
| A6 — Release-pipeline adversary | Substitutes archives, sidecars, or manifests; replays an older attestation; claims a signature from an unauthorized signer. |
| A7 — Concurrent legitimate load | N simultaneous admissions against a wedged or slow authority ledger; bursts of terminalizations during a witness outage. |

## Security properties (mapped to INV-xx)

| Property | Threat it defeats | Mechanism |
|---|---|---|
| INV-01 authority | A1 | kernel-issued authorization at admission; folded-chain check per dispatch |
| INV-02 revocation | A1/A2 | re-read ledger per admission; generation-fenced probes (F-01) |
| INV-03 idempotency | A1/A7 | durable idempotency store, fenced CAS transitions |
| INV-04 UNKNOWN honesty | A1 | UNKNOWN never auto-relabeled FAILED or retried |
| INV-05 durable obligations | A2/A7 | terminal-seq replay scanner + outbox (F-02) |
| INV-06 evidence honesty | A2 | durable degraded/repair state, never memory-only (F-02) |
| INV-07 verified startup | A2/A4 | witness-verified readiness before CRITICAL admission (F-03) |
| INV-08 release binding | A6 | signed release manifest bound into every envelope (F-04) |
| INV-09 cleanup honesty | A5 | identity-conditioned removal or documented namespace limitation (F-06) |
| INV-10 exact-artifact qualification | A6 | frozen-commit qualification, artifact digest binding (F-07/F-08) |
| INV-11 research governance | A1 | observation-v1 verifier + operator-signed promotion (RC8.1 PR-06) |

## Trust boundaries

1. **Socket admission** — peer-auth principal verification, bounded
   handshake phase; the control gate re-reads the folded operator chain
   per admission (never cached).
2. **Terminalization** — fenced CAS into the idempotency store under a
   lease token + generation; `terminal_seq` allocated in the same tx.
3. **Custody enqueue** — obligation written to the durable outbox; the
   obligation outlives the process.
4. **Witness drain** — checkpoint realignment under a pinned custodian
   trust set; acks verified at the recording boundary, never trusted
   from the transport.
5. **Sandbox runtime** — `msb` CLI is an unprivileged external runtime;
   identity is established by nonce-bound handles, and deletion that
   cannot prove identity is REMOVAL_UNCERTAIN, not success.
6. **Release pipeline** — source commit → deterministic archive →
   signed attestation; verification replays the whole chain
   clean-room.

## Assumptions

- Operator, custodian, and release signing keys remain outside the
  service's failure domain (externally provisioned trust files).
- SQLite WAL + `synchronous=FULL` gives durable commits for the
  idempotency store and outbox on a non-adversarial filesystem.
- The witness is separately administered; its ledger is append-only
  and its checkpoint is signed under the pinned custodian key.
- A kernel compromise (A2) can delay or destroy *its own* evidence but
  cannot fabricate verified custody, cannot remove a durable degraded
  marker without the repair procedure, and cannot admit CRITICAL work
  while the custody path is unverified.

## Out of scope

- VMM/hardware trust: the sandbox lane inherits `msb`/hypervisor
  integrity; kernel compromise of the *host* below the service UID is
  outside this model.
- Denial of service from a legitimately authorized operator.
