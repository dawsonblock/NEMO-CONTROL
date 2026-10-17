# Threat Model — NEMO-CONTROL RC7.4

## Actors and trust boundaries

| Boundary | Untrusted side | Trusted side |
|---|---|---|
| Reasoning → capability ABI | NEMO runtime output, untrusted callers | Capability registry, schema validation, request framing |
| ABI → authority kernel | Forged/expired/wrong-principal requests | `internal/authority` grant store, signature verification |
| Admission → execution | Signed-but-hostile jobs, replayed nonces | `AdmitJob` (contract signature, pool CAS, durable identity) |
| Effect fabric → microVM | Guest code, substituted VMs, runtime faults | `MSBBackend` policy digest, boot-generation binding, handle ownership |
| Executor → storage | Bit-rot, tampering, partial writes | SQLite ledger (flock + fence epoch + `MaxOpenConns(1)`), signed receipts, hash-chained checkpoints |
| Executor → custody | Self-declared custody, forged acks | `SocketCustodian` + trust-root-verified signed acknowledgements |
| Qualification → release | Laundered evidence, stale reports, mutable deps | `go-test-case-evidence.py`, required-test inventory, digest pins, `ci` provenance |

## Threats and mitigations

- **T1 Self-authorization.** A reasoning-layer request minting or widening its own grant. Mitigated
  by authority kernel (I1): capabilities are schema-bound, grants are signed out-of-band, advisory
  capabilities have no signing/dispatch power.
- **T2 Authority bypass.** An alternate path (reconcile/maintenance/direct backend call) executing
  without admission. Mitigated by single `driveDispatch` pipeline (I2) — non-admission paths can
  only observe.
- **T3 Ambiguous-effect replay/destruction.** A launch whose outcome is uncertain being retried
  (double effect) or destroyed (killing a running workload). Mitigated by `ErrAmbiguousDispatch`
  (I3): unresolved rows persist, are re-observed not re-dispatched, and destruction requires the
  dispatch-ownership label.
- **T4 Split recovery ownership.** Concurrent/stale controllers both claiming the same recovery
  window. Mitigated by atomic fenced claims (I4) — one conditional write decides, epoch+lease bound
  reassignment.
- **T5 Silent audit loss.** A mandatory decision landing without durable evidence. Mitigated by
  transactional state+event commits (I5) — no evidence, no state change.
- **T6 Artifact/source substitution.** Tampered source, runtime, image, or evidence passing as
  reviewed. Mitigated by bidirectional manifests, pinned digests, signature checks, schema-version
  gating (I6), and stream-rederived qualification records (I7).
- **T7 Mutable qualification environment.** Tag drift between review and run. Mitigated by pinned
  digests everywhere the gate runs, incl. the local helper default (WP6).
- **T8 Stale-controller fencing.** A superseded executor epoch authorizing effects. Mitigated by
  ledger flock + monotonic epoch checked on every fenced transition, and by `claim_epoch` binding
  recovery ownership to the epoch that earned it.

## Out of scope / residual

- Physical/hypervisor compromise of the host itself (the microVM is the isolation boundary, not
  the host).
- External third-party evidence custody (interface proven locally; service not deployed — blocker).
- The linux-kvm lane on this host (needs an amd64 KVM runner — NOT_RUN, not claimed).
