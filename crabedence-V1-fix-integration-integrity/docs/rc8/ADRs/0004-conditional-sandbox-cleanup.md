# ADR-0004: Conditional Sandbox Cleanup and Honest Atomicity Claims

- Status: Proposed (PR-00 record; implementation PR-05)
- Date: 2026-10-24
- Related: INV-3, D-06, G5

## Context

`internal/sandboxexecutor` cleanup currently resolves a sandbox by label and
then removes it (`msb rm`). Between resolve and remove, the runtime may
recreate a same-labelled sandbox owned by a different job, generation, or
deployment; the remove then destroys the wrong instance. Neither the label
namespace nor a "last writer wins" model makes this safe.

## Decision

1. Preferred: use an **identity-conditional delete** whose check-and-destroy
   boundary is atomic in the underlying runtime (e.g., remove-if-token /
   remove-if-generation match executed inside the hypervisor/VMM API).
2. If the runtime offers no atomic conditional delete, the cleanup obligation
   is retained as `REMOVAL_UNCERTAIN` with its cleanup record — we do **not**
   claim the atomicity property is solved. Software-side pre-checks
   (nonce/boot-generation/namespace/catalog verification) narrow the window
   but are documented as best-effort, never as verified-atomic.
3. Before any cleanup: verify job nonce, boot generation, namespace
   ownership, and runtime catalog identity; confirm the target is this
   deployment's instance, not a replacement or foreign sandbox.
4. Terminal classifications stay distinct: `RETAINED_BY_POLICY`,
   `REMOVED_VERIFIED`, `ALREADY_ABSENT_VERIFIED`, `REMOVAL_UNCERTAIN`. Timeouts
   on inspect, cleanup, and post-cleanup verification.
5. Exclusive namespace ownership is documented as an **interim deployment
   constraint**, not a substitute for atomic deletion. If no native
   conditional delete exists and substitution risk cannot be eliminated in
   the deployment threat model, the candidate is production **NO-GO**.
6. Crash between any two transitions must be recoverable without effect
   duplication or loss of the cleanup obligation.

## Consequences

- Live tests must include kill-at-every-boundary, incomplete create, orphaned
  VM, stale ownership, retargeted deletion races, hanging inspect, retained
  resources, credential leakage, recreation, and label collisions — on both
  KVM and Apple Silicon lanes.
- Cleanup outcomes are honest in receipts: `REMOVAL_UNCERTAIN` surfaces to
  operators instead of being folded into success.
- The VM-helper identity-bound deletion fix on Main
  (`internal/applevmhelper/cli_darwin_arm64.go` @
  `669f335d…`) is reviewed in PR-05 for alignment with this decision rather
  than cherry-picked blindly.
