# RC8.3 Security Invariants

1. **No destructive action against an unverified occupant.** Inspect
   timeout, transport error, malformed response, missing/invalid
   labels, invalid namespace, or unproven runtime-ownership posture
   all refuse before `rm` — the obligation stays pending.
   (INV-CLEANUP-01)
2. **Verified absence is distinguished from unknown.** Positive
   not-found → `ALREADY_ABSENT_VERIFIED`; post-removal absence →
   `REMOVED_VERIFIED`; unreachable inspect → `IDENTITY_UNVERIFIABLE`;
   removal issued but unverifiable → `REMOVAL_UNCERTAIN`. Never
   coerced.
3. **High assurance requires exclusive runtime ownership.** A
   dedicated owner-only `MSB_HOME` catalog + validated namespace,
   re-verified per destructive admission and at dispatch. Shared or
   empty namespace is `UNSUPPORTED` — naming conventions alone never
   qualify. No atomic CAS delete exists in msb 0.7.8 and none is
   faked.
4. **Custody repair is authenticated and audited.** Actor + non-empty
   reason + full seq-0 rescan + verified drain + fresh readiness +
   zero backlog before `REPAIR_REQUIRED` clears; the audit note binds
   actor, reason and verification durably. Read-only vs mutating ops
   are distinct permissions (signer required to mutate).
5. **Failures invalidate readiness immediately.** The newest
   completed drain decides — a prior success inside the TTL never
   masks a current failure; drain passes are serialized so stale
   results cannot overwrite newer failures.
6. **Custody work is bounded.** Incremental reconcile scans pages of
   256 beyond the durable HWM via the `terminal_seq` index — O(new
   rows), not O(history). HWM never advances over gaps,
   contradictions, or uncovered rows.
7. **History is append-only.** Legacy rows are classified and
   journaled, never silently rewritten or blessed; acknowledged rows'
   bytes are evidence and are never modified; compensation only
   touches unacknowledged pending obligations and preserves sequence
   + chain linkage.
8. **Provenance has one authority.** The embedded
   `release-evidence/source-tree-sha256.txt` is the signed inventory;
   verification requires operator-pinned signers — the bundle never
   supplies its own production trust root.
9. **Admission stays fail-closed.** REPAIR_REQUIRED, DEGRADED,
   UNVERIFIED_STARTUP, and migration-pending all deny CRITICAL
   admission; a passing unit test is not an independently qualified
   lane.
10. **A checkpoint is a state, not a barrier.** A signed custody head
    proves the witness's state at one instant and nothing about what is
    in flight. A rewrite of durable evidence therefore requires a
    signed, open migration epoch: the custodian freezes the deployment
    at the head the operator observed — admitted only if that head is
    still current, atomically — and refuses every submission until the
    epoch closes. (INV-FENCE-01)
11. **The epoch is verified where the rewrite happens.** The migration
    library verifies the fence receipt itself under the pinned
    custodian set, requires it to be OPEN and bound to the run's grant,
    and binds it into the signed proof and journal. A caller's
    verification is never accepted as the library's own.
    (INV-FENCE-02)
12. **An epoch is durable, not leased.** A witness restart leaves the
    epoch open; a kernel crash leaves the custodian frozen; an abort is
    refused if custody advanced inside the window. Recovery is an
    explicit operator act, never an expiry. (INV-FENCE-03)
13. **One key, one authority.** Custodian, kernel-relay and
    repair-authority keys resolve from three separately pinned files,
    each of which may name only its own role, and no key may be pinned
    under two authorities. The authority that attests custody is never
    the authority whose records it attests. (INV-TRUST-01)
14. **A proof describes the rewrite it performed.** The signed
    migration proof binds action, row, execution, terminal receipt,
    before/after envelope hashes and the frozen epoch, and verification
    re-derives both suffix digests from the proof's own rows. A proof
    that verifies under the right key but describes a different rewrite
    is not evidence. (INV-PROOF-01)
