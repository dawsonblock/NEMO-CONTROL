# RC8.2 Security-Invariant Verification Report

Candidate: commit `32654cedd2699d27e23314ec3a91309ff71229ad`,
branch `codex/rc8.2-security-qualification`, artifact sha256
`57f4f6a6555edbc89a0c32a89240b1d6ed3fb25a1af6340e349413b2ef543fcc`.

| INV | Property | Implementation (PR) | Verification | Status |
|---|---|---|---|---|
| INV-01 | No external mutation without valid kernel authorization | Control-gate probe + admission checks (`internal/execution`) | g2-authority-abi suite + `TestControlGateProbe*` broadcast/fail-closed cases; `TestINV001*`/`TestINV003*` | **VERIFIED** (race) |
| INV-02 | Revoked authority cannot authorize new effects | Revocation checks in admission + ledger | g2 suite revocation/halt cases | **VERIFIED** (race) |
| INV-03 | Retried requests cannot duplicate effects | `internal/idempotency` durable ledger | idempotency suite + crash-recovery matrices | **VERIFIED** (race) |
| INV-04 | UNKNOWN is never silently FAILED/retried | UNKNOWN reconciliation worker | reconcile suite + ambiguous-wait cases | **VERIFIED** (race) |
| INV-05 | Every committed terminal effect has durable custody obligation | `witness.Outbox` obligations + terminal replay scanner + high-water mark (PR-10) | `TestObligationReplay*`, `TestCustodyObligation*`, crash/restart injection | **VERIFIED** (race) |
| INV-06 | Missing evidence never presented as healthy custody | Durable `degraded_reason`/`repair_reason`, empty-payload refusal, sticky contradiction (PR-10) | `TestCustodyDegraded*`, `TestCustodyRepairRequired*`, `TestCustodyEmptyPayload*` | **VERIFIED** (race) |
| INV-07 | No CRITICAL admission before verified witness readiness | `UNVERIFIED_STARTUP` + signed-checkpoint readiness + freshness TTL + fail-closed gate (PR-10) | `TestCustodyStartup*`, `TestCustodyGate*`, stale/offline/wrong-identity cases | **VERIFIED** (race) |
| INV-08 | Production receipts bind exact release + policy identity | Signed `release-manifest-v1` (Ed25519, allowed-signers) bound into custody envelopes (PR-10) | `TestReleaseManifest*` rejection matrix; signed artifact attestation `rc8-release` | **VERIFIED** (tests + signed artifact) |
| INV-09 | Cleanup cannot claim safe deletion without identity-safe removal | Exclusive-namespace enforcement + honest `REMOVAL_UNCERTAIN`; no atomicity claimed (PR-11) | `TestNamespace*`, G5 adversarial suite, msb v0.7.8 inventory | **VERIFIED — LIMITED**: exclusive-namespace deployments only; shared ns NO-GO |
| INV-10 | Only the exact tested artifact inherits qualification | Deterministic packaging (byte-identical rebuild), commit-bound evidence records, inventory digest pin `b3cf71c5…` | `package-source-archive.sh` double-build + extraction verify; g7 emit+verify | **VERIFIED** (reproducible) |
| INV-11 | AI-generated changes do not bypass independent evaluation | Trust/research gates (g1, g6); this release's own evidence is machine-verified, not self-attested | g1/g6 suites; evidence-verify passes on emitted records | **VERIFIED** |

## Honest boundary

"VERIFIED" above means: the invariant's implementation is present and
its test matrix passes under the pinned toolchain on this commit. It
does NOT mean production qualification — the live lanes (external
witness host, hypervisor lanes, signed-deployment end-to-end) remain
open in the release-readiness gate table.
