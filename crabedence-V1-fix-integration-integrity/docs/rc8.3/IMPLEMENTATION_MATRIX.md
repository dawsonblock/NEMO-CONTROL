# RC8.3 Implementation Matrix

| PR | Requirement | Implementation | Key files |
|---|---|---|---|
| PR-01 | Fail-closed deletion | Unclassifiable inspect → `IDENTITY_UNVERIFIABLE`, no `rm`; posture gate on Cleanup+Dispatch; invalid-namespace refuse | `internal/sandboxexecutor/backend_msb.go`, `cmd/sandbox-executord/main.go` (`-msb-home`, `-assurance-profile`, `SANDBOX_EXECUTOR_MSB_HOME`/`SANDBOX_EXECUTOR_ASSURANCE_PROFILE`) |
| PR-01 | HA exclusivity | `DeploymentPosture()`: non-empty validated namespace + dedicated owner-only (0700, euid-owned) `MSB_HOME`; `MSB_HOME` env pinned per msb call; posture re-verified per admission + fatal at `-assurance-profile=high-assurance` startup | `backend_msb.go` `DeploymentPosture`, `requireCleanupPosture`, `runOnce` env pin |
| PR-01 | TOCTOU honesty | Inspect-then-delete documented as non-atomic; post-removal verify classifies absence/foreign-occupant/uncertain; runtime-internal substitution residual documented as requiring catalog exclusivity | `postCleanupVerify`, `docs/rc8.3/THREAT_MODEL.md` |
| PR-02 | Operator lifecycle | `cmd/custodyctl`: status/inspect/preflight (read-only), migrate/rescan/repair (mutating: `-signer-key` + `-actor`; repair also `-reason`) | `cmd/custodyctl/main.go` |
| PR-02 | Full-rescan repair | `SetFullRescanScanner` → `CustodyObligationRescan` (seq 0); `OperatorRepair` requires actor+reason, REPAIR_REQUIRED open, full rescan, verified drain, fresh readiness, zero backlog, no degraded marker | `internal/witness/sender.go`, `internal/execution/serve.go` |
| PR-02 | Durable audit | Repair note `actor=… reason=… full-rescan=verified` into `ClearRepairRequired` → `custody_events`; migration journal for legacy transitions | `outbox.go`, `migration.go` |
| PR-03 | Legacy migration | `LegacyRows` classify (acked/unacked); `CompensateLegacyRow` rebuilds unacked rows in place (same seq/epoch/prev-hash, re-signed); `JournalLegacyWitnessed`/`JournalUnverifiable`; `custody_migration_journal` table; reconcile consults `LegacyJournalAction` | `internal/witness/migration.go`, `custody_reconcile.go` |
| PR-04 | Readiness invalidation | `passGen`/`verifyGen` + `drainMu`: newest completed pass decides; serialized drains; `readinessFresh` for repair | `sender.go` |
| PR-05 | Bounded reconcile | `EffectStore.TerminalEvidenceAfter` both engines; NULL-seq rows still fail closed; page size 256; per-page covered-prefix HWM advance; ctx-cancelable | `evidence_verify.go`, `effectstore.go`, `custody_reconcile.go` |
| PR-06 | Provenance contract | `PROVENANCE_CONTRACT.md`; legacy verifier fails fast with pointer; RC8.2 bytes untouched | `docs/rc8.3/PROVENANCE_CONTRACT.md`, `verify-rc75-release.py` |
| PR-07 | Qualification | Local unit lanes run; independent witness/HVF/KVM lanes BLOCKED — see `RELEASE_READINESS.md` | `qualification/rc8.3-*.json` |
