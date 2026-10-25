# RC8.3 Defect Register

| # | Defect | Status | Source / test reference |
|---|---|---|---|
| D-01 | `MSBBackend.Cleanup` issued `msb rm -f` when pre-deletion inspection could not classify the occupant | **CLOSED** | `internal/sandboxexecutor/backend_msb.go` — unclassifiable inspect now returns `IDENTITY_UNVERIFIABLE` before any `rm`; `cleanup_failclosed_test.go::TestCleanupUnverifiedInspectNeverRemoves` proves the rm counter is 0 and the occupant survives |
| D-02 | Legacy empty custody payloads wedge upgrades into unrecoverable REPAIR_REQUIRED | **CLOSED** | `internal/witness/migration.go` (classify/compensate/journal) + `custody_reconcile.go` journal consult + `custodyctl preflight|migrate` |
| D-03 | `OperatorRepair`/`CustodyObligationRescan` unreachable; repair called ordinary drain only | **CLOSED** | `cmd/custodyctl/main.go` ships status/inspect/preflight/migrate/rescan/repair; `sender.OperatorRepair(ctx, actor, reason)` requires authenticated actor + reason + full seq-0 rescan + verified drain + fresh readiness before clearing; `custody_state_test.go::TestCustodyRepairRequiredStickyUntilOperatorRepair` covers refusals |
| D-04 | `CustodyState` could report HEALTHY after a fresh failed check inside the readiness TTL | **CLOSED** | `sender.go` generation-scoped readiness (`passGen`/`verifyGen`); `TestCustodyFailedProbeImmediatelyDegrades` |
| D-05 | `reconcileCustodyObligations` enumerated total terminal history per drain | **CLOSED** | `EffectStore.TerminalEvidenceAfter(afterSeq, limit)` (SQLite+PG, terminal_seq unique index), `custody_reconcile.go` paged loop (256/page), per-page HWM advance; `TerminalEvidence` retained for forensic rescan |
| D-06 | Ambiguous release provenance: embedded text inventory vs JSON sidecar | **CLOSED** | `docs/rc8.3/PROVENANCE_CONTRACT.md`; `verify-rc75-release.py` fails fast with actionable error on RC8 schemas; tamper coverage mapped |
| D-07 | High-assurance namespace exclusivity unproven (naming only) | **CLOSED** | `MSBBackend.MSBHome` + `HighAssurance` + `DeploymentPosture()`: dedicated owner-only `MSB_HOME` catalog + exclusive namespace enforced at startup, per-Dispatch and per-Cleanup; `TestHighAssurance*` suite; shared namespace remains UNSUPPORTED |
| D-08 | G8 independent end-to-end + real-hypervisor qualification unexecuted | **BLOCKED** | See `RELEASE_READINESS.md` — unit lanes run; Apple HVF/Linux KVM/independent-witness lanes not executed in this environment |
| D-09 | Shared-namespace high-assurance cleanup without atomic identity-conditioned delete | **UNSUPPORTED/BLOCKED** | msb 0.7.8 offers no CAS delete; high-assurance requires the exclusive-catalog posture; shared/empty namespace denied by `requireCleanupPosture` |

## Integrity-closure addendum (branch `codex/rc8.3-integrity-closure`)

The RC8.3-dev closures for D-02 and D-03 were incomplete and are superseded by
the stricter register in
`qualification/rc8.3-integrity/defect-closure.json`:

- **D-02 (superseded by RC83-IC-01..07).** `custody_reconcile.go` treated *any*
  non-empty migration-journal action as coverage, including
  `unverifiable-legacy`; `LegacyJournalAction` swallowed database errors;
  compensation rewrote the target envelope hash without re-linking successors;
  and migration had no preflight for witnessed or checkpointed suffixes.
  Coverage is now a typed, independently verified verdict, and migration is an
  atomic, authorized, chain-consistent suffix rewrite.
- **D-03 (superseded by RC83-IC-08..11).** `OperatorRepair` proceeded with no
  full-history scanner and treated a caller-supplied actor string as
  authentication. Repair now requires an installed full-history scanner, a
  detached grant signed by a separately pinned repair-authority key, a
  single-use nonce, a verified drain, and a compare-and-swap marker clear.
- **D-01/D-07/D-09 addendum (RC83-IC-14..17).** The fail-closed deletion and
  exclusive-catalog posture are preserved, and extended with symlink/ancestor
  checks, catalog dev/inode re-verification, a second pre-delete inspection,
  and durable cleanup intents. Shared-runtime high assurance remains
  UNSUPPORTED; the inspect-then-delete residual is documented.
