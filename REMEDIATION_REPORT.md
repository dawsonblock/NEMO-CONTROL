# Remediation Report — NEMO-CONTROL RC7.4

Baseline `0.54.0-rc.7.3` → development candidate `0.54.0-rc.7.4-dev`.
Six confirmed defects repaired; all fixes are minimal, use the existing architecture, and are
covered by permanent regression tests.

## WP1 — Ambiguous dispatch can no longer destroy or mask an unresolved workload

`internal/sandboxexecutor/backend_msb.go`

- Fallback discovery (`exec -d` admitted, no name returned): a single discovered job whose
  `RuntimeBoot` differs from the verified launch now returns `ErrAmbiguousDispatch` with the
  discovered run identity preserved for reconciliation. The VM is never destroyed on a mismatch.
- Pre-execution destroys are ownership-gated via `destroyIfOurs`: the dispatch label
  (`crabbox.dispatch` nonce) must prove the current dispatch owns the sandbox before anything is
  removed. A substituted or foreign VM survives every failed-launch path for operator review.

Regression tests (`backend_msb_test.go`, all red→green):
- `TestMSBDispatchDiscoveredBootMismatchIsAmbiguous` — the P0 defect.
- `TestMSBDispatchDuplicateAdmittedJobsIsAmbiguous` — multiple matching records.
- `TestMSBDispatchProbeFailureIsAmbiguous` — failed job-list probe after possible admission.
- `TestMSBDispatchCancelledAfterAdmissionIsAmbiguous` — deterministic cancel on durable record
  appearance (no wall-clock guess).
- Existing `TestMSBDispatchBindsBootGeneration` (named-launch path) still passes.

## WP2 — Recovery claims are atomic, fenced, and leased

`internal/sandboxexecutor/recovery.go`, `ledger.go` (schema v9 → v10)

- `ClaimRecoveryAttempt` is now a single `INSERT … ON CONFLICT … DO UPDATE … WHERE … RETURNING`
  inside the ledger's immediate-lock transaction. The grant requires the previous attempt to be
  older than `backoff` AND the previous lease (`claim_until_ms`) expired; the row records the owning
  fence `claim_epoch`, the monotonic `attempts` ordinal, and the new lease in one statement.
- `last_attempt_ms` uses `MAX(old, new)` so a rolled-back clock cannot regress the pacing stamp.
- The claim's durable `recovery_events` record commits in the same transaction — a claim that
  cannot be evidenced is a claim that never happened (`tx.Rollback` on any failure).
- New `RecoveryClaim` value carries `Attempt`, `OwnerEpoch`, `ClaimedAt`, `LeaseUntil`.

Contention/correctness tests (`recovery_test.go`):
- `TestRecoveryClaimAtomicUnderContention` — 16 concurrent claimants: exactly one grant.
- `TestRecoveryClaimDistinctJobsAllWin` — independent claims don't contend.
- `TestRecoveryClaimLeaseBoundsReassignment` — a live lease blocks; expiry re-arms.
- `TestRecoveryClaimOwnershipFollowsTheFenceEpoch` — claims record the claiming epoch.
- `TestRecoveryClaimClockRollbackStaysClosed` — wall-clock rollback never reopens a window.
- `TestRecoveryClaimActionsAreIndependent` — (job, action) pairs are independent.
- `TestRecoveryClaimWritesItsEventAtomically` — grant and event are one commit.
- `TestRecoveryClaimFailsClosedWhenEvidenceCannotCommit` — evidence failure ⇒ no claim.
- Plus pre-existing: pacing across restart, downtime-makes-due, forget-resets, durable events,
  residue-throttle-across-reopen — all updated to the new signature and passing.

## WP3 — Mandatory audit is transactional with the state it justifies

`internal/sandboxexecutor/maintenance.go`, `ledger.go`, `server.go`

- `TransitionWithRecoveryEvent` binds the mandatory recovery record into the transition's commit.
- `AdoptBackendRun`, `MarkCleanupPending`, `ClearCleanupPending`, claim/marking/expiry paths now
  write their `recovery_events` row inside the same transaction — a state change whose mandatory
  evidence cannot commit leaves the row untouched.
- `escalateResidue` records its durable event **before** the throttle mark (a crash between them
  can no longer produce a suppressed, unaudited escalation).
- Two previously ignored `Transition` errors in `driveDispatch` are now reported.

Storage-failure tests (`maintenance_test.go`, red→green):
- `TestMaintenanceClaimFailsClosedOnEvidenceFailure`
- `TestMaintenanceMarkAmbiguousFailsClosedOnEvidenceFailure`
- `TestMaintenanceExpireFailsClosedOnEvidenceFailure`
- `TestMaintenanceEscalationEvidencePrecedesThrottle`

## WP4 — Evidence generation and verification share one lifecycle

`scripts/go-test-case-evidence.py`, `scripts/go-test-case-evidence.test.js` (new)

- One authoritative scanner + lifecycle validator backs both generation and verification.
- Generation now refuses every stream verification rejects: missing package-terminal outcome,
  un-run terminal outcome, duplicate runs/terminals, post-terminal events, illegal pause/cont,
  conflicting package identity, and a failed package laundered into per-test passes.
- 30-case adversarial corpus (`node --test scripts/go-test-case-evidence.test.js`): every malformed
  shape refused by generation AND rejected by verification; positive cases (complete pass, empty
  package) still generate and verify.

## WP5 — Artifact/source/runtime identity binding (verified existing + extended)

- `verify-msb-runtime-pins.sh`: qualifying mode refuses `MSB_PINS_FILE` substitution, requires the
  pins byte-identical to `HEAD:` when in a work tree, and checks doctor + version + executable +
  firmware digests. Covered by `msb-runtime-pins.test.js` (override refusal, substituted
  executable, forged manifest).
- `verify-release-artifact.sh`: 36 tests cover forged signatures, wrong keys, modified manifests,
  modified source, missing `.git`, replayed qualification, unsupported schema.
- `verify-source-manifest.sh`: bidirectional manifest↔source verification that works inside an
  extracted archive (no `.git` assumed) — the source-only release path.
- New: `qualification/msb-lane-image-pins.json` binds each live lane to a reviewed per-arch image
  digest (see WP6).

## WP6 — Qualification environments pin reviewed bytes

- `.github/workflows/stage-b.yml`: `postgres:16` → `postgres:16@sha256:f1c3376c…` (same reviewed
  digest as the release workflows).
- `.github/workflows/release-qualification.yml`: the live lane pulls `python:3.12` at the pinned
  per-arch digest from `qualification/msb-lane-image-pins.json` and fails if the resolved digest
  moved — the lane exercises reviewed bytes, not whatever the tag serves that run.
- `scripts/test-live-postgres.sh`: the local default is the same digest-pinned image so local and
  gate runs match.

## WP7 — Evidence custody (verified; external service remains a documented blocker)

- `SocketCustodian` + `sandbox-custodyd` + `internal/sandboxcustody`: signed, verified
  acknowledgements against configured trust roots; archive rows release only after a verified ack;
  interrupted handoffs re-witness idempotently; fail-closed without configured trust.
- Adversarial suite (`ack_verify_test.go`, `adversarial_test.go`): invalid signature, field tamper,
  substituted signer, replayed ack, self-declared signer, missing trust.
- Outstanding dependency: no third-party/external custody service is integrated; the external
  custody gate stays unsatisfied and is recorded as a release blocker.

## WP8 — One authoritative version source

`VERSION`, `worker/package.json`, `worker/package-lock.json`, `nemo/package.json`,
`nemo/package-lock.json`, `.github/workflows/release-qualification.yml` (`RELEASE_VERSION`,
`RELEASE_NAME`), `VERIFY-RELEASE.md` → `0.54.0-rc.7.4-dev`. `verify-version-consistency` passes.
Historical records (`qualification/baseline/manifest.json`, CHANGELOG release sections) are
retained and remain explicitly historical.

## Files changed

- `internal/sandboxexecutor/backend_msb.go`, `backend_msb_test.go`
- `internal/sandboxexecutor/recovery.go`, `recovery_test.go`
- `internal/sandboxexecutor/ledger.go`
- `internal/sandboxexecutor/maintenance.go`, `maintenance_test.go`
- `internal/sandboxexecutor/server.go`
- `scripts/go-test-case-evidence.py`, `scripts/go-test-case-evidence.test.js` (new)
- `scripts/test-live-postgres.sh`
- `.github/workflows/stage-b.yml`, `.github/workflows/release-qualification.yml`
- `qualification/msb-lane-image-pins.json` (new)
- `VERSION`, `worker/package*.json`, `nemo/package*.json`, `CHANGELOG.md`, `VERIFY-RELEASE.md`
