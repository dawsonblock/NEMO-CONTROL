# Defect Register — NEMO-CONTROL RC7.4

Baseline source: `crabedence-V1-fix-integration-integrity` @ `303caba6` (version `0.54.0-rc.7.3`).
Every entry below was reproduced against that revision before repair; reproduction commands and
pre-fix behavior are recorded per defect.

## D-RC74-1 (P0, WP1) — Fallback-discovered boot mismatch destroyed the VM and reported a definitive failure

**File:** `internal/sandboxexecutor/backend_msb.go`, fallback discovery path of `MSBBackend.Dispatch()`.

**Defect:** When `msb exec -d` admitted the job but returned no name, dispatch fell back to
`listJobs`. On a single discovered match whose `RuntimeBoot` differed from the verified boot, the
code executed `b.destroy(name)` and returned a plain (non-ambiguous) error — destroying a VM whose
workload state was never proven and classifying an unresolved external effect as a clean failure.

**Reproduction:** fake runtime with `MSB_FAKE_LAUNCH_FAIL_ADMITTED=1` + `MSB_FAKE_JOB_BOOT_MISMATCH`.
Pre-fix output: `the sandbox records job <id> under boot generation <a> not the verified <b>` and the
sandbox file was deleted. Test: `TestMSBDispatchDiscoveredBootMismatchIsAmbiguous` (added,
red before fix / green after).

**Fix:** the mismatch now preserves the discovered run identity on the dispatch result, returns
`ErrAmbiguousDispatch`, and never calls destroy; regression tests also cover duplicate admitted
records, job-list probe failure, and cancellation after admission.

## D-RC74-2 (P0, WP1) — Pre-execution destroy lacked an ownership check

**File:** `internal/sandboxexecutor/backend_msb.go`.

**Defect:** Pre-exec failure paths (unverifiable inspect/launch errors before `exec` ran) called
`b.destroy(name)` on the expected handle without proving the sandbox at that name belonged to this
dispatch — a substituted or foreign VM under the deterministic handle was destroyed on a transient
probe failure.

**Reproduction:** cancel-deadline fired during fake `inspect` under `-race` (slower child boot),
hitting the unverified destroy path; deterministic tests confirm the foreign sandbox survives.

**Fix:** all pre-execution destroys now go through `destroyIfOurs`, which verifies the dispatch
ownership label (`crabbox.dispatch` nonce) before removing anything.

## D-RC74-3 (P1, WP2) — Recovery claims were a non-atomic SELECT→check→UPSERT

**File:** `internal/sandboxexecutor/recovery.go` `ClaimRecoveryAttempt`.

**Defect:** a `QueryRow` read of `recovery_attempts` followed by a separate `Exec` UPSERT let
concurrent claimants interleave between the check and the write.

**Reproduction:** scratch test with 16 concurrent claimants on one (job, action): **all 16 received
the claim with identical ordinal 1.** Test: `TestRecoveryClaimAtomicUnderContention`.

**Fix:** the claim is now one SQLite `UPDATE … RETURNING` inside the ledger's fenced transaction:
the attempt row's ordinal, lease, owner and fence epoch are decided and recorded in a single
statement, and the durable `recovery_events` record commits in the same transaction — a claim
without its evidence is impossible, and a failed evidence write rolls the claim back.

## D-RC74-4 (P1, WP3) — Mandatory audit writes were best-effort siblings of state changes

**Files:** `internal/sandboxexecutor/maintenance.go`, `ledger.go`, `server.go`.

**Defect:** `recordRecovery()` treated every recovery/audit event as advisory telemetry: the durable
state change committed even when the event write failed. Ambiguous markings, contract expirations,
residue escalations and terminal transitions could land with no corresponding durable record.
Additionally, residue escalation wrote its throttle marker before its evidence event (a crash in
between produced a suppressed, unaudited escalation), and `driveDispatch` ignored two `Transition`
errors outright.

**Fix:** mandatory events now commit inside the same ledger transaction as the state change they
justify (`TransitionWithRecoveryEvent`, event-bound `AdoptBackendRun`, `MarkCleanupPending`,
`ClearCleanupPending`, claim/marking/expiry paths); escalation records the event before the throttle
mark; ignored transition errors are reported.

## D-RC74-5 (P1, WP4) — Case-evidence generation lacked verification's lifecycle checks

**File:** `scripts/go-test-case-evidence.py`.

**Defect:** generation (`parse_stream`) rejected only per-test scan findings; the package-terminal
completeness check lived exclusively in `verify_stream`. A truncated stream (test `pass`, no
package-level terminal event) generated a normalized evidence record that `--verify` then rejected —
the exact asymmetry the baseline audit reported.

**Reproduction:** synthetic stream `{start, run, pass(test)}` with no package terminal: generation
exited 0, verification refused.

**Fix:** one authoritative scanner + lifecycle validator shared by both modes; generation now
refuses every lifecycle violation verification rejects, with an adversarial corpus
(`go-test-case-evidence.test.js`, 30 cases) pinning each rejection in both modes.

## D-RC74-6 (P1, WP6) — Mutable qualification images

**Files:** `.github/workflows/stage-b.yml`, `.github/workflows/release-qualification.yml`,
`scripts/test-live-postgres.sh`.

**Defect:** `stage-b.yml` ran `postgres:16` by mutable tag (the release workflows already pinned by
digest); the live-microVM lane pulled `python:3.12` by mutable tag and qualified whatever digest the
tag resolved to that run; the local live-postgres helper defaulted to the mutable tag.

**Fix:** `stage-b` pins `postgres:16@sha256:f1c3376c…` (same reviewed digest as the release
workflows); each lane now pulls the per-architecture reviewed digest from the new
`qualification/msb-lane-image-pins.json` and fails if the tag's resolved digest moved; the local
helper defaults to the pinned image so local results match the gate.

## Not defects (verified during inspection)

- **Named-launch boot mismatch** was already correctly ambiguous pre-change; only the fallback path
  was defective (regression coverage for the fallback path added).
- **Custody acknowledgements** are signed, verified against configured trust roots, persisted before
  operational rows release, and re-witnessed idempotently — no self-declared custody.
- **Evidence receipts** are signed and fsynced before terminal ledger transitions; checkpoints are
  atomically published and sequenced.
