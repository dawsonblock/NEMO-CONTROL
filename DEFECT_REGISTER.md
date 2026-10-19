# Defect Register — NEMO-CONTROL RC7.4

Baseline source: `crabedence-V1-fix-integration-integrity` @ `303caba6` (version `0.54.0-rc.7.3`).
Every entry below was reproduced against that revision before repair; reproduction commands and
pre-fix behavior are recorded per defect.

# RC7.5 qualification findings (2026-10-19)

Baseline source: `NEMO-CONTROL-v0.54.0-rc7.5-development.zip`
(SHA-256 `796437dd…f6c0`, attestation-verified). Live-lane evidence under
`rc75-evidence/rc7.5-qualification/`; CI run
`https://github.com/dawsonblock/nemo-rc75-qualification/actions/runs/39186297140`
(source commit `67bacdb` on private repo `dawsonblock/nemo-rc75-qualification`).
All three entries are **OPEN** — reproduced on `ubuntu-latest` CI, none reproduced on
darwin/arm64 bare metal (M2 Pro).

## D-RC75-1 (P1) — `msb inspect` of a dead sandbox hangs on Linux; crash reconciliation can never settle DISPATCH_AMBIGUOUS

**File:** `internal/sandboxexecutor/recovery.go` reconcile path → `MSBBackend` inspect;
symptom test `crash_test.go` `TestDaemonCrashPreservesAcknowledgedJobs`.

**Defect:** after the daemon is SIGKILLed mid-dispatch, the recovered daemon calls
`msb inspect sx-crash-1` to bind the dead sandbox's boot generation. On Linux the call never
returns — it dies on the reconcile context deadline (`msb inspect sx-crash-1: context canceled`),
so the job stays `DISPATCH_AMBIGUOUS` and the registry residue ESCALATION persists. The system
fails *closed* (no blind retry, no unverified destroy), but on the linux-kvm lane a crashed
dispatch permanently strands jobs for operator reconciliation.

**Reproduction:** `go test -run TestDaemonCrashPreservesAcknowledgedJobs ./internal/sandboxexecutor/`
on `ubuntu-latest` with pinned msb 0.7.8 installed — failed identically in 3 consecutive CI
invocations (race suite twice, plain suite once; 21–61s before the context deadline). Same test on
darwin/arm64 passes in ~1.2s: `msb inspect` reports the dead sandbox absent immediately and
recovery settles `SUCCEEDED` via run `job_…`/boot binding.

## D-RC75-2 (P2) — Ambiguous dispatch not observable before terminal resolution on Linux

**File:** `internal/sandboxexecutor/maintenance.go` scan ordering vs
`maintenance_test.go:366` `TestMaintenanceAmbiguousDispatchReconcilesNotRetries` (stub backend).

**Defect:** the test injects an ambiguous dispatch and expects the ledger to record
`DISPATCH_AMBIGUOUS`; on the CI runner the stub backend completed the run first — the job
transitioned `UNCERTAIN`-class dispatch straight to `SUCCEEDED` and the ambiguous state was never
observed (`job amb-1 never reached [DISPATCH_AMBIGUOUS] — state SUCCEEDED`). Either the
maintenance scan reads the ledger before the ambiguity transition commits, or the test's ordering
assumption does not hold under Linux scheduler timing.

**Reproduction:** `go test -run TestMaintenanceAmbiguousDispatchReconcilesNotRetries
./internal/sandboxexecutor/` on `ubuntu-latest` — failed in both CI invocations (15.1s, 15.0s).
Passes on darwin/arm64 in 0.06s.

## D-RC75-3 (P1) — Apple lane runner mapping targets a runner that cannot boot microVMs

**File:** `.github/workflows/release-qualification.yml`, lane-matrix runner selection
(`apple-hypervisor-framework → macos-15`).

**Defect:** GitHub-hosted `macos-15` runners are themselves virtualized; `msb` installs and
`doctor` reports ready, but `msb create` fails at `build_vm: VM enter: build_microvm:
Internal(Vm(VmSetup(VmCreate)))` — every `TestMSBLive*` case failed. The workflow comment already
notes the intended Blacksmith (bare-metal Mac) label "does not resolve here", so the fallback
runner is a lane that cannot ever pass. A push-triggered run claiming `apple-hypervisor-framework`
fails release admission on hosted CI by construction; lane evidence must come from bare-metal
Apple Silicon (local run or self-hosted runner).

**Reproduction:** run `39186297140`, job `Live microVM (apple-hypervisor-framework)`, failed
identically in both invocations; the same suite passes on the M2 Pro host (13/13, log in
`rc75-evidence/rc7.5-qualification/apple-hypervisor-framework/local-m2pro-test.log`).

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
