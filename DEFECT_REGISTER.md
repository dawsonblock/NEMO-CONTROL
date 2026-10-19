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

---

# External audit merge — verified 2026-10-19 against the shipped archive

Independent second-pass audit of the same archive (SHA `796437dd…f6c0`). Each claim below was
re-verified against the extracted source before registration — several were confirmed by live
reproduction, not reading alone. D-RC75-1 and D-RC75-2 above carry the audit's root-cause
refinements in-line.

## D-RC75-1 addendum — root cause confirmed in code

`reconcileOne` (server.go:452) extends the durable claim by `ReconcileTimeout + 1m` (≈90s at the
30s default) before issuing work. On CI, the first daemon's shutdown context cancelled the
in-flight `msb inspect`; the replacement daemon then could not reclaim the row — a fresh epoch's
`ClaimRecoveryAttempt` requires `claim_until_ms <= now` (recovery.go:126), so the dead claimant's
durable lease (~90s) blocks takeover far past the test's 20s settlement window. A crash inside the
extended observation window is a progress failure with no bound: epoch-aware takeover must wait on
verified prior-owner shutdown, not lease expiry alone.

## D-RC75-4 (P0) — Dispatch refusal discards the uncertain cleanup obligation

**Files:** `internal/sandboxexecutor/backend_msb.go:766–807`, `:900–915` (`destroyDispatch`),
`server.go` dispatch-failure path.

**Defect (confirmed in source):** when `msb create` fails after partial effect, the backend calls
`destroyDispatch(nonce)` — best-effort by design ("Failures are ignored by design",
`_, _ = b.runOnce(...)`) — then returns `ErrDispatchRefused` with an **empty `RunIdentity`**. The
server records `DISPATCH_FAILED` and issues a `NO_EFFECT` receipt even though nothing proves the
VM is gone: the removal result is never observed and no durable cleanup obligation is recorded.
The context-canceled path one case up (line 772) does preserve the identity and returns
`ErrAmbiguousDispatch` — the plain-failure path does not, which is the asymmetry.

**Fix:** preserve the prepared dispatch identity on create-failure and record a durable cleanup
obligation whenever VM creation may have had an effect; never terminalize resource cleanup on
best-effort removal.

## D-RC75-5 (P0) — Identity-conditioned destroy is non-atomic across the CLI's resolve→delete window

**File:** `internal/sandboxexecutor/backend_msb.go:1393–1508` (`Cleanup`).

**Defect (confirmed in source):** removal is `msb rm -f --label crabedence.dispatch=<nonce>` —
the CLI resolves labels to names and then deletes. The code's own comment bounds the residual
window on "msb's own transition guard", but a fake-runtime test cannot prove the real runtime
never deletes a substituted instance inside that window: the label check and the destroy are not
one runtime operation.

**Fix:** deletion through an identity-aware operation in the native runtime SDK (single fused
identify+remove), exercised against the real backend with concurrent substitution and stale
cleanup on both lanes.

## D-RC75-6 (P1) — Retained sandbox is reported as verified-absent

**File:** `internal/sandboxexecutor/backend_msb.go:1394–1397`.

**Defect (confirmed in source):** with `KeepSandboxes` set, `Cleanup` returns
`CleanupAlreadyAbsentVerified` for a sandbox that is intentionally retained — i.e., still exists.
A result named "absent verified" satisfies a predicate the retained instance does not meet;
retention must not satisfy absence accounting.

**Fix:** a distinct `RETAINED_BY_POLICY` classification, tracked separately from
`REMOVED_VERIFIED` / `ALREADY_ABSENT_VERIFIED`.

## D-RC75-7 (P1) — Post-cleanup verification runs unbounded

**File:** `internal/sandboxexecutor/backend_msb.go:1471,1475` (`postCleanupVerify`).

**Defect (confirmed in source):** both call sites pass `context.WithoutCancel(ctx)` with no fresh
deadline — a hung `msb inspect` blocks cleanup accounting indefinitely. The same file already uses
the correct pattern for the image lookup (`context.WithTimeout(context.WithoutCancel(ctx), 15s)`,
line 233); it was not applied here.

**Fix:** bounded verification context; deadline expiry records `REMOVAL_UNCERTAIN`.

## D-RC75-8 (P1) — Custody recording boundary performs no cryptographic verification

**File:** `internal/sandboxexecutor/custody_outbox.go:137–181` (`DrainRecoveryCustody`).

**Defect (confirmed in source):** the drain records whatever `RecoveryCustodian.
WitnessRecoveryCheckpoint` returns after only monotonic-sequence checks. `SocketCustodian`
verifies its signed ack internally (refuses when trust is unconfigured) — but that is
adapter-level defense. Any other implementation can return a fabricated ack and the drain records
it as verified custody.

**Fix:** verify the acknowledgement cryptographically at the recording boundary; adapter checks
are additive, never the sole enforcement point.

## D-RC75-9 (P1) — Release verifier never binds the embedded manifest — reproduced

**File:** `scripts/verify-rc75-release.py:327–435` (`cmd_verify`).

**Defect (reproduced 2026-10-19):** `verify` checks the *external* `--manifest` against the
attestation and the extracted tree against the external manifest — but never compares the
**embedded** `release-evidence/rc75-source-manifest.json` against either. Reproduction: copied the
real archive, set the embedded manifest's `root_hash` to 64 zeros, regenerated the external
manifest and attestation sidecar — `verify` printed `verified: tampered.zip` and exited 0.
A package whose embedded manifest asserts a fabricated root hash is "verified".

**Fix:** parse the embedded manifest during verification; require its `root_hash`, `version`, and
`entry_count` to equal the external manifest's, and require a trusted signature over the release
identity — the attestation is currently a JSON sidecar, so an attacker controlling archive +
sidecar can construct self-consistent hashes.

## D-RC75-10 (P2) — Release records disagree about what was shipped

**Files:** `docs/qualification/RC75_QUALIFICATION_REPORT.md` (inside the rc7.5 archive) cites
archive SHA `6001dd98…` — not the shipped `796437dd…`; the report's live lanes read NOT_RUN while
run-39186297140 evidence exists; bundle `RELEASE_MANIFEST.json` still targets `0.54.0-rc.7.4-dev`.

**Defect:** not proven tampering — proven that artifact identity, platform evidence, and
qualification status were never reconciled into one authoritative record for the shipped bytes.

**Fix:** regenerate the qualification report and release manifest against the exact shipped
archive digest; bind per-lane evidence (logs/artifacts) to the same commit.

---

## D-RC75-11 (P1) — Development zip drops symlinks; extracted tree cannot match declared provenance

**Files:** `NEMO-CONTROL-v0.54.0-rc7.5-development.zip` (the shipped `796437dd…` archive).

**Defect:** the archive's `runtimes/nemo-relay` entries contain zero symlink entries — the
packaging step neither preserved nor dereferenced the runtime's 10 declared symlinks
(5× `crates/*/LICENSE`, `.claude/skills`, `CLAUDE.md`, `integrations/pi/{package.json,index.ts,src}`),
it dropped them. Any tree extracted from the zip recomputes `shipped_tree_sha256 = 6b4ccaa7…`
against the declared `f6229bb3…` with `symlink_count` 0 vs 10, so the
`nemo-transfer-provenance` mandatory gate fails on the shipped bytes themselves (observed on
run 39221954134: 33/34 gates pass, this gate FAIL). The authoritative repo tree and the frozen
reference both carry the symlinks — the defect is in archive production, not the source.

**Impact:** a consumer verifying the shipped artifact against its own declared manifest gets a
provenance failure indistinguishable from tampering; qualification of the extracted tree is
impossible without repairing transport loss out-of-band.

**Fix:** restore the 10 symlinks (done on `fix/rc7.6-defect-repair` @ `1d9536e`, verified locally:
`verify-nemo-provenance.sh --require-source` recomputes `f6229bb3` and the typed delta is
exhaustive); longer-term, produce the development zip with symlink-preserving packaging so the
shipped artifact is self-verifying.

---

# RC7.6 repair status (branch `fix/rc7.6-defect-repair`, over RC7.5 baseline `67bacdb3`)

Repairs implemented in the extracted RC7.5 source tree; `main` remains the frozen RC7.5
baseline. Each fix is verified by the package test suite (fake-runtime model plus
real-daemon crash tests, `-race`, 754.8s) and by both live lanes against real `msb 0.7.8`:
apple-hypervisor-framework on bare-metal M2 Pro (`-race`, qualifying, PASS 14 / SKIP 1 /
FAIL 0) and linux-kvm on CI (PASS 15/15, runs 39228255743 + 39235314309). The full
admission workflow passed end-to-end on `6ceabf8` (run 39235314309: 34/34 mandatory
gates, `artifact_promotable: true` for the claimed linux-kvm lane). Evidence:
`rc75-evidence/rc7.6-repairs/`.

| Defect | Status on `fix/rc7.6-defect-repair` | Mechanism |
|---|---|---|
| D-RC75-1 | **Repaired** | `ClaimRecoveryAttempt` reclaims a row whose `claim_epoch` predates the live epoch — the flock the new epoch holds proves the claimant dead; its outstanding lease is residue. Backoff still paces. `TestDaemonCrashPreservesAcknowledgedJobs` settles <1s (was >20s timeout on Linux CI); `TestRecoveryClaimDeadEpochLeaseDoesNotBlockTakeover` added. |
| D-RC75-2 | **Repaired** | Ambiguous-dispatch test holds the stub backend's `Wait` behind an explicit gate and counts dispatches; ambiguity asserted under synchronization, `Resume`-only reconciliation verified. |
| D-RC75-3 | Open (by design) | CI lane mapping — hosted `macos-15` cannot boot microVMs; Apple lane remains bare-metal only. Not a code defect. |
| D-RC75-4 | **Repaired** | Refused/uncertain creates run the real identity-bound `Cleanup`; unproven absence upgrades the refusal to `ErrAmbiguousDispatch` carrying the full dispatch identity — the cleanup obligation is durable. |
| D-RC75-5 | **Repaired (CLI-bound)** | Handles are nonce-bound (`sx-<job>-<nonce>`); `msb rm <handle>` deletes by unforgeable name — the resolve→delete window can only resolve this dispatch's record. Residual: runtime-internal catalog swap under an occupied name requires the nonce (never leaves dispatch identity); a native catalog-locked conditional delete remains the documented upgrade path. |
| D-RC75-6 | **Repaired** | `RETAINED_BY_POLICY` discharges the cleanup obligation without claiming absence; `ProvesAbsent()` unchanged; `DischargesCleanup()` added for obligation accounting. |
| D-RC75-7 | **Repaired** | `postCleanupCtx` = `WithTimeout(WithoutCancel(ctx), 15s)` at all post-removal verification sites; expiry → `REMOVAL_UNCERTAIN`. |
| D-RC75-8 | **Repaired** | Generic custody boundaries (recovery drain + archive `completeCustodial`) verify the ack's signature, signer trust root, sequence, payload digest and segment binding before recording; unsigned/forged acks rejected at the boundary, covered by a dedicated negative test. |
| D-RC75-9 | **Repaired** | Verifier extracts the embedded `release-evidence/rc75-source-manifest.json` and compares schema/version, `entry_count`, `root_hash` and the full entry list to the attested external manifest. Tampered package (zeroed embedded `root_hash`, regenerated sidecars) now fails exit 1; the real archive still verifies exit 0. The trusted-signature gap remains a design limitation — the attestation is a JSON sidecar, not a signature. |
| D-RC75-10 | **Repaired** | In-archive report's stale `6001dd98…` cite corrected to `796437dd…` with the external attestation named as the authoritative binding; `RELEASE_MANIFEST.json` regenerated for the shipped RC7.5 artifact (was RC7.4). |
| D-RC75-11 | **Repaired (tree)** | The 10 dropped symlinks restored on `fix/rc7.6-defect-repair` @ `1d9536e` — `verify-nemo-provenance.sh --require-source` recomputes declared `f6229bb3` and the typed delta is exhaustive. Residual: the zip production step still drops symlinks — a future archive must be produced with symlink-preserving packaging. |
| CI-evidence-timeout | **Repaired** | `release-qualification.yml` evidence job `timeout-minutes` 30 → 60 @ `6563a6c`: the step re-runs the heavyweight gates (~15min sandboxexecutor race alone) and was cancelled at 29m11s on run 39216619316, making admission unreachable on a green run. |

**Residual release blockers (not closed by repairs):** trusted release signature (the attestation
is hash-binding, not signing); independently controlled external custodian still NOT_RUN;
hosted-macOS lane cannot boot microVMs, so apple CI evidence remains bare-metal only and the
green admission run claimed only linux-kvm; the shipped zip still drops `nemo-relay` symlinks
(D-RC75-11) — tree repaired, archive-production repair outstanding. No production claim.

**Transplant note (2026-10-19):** the same repairs are applied to this repo on
`fix/rc7.6-defect-repair` @ `a86854b1` — the repair-branch file contents were verified
byte-identical against `nemo-rc75-qualification` `1b73f626`/`6563a6c4`/`6ceabf8e` before
commit (the nemo-relay symlink entries were already preserved as git links here, so
`1d9536ea` needed no action). Local verification: `go build` + `go vet` clean under
go1.27.2 (the pinned toolchain is go1.26.5 — re-verify under the pin before citing),
targeted `internal/sandboxexecutor` tests PASS under `-race` (186s).

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
