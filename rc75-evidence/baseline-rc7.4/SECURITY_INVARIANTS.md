# Security Invariants — NEMO-CONTROL RC7.4

The release claims the following invariants. Each lists where it is enforced and the tests that
prove it. Anything not demonstrated remains an explicit release blocker (see `KNOWN_LIMITATIONS.md`).

## I1 — An AI cannot authorize its own privileged execution

The reasoning layer (`internal/execution` capability surface, incl. `history.*`/`research.*`
advisory capabilities) can request but never sign, grant, or dispatch. Only the authority kernel
(`internal/authority`) mints grants; admission requires a signed `JobContractV2` under a configured
authority key; `research.propose`/`history.*` cannot sign contracts, dispatch jobs, or mint evidence.
Tests: `internal/execution` e2e (`TestEndToEndAuthorityRejection`, `TestEndToEndExpiredGrant`,
`TestEndToEndWrongPrincipal`), registry posture/invariant scans.

## I2 — Unauthorized operations cannot bypass the authority kernel

Every dispatch path funnels through `driveDispatch` → `AdmitJob` (signed-contract verification,
pool CAS) before any backend call; there is no alternate admission path. Alternate code paths
(reconcile, maintenance, recovery) can only re-observe or mark — never authorize a new effect.
Tests: `dispatch_matrix_test.go`, `adversarial_test.go`, admission tests.

## I3 — Ambiguous external effects are never silently retried or destroyed

Once a launch may have reached the runtime, any unverified identity → `ErrAmbiguousDispatch`
(never `destroy`, never a definitive-failure receipt). This now covers the fallback-discovery boot
mismatch, duplicate matches, probe failures, and post-admission cancellation — plus every
pre-execution destroy is ownership-gated. Unresolved rows persist as `DISPATCH_AMBIGUOUS` for
operator reconciliation; maintenance never auto-retries a non-idempotent dispatch.
Tests: `TestMSBDispatchDiscoveredBootMismatchIsAmbiguous`, `…DuplicateAdmittedJobs…`,
`…ProbeFailure…`, `…CancelledAfterAdmission…`, `TestMSBLiveSubstitutedVMIsNeverAdopted` (live).

## I4 — Recovery ownership is atomic and fenced

`ClaimRecoveryAttempt` is one conditional `UPDATE…RETURNING` in the ledger's immediate transaction:
at most one claimant per (job, action) window, monotonic ordinals, fence-epoch ownership, leased
reassignment, clock-rollback-safe. No in-memory mutex is load-bearing.
Tests: the `TestRecoveryClaim*` suite (contention, lease, epoch, rollback, independence, atomic
evidence, fail-closed) + restart-pacing tests.

## I5 — Mandatory execution decisions leave durable, verifiable evidence

Terminal transitions, adoptions, cleanup-pending marks/clears, claims, ambiguous markings,
expirations and escalations each commit their `recovery_events` record in the same transaction as
the state change — a state change that cannot be evidenced does not land. Terminal receipts are
signed and fsynced before the transition; checkpoints are atomically published.
Tests: `TestMaintenance*FailsClosedOnEvidenceFailure`, `…EscalationEvidencePrecedesThrottle`,
recovery-event durability tests, evidence-log tests.

## I6 — Released code and runtime identities are authenticated

Source: bidirectional `verify-source-manifest.sh` (works without `.git` inside an extracted
archive) + `verify-nemo-transfer.py` (frozen tree, both digests verified). Runtime:
`verify-msb-runtime-pins.sh` (doctor + version + executable + firmware digests; refuses pin
substitution; qualifying mode requires pins byte-identical to `HEAD:`). Lane images: per-lane
reviewed digests (`qualification/msb-lane-image-pins.json`), lane fails if the tag moved.
Tests: `msb-runtime-pins.test.js`, `verify-release-artifact.test.js` (36 cases),
`go-test-case-evidence.test.js` (30 cases).

## I7 — Qualification applies to the exact released source and artifacts

Evidence records bind `source_commit`, toolchain string, runner os/arch, lane identity and CI
provenance; the lane validator re-derives the normalized record from the raw stream; imported
evidence must carry this exact commit and matching `ci`; skipped/absent required tests fail the
gate. A results file is never trusted for values the stream must prove.
Tests: `go-test-case-evidence.test.js`, admission/generator script tests.

## I8 — Unproven safety requirements remain explicit blockers

Unresolved rows are never auto-resolved; the linux-kvm lane, external custody, and Crabbox remote
validation are recorded NOT_RUN/unsatisfied rather than passed. See `QUALIFICATION_REPORT.md`.
