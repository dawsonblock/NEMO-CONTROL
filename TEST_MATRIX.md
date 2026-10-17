# Test Matrix — NEMO-CONTROL RC7.4

Host: macOS arm64 (Apple Silicon), `go1.26.5`, node `v24.16.0`, python `3.12.0`, msb `0.7.8`
(pin-verified, doctor-healthy). Status legend: PASS / FAIL / NOT_RUN (never counted as pass).

## Unit / race / concurrency

| Suite | Command | Result |
|---|---|---|
| Whole repo | `go test -race -timeout=20m ./...` | **PASS** — all packages; cli 1122s, sandboxexecutor 633s |
| `internal/sandboxexecutor` | `go test -race -timeout=20m ./internal/sandboxexecutor/` | PASS (~605s baseline; re-run after changes) |
| Build | `go build -trimpath -o bin/crabbox ./cmd/crabbox` | PASS |
| Vet | `go vet ./...` | PASS |

## WP-targeted regression (all red→green where they pin a defect)

| Defect | Tests |
|---|---|
| D-RC74-1/2 | `TestMSBDispatchDiscoveredBootMismatchIsAmbiguous`, `…DuplicateAdmittedJobsIsAmbiguous`, `…ProbeFailureIsAmbiguous`, `…CancelledAfterAdmissionIsAmbiguous` |
| D-RC74-3 | `TestRecoveryClaimAtomicUnderContention`, `…DistinctJobsAllWin`, `…LeaseBoundsReassignment`, `…OwnershipFollowsTheFenceEpoch`, `…ClockRollbackStaysClosed`, `…ActionsAreIndependent`, `…WritesItsEventAtomically`, `…FailsClosedWhenEvidenceCannotCommit` + existing pacing/durability tests |
| D-RC74-4 | `TestMaintenanceClaimFailsClosedOnEvidenceFailure`, `…MarkAmbiguousFailsClosedOnEvidenceFailure`, `…ExpireFailsClosedOnEvidenceFailure`, `…EscalationEvidencePrecedesThrottle` |
| D-RC74-5 | `scripts/go-test-case-evidence.test.js` — 30 cases (13 malformed shapes × generation+verification, positives, empty-package edges, non-JSON) — all PASS |
| D-RC74-6 | pin checks: `check-docker-base-images.test.js`, `msb-runtime-pins.test.js` — PASS |

## Evidence / provenance / release-verification script tests

`msb-runtime-pins.test.js` (3), `verify-release-artifact.test.js` (36), `verify-version-consistency.test.js`,
`generate-source-manifest.test.js`, `package-source-archive.test.js`, `generate-release-evidence.test.js`,
`generate-evidence-root.test.js`, `finalize-release-evidence.test.js` — run via `node --test`.

## Live / environment-gated

| Lane | Status | Reason |
|---|---|---|
| `apple-hypervisor-framework` (`CRABBOX_MSB_LIVE=1 go test -race -run TestMSBLive ./internal/sandboxexecutor/`) | **PASS** | 79s — real microVMs, pin-verified runtime, pinned image digest |
| `linux-kvm` | **NOT_RUN** | requires amd64 KVM runner (`ubuntu-latest`); cannot run on darwin/arm64 |
| Live PostgreSQL (`CRABBOX_TEST_DATABASE_URL` / `test-live-postgres.sh`) | runnable if docker/initdb available | helper now defaults to the pinned image digest |
| External custody service integration | **NOT_RUN** | no external custody service available — interface tested locally via `sandbox-custodyd`; gate stays unsatisfied |
| Post-dispatch qualification (`CRABBOX_QUALIFICATION_POST_DISPATCH=1`) | gated, ~100s | per AGENTS.md budget |
