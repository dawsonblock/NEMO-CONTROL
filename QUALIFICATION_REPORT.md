# Qualification Report — NEMO-CONTROL `0.54.0-rc.7.4-dev`

**Verdict: DEVELOPMENT CANDIDATE — not a qualified release.**

All implementable repairs are complete and locally verified. Mandatory gates that require
environments or services unavailable on this host remain explicit blockers and are recorded
**NOT_RUN** — never as passes.

## Gate results

| Gate | Result | Evidence |
|---|---|---|
| Source identity (canonical runtime + frozen reference digests) | **PASS** | `verify-nemo-transfer.py`, both digests match rc.7.3 baseline |
| Build | **PASS** | `go build -trimpath ./cmd/crabbox` |
| `go vet ./...` | **PASS** | clean |
| Full race suite `go test -race -timeout=20m ./...` | **PASS** | every package green; `internal/cli` 1122s, `internal/sandboxexecutor` 633s (a first combined attempt timed cli out at 20m only because the live-VM lane ran concurrently — contention, not a failure; dedicated rerun passed) |
| `internal/sandboxexecutor` race suite | **PASS** | baseline + post-change runs |
| WP1–WP4 regression tests | **PASS** | see `TEST_MATRIX.md` |
| Evidence lifecycle adversarial corpus | **PASS** | 30/30 in `go-test-case-evidence.test.js` |
| Runtime pins (executable + firmware + doctor) | **PASS** | `verify-msb-runtime-pins.sh` |
| Version consistency | **PASS** | `verify-version-consistency.mjs` → `0.54.0-rc.7.4-dev` |
| `apple-hypervisor-framework` live lane | **PASS** | `CRABBOX_MSB_LIVE=1 go test -race -run TestMSBLive` — 79s, real microVMs on pin-verified msb 0.7.8, image at pinned arm64 digest |
| `linux-kvm` live lane | **NOT_RUN** | needs amd64 KVM runner — blocker |
| External custody service | **NOT_RUN** | no deployed service; local `custodyd` interface tested — blocker |
| Crabbox remote auditable validation | **NOT_RUN** | not exercised this session — blocker |
| Live PostgreSQL lanes | see run log | `test-live-postgres.sh` (pinned image) |

## Why this is not `0.54.0-rc.7.4` (qualified)

Per the hard qualification rules: a mandatory test cannot become optional because the host lacks a
dependency, and skips do not count as passes. The `linux-kvm` lane, a deployed external custody
service, and remote/auditable execution each need an environment this host does not provide. Local
results qualify this working tree only — a release is qualified by gate evidence bound to the exact
frozen commit and published artifacts, which requires the CI lanes to run on the release commit.

## How to close the remaining gates

1. Run `.github/workflows/release-qualification.yml` on the frozen `0.54.0-rc.7.4-dev` commit (or
   the finalized `-rc.7.4` commit): it schedules `linux-kvm` on `ubuntu-latest` and
   `apple-hypervisor-framework` on `macos-15`, each pulling the pinned image digest.
2. Deploy or integrate a real external custody service against `SocketCustodian`'s protocol and run
   the custody integration lane; until then the external-custody gate stays unsatisfied.
3. Re-run `package-source-archive.sh` + `qualify-source-distribution.sh` on the release commit and
   bind artifact digests into the signed release manifest.
