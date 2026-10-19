# RC7.6 qualification — 2026-10-19

Branch under test: `fix/rc7.6-defect-repair` (over frozen RC7.5 baseline `67bacdb3`).

## Live-lane results

| Lane | Environment | Result | Evidence |
|---|---|---|---|
| `apple-hypervisor-framework` | M2 Pro, macOS 26.2, bare metal, `msb 0.7.8` @ `1b73f626` | **PASS 14 / SKIP 1 / FAIL 0**, `-race`, 77.4s | `apple-hvf-qualification.log` |
| `linux-kvm` | GitHub `ubuntu-latest`, `/dev/kvm`, `msb 0.7.8`, go1.26.5 @ `1d9536e` | **PASS 15/15** (incl. `TestMSBLiveLinuxKVM`) | `linux-kvm-ci/` |
| `linux-kvm` | same @ `6ceabf8` | **PASS 15/15** | `linux-kvm-ci-run39235314309/` |

## Full admission workflow — run 39235314309 @ `6ceabf8`

`release-qualification.yml` dispatched with `claimed_lanes=linux-kvm` (the
apple lane cannot run on hosted `macos-15` — its evidence is the bare-metal
run above). Result: **PASS — 34/34 mandatory gates, 0 failed, 0 skipped;
`artifact_promotable: true`** for the claimed lane set. Evidence root
`c499aabb1a8205e69ca2de9ac09506f0c8f465ce5482983b142b6b136bf06d1d`, bound to
commit `6ceabf8e`. Bundle: `release-evidence-run39235314309/`.

GitHub artifact attestation was skipped by design on this user-owned private
repository (platform limitation, recorded as a workflow warning); all
attestation-independent steps passed.

## Earlier CI attempts (defect-driven)

| Run | Outcome | Cause |
|---|---|---|
| 39216619316 | cancelled | evidence job killed at the 30-min timeout mid-generation; fixed by `6563a6c` (60-min budget) |
| 39221954134 | failure | `nemo-transfer-provenance` FAIL (33/34) — shipped zip dropped `nemo-relay` symlinks; fixed by `1d9536e` restoring them (D-RC75-11) |
| 39228255743 | failure | all 34 gates + admission + verification passed; `actions/attest` unavailable on user-owned private repos; made conditional by `6ceabf8` |

## Command

```sh
CRABBOX_MSB_LIVE=1 CRABBOX_MSB_QUALIFY=1 \
  go test -v -race -timeout=900s -run 'TestMSBLive' ./internal/sandboxexecutor/
```

## Scope of evidence

The qualifying run exercises the repaired code paths against the real
Microsandbox `0.7.8` runtime on Apple Hypervisor.framework: lifecycle with
pinned `python:3.12` manifest digest, refusal proof (no VM created for a forged
contract), pre-existing-sandbox refusal, network/credential isolation,
interrupted-monitor and transport-failure `UNCERTAIN` handling, contract
timeout observability, read-only mounts, recovery resumption of an interrupted
job (D-RC75-1 mechanism), and substituted-VM cleanup (D-RC75-5 nonce-bound
handle removal against the real `msb rm`).

An earlier non-race run on the same commit passed 14/15 (same single skip) in
75.7s — preserved at `apple-hvf-live.log`.

## What remains open

- The apple-hypervisor lane's CI evidence is bare-metal local only (hosted
  `macos-15` cannot boot microVMs — D-RC75-3); the admission run claimed only
  `linux-kvm`, so its `artifact_promotable` verdict is lane-scoped.
- Trusted release signature and independently controlled external custody:
  residual release blockers unchanged.
- The shipped RC7.5 zip itself still drops the `nemo-relay` symlinks
  (D-RC75-11) — the tree repair is on the branch; archive production needs
  symlink-preserving packaging for a future artifact.
