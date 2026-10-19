# RC7.5 live-lane qualification run — 2026-10-19

Subject: `NEMO-CONTROL-v0.54.0-rc7.5-development.zip`
SHA-256 `796437dd80667b0febe63f1c272a4d45c655524081d3e1aefc23b89e0a31f6c0`
(matched `.sha256` and `.attestation.json` before extraction).

Runtime: microsandbox **0.7.8**, both `msb` binary and `libkrunfw` verified against
`qualification/msb-runtime-pins.json` on each host. Toolchain `go1.26.5`.
Image: `python:3.12` at the reviewed per-architecture digests in
`qualification/msb-lane-image-pins.json`.

## Lane results

| Lane | Host | Result | Evidence |
|---|---|---|---|
| `apple-hypervisor-framework` | M2 Pro, macOS 26.2, bare metal | **PASS 13/13** (1 designed SKIP: `TestMSBLiveLinuxKVM`) `-race`, 77s | `apple-hypervisor-framework/local-m2pro-test.log` |
| `linux-kvm` | GitHub `ubuntu-latest`, amd64, `/dev/kvm` | **PASS 14/14** incl. `TestMSBLiveLinuxKVM`, `-race` | `linux-kvm/test.json`, `linux-kvm/cases.json` |
| `apple-hypervisor-framework` | GitHub `macos-15` hosted | **FAIL** — `VmCreate` error; hosted Mac runners are themselves VMs, no nested virt | `apple-hypervisor-framework/ci-macos15-test.json`, D-RC75-3 |

## CI run

`https://github.com/dawsonblock/nemo-rc75-qualification/actions/runs/39186297140`
— Release Qualification workflow on commit `67bacdb` (imported archive source on private repo
`dawsonblock/nemo-rc75-qualification`). Triggered by push to `main`; empty `claimed_lanes`
claimed all inventoried lanes.

Passed jobs: Provenance (repository gates on pushed tree), Go race tests
(cli/execution/providers), Worker, NeMo, PostgreSQL fencing + parity (both), Cross-language
conformance, Live microVM (linux-kvm).

Failed jobs: Live microVM (apple-hypervisor-framework — D-RC75-3, environmental), Go tests and
Go race tests (sandboxexecutor) — `TestDaemonCrashPreservesAcknowledgedJobs` (D-RC75-1) and
`TestMaintenanceAmbiguousDispatchReconcilesNotRetries` (D-RC75-2). Both defects reproduced on
rerun; neither reproduces on darwin/arm64 bare metal.

Release evidence + admission job: correctly **skipped** — the gate requires all green.

## Read

Both live lanes produced real-microVM evidence — that part of RC7.5 qualification is complete.
The release is still blocked by D-RC75-1 (Linux crash recovery cannot settle ambiguous
dispatches — the serious one), D-RC75-2, D-RC75-3, plus the pre-existing RC7.4 register items
above and the external-custody gate.
