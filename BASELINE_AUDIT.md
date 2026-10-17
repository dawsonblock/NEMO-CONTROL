# Baseline Audit — NEMO-CONTROL RC7.4

## Scope

Starting point: `crabedence-V1-fix-integration-integrity` @ commit
`303caba62fb7546ccdbb8fb273bd0a8645bb904c`, branch
`fix/rc7.1-closed-policy-and-recovery`, declared version `0.54.0-rc.7.3`.
Frozen NEMO reference: `../NEMO-feat-native-plugin-isolation`.

## Source identity (independently recomputed)

| Tree | Expected SHA-256 | Result |
|---|---|---|
| `runtimes/nemo-relay` (canonical runtime) | `f6229bb342d31fc1fa3224fd24b53490ceb507e4489f305605bb274947c16d0f` | **match** |
| `NEMO-feat-native-plugin-isolation` (frozen reference) | `05d45ec86b1985b4aa4ba24f1315b96c858c56694c66116eae097cb68de06957` | **match** |

Verified by `scripts/verify-nemo-transfer.py` in both directions (file + symlink inventory digests,
delta and binary declarations). Git metadata was not relied on.

## Toolchain availability

| Tool | Required | Present |
|---|---|---|
| Go | `toolchain go1.26.5` (go.mod) | `go1.26.5 darwin/arm64` at `~/sdk/go1.26.5/bin/go` |
| Node/npm | worker + script tests | `v24.16.0` / `11.13.0` |
| Python | evidence tooling | `3.12.0` |
| jq | pin manifests | `jq-1.7.1-apple` |
| msb | pinned `0.7.8` | `0.7.8`, executable+firmware digests verified against `qualification/msb-runtime-pins.json`, `msb doctor` healthy |

See `DEPENDENCY_AND_TOOLCHAIN_LOCK.json` and `SOURCE_INVENTORY.json` (9470 tracked files).

## Baseline test status

- `go build -trimpath -o bin/crabbox ./cmd/crabbox`: **PASS**
- `go test -race -timeout=20m ./internal/sandboxexecutor/`: **PASS** (~605s; earlier 5m-timeout
  failures were timeouts of the harness, not test failures — the package needs the repository's
  20-minute race budget)
- All other packages PASS at baseline (`internal/evidence`, `authority`, `idempotency`,
  `reconcile`, `sandboxcustody`, `capability`, `execution`, `cli`, …)
- Live microVM suite (`CRABBOX_MSB_LIVE=1`): runnable on this host — runtime pin-verified and
  `msb doctor` healthy on the `apple-hypervisor-framework` lane.

## Defects confirmed at baseline

| ID | Severity | Defect |
|---|---|---|
| D-RC74-1 | P0 | Fallback boot-generation mismatch destroyed the discovered VM and returned a definitive error |
| D-RC74-2 | P0 | Pre-execution destroys not gated on dispatch ownership |
| D-RC74-3 | P1 | Recovery claim non-atomic (16/16 duplicate ordinal-1 claims reproduced) |
| D-RC74-4 | P1 | Mandatory audit events best-effort; escalation wrote throttle before evidence; silent transition drops |
| D-RC74-5 | P1 | Evidence generation accepted streams verification rejects (truncated package lifecycle) |
| D-RC74-6 | P1 | Mutable image tags in `stage-b.yml`, live lane image pull, and local live-postgres default |

Full reproduction evidence in `DEFECT_REGISTER.md`.

## Baseline limitations (carried honestly)

- The `linux-kvm` live lane cannot run on this Darwin/arm64 host; it requires an amd64 KVM runner
  (the qualification workflow schedules it on `ubuntu-latest`). Recorded **NOT_RUN** locally.
- External evidence custody: the `sandbox-custodyd` daemon and `SocketCustodian` interface exist and
  are tested locally; no third-party custody service is integrated — the external-custody gate
  remains unsatisfied.
- Crabbox remote execution was not exercised for this baseline; `.crabbox.yaml` remains available
  for auditable remote validation.
