# RC7.6 live-lane qualification run — 2026-10-19

Branch under test: `fix/rc7.6-defect-repair` @ `1b73f626` (over frozen RC7.5 baseline `67bacdb3`).

## Lane results

| Lane | Environment | Result | Evidence |
|---|---|---|---|
| `apple-hypervisor-framework` | M2 Pro, macOS 26.2, bare metal, `msb 0.7.8` (pinned at `~/.microsandbox/bin/msb`) | **PASS 14 / SKIP 1 / FAIL 0**, `-race`, 77.4s | `apple-hvf-qualification.log` |
| `linux-kvm` | — | **NOT_RUN** — requires a Linux/KVM host; `TestMSBLiveLinuxKVM` skipped correctly on darwin | — |

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

## What this run does not establish

- Linux/KVM lane: still requires a KVM-capable host (or the CI lane re-run
  against `fix/rc7.6-defect-repair`).
- Trusted release signature and independently controlled external custody:
  residual release blockers unchanged.
- Full RC7.6 admission workflow: not yet run. This run is lane evidence, not
  release admission.
