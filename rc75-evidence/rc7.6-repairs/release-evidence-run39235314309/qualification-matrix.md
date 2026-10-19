# Crabedence V1 Hardening — Qualification Matrix

**Branch:** `HEAD`
**Source commit:** `6ceabf8e5411b0090fbfc5c5ad224a3dd8024711`
**Git tree:** `a142df756e0e36c0a06f0ddcb9fb6d05d8388f28`
**Date:** 2026-10-19T11:02:32Z
**Release status:** PASS (34/34 gates passed)

## Toolchains

| Tool | Version |
|------|---------|
| Go | go version go1.26.5 linux/amd64 |
| Node | v24.21.0 |

## Gate Results

| Gate | Type | Status | Tests | Log |
|------|------|--------|-------|-----|
| `source_manifest` | PROVENANCE | PASS | 0 | `gate-results/source-manifest-verify.log` |
| `exact-toolchain` | BUILD | PASS | 0 | `gate-results/exact-toolchain.log` |
| `go-vet` | STATIC_ANALYSIS | PASS | 0 | `gate-results/go-vet.log` |
| `go-evidence-tests` | TEST | PASS | 237 | `gate-results/go-evidence-tests.log` |
| `go-tart-tests` | TEST | PASS | 391 | `gate-results/go-tart-tests.log` |
| `go-lume-tests` | TEST | PASS | 74 | `gate-results/go-lume-tests.log` |
| `go-shared-tests` | TEST | PASS | 323 | `gate-results/go-shared-tests.log` |
| `go-race-evidence` | TEST | PASS | 189 | `gate-results/go-race-evidence.log` |
| `go-race-providers` | TEST | PASS | 788 | `gate-results/go-race-providers.log` |
| `go-race-sandboxexecutor` | TEST | PASS | 446 | `gate-results/go-race-sandboxexecutor.log` |
| `live-microvm-linux-kvm` | TEST | PASS | 15 | `gate-results/live-microvm-linux-kvm.log` |
| `effect-fabric-contract` | TEST | PASS | 31 | `gate-results/effect-fabric-contract.log` |
| `effect-fabric-reconciliation` | TEST | PASS | 32 | `gate-results/effect-fabric-reconciliation.log` |
| `effect-fabric-evidence` | TEST | PASS | 61 | `gate-results/effect-fabric-evidence.log` |
| `effect-fabric-post-dispatch-timeout` | TEST | PASS | 2 | `gate-results/effect-fabric-post-dispatch-timeout.log` |
| `effect-fabric-race` | TEST | PASS | 1022 | `gate-results/effect-fabric-race.log` |
| `registry-digest` | PROVENANCE | PASS | 0 | `gate-results/registry-digest.log` |
| `nemo-transfer-provenance` | PROVENANCE | PASS | 0 | `gate-results/nemo-transfer-provenance.log` |
| `postgres-fencing` | INTEGRATION | PASS | 4 | `gate-results/postgres-fencing.log` |
| `postgres-parity` | INTEGRATION | PASS | 4 | `gate-results/postgres-parity.log` |
| `effect-fabric-postgres` | INTEGRATION | PASS | 158 | `gate-results/effect-fabric-postgres.log` |
| `provider-github-faults` | FAULT_INJECTION | PASS | 7 | `gate-results/provider-github-faults.log` |
| `authority-postgres` | INTEGRATION | PASS | 11 | `gate-results/authority-postgres.log` |
| `critical-external` | INTEGRATION | PASS | 16 | `gate-results/critical-external.log` |
| `critical-faults` | FAULT_INJECTION | PASS | 2 | `gate-results/critical-faults.log` |
| `cross-language-conformance` | TEST | PASS | 104 | `gate-results/cross-language-conformance.log` |
| `worker-typecheck` | STATIC_ANALYSIS | PASS | 0 | `gate-results/worker-typecheck.log` |
| `worker-tests` | TEST | PASS | 3053 | `gate-results/worker-tests.log` |
| `worker-format` | STATIC_ANALYSIS | PASS | 0 | `gate-results/worker-format.log` |
| `worker-lint` | STATIC_ANALYSIS | PASS | 0 | `gate-results/worker-lint.log` |
| `worker-build` | BUILD | PASS | 0 | `gate-results/worker-build.log` |
| `nemo-typecheck` | STATIC_ANALYSIS | PASS | 0 | `gate-results/nemo-typecheck.log` |
| `nemo-tests` | TEST | PASS | 145 | `gate-results/nemo-tests.log` |
| `evidence-secret-scan` | PROVENANCE | PASS | 0 | `gate-results/evidence-secret-scan.log` |

## Release Invariants

- **CRAB-V1-001:** V3 receipt always binds evidence_sha256
- **CRAB-V1-002:** V2 receipt can never contain evidence_sha256
- **CRAB-V1-003:** receipt evidence digest equals canonical RunEvidenceV1 SHA-256
- **CRAB-V1-004:** Go and TypeScript produce identical canonical evidence
- **CRAB-V1-005:** Go and TypeScript accept/reject identical receipt/evidence domains
- **CRAB-V1-006:** startup confirmation failure evidence survives to RunEvidenceV1
- **CRAB-V1-007:** detached providers never advertise exit observability
- **CRAB-V1-008:** persistence failure cannot alter FinalRunOutcome
- **CRAB-V1-009:** new mutations fail after coordinator authority loss
- **CRAB-V1-010:** replacement mutations cannot overlap pre-admitted old-coordinator mutations
- **CRAB-V1-011:** qualified source tree equals packaged source tree
- **CRAB-V1-012:** every mandatory qualification gate was executed and passed
- **CRAB-V1-013:** Go capability registry is authoritative for execution class
- **CRAB-V1-014:** durable idempotency prevents duplicate side effects
- **CRAB-V1-015:** UNKNOWN is a first-class terminal state for post-dispatch ambiguity
- **CRAB-V1-016:** crabbox exec never returns fake success for undispatched operations
- **CRAB-V1-017:** expired IN_FLIGHT work is never blindly redispatched
- **CRAB-V1-018:** only an unexpired active lease generation may mutate execution state
- **CRAB-V1-019:** terminal finalization is immutable and conflict-aware
- **CRAB-V1-020:** post-dispatch uncertainty cannot become retryable without evidence
- **CRAB-V1-021:** concurrent identical mutations cause at most one provider dispatch
- **CRAB-V1-022:** the release toolchain is exactly the declared toolchain (declared = installed = runtime GOVERSION, GOTOOLCHAIN=local)

## Provenance

- Commit: `6ceabf8e5411b0090fbfc5c5ad224a3dd8024711`
- Tree: `a142df756e0e36c0a06f0ddcb9fb6d05d8388f28`
- Branch: `HEAD`
- Dirty: false (clean working tree required)

## Verification

To verify this release artifact:

```bash
./scripts/verify-release-artifact.sh --mode qualification
```

To check release admission:

```bash
./scripts/check-release-admission.sh
```
