# Final Qualification Report — crabedence-v0.54.0-rc.7.5-dev

**Generated from machine-readable records — do not edit by hand.**
Source of truth: `qualification.json`, `release-manifest.json`,
`gates/*.json`, `gate-results/*.log`, `SHA256SUMS`, and
`evidence-root.json` in this evidence directory.

| Field | Value |
|---|---|
| Release | crabedence-v0.54.0-rc.7.5-dev (0.54.0-rc.7.5-dev) |
| Status | **PASS** |
| Artifact promotable | true |
| Source commit | `6ceabf8e5411b0090fbfc5c5ad224a3dd8024711` |
| Source tree | `a142df756e0e36c0a06f0ddcb9fb6d05d8388f28` |
| Branch | `HEAD` |
| Qualified at | 2026-10-19T10:27:54Z |
| Evidence root SHA-256 | `c499aabb1a8205e69ca2de9ac09506f0c8f465ce5482983b142b6b136bf06d1d` |

## Gate summary

| Total | Passed | Failed | Skipped |
|---|---|---|---|
| 34 | 34 | 0 | 0 |

## Gates

Every gate's result is bound to the SHA-256 of its captured log; each
log is in turn covered by SHA256SUMS and the signed evidence root.

| Gate | Type | Mandatory | Status | Exit | Tests | Duration (ms) | Log SHA-256 |
|---|---|---|---|---|---|---|---|
| source_manifest | PROVENANCE | true | PASS | 0 | 0 | 76470 | `c0989438c3345d21…` |
| exact-toolchain | BUILD | true | PASS | 0 | 0 | 25 | `326a4aedabb10303…` |
| go-vet | STATIC_ANALYSIS | true | PASS | 0 | 0 | 289391 | `35f47103dba00feb…` |
| go-evidence-tests | TEST | true | PASS | 0 | 237 | 64032 | `27d857204e9a0165…` |
| go-tart-tests | TEST | true | PASS | 0 | 391 | 81229 | `d8344ad24c96c3a8…` |
| go-lume-tests | TEST | true | PASS | 0 | 74 | 3003 | `8d3af9f3dc5d2551…` |
| go-shared-tests | TEST | true | PASS | 0 | 323 | 3136 | `62466e78d8a58d1d…` |
| go-race-evidence | TEST | true | PASS | 0 | 189 | 254323 | `58e3c384a1d6fcdc…` |
| go-race-providers | TEST | true | PASS | 0 | 788 | 119705 | `5535c3835eabb2aa…` |
| go-race-sandboxexecutor | TEST | true | PASS | 0 | 446 | 775291 | `c11c40ad33d05c84…` |
| live-microvm-linux-kvm | TEST | true | PASS | 0 | 15 | 68 | `3830be96eea8c4f4…` |
| effect-fabric-contract | TEST | true | PASS | 0 | 31 | 3289 | `f258c0955a926ab7…` |
| effect-fabric-reconciliation | TEST | true | PASS | 0 | 32 | 3071 | `f27486afb4dde0ad…` |
| effect-fabric-evidence | TEST | true | PASS | 0 | 61 | 6093 | `c789827f605a9190…` |
| effect-fabric-post-dispatch-timeout | TEST | true | PASS | 0 | 2 | 99881 | `cf740f5a8cb08e32…` |
| effect-fabric-race | TEST | true | PASS | 0 | 1022 | 60420 | `bae7c59f49348754…` |
| registry-digest | PROVENANCE | true | PASS | 0 | 0 | 464 | `7f2d1572f56efdea…` |
| nemo-transfer-provenance | PROVENANCE | true | PASS | 0 | 0 | 3226 | `cba1df2d23204a96…` |
| postgres-fencing | INTEGRATION | true | PASS | 0 | 4 | 3230 | `c851381419337277…` |
| postgres-parity | INTEGRATION | true | PASS | 0 | 4 | 2955 | `aa746c958f3cea7d…` |
| effect-fabric-postgres | INTEGRATION | true | PASS | 0 | 158 | 55325 | `f1ae6c72bfeadd34…` |
| provider-github-faults | FAULT_INJECTION | true | PASS | 0 | 7 | 1325 | `aaeb938ac67959fd…` |
| authority-postgres | INTEGRATION | true | PASS | 0 | 11 | 1142 | `4cee44409e1078cd…` |
| critical-external | INTEGRATION | true | PASS | 0 | 16 | 35194 | `5519036e6ce67ecf…` |
| critical-faults | FAULT_INJECTION | true | PASS | 0 | 2 | 662 | `73f6488d5d5b7150…` |
| cross-language-conformance | TEST | true | PASS | 0 | 104 | 3530 | `a474d99049304abb…` |
| worker-typecheck | STATIC_ANALYSIS | true | PASS | 0 | 0 | 861 | `da7a7c3490beca17…` |
| worker-tests | TEST | true | PASS | 0 | 3053 | 33514 | `2471289c4bb39de3…` |
| worker-format | STATIC_ANALYSIS | true | PASS | 0 | 0 | 408 | `774d5df19129e46c…` |
| worker-lint | STATIC_ANALYSIS | true | PASS | 0 | 0 | 345 | `19b2174b53d9a037…` |
| worker-build | BUILD | true | PASS | 0 | 0 | 1649 | `f6f5b4df107557ef…` |
| nemo-typecheck | STATIC_ANALYSIS | true | PASS | 0 | 0 | 418 | `b84e2326fc9882e7…` |
| nemo-tests | TEST | true | PASS | 0 | 145 | 2961 | `ec2cfd453a679409…` |
| evidence-secret-scan | PROVENANCE | true | PASS | 0 | 0 | 22 | `a01ddcf79a09b3b1…` |

## Verification

From a checkout containing this evidence directory:

```sh
# 1. Every evidence file matches its recorded checksum.
(cd dist/release-evidence && shasum -a 256 -c SHA256SUMS)

# 2. The semantic evidence root honestly covers the bundle's identity
#    bindings and its root_sha256 covers the stored document.
python3 scripts/generate-evidence-root.py --verify dist/release-evidence

# 3. The extracted source archive qualifies standalone (the archive
#    carries its own embedded source manifest):
tar xzf <source-archive>.tar.gz -C <clean-room>
bash <clean-room>/<prefix>/scripts/qualify-source-distribution.sh <clean-room>/<prefix>
```

## Invariants asserted by this qualification

- **CRAB-V1-001** — V3 receipt always binds evidence_sha256
- **CRAB-V1-002** — V2 receipt can never contain evidence_sha256
- **CRAB-V1-003** — receipt evidence digest equals canonical RunEvidenceV1 SHA-256
- **CRAB-V1-004** — Go and TypeScript produce identical canonical evidence
- **CRAB-V1-005** — Go and TypeScript accept/reject identical receipt/evidence domains
- **CRAB-V1-006** — startup confirmation failure evidence survives to RunEvidenceV1
- **CRAB-V1-007** — detached providers never advertise exit observability
- **CRAB-V1-008** — persistence failure cannot alter FinalRunOutcome
- **CRAB-V1-009** — new mutations fail after coordinator authority loss
- **CRAB-V1-010** — replacement mutations cannot overlap pre-admitted old-coordinator mutations
- **CRAB-V1-011** — qualified source tree equals packaged source tree
- **CRAB-V1-012** — every mandatory qualification gate was executed and passed
- **CRAB-V1-013** — Go capability registry is authoritative for execution class
- **CRAB-V1-014** — durable idempotency prevents duplicate side effects
- **CRAB-V1-015** — UNKNOWN is a first-class terminal state for post-dispatch ambiguity
- **CRAB-V1-016** — crabbox exec never returns fake success for undispatched operations
- **CRAB-V1-017** — expired IN_FLIGHT work is never blindly redispatched
- **CRAB-V1-018** — only an unexpired active lease generation may mutate execution state
- **CRAB-V1-019** — terminal finalization is immutable and conflict-aware
- **CRAB-V1-020** — post-dispatch uncertainty cannot become retryable without evidence
- **CRAB-V1-021** — concurrent identical mutations cause at most one provider dispatch
- **CRAB-V1-022** — the release toolchain is exactly the declared toolchain (declared = installed = runtime GOVERSION, GOTOOLCHAIN=local)

## Toolchains

- go: go version go1.26.5 linux/amd64
- goversion: go1.26.5
- gotoolchain: local
- go_toolchain_directive: go1.26.5
- node: v24.21.0
- npm: 11.19.0
- git: git version 2.55.0
- postgres_client: psql (PostgreSQL) 16.15 (Ubuntu 16.15-1.pgdg24.04+2)
- postgres_server: 16.15(Debian16.15-1.pgdg13+2)
- effect_fabric_schema_version: unavailable
- worker_package_version: 0.54.0-rc.7.5-dev

## Environment

- os: Linux
- os_version: 6.17.0-1022-azure
- arch: x86_64
- date: 2026-10-19T11:02:32Z

---

_Generated from records qualified at 2026-10-19T10:27:54Z. If any
figure here disagrees with the JSON records, the JSON records win._
