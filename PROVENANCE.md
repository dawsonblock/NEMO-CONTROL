# NEMO-CONTROL provenance and transfer verification

Derived from `BASELINE-HARDENING-MANIFEST.json` (phase-0 baseline,
captured 2026-10-02). This document is the human-readable half of that
baseline: which trees exist, what each identity in the chain names, how
to re-verify every one of them, and what the baseline found.

## Trees

| Tree | Role |
| --- | --- |
| `NEMO-feat-native-plugin-isolation/` | Frozen reference — provenance only, not a development target |
| `crabedence-V1-fix-integration-integrity/runtimes/nemo-relay/` | Canonical NEMO source — all fixes and features land here |
| `crabedence-V1-fix-integration-integrity/` | Crabedence / Crabbox authority and effect kernel |

## The identity chain

```
source commit → capability registry digest → shipped runtime digest
                                            ↘ declared source digest + delta
```

| Identity | Value at last verification | How it is produced |
| --- | --- | --- |
| Capability registry SHA-256 | `3c32a9d2f51f9c1d0068dfaad04f2499ce7baade91ccafa42fa233c1700db3e9` | `crabbox` capability snapshot; bound into the runtime-identity file at serve time |
| Shipped runtime SHA-256 | `1bcf5f9dac40646db3e6a3e997637d8d3d683cb178c5fe7717f42da1e057055c` (1466 files) | `cmd/nemo-runtime-digest`; declared in `runtimes/nemo-transfer-manifest.json` |
| Source runtime SHA-256 | `5c9f32e82c317eba918936a4e90d9b35cd18e4ee6dcd935397fea3fdb49f9526` (1438 files) | Same digest definition over `NEMO-feat-native-plugin-isolation/` |
| Declared delta | 66 modified / 29 added / 1 removed | `local_modifications`, `added_paths`, `removed_paths` in the manifest; must equal the computed delta exactly |
| Crabedence version | 0.53.2 | `VERSION` |
| NEMO runtime version | 0.9.1-rc.4 | `runtimes/nemo-relay/Cargo.toml` `[workspace.package]` |
| Runtime configuration identity | computed at serve time | `{release, registry_sha256, effect_store, enabled_adapters}` — see `internal/execution/runtime_identity.go` |

The digest definition (all verifiers agree byte-for-byte): SHA-256 over
the sorted records `sha256(file-content) + two spaces + ./path + \n`
of every regular file below the tree, with `target/`, `.git/`,
`node_modules/`, `.venv/`, `.uv-cache/`, `__pycache__/` pruned.
Symlinks are not part of the file digest; they are covered by the
delta walk and by the component manifest's exhaustive check.

## Verifying the transfer

Three equivalent verifiers, in decreasing dependency order:

```sh
# Go tool — the CI gate (scripts/check-nemo-transfer-manifest.sh)
go run ./cmd/nemo-runtime-digest -manifest runtimes/nemo-transfer-manifest.json

# Python — consumer-side, stdlib only, same definition and semantics
python3 scripts/verify-nemo-transfer.py

# Shell — the bare digest only, no inventory checks
cd runtimes/nemo-relay && find . -type f -not -path './target/*' -print0 \
  | LC_ALL=C sort -z | xargs -0 shasum -a 256 | shasum -a 256
```

The full verify checks, in order: computed identity (digest, file
count, version, exclusion set), inventory (declared workspace members
are members; declared paths exist), declared binaries (source exists
inside the tree, the package declares it, features exist), the
generated blocks in `runtimes/nemo-relay/TRANSFER-PROVENANCE.md`, and —
when `NEMO-feat-native-plugin-isolation/` is present — the source
identity and the complete declared delta.

Regenerate the declaration after a deliberate tree change:

```sh
go run ./cmd/nemo-runtime-digest -manifest runtimes/nemo-transfer-manifest.json -update
```

## Baseline findings and resolution

The phase-0 baseline recorded the transfer gate **FAIL** at capture:
the manifest declared 1461 files / `c047c379…` while the on-disk tree
computed 1484 / `955a2614…`. Root cause was twofold:

- **Tracked-but-undeclared source additions** — real transfer drift the
  manifest predated (for example `crates/effect-runtime/src/kernel.rs`,
  `crates/ffi/src/plugin_host_location.rs`, `scripts/tcb/*.py`,
  `security/LINUX-RESTRICTED-HOST.md`, the `bridges/` crates).
- **Untracked local artifacts the digest does not exclude** —
  `.pytest_cache`, `.ruff_cache`, `*.egg-info`, the built
  `_native.abi3.so`, event `*.jsonl`, and `reports/*.json`.

Resolution in phase 7: the artifacts were removed (they are regenerable
local state), and the manifest was regenerated so the declaration again
equals the actual delta. The gate now passes with the real transfer
delta — 66 modifications, 29 added paths (10 declarations), 1 removal
(`crates/core/src/kernel.rs`, moved to `crates/effect-runtime/`).

## Qualification evidence (phase 8)

The following gates were executed against this tree; results bind the
shipped digest above (`1bcf5f9d…`):

| Gate | Result |
| --- | --- |
| `node --test scripts/*.test.js scripts/*.test.mjs` | 1039 pass / 43 skipped (platform-gated) / 0 fail — covers the unsigned macOS contract, artifact binding, qualification-registry extension, evidence finalize/package/publish, credential isolation |
| `scripts/test-nemo-plugin-host.sh` | PASS — real process-boundary composition; malformed and unhonorable isolation policies fail closed |
| `NEMO_DIST_PROFILE=debug scripts/build-nemo-distribution.sh` | PASS — 6-component manifest verifies exhaustively |
| `scripts/test-nemo-installed-distribution.sh dist/nemo-control_0.53.2_darwin_arm64` | PASS — 31 e2e checks on shipped bytes + authority/restart suites; attestation emitted and verified (`*.qualification.json`, 5 gates) |
| `scripts/test-nemo-runtime-e2e.sh` (development context) | PASS — 29 checks |
| `node scripts/verify-version-consistency.mjs` | OK (0.53.2) |
| `scripts/check-nemo-credential-isolation.sh`, `check-nemo-runtime-dependencies.sh` | PASS |
| `cargo test -p nemo-crabedence-runtime` | PASS — 34 tests |

Phase 8 found and fixed a real qualification defect: the e2e
ambient-override gate assumed a development tree (nothing pins the host),
so under an installed distribution — where the component manifest pins the
host — the check demanded a refusal that cannot happen, making the
installed-artifact gate unpassable. The check now branches on
`NEMO_E2E_EXPECT_RELEASE_ROOT`: the development branch keeps the refusal;
the installed branch proves the stronger property — the manifest-pinned
override runs, and an override naming *different bytes* is refused
(`scripts/test-nemo-runtime-e2e.sh`). A companion fix names the pin's
source in the mismatch error, so a release-install failure says the
component manifest rejected the bytes rather than naming
`NEMO_RELAY_PLUGIN_HOST_SHA256` when the deployer never set it
(`runtimes/nemo-relay/bridges/nemo-crabedence-runtime/src/plugin_host.rs`).

Explicitly **not run**: `generate-release-evidence.sh` /
`check-release-admission.sh` (require a clean tree — this workspace holds
uncommitted hardening work — and the full gate matrix including live
PostgreSQL; it is the CI `release-rc.yml` pipeline),
`verify-release-source.sh` / `verify-release-artifact.sh` /
`verify-release.sh` (require the signed tag and published artifacts —
`release/records/v0.53.2.json` records `publicationStatus: ready`, which
is admission evidence, not a published release), `publish-*.sh` and
`build-release-candidate.sh` (publication path; no release was requested),
and `codesign-macos.sh` under `developer-id` (requires Apple authority
material; the declared `none` contract is test-verified).

Remaining baseline note: the digest covers **disk state**, not git
state — local artifacts silently widen it. If the tree computes more
files than declared and no tracked change explains it, look for
regenerable pollution first (`find . -newer .git -type f` outside the
excluded directories).
