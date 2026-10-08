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

### Complete outer-repository identity

The transfer identity below covers the NEMO subtree, not the complete
NEMO-CONTROL release. The outer-source tool is
`crabedence-V1-fix-integration-integrity/scripts/outer-release-manifest.mjs`.
Its `--help` describes the source, verify, archive, extract, evidence-digest,
and finalize commands. All path arguments must be absolute; keep generated
bundles and logs outside the source checkout, such as under `/tmp`.

The source bundle contains `root/` (both component trees, including the
frozen reference) and `source-manifest.json`. Its canonical inventory binds
all HEAD paths plus both runtime provenance inventories to worktree bytes,
symlink targets and executable bits. It carries the source commit and source
component digests, the authoritative registry envelope, ABI, recipes and
toolchain/dependency locks. Component digest semantics are embedded in the
manifest: source component digests are **not binary attestations**.

The source manifest hash must be retained through a trusted channel.
Verification of an extracted bundle needs neither Git nor the original
checkout. Every inventory digest is recomputed; extra, missing, changed,
unsafe and colliding paths are refused. Source snapshots may describe dirty
development bytes, but finalization refuses a dirty source or a changed
HEAD/source inventory.

The source manifest has no qualification claim. After an actual rebuild and
qualification, finalization consumes a separate operator-supplied check
record with matching source commit, source digest, registry digest and
qualification evidence digest. Evidence and the check record are outside the
source inventory to avoid circular hashes. The resulting release manifest
binds all ten release identities and the qualification record.

**Limits:** binding an operator record does not execute qualification, prove
the truth of its checks, satisfy the production qualification matrix, or
authorize publication. Authenticate the finalized release manifest as well
as the source manifest; a trusted source hash alone cannot authenticate an
operator's qualification assertion. No signing keys or promotion authority
are supplied by this tooling.

The root consolidation workflow exercises independent archive extraction
and source verification. Rebuilding the extracted source, rerunning the full
qualification matrix, comparing release-profile binaries and normalized
evidence, signing, and publication remain release prerequisites. The
historical `FINAL_QUALIFICATION_REPORT.md` must not be used as evidence for
the newly generated outer identity.

### NEMO transfer identity

```
source commit → capability registry digest → shipped runtime digest
                                            ↘ declared source digest + delta
```

| Identity | Value at last verification | How it is produced |
| --- | --- | --- |
| Provenance format | 2 | `provenance_format_version` in the transfer manifest; `runtimes/nemo-provenance-policy.json` defines the canonical stream |
| Capability registry SHA-256 | `3c32a9d2f51f9c1d0068dfaad04f2499ce7baade91ccafa42fa233c1700db3e9` | `crabbox` capability snapshot; bound into the runtime-identity file at serve time |
| Shipped runtime SHA-256 | `e1279ef20acc448ac52a6ac2332c81f71e278b2bf71579160ffc953d0f9567a0` (1466 files, 10 symlinks) | `cmd/nemo-runtime-digest` format-2 canonical stream; declared in `runtimes/nemo-transfer-manifest.json` |
| Source runtime SHA-256 | `05d45ec86b1985b4aa4ba24f1315b96c858c56694c66116eae097cb68de06957` (1438 files, 10 symlinks) | Same format-2 stream over `NEMO-feat-native-plugin-isolation/` |
| Declared delta | 78 modified / 10 declared added entries covering 29 files / 1 removed / 0 symlink deltas / 0 retyped / 0 mode changes | `delta` object in the manifest; must equal the computed delta class-for-class |
| Provenance policy SHA-256 | `0ffe1cc939bcaaf4d4c361d5a58d9bd4e2a39e009f0c89d6809c32988c3feba1` | Bound into the manifest as `policy.path` + `policy.sha256`; the enumeration rules cannot drift silently |
| Crabedence version | 0.53.2 | `VERSION` |
| NEMO runtime version | 0.9.1-rc.4 | `runtimes/nemo-relay/Cargo.toml` `[workspace.package]` |
| Runtime configuration identity | computed at serve time | `{release, registry_sha256, effect_store, enabled_adapters}` — see `internal/execution/runtime_identity.go` |

The format-2 digest definition (Go and Python verifiers agree
byte-for-byte): SHA-256 over the canonical record stream of every
provenance object under the tree, in byte-wise `./`-prefixed path
order:

```text
FILE<TAB>./path<TAB>sha256(content)<TAB>x|-      # regular file + exec bit
SYMLINK<TAB>./path<TAB>readlink-target            # symlinks are bound, not skipped
```

The enumeration rules — excluded directory names/suffixes, excluded
file names/suffixes, and `generated_paths` (deterministic build outputs
such as the `plugin_worker_pb2*.py` bindings) — live in
`runtimes/nemo-provenance-policy.json`, bound into the manifest by
SHA-256. Anything in the tree that is neither excluded nor a declared
delta object fails verification; generated files can be present on disk
without perturbing identity and can never be declared as source.

## Verifying the transfer

Two verifiers, in decreasing dependency order:

```sh
# Go tool — the CI gate (scripts/check-nemo-transfer-manifest.sh)
go run ./cmd/nemo-runtime-digest -manifest runtimes/nemo-transfer-manifest.json

# Python — consumer-side, stdlib only, same definition and semantics
python3 scripts/verify-nemo-transfer.py
```

Both take a strict mode for transfer-provenance qualification —
`-require-source` / `--require-source` — under which a missing frozen
reference is a hard failure rather than a reported note. Official
release admission runs the strict mode. The manifest can demand the
same with `source.required: true`.

The full verify checks, in order: the bound policy hash; computed
identity (format-2 digest, file count, symlink count, version);
inventory (declared workspace members are members; declared paths exist
and none name a generated artifact); declared binaries (source exists
inside the tree, the package declares it, features exist); the
generated blocks in `runtimes/nemo-relay/TRANSFER-PROVENANCE.md`; and —
when `NEMO-feat-native-plugin-isolation/` is present — the source
identity and the complete typed delta: modified/added/removed files,
added/removed/retargeted symlinks, retyped paths, and mode changes.

Regenerate the declaration after a deliberate tree change:

```sh
go run ./cmd/nemo-runtime-digest -manifest runtimes/nemo-transfer-manifest.json -update
```

Running the regeneration twice produces a zero-diff second run; running
verification twice produces identical results and no modified files.

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
equals the actual delta. The gate then passed with the real transfer
delta — 66 modifications, 29 added paths, 1 removal
(`crates/core/src/kernel.rs`, moved to `crates/effect-runtime/`).

The release-integrity repair cycle subsequently superseded the format-1
identity: the v1 digest was regular-files-only, counted two generated
protobuf bindings as source additions, and left symlinks outside the
identity entirely. Format 2 binds files, symlinks, and executable bits
under a policy hash; the pb2 bindings are generated artifacts that can
no longer perturb canonical identity or ride into the delta. The
format-1 shipped digest `1bcf5f9d…` (1466 files) is retired; the current
format-2 identity is `e1279ef2…` (1466 files, 10 symlinks) — the digest moves
when the vendored runtime's declared content changes (a documentation split
added `security/PLUGIN-ISOLATION-HISTORY.md`), and every such move is a
manifest regeneration recorded here rather than a silent change.


## Status vocabulary

Words that name release state mean exactly one thing here. Nothing else a
check, log, or report prints is a status claim.

- **IMPLEMENTED** — code exists. Says nothing about whether it ran.
- **TESTED** — the relevant test passed in the environment it ran in.
- **QUALIFIED** — every required qualification gate passed for the exact
  artifact the gates ran on. A gate that did not run is `NOT_RUN`, never
  PASS.
- **SIGNED** — the exact qualified artifact carries a valid release
  signature (Developer ID Application for macOS artifacts, the allowed
  signers list otherwise).
- **PUBLISHED** — the exact qualified, signed artifact was published; the
  bytes a consumer fetches are the bytes the evidence describes.

`ready`, `verified`, and `done` are deliberately not status words: a tree
that is IMPLEMENTED and TESTED is not QUALIFIED, and a QUALIFIED artifact
is neither SIGNED nor PUBLISHED.

## Qualification evidence (phase 8)

The following gates were executed against this tree; results bound the
format-1 shipped digest (`1bcf5f9d…`) current at that capture:

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
