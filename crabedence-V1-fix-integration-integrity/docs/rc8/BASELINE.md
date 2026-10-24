# RC8 Baseline — Verified Source and Evidence Identities

Status: PR-00 baseline record. Binding for `codex/rc8-authority-integration`.
Date: 2026-10-24
Qualification: **NOT QUALIFIED** — development integration branch; no mandatory
qualification lane has executed for this identity.

## 1. Branch and parent

| Identity | Value |
|---|---|
| Integration branch | `codex/rc8-authority-integration` |
| Parent commit | `13566f1adf4fd3e3bd94981fe99670dc9de15793` |
| Parent commit subject | `fix: close retained-resource accounting gaps found in RC7.6 review` |
| Parent's parent | `239c933168d5455bb23386db327d0281057b9b66` |
| Parent's branch | `chore/rc7.6-qualification` (local + `origin`) |
| Remote | `https://github.com/dawsonblock/NEMO-CONTROL.git` |
| Development version (frozen in PR-00) | `0.55.0-rc8-dev` |

The branch was created in the authenticated Git checkout, **not** from a ZIP
extraction. `git cat-file -e` and `git show` confirmed the commit exists in
fetched remote history before branching.

### Why `13566f1a` and not the `chore/rc7.6-qualification` tip

Branch tip `b501963eaad0db34f3c844539da29f8555420b1a` is two commits ahead of
the signed candidate:

- `14e78a7` — `release: rebind RC7.6 development candidate to commit 13566f1a`
- `b501963` — `chore: refresh RC7.6 lane image pins for moved python:3.12 tag`

The tip refreshes `qualification/msb-lane-image-pins.json` after the signed
candidate was cut. Per the RC8 plan, the signed candidate is the canonical
reference; the moved-pin refresh is treated as a separate, ADR-gated decision
(see ADR-0001). The two identities are never mixed.

## 2. Source ↔ package binding (verified)

| Artifact | SHA-256 |
|---|---|
| Signed RC7.6 candidate ZIP (`NEMO-CONTROL-v0.54.0-rc7.6-development.zip`) | `73815dbd8bad1bcd219e1b2917342b2d1fa30b789463af93b1b7a2e7d992d3fd` |
| Outer RC7.6 bundle (`NEMO-CONTROL-chore-rc7.6-qualification.zip`, reference only) | `303d1fe45aaf52afd00d3590407144cb5445e8408828a90a6b23b94a62d841cb` |
| Source manifest (`…zip.source-manifest.json`) | `5f524be5e078438dbbec1fb2a468d5d6b9d347851ba0f533e51d6341ae9f3b0e` |
| Source manifest root hash | `7bd558ed6adca0d35486f58b33ff00e204fc0c936f9e9541d1229ebff57a3bd1` |

Verification executed 2026-10-24 in this checkout:

1. `git archive 13566f1a crabedence-V1-fix-integration-integrity` extracted to a
   clean directory.
2. All 4,265 manifest entries checked against extracted content: **4,253 files
   SHA-256-exact, 12 symlinks target-exact, exec bits exact, 0 mismatches,
   0 extra files on disk.**
3. The only manifest entry absent from the Git tree is
   `release-evidence/source-tree-sha256.txt`, which the manifest itself records
   as auto-embedded by the packager (4,264 real source entries + 1 embedded).
4. `qualification/msb-lane-image-pins.json` at `13566f1a` hashes to
   `f86821a73fba103d2bb70a00bba3ca71dc8e404cc75ddcae3c3a227b65a32b27` — equal to
   `lane_image_pins_sha256` in `RELEASE_MANIFEST.json`.
5. `qualification/msb-runtime-pins.json` at `13566f1a` hashes to
   `e6bde12f337538481bf3af680a6bc727231b142be950b67e1750ebf80b7e6894` — equal to
   `msb_runtime_pin_manifest_sha256` in `RELEASE_MANIFEST.json`.
6. Attestation signature verified:
   `ssh-keygen -Y verify -f …zip.allowed-signers -I dawsonblock@users.noreply.github.com -n rc75-release`
   → `Good "rc75-release" signature … ED25519 key SHA256:QwHCO7Y+LO6Z60LfX0r5xeFTTnrmTxGo6wiFWt35rQI`.

Conclusion: commit `13566f1a`'s tracked `crabedence-V1-fix-integration-integrity/`
tree is byte-identical to the signed candidate's packaged source. The parent is
canonical.

## 3. Main-side import source (authenticated, supersedes the ZIP)

The plan's import source "NEMO-CONTROL-main 17.zip (VERSION 0.53.2)" is
superseded by stronger evidence available locally: the authenticated `main`
branch in this repository.

| Identity | Value |
|---|---|
| Main tip commit | `655d4e2b4f88474e2f97bb564eef29157684f18d` |
| Main VERSION | `0.53.2` (matches the plan's claimed ZIP version) |
| Merge-base with RC7.6 | `2938f3aafb068ea7c56477bafe39f250afa19af7` (PR #1 merge) |
| Main subtree tree ID | `cc850485ea64b52635c9b55dffc5f3de7c7c686d` |
| RC7.6 subtree tree ID | `20f08be1416249e2c14d7878288262c24bf3cefc` |
| Commits on main since merge-base | 10 |
| Commits on RC7.6 side since merge-base | 134 |
| Files changed on main (subtree) | 44 (24 added, 20 modified) |
| Files changed on RC7.6 side (subtree) | 260 (181 added, 79 modified) |
| Files changed on **both** sides | 12 (conflict surfaces — see INTEGRATION_INVENTORY.md) |

Note: the plan's "Main artifact SHA-256" for the ZIP could not be recorded
because the file `NEMO-CONTROL-main 17.zip` was not present on this machine.
The authenticated branch + subtree tree ID + per-file SHA-256 table in
INTEGRATION_INVENTORY.md is the binding replacement — do not import from an
unverified ZIP if it later appears.

## 4. Frozen NEMO provenance boundary

| Identity | Value |
|---|---|
| NEMO subtree tree ID (`NEMO-feat-native-plugin-isolation/` @ `13566f1a`) | `42a9c4055df2a38e6ca6f1178d1ebcefa38672b7` |
| `runtimes/nemo-transfer-manifest.json` shipped tree SHA-256 | `f6229bb342d31fc1fa3224fd24b53490ceb507e4489f305605bb274947c16d0f` |
| Transfer source SHA-256 (`../NEMO-feat-native-plugin-isolation`) | `05d45ec86b1985b4aa4ba24f1315b96c858c56694c66116eae097cb68de06957` |
| Runtime version | `0.9.1-rc.4` |
| Policy SHA-256 (`runtimes/nemo-provenance-policy.json`) | `0ffe1cc939bcaaf4d4c361d5a58d9bd4e2a39e009f0c89d6809c32988c3feba1` |
| `nemo_transfer_manifest_sha256` (release manifest) | `43d8f6e69be3ad504359815bbd1ee7b44e405132c086cf8b608f850da7d57519` |

Invariant 7: the frozen upstream copy is not modified as a shortcut. Changes
land in the canonical integration tree (`crabedence-V1-fix-integration-integrity/`)
and the declared transfer delta only.

## 5. Toolchain pins

| Tool | Pinned version | Declared in |
|---|---|---|
| Go | `1.26.5` | `go.mod` (`toolchain go1.26.5`), `scripts/release-config.sh`, CI |
| Rust | `1.96.1` | `runtimes/nemo-relay/rust-toolchain.toml` |
| Node.js | `24.x` | `.github/workflows/ci.yml` (`node-version: 24`) |

`node scripts/verify-version-consistency.mjs` passes at
`0.55.0-rc8-dev` (worker/nemo package manifests, locks, and the
release-qualification `RELEASE_VERSION` were bumped with VERSION in PR-00).

**Local environment note:** this authoring host runs Go 1.27.2, not the pinned
1.26.5 — `verify-go-toolchain.sh` fails closed here (recorded as DEFECT_REGISTER
E-01). Development builds work (the toolchain directive is a floor), but no
gate evidence may be produced on this host until the pinned toolchain is
installed.

## 6. Known failures and open defects (inherited)

From `RELEASE_MANIFEST.json` and `DEFECT_REGISTER.md` of the RC7.6 candidate
(both state **NOT QUALIFIED**):

- RC7.6 development candidate was never through the mandatory qualification
  campaign (pinned toolchain, both microVM lanes, live crash/fault injection,
  independent custody). That evidence does not transfer to RC8 bytes
  (invariant 6).
- The RC7.5 artifact remains NO-GO (per RC7.6 manifest supersedes note).
- The `msb rm` label-resolve-then-remove cleanup path is **not** identity-atomic;
  exclusive namespace ownership is an interim constraint, not proof of
  conditional deletion (PR-05 scope).
- Adaptive-evidence trust defect: unassessed/blank trust values are treated as
  trusted in `internal/experience`/`internal/history`/`internal/research`
  (PR-01 scope — see DEFECT_REGISTER.md D-01).
- Main's `internal/releasectl` verifies against an empty trusted-fingerprint
  map and implements resume/unrevoke/clear-stage as unsigned file deletion
  (PR-03 scope — D-02, D-03).

## 7. Gate status

| Gate | Status | Evidence |
|---|---|---|
| G0 — verified parent + reproducible source inventory | **PASS** | sections 1–6; checks 1–6 of §2 executed in this checkout |
| G1–G8 | NOT RUN | gated by PR-01…PR-08 |

Development GO is granted for this branch only. Nothing here asserts release
qualification.
