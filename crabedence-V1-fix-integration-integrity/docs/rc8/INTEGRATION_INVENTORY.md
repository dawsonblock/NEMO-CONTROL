# RC8 Integration Inventory — Main-side Import Ledger

Status: PR-02 executed (topic `codex/rc8-pr02-authority-abi`). Outcomes:

- **Landed clean:** `internal/execution/invocation_abi.go` (scanner
  enforces mediation/session fields + digest shapes in wire order),
  `internal/execution/dispatch.go` (inert `SetCustodyGate`/`SetCustodySink`
  hooks; no `internal/witness` dependency — PR-04 wires them),
  `internal/reconcile/worker.go` (recovery-resolution receipts to the same
  sink), `internal/evidence/evidence.go` merge (kept RC7.6 `SignRecord`
  domain separation **and** added Main's raw `SignBytes`), all of import
  set B except `check-image-pins*`/`generate-source-inventory.mjs` (PR-07).
- **Rejected as clean takes:** `internal/cli/run_test.go` and
  `internal/cli/checkpoint_capture_binary_test.go` are *true* three-way
  merges — both sides fixed the umbrella-repo layout differently, and
  RC7.6's resolution (`checkpointTestModuleRoot` + `git rev-parse`
  toplevel, fixture-repo hydration) subsumes Main's. RC7.6 versions kept.
- **Deferred by design:** `internal/execution/service.go`,
  `internal/execution/serve.go`, `internal/execution/config.go` (Main's
  delta is releasectl/witness wiring → PR-03/PR-04);
  `docs/spec/durable-execution-contract.md` (recovery+custody content →
  PR-03/PR-04); `qualification/*`, `.github/workflows/*`,
  `scripts/package-source-archive*`, `internal/applevmhelper/*` → PR-05/07.
- **Provenance impact:** `abi_verdict.rs` lands inside the shipped
  `runtimes/nemo-relay` tree under declared addition `bridges/`; shipped
  identity recomputed to `14fc142e…` (1467 files, delta 30 added) via the
  declared `nemo-runtime-digest -update` path; dependent umbrella docs
  restated and `check-nemo-transfer-manifest.sh` green.

Every candidate import from `main`
(`655d4e2b4f88474e2f97bb564eef29157684f18d`, subtree tree
`cc850485ea64b52635c9b55dffc5f3de7c7c686d`) into
`codex/rc8-authority-integration` (parent `13566f1a`, subtree tree
`20f08be1416249e2c14d7878288262c24bf3cefc`), relative to merge-base
`2938f3aafb068ea7c56477bafe39f250afa19af7`.

Rule (plan §0, §4): **hunk-level three-way semantic merge only**. No
directory-level copy. Each row lists the SHA-256 of the file *as it exists on
`main`* — the pre-import identity to re-verify at cherry time.

## 1. Import set A — new authority/evidence modules (PR-03, PR-04)

| Path (under `crabedence-V1-fix-integration-integrity/`) | SHA-256 @ main | Purpose | Import policy | Owning PR |
|---|---|---|---|---|
| `internal/releasectl/releasectl.go` | `8c63928455ebb105ca91d38a3543ee23e17472825c38a1a1c606186cd10b7a3d` | Release halt/resume/revoke/stage control | **Redesign, do not copy**: empty-trust-set acceptance and file-deletion transitions are the defects PR-03 removes. Port API shape + tests only. | PR-03 |
| `internal/releasectl/releasectl_test.go` | `be2c807ce9ac34e27494c0418d7904ddfbb22c0d92c3da807d5999a167ba8741` | Control tests | Port, then extend per PR-03 negative matrix. | PR-03 |
| `internal/cli/control.go` | `6937b2e1081fb409b7a0149180325a3afd27843f4a77e3d1dd78e3b64d76331e` | Operator control CLI surface | Hand-merge into `cli_kong.go` command table; must route through signed ledger semantics. | PR-03 |
| `internal/cli/witness.go` | `5a8491c94150cd3189097937a98172d88e1cf4adea40041fe4a4143fa46773c2` | Witness CLI surface | Hand-merge; distinct from sandboxcustody commands. | PR-04 |
| `internal/cli/recovery.go` | `202c5e7796136af117bc85c49fbd4edd6463fc3c57758c070df5e0f020603622` | Operator recovery surface | Hand-merge; recovery must not become an unsigned clear path. | PR-03 |
| `internal/cli/recovery_test.go` | `4f64f6b645863be8acb29fc3db9733fb7646b2d2329d1fbb97e16a26a8fe6652` | Recovery tests | Port. | PR-03 |
| `internal/witness/witness.go` | `172aff8577ac4a437815c5a7747519ceb5a6a074b12046e18baa3ce4e585895c` | Receipt witness core | Port behind custody-envelope-v1 contract; distinct domain from sandboxcustody. | PR-04 |
| `internal/witness/service.go` | `18fba6ec2241ed2308221921a43d3b30dcc395757c29260bd0b81c751b73842c` | Witness service | Port; local UDS transport only — separate-host transport is PR-04 work. | PR-04 |
| `internal/witness/client.go` | `3ce8d74d0be2298e37c9951ae5532e38d027a79a74a6eb251a9bef9e86e090c5` | Witness client | Port. | PR-04 |
| `internal/witness/outbox.go` | `4c2d29434c210dded6a1ce1322d2134d204e67491764c215fa9edb2753cb31e1` | Durable outbox | Port; verify restart/cold-restore reconciliation. | PR-04 |
| `internal/witness/ledger.go` | `45a1ca832318c240285197f1657bd8f2076563374e865bfa2c38a1e720231314` | Witness ledger | Port; bind to versioned envelope. | PR-04 |
| `internal/witness/witness_test.go` | `cdd59220e310486b14f675b0699b7e5712085c37cf201d554fc3cca55a1cffa2` | Witness tests | Port + extend per PR-04 forgery/replay matrix. | PR-04 |

## 2. Import set B — ABI verification tooling (PR-02)

| Path | SHA-256 @ main | Purpose | Import policy | Owning PR |
|---|---|---|---|---|
| `cmd/abi-verdict/main.go` | `3ad7acfb1fbb8b36b532c5469b7909c5b2e00d2ed6b8813035974198068b8cd0` | ABI verdict CLI | Import after schema compat check against RC7.6 `invocation_abi.go`. | PR-02 |
| `internal/execution/invocation_abi_fuzz_test.go` | `086ed42b08084cc6dc68693881e149bd506537f9358b498389b13953133cf8ce` | Invocation-ABI fuzz | Import; must run against merged `invocation_abi.go`, not Main's copy verbatim. | PR-02 |
| `scripts/abi-differential.mjs` | `b3eab49b3fc6561660fea5bd796babdfa1f15a5f81d024a3dedf79cbbfeb0b89` | Go/Rust corpus differential driver | Import; must execute both implementations. | PR-02 |
| `scripts/abi-differential.test.js` | `3212921a830b8d4f283580a874036a03ab5987bac5ab340ea988cde7fa29424a` | Differential tests | Import. | PR-02 |
| `runtimes/nemo-relay/bridges/nemo-crabedence/examples/abi_verdict.rs` | `dae092bee8b7edf127a5a8d15d73c0fe6284accf6ba40ff882313d31b089c25a` | Rust-side ABI example | Import only if schema-compatible; lives inside the provenance-managed nemo-relay tree — transfer-manifest impact must be recomputed. | PR-02 |
| `scripts/generate-source-inventory.mjs` | `4b3a0165433878f7c66dfcec5b16bb3fc813c1d686542a4e8ad30c90336ca668` | Source inventory generator | Import for PR-07 packaging. | PR-07 |
| `scripts/check-image-pins.mjs` | `e5798efc40a2ba5be327eb04b88818018f663c02d390fd0d4cb7f2dba3f81f46` | Image-pin checker | Import for PR-07 gate. | PR-07 |
| `scripts/check-image-pins.test.js` | `13f308a1b5e9569bb02a979dd49368a39789cfcbe37237252c56e741adabaa60` | Pin checker tests | Import. | PR-07 |

## 3. Conflict surfaces — modified on BOTH sides (three-way merge required)

These 12 paths changed on main **and** on the RC7.6 line. Column "retained
RC7.6 behavior" is the invariant that must survive the merge.

| Path | SHA-256 @ main | RC7.6 behavior to retain | Owning PR |
|---|---|---|---|
| `.github/workflows/ci.yml` | `c8a266f29ed37108b19217c74dd725029ef612e016cfbf6e20d2223158744455` | RC7.6 gates incl. sandbox/custody suites | PR-07 |
| `.github/workflows/stage-b.yml` | `519c4d4f43773f57f980ea8f6190eff51199c29397b090ba5d199bab4a3e4fd1` | RC7.6 staging gates | PR-07 |
| `CHANGELOG.md` | `dd2db18d00d8c9f4e3647790c501dd8ccbddd20e5dc2dd704f0d31ffdb6a2d36` | RC7.x history; RC8 entries go under Unreleased | PR-00+ |
| `internal/cli/checkpoint_capture_binary_test.go` | `675220c7a864496f2ee64e27794907c57e6012a66a51c8a04790ea4afde7d6aa` | RC7.6 checkpoint capture semantics | PR-02 |
| `internal/cli/run_test.go` | `cd05703fd5ff4b8605501225b4aef7c753a04bde83bcf59706775a294b53bc30` | RC7.6 run-path tests | PR-02 |
| `internal/evidence/evidence.go` | `379aa361a49f60ebb48bbecd49c798743bb16b48f60fcae800d2d5140e7446df` | RC7.6 evidence model (5 files added on RC7.6 side) | PR-02 |
| `internal/execution/config.go` | `021f01887527aab8c7e3a8b117c4b27a0ea29868ceb3774fceb105ee137f1403` | RC7.6 config incl. sandbox/custody wiring | PR-02 |
| `internal/execution/serve.go` | `e212e8d4ceefdd8acec9e7362227dd1540cfe2e9cb5bd50219716d7f829b0156` | RC7.6 serve path | PR-02 |
| `internal/execution/service.go` | `31daa5b4085d050912a6f87e997bc8ddd00ebd7cf61474666a8ffed1130dd76a` | RC7.6 dispatch/idempotency semantics | PR-02 |
| `qualification/msb-lane-image-pins.json` | `f923d14f65cfab6043a5e234f66e61a6df75da7fee97f7381d281c70668140fd` | **Signed-candidate pins win by default** (`f86821a7…` @ `13566f1a`); main's copy only via ADR-0001 decision + requalification | PR-07 |
| `runtimes/nemo-transfer-manifest.json` | `f758e695a00a91875d5003a43f77f56ffc3c8360add876247bda53ea75740a77` | RC7.6 frozen provenance rules; recompute only through the declared transfer delta | PR-02/07 |
| `scripts/package-source-archive.sh` | `e434d0ecce03380f092ad023a4a13554ea39388ae9f51a71a9e9f08574254970` | RC7.6 packager semantics (source-manifest embedding) | PR-07 |
| `scripts/package-source-archive.test.js` | `4f30416e0ea2704f42bc8104b9992481a01544f948c54b30511501244cdaf4ce` | Packager tests | PR-07 |

## 4. Main-modified, RC7.6-untouched — candidate clean takes (still hunk-reviewed)

| Path | SHA-256 @ main | Notes | Owning PR |
|---|---|---|---|
| `internal/applevmhelper/cli_darwin_arm64.go` | `669f335d0e5b71db50b6fd8f421658cd67e26decbf4b0a1bc4368f075d83ff98` | Identity-bound metadata-less deletion fix; overlaps PR-05 cleanup semantics — review against sandboxexecutor invariants | PR-05 |
| `internal/applevmhelper/cli_darwin_arm64_test.go` | `81038212456ad78db21d46392daf2e702715ab7b5cce5f5afd0ef7d25c9a3678` | Port with above | PR-05 |
| `internal/applevmhelper/protocol.go` | `f8e1acc6c7a948b320b96bb9f5b93a4413615ab09891ae26b4430c3b9e76061e` | Protocol support for above | PR-05 |
| `internal/execution/dispatch.go` | `e97e771dc12fb53814d5949b9d71510868354ced7ab974d3cabb2bfaa5457284` | Main-side dispatch changes — merge against RC7.6 UNKNOWN/at-most-once semantics | PR-02 |
| `internal/execution/invocation_abi.go` | `1f91e19327299854b840c4f48da7bb59de0c8ec350bdea2318cc9eb218c7f9a3` | Main ABI evolution — three-way vs RC7.6 additions (14 files added on RC7.6 side) | PR-02 |
| `internal/reconcile/worker.go` | `6efc0d08ddb951905877427c19ff11081319b4deebd93bf65163288ebde5e2a0` | Merge preserving stricter RC7.6 state machine | PR-02 |
| `docs/spec/durable-execution-contract.md` | `689e8e86e7d17e7fdc4b82656bb989fe5528472a0f2568e1df54d1801f330297` | Contract doc; reconcile with RC7.6 semantics | PR-02 |
| `qualification/README.md` | `3f1b6c32f8ee67ab4df4d44e5282c6978423759853587367e59a721c857c3ee9` | New on main | PR-07 |
| `qualification/provenance-reconciliation.md` | `b0ec05e35c72b585bd533eef63b284b941c66c709678ae3c18238707c515ad5f` | New on main | PR-07 |
| `qualification/source-inventory.json` | `073991b2548c15e0bd630f2abba436f7d44e2c9688a84cc969d9e293354dad2e` | Regenerate post-merge; do not carry a main-scoped inventory forward | PR-07 |

## 5. RC7.6-exclusive surface — preserved, never overwritten by Main import

RC7.6-side additions since merge-base (181 files). The directory set is the
preservation boundary from plan §4:

- `internal/sandboxexecutor/` — 41 files (backend_msb, cleanup_identity,
  recovery, server, maintenance, ledger, live tests)
- `internal/sandboxcustody/` — 8 files
- `internal/history/` — 19 files
- `internal/research/` — 4 files · `internal/dream/` — 5 files ·
  `internal/experience/` — 3 files
- `internal/execution/` — 14 added files · `internal/qualprovider/` — 7 ·
  `internal/evidence/` — 5 · `internal/sockfile/` — 6 ·
  `internal/idempotency/` — 1
- `qualification/required-tests.json` (13 common `TestMSBLive*` cases +
  `TestMSBLiveLinuxKVM`), `scripts/qualify-repository.sh`,
  `scripts/qualify-source-distribution.sh`, `scripts/verify-rc75-release.py`,
  evidence-inventory/release-paths libs, evidence fixtures, release records.

## 6. Merge execution rules

1. Every import lands through a topic branch `codex/rc8-prNN-*` →
   `codex/rc8-authority-integration` with its gate's test evidence.
2. At cherry time re-hash the source file; if it differs from the table above,
   refresh this inventory in the same commit (source identity changed —
   invariant 6).
3. No force-push after qualification evidence is generated for a commit.
4. Files marked "redesign/hand-merge" are never imported by directory copy.
