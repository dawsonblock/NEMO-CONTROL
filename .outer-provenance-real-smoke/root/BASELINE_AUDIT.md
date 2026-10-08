# NEMO-CONTROL — Phase 0 Baseline Audit

Captured: 2026-10-02, on the workspace `/Users/dawsonblock/Downloads/NEMO-CONTROL`.

The "project" here is a **git checkout**, not a ZIP archive. The checkout is
pristine (`git status` clean, `HEAD = 5ee1f403cb07d07de377909cd78a81a99c4554e2`,
up to date with `origin/main`, remote `https://github.com/dawsonblock/NEMO-CONTROL.git`).
Extracting a second copy is impractical and unnecessary: the tree is ~78 GB
(mostly `target/` build caches) and git already provides the unmodified
original — every change this cycle makes is diffable against that commit.
`zip_sha256`: **NOT_APPLICABLE** (git checkout; consistent with the prior
baseline manifest).

## Trees and key files

| Role | Path |
| --- | --- |
| Frozen reference (provenance only) | `NEMO-feat-native-plugin-isolation/` |
| Canonical shipping runtime | `crabedence-V1-fix-integration-integrity/runtimes/nemo-relay/` |
| Authority/effect kernel | `crabedence-V1-fix-integration-integrity/` |
| Transfer manifest | `crabedence-V1-fix-integration-integrity/runtimes/nemo-transfer-manifest.json` |
| Provenance report (in-tree generated record) | `crabedence-V1-fix-integration-integrity/runtimes/nemo-relay/TRANSFER-PROVENANCE.md` |
| Prior provenance doc (outer) | `PROVENANCE.md` |
| Prior baseline manifest | `BASELINE-HARDENING-MANIFEST.json` |
| Runtime digest implementation | `crabedence-V1-fix-integration-integrity/cmd/nemo-runtime-digest/main.go` (+ `main_test.go`) |
| Stdlib-only verifier mirror | `crabedence-V1-fix-integration-integrity/scripts/verify-nemo-transfer.py` |
| CI transfer gate | `crabedence-V1-fix-integration-integrity/scripts/check-nemo-transfer-manifest.sh` |
| Packaging | `crabedence-V1-fix-integration-integrity/scripts/build-nemo-binaries.sh`, `build-nemo-distribution.sh`, `package-release.sh`; `runtimes/nemo-relay/python/plugin/build_backend.py` (PEP 517 backend generating the worker pb2 bindings) |
| Generated code | `runtimes/nemo-relay/crates/worker-proto/proto/nemo/relay/worker/v1/plugin_worker.proto` → `python/plugin/src/nemo_relay_plugin/_proto/plugin_worker_pb2{,_grpc}.py` via `grpc_tools.protoc` (also `generate_python_worker_proto_files` in `runtimes/nemo-relay/justfile`); Rust protos via `buf`/`tonic` build |
| Release qualification | `scripts/generate-release-evidence.sh`, `check-release-admission.sh`, `finalize-release-evidence.sh`, `package-release-evidence.sh`, `verify-release{,-source,-artifact}.sh`, `build-release-candidate.sh`, `release-config.sh`; `runtimes/nemo-relay/qualification/` |
| Installed-artifact tests | `scripts/test-nemo-installed-distribution.sh`, `test-nemo-runtime-e2e.sh`, `test-nemo-plugin-host.sh`, `test-nemo-critical-path.sh`, `test-nemo-expired-authority.sh`, `test-nemo-restart-idempotency.sh` |

## Tree counts (disk state at capture)

| Tree | All objects | Regular files | Symlinks | Dirs | Digest-eligible regular files* |
| --- | --- | --- | --- | --- | --- |
| `NEMO-feat-native-plugin-isolation/` | 8,125 | 6,715 | 10 | 1,400 | **1,438** |
| `runtimes/nemo-relay/` | 220,981 | 210,199 | 13 | 10,769 | **1,466** on disk / **1,464** canonical |
| `crabedence-V1-fix-integration-integrity/` (whole) | 234,475 | 221,953 | 39 | 12,483 | — |

\* Digest-eligible = regular files minus `target/`, `.git/`, `node_modules/`,
`.venv/`, `.uv-cache/`, `__pycache__/` (the tool's exclusion set).

Symlinks in digest scope (non-excluded): **10 per tree, identical sets** —
`crates/{adaptive,core,ffi,node,python}/LICENSE`, `CLAUDE.md`,
`integrations/pi/{package.json,index.ts,src}`, `.claude/skills`.
Note: the canonical tree's `.claude/` is **git-ignored**
(`crabedence-V1-fix-integration-integrity/.gitignore:53`), so `.claude/skills`
is absent in a clean checkout while it is a **git-tracked symlink** (mode
120000, blob `2b7a412b`) in the frozen tree — a symlink delta the current
manifest format cannot declare (its `removed_paths`/digest only carry
regular-file semantics; the `treeEntries` delta walk sees it, but the
declaration has no symlink class).

## Toolchains (measured)

| Tool | Version | Notes |
| --- | --- | --- |
| go | go1.26.5 darwin/arm64 | `go.mod` requires 1.26 |
| rustc/cargo | 1.96.1 via rustup inside `runtimes/nemo-relay` (`rust-toolchain.toml` pin); rustup default outside the tree reports 1.95.0 | pin is authoritative for the workspace |
| python3 | 3.12.0 | `.venv` inside the runtime tree carries 3.13 links |
| node | 24.16.0 | |
| npm | 11.13.0 | |
| just | 1.47.1 | |
| uv | 0.11.8 | |

## Identity verification (run before any modification)

| # | Command | Exit | Result |
| --- | --- | --- | --- |
| 1 | `find . -type f -not -path './target/*' \| sort -z \| xargs shasum -a 256 \| shasum -a 256` (frozen tree) | 0 | **`5c9f32e82c317eba918936a4e90d9b35cd18e4ee6dcd935397fea3fdb49f9526`, 1438 files — matches the declared frozen identity exactly** |
| 2 | Same command (shipping tree) | 0 | `1b6737624d67e301a4b612444eb5f39bcfccac006de5dfe374e2a30204ff2863`, 1466 files — **does not reproduce the declared digest**: the documented shell equivalent prunes only `target/` and therefore digests `.venv/` (4,123 files) and `__pycache__/` (250 files) pollution the tool excludes. Doc defect: the "equivalent" shell pipeline is not equivalent whenever those dirs exist. |
| 3 | Digest-eligible-only recompute minus the two generated pb2 files (all six exclusions) | 0 | **`f0e6ab9a28d27394a41f93b1a13e45dcb0ad4b10f9c7954bafa0913e75eb97b0`, 1464 files** — reproduces the stated canonical identity exactly |
| 4 | `go run ./cmd/nemo-runtime-digest -manifest runtimes/nemo-transfer-manifest.json` | 0 | PASS — `1bcf5f9d… (1466 files, 0.9.1-rc.4)`; inventory 3 members / 66 mods / 10 added paths; 4 binaries; generated blocks match; source `5c9f32e8… (1438)`; delta 66/29/1 all declared |
| 5 | `python3 scripts/verify-nemo-transfer.py` | 0 | PASS — identical output to #4 |
| 6 | `bash scripts/check-nemo-transfer-manifest.sh` | 0 | PASS — same checks |
| 7 | `git ls-files` + `git check-ignore` on the pb2 paths | 0 | **Both pb2 files are git-ignored generated output** (`python/plugin/.gitignore:11-12`), produced by `grpc_tools.protoc` in `build_backend.py` from `crates/worker-proto/proto/.../plugin_worker.proto`. They are present on disk only because packaging ran here — the manifest nonetheless declares them under `added_paths` and counts them in `file_count`/digest. **The defect reproduces exactly as stated: on a clean checkout the tree computes 1464/`f0e6ab9a` against a manifest declaring 1466/`1bcf5f9d`, and the declared additions cover nothing.** The current PASS is pollution-dependent. |
| 8 | `git ls-files -s` / `git check-ignore` on `.claude/skills` | 0 | Frozen: tracked symlink blob `2b7a412b`. Canonical: ignored (`.gitignore:53 .claude/`) — absent from canonical source; on-disk copy is local state. |

## Qualification/integrity gates (run before any modification)

| # | Command | Exit | Result |
| --- | --- | --- | --- |
| 9 | `cargo test --workspace --locked --no-fail-fast` (`runtimes/nemo-relay`) | 101 | **FAIL — 4 targets.** `-p nemo-relay-cli --lib`: 2 failed (`installation::marketplace::tests::doctor_validates_claude_host_registration_before_setup_doctor` — generated `.mcp.json` fails the doctor's own check; `server::tests::a_standalone_gateway_ignores_a_named_upstream` — expected 200, got 400). `-p nemo-relay-cli --test architecture_tests`: `tests_are_not_embedded_in_the_source_tree` (inline `#[cfg(test)]` in `crates/cli/src/mcp_environment.rs`). `-p nemo-relay-plugin-host --test process_backend`: 6 failed — shared in-process registration collisions under parallel threads. `-p nemo-relay-python --lib`: `test_guardrails_local_runtime_enforces_llm_input_and_output_checks` stack-overflows the default test-thread stack. |
| 10 | `cargo clippy --workspace --all-targets -- -D warnings` | 101 | **FAIL** — `clippy::large_enum_variant` ×2: `DynamicPluginCloseStatus` (`crates/node/src/api/mod.rs:6093`), `PluginHostCloseStatus` (`crates/python/src/py_plugin.rs:904`). Inherited upstream lint debt. |
| 11 | `node --test scripts/*.test.js scripts/*.test.mjs` | 0 | 1039 pass / 43 skipped (platform-gated) / 0 fail |
| 12 | `npm test --prefix nemo` (vitest) | 0 | 145 pass, 9 files |
| 13 | `npm test --prefix worker` (vitest) | 0 | 3053 pass / 2 skipped, 68 files |
| 14 | `python3 -m pytest runtimes/nemo-relay/scripts/tcb/` | 0 | 70 pass |
| 15 | `python3 -m pytest runtimes/nemo-relay/scripts/qualification/` | 0 | 113 pass |
| 16 | `go build ./...` (crabedence) | 0 | PASS |
| 17 | `go test -race -timeout=15m ./internal/{execution,capability,idempotency,authority,evidence,reconcile}` | 0 | PASS — all six packages |
| 18 | `node scripts/verify-version-consistency.mjs` | 0 | OK (0.53.2) |
| 19 | `bash scripts/check-nemo-credential-isolation.sh` | 0 | PASS — blocklist covers every credential name |
| 20 | `bash scripts/check-nemo-runtime-dependencies.sh` | 0 | PASS |
| 21 | `bash scripts/test-nemo-plugin-host.sh` | 0 | PASS — real process-boundary composition; malformed/unhonorable isolation policies fail closed |
| 22 | `bash scripts/test-nemo-installed-distribution.sh dist/nemo-control_0.53.2_darwin_arm64` | 0 | PASS — 31 e2e checks on shipped bytes + expired-authority + restart-idempotency suites; qualification attestation emitted and verified (5 gates) |
| 23 | `bash scripts/test-nemo-runtime-e2e.sh` | 0 | PASS — 29 checks |
| 24 | `go test ./...` (full Go suite incl. `internal/cli` ~13min) | — | NOT_RUN at baseline (deferred; documented ~13 min runtime) |
| 25 | `generate-release-evidence.sh` / `check-release-admission.sh` / `verify-release*.sh` / `publish-*.sh` / `codesign-macos.sh` (developer-id) | — | NOT_RUN — require clean tree, full CI gate matrix, signed tag/published artifacts, and Apple authority material respectively (per prior baseline) |

## Baseline findings (the reproduced inconsistency)

1. **PROV-1 (release-blocking): the archive fails its own transfer identity on
   clean source.** The manifest declares 1466 files / `1bcf5f9d` and lists the
   two generated `plugin_worker_pb2{,_grpc}.py` files under `added_paths`.
   Those files are git-ignored build outputs; a clean tree computes 1464 /
   `f0e6ab9a` (reproduced in #3). Verification only passes while stale
   generated output happens to sit on disk — provenance currently binds
   leftover build artifacts, not source. Phase 3 must remove them from
   declared source and exclude them by policy.
2. **PROV-2: symlinks are outside the digest identity.** The digest is a
   regular-file-only identity; a symlink add/remove/retarget changes nothing
   it binds (the delta walk catches it only when the frozen source is
   present, and the manifest cannot declare symlink classes). The tracked
   `.claude/skills` link exists in the frozen tree but is ignored/absent in
   canonical source — an unrepresentable removal under the current format.
   Phase 2 binds symlinks into a v2 canonical record.
3. **PROV-3: missing frozen source degrades to a note.** `verifyManifest`
   prints "source tree … is not present" and exits 0 when the frozen tree is
   absent — fine for standalone informational checks, unacceptable for
   official transfer-provenance qualification. Phase 5 adds the strict mode.
4. **PROV-4: digest documentation is self-inconsistent.** The documented
   shell "equivalent" prunes only `target/` while the tool excludes six
   directory classes — with `.venv/` present the two disagree (#2). The spec
   must name the full exclusion set (Phase 8 documents; Phase 1's policy
   file makes it machine-readable).
5. **PROV-5: manifest format is unversioned.** No `format_version` field;
   the parser neither requires nor rejects versions. Phase 8 adds v2 with
   explicit rejection of unsupported versions.
6. **TEST-1: two undeclared `nemo-relay-cli --lib` failures** beyond the
   previously documented set (doctor `.mcp.json` self-check; standalone
   gateway named-upstream 400-vs-200) — both adjacent to the
   `mcp_environment.rs`/MCP vendored drift. Resolved in Phase 9, not
   normalized.
7. **TEST-2/3/4 (previously documented):** inline-test placement in
   `mcp_environment.rs`; plugin-host process_backend shared-registry
   collisions under parallel tests; python guardrails stack overflow.
8. **LINT-1:** two `large_enum_variant` sites in the Node/Python binding
   close-status enums. Phase 10 resolves with boxing, not global allows.
9. Root `README.md`/`PROVENANCE.md` carry hand-maintained transfer stats —
   the drift class Phase 7 eliminates via generated values.

## Acceptance

The baseline independently reproduces the stated provenance inconsistency:
frozen = 1438/`5c9f32e8` ✓; canonical clean source = 1464/`f0e6ab9a` ✓;
declared = 1466/`1bcf5f9d` ✓; the two generated pb2 files are declared but
absent from canonical source ✓; `.claude/skills` is a tracked symlink in the
frozen tree and unrepresented in the canonical runtime's declaration ✓.
