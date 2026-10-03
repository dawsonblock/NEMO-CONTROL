# Final Qualification Report

Release-integrity repair cycle for the extracted NEMO-CONTROL workspace.
Verdict and per-gate status are honest: a gate that did not run is `NOT_RUN`,
never PASS. Status vocabulary is defined in `PROVENANCE.md`.

## Artifact identity (tested bytes)

- Frozen source: `NEMO-feat-native-plugin-isolation`
  - `05d45ec86b1985b4aa4ba24f1315b96c858c56694c66116eae097cb68de06957`
  - 1,438 files, 10 symlinks (provenance format 2)
- Canonical runtime: `runtimes/nemo-relay`
  - `060719d750238e7de19527aca256262e4568dea09d311dfde08855dfdf97cba9`
  - 1,465 files, 10 symlinks, version `0.9.1-rc.4`, format 2
- Provenance policy: `runtimes/nemo-provenance-policy.json`
  - `0ffe1cc939bcaaf4d4c361d5a58d9bd4e2a39e009f0c89d6809c32988c3feba1`
- Declared source→runtime delta: 78 modified, 28 added, 1 removed file;
  0 link/retype/mode changes — all declared in `runtimes/nemo-transfer-manifest.json`
- Installed distribution (tested root):
  `dist/nemo-control_0.53.2_darwin_arm64`, component manifest
  `7a4585d24a0cbbca426bc68ebf3b418ac6e225175c7e974755816b06a95933ab`,
  6 components, unsigned (development build; no signing key configured)

## Gate results

| Gate | Command / check | Status |
|---|---|---|
| Frozen source identity | v2 digest of `NEMO-feat-native-plugin-isolation` | PASS |
| Runtime identity | `nemo-runtime-digest -manifest` (v2: files + symlinks + exec bits, generated paths excluded) | PASS |
| Source→runtime delta | every delta class declared; undeclared change fails | PASS |
| Require-source qualification | `--require-source` fails closed when frozen source absent | PASS (adversarial test) |
| Regeneration idempotency | `scripts/regenerate-nemo-provenance.sh` twice → byte-identical | PASS |
| Cross-language parity | Go `nemo-runtime-digest` vs Python `verify-nemo-transfer.py`, identical digests + record stream | PASS |
| Generated-file exclusion | protobuf pb2 paths bound by policy `generated_paths`; tree identity stable with/without them on disk | PASS |
| Golden fixture | fixed-tree v2 digest vector in `main_test.go`, agreed by both implementations | PASS |
| Doc-drift gate | `scripts/check-provenance-docs.sh` — PROVENANCE.md / README stats must match manifest | PASS |
| Rust workspace tests | `cargo test --workspace --locked --no-fail-fast` — all groups green incl. doctests | PASS |
| Clippy | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | PASS |
| Go digest tests | `go test ./cmd/nemo-runtime-digest` (v1 compat + v2 battery: symlinks, exec bits, generated paths, require-source, malformed manifests, duplicate blocks, incomplete deltas) | PASS |
| Worker test suite | 3,053 tests (baseline; worker tree untouched this cycle) | PASS |
| Dev-context e2e | 29 checks (baseline) | PASS |
| Installed-artifact qualification | `scripts/test-nemo-installed-distribution.sh` on the exact built root: manifest+sidecar verify, platform/version pin, 31 runtime checks, authority expiry, restart idempotency, 5-gate attestation `dist/…qualification.json` | PASS |
| macOS release lane | `package-plugin-host-app.py` supports real signing identity, notary profile, `--verify-release` rejecting ad-hoc-only artifacts; 10/10 script tests | PASS (implementation); NOT_RUN (real Developer ID signing — no credentials in this environment) |
| Release evidence pipeline | `generate-release-evidence.sh` now runs PROVENANCE as a mandatory gate; admission vocabulary PASS/FAIL/NOT_RUN, fail-closed | PASS (integration); NOT_RUN (full matrix needs clean tree + live PostgreSQL + signing authority) |
| SIGNED | Developer ID / allowed-signers signature on the exact qualified artifact | NOT_RUN — no signing key in environment; unsigned build is honest (`unsigned release root` noted by builder) |
| PUBLISHED | the exact signed artifact published | NOT_RUN |

## Defects fixed this cycle

1. Inline `#[cfg(test)]` module in `crates/cli/src/mcp_environment.rs` violated the
   architecture gate; body moved to `tests/coverage/shared/mcp_environment_tests.rs`
   behind the established `#[path]` shim (15 tests).
2. Six `plugin-host` process-backend tests collided on the global fixture proxy
   registration `fixture_intercept_sanitize_request`; serialized with a named
   `FIXTURE_NAMESPACE_GUARD` (20 acquisition sites, lock order: fixture → lease).
3. Python coverage `--lib` tests overflowed the default 2 MiB stack on the deep
   pyo3 async bridge (bounded ~3 MiB, passes at 4 MiB). Root cause of the
   `tokio-rt-worker` overflow: `pyo3_async_runtimes::TOKIO_RUNTIME` freezes at
   first `get_runtime()`; whichever test ran first set worker stacks process-wide.
   `init_python_test` now freezes the 8 MiB runtime up front, and all 77 coverage
   tests execute managed Python calls inside `with_test_stack` worker threads.
4. Clippy `large_enum_variant` on two runtime-state enums → `Option<Box<…>>`.
5. Clippy `unused doc comment` after guard insertion — comment re-anchored.

## Hardening delivered

- Provenance format 2: binds regular files, symlink targets, executable bits;
  typed delta classes (modified/added/removed/added-link/removed-link/
  retargeted/retyped/mode); policy-pinned exclusion of generated paths.
- Frozen-source requirement for official qualification (`-require-source`).
- Canonical verify/regenerate pair; documentation generated from the manifest
  and checked for drift.
- Format spec `runtimes/NEMO-PROVENANCE-FORMAT.md` + golden vector; Go/Python
  implementations agree byte-for-byte on the record stream.
- ABI spec clarified: fields present on the wire ≠ fields trusted;
  `authority_generation`/`authority_digest` accepted and overwritten, never trusted.
- Plugin isolation honest claims: hostile spellings refused by name,
  `hostile_code_boundary: false`, Windows unsupported backend typed and tested.
- macOS packaging distinguishes ad-hoc (local architecture qualification) from
  Developer ID + notarization (distribution), with a `--verify-release` gate.
- `generate-release-evidence.sh` invokes the transfer provenance verifier as a
  mandatory PROVENANCE gate — release evidence cannot be produced without it.

## Deferred / limitations

- **Phase 18 (fleet.ts decomposition):** deliberately not started. `worker/src/fleet.ts`
  is 24,278 lines; a responsibility-true decomposition is a dedicated refactor
  program, and a token extraction this late would only widen the change surface.
  Recorded as remaining work, not a defect.
- Full `generate-release-evidence.sh` matrix, real signing/notarization, and any
  Crabbox/remote clean-room run require a clean tree, live PostgreSQL, and
  signing authority not available in this environment → NOT_RUN above.
- `dist/` build is a debug-profile development artifact; qualification attestation
  binds it, but it is not a release candidate.

## Verdict

**QUALIFIED** for local/development qualification on `darwin_arm64`:
provenance chain, tests, static analysis, and installed-artifact qualification
all pass on the exact artifact described by the evidence.

**Not SIGNED, not PUBLISHED** — those lanes are NOT_RUN and must be executed
in a release environment before any distribution claim is made.
