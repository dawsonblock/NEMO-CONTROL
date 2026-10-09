# Final Qualification Report

Qualification evidence for the extracted NEMO-CONTROL workspace.
Verdict and per-gate status are honest: a gate that did not run is `NOT_RUN`,
never PASS. Status vocabulary is defined in `PROVENANCE.md`.

## Artifact identity (tested bytes)

The identity this report qualifies. Every value below was produced by the
canonical pipeline (or the lane named beside it) executed in this environment
against these exact bytes; the machine-readable records live in
`crabedence-V1-fix-integration-integrity/dist/release-evidence/`.

- Source commit: `0725423a7bc90b924859e827abe4af1f97bcdfa3`
  (branch `fix/execution-admission-and-qualprovider-durability`)
- Source tree: `406b6ae21fceb531b7c37ccd730dd2e66e586cf2`
- Frozen source: `NEMO-feat-native-plugin-isolation`
  - `05d45ec86b1985b4aa4ba24f1315b96c858c56694c66116eae097cb68de06957`
  - 1438 files, 10 symlinks (provenance format 2)
- Canonical runtime: `runtimes/nemo-relay`
  - `f2033ac7eddc2ee8f5b35c2ad8a3d5a3260f8e4aad03d761f3959918ba011776`
  - 1466 files, 10 symlinks, version `0.9.1-rc.4`, format 2
- Provenance policy: `runtimes/nemo-provenance-policy.json`
  - `0ffe1cc939bcaaf4d4c361d5a58d9bd4e2a39e009f0c89d6809c32988c3feba1`
- Declared source→runtime delta: 79 modified, 29 added, 1 removed file
  (10 declared added entries); 0 link/retype/mode changes — all declared
  in `runtimes/nemo-transfer-manifest.json`
- Qualification run: `RELEASE_VERSION=0.54.0-rc.1`, `GOTOOLCHAIN=local`
  `go1.26.5`, live gates against a managed PostgreSQL 16 (initdb fallback),
  qualified at `2026-10-09T03:47:50Z`
- Evidence root: `0d45ba24d8b67f6f7107f7e19be766de3b10b4476909ec3819f9a9a5caf8dcc5`
  (`evidence-root.json`; per-gate records and log digests in
  `dist/release-evidence/gates/` and `gate-results/`)

## Supersession record (descriptor boundary)

The plugin host now marks every inherited descriptor close-on-exec before
`exec` (`crates/plugin-host/src/supervisor.rs`, with the sweep ceiling in
`limits.rs`), so a descriptor the kernel process holds without close-on-exec
can no longer cross into the host and through it into a plugin; the intercept
fixture witnesses descriptors by inode identity, and the runtime e2e plants a
caller descriptor and asserts it does not cross (with the boundary removed the
same check fails `canary_fds=3`). Marking rather than closing is deliberate:
the standard library keeps a private close-on-exec pipe between parent and
child to report an `exec` failure, and a sweep that closed descriptors closed
that pipe first. That move, together with the admission and qualification
fixes below, produced the identity this report now binds — the pipeline was
rerun for it, and the results are the table in "Qualification run" below. The
previous identity `e1279ef2…` (1466 files, 78 modified / 29 added / 1 removed)
was qualified by the prior revision of this report; its verdict applies only
to those bytes.

## Supersession record (prior cycle)

That cycle replaced the one before it: it bound runtime digest
`060719d750238e7de19527aca256262e4568dea09d311dfde08855dfdf97cba9`
(1465 files, 10 symlinks) and a 78 modified / 28 added / 1 removed delta, and
superseded it when the `.claude/skills` provenance symlink became tracked and
packaged, `security/PLUGIN-ISOLATION-HISTORY.md` appeared, deployment mode
failed closed, and source packaging verified the emitted archive. A QUALIFIED
verdict binds exact bytes and never carries forward silently;
`scripts/check-provenance-docs.sh` binds this report to the manifest so a tree
that moves past its qualified identity fails the docs gate until the report is
regenerated.

## Qualification run

The canonical pipeline (`scripts/generate-release-evidence.sh`, run through
`scripts/test-live-postgres.sh` so the live gates have PostgreSQL) executed
against the identity above: **32/32 gates PASS, 0 failed, 0 skipped, RELEASE
ADMISSION PASS**, all 22 CRAB-V1 invariants, evidence root `0d45ba24…`.

| Gate | Type | Tests | Status |
|---|---|---|---|
| source_manifest | PROVENANCE | — | PASS |
| exact-toolchain | BUILD | — | PASS (`declared = installed = runtime = go1.26.5`, `GOTOOLCHAIN=local`) |
| go-vet | STATIC_ANALYSIS | — | PASS |
| go-evidence-tests | TEST | 237 | PASS |
| go-tart-tests | TEST | 391 | PASS |
| go-lume-tests | TEST | 74 | PASS |
| go-shared-tests | TEST | 323 | PASS |
| go-race-evidence | TEST | 189 | PASS |
| go-race-providers | TEST | 788 | PASS |
| effect-fabric-contract | TEST | 31 | PASS |
| effect-fabric-reconciliation | TEST | 32 | PASS |
| effect-fabric-evidence | TEST | 14 | PASS |
| effect-fabric-post-dispatch-timeout | TEST | 2 | PASS (32s ambiguous-wait + 65s late-response, real wall-clock) |
| effect-fabric-race | TEST | 912 | PASS |
| registry-digest | PROVENANCE | — | PASS |
| nemo-transfer-provenance | PROVENANCE | — | PASS |
| postgres-fencing | INTEGRATION | 4 | PASS |
| postgres-parity | INTEGRATION | 4 | PASS |
| effect-fabric-postgres | INTEGRATION | 146 | PASS |
| provider-github-faults | FAULT_INJECTION | 7 | PASS |
| provider-github-real-api | — | — | SKIP (the gate's own "not applicable" semantics: no test token/repo configured) |
| authority-postgres | INTEGRATION | 11 | PASS |
| critical-external | INTEGRATION | 16 | PASS |
| critical-faults | FAULT_INJECTION | 2 | PASS |
| cross-language-conformance | TEST | 104 | PASS |
| worker-typecheck | STATIC_ANALYSIS | — | PASS |
| worker-tests | TEST | 3053 | PASS |
| worker-format | STATIC_ANALYSIS | — | PASS |
| worker-lint | STATIC_ANALYSIS | — | PASS |
| worker-build | BUILD | — | PASS |
| nemo-typecheck | STATIC_ANALYSIS | — | PASS |
| nemo-tests | TEST | 145 | PASS |
| evidence-secret-scan | PROVENANCE | — | PASS |

Lanes outside the pipeline, executed against the same identity:

| Lane | Command / check | Status |
|---|---|---|
| Rust workspace tests | `cargo test --workspace --locked --no-fail-fast` | PASS (rerun: 5353 passed / 47 ignored / 0 failed across 106 targets) |
| Plugin-host crate | `cargo test -p nemo-relay-plugin-host` | PASS (rerun: 128 lib tests + architecture / lifecycle / limits / platform-boundary / process-backend suites) |
| Clippy / fmt (changed crate) | `cargo clippy -p nemo-relay-plugin-host --all-targets --all-features -- -D warnings`; `cargo fmt --check` | PASS (rerun) |
| Runtime e2e | `scripts/test-nemo-runtime-e2e.sh` | PASS (rerun: 30 checks, including the new descriptor canary; mutation check fails `canary_fds=3`) |
| Critical-path e2e | `scripts/test-nemo-critical-path.sh` | PASS (rerun: CRITICAL commit with evidence through the deployed service and provider) |
| Full Go suite | `go test -race -timeout=20m ./...` | PASS (rerun: every package green, `internal/cli` 1162s — the prior cycle's nested-checkout carve-out did not reproduce) |
| Live-PostgreSQL matrix | `scripts/test-live-postgres.sh` — `TestLive` across idempotency / reconcile / execution / authority | PASS (rerun, `-race`; the 100-way concurrency qualification classifies ceiling refusals: 50 of 100 refused pre-dispatch, `counter=1`) |
| Qualification provider regressions | `go test ./internal/qualprovider/` + crash-phase and injected-failure suites | PASS (rerun: 20 tests; a mutation check that disables the repair fails the suite) |
| Admission ceilings | `go test ./internal/execution/ -run TestAdmission\|TestConnectionCeiling\|TestHandshakeCeiling\|TestHeaderTimeout\|TestStopDrains` | PASS (rerun: 6 tests, each red before the fix) |
| Provenance gates | `check-nemo-transfer-manifest.sh`; `check-provenance-docs.sh`; `verify-nemo-transfer.py --require-source` | PASS (rerun, cross-language parity on the new identity) |
| Credential isolation | `scripts/check-nemo-credential-isolation.sh` | PASS (rerun) |
| Evidence checkpoints | `go test ./internal/evidence/` — sign/verify roundtrip; a rewritten covered field, a deleted or reordered covered record, a store rolled back below the covered count, an untrusted signer, a tampered signed field, and a signer/public_key mismatch all fail; appended records do not disturb an older checkpoint | PASS (rerun) |
| Terminal-evidence enumeration | `TestStoreConformanceTerminalEvidence` on both engines (postgres under the live DSN): every terminal record enumerated in execution_id order with its immutable digests and provider identity; non-terminal records excluded | PASS (rerun) |
| Checkpoint emission | `go test ./internal/execution/ -run TestEmitCheckpoint` — emitted file verifies; sequence increments; an unreadable existing file is refused rather than overwritten | PASS (rerun) |
| Independent verifier CLI | `go test ./cmd/evidence-checkpoint/` — end-to-end: emit → verify → tamper → rollback → usage, over a real sqlite store | PASS (rerun) |
| NEMO Relay Python binding | `just test-python` | CARRIED (no files on that surface changed this cycle; last qualified against `e1279ef2…`) |
| NEMO Relay Node binding | `just test-node` | CARRIED (same reason) |
| NEMO Relay Go binding | `just test-go` | CARRIED (same reason) |
| Installed-artifact qualification | `scripts/test-nemo-installed-distribution.sh` | NOT_RUN — the `dist/` build is from the superseded identity; building and qualifying a new one is the release lane |
| Source-packaging clean room | `package-source-archive.sh` + extraction verification | NOT_RUN this cycle (no packaging change; last qualified against `e1279ef2…`) |
| macOS release lane | Developer ID signing + notarization | NOT_RUN — no signing authority in this environment |
| SIGNED | signature on the exact qualified artifact | NOT_RUN |
| PUBLISHED | the exact signed artifact published | NOT_RUN |

## Defects fixed this cycle

1. **Unbounded execution admission (release-blocking for hostile-local
   use).** The accept loop spawned a handler goroutine per accepted
   connection with no ceiling, and a silent connection held a handler for the
   full request lifetime. Admission is now bounded before any goroutine
   exists (`CRABEDENCE_MAX_CONNECTIONS`, default 64), the unauthenticated
   phase has its own smaller ceiling (`CRABEDENCE_MAX_HANDSHAKES`, default
   16), refusals are explicit and definitive (`FAILED`/`EXECUTION_BUSY`,
   pre-dispatch, retry-safe), the length prefix has a 5s bound, and `Stop`
   drains in-flight handlers.
2. **Qualification provider could diverge on an intermediate write
   failure.** The ledger was appended before the artifact was written and the
   dedup map was not updated on that path, so a retry appended a second
   record for the same token; startup silently skipped unparseable ledger
   lines, artifacts were written `O_TRUNC`, and reads followed symlinks. The
   commit is now a recoverable two-phase protocol (durable PREPARED, artifact
   with temp write + fsync + atomic rename + parent fsync, durable COMMITTED;
   acknowledgement last), startup refuses state it cannot interpret, and a
   repeated token can never execute twice across a crash.
3. **Inherited descriptors crossed into the plugin host.** The spawn cleared
   the environment but not the descriptor table; the boundary now marks
   inherited descriptors close-on-exec between `fork` and `exec`, preserving
   the confined host's kernel channel (see the descriptor-boundary
   supersession record).
4. **The 100-way concurrency qualification failed on bounded-service
   refusals.** It now classifies `EXECUTION_BUSY` and pre-dispatch transport
   refusals separately from mutation outcomes while keeping the
   exactly-one-dispatch assertion.
5. **Store invariant counters were collected but not exported.** Fence
   rejections, conflicting provider observations, lost leases, epoch and
   recovery rejections and denied CRITICAL receipts now travel on
   `reconciler-status.json` via `Health.InvariantCounters`.

6. **No independently-held anchor over the terminal evidence set.** A
   receipt left in the same store as the record it describes is rewritten
   or deleted with it, and a store rolled back to an earlier snapshot
   silently loses the executions that happened after it. The service now
   periodically commits the canonical terminal-evidence enumeration to a
   signed checkpoint (`CRABEDENCE_CHECKPOINT_PATH`,
   `CRABEDENCE_CHECKPOINT_INTERVAL`) that an operator archives
   independently, and `cmd/evidence-checkpoint` is the verifier that
   proves a held checkpoint still covers the store — a deleted,
   rewritten, reordered or rolled-back covered record fails, while
   records appended afterwards do not disturb an older checkpoint.

## Deferred / limitations

- **Phase 18 (fleet.ts decomposition):** deliberately not started.
  `worker/src/fleet.ts` is 24,278 lines; a responsibility-true decomposition
  is a dedicated refactor program. Recorded as remaining work, not a defect.
- Real signing/notarization, publication, and `provider-github-real-api`
  require signing authority and test credentials not available in this
  environment → `NOT_RUN` above.
- The Python/Node/Go binding lanes are carried: no files on those surfaces
  changed this cycle, and the Rust workspace suite that backs them passed on
  this identity.
- The live PostgreSQL gates ran against a local PostgreSQL 16 started by
  `scripts/test-live-postgres.sh` (initdb fallback; Docker unavailable in
  this environment). A reused database across pipeline runs flips
  `postgres-parity` — the gate requires a fresh database per run, which the
  script provides.
- The macOS release lane needs a Developer ID identity and a notary profile;
  nothing in this environment can produce them, so the restricted-macos
  confinement cannot be exercised here (its refusal paths are covered by
  unit tests).
- Residual audit findings recorded, not fixed: no dial-time IP policy in the
  provider transport (mitigated by TLS validation, redirect refusal, and
  plaintext restricted to loopback); the receipt does not directly carry the
  policy/registry digest or authoritative timestamps; the signer is not yet a
  separate service identity.
- The workspace git root is the NEMO-CONTROL umbrella, so the packager's
  dirty-tree check also sees the sibling trees' tracked modifications; in the
  standalone Crabedence checkout the release workflow runs with the root as
  the checkout root, as designed.

## Verdict

**Locally qualified for the executed gate set on `darwin_arm64`** for source
commit `0725423a`, source tree `406b6ae2`, runtime `f2033ac7…` (1466 files,
79 modified / 29 added / 1 removed): the canonical pipeline passed 32/32
gates with RELEASE ADMISSION PASS and evidence root `0d45ba24…`, the Rust
workspace lane and the runtime e2e passed on the same bytes, and the
provenance gates agree on the identity.

**Not SIGNED, not PUBLISHED.** The installed-distribution qualification, the
packaging clean room, and the macOS signing/notarization lane are `NOT_RUN`
for this identity — they belong to the release environment. The binding lanes
are carried from the previous cycle and must be rerun there if any file on
those surfaces changes.
