# Final Qualification Report

Qualification evidence for the extracted NEMO-CONTROL workspace.
Verdict and per-gate status are honest: a gate that did not run is `NOT_RUN`,
never PASS. Status vocabulary is defined in `PROVENANCE.md`.

## Artifact identity (tested bytes)

The identity this report qualifies. Every value below was produced by the
canonical pipeline (or the lane named beside it) executed in this environment
against these exact bytes; the machine-readable records live in
`crabedence-V1-fix-integration-integrity/dist/release-evidence/`.

- Source commit: `369d2860fe38a9afd4696b9f6218fb6bdb2b29e0`
  (branch `fix/rc3-pr03-deterministic-evidence`)
- Source tree: `3306903e7b293dd69c835548d9347e2ed2f8443d`
- Frozen source: `NEMO-feat-native-plugin-isolation`
  - `05d45ec86b1985b4aa4ba24f1315b96c858c56694c66116eae097cb68de06957`
  - 1438 files, 10 symlinks (provenance format 2)
- Canonical runtime: `runtimes/nemo-relay`
  - `f6229bb342d31fc1fa3224fd24b53490ceb507e4489f305605bb274947c16d0f`
  - 1466 files, 10 symlinks, version `0.9.1-rc.4`, format 2
- Provenance policy: `runtimes/nemo-provenance-policy.json`
  - `0ffe1cc939bcaaf4d4c361d5a58d9bd4e2a39e009f0c89d6809c32988c3feba1`
- Declared source→runtime delta: 80 modified, 29 added, 1 removed file
  (10 declared added entries); 0 link/retype/mode changes — all declared
  in `runtimes/nemo-transfer-manifest.json`
- Qualification run: `RELEASE_VERSION=0.54.0-rc.3`, `GOTOOLCHAIN=local`
  `go1.26.5`, live gates against a local PostgreSQL 14.20 started by
  `initdb` (Docker daemon read-only in this environment; the CI image
  lane `postgres:16` is `NOT_RUN` here), qualified at `2026-10-10T03:29:33Z`
- Evidence root: `177a3afb7492078684cc0573aa8ae5c3d89f9df4dff570c8e68d2a81954fb681`
  (`evidence-root.json`; per-gate records and log digests in
  `dist/release-evidence/gates/` and `gate-results/`)

## Supersession record (rc.3 clean-room lane, F-010/F-011)

An earlier revision of this cycle qualified commit `24a493a4` (evidence
root `4db59160…`) and packaged release artifacts bound to it. Running the
`release-rc.yml` clean-room steps locally on those staged bytes exposed
two latent defects that made the lane unpassable on any shipped archive:
the manifest verifier's self-exemption covered only the passed manifest
path, so the embedded `release-evidence/source-tree-sha256.txt` always
failed the inverse check (`unexpected=1`) whenever verification ran
against the published manifest (F-010); and the schema validator could
never resolve — the verifier preferred the in-tree script whose `ajv`
dependency the archive deliberately does not ship, while the workflow
installed dependencies at `clean-room/nemo` without copying the validator
script there (F-011). Both were fixed (PR-12), the pipeline reran on the
repaired tree, and this report now binds commit `369d2860`; the previous
verdict applies only to its bytes.

## Supersession record (rc.3 corrective cycle, descriptor inventory)

The rc.3 corrective cycle moved the runtime identity again. The bounded
3..65_536 close-on-exec sweep qualified below was still incomplete: a
descriptor planted above the ceiling crossed `exec` unmarked. The parent
now inventories its open descriptors before the fork boundary
(`close_range(CLOSE_RANGE_CLOEXEC)` on Linux, a `proc_pidinfo` inventory
on macOS) and marks every inherited descriptor — the kernel channel
remains the one preserved fd, marking (not closing) still protects the
child-error pipe, and a real fork/exec regression proves a marked
descriptor is lost while the preserved one survives. The high-fd lane
(fd 70_000) is qualified on a Linux aarch64 host — the macOS host's
kernel ceiling (61440) cannot place it and reports SKIP. The runtime
identity moves to `f6229bb3…` (1466 files, 80 modified / 29 added /
1 removed); `libc` joins `plugin-host` for the two syscalls rustix 1.1.4
does not wrap, and the TCB budget raise is recorded in `security/tcb.toml`
with its rationale. The previous identity `f2033ac7…` (1466 files,
79 modified / 29 added / 1 removed) was qualified by the prior revision
of this report; its verdict applies only to those bytes. The same cycle
made execution `Stop` linearizable against admission (PR-04), made the
evidence inventory canonical across generation/finalization/packaging
(PR-06), made source packaging portable across BSD and GNU tar (PR-07),
and gave evidence checkpoints a retained append-only sequence with a
scoped custody path (PR-08).

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

## Corrective record (v0.54.0-rc.2, F-001)

The rc.2 audit found a real defect in the checkpoint feature qualified at
`0725423a`: terminal evidence was enumerated in `execution_id` order, but
execution ids are random UUIDv4 — not terminalization order — so a record
that terminalized late legitimately inserted into the middle of an
already-checkpointed prefix and invalidated it. The repair makes the
enumeration append-only by construction: schema migration 17 adds a
`terminal_seq` column and a single-row `terminal_counter` on both engines;
each terminalization (`Finalize`, `ResolveRecovery`) allocates its position
inside the same transaction as the terminal write, so a rolled-back or
CAS-losing attempt leaves no gap and the counter lock makes sequence order
equal durable commit order under concurrent writers. Existing terminal rows
backfill in `(updated_at, execution_id)` order; a convergence pass at every
open heals rolling-upgrade stragglers at the ledger end, and a terminal row
still lacking a position is a fail-closed enumeration error. Checkpoints are
now `evidence-checkpoint-v2`, binding each covered record's ledger position
into the chain (renumbering is detected like rewriting); v1 checkpoints
remain verifiable under their own semantics. The commit-order regression
test fails on the previous implementation and passes on this one. The
pipeline was rerun for this identity; the results are the table below, and
the prior verdict applies only to its bytes.

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

The canonical pipeline (`scripts/generate-release-evidence.sh`, with
`CRABBOX_TEST_DATABASE_URL` pointed at a local `initdb` PostgreSQL so the
live gates have a database) executed against the identity above:
**32/32 gates PASS, 0 failed, RELEASE ADMISSION PASS**, all 22 CRAB-V1
invariants, evidence root `177a3afb…`. `provider-github-real-api` is the
one SKIP — its own "not applicable" semantics, no test token/repo
configured — and is not counted among the 32 gate records.

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
| effect-fabric-evidence | TEST | 40 | PASS |
| effect-fabric-post-dispatch-timeout | TEST | 2 | PASS (32s ambiguous-wait + 65s late-response, real wall-clock) |
| effect-fabric-race | TEST | 964 | PASS |
| registry-digest | PROVENANCE | — | PASS |
| nemo-transfer-provenance | PROVENANCE | — | PASS |
| postgres-fencing | INTEGRATION | 4 | PASS |
| postgres-parity | INTEGRATION | 4 | PASS |
| effect-fabric-postgres | INTEGRATION | 158 | PASS |
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

Lanes outside the pipeline, executed against the same identity unless
noted otherwise:

| Lane | Command / check | Status |
|---|---|---|
| Plugin-host crate — Linux aarch64 | `cargo test -p nemo-relay-plugin-host` (lima VM, kernel fd ceiling 1048576) | PASS — 126 lib + 5 architecture + 34 process-boundary + lifecycle/limits suites; `inherited_descriptor_above_the_legacy_ceiling_is_marked` plants fd 70_000 and verifies it is marked close-on-exec; the real fork/exec regression proves a marked descriptor is lost and the preserved kernel channel survives |
| Plugin-host crate — macOS arm64 | `cargo test -p nemo-relay-plugin-host` | PASS — same suite minus the fd-70_000 placement (host kernel ceiling 61440; the check reports SKIP locally by design) |
| Clippy (changed crate) | `cargo clippy -p nemo-relay-plugin-host --all-targets --all-features -- -D warnings` | PASS |
| Rust workspace tests | `cargo test --workspace --locked --no-fail-fast` | NOT_RUN this cycle — the plugin-host crate suite is the changed surface; last full-workspace qualified against `f2033ac7…` |
| Runtime e2e | `scripts/test-nemo-runtime-e2e.sh` | NOT_RUN this cycle — last qualified against `f2033ac7…`; the descriptor containment it exercises is covered on this identity by the plugin-host process-boundary suite above |
| Critical-path e2e | `scripts/test-nemo-critical-path.sh` | NOT_RUN this cycle — last qualified against `f2033ac7…` |
| Full Go suite | `go test -race -timeout=20m ./...` | PASS — every package green including `internal/cli` (1056s); checkpoint config/emission regressions included |
| Live-PostgreSQL matrix | `scripts/test-live-postgres.sh` — `TestLive` across idempotency / reconcile / execution / authority | PASS (`-race`, local `initdb` PostgreSQL 14.20 — the Docker `postgres:16` lane is NOT_RUN, daemon read-only in this environment) |
| Stop/admission boundary | deterministic barrier test + 1000-schedule randomized campaign (`internal/execution/stop_accept_race_test.go`) | PASS — a handler can no longer register after the drain decision; refusals post-stop verified; campaign 1.15s |
| Transport-refusal classification | `TestConcurrentIdenticalMutations` — 100-way burst against bounded admission | PASS — definitive FAILED frames and pre-frame closes both counted as fail-closed refusals; zero successes, zero mutations |
| Provenance gates | `check-provenance-docs.sh`; `verify-nemo-transfer.py`; `cmd/nemo-runtime-digest` verify | PASS on `f6229bb3…` — manifest regenerated, delta 80 modified / 29 added / 1 removed all declared, policy and baseline-source digests unchanged |
| Checkpoint custody | `go test ./internal/execution/ -run TestEmitCheckpoint` + `go test ./internal/evidence/` + `go test ./cmd/evidence-checkpoint/` | PASS — every emission retained in `<path>.jsonl`, sequence survives latest-file loss, corrupt retained tail refuses emission, custody path mirrors latest + log; **independent custody itself is NOT_QUALIFIED as a deployment property** — it requires the custody target to live outside the service host's failure domain, which this environment does not provide |
| Source-packaging clean room | `package-source-archive.sh --format tar.gz\|zip` + extraction verification | PASS — both formats built and verified on extracted bytes (manifest 4115 entries, transfer provenance ok); tar.gz `ab1b6069…`, zip `7999cdcd…`; both BSD-tar and GNU-tar branches exercised in the packager suite |
| Release-artifact binding | `artifact.json` schema v2 (the `release-rc` build-job object) | PASS — binds the qualified source `369d2860`/`3306903e`, manifest `ee07a945…`, both archive digests+sizes, the CycloneDX SBOM `3a5bf473…`, the registry, qualification `84910888…` and provenance digests, toolchain `go1.26.5`/`v24.16.0`/`11.13.0` |
| Evidence-bundle packaging | `finalize-release-evidence.sh` + `package-release-evidence.sh` | PASS — `crabedence-0.54.0-rc.3-release-evidence.tar.gz` `97540ebc…`; the bundle is FINALIZED (artifact-bound): `artifact.json` is covered by `SHA256SUMS`, `evidence-manifest.json` `05ee5af8…` (95 files), evidence root `177a3afb…` |
| Release clean room | the `release-rc.yml` `clean-room-verify` steps run locally on the staged bytes | PASS — published `SHA256SUMS` self-check clean; both extracted trees verify the published source manifest with the shipped verifier (`unexpected=0`); tar/zip inventories identical; `qualify-source-distribution` PASS on each tree; `verify-release-artifact --mode release` 45/45 including schema validation through the materialized `clean-room/nemo` pinned `ajv` |
| NEMO Relay Python binding | `just test-python` | CARRIED — no files on that surface changed this cycle; last qualified against `f2033ac7…` |
| NEMO Relay Node binding | `just test-node` | CARRIED (same reason) |
| NEMO Relay Go binding | `just test-go` | CARRIED (same reason) |
| Installed-artifact qualification | `scripts/test-nemo-installed-distribution.sh` | NOT_RUN — release lane; no binary artifact was produced in this environment |
| macOS release lane | Developer ID signing + notarization | NOT_RUN — no signing authority in this environment |
| GoReleaser binary candidate | `scripts/build-release-candidate.sh` (credential-free producer, `vX.Y.Z` final tags only) | NOT_RUN — rejects `-rc` tags by design and requires the merged authorize-source record on `main`; the rc deliverable is the source-archive object above, which is bound |
| Attestation | `actions/attest` SLSA + qualification predicate | NOT_RUN — requires GitHub OIDC (`id-token: write`); the attestation subjects are the staged bytes verified above |
| SIGNED | signature on the exact qualified artifact | NOT_RUN |
| PUBLISHED | the exact signed artifact published | NOT_RUN |

## Defects fixed this cycle (rc.3 corrective register)

1. **F-005 — `Stop()` could race a late `handlers.Add(1)`.** The accept
   loop registered accepted connections after `handlers.Wait()` could
   already observe zero, so a connection served after the service
   reported stopped. Admission and lifecycle now move under the service
   mutex (running→stopping→stopped), the accept loop is joined before
   the drain, and a drain timeout cannot report a clean stop.
2. **F-004 — descriptor sweeping was capped below high-numbered fds.**
   The bounded 3..65_536 sweep is replaced by an open-descriptor
   inventory (`close_range` on Linux, `proc_pidinfo` on macOS) marking
   every inherited descriptor `CLOEXEC`; the kernel channel is
   preserved; a planted fd 70_000 verifies on Linux and reports SKIP on
   hosts that cannot place it.
3. **F-008 — evidence inventory disagreement.** Finalization silently
   pruned hidden entries the packager rejected. One canonical inventory
   (`scripts/lib/evidence-inventory.sh`) now binds generation,
   finalization, verification and packaging: strays fail closed,
   attestation members in sealed bundles ship.
4. **F-009 — nonportable `tar --format=gnutar`.** The packager detects
   the tar implementation and uses its own spelling (`--format=gnu` /
   `--format=gnutar`); both write the same on-disk format.
5. **F-006 — no retained checkpoint sequence or custody path.** Every
   emission is now appended to a tamper-evident `<path>.jsonl` (the
   sequence authority; a corrupt tail refuses emission), and
   `CRABEDENCE_CHECKPOINT_CUSTODY_PATH` mirrors the sequence onto a
   second target. Independent custody is a deployment property the
   service cannot verify: with no custody target the startup report
   says so and this report scopes the property NOT_QUALIFIED.
6. **F-007 — stale transfer manifest.** Regenerated: shipped identity
   `f6229bb3…` (80 modified / 29 added / 1 removed, all declared);
   the hand-edited provenance documents restate it.
7. **Q-001 — stale release identity.** `VERSION` and every
   version-carrying surface moved `0.54.0-rc.1` → `0.54.0-rc.3`;
   `verify-version-consistency.mjs` passes.
8. **Q-002 — qualification evidence.** The canonical pipeline reran
   (32/32 PASS) on the exact corrected tree; lane results above record
   honest PASS / NOT_RUN per surface.
9. **F-010 — the clean-room source-manifest check could never pass.**
   `verify-source-manifest.sh` exempted only the passed manifest path
   from its inverse check, so verifying an extracted archive against the
   *published* manifest always failed on the packager-embedded
   `release-evidence/source-tree-sha256.txt` (`unexpected=1`). The
   embedded copy is now exempt exactly when it is byte-identical to the
   manifest under verification — which also newly proves the shipped
   self-identity equals the published record. A divergent copy still
   fails closed.
10. **F-011 — the clean-room schema validator could never resolve.** The
    verifier preferred the in-tree `validate-schema.mjs`, which cannot
    resolve `ajv` where the archive deliberately ships no
    `node_modules`; and the workflow installed dependencies at
    `clean-room/nemo` without ever copying the validator script there,
    so the resolved candidate did not exist. The verifier now prefers
    `dirname(evidence)/nemo/scripts/validate-schema.mjs`, and both
    clean-room install steps copy the script beside the pinned
    dependencies.

Prior-cycle defect records are below, unchanged — their verdicts apply
to the bytes they qualified.

## Defects fixed in the previous cycle

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
- The live PostgreSQL gates ran against a local PostgreSQL 14.20 started
  by `initdb` (Docker daemon read-only in this environment — the CI image
  lane `postgres:16` is `NOT_RUN` here). A reused database across pipeline
  runs flips `postgres-parity` — the gate requires a fresh database per
  run.
- Independent checkpoint custody is implemented but scoped NOT_QUALIFIED:
  `CRABEDENCE_CHECKPOINT_CUSTODY_PATH` mirrors the retained checkpoint
  sequence, and custody is only independent when that storage lives
  outside the service host's failure domain — a deployment property this
  environment cannot establish.
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
commit `369d2860`, source tree `3306903e`, runtime `f6229bb3…` (1466 files,
80 modified / 29 added / 1 removed): the canonical pipeline passed 32/32
gates with RELEASE ADMISSION PASS and evidence root `177a3afb…`, the
plugin-host crate suite passed on both this host and a Linux aarch64
target (including the fd-70_000 lane the macOS kernel cannot run), the
full Go race suite and live-PostgreSQL lanes are green, the provenance
gates agree on the identity, `artifact.json` binds the exact archive
digests to the qualified source, the evidence bundle is finalized and
packaged, and the release clean-room lane verified the shipped bytes
end-to-end — including the two defects (F-010, F-011) that made the lane
unpassable before this cycle's fix.

**Not SIGNED, not PUBLISHED — STOP-SHIP remains.** The GoReleaser binary
candidate (`build-release-candidate.sh` — a `vX.Y.Z` final-tag lane),
installed-distribution qualification, GitHub OIDC attestation, macOS
signing/notarization, and publication lanes are `NOT_RUN` — they belong
to the release environment, and admission of the signed deliverable
requires rerunning the mandatory gates against those exact bytes. The
binding lanes are carried from the previous cycle and must be rerun
there if any file on those surfaces changes. Independent checkpoint
custody is scoped NOT_QUALIFIED: the mechanism exists
(`CRABEDENCE_CHECKPOINT_CUSTODY_PATH`), but custody is only independent
when its storage lives outside the service host's failure domain — a
deployment property no test in this environment can establish.
