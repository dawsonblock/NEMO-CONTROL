# RC8.3 Integrity Closure — Final Qualification Report

> **Superseded decision (witness-fence branch).** This report records the
> integrity-closure candidate `0.55.0-rc8.3-integrity-closure`. The
> witness-fence branch `codex/rc8.3-witness-fence-proof-qualification`
> closes RC83-IC-34..40 and **withdraws the scoped GO**: migration
> authority is now a signed witness epoch rather than a checkpoint, the
> proof binds the whole journal row, and the three custody authorities
> resolve from three role-pinned trust files. The external gates (G31
> trust-root authorization, G32 independently administered witness, G33
> third-party clean-room, G34 restricted-deployment certification) are
> unexecuted. Current decision: **NO-GO for every deployment profile**.
> See `docs/rc8.3/RELEASE_READINESS.md` and
> `qualification/rc8.3-integrity/qualification-matrix.json` (G24–G34).

Release: `0.55.0-rc8.3-integrity-closure`
Branch: `codex/rc8.3-integrity-closure`
Baseline artifact: `NEMO-CONTROL-v0.55.0-rc8.3-development.zip`
(sha256 `1611b161…`, source commit `0db72fd2`)

## Decision

**GO — scoped (withdrawn by the witness-fence branch; retained as the
integrity-closure record).** The corrected source qualified for the
**macOS arm64 / Apple Silicon HVF, exclusive-runtime profile** at the time
of that branch. The following are explicitly out of scope and must not be
inferred from this decision:

- **Linux/KVM**: excluded by operator direction; not executed.
- **Shared-runtime high-assurance cleanup**: **UNSUPPORTED** (no atomic
  identity-conditioned delete in msb 0.7.8).
- **Third-party trust root**: the release attestation is signed and verified
  against a **locally provisioned, pinned Ed25519 release root**, not an
  externally administered third-party root. The root public key must be
  distributed out of band and countersigned externally if third-party trust is
  required.
- **Third-party clean-room**: a local clean-room reproduction was executed
  (fresh extraction, fresh caches, 4376/4376 inventory, build/vet/targeted
  race). It is not an independent third-party verification.

The exact 20-minute full-tree race command **fails** and remains recorded as
`G4a`. The operator-directed requalified gate `G4b` raises the per-package
budget to 45 minutes and limits package parallelism to 4; it passes with zero
failures. This is a test-budget/parallelism change, not a security waiver.

## 1. Independent audit findings — closure

| Audit finding | Disposition | Evidence |
|---|---|---|
| **IC-A** Offline migration could rewrite a suffix the witness may hold | **CLOSED** — migrate requires a live witness checkpoint; checkpoint seq/hash/witness FP are verified, bound into the signed migration proof, and journaled; zero-value checkpoint refused | `TestMigrationWithoutWitnessCheckpointFailsClosed`, `TestLostLocalAckWithRemoteCheckpointRefusesRewrite`, `TestMigrationRequiresVerifiedCheckpoint` |
| **IC-B** Repair-marker ABA / same-reason gap | **CLOSED** — every contradiction advances `repair_generation` transactionally; CAS compares reason + generation | `TestRepairNewContradictionWithSameReasonRejectsCAS`, `TestRepairMarkerABACycleRejectsOldGeneration`, `TestRepairGenerationIncrementsOnSameReason` |
| **IC-C** Cleanup intent not demonstrably durable | **CLOSED** — durable state directory mandatory; O_EXCL write, file fsync, atomic rename, parent fsync; clear failures surfaced and intent remains visible | `TestCleanupIntentRequiresDurableStateDirectory`, `TestCleanupIntentSyncFailureFailsClosed`, `TestCleanupIntentClearFailureSurfaced` |
| **IC-D** Full-race evidence truncated/mismatched | **CLOSED** — complete requalified log attached; bundle verifier checks size, hash, and terminal `EXIT=` line; prior 20m failure retained | `full-race-requalified-45m.log`, `verify-evidence-bundle.py` |
| **IC-E** Verification non-portable and unsigned | **CLOSED** — relative bundle paths; signed canonical attestation; verifier resolves within the bundle; standalone copy test passes | `attestation.json`, `attestation.sig`, `verify-release-attestation.py`, `verify-evidence-bundle.py` |
| **IC-F** Residual non-atomic msb deletion | **RETAINED AS RESIDUAL** — second inspection, catalog dev/inode re-check, nonce-bound handle; shared-runtime high assurance remains UNSUPPORTED | `RESIDUAL-LIMITATIONS.md` |

## 2. Implemented corrections

| PR | Correction | Key regression gates |
|---|---|---|
| PR-01 | Typed legacy coverage: journal identity, terminal receipt digest, envelope hash, row sequence, signed authorization, disposition; DB errors propagate | `TestUnverifiableLegacyJournalCannotAdvanceHWM`, `TestTerminalArrivesAfterQuarantine`, `TestMalformedLegacyJournalFailsClosed`, `TestJournalDBErrorNotSwallowed`, `TestLegacyWitnessedWithoutVerifiedAckIsNotCovered` |
| PR-02 | Atomic, authorized suffix rewrite; in-transaction preflight; successor relinking/re-signing; signed before/after proof; crash/replay; witnessed/checkpointed refusal; **live checkpoint mandatory** | `TestLegacyTwoRowSuffixRehash`, `TestLegacyThreeRowMixedPayloads`, `TestLegacyMixedWitnessedSuffixRefusal`, `TestMigrationCrashBeforeCommit`, `TestMigrationCrashAfterCommitBeforeAck`, `TestConcurrentEnqueueFenced`, `TestMigrationReplayIdempotent`, `TestMigrationWithoutWitnessCheckpointFailsClosed` |
| PR-03 | Repair authority: full-history scanner mandatory; detached repair-authority grant; subject signature-bound; deployment/operation/window/nonce; **generation CAS** | `TestOperatorRepairWithoutFullScannerFailsClosed`, `TestUnauthorizedEvidenceSignerDeniedRepair`, `TestCallerSuppliedActorSpoofRejected`, `TestExpiredOperatorApprovalRejected`, `TestConcurrentContradictionPreventsClear`, `TestRepairNewContradictionWithSameReasonRejectsCAS` |
| PR-04 | Subcommand-first `custodyctl`, authorization, dry-run, JSON, SQL cursor pagination, read-only access that never creates the outbox | `TestPreflightSubcommandFlagsAndJSON`, `TestInspectPaginationBounded`, `TestRepairAuthorityRequired`, `TestReadOnlyCommandsRefuseMissingOutbox` |
| PR-05 | Sandbox cleanup: symlink/ancestor checks, catalog dev/inode/uid re-check, second pre-delete inspection, **durable cleanup intents** | `TestHighAssuranceRejectsSymlinkCatalog`, `TestCleanupRejectsCatalogReplacementInsideWindow`, `TestCleanupReinspectCatchesSubstitution`, `TestCleanupIntentSurvivesUncertainOutcome`, `TestCleanupIntentSyncFailureFailsClosed` |

Full register: `defect-closure.json` (RC83-IC-01..24 plus residuals).

## 3. Verification evidence

| Lane | Result | Evidence |
|---|---|---|
| Full Go build (`go build ./...`) | PASS | exit 0 |
| `go vet ./...` | PASS | exit 0 |
| Targeted `-race` (witness, execution, idempotency, custody, custodyctl) | PASS | `logs/targeted-race-final.log`, sha256 `d77dbd62…` |
| **G4a exact `go test -race -timeout=20m ./...`** | **FAIL (retained)** | `logs/full-race-20m.log`, sha256 `7097567c…` |
| **G4b `GOFLAGS=-p=4 go test -race -timeout=45m ./...`** | **PASS** (0 FAIL; cli 1311.6s, sandboxexecutor 1115.0s) | `logs/full-race-requalified-45m.log`, sha256 `bf814a32…` |
| Live PostgreSQL 16 (4 suites) | PASS | `logs/live-postgres.log` |
| Apple Silicon/HVF real microVMs, msb 0.7.8 | PASS (78s) | `logs/live-msb-hvf.log` |
| Independent TLS witness (separate process/keys/trust) | PASS | `logs/independent-witness-tls.log`, sha256 `45323027…` |
| Linux KVM | NOT RUN — excluded by operator direction | — |
| ABI differential corpus | PASS (68/68 verdict-identical) | `logs/abi-differential-corpus.log` |
| Worker TypeScript | PASS (3053 passed, 2 skipped) | `logs/worker.log` |
| Python | PASS (751 passed, 110 skipped) | `logs/python.log` |
| Rust nextest | PASS (5353 passed, 44 skipped) | `logs/rust-nextest.log` |
| Node binding | PASS (414 + 26) | `logs/node-binding.log` |
| Nemo TypeScript | PASS (145) | `logs/nemo-ts.log` |
| Deterministic packaging | PASS (2 identical archives, 4376 entries) | detached `packaging.json` |
| Signed attestation (pinned local root) | PASS | `attestation.json`, `attestation.sig`, `verify-attestation.log` |
| Tamper rejection | PASS (modified attestation, bad signature, swapped manifest, swapped archive, wrong root all rejected) | `verify-attestation-*.log` |
| Local clean-room reproduction | PASS (4376/4376 inventory, fresh caches, build/vet/targeted race) | `cleanroom.log` |
| Evidence bundle self-contained | PASS | `verify-bundle.log` |

Machine-readable matrix: `qualification-matrix.json`.

## 3b. Post-review corrections (RC83-IC-25..33)

A branch review against `codex/rc8.3-custody-sandbox-qualification` found the
release-evidence gate self-referential and two authorization/upgrade paths
still open. All are closed in this tree; the register is
`defect-closure.json`:

| Finding | Disposition | Evidence |
|---|---|---|
| Release-root **private** key committed to the repo | **CLOSED** — removed, gitignored, rotated; signing reads `$RELEASE_ROOT_KEY` outside any worktree | no private key in `git ls-files`; key id `c1fc3765…` |
| Attestation anchor resolved from inside the bundle | **CLOSED** — external `--root-key-id`/`--root` required; a coherent root substitution is rejected | `verify-attestation-forgedroot.log` |
| Bundle verifier executed an in-bundle script | **CLOSED** — verifier resolved beside the tool; in-bundle copy deleted | `verify-bundle.log` |
| `preflight` failed on pre-upgrade journal schema | **CLOSED** — select list derived from the live schema | `TestJournalReadsPreUpgradeSchema`, `TestPreflightReadsPreUpgradeJournalSchema` |
| Compensated coverage unbound to the signed rewrite | **CLOSED** — proof verified under a pinned kernel-relay set, target sequence bound | `TestCompensatedCoverageRequiresSignedProof`, `TestCopiedMigrationProofDoesNotTransferCoverage` |
| Migration could mint envelopes outside a rotation window | **CLOSED** — suffix spanning a rotation is refused | `TestMigrationRefusesSuffixAcrossKeyRotation` |

The retired root (`387d837e…`) must be rejected; the pinned root is
`c1fc37659b9b8f4f41b30bc89288c7334b7eea0628a17eb2897b34236a1379b5`. The old
private key is still present in git history — purging it is a destructive
rewrite that needs an explicit operator decision (RC83-IC-R4), so it is
carried as a residual rather than performed here.

## 4. Residual limitations

See `RESIDUAL-LIMITATIONS.md`. Material residuals:

- Microsandbox 0.7.8 has no atomic identity-conditioned delete. The
  inspect-then-delete race is narrowed but not eliminated; shared-runtime high
  assurance remains **UNSUPPORTED**.
- A same-UID process that can write inside the verified catalog can modify
  runtime state in place; dev/inode detects replacement, not in-place tampering.
- A compromised `repair-authority` key grants full repair authority until
  rotation.
- Witness-coordinated recovery of a checkpointed/witnessed suffix remains a
  manual forensic protocol.
- The release root is locally provisioned and pinned; third-party trust
  requires an external countersignature.

## 5. Scope of the GO

**GO** for the exclusive-runtime, macOS arm64/HVF profile, on the exact
artifact bound by the detached attestation. **NO-GO** for:

- Linux/KVM (not executed; operator-directed exclusion);
- shared-runtime high-assurance cleanup;
- any deployment requiring a third-party trust root without an external
  countersignature.

The prior RC8.3 development candidate's qualification results are not inherited;
all evidence here is bound to the final source commit and artifact SHA-256 in
the detached attestation.
