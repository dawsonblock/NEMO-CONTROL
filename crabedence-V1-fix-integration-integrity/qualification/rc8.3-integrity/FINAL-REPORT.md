# RC8.3 Integrity Closure — Final Qualification Report

Release: `0.55.0-rc8.3-integrity-closure`
Branch: `codex/rc8.3-integrity-closure`
Baseline artifact: `NEMO-CONTROL-v0.55.0-rc8.3-development.zip`
(sha256 `1611b161…`, source commit `0db72fd2`)

## Decision

**NO-GO.** The security corrections are implemented, regression-tested, and
green on every locally executable lane, including live PostgreSQL, real Apple
Silicon/HVF microVMs, Worker, Python, Rust, Node, Nemo TypeScript, and the ABI
differential corpus. The release remains NO-GO because mandatory independent
qualification and release-attestation prerequisites are not satisfied:

1. G8 independent witness under separate administration and authenticated
   transport: **BLOCKED** (no independent host/trust domain/TLS witness).
2. Linux KVM sandbox lane: **BLOCKED** (macOS arm64 host; no KVM hardware).
3. Signed release attestation validated against an externally trusted release
   root: **BLOCKED** (no release key material).
4. Third-party clean-room verification: **BLOCKED**.
5. The exact full-tree `go test -race -timeout=20m ./...` gate is **FAIL**:
   `internal/cli` hit the 20m package timeout (1203.2s) and
   `providers/{aws,blacksmith,localcontainer,machine0,tart}` failed on
   deadline/signal-killed paths under full-tree parallelism. A timed-out
   package is FAIL, and isolated reruns are not substituted. The changed
   custody/witness/execution packages passed inside the same run.

A NO-GO here is not a claim that the security work is incomplete. It is a claim
that the remaining gates cannot be evidenced in this environment, and the
release directive forbids calling them PASS.

## 1. Baseline findings

The mission named
`NEMO-CONTROL-codex-rc8.3-custody-sandbox-qualification.zip` with SHA-256
`45bf1438…`. No file in the workspace matches that name or hash. The RC8.3
candidate actually present is `NEMO-CONTROL-v0.55.0-rc8.3-development.zip`
(SHA-256 `1611b161…`), bound by its attestation to source commit `0db72fd2`.
The reviewed security files are byte-identical between the archive and
`crabedence-V1-fix-integration-integrity/`; `0db72fd2..54ad877` changes only
release artifacts. All work is bound to the actual artifact and its source
identity, and the mismatch is recorded rather than papered over.

Safe extraction: 4971 entries, zero traversal or absolute paths, 12 symlinks,
zero escaping symlinks, permissions preserved. Pinned toolchain: Go 1.26.5
(host default is 1.27.2 and is not used for evidence).

Pre-fix reproduction against the unmodified commit produced four genuine
failures: swallowed journal DB errors, successor-chain breakage after
compensation, repair without a full-history scanner, and an unverifiable-legacy
journal accepted as coverage with high-water advancement. Log:
`logs/baseline-defect-reproduction.log`.

## 2. Implemented corrections

| PR | Correction | Regression gates |
|---|---|---|
| PR-01 | Typed legacy coverage: journal identity, terminal receipt digest, envelope hash, row sequence, signed authorization, and disposition are re-verified. Unverifiable/malformed/stale rows stay `REPAIR_REQUIRED` and block HWM. DB errors propagate. | `TestUnverifiableLegacyJournalCannotAdvanceHWM`, `TestTerminalArrivesAfterQuarantine`, `TestMalformedLegacyJournalFailsClosed`, `TestJournalDBErrorNotSwallowed`, `TestLegacyWitnessedWithoutVerifiedAckIsNotCovered` |
| PR-02 | Atomic, authorized suffix rewrite: in-transaction preflight, every successor link and signature updated, signed before/after proof, crash/replay idempotence, concurrent enqueue fence, witnessed/checkpointed suffix refusal. | `TestLegacyTwoRowSuffixRehash`, `TestLegacyThreeRowMixedPayloads`, `TestLegacyMixedWitnessedSuffixRefusal`, `TestMigrationCrashBeforeCommit`, `TestMigrationCrashAfterCommitBeforeAck`, `TestConcurrentEnqueueFenced`, `TestMigrationReplayIdempotent` |
| PR-03 | Repair authority: full-history scanner mandatory; detached grant signed by a separately pinned `repair-authority` key; subject signature-bound; deployment/operation/window/nonce verified; compare-and-swap marker clear. | `TestOperatorRepairWithoutFullScannerFailsClosed`, `TestUnauthorizedEvidenceSignerDeniedRepair`, `TestCallerSuppliedActorSpoofRejected`, `TestExpiredOperatorApprovalRejected`, `TestConcurrentContradictionPreventsClear` |
| PR-04 | Subcommand-first `custodyctl`, explicit authorization, dry-run, JSON output, SQL cursor pagination, bounded inspection, read-only commands that never create the outbox. | `TestPreflightSubcommandFlagsAndJSON`, `TestInspectPaginationBounded`, `TestMigrateDryRunDoesNotMutate`, `TestRepairAuthorityRequired`, `TestReadOnlyCommandsRefuseMissingOutbox` |
| PR-05 | Sandbox cleanup: symlink/ancestor checks, catalog dev/inode/uid re-verification, second pre-delete inspection, durable cleanup intents. | `TestHighAssuranceRejectsSymlinkCatalog`, `TestHighAssuranceRejectsNonRootAncestorSymlink`, `TestHighAssuranceRejectsGroupWritableAncestor`, `TestCleanupRejectsCatalogReplacementBeforePosture`, `TestCleanupRejectsCatalogReplacementInsideWindow`, `TestCleanupReinspectCatchesSubstitution`, `TestCleanupIntentSurvivesUncertainOutcome` |

Full register: `defect-closure.json` (RC83-IC-01..17, plus residuals).

## 3. Verification evidence

| Lane | Result | Evidence |
|---|---|---|
| Full Go build (`go build ./...`) | PASS | exit 0 |
| `go vet ./...` | PASS | exit 0 |
| Targeted `-race` (witness, execution, idempotency, custody, sandboxexecutor, custodyctl) | PASS | `logs/targeted-race.log`, sha256 `ec388dc5…` |
| Exact full `go test -race -timeout=20m ./...` | **FAIL** — `internal/cli` timed out at 20m; five provider packages hit deadline/starvation paths | `logs/full-race-20m.log`, sha256 `22385227…` |
| SQLite durability | PASS | targeted log |
| Live PostgreSQL 16 (4 suites) | PASS | `logs/live-postgres.log`, sha256 `d777b0f7…` |
| Apple Silicon/HVF real microVMs, msb 0.7.8 | PASS (78s) | `logs/live-msb-hvf.log`, sha256 `a891b5ca…` |
| Linux KVM | BLOCKED | no KVM host |
| ABI differential corpus | PASS (68/68 verdict-identical) | `logs/abi-differential-corpus.log`, sha256 `fa8aaba5…` |
| Worker TypeScript (fmt/lint/tsc/vitest) | PASS (3053 passed, 2 skipped) | `logs/worker.log`, sha256 `a5a9c770…` |
| Python | PASS (751 passed, 110 skipped) | `logs/python.log`, sha256 `c842e480…` |
| Rust nextest | PASS (5353 passed, 44 skipped) | `logs/rust-nextest.log`, sha256 `8670f578…` |
| Node binding | PASS (414 + 26) | `logs/node-binding.log`, sha256 `fbc83612…` |
| Nemo TypeScript | PASS (145) | `logs/nemo-ts.log`, sha256 `7ac8ccf3…` |
| Deterministic packaging | PASS (2 identical archives, 4371 entries) | detached attestation / `packaging.json` |
| Independent witness (G8) | BLOCKED | no separate administration/TLS |
| Signed attestation / external root | BLOCKED | no release key material |
| Archive tamper rejection | PARTIAL | hash binding verified; signature rejection blocked with signing |

Machine-readable matrix: `qualification-matrix.json`.

## 4. Residual limitations

See `RESIDUAL-LIMITATIONS.md`. The material ones:

- Microsandbox 0.7.8 has no atomic identity-conditioned delete. The
  inspect-then-delete race is narrowed (second inspection, catalog dev/inode
  re-check, nonce-bound handle) but not eliminated. Shared-runtime high
  assurance remains **UNSUPPORTED**.
- A same-UID process that can write inside the verified catalog can modify
  runtime state in place; dev/inode detects replacement, not in-place tampering.
- A compromised `repair-authority` key grants full repair authority until
  rotation.
- Witness-coordinated recovery of a checkpointed/witnessed suffix is a manual
  forensic protocol; this release refuses safely but does not automate it.
- The `-race` sandboxexecutor package observed 1092.8s against a 20m budget; a
  loaded host can time out.

## 5. Conditions to promote

1. Provision a separately administered witness host with independent custodian
   keys and authenticated TLS; run partition, stale-ack, forged-signature,
   checkpoint-substitution, crash/restart, and replay lanes.
2. Execute the Linux KVM msb lane on KVM-capable hardware.
3. Sign the detached attestation with a release key validated against an
   externally trusted root, and verify tamper/signature rejection.
4. Obtain third-party clean-room verification of the exact archive SHA-256.
5. Resolve the full-tree `-race` budget (shard or raise the per-package budget)
   so the exact mandated invocation passes without isolated reruns.

Until then, the candidate is a corrected development candidate, not a
security-qualified release.
