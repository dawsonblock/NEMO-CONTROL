# RC8 Security Invariants — Test-Bound Register

Each invariant names its owning modules, the PR that enforces it, and the test
IDs that must exist and pass before the corresponding gate can report PASS.
Test IDs are assigned here so gate evidence can cite them; tests do not exist
yet unless marked (exists).

## INV-1 — Crabedence alone grants external-effect authority

- Owning modules: `internal/capability`, `internal/execution`,
  `runtimes/nemo-relay/bridges/nemo-crabedence`
- Statement: NEMO, memory (`internal/history`, `internal/experience`), agents,
  `internal/dream`, `internal/research`, and tool outputs are untrusted
  proposal sources. Route selection, approval status, assurance class, and
  execution receipt authority are kernel-assigned; NEMO-supplied values are
  never authoritative.
- Enforcing PR: PR-02
- Tests: `TestAuthorityKernelAssignedFields` (route/approval/assurance/receipt
  fields from request ignored or rejected), `TestGrantScopeEnforced`,
  `TestRequestDigestBinding`, `TestNemoCannotMintCapability` (differential
  corpus case `authority/fields-*`)

## INV-2 — At-most-once dispatch for ambiguous external effects

- Owning modules: `internal/idempotency`, `internal/execution/dispatch.go`,
  `internal/reconcile`
- Statement: UNKNOWN / DISPATCH_AMBIGUOUS is never blindly retried. A new
  dispatch requires independent absence proof or operator-controlled
  reconciliation under policy.
- Enforcing PR: PR-02 (preserved from RC7.6)
- Tests: `TestUnknownNotRetried` (exists in RC7.6 lineage — locate and keep),
  `TestAmbiguousRequiresAbsenceProof`, `TestReconcileOperatorOnly`,
  crash/replay: `TestDispatchCrashBeforeCommit`, `TestDispatchCrashAfterCommit`

## INV-3 — Evidence before release of irreversible state

- Owning modules: `internal/evidence`, `internal/witness`, `internal/sandboxcustody`,
  `internal/releasectl`, `internal/execution`
- Statement: terminal receipts, cleanup obligations, custody acknowledgements,
  and release admission bind to deployment + release identities and are checked
  at recording/commit boundaries.
- Enforcing PRs: PR-03 (release admission), PR-04 (custody), PR-05 (cleanup)
- Tests: `TestTerminalReceiptBound`, `TestCustodyAckVerifiedAtCommit`,
  `TestStageRequiresQualificationEvidence`, `TestCleanupObligationPersistsAcrossCrash`

## INV-4 — Signer pinned independently

- Owning modules: `internal/releasectl`, `internal/witness`, release scripts
- Statement: signed-with-embedded-key is insufficient for production trust;
  empty operator/witness trust set fails closed.
- Enforcing PR: PR-03 (operator), PR-04 (witness)
- Tests: `TestVerifyEmptyAllowlistFailsClosed`, `TestVerifySelfSignedRejected`,
  `TestWitnessKeyFromRecordRejected`, `TestProductionUnsignedModeUnreachable`

## INV-5 — Research cannot self-promote

- Owning modules: `internal/research`, `internal/dream`, `internal/experience`,
  `internal/history`
- Statement: unassessed memory is untrusted; experiments are bounded;
  qualification evidence comes from independent evaluators; promotion requires
  a separate operator decision.
- Enforcing PRs: PR-01 (trust predicate), PR-06 (promotion gate)
- Tests: `TestUnassessedNotTrusted` (all trust states), `TestProposalImmutable`,
  `TestPromotionRequiresOperatorSignature`, `TestSelfReportedDeltaInsufficient`,
  `TestBoundedExperimentBudget`

## INV-6 — Qualification is exact-byte-scoped

- Owning modules: `qualification/`, `scripts/qualify-*.sh`,
  `scripts/verify-*.mjs`, `.github/workflows/*`
- Statement: no carried-forward PASS for changed source, runtime digest,
  toolchain, image pins, generated artifact, deployment identity, or witness
  trust root.
- Enforcing PR: PR-07, gate G8
- Tests: `scripts/rc8-evidence-verify.sh` checks; `TestEvidenceBoundToCommit`,
  `TestForeignCommitEvidenceRejected`, `TestChangedPinsInvalidate`

## INV-7 — Frozen NEMO provenance boundary intact

- Owning modules: `NEMO-feat-native-plugin-isolation/` (frozen source),
  `runtimes/nemo-relay`, `runtimes/nemo-transfer-manifest.json`,
  `scripts/verify-nemo-*.sh/.py`
- Statement: modify the canonical integration/runtime and the declared transfer
  delta, never the frozen upstream copy.
- Enforcing PRs: all; check runs in PR-02 and PR-07
- Tests: `verify-nemo-provenance.sh`, `verify-nemo-transfer.py`,
  `TestTransferManifestRecomputed` — subtree tree ID stays
  `42a9c4055df2a38e6ca6f1178d1ebcefa38672b7` unless a deliberate,
  separately-reviewed transfer changes it.

## Cross-cutting failure-mode tests (gate-cited)

| Test ID | Invariant | PR |
|---|---|---|
| `TestTrustBlankIsUnverified` | INV-5 | PR-01 |
| `TestTrustStalePolicyInvalid` | INV-5 | PR-01 |
| `TestTrustContradictoryAssessment` | INV-5 | PR-01 |
| `TestTrustedTaskSetExcludesUnassessed` | INV-5 | PR-01 |
| `TestLegacyStoreMigrationKeepsUntrusted` | INV-5 | PR-01 |
| `TestResumeUnsignedRejected` | INV-4 | PR-03 |
| `TestHaltSurvivesFileDeletion` | INV-3/4 | PR-03 |
| `TestControlLedgerRollbackFailsClosed` | INV-4 | PR-03 |
| `TestRogueDaemonCannotClear` | INV-4 | PR-03 |
| `TestWitnessForgedAckRejected` | INV-3/4 | PR-04 |
| `TestWitnessCrossFamilyConfusion` | INV-3 | PR-04 |
| `TestCustodyOutageNoTerminalSuccess` | INV-3 | PR-04 |
| `TestCleanupReplacementSandboxSafe` | INV-3 | PR-05 |
| `TestCleanupLabelCollisionRejected` | INV-3 | PR-05 |
| `TestVerifiedAbsentNeverFalse` | INV-3 | PR-05 |
| `TestEvalLeakageDetected` | INV-5 | PR-06 |
| `TestForgedOutcomeRejected` | INV-5 | PR-06 |
