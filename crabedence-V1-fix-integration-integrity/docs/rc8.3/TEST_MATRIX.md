# RC8.3 Test Matrix

## Profiles

| Profile | Cleanup posture | Admission | Coverage |
|---|---|---|---|
| development | shared `sx-` namespace allowed | qualified for dev only | existing suite |
| reduced | namespaced labels, shared catalog | reduced custody claims | existing + namespace suite |
| high-assurance exclusive | `MSB_HOME` dedicated catalog + namespace | exclusive-runtime claims | `TestHighAssuranceExclusivePostureAdmits` |
| high-assurance shared | shared/empty namespace | **DENIED** | `TestHighAssuranceSharedNamespaceDenied`, `TestHighAssuranceSharedCatalogDenied` |

## New tests (RC8.3)

| Test | Proves |
|---|---|
| `TestCleanupUnverifiedInspectNeverRemoves` (transport_error / malformed_response / inspect_wedge) | rm counter 0, occupant survives, `IDENTITY_UNVERIFIABLE`, obligation stays pending |
| `TestCleanupPostCheckDelayUncertain` | wedged post-removal verify → `REMOVAL_UNCERTAIN`, exactly 1 rm |
| `TestCleanupInvalidNamespaceRefused` | malformed namespace refuses Dispatch AND Cleanup, rm counter 0 |
| `TestHighAssuranceSharedNamespaceDenied` | HA + no namespace/catalog → dispatch+cleanup refused, 0 rm |
| `TestHighAssuranceSharedCatalogDenied` | namespace alone is not exclusivity |
| `TestHighAssuranceExclusivePostureAdmits` | dedicated catalog + namespace → posture proof, dispatch, verified removal |
| `TestHighAssuranceLooseCatalogDenied` | 0755 catalog → refused |
| `TestCustodyFailedProbeImmediatelyDegrades` | fresh failure after success → DEGRADED instantly; recovery needs new verified pass |
| `TestCustodyRepairRequiredStickyUntilOperatorRepair` (extended) | repair without actor/reason refused; marker stays open |
| `TestSQLiteTerminalEvidenceMissingSeqFailsClosed` (regression-preserved) | NULL terminal_seq still errors under bounded reads |

Pre-existing coverage reused: substitution inside removal window,
name reuse under different nonce, missing labels, failed remove,
concurrent cleanup independence, ledger-reopen identity, retained-
obligation inventory.

## Reproduction

```
go test -race -timeout=300s -run 'TestCleanup|TestHighAssurance' ./internal/sandboxexecutor/
go test -race -timeout=300s ./internal/witness/ ./internal/custody/
go test -race -timeout=300s -run 'Custody|Obligation|Manifest' ./internal/execution/
go test -race -timeout=200s -run 'TerminalEvidence' ./internal/idempotency/
```

Live PostgreSQL parity: `scripts/test-live-postgres.sh` (NOT_RUN here —
no daemon required by default; run for G-lane qualification).
