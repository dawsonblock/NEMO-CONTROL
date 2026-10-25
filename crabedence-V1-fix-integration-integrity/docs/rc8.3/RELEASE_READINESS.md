# RC8.3 Release Readiness

Gate statuses are only PASS / FAIL / NOT_RUN / BLOCKED. Results apply
to the working tree at the recorded commits; no frozen RC8.3 artifact
was packaged or signed — no artifact-bound claim is made.

## G1–G8 status

| Gate | Scope | Status | Evidence |
|---|---|---|---|
| G1 | Go build, all packages + custodyctl | PASS | `go build ./...` clean |
| G2 | Go unit/race — sandbox cleanup lanes (PR-01) | PASS | `go test -race -run 'TestCleanup\|TestHighAssurance' ./internal/sandboxexecutor/` — 32.9s; full cleanup suite 170.7s |
| G3 | Go unit/race — custody/witness/idempotency lanes (PR-02..05) | PASS | `go test -race ./internal/witness/ ./internal/custody/` 2.7s; `-run 'Custody\|Obligation\|Manifest' ./internal/execution/` 3.8s; `-run 'TerminalEvidence' ./internal/idempotency/` 2.7s |
| G4 | Full `go test -race -timeout=20m ./...` | NOT_RUN | Time budget; targeted suites above ran instead |
| G5 | Worker TypeScript / npm suites | NOT_RUN | No worker changes in RC8.3 scope |
| G6 | Live PostgreSQL parity | NOT_RUN | `scripts/test-live-postgres.sh` not executed (no live DB provisioned) |
| G7 | Release packaging / attestation | NOT_RUN | No frozen candidate built; PR-06 contract landed (`docs/rc8.3/PROVENANCE_CONTRACT.md`, legacy verifier fail-fast) |
| G8 | Independent witness, Apple HVF, Linux KVM real-hypervisor lanes | **BLOCKED** | No separately administered witness, no independent trust root, and no executed real-hypervisor fault-injection lanes in this environment. msb 0.7.8 verified present; fake-runtime lanes qualified only |

## Residual risks

- Shared-namespace high-assurance cleanup remains **UNSUPPORTED**
  (no atomic identity-conditioned delete in msb 0.7.8); only the
  exclusive-catalog posture carries the claim — unqualified until G8
  runs on real hypervisors.
- Full-history operator rescan is intentionally unbounded memory on
  the ledger; bounded-page incremental drains are the steady state.
- Legacy witnessed-empty rows are journaled divergences — provable
  chain continuity rests on the operator-approved journal, not on
  rewritten history.

## Release decision

**CONDITIONAL / RESTRICTED.** Code-level defect closures are
implemented and locally tested, but G8 and several qualification
lanes are NOT_RUN/BLOCKED: no GO claim, and no high-assurance
production claim, can be made for this tree. Required next steps:

1. Execute `go test -race -timeout=20m ./...` and the live-PG lane.
2. Provision an independently administered witness + signed trust
   root; run custody partition/replay/rotation lanes.
3. Run Apple HVF and Linux KVM fault-injection lanes against the
   exclusive-catalog posture; re-attempt shared-namespace only if a
   runtime offers atomic identity-conditioned delete.
4. Freeze, package, attest, then bind all gate results to the exact
   frozen artifact SHA-256.
