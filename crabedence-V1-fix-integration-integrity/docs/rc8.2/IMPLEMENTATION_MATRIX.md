# RC8.2 Implementation Matrix

| PR | Findings | Files touched | Tests | Status |
|---|---|---|---|---|
| Phase 0 | baseline | `docs/rc8.2/*` | baseline build + witness/custody/execution/reconcile `-race` | DONE |
| PR-10 | F-01 | `internal/execution/control_gate.go`, `control_gate_test.go` | broadcast 32/128, failure, deadline, stale worker, cancel, recheck, race, stress | DONE |
| PR-10 | F-02 | `internal/witness/outbox.go`, `sender.go`, `internal/execution/serve.go`, `dispatch.go`, `internal/reconcile/worker.go`, `internal/idempotency/contract.go`, custody tests | enqueue-failure durability, crash-gap replay, hwm, states, corrupt obligations, concurrent drains, dup acks | DONE |
| PR-10 | F-03 | `internal/witness/sender.go`, `config.go`, `serve.go`, `witness_test.go`, `custody_gate_test.go` | offline/slow/bad-sig/stale/wrong-id witness, cold restart w/ backlog, outage pre-admission | DONE |
| PR-10 | F-04 | `internal/execution/release_manifest.go` (new), `config.go`, `serve.go`, `internal/custody/envelope.go` | manifest verify suite: tamper/wrong-signer/wrong-artifact/policy/registry/commit | DONE |
| PR-10 | F-05 | `internal/execution/config.go`, `serve.go`, `config_test.go` | every invalid profile/config → fail closed | DONE |
| PR-11 | F-06 | `internal/sandboxexecutor` (inspect), `docs/rc8.2/SANDBOX_CLEANUP.md`, config | G5 adversarial suite re-run; exclusive-namespace enforcement | PENDING |
| PR-12 | F-07/F-08 | `RELEASE_MANIFEST.json`, `qualification/rc8-required-tests.json` binding, packaging scripts, `docs/rc8.2/RELEASE_PROVENANCE.md` | version consistency, inventory digest, clean-room extract, deterministic pack | PENDING |
| PR-13 | G8 | qualification runs | gate-by-gate statuses in `docs/rc8.2/G8_REPORT.md` | PENDING |
| PR-14 | F-09 | `worker/src/fleet.ts` (assessment only) | scoping note in `docs/rc8.2/F09_ASSESSMENT.md` | PENDING |
