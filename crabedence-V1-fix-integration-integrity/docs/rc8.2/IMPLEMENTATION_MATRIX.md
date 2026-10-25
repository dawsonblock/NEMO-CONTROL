# RC8.2 Implementation Matrix

| PR | Findings | Files touched | Tests | Status |
|---|---|---|---|---|
| Phase 0 | baseline | `docs/rc8.2/*` | baseline build + witness/custody/execution/reconcile `-race` | DONE |
| PR-10 | F-01 | `internal/execution/control_gate.go`, `control_gate_test.go` | broadcast 32/128, failure, deadline, stale worker, cancel, recheck, race, stress | DONE |
| PR-10 | F-02 | `internal/witness/outbox.go`, `sender.go`, `internal/execution/serve.go`, `dispatch.go`, `internal/reconcile/worker.go`, `internal/idempotency/contract.go`, custody tests | enqueue-failure durability, crash-gap replay, hwm, states, corrupt obligations, concurrent drains, dup acks | DONE |
| PR-10 | F-03 | `internal/witness/sender.go`, `config.go`, `serve.go`, `witness_test.go`, `custody_gate_test.go` | offline/slow/bad-sig/stale/wrong-id witness, cold restart w/ backlog, outage pre-admission | DONE |
| PR-10 | F-04 | `internal/execution/release_manifest.go` (new), `config.go`, `serve.go`, `internal/custody/envelope.go` | manifest verify suite: tamper/wrong-signer/wrong-artifact/policy/registry/commit | DONE |
| PR-10 | F-05 | `internal/execution/config.go`, `serve.go`, `config_test.go` | every invalid profile/config → fail closed | DONE |
| PR-11 | F-06 | `internal/sandboxexecutor/backend_msb.go`, `namespace_test.go`, `cmd/sandbox-executord`, `docs/rc8.2/SANDBOX_CLEANUP.md` | G5 adversarial suite + namespace tests under `-race`; `msb` v0.7.8 inventory — no atomic delete, exclusive-namespace fallback | DONE |
| PR-12 | F-07/F-08 | `RELEASE_MANIFEST.json`, `qualification/rc8.2-required-tests.json` (digest `b3cf71c5…`), `rc8_evidence_verify_test.py` G7PackagingGate, signed artifact + sidecars | deterministic double-build byte-identical; clean-room extract verify; g7 4/4 evidence records | DONE |
| PR-13 | G8 | all runnable lanes | `docs/rc8.2/RELEASE_READINESS.md` gate table — Go race sweep, Rust workspace, Node, Python, ABI differential, live Postgres, post-dispatch | DONE (BLOCKED on external-witness + live-hypervisor lanes; NO-GO for shared-ns) |
| PR-14 | F-09 | `worker/src/fleet.ts` (assessment only) | `docs/rc8.2/FLEET_SCOPING.md` — ranked boundaries, characterization requirements | SCOPED (no refactor in candidate) |
