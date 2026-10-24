# RC8 Dependency Graph

Gate/PR ordering. A node may start only when every incoming edge's gate is
PASS for the same HEAD commit. Merging a later PR never skips an earlier gate.

```
G0 baseline (verified parent 13566f1a, clean checkout, pins, NOT QUALIFIED)
 │
 ├─► PR-01 trust repair ──────────────┐
 │   (history/experience/research     │
 │    trusted-observation predicate)  │
 │                                    ├─► PR-06 governed research ────┐
 │                                    │   (depends on PR-01 + PR-04)  │
 ├─► PR-02 authority + ABI ───────────┤                               │
 │   (invocation ABI, admission,      │                               │
 │    idempotency, differential)      │                               │
 │                                    │                               │
 ├─► PR-03 signed release controls ───┤                               │
 │   (releasectl redesign, ledger)    │                               │
 │                                    ├─► PR-07 packaging + CI ───────┤
 ├─► PR-04 witness/custody contracts ─┤   (reproducible identity,      │
 │   (envelope-v1, outbox, keys)      │    manifest, image pins)       │
 │                                    │                               │
 └─► PR-05 sandbox cleanup/recovery ──┴──────────────► PR-08 live qual ─┴─► PR-09 efficacy
     (identity-safe cleanup, bounded  │                (G8: both lanes,    (G9 optional,
      recovery, no blind retry)       │                 custody, security)  measured rollout)
```

## Edge rationale

- **PR-06 ← PR-01**: research reads only G1-verified memory; building it on the
  broken trust predicate would inherit the defect.
- **PR-06 ← PR-04**: experiment receipts and outcome verification flow through
  the custody/evidence contract.
- **PR-07 ← PR-02/03/04/05**: the release/source manifest can only bind a
  merged tree; image-pin reconciliation needs the final pin decision.
- **PR-08 ← PR-07**: qualification evidence binds the packaged artifact, which
  must be the final bytes. Freeze commit before artifact generation; any
  change re-opens affected lanes.
- **PR-09 ← PR-08**: efficacy claims require a previously qualified candidate.

## Parallel-safe pairs

PR-01, PR-02, PR-03, PR-04, PR-05 are mutually independent at the module
level after G0 (disjoint ownership per INTEGRATION_INVENTORY §5) but must not
assume each other's fixes: e.g. PR-04 does not rely on PR-03's ledger, and
PR-05 does not rely on PR-04's transport.

## Merge-governance invariants

- Topic branches `codex/rc8-prNN-*` target `codex/rc8-authority-integration`.
- CI + human review required for authority/crypto paths (`internal/execution`,
  `internal/capability`, `internal/releasectl`, `internal/witness`,
  `internal/sandboxcustody`, `internal/sandboxexecutor`).
- No force-push after a commit has qualification evidence bound to it.
- RC8 modes land behind explicit development flags; production defaults fail
  closed.
- A failed gate in a dependency re-opens the dependent PRs it feeds.
