# NEMO-CONTROL authority invariants

Status: architecture freeze. This document reinforces
[ADR-003](crabedence-V1-fix-integration-integrity/docs/adr/ADR-003-nemo-runtime-transfer-boundary.md);
it does not establish another policy authority.

## One authority chain

```text
Reasoning / Planner / Learning → proposes
NEMO middleware               → mediates
nemo-crabedence-runtime        → composes the mediated invocation
══════════════════ TRUST BOUNDARY ══════════════════
Crabedence                    → authorizes
Provider transport            → executes
Evidence system               → proves and reconciles
```

The sole production NEMO composition root is `nemo-crabedence-runtime`.
Crabedence owns capability classification, consequential routing, assurance,
credential scope, grant scope, grants, effect state, receipts and reconciliation.
The planner may assert a class for compatibility, but cannot select it:
the registry determines it and a mismatch is refused.

Learning is not promotion authority. Plugins are not grant authorities.
Providers are not policy authorities. NEMO is not grant authority.
Improving intelligence or generating a tool cannot automatically expand authority.
Promotion of generated tools or policy requires independent qualification and
authorization; this freeze does not claim that a promotion pipeline exists.

## Production invariants

1. Every consequential effect crosses the Crabedence invocation boundary.
   Neither plugins nor middleware dispatch consequential effects independently.
2. Crabedence's immutable grant material is the only production grant
   implementation. Registry policy, not caller-supplied fields, determines
   admission and execution.
3. The Crabedence Effect Fabric is the only production effect ledger.
   SQLite and PostgreSQL are storage implementations of one contract, not
   separate effect authorities.
4. Provider transports execute only admitted work. Provider credentials remain
   outside the planner and plugin host.
5. Possible dispatch with an uncertain result remains UNKNOWN. It never causes
   automatic redispatch; independent evidence must resolve it.
6. The experimental `nemo-effect-runtime` and `nemo-relay-authority` must not be
   reachable from the production composition root. Workspace membership for
   characterization tests does not make them production components.
7. Executor/ledger types currently used by the Rust bridge are a documented
   structural exception, not authorization to instantiate a second effect
   store. Removing this coupling is deferred, not silently claimed complete.
8. Qualified source, packaged source and signed source must have the same
   canonical identity. Historical reports do not qualify a changed outer tree.
9. Trusted-process plugin isolation is not a hostile-code boundary. No L3
   containment or production signing claim may be made before it is proven.

## Enforcement and limits

`scripts/check-nemo-runtime-dependencies.sh` in the Crabedence subtree checks
locked normal and build dependencies across all features and targets for runtime/plugin crates and the
production composition root. It refuses experimental authority/effect
dependencies and checks that plugin-host/native-loader source does not name the
authority socket. Its regression tests exercise refusal and resolution failure.
`scripts/check-nemo-credential-isolation.sh` checks credential confinement.

The outer repository's `.github/workflows/consolidation.yml` runs these guards,
transfer/doc checks and targeted provenance tests. Workflows nested inside
component directories are reference workflows, not active outer-repository CI.
These checks enforce practical boundaries, not a proof that arbitrary native
code cannot bypass them. A root workflow must pass before release promotion;
branch-protection configuration and real signing remain operator responsibilities.

No new major functionality belongs in `worker/src/fleet.ts`; extract bounded
domains under characterization tests first. Capability expansion is deferred
until source provenance and the production authority path are closed.
