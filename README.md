# NEMO-CONTROL

Two runtimes, one distribution: a reasoning/runtime layer (**NEMO**) and the
authority/effect kernel that decides whether consequential work is authorized
(**Crabedence**). This repository holds both while they are consolidated into a
single platform with a deliberately small trust boundary.

## What is here

| Directory | What it is | Version |
| --- | --- | --- |
| [`NEMO-feat-native-plugin-isolation/`](NEMO-feat-native-plugin-isolation) | **NEMO** — a multi-language agent runtime: scope stacks, middleware and interceptors, plugin lifecycle, an isolated native plugin host, LLM wrapping and routing, and Python / Node.js / Go bindings. A derived development fork of [NVIDIA NeMo Relay](https://github.com/NVIDIA/NeMo-Relay) (Apache-2.0). It is **not** an official NVIDIA release — see its [`FORK_PROVENANCE.md`](NEMO-feat-native-plugin-isolation/FORK_PROVENANCE.md). | 0.9.1-rc.4 |
| [`crabedence-V1-fix-integration-integrity/`](crabedence-V1-fix-integration-integrity) | **Crabedence** (Crabbox) — the trusted execution kernel: capability registry, authority, admission, durable idempotency, the Effect Fabric, evidence and receipts, and UNKNOWN reconciliation. A Go CLI plus an optional Cloudflare Worker or Node.js coordinator (MIT). It carries the vendored NEMO runtime under [`runtimes/nemo-relay/`](crabedence-V1-fix-integration-integrity/runtimes/nemo-relay) and the Rust bridge and effect router under `bridges/`. | 0.53.2 |

## The boundary

The two are **not** merged, and the split is deliberate:

```text
NEMO decides how to run, reason, and route.
Crabedence decides whether consequential work is authorized and how it is committed.
```

One narrow contract crosses between them — the capability invocation ABI. The
request on that wire carries a capability, its arguments, authority material, an
idempotency key, and a deadline. It never carries execution route, provider
selection, assurance profile, approval requirements, retry policy, or receipt
requirements: those are resolved by Crabedence's registry, and a planner that
supplies them is refused rather than obeyed.

The invariant that follows:

> No NEMO component can independently produce a MUTATION or CRITICAL external
> effect.

It is asserted by tests in CI, not only documented.

## Where to read

- [`docs/plan/nemo-runtime-transfer.md`](crabedence-V1-fix-integration-integrity/docs/plan/nemo-runtime-transfer.md) — the transfer plan, the findings recorded while executing it, and the state of each release blocker.
- [`docs/adr/ADR-003-nemo-runtime-transfer-boundary.md`](crabedence-V1-fix-integration-integrity/docs/adr/ADR-003-nemo-runtime-transfer-boundary.md) — the trust-boundary decision and the ownership matrix.
- [`docs/spec/capability-invocation-abi.md`](crabedence-V1-fix-integration-integrity/docs/spec/capability-invocation-abi.md) — the frozen wire contract, with its strict parsing rules.
- [`crabedence-V1-fix-integration-integrity/README.md`](crabedence-V1-fix-integration-integrity/README.md) — the Crabedence project README: the Effect Fabric, the execution kernel, providers, and operations.
- [`NEMO-feat-native-plugin-isolation/README.md`](NEMO-feat-native-plugin-isolation/README.md) — the NEMO project README.

## Status

Consolidation in progress. The vendored NEMO runtime, the Rust bridge, the
effect router, the shared invocation and outcome conformance corpora, and the
credential-isolation and dependency-graph checks are in place and verified. The
transfer plan records what remains, with each item's state and the reason it
holds that state.

## Licensing

The two trees carry different licenses: NEMO is Apache-2.0 and Crabedence is
MIT. Each directory's `LICENSE` is authoritative for that subtree.
