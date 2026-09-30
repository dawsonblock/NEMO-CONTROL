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

The distinction that matters below is between proving architectural
prerequisites and proving the assembled system. "Partial" entries are the
latter.

| Workstream | State |
| --- | --- |
| Source integrity (provenance, declared identity, CI gate) | Closed |
| Binary declaration and build (manifest-declared binaries compiled in CI) | Closed |
| Authority dependency guards (plugin path cannot reach the authority) | Closed — static invariant; runtime containment still requires composition testing |
| `DIRECT` policy | Closed — deliberately refused in the first release |
| Distribution assembler and component binding | Closed |
| Distribution release adoption (GoReleaser emits the assembled distribution) | Open |
| Plugin-host composition | Partial — safety prerequisites done, actual composition open |
| Installed-artifact qualification | Open |
| Windows integration | Deferred (scoped out; see the platform decision) |

## Distribution

`crabedence-V1-fix-integration-integrity/scripts/build-nemo-distribution.sh`
assembles the binary distribution: `bin/` (crabbox, the NEMO effect runtime,
the plugin host), `share/` (the capability schema and the registry envelope the
runtime serves), and `manifests/` (the transfer manifest plus a component
manifest that binds every component by SHA-256, with its own digest alongside).
CI assembles it and verifies the binding on every change.

The Crabedence release pipeline does not consume it yet — its archives still
carry the CLI alone — and that gap is recorded in the transfer plan rather than
implied away by the heading above.

## Running the suites

The NEMO-side and integration suites run from here without ceremony — Rust
(`cargo test` under `crabedence-V1-fix-integration-integrity/runtimes/nemo-relay`),
TypeScript (`npm test --prefix nemo`), and the docs gate
(`scripts/check-docs.sh`).

The Crabedence Go suite is different, and the reason is worth knowing before it
bites. That CLI derives its **repository root** from
`git rev-parse --show-toplevel`. In this layout that resolves to *this*
directory rather than the subtree, so lease-claim identity, Actions hydration,
and checkpoint source-claim checks compare against the wrong root and fail —
with messages that name the mismatch, e.g. `lease … is claimed by repo
…/crabedence-V1-fix-integration-integrity; use --reclaim to claim it for
…/NEMO-CONTROL`. Nothing is broken in the code; the suite is being run from a
repository it was not written for.

Run it from a checkout where `crabedence-V1-fix-integration-integrity/` **is**
the repository root — its own clone. That is what its CI does, and it is why CI
is unaffected. The same resolution is why a test run can leave a `.crabbox/`
run record here, which is gitignored.

## Licensing

The two trees carry different licenses: NEMO is Apache-2.0 and Crabedence is
MIT. Each directory's `LICENSE` is authoritative for that subtree.
