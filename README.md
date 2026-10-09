<div align="center">

# NEMO-CONTROL

**A reasoning runtime and an authority kernel, consolidated behind one narrow, testable trust boundary.**

[![NEMO](https://img.shields.io/badge/NEMO-0.9.1--rc.4-blueviolet)](NEMO-feat-native-plugin-isolation/RELEASING.md)
[![Crabedence](https://img.shields.io/badge/Crabedence-0.53.2-blue)](crabedence-V1-fix-integration-integrity/VERSION)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](crabedence-V1-fix-integration-integrity/go.mod)
[![Rust](https://img.shields.io/badge/Rust-1.96.1-dea584?logo=rust&logoColor=white)](NEMO-feat-native-plugin-isolation/rust-toolchain.toml)
[![Node.js](https://img.shields.io/badge/Node.js-24.x-339933?logo=node.js&logoColor=white)](NEMO-feat-native-plugin-isolation)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](NEMO-feat-native-plugin-isolation)
[![License](https://img.shields.io/badge/license-Apache%202.0%20%C2%B7%20MIT-lightgrey)](#licensing)

[Components](#components) ·
[The boundary](#the-boundary) ·
[Capability surface](#capability-surface) ·
[Status](#status) ·
[Distribution](#distribution) ·
[Development](#development) ·
[Documentation](#documentation)

</div>

---

Two runtimes, one distribution. **NEMO** is the reasoning/runtime layer —
scopes, middleware, plugins, routing, observability. **Crabedence** is the
authority and effect kernel that decides whether consequential work is
authorized, and how it is committed. This repository holds both while they are
consolidated into a single platform with a deliberately small trust boundary.

The design premise: an agent runtime should be free to plan, and should be
powerless to authorize. Everything that can produce an external effect crosses
one contract — the capability invocation ABI — into a kernel that resolves
class, authority, route, and evidence independently of whatever asked.

## Components

| Directory | What it is | Version | License |
| --- | --- | --- | --- |
| [`NEMO-feat-native-plugin-isolation/`](NEMO-feat-native-plugin-isolation) | **NEMO** — a multi-language managed execution runtime: immutable capability registration, scope stacks, middleware/interceptors, plugin lifecycle, an isolated native plugin host, LLM wrapping and routing, typed events, and Rust / Python / Node.js / Go bindings. A derived development fork of [NVIDIA NeMo Relay](https://github.com/NVIDIA/NeMo-Relay) — **not** an official NVIDIA release; see [`FORK_PROVENANCE.md`](NEMO-feat-native-plugin-isolation/FORK_PROVENANCE.md). **Frozen reference, not a development target** — see below. | `0.9.1-rc.4` | Apache-2.0 |
| [`crabedence-V1-fix-integration-integrity/`](crabedence-V1-fix-integration-integrity) | **Crabedence** (Crabbox) — the trusted execution kernel and remote-execution control plane: capability registry, grant-scoped authority, admission, durable idempotency, the Effect Fabric, signed evidence, UNKNOWN reconciliation, plus a Go CLI, ~47 remote-execution providers, and an optional Cloudflare Worker or Node.js/PostgreSQL coordinator. Carries the **canonical NEMO source** under [`runtimes/nemo-relay/`](crabedence-V1-fix-integration-integrity/runtimes/nemo-relay) and the Rust bridge/effect router under `bridges/`. | `0.53.2` | MIT |

> **One NEMO source.** The NEMO code that builds, ships, and is qualified lives
> in `crabedence-V1-fix-integration-integrity/runtimes/nemo-relay/` — every fix
> and feature goes there. The outer `NEMO-feat-native-plugin-isolation/` tree
> is a frozen copy kept for provenance: it is the baseline the transfer
> manifest's typed delta (80 modified / 29 added / 1 removed files; see
> `runtimes/nemo-transfer-manifest.json` and `PROVENANCE.md`) is computed
> against, and
> nothing in the distribution compiles from it. A change made only to the
> outer tree does not exist as far as the product is concerned.

## The boundary

The two are **not** merged, and the split is the point:

```text
NEMO decides how to run, reason, and route.
Crabedence decides whether consequential work is authorized and how it commits.
```

```text
┌──────────────────────────────┐         ┌──────────────────────────────┐
│            NEMO              │         │          CRABEDENCE          │
│                              │         │                              │
│  planner · scopes · plugins  │         │  capability registry         │
│  middleware · intercepts     │         │  authority verification      │
│  LLM routing · telemetry     │         │  admission + schema checks   │
│                              │  ABI    │  Effect Fabric (durable      │
│  capability invocation ──────┼────────▶│    idempotent execution)     │
│  (capability, args,          │  only   │  evidence + signed receipts  │
│   principal, grant_id,       │         │  UNKNOWN reconciliation      │
│   idempotency_key, deadline) │         │  provider dispatch           │
└──────────────────────────────┘         └──────────────────────────────┘
```

One narrow contract crosses between them. The request on that wire carries a
capability, its arguments, authority material, an idempotency key, and a
deadline. It **never** carries execution route, provider selection, assurance
profile, approval requirements, retry policy, or receipt requirements — those
are resolved by Crabedence's registry, and a planner that supplies them is
refused rather than obeyed.

> **The invariant:** no NEMO component can independently produce a `MUTATION`
> or `CRITICAL` external effect. Asserted by tests in CI, not only documented.

## Capability surface

Crabedence's built-in registry currently pins eleven capabilities across the
route lattice — `LOCAL` (pure), `DIRECT` (bounded reads), and `CRABEDENCE`
(durable mutations):

| Route | Capabilities |
| --- | --- |
| **LOCAL** | `system.echo` |
| **DIRECT** | `system.info` · `github.issue.get` · `github.issue.list` |
| **CRABEDENCE** | `test.counter.increment` · `github.issue.create` · `github.issue.comment` · `github.issue.close` · `github.issue.update` · `github.pr.create` · `github.pr.merge` |
| **CRITICAL** | `qualification.critical.commit` — release-gate commits, registered only when `CRABEDENCE_QUAL_PROVIDER_URL` wires the qualification provider |

All GitHub mutations are grant-required (`github.issue` / `github.pr`
authority policies) with `repo` resource constraints — `github.pr.create`
adds a `base`-branch constraint. Mutations that can embed a marker recover by
scanning for it; mutations that can't (state PATCHes, merges) recover by
desired-state observation: the locator persists SHA-256 digests of the
canonical fields and the resolver commits only when every digest matches the
observed object. Interleaved edits and non-application are indistinguishable,
so ambiguity resolves `UNKNOWN` — never a fabricated `COMMITTED`, never a
blind retry.

<details>
<summary><strong>Execution classes and the Effect Fabric contract</strong></summary>

- **PURE** — no external effect; executes locally.
- **READ** — observational; bounded results over the DIRECT route.
- **MUTATION** — durable external effect with at-most-once dispatch:
  requires an idempotency key and durable storage; an ambiguous
  post-dispatch failure resolves `UNKNOWN` and reconciles by independent
  evidence, never a blind retry.
- **CRITICAL** — release-gate class; terminal states require Ed25519-signed
  evidence (`COMPLETED` on success, `NO_EFFECT` on failure).

The frozen state machine (`PREPARED → EXECUTING → IN_FLIGHT →
COMMITTED | FAILED | UNKNOWN`) is implemented identically by the SQLite and
PostgreSQL stores and pinned by
[ADR-002](crabedence-V1-fix-integration-integrity/docs/adr/ADR-002-durable-effect-r13-contract-freeze.md):
`IN_FLIGHT` means the effect *may* have occurred; `UNKNOWN` can never
auto-redispatch and is resolved only by independent evidence; terminal states
cannot regress; and every mutation is fenced by lease token, generation,
state CAS, and cluster epoch.

</details>

## Status

Consolidation in progress. The vendored NEMO runtime, the Rust bridge, the
effect router, the shared invocation and outcome conformance corpora, and the
credential-isolation and dependency-graph checks are in place and verified.
"Partial" entries below are where architectural prerequisites are proven but
the assembled system is not yet.

| Workstream | State |
| --- | --- |
| Source integrity (provenance, declared identity, CI gate) | ✅ Closed |
| Binary declaration and build (manifest-declared binaries compiled in CI) | ✅ Closed |
| Authority dependency guards (plugin path cannot reach the authority) | ✅ Closed |
| `DIRECT` policy | ✅ Closed — implemented: `system.info`, `github.issue.get`, and `github.issue.list` dispatch over the socket on the registry-selected `DIRECT` route with bounded reads and no durable receipt (proven by `scripts/test-nemo-runtime-e2e.sh`); the wire cannot request a route |
| Distribution assembler and component binding | ✅ Closed |
| Distribution release adoption (tag-time per-target assembly, qualification, signed `SHA256SUMS`) | ✅ Closed — `.github/workflows/nemo-distribution.yml`; tag builds fail closed when `NEMO_RELEASE_SSH_SIGNING_KEY` is absent |
| NEMO artifact publication through the proof-gated release contract | ✅ Closed — the family publishes under its own signed `nemo-vX.Y.Z` tag via `scripts/publish-nemo-release.sh`: signed-tag, ruleset, distribution-run, signed-`SHA256SUMS`, and per-archive attestation binding all verified before the family release publishes (see "NEMO Distribution Family" in `docs/RELEASING.md`); the kernel `publish-release.sh` provenance contract stays scoped to `crabbox_*` |
| Plugin-host composition | ✅ Closed — real host child, mediated managed chain, fail-closed cases proven in CI; `restricted-macos` and `restricted-linux` confinement policies ship (Linux positive confinement is a non-skippable lane) |
| Installed-artifact qualification | ✅ Closed — `scripts/test-nemo-installed-distribution.sh` qualifies each packed archive on its native runner and emits a bound attestation |
| Windows integration | ⏸ Deferred (scoped out; see the platform decision) |

## Distribution

`crabedence-V1-fix-integration-integrity/scripts/build-nemo-distribution.sh`
assembles the binary distribution:

```text
dist/
├── bin/        crabbox · nemo-effect-runtime · nemo-plugin-host
├── share/      capability schema + the registry envelope the runtime serves
└── manifests/  transfer manifest + component manifest binding every
                component by SHA-256 (with its own digest alongside)
```

CI assembles the distribution and verifies the binding on every change, and
`.github/workflows/nemo-distribution.yml` builds, signs, and qualifies the
four per-target roots at tag time — a tag build fails closed when
`NEMO_RELEASE_SSH_SIGNING_KEY` is absent, while manual development runs may
still produce unsigned artifacts. Publication is the separate bound-family
operation: the qualified `nemo-control_*` tarballs ship under their own
signed `nemo-vX.Y.Z` tag with a `release/records/nemo-vX.Y.Z.json`
authorization, published by `scripts/publish-nemo-release.sh` — it
re-verifies the signed family tag, the `nemo-v*` tag ruleset, the
distribution run, the signed checksum manifest, and every
attestation-to-archive binding before creating and publishing the family
release. The kernel `publish-release.sh` provenance contract deliberately
stays scoped to `crabbox_*`: two families, two proof chains, no shared
asset list.

## Development

### Layout

```text
NEMO-CONTROL/
├── NEMO-feat-native-plugin-isolation/   # frozen NEMO reference (provenance only)
│   ├── crates/                          # core, adaptive, authority, executor,
│   │                                    #   isolation, ledger, plugin-host, …
│   ├── python/ · go/ · crates/node/     # language bindings
│   └── FORK_PROVENANCE.md               # upstream lineage and divergence
└── crabedence-V1-fix-integration-integrity/   # Crabedence / Crabbox
    ├── cmd/crabbox                      # CLI entrypoint
    ├── internal/                        # execution, authority, capability,
    │                                    #   idempotency, providers, cli
    ├── runtimes/nemo-relay/             # canonical NEMO source + Rust bridges
    ├── worker/                          # Cloudflare Worker coordinator
    ├── nemo/                            # TypeScript ABI adapter + client
    └── docs/                            # specs, ADRs, provider guides
```

### Running the suites

The NEMO-side and integration suites run from this root directly:

```sh
# Rust runtime + bridges
cargo test --manifest-path crabedence-V1-fix-integration-integrity/runtimes/nemo-relay/Cargo.toml

# TypeScript ABI adapter
npm test --prefix crabedence-V1-fix-integration-integrity/nemo

# Docs gate
crabedence-V1-fix-integration-integrity/scripts/check-docs.sh
```

> **Note — the Crabedence Go suite is different.** The `crabbox` CLI derives
> its repository root from `git rev-parse --show-toplevel`. In this layout
> that resolves to `NEMO-CONTROL/` rather than the subtree, so lease-claim
> identity, Actions hydration, and checkpoint source-claim checks compare
> against the wrong root and fail with messages that name the mismatch.
> Nothing is broken — the suite is being run from a repository it was not
> written for. Run it from a checkout where
> `crabedence-V1-fix-integration-integrity/` **is** the repository root (its
> own clone). That is what its CI does. A test run here can leave a
> `.crabbox/` run record, which is gitignored.

From a standalone Crabedence checkout:

```sh
go build -trimpath -o bin/crabbox ./cmd/crabbox
go test -race -timeout=20m ./...
```

## Documentation

| Document | Contents |
| --- | --- |
| [`docs/plan/nemo-runtime-transfer.md`](crabedence-V1-fix-integration-integrity/docs/plan/nemo-runtime-transfer.md) | The transfer plan, findings recorded while executing it, and the state of each release blocker |
| [`docs/adr/ADR-003-nemo-runtime-transfer-boundary.md`](crabedence-V1-fix-integration-integrity/docs/adr/ADR-003-nemo-runtime-transfer-boundary.md) | The trust-boundary decision and the ownership matrix |
| [`docs/spec/capability-invocation-abi.md`](crabedence-V1-fix-integration-integrity/docs/spec/capability-invocation-abi.md) | The frozen wire contract, with its strict parsing rules |
| [`docs/spec/durable-execution-contract.md`](crabedence-V1-fix-integration-integrity/docs/spec/durable-execution-contract.md) | The Effect Fabric's durable execution contract |
| [`docs/architecture/`](crabedence-V1-fix-integration-integrity/docs/architecture) | Execution kernel, authority model, capability registry semantics, reconciliation and recovery |
| [`crabedence-V1-fix-integration-integrity/README.md`](crabedence-V1-fix-integration-integrity/README.md) | The Crabedence project README: Effect Fabric, kernel, providers, operations |
| [`NEMO-feat-native-plugin-isolation/README.md`](NEMO-feat-native-plugin-isolation/README.md) | The NEMO project README: runtime model, bindings, security posture |

## Licensing

The two trees carry different licenses: **NEMO is Apache-2.0** and
**Crabedence is MIT**. Each directory's `LICENSE` file is authoritative for
that subtree.
