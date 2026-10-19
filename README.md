<div align="center">

# NEMO-CONTROL

**A reasoning runtime and an authority kernel, consolidated behind one narrow, testable trust boundary.**

[![Release candidate](https://img.shields.io/badge/RC-0.54.0--rc.7.5--dev-blueviolet)](RELEASE_MANIFEST.json)
[![Crabedence](https://img.shields.io/badge/Crabedence-0.54.0--rc.7.5--dev-blue)](crabedence-V1-fix-integration-integrity/VERSION)
[![NEMO](https://img.shields.io/badge/NEMO-0.9.1--rc.4-76B900)](NEMO-feat-native-plugin-isolation/RELEASING.md)
[![Go](https://img.shields.io/badge/Go-1.26.5-00ADD8?logo=go&logoColor=white)](crabedence-V1-fix-integration-integrity/go.mod)
[![msb](https://img.shields.io/badge/microsandbox-0.7.8%20pinned-orange)](rc75-evidence)
[![License](https://img.shields.io/badge/license-Apache%202.0%20%C2%B7%20MIT-lightgrey)](#licensing)

[What this is](#what-this-is) ·
[The boundary](#the-boundary) ·
[Release candidates](#release-candidates) ·
[Qualification](#qualification-status) ·
[Security model](#security-model) ·
[Layout](#repository-layout) ·
[Docs](#documentation)

</div>

---

## What this is

Two runtimes, one distribution, and the evidence trail that decides when they may ship.

| Component | Role | Version | License |
| --- | --- | --- | --- |
| **NEMO** | The reasoning/runtime layer — scopes, middleware, plugins, routing, observability. Free to plan. | `0.9.1-rc.4` | Apache-2.0 |
| **Crabedence** (Crabbox) | The authority and effect kernel — decides whether consequential work is authorized, and how it commits. Powerless to be bypassed. | `0.54.0-rc.7.5-dev` | MIT |

The design premise: **an agent runtime should be free to plan and powerless to authorize.**
Everything that can produce an external effect crosses one contract — the capability invocation
ABI — into a kernel that resolves class, authority, route, and evidence independently of whatever
asked.

This repository holds:

- Both component trees (NEMO frozen for provenance; Crabedence as the live source),
- The release-candidate source archives (`NEMO-CONTROL-v0.54.0-*.zip`) with SHA-256 digests and
  attestation records,
- The qualification campaign records: baseline audit, defect register, test matrix, threat model,
  qualification reports, and **live-lane evidence** under [`rc75-evidence/`](rc75-evidence/).

## The boundary

The two are **not** merged — and the split is the point:

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

The request on that wire carries a capability, its arguments, authority material, an idempotency
key, and a deadline. It **never** carries execution route, provider selection, assurance profile,
approval requirements, retry policy, or receipt requirements — those are resolved inside
Crabedence, and a planner that supplies them is refused rather than obeyed.

> **The invariant:** no NEMO component can independently produce a `MUTATION` or `CRITICAL`
> external effect. Asserted by tests in CI, not only documented.

<details>
<summary><strong>Execution classes and the Effect Fabric contract</strong></summary>

- **PURE** — no external effect; executes locally.
- **READ** — observational; bounded results over the `DIRECT` route.
- **MUTATION** — durable external effect with at-most-once dispatch: requires an idempotency key
  and durable storage; an ambiguous post-dispatch failure resolves `UNKNOWN` and reconciles by
  independent evidence, never a blind retry.
- **CRITICAL** — release-gate class; terminal states require Ed25519-signed evidence
  (`COMPLETED` on success, `NO_EFFECT` on failure).

The frozen state machine (`PREPARED → EXECUTING → IN_FLIGHT → COMMITTED | FAILED | UNKNOWN`) is
implemented identically by the SQLite and PostgreSQL stores and pinned by
[ADR-002](crabedence-V1-fix-integration-integrity/docs/adr/ADR-002-durable-effect-r13-contract-freeze.md):
`IN_FLIGHT` means the effect *may* have occurred; `UNKNOWN` can never auto-redispatch; terminal
states cannot regress; every mutation is fenced by lease token, generation, state CAS, and
cluster epoch.

</details>

## Release candidates

Development candidates ship as hashed, attested source archives — never floating tags.

| Package | Version | SHA-256 | Attestation |
| --- | --- | --- | --- |
| [`NEMO-CONTROL-v0.54.0-rc7.5-development.zip`](NEMO-CONTROL-v0.54.0-rc7.5-development.zip) | `0.54.0-rc.7.5-dev` | `796437dd…f6c0` | [`attestation.json`](NEMO-CONTROL-v0.54.0-rc7.5-development.zip.attestation.json) — manifest root hash + entry count |
| [`NEMO-CONTROL-v0.54.0-rc7.4-development.zip`](NEMO-CONTROL-v0.54.0-rc7.4-development.zip) | `0.54.0-rc.7.4-dev` | `ec25838d…e5b` | superseded |

Verifying a candidate:

```sh
shasum -a 256 NEMO-CONTROL-v0.54.0-rc7.5-development.zip   # must equal the .sha256 file
cat NEMO-CONTROL-v0.54.0-rc7.5-development.zip.attestation.json   # binds hash + manifest root hash
unzip NEMO-CONTROL-v0.54.0-rc7.5-development.zip -d src
```

## Qualification status

**Verdict: DEVELOPMENT CANDIDATE — not a qualified release.**

Honest accounting per the campaign rule: a mandatory gate that cannot run is recorded
`NOT_RUN` — never counted as a pass, and a skip never fabricates evidence for a lane.

| Lane / gate | Latest result | Evidence |
| --- | --- | --- |
| `apple-hypervisor-framework` live lane | ✅ **PASS 13/13** — M2 Pro, macOS 26.2, msb `0.7.8` pin-verified, `python:3.12` at the reviewed arm64 digest, `-race`, 77s | [`local-m2pro-test.log`](rc75-evidence/rc7.5-qualification/apple-hypervisor-framework/local-m2pro-test.log) |
| `linux-kvm` live lane | ✅ **PASS 14/14** — `ubuntu-latest`, `/dev/kvm`, pinned runtime + amd64 digest | [`test.json`](rc75-evidence/rc7.5-qualification/linux-kvm/test.json) · CI run [`39186297140`](https://github.com/dawsonblock/nemo-rc75-qualification/actions/runs/39186297140) |
| Unit / race / worker / postgres parity / conformance | ✅ PASS on CI | same run |
| Release evidence + admission | ⏭ **skipped — correctly** | requires an all-green board |

### Open defects blocking release (filed in [`DEFECT_REGISTER.md`](DEFECT_REGISTER.md))

| ID | Severity | Defect |
| --- | --- | --- |
| D-RC75-1 | P1 | `msb inspect` of a dead sandbox hangs on Linux → crash reconciliation cannot settle `DISPATCH_AMBIGUOUS` (3× reproduced on CI; passes on macOS) |
| D-RC75-2 | P2 | Ambiguous dispatch resolves to `SUCCEEDED` before `DISPATCH_AMBIGUOUS` is observable on Linux (2× reproduced) |
| D-RC75-3 | P1 | `release-qualification.yml` maps the apple lane to hosted `macos-15`, which cannot boot microVMs — lane evidence must come from bare-metal Apple Silicon |

Plus the pre-existing RC7.4 register items (non-atomic cleanup, false-absence outcomes,
failed-creation cleanup, release attestation) and the external-custody gate — all in
[`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md).

### Reproducing a lane

```sh
# prerequisites: jq, Go 1.26.5 (GOTOOLCHAIN=go1.26.5), and — on the host —
# Apple Silicon with kern.hv_support=1, or Linux with /dev/kvm
bash scripts/install-msb-runtime.sh            # pinned msb 0.7.8, digest-verified

MSB="$HOME/.microsandbox/bin/msb"
"$MSB" doctor                                   # host readiness
"$MSB" pull python:3.12                         # tag resolves to the pinned digest or stop

set -o pipefail
CRABBOX_MSB_LIVE=1 CRABBOX_MSB_QUALIFY=1 \
go test -v -race -count=1 -timeout=1200s -run '^TestMSBLive' \
  ./internal/sandboxexecutor/ | tee lane-test.log
```

## Security model

- **Capability registry** pins eleven capabilities across `LOCAL` / `DIRECT` / `CRABEDENCE`
  routes; all GitHub mutations are grant-required with `repo` resource constraints.
- **Runtime pinning** — every qualification artifact is digest-anchored: the msb binary and
  libkrunfw firmware against `qualification/msb-runtime-pins.json`, lane images against
  `qualification/msb-lane-image-pins.json`. A substituted release serving forged checksums still
  fails — the bytes can't match the repository-pinned digests.
- **Ambiguity is a first-class outcome.** A dispatch whose effect can't be proven resolves
  `UNKNOWN`/`DISPATCH_AMBIGUOUS` and escalates — never a blind retry, never an unverified destroy,
  never a fabricated `COMMITTED`.
- **Lane independence** — evidence from one virtualization lane never qualifies the other; a
  claimed lane missing its runtime, image, or host capability is a failed gate, not a skip.

See [`THREAT_MODEL.md`](THREAT_MODEL.md) and [`SECURITY_INVARIANTS.md`](SECURITY_INVARIANTS.md).

## Repository layout

```text
NEMO-CONTROL/
├── NEMO-feat-native-plugin-isolation/        # frozen NEMO reference (provenance only)
├── crabedence-V1-fix-integration-integrity/  # Crabedence/Crabbox — the live source
│   ├── cmd/crabbox                           # CLI entrypoint
│   ├── internal/sandboxexecutor/             # microsandbox executor, ledger, recovery
│   ├── runtimes/nemo-relay/                  # canonical NEMO source + Rust bridges
│   ├── qualification/                        # runtime + image pin manifests, required tests
│   ├── worker/ · nemo/                       # CF Worker coordinator · TS ABI adapter
│   └── docs/                                 # specs, ADRs, provider guides
├── NEMO-CONTROL-v0.54.0-rc7.*-development.zip          # release-candidate archives
│   + .sha256 · .attestation.json                       # digests + bound attestations
├── rc75-evidence/
│   ├── baseline-rc7.4/                       # RC7.4 campaign records
│   └── rc7.5-qualification/                  # this campaign: lane artifacts + run metadata
├── DEFECT_REGISTER.md                        # D-RC74-* (fixed) · D-RC75-* (open)
├── QUALIFICATION_REPORT.md · TEST_MATRIX.md  # verdicts + suite inventory
├── THREAT_MODEL.md · SECURITY_INVARIANTS.md  # trust analysis + asserted invariants
└── KNOWN_LIMITATIONS.md · REMEDIATION_REPORT.md
```

> **One NEMO source.** The NEMO code that builds, ships, and is qualified lives in
> `crabedence-V1-fix-integration-integrity/runtimes/nemo-relay/`. The outer
> `NEMO-feat-native-plugin-isolation/` tree is a frozen provenance baseline — nothing in the
> distribution compiles from it.

## Development

```sh
# from a standalone Crabedence checkout (the subtree IS its own repo root)
go build -trimpath -o bin/crabbox ./cmd/crabbox
go test -race -timeout=20m ./...

# NEMO-side + integration suites from this root
cargo test --manifest-path crabedence-V1-fix-integration-integrity/runtimes/nemo-relay/Cargo.toml
npm test --prefix crabedence-V1-fix-integration-integrity/nemo
crabedence-V1-fix-integration-integrity/scripts/check-docs.sh
```

> The Crabedence Go suite derives its repo root from `git rev-parse --show-toplevel`; run it from
> a standalone checkout, not this umbrella root. `internal/cli` legitimately takes ~13 min under
> `-race` — use the documented timeouts.

## Documentation

| Document | Contents |
| --- | --- |
| [`DEFECT_REGISTER.md`](DEFECT_REGISTER.md) | Every reproduced defect — RC7.4 (fixed) and RC7.5 (open), with reproductions |
| [`QUALIFICATION_REPORT.md`](QUALIFICATION_REPORT.md) | RC7.4 gate-by-gate verdict |
| [`rc75-evidence/rc7.5-qualification/QUALIFICATION-RUN.md`](rc75-evidence/rc7.5-qualification/QUALIFICATION-RUN.md) | The RC7.5 live-lane run: hosts, digests, CI run link |
| [`TEST_MATRIX.md`](TEST_MATRIX.md) | Suite inventory and per-gate commands |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) · [`SECURITY_INVARIANTS.md`](SECURITY_INVARIANTS.md) | Trust boundaries and the invariants tests assert |
| [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md) | Unsatisfied gates and scope limits, stated plainly |
| [`PROVENANCE.md`](PROVENANCE.md) · [`REMEDIATION_REPORT.md`](REMEDIATION_REPORT.md) | Source lineage and the RC7.4 repair campaign |
| [`docs/spec/capability-invocation-abi.md`](crabedence-V1-fix-integration-integrity/docs/spec/capability-invocation-abi.md) | The frozen wire contract |
| [`docs/RELEASING.md`](crabedence-V1-fix-integration-integrity/docs/RELEASING.md) | The release procedure this repo's machinery enforces |

## Licensing

The two trees carry different licenses: **NEMO is Apache-2.0** and **Crabedence is MIT**. Each
directory's `LICENSE` file is authoritative for that subtree.
