# RC8.2 Release-Readiness Report

Candidate: `0.55.0-rc8.2-dev` at commit
`32654cedd2699d27e23314ec3a91309ff71229ad` (branch
`codex/rc8.2-security-qualification`). Artifact:
`NEMO-CONTROL-v0.55.0-rc8.2-development.zip`, sha256
`57f4f6a6555edbc89a0c32a89240b1d6ed3fb25a1af6340e349413b2ef543fcc`,
SSH-signed attestation under namespace `rc8-release` (verified).

Pinned toolchains used for all lanes: **Go 1.26.5** (`go1.26.5`),
**Rust 1.96.1** (`1.96.1-aarch64-apple-darwin`), **Node v24.16.0**,
**msb 0.7.8**, Python 3.13 (uv venv).

## Gate table

| Gate | Scope | Command / evidence | Status |
|---|---|---|---|
| G1 trust-repair | unverified assessment never trusted | go1.26.5 `test -race ./internal/{history,experience,research}` (inside full sweep — 111 pkgs ok) | **PASS** |
| G2 authority-abi | signed authority, digest binding, ABI conformance | same sweep + `TestInvocationABIConformanceCorpus` (68 vectors) + `abi-differential.mjs` 2068 cases (68 corpus + 2000 seeded, seed 20261023) verdicts identical, 418 informational text-drifts | **PASS** |
| G3 release-controls | release plumbing | same sweep (`internal/releasectl`, `internal/cli` — re-run serial after load-timeout: ok 1181s) | **PASS** |
| G4 custody | durable obligations, verified readiness | same sweep + `TestCustody*`/`TestObligation*` fault-injection (13+10 new cases) + live-postgres execution suite 41s | **PASS** (loopback/local scope — see G8 blocker) |
| G5 sandbox-lifecycle | identity-bound cleanup, exclusive namespace | `internal/sandboxexecutor` full suite under `-race` 942s incl. G5 adversarial + 7 `TestNamespace*` cases | **PASS** (fake-runtime scope — see G8 blocker) |
| G6 research-boundary | no unverified promotion | same sweep (`internal/{history,experience,research,dream}`) | **PASS** |
| G7 packaging | deterministic archive + evidence binding | `package-source-archive.sh` ×2 byte-identical (57f4f6a6…), clean-room extraction verify, g7 emit→verify 4/4 records | **PASS** |
| G8 security qualification | independent end-to-end lanes | see below | **BLOCKED** |

## Qualification lanes executed for this commit

| Lane | Result |
|---|---|
| Go `-race` full sweep (`go1.26.5 test -race -timeout=20m ./...`) | 116/116 package results ok — 5 pkgs failed once under concurrent load (`internal/cli` 20m cap, providers aws/blacksmith/localcontainer/machine0); all **PASS** when re-run on the quiet machine |
| `go vet ./...`, `gofmt -l` | clean |
| Rust workspace (`cargo +1.96.1 test --workspace`, fixtures built) | 106 test-result blocks, 0 failures |
| Worker (`npm test`) | 3053 pass, 2 skip; `tsc --noEmit`, `oxlint`, `oxfmt` clean |
| Python binding (uv venv + maturin) | 609 + 142 plugin tests pass, 110 skip |
| ABI differential | 2068 cases, verdicts identical |
| Live PostgreSQL parity (`scripts/test-live-postgres.sh`, postgres:16 Docker) | 4/4 suites ok under race |
| Post-dispatch qualification (env-gated 32s/65s) | PASS 108s |
| msb runtime pins / NEMO transfer provenance | verified |

## G8 blockers (NOT_RUN — never recorded as pass)

1. **External witness custody on a separately administered host** —
   durable obligations, verified readiness, and replay are implemented
   and loopback-tested; an independently controlled custodian has not
   run (RR-02).
2. **Real hypervisor lanes** — apple-hypervisor-framework and
   Linux/KVM fault-injection on physical hosts for this commit
   (RR-03); fake-runtime adversarial coverage is comprehensive but is
   not the live lane.
3. **Shared-namespace high-assurance cleanup** — structurally
   NO-GO, not merely unrun: `msb` v0.7.8 offers no atomic
   conditional delete (RR-01); the exclusive-namespace mode is the
   enforceable boundary.

## Production decision

**CONDITIONAL / RESTRICTED.** The candidate satisfies every
implementable, independently testable security property of the RC8.2
closure scope (F-01..F-08 closed with machine-verified evidence; g1–g7
inventories executed-status and green). Production-independent-custody
deployment remains blocked by the three G8 items above.

The supported posture is: **development-candidate + exclusive-namespace
sandbox deployments**, with high-assurance production deferred until
the external-witness and live-hypervisor lanes execute against this
exact identity (commit `32654ced`, artifact `57f4f6a6…`). Any source
change produces a new candidate identity and invalidates this
report's qualification evidence.

## Next actions (exact)

1. Stand up witness on a separately administered host; run the
   custody drill matrix against commit `32654ced`.
2. Execute `internal/sandboxexecutor` on the apple-HVF and Linux-KVM
   runners for this commit (G5 lane-D evidence).
3. Keep `SANDBOX_EXECUTOR_MSB_NAMESPACE` set on every deployment that
   makes cleanup claims until a runtime with atomic conditional
   delete ships.
