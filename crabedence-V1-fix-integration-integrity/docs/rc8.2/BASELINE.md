# RC8.2 Baseline — Security Closure & Release Qualification

Status: Phase 0 baseline. Branch `codex/rc8.2-security-qualification`
descends from the **executed** RC8.1 integration HEAD — authenticated
Git history, not a ZIP extraction. Target development version
`0.55.0-rc8.2-dev`.

## 1. Provenance of the branch point

| Identity | Value |
|---|---|
| Parent commit | `4e2afb8e17a715495925dab0bbff184a8f88f61d` (`codex/rc8.1-security-closure` HEAD: PR-00..PR-06 executed) |
| Tree | `022c071515d94286fbc27b27d57acc0ec74c741c` |
| Crabedence subtree | `7b18ec02b6ade7a3a8d0448f3e0c182323af7dcf` |
| RC7.6 signed-candidate ancestor | `13566f1adf4fd3e3bd94981fe99670dc9de15793` (verified ancestor — see `docs/rc8/BASELINE.md` §2 and `docs/rc8.1/BASELINE.md` §1) |
| Working tree at branch | clean except untracked `node_modules/` (umbrella-root npm artifacts, excluded) |
| Development version | `0.55.0-rc8.1-dev` at branch point; RC8.2 bumps to `0.55.0-rc8.2-dev` in the first development commit |

## 2. Toolchain lock (this host)

| Toolchain | Pinned | Resolved |
|---|---|---|
| Go | `go1.26.5` (go.mod toolchain; `GOTOOLCHAIN=local` gate) | `go1.26.5` present in `$GOPATH/bin`; `GOTOOLCHAIN=auto` resolves it per go.mod |
| Rust | `1.96.1` (`runtimes/nemo-relay/rust-toolchain.toml`, `NEMO-feat-native-plugin-isolation/rust-toolchain.toml`) | resolved by rustup inside the runtime trees only |
| Node | 24.x | `v24.16.0` on PATH |
| Host | darwin/arm64 (Apple Silicon, M-series) | Apple Hypervisor lane executable locally; Linux/KVM lane NOT available on this host |

## 3. Provenance-managed digests (at branch point)

| Object | SHA-256 |
|---|---|
| `runtimes/nemo-relay` shipped tree (format 2, 1467 files, 10 symlinks) | `14fc142eda18ac4da65d498d4951f65914a175becf2bfff09ab2799043f530e1` |
| Frozen source `NEMO-feat-native-plugin-isolation` (1438 files) | `05d45ec86b1985b4aa4ba24f1315b96c858c56694c66116eae097cb68de06957` |
| `qualification/rc8-required-tests.json` (current bytes) | `741048c9eb6e520a4580146a569d49f0e7d3d9e45e673bf9f50da7d319f5617e` |
| `qualification/rc8.2-required-tests.json` (RC8.2 inventory, PR-12) | `b3cf71c5bc263c7aec43b8bd449cfc7487496e52e78863eca56a346fd0809881` |
| Provenance policy | `0ffe1cc939bcaaf4d4c361d5a58d9bd4e2a39e009f0c89d6809c32988c3feba1` |

Note: the rc8.1 baseline recorded inventory digest `607b960d…`; the
inventory then evolved through PR-03..PR-06. `741048c9…` is the digest
of the exact bytes at the RC8.2 branch point and is the value RC8.2
release records must carry (F-08).

PR-12 note: `qualification/rc8.2-required-tests.json` is the RC8.2
mandatory-test inventory — the rc8.1 file is retained unmodified for
history; the RC8.2 document binds the PR-10/PR-11/PR-12 closure tests
and flips `g7-packaging` to `executed` (the four normative cases are
implemented in `scripts/rc8_evidence_verify_test.py::G7PackagingGate`,
executed by `--emit-evidence`). Its digest `b3cf71c5…` is the value RC8.2
release manifests and evidence verification must pin.

## 4. Artifact status

No RC8.2 artifact exists. Any archive claiming RC8.2 identity before
the freeze commit is not a release candidate. Historical RC7.x bundles
remain reference sidecars only — their manifests are never inputs to
RC8.2 qualification. Top-level `RELEASE_MANIFEST.json` still describes
`0.54.0-rc.7.6-dev` — retained as a historical record and superseded
by the RC8.2 manifest produced under PR-12 (F-07).

## 5. Module inventory (authoritative surfaces)

| Surface | Path | Role |
|---|---|---|
| Authority admission gate | `internal/execution/control_gate.go` + `internal/releasectl` | operator halt/resume/revoke folded-chain check at dispatch |
| Dispatch executor | `internal/execution/dispatch.go` | admission, provider invocation, fenced terminalization |
| Terminal ledger | `internal/idempotency` (sqlite + postgres) | `terminal_seq` append-only terminalization order |
| Custody envelope | `internal/custody` | `custody-envelope-v1` typed records + trust sets |
| Witness | `internal/witness` | receipt-family custody log, checkpoint, ack, sender, outbox |
| Reconciliation | `internal/reconcile` | UNKNOWN-claim recovery workers |
| Sandbox executor | `internal/sandboxexecutor` | fenced job ledger + microsandbox backend cleanup |
| Release controls | `internal/releasectl` + `cmd/crabbox control` | signed append-only operator event ledger |
| Worker coordinator | `worker/src` (`fleet.ts` ~24.3k lines) | Cloudflare Worker control plane (F-09 scope) |
| Qualification inventory | `qualification/rc8-required-tests.json` | mandatory-test registry (schema v2) |

## 6. Baseline test state (at branch point)

Executed under `go1.26.5` on darwin/arm64:

| Suite | Result |
|---|---|
| `go build ./...` | PASS |
| `go test -race ./internal/witness` | PASS (3.8s) |
| `go test -race ./internal/custody` | PASS (1.4s) |
| `go test -race ./internal/execution` | PASS (see §6a) |
| `go test -race ./internal/reconcile` | PASS (see §6a) |

### 6a. Baseline notes

- F-01 reproduced before repair: `controlGateProbe` delivers the shared
  probe result on a single buffered `chan error`; of N concurrent
  waiters exactly one receives the completed result and N−1 fall to
  their timeout denial. See FINDINGS_REGISTER F-01 for the regression
  test that demonstrates it.
- `internal/cli` is the known-slow package (~13min, 15m budget) — run
  only in the full-suite lane, not per-PR iteration.
- Live-PostgreSQL gates run via `scripts/test-live-postgres.sh` when a
  database is provisioned; Docker is unavailable in this environment —
  `initdb`/`pg_ctl` local-instance path required, else NOT_RUN.
- Rust workspace tests run inside `runtimes/nemo-relay` only (rustup
  resolves 1.96.1 there).

## 7. Qualification claim for this identity

**NOT QUALIFIED.** RC8.1 evidence is reference evidence on prior bytes.
No mandatory lane has executed on `4e2afb8`+RC8.2 deltas.
