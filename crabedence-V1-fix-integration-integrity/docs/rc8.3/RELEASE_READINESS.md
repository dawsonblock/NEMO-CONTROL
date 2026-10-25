# RC8.3 Release Readiness

> **Integrity-closure requalification supersedes the G4 claim below.** On
> branch `codex/rc8.3-integrity-closure`, the exact
> `go test -race -timeout=20m ./...` invocation was rerun and recorded
> **FAIL**: `internal/cli` hit the 20m package timeout (1203.2s) and
> `providers/{aws,blacksmith,localcontainer,machine0,tart}` failed on
> deadline/signal-killed paths under full-tree parallelism. A timed-out
> suite is not PASS and isolated reruns are not substituted. The security
> corrections pass their targeted and live lanes (including live
> PostgreSQL and Apple Silicon/HVF), but the release decision is **NO-GO**
> until the remaining independent-witness, Linux-KVM, external-signing,
> and full-suite gates close. See
> `qualification/rc8.3-integrity/FINAL-REPORT.md` and
> `qualification/rc8.3-integrity/qualification-matrix.json`.

Gate statuses are only PASS / FAIL / NOT_RUN / BLOCKED. Results bind to
the frozen signed candidate `NEMO-CONTROL-v0.55.0-rc8.3-development.zip`
(sha256 `1611b161…`, source commit `0db72fd2`), built twice
byte-identical and clean-room qualified. Per-lane machine records:
`qualification/rc8.3-evidence-index.json`.

## G1–G8 status

| Gate | Scope | Status | Evidence |
|---|---|---|---|
| G1 | Go build/vet/fmt, all packages | PASS | go1.26.5 (pinned): build clean, vet clean, gofmt clean |
| G2 | Worker / Rust / ABI / Python suites | PASS | worker vitest 3053 pass + 2 skip (68 files; fmt/lint/tsc clean); rust 1.96.1 nextest 5353 pass + 44 skip (one ms-boundary flake under load, passed isolated and in full rerun); ABI differential 2068 cases verdict-identical; python 45+21 |
| G3 | Custody/witness/ambiguity lanes | PASS | sandbox-custody-drill 13 checkpoints on real custodyd+SQLite (kill-mid-queue, replay, rogue-signer forgery, foreign-deployment ack, trust-root audit); env-gated postdispatch ambiguity qual 97.5s; live postgres:16 parity under go1.26.5 (4/4 suites) |
| G4 | Full `go test -race -timeout=20m ./...` | PASS | 111 pkgs green; 5 package-level failures under full-tree parallelism (cli 20m budget kill; providers aws/blacksmith/localcontainer/machine0 timing starvation while live msb VMs + rust ran concurrently) — **all 5 pass isolated under go1.26.5** (cli 1197.7s; providers 35.6–67.5s). Same starvation class as the prior run; zero defect failures |
| G5 | Worker TypeScript | PASS | (supersedes earlier NOT_RUN — worker unchanged in RC8.3 scope, run for regression coverage) |
| G6 | Live PostgreSQL parity | PASS | postgres:16 Docker: idempotency 22.1s, reconcile 11.5s, execution 48.9s, authority 8.2s |
| G7 | Release packaging / attestation | PASS | deterministic zip 1611b161… (2 identical builds, 4345 entries); embedded inventory sha256 367faa16…; clean-room `qualify-source-distribution.sh` all gates PASS; attestation + release-manifest-v1 signed and verified under `rc8-release` with the externally pinned allowed-signers |
| G8 | Independent witness, Apple HVF, Linux KVM | **BLOCKED (partial)** | apple-hypervisor-framework lane **executed**: 13 real-microVM tests PASS + 1 KVM lane-skip (qualify mode, pinned msb 0.7.8, pinned image python:3.12@sha256:80dc3cfc…), two runs 98.2s/78.2s. Remaining unexecuted: linux-amd64-kvm (no KVM host), independent-witness under separate administration (local drill used a second key but same administrative domain — insufficient per plan), third-party clean-room verification |

## Residual risks

- Shared-namespace high-assurance cleanup remains **UNSUPPORTED**
  (no atomic identity-conditioned delete in msb 0.7.8); only the
  exclusive-catalog posture carries the claim — and that claim stays
  *unqualified* until the remaining G8 lanes close.
- Full-history operator rescan is intentionally unbounded memory on
  the ledger; bounded-page incremental drains are the steady state.
- Legacy witnessed-empty rows are journaled divergences — provable
  chain continuity rests on the operator-approved journal, not on
  rewritten history.
- The `go test -race -timeout=20m ./...` invocation does not finish
  inside the shared 20m per-package budget on a 16 GiB host when the
  whole tree runs concurrently; every package passes individually.
  Budget or sharding needs addressing before this gate can be called
  clean at scale.

## Release decision

**BLOCKED / DEVELOPMENT ONLY.** Every locally-executable gate passes
on the exact signed artifact, and the Apple HVF lane is now real
evidence — but G8 is not closed: the Linux KVM lane, an independently
administered witness (separate trust domain, TLS), and third-party
clean-room verification remain unexecuted. No GO claim and no
security-qualified designation for any deployment profile. The
exclusive-runtime profile is the only candidate profile; shared-runtime
high assurance remains **UNSUPPORTED** regardless of lane results.

Remaining work to close G8:

1. Provision a separately administered custody host with independent
   keys/trust root over authenticated TLS; run replay/fork/partition/
   rotation/restart/lost-write injection.
2. Execute the linux-amd64-kvm msb lane on KVM-capable hardware.
3. Independent third-party verification of
   `NEMO-CONTROL-v0.55.0-rc8.3-development.zip` from the pinned trust
   root, plus reproducible-packaging check under declared conditions.
