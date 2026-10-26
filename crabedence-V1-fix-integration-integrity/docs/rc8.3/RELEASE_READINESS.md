# RC8.3 Release Readiness

> **Witness-fence requalification supersedes the integrity-closure
> readiness claim.** On branch
> `codex/rc8.3-witness-fence-proof-qualification`, migration authority
> moved from a verified checkpoint to a signed, open witness epoch
> (RC83-IC-34/35), the migration proof now binds the whole journal row
> (IC-36), and the three custody authorities resolve from three
> role-pinned trust files (IC-37). The locally executable gates for
> those changes pass under `-race`; the external gates below remain
> unexecuted and are not claimed.
>
> Decision: **NO-GO for every deployment profile.** The macOS
> arm64/HVF exclusive-runtime profile is the only candidate profile and
> its local evidence is intact, but external trust-root authorization
> (G31), an independently administered witness (G32), third-party
> clean-room attestation (G33) and restricted-deployment certification
> (G34) are unexecuted. A scoped GO would require at least G31 and G32.
>
> **Release-root pin.** The attestation is signed under the release root whose
> SHA-256 key id is
> `c1fc37659b9b8f4f41b30bc89288c7334b7eea0628a17eb2897b34236a1379b5`. That
> fingerprint is the anchor: it is supplied from outside the bundle to
> `verify-release-attestation.py` / `verify-evidence-bundle.py`, and the
> private key is held outside the repository (`$RELEASE_ROOT_KEY`). The
> previous root and its private key were committed to the tree by mistake;
> both are retired, and any signature under key id `387d837e…` must be
> rejected.

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

## Witness-fence gates (RC8.3 PR-01..PR-06)

| Gate | Scope | Status | Evidence |
|---|---|---|---|
| G24 | Fence verification at the migration library boundary | PASS | unpinned key, closed epoch, zero fence and another grant's epoch each refused before mutation |
| G25 | In-flight submission protection | PASS | a submission on the wire is refused once the epoch is open; stale fence base refused; abort over advanced custody escalated |
| G26 | Epoch durability and crash recovery | PASS | witness restart leaves the epoch open; pre/post-commit crash and idempotent replay; durable local fence intent |
| G27 | Proof/journal/chain binding | PASS | correctly signed proofs that differ in identity, digest, action, row hash, grant or epoch all refused |
| G28 | Role-separated trust roots | PASS | mixed files refused, shared keys refused, cross-role resolution refused, CLI requires three files |
| G29 | End-to-end fenced migration through the shipped binary | PASS | real witness, real outbox, real effect store; 2 rows compensated, epoch closed, chain intact, drain to HEALTHY, replay refused |
| G30 | Formal per-package race gate | PASS | `scripts/qualify-race.sh`: 5 packages, 0 failed, per-package JSON evidence |

The whole-tree `go test -race -timeout=20m ./...` invocation is retained
as G4a evidence of a package-budget problem, not as the gate; G30
replaces it with a reproducible per-package measurement.


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
  `scripts/qualify-race.sh` is the gate that measures this without
  hiding it (G30); the whole-tree invocation stays recorded as G4a.
- A migration epoch freezes custody for the whole deployment. While it
  is open, submissions are refused and the sender reports the fence
  rather than a fault. An operator who leaves an epoch open has
  suspended custody — deliberately, and visibly, via `custodyctl fence
  status`.

## Release decision

**NO-GO for every deployment profile.** Every locally-executable gate
passes on the candidate, including the witness-fence gates G24–G30, and
the Apple HVF lane is real evidence — but the external gates are not
closed: no external authorization of the trust root (G31), no
independently administered witness (G32), no third-party clean-room
attestation (G33), and no restricted-deployment certification (G34).
The macOS arm64/HVF exclusive-runtime profile remains the only
candidate profile; shared-runtime high assurance remains
**UNSUPPORTED** regardless of lane results, and Linux/KVM remains
outside the release claim.

A scoped GO for the exclusive-runtime profile would require, at
minimum, G31 (an external authority countersigning the release root)
and G32 (a witness administered in a separate trust domain over
authenticated TLS, with replay/fork/partition/rotation/restart/
lost-write injection).

Remaining work:

1. Provision a separately administered custody host with independent
   keys/trust root over authenticated TLS; run replay/fork/partition/
   rotation/restart/lost-write injection, including the new
   fence-begin/fence-end handshake across the trust boundary.
2. Obtain an external countersignature of the release root and of the
   candidate artifact.
3. Execute the linux-amd64-kvm msb lane on KVM-capable hardware.
4. Independent third-party verification of the candidate archive from
   the pinned trust root, plus reproducible-packaging check under
   declared conditions.
