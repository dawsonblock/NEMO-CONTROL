# RC8.2 Findings Register

Findings carried into RC8.2 from the RC8.1 security-closure review.
Statuses: OPEN / IN_PROGRESS / CLOSED / NOT_RUN / BLOCKED.

## F-01 — Concurrent authority-admission probing consumes one result

- **Severity:** P1 (fail-closed by accident — denials are safe but
  arbitrary; correctness and availability defect)
- **Evidence:** `internal/execution/control_gate.go:86-114`. The shared
  `done chan error` (buffer 1) receives exactly one result from the
  worker; of N waiters selecting on the same channel, one consumes it
  and N−1 hit `time.After(budget)` — i.e. a completed probe is *not*
  broadcast. Reproduced by `TestControlGateProbeBroadcast*`.
- **Root cause:** result delivery via a consumable channel send rather
  than broadcast completion.
- **Correction:** generation-scoped single-flight: result stored on a
  per-flight struct, `done` closed (not sent), waiters read the stored
  result; generation counter prevents stale workers clearing newer
  probes; per-waiter timeout preserved; completed state not reused.
- **Tests:** 32- and 128-waiter broadcast, concurrent failure,
  concurrent deadline expiry, delayed stale-worker completion,
  cancellation during shared probing, recheck-after-completion,
  `-race`, repeated stress.
- **Status:** CLOSED (PR-10).

## F-02 — Custody obligations not durable; degraded state erasable

- **Severity:** P0 evidence-integrity
- **Evidence:** `internal/execution/serve.go:934-945` — enqueue failure
  calls `sender.MarkDegraded` which stores a string in an in-memory
  `atomic.Value` (`internal/witness/sender.go:80`); a subsequent
  successful `drain` executes `s.lastErr.Store("")`
  (`sender.go:202`), clearing the degraded condition even though the
  failed obligation was never persisted. Restart clears it too. A
  crash between `Finalize` commit and `Enqueue` commit loses the
  obligation silently — nothing durable records it was ever owed.
  Additionally `dispatch.go:1093` enqueues `receipt.EvidenceReceipt`,
  which is empty for non-CRITICAL terminalizations → an envelope whose
  content never verifies → permanent drain wedge.
- **Correction:** durable custody state in the outbox (`custody_events`
  audit table + `degraded_reason`/`repair_reason` meta + high-water
  `obligation_hwm`); obligation replay scanner over the store's
  `terminal_seq` enumeration (`internal/execution/custody_reconcile.go`)
  restores missing obligations with byte-identical canonical payloads
  *and* verifies stored payload bytes for present rows — a forked row
  is REPAIR_REQUIRED, never overwritten; custody states
  UNVERIFIED_STARTUP/HEALTHY/DEGRADED/REPAIR_REQUIRED; verified repair
  is the only clearing path; `Enqueue` refuses empty payloads as an
  evidence fault.
- **Tests:** outbox-write failure, kill between terminalize/enqueue,
  kill before ack, outage, concurrent drains, reconnect, duplicate
  acks, corrupt/missing obligations, partially populated recovery.
- **Status:** CLOSED (PR-10).

## F-03 — Optimistic custody startup

- **Severity:** P1
- **Evidence:** `internal/witness/sender.go:62-68` — a fresh sender has
  empty `lastErr` and an empty backlog, so `CustodyHealthy` is true
  before any witness contact, checkpoint verification, or
  reconciliation has ever occurred.
- **Correction:** `CustodyHealthy` requires a completed verified drain
  (authenticated connection + valid signed checkpoint + custody-state
  reconciliation + zero unresolved obligations) within an explicit
  freshness bound `CRABEDENCE_WITNESS_READINESS_TTL` (default 5s at
  config load; sender default `DefaultReadinessTTL` 30s); state
  reported via `CustodyState()` as
  UNVERIFIED_STARTUP/HEALTHY/DEGRADED/REPAIR_REQUIRED.
- **Tests:** offline/slow/invalid-signature/stale/wrong-identity
  witness at startup; cold restart with unacked receipts; unresolved
  historical gaps; outage immediately before admission.
- **Status:** CLOSED (PR-10).

## F-04 — Custody evidence not bound to exact release identity

- **Severity:** P1 provenance
- **Evidence:** `internal/execution/serve.go:927-932` builds
  `custody.ReleaseIdentity{Version: release}` — version string only;
  `SourceCommit`/`ArtifactSHA256` optional and never populated; no
  policy/registry binding enforcement.
- **Correction:** signed `release-manifest-v1` (`CRABEDENCE_RELEASE_MANIFEST`
  + `CRABEDENCE_RELEASE_SIGNERS` pinned fingerprints): Ed25519-verified
  manifest supplies version, source commit, artifact SHA-256, policy
  digest, registry digest; `ReleaseIdentity` extended; high-assurance
  profile requires self-hash match for `binary` artifacts (external
  binding, no circular self-hash).
- **Tests:** same-version-different-artifact, different commit, empty
  mandatory policy digest, wrong registry digest, foreign witness
  policy, tampered manifest, incorrect artifact hash, valid signature
  from unauthorized signer.
- **Status:** CLOSED (PR-10).

## F-05 — No explicit enforceable assurance profile

- **Severity:** P1
- **Evidence:** `config.go` — `CRABBOX_MODE=production` is a binary
  flag; nothing distinguishes independent-custody high assurance from
  reduced production.
- **Correction:** `CRABEDENCE_ASSURANCE_PROFILE` =
  `development`/`reduced`/`high-assurance`; high-assurance refuses
  startup (and the custody gate refuses CRITICAL admission) without
  the full custody + release-identity prerequisites; profile exposed
  on the startup report; no silent downgrade.
- **Tests:** every invalid/ambiguous configuration fails closed.
- **Status:** CLOSED (PR-10).

## F-06 — Conditional sandbox deletion is not atomic

- **Severity:** P1 (bounded by nonce handles; residual on shared
  namespaces)
- **Evidence:** `internal/sandboxexecutor/backend_msb.go` `Cleanup` +
  `docs/rc8/ADRs/0004-conditional-sandbox-cleanup.md` — `msb` exposes
  no remove-if-identity primitive; RC8.1 PR-05 bounded the steps and
  lands REMOVAL_UNCERTAIN on any unproven step (implemented).
- **Correction (this cycle):** re-inventory runtime primitives; if
  none is atomic, ship the documented exclusive-namespace deployment
  mode (`CRABEDENCE_SANDBOX_NAMESPACE=exclusive`) that makes the
  residual trust assumption explicit and enforceable, and retain
  NO-GO for shared-namespace high-assurance claims.
- **Tests:** the RC8.1 G5 adversarial suite already covers replacement,
  nonce mismatch, concurrent cleanup, disappearance, timeouts, crash,
  name reuse, collision — re-run under `-race`.
- **Status:** OPEN — PR-11 not yet executed.

## F-07 / F-08 — Release identity and reproducibility

- **Severity:** P1 release-integrity
- **Evidence:** top-level `RELEASE_MANIFEST.json` still describes
  `0.54.0-rc.7.6-dev`; no signed RC8.x artifact exists; the recorded
  required-test inventory digest (`607b960d…` in the rc8.1 baseline)
  is stale vs current bytes `741048c9…`; `g7-packaging` is
  `status: "specified"` (4 tests unimplemented); G8 not executed.
- **Correction (PR-12):** freeze candidate commit; version bump to
  `0.55.0-rc8.2-dev`; regenerate inventory digest binding; produce
  RC8.2 `RELEASE_MANIFEST` + deterministic source archive + signed
  attestation via the existing SSH `allowed-signers` mechanism;
  clean-room extraction verification; implement or rescope the four
  specified G7 tests.
- **Status:** OPEN — PR-12 not yet executed (the signed-manifest
  *runtime* half landed in PR-10: `release-manifest-v1` verify/load +
  custody-envelope release binding).

## F-09 — Maintainability: `worker/src/fleet.ts` ~24.3k lines

- **Severity:** P2 maintainability
- **Evidence:** single-module concentration across scheduling,
  lifecycle, dispatch, evidence, reconciliation, adapters.
- **Correction:** deferred to post-stabilization (PR-14); safe
  extraction boundaries identified; characterization tests required
  before any move. Not bundled into the qualification candidate.
- **Status:** OPEN — scoped, not started (by design).
