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
- **Correction (this cycle):** re-inventoried `msb` v0.7.8 — `rm`
  resolves name/label then deletes; **no conditional/atomic delete
  exists**, so the native branch is unavailable and the fallback
  stands. Implemented `MSBBackend.Namespace` +
  `-msb-namespace`/`SANDBOX_EXECUTOR_MSB_NAMESPACE`: handles mint under
  `sx-<ns>-`, `crabedence.namespace` is stamped at create and verified
  on cleanup, foreign/absent-namespace occupants classify
  `IDENTITY_MISMATCH` and survive, out-of-namespace handles classify
  `IDENTITY_UNVERIFIABLE`. Documented in
  `docs/rc8.2/SANDBOX_CLEANUP.md`; NO-GO retained for shared-namespace
  high-assurance deployments.
- **Tests:** the RC8.1 G5 adversarial suite already covers replacement,
  nonce mismatch, concurrent cleanup, disappearance, timeouts, crash,
  name reuse, collision — re-run under `-race`; new
  `namespace_test.go` adds namespace validation, prefixed/labeled
  minting, foreign- and absent-namespace refusal, out-of-prefix handle
  refusal, and symmetric cross-deployment isolation.
- **Status:** CLOSED (PR-11) — exclusive-namespace fallback enforced;
  production claim restricted to namespaced deployments only.

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
- **Status:** CLOSED (PR-12) — `RELEASE_MANIFEST.json` now binds the
  RC8.2 candidate (commit `32654ced`, artifact `57f4f6a6…`,
  deterministic double-build, extraction-verified, SSH-signed
  attestation `rc8-release`); `rc8.2-required-tests.json` digest
  `b3cf71c5…` is the authoritative inventory; the stale transfer-
  manifest digest was corrected to `d094c949…`; g7-packaging's four
  normative cases are implemented and executed (`--emit-evidence`,
  4/4 verified records).

## F-09 — Maintainability: `worker/src/fleet.ts` ~24.3k lines

- **Severity:** P2 maintainability
- **Evidence:** single-module concentration across scheduling,
  lifecycle, dispatch, evidence, reconciliation, adapters.
- **Correction:** deferred to post-stabilization (PR-14); safe
  extraction boundaries identified; characterization tests required
  before any move. Not bundled into the qualification candidate.
- **Status:** SCOPED (PR-14) — `docs/rc8.2/FLEET_SCOPING.md` records
  the measured module shape and ranked extraction boundaries with
  characterization-test requirements; no refactor in the candidate,
  by design.

## Post-closure review findings (rc8.2 candidate review)

The following were raised by code review of the rc8.2 branch itself
(commits `820d44b`..`089ab75` over `codex/rc8.1-security-closure`).

## F-10 — Pre-rc8.2 outbox rows with empty payloads escalate to an unrecoverable REPAIR_REQUIRED

- **Severity:** P1 upgrade-safety (latent if no rc8.1 custody
  deployment exists; permanent wedge if one does)
- **Evidence:** rc8.1 enqueued `receipt.EvidenceReceipt` for every
  terminal execution — nil for non-CRITICAL (the F-02 evidence above)
  — producing `custody_outbox` rows whose envelope carries
  `content.bytes_b64=""`. Under rc8.2,
  `internal/execution/custody_reconcile.go:34` treats such a row as a
  present obligation; `internal/witness/outbox.go` `StoredPayload`
  returns its empty content; the byte-identity coverage check at
  `custody_reconcile.go:84` then marks `repair_reason`. The row is
  self-poisoning: re-enqueue of the same `execution_id` with real
  bytes is refused as a contradiction (`Enqueue` unique-row check),
  the outbox has no delete/quarantine path, and
  `Sender.OperatorRepair`/`CustodyObligationRescan` re-hit the same
  rows and re-escalate. Net: an rc8.1 custody outbox upgrades into a
  REPAIR_REQUIRED that no code path discharges; the only recovery is
  deleting the outbox file — undocumented chain-continuity loss.
- **Correction (required):** pick one and document/enforce it —
  (a) a documented upgrade step requiring a fresh outbox for any
  rc8.1 custody store that ever terminalized a non-CRITICAL record,
  stated in `OPERATOR_DEPLOYMENT.md` with its custody-continuity
  implication; or (b) a migration/quarantine path that retires
  empty-content rows as a legacy class (distinct from fork
  contradictions) and continues the chain.
- **Tests:** upgrade fixture — an outbox containing rc8.1-shape
  empty-content rows booted under the rc8.2 scanner must reach a
  documented, recoverable state.
- **Status:** OPEN.

## F-11 — REPAIR_REQUIRED has no shipped invocation path

- **Severity:** P1 operability
- **Evidence:** `internal/witness/sender.go:319` `OperatorRepair` and
  `internal/execution/custody_reconcile.go` `CustodyObligationRescan`
  have no non-test callers — no CLI command, admin socket, or service
  endpoint invokes them. `CustodyState` is read only by the admission
  gate (`serve.go:971`). `docs/rc8.2/OPERATOR_DEPLOYMENT.md:44`
  describes `Sender.OperatorRepair` as the clearing path, but in a
  shipped deployment the only way to clear `repair_reason` is
  hand-editing `outbox_meta` in sqlite — the un-audited mutation this
  design exists to prevent. The forensic views (`Outbox.Pending`,
  `Outbox.CustodyEvents`) are likewise unsurfaced.
- **Correction (required):** wire an operator surface — a custody
  status/repair command or a service admin endpoint — that runs a
  verified pass and records the operator's evidence note through
  `OperatorRepair`; surface `CustodyState`/`CustodyEvents` read-only.
- **Tests:** a REPAIR_REQUIRED deployment reaches HEALTHY via the
  shipped surface; a failed verified pass clears nothing.
- **Status:** OPEN.

## F-12 — Obligation rescan enumerates the entire terminal stream every drain pass

- **Severity:** P2 scalability/correctness-under-load
- **Evidence:** `custody_reconcile.go:35` calls
  `store.TerminalEvidence(ctx)` — an unbounded
  `WHERE state IN ('COMMITTED','FAILED','DENIED') ORDER BY
  terminal_seq` (`internal/idempotency/evidence_verify.go:168,205`) —
  at the head of every drain pass (default 2s). The high-water mark
  bounds re-verification, not enumeration, so per-pass cost grows
  monotonically with terminal history on both engines. Every
  above-HWM row additionally costs a `store.Lookup` plus a
  `StoredPayload` read.
- **Correction:** bound the enumeration (`terminal_seq > ?`) — e.g.
  a `TerminalEvidenceFrom(ctx, hwm)` variant — keeping the full
  fromSeq=0 form for `CustodyObligationRescan`.
- **Tests:** bounded scan still advances the HWM and still detects a
  gap below the bound when forced via the operator rescan.
- **Status:** OPEN.

## F-13 — Minor review items

- **Severity:** P3
- **Evidence:**
  - `internal/execution/control_gate.go:84` — `controlGateFlight.gen`
    is written, never read; retirement is pointer identity
    (`current == f`). The comment describes a generation guard that
    does not exist.
  - `internal/witness/sender.go:106` — `CustodyState` never consults
    in-memory `lastErr`; a transiently failed durable `MarkDegraded`
    write can leave custody reading HEALTHY inside the freshness
    window.
  - `serve.go:983` — stale-freshness DEGRADED with an empty `lastErr`
    reports "custody backlog pending" (misattributed reason).
  - `internal/witness/outbox.go:114` — empty-payload refusal reuses
    `ErrEvidenceContradiction`; it is an obligation fault, not a
    contradiction — a future caller escalating on `errors.Is` would
    over-escalate.
  - `internal/witness/sender.go:307` — the `RepairDegraded` evidence
    string asserts "obligation rescan" even when no scanner is
    installed.
  - `dispatch.go:1098` / `reconcile/worker.go:484` —
    `CustodyPayload` errors collapse to nil, losing the
    canonicalization detail from logs.
- **Correction:** drop or read `gen`; treat non-empty `lastErr` as
  DEGRADED in `CustodyState`; give stale freshness its own reason;
  use a distinct error (or plain error) for empty payloads; record
  the actual scan condition in the repair note; propagate the payload
  error into the degraded marker detail.
- **Status:** OPEN.
