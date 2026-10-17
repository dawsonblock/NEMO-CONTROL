# Upgrade Guide — RC7.3 → RC7.4 (`0.54.0-rc.7.4-dev`)

## What changed (operator-visible)

- **Ambiguous dispatch is safer.** A discovered microVM whose boot generation does not match the
  verified launch is preserved for reconciliation and reported `DISPATCH_AMBIGUOUS` — never
  destroyed, never reported as a clean failure. Operators may see new ambiguous rows where rc.7.3
  would have destroyed the VM; resolve them through the normal reconciliation path.
- **Recovery claims carry a lease and fence epoch.** Concurrent maintenance can no longer split a
  recovery window; a crashed claimant's lease expires before reassignment.
- **Mandatory audit is atomic with state.** Ambiguous markings, expirations, adoptions, and
  cleanup-pending writes now carry their durable record in the same commit — a transient storage
  fault fails the operation closed instead of landing an unaudited change.
- **Case-evidence generation is stricter.** `go-test-case-evidence.py` generation now refuses the
  malformed streams verification always rejected. A pipeline that relied on generating a record
  from a truncated/failed-package stream must fix the suite, not the tool.
- **Pinned images.** `stage-b` and both live lanes pull digest-pinned images; local
  `test-live-postgres.sh` defaults to the pinned postgres image.

## Data migration

- **Ledger schema v9 → v10** is automatic on first open: `recovery_attempts` gains `claim_epoch`
  and `claim_until_ms` (existing rows get epoch 0 and an expired lease — they remain claimable on
  their existing backoff schedule). No manual step; opening with an older binary on a v10 ledger is
  refused by the version check, as before.

## API changes (internal only)

- `Ledger.ClaimRecoveryAttempt(jobID, action string, backoff, lease time.Duration, now time.Time)
  (*RecoveryClaim, error)` — replaces `(bool, int, error)`; `nil` claim = not due / still claimed.
- `Ledger.TransitionWithRecoveryEvent(...)` — transition + mandatory event in one commit.
- `Config.ResumeBackoff` / `Config.CleanupBackoff` unchanged; the claim lease defaults to `backoff`
  when no explicit `lease` is given.

## Verification after upgrade

```bash
go build -trimpath -o bin/crabbox ./cmd/crabbox
go vet ./...
go test -race -timeout=20m ./...
node --test scripts/go-test-case-evidence.test.js
bash scripts/verify-msb-runtime-pins.sh
node scripts/verify-version-consistency.mjs
```

## Pin refresh procedure (reviewed, deliberate)

To advance `python:3.12` lane images intentionally: resolve the manifest-list digest per lane arch
(`apple-hypervisor-framework` → arm64, `linux-kvm` → amd64), update
`qualification/msb-lane-image-pins.json` under review, and let the lane verify the tag's resolved
digest equals the new pin. The lane fails closed on any unpinned drift.
