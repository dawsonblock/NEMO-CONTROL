# RC8.3 Upgrade Guide

## From RC8.2 → RC8.3

Backward-compatible: schema changes are additive
(`custody_migration_journal` CREATE IF NOT EXISTS), the
`TerminalEvidence` interface gains a bounded variant, and all new
behavior is fail-closed only where it replaces an unsafe fall-through.

### Steps

1. Deploy the RC8.3 binaries. The version string moves to
   `0.55.0-rc8.3-dev`; `crabbox`/`sandbox-executord`/`custodyctl` all
   read the same env contract.
2. **Preflight (mandatory when upgrading an existing custody outbox):**
   ```
   custodyctl preflight -outbox <outbox.db>
   ```
   Exit 3 means legacy empty-payload rows need classification —
   CRITICAL admission stays blocked until migration runs.
3. **Migrate (operator-approved):**
   ```
   custodyctl migrate -outbox … -signer-key <evidence.pem> \
     -effect-store <store.db> -actor <operator> -witness-socket … \
     -deployment … -trust-roots … [-release-version 0.55.0-rc8.3-dev]
   ```
   Unacked legacy rows are compensated in place from the
   authoritative terminal store; witnessed rows are journaled;
   unverifiable rows are quarantined (exit 3 — forensic escalation,
   REPAIR_REQUIRED stays open).
4. **High-assurance deployments:** provision the exclusive catalog
   first (`mkdir -m700 <msb-home>` owned by the daemon uid), then run
   `sandbox-executord -assurance-profile=high-assurance -msb-namespace
   <ns> -msb-home <dir>`. Startup is refused otherwise.
5. Rollback: RC8.3 is safe to downgrade **unless** migration ran —
   compensated rows are valid RC8.2-readable envelopes, but the
   journal table is unknown to older code (harmless, ignored).
   Rollback BEFORE migration needs no action. If a migration
   partially applied, restore the preflight backup of the outbox.

### Compatibility

| Surface | Status |
|---|---|
| Existing stores | additive migration journal; terminal_seq index unchanged |
| IPC/ABI | custodyctl is additive; no wire changes |
| User settings | `SANDBOX_EXECUTOR_MSB_HOME`, `SANDBOX_EXECUTOR_ASSURANCE_PROFILE` are new, optional |
| Deployed daemons | executord requires catalog provisioning only under high-assurance |
| Release formats | contract pinned in PROVENANCE_CONTRACT.md; rc75 script fails fast on rc8 schemas |

### Operator runbook (recovery)

- `custodyctl status` → state + markers + HWM + backlog.
- `custodyctl inspect` → pending rows + custody events.
- `custodyctl rescan` → full-history obligation verification.
- `custodyctl repair -actor X -reason "…"` → authenticated repair;
  requires the marker open, a full rescan, verified drain and fresh
  readiness. A failed stage clears nothing.
- `custodyctl preflight` exit 3 → run `migrate`; migrate exit 3 →
  forensic escalation (quarantined rows listed in the journal).
