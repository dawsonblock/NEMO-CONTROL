# RC8.3 Threat Model

## Adversaries

- A co-tenant on a shared microsandbox catalog who can create,
  inspect, and (in the default catalog) resolve-and-delete names.
- A compromised or wedged msb CLI: inspect timeouts, malformed JSON,
  removals that partially apply, substitutions inside the remove.
- A replayed or forked witness: contradictory checkpoints, acks that
  disagree with recorded history, restored-from-older-snapshot heads.
- An operator action that is not authorized — including a planner,
  agent, model, plugin, or user-supplied instruction claiming
  authority (never authorization for a side effect).
- Upgrade-time adversarial history: RC8.1 legacy empty-payload rows
  that look like contradictions to canonical reconciliation.

## Boundaries and residual exposure

1. **Pre-deletion identity** — all destructive admission requires a
   classified occupant: handle prefix, nonce suffix, dispatch+job+namespace
   labels, valid namespace, and (high-assurance) a re-verified
   exclusive posture. Anything else refuses with the obligation
   preserved.
2. **Inspect→remove race** — CLI-level inspect-then-delete is not
   atomic. A substitution landing *inside* the runtime's own
   resolve-then-delete cannot be prevented client-side; RC8.3's
   mitigation is the exclusive `MSB_HOME` catalog (owner-only, euid),
   which removes co-tenant reach to write into the catalog at all.
   Shared catalogs carry NO high-assurance cleanup claim.
3. **Custody escalation** — forks, conflicting acks, contradictory
   obligation bytes, and unjournaled legacy rows all escalate to
   durable `REPAIR_REQUIRED`; nothing overwrites or reclassifies.
   Clearing requires the authenticated full-rescan repair.
4. **Operator authority** — `custodyctl` mutating ops require the
   custody evidence signer (`-signer-key`): only its holder can
   produce envelopes the witness trusts. Actor + reason are bound
   into the durable audit/journal. Read-only ops need only outbox
   read access — distinct permissions by construction.
5. **Migration safety** — acknowledged rows are evidence: never
   rewritten. Compensation touches only unacknowledged pending
   obligations and preserves chain linkage. Unverifiable history is
   quarantined + journaled, not erased; REPAIR_REQUIRED stays open.
6. **Provenance** — one signed inventory authority; verification
   requires operator-pinned signers; tamper cases covered by existing
   manifest/evidence suites.

## Explicitly out of scope / NOT closed

- Runtime-internal races below the CLI layer (a compromised msb
  daemon itself can substitute inside its own remove — mitigated, not
  eliminated, by catalog exclusivity).
- Atomic identity-conditioned delete: unavailable in msb 0.7.8; shared
  namespace remains a denied profile.
- Independent-witness and real-hypervisor (HVF/KVM) qualification —
  BLOCKED in this environment, see RELEASE_READINESS.
