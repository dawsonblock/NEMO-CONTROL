# RC8.3 Legacy Custody Migration Recovery Runbook

Status: applies to `0.55.0-rc8.3-witness-fence`.
Audience: custody operator + deployment owner. Every mutating step needs a
signed operator grant from the repair authority (see
`OPERATOR-AUTHORIZATION.md`).

## 0. Non-negotiable rules

- Never hand-edit `custody_outbox`, `custody_migration_journal`, or the effect
  store. The journal is append-only; the chain is hash-linked.
- Never delete a `REPAIR_REQUIRED` marker to "unblock" admission. Clear it only
  through `custodyctl repair` after a verified full-history rescan.
- Never rewrite a witnessed (acknowledged) or checkpointed row. The tool refuses;
  do not work around it. Use the witness-coordinated recovery path in §7.
- A timed-out or partially completed command is not success. Re-run preflight and
  inspect the journal before retrying.

## 1. Preconditions

1. Stop every writer that can enqueue custody obligations (the kernel service).
2. Back up both durable stores, preserving file modes:
   - `sqlite3 custody-outbox.db ".backup 'custody-outbox.backup.db'"`
   - `sqlite3 effects.db ".backup 'effects.backup.db'"`
3. Record the current posture:
   - `custodyctl status -outbox custody-outbox.db -json`
   - `custodyctl preflight -outbox custody-outbox.db -json` (exit 3 = migration pending)
4. A live witness is mandatory, and so is a migration epoch. `migrate` fetches
   and verifies the witness's signed head over `-witness-socket` or
   `-witness-tls`, then asks the witness to **freeze the deployment at that
   head**. Offline suffix rewriting is **not authorized** in this release: a
   local outbox that lost an acknowledgement cannot prove the custodian does
   not already hold the suffix, and a checkpoint cannot prove that no
   submission is still in flight.
5. Three role-pinned trust files are mandatory and must name three distinct
   keys: `-custodian-trust-roots` (custodian keys only),
   `-kernel-trust-roots` (kernel-relay keys only) and
   `-repair-trust-roots` (repair-authority keys only). A file that pins more
   than one role, or a key pinned under two roles, is refused before any row
   is examined.

## 2. Classify the backlog (read-only)

```sh
custodyctl preflight -outbox /var/lib/crabbox/custody-outbox.db -json
```

Classifications:

| Class | Meaning | Action |
|---|---|---|
| `LEGACY-EMPTY-UNACKED` | empty payload, never witnessed | compensation candidate (§5) |
| `WITNESSED-LEGACY` | empty payload, acknowledged | classification only if the ack verifies (§5) |
| journal `unverifiable-legacy` | no authoritative terminal record | stays quarantined; find the record or escalate (§7) |
| journal `payload-compensated` | already rebuilt | verify, do not rewrite |

## 3. Issue the operator grant

The repair authority signs one grant for one operation. Required fields:
subject, role `repair-authority`, deployment id, operation (`custody-migrate`,
`custody-rescan`, or `custody-repair`), `not_before`, `expires_at`, and a
single-use nonce of at least 16 bytes. Keep the window short (minutes).

Deliver the grant file and the pinned repair-authority trust file to the
operator host out of band. The grant is not a secret, but it is authority:
protect it like a signed change ticket.

## 4. Dry run

```sh
custodyctl migrate \
  -outbox /var/lib/crabbox/custody-outbox.db \
  -effect-store /var/lib/crabbox/effects.db \
  -deployment dep-prod-a \
  -signer-key /etc/crabbox/evidence-signer.pem \
  -custodian-trust-roots /etc/crabbox/custodian-trust.json \
  -kernel-trust-roots /etc/crabbox/kernel-trust.json \
  -repair-trust-roots /etc/crabbox/repair-trust.json \
  -operator-token /run/grants/migrate.json \
  -actor alice@example.com \
  -witness-socket /run/crabbox/witness.sock \
  -dry-run -json
```

Dry-run verifies the grant, the deployment scope, the actor/subject match, and
per-row preflight. It consumes no nonce and mutates nothing. Review every
`blocked`/`quarantined` count before proceeding.

## 5. Apply

Remove `-dry-run` and use a fresh grant (the dry-run grant was not consumed, but
using a fresh one keeps the audit trail unambiguous). The witness transport is
mandatory:

```sh
custodyctl migrate ... -witness-socket /run/crabbox/witness.sock -json
```

If the witness is unreachable, its checkpoint does not verify, or the epoch
cannot be opened, migration refuses before examining any row.

`migrate` opens one epoch for the whole run and closes it after the last row.
While the epoch is open the witness refuses every submission for the
deployment — that is the point of the fence, not a fault. The sender reports
`custody is fenced for a migration epoch` and resumes on the next pass after
the close.

Per-row behavior:

- **Unacknowledged suffix, frozen epoch below the target**: the target
  receives canonical receipt bytes and every successor's
  `previous_checkpoint_hash` and signature are rewritten in one transaction.
  A signed `custody-migration-proof-v1` before/after record lands in the
  journal, binding the action, execution, terminal receipt digest,
  before/after envelope hashes, every rewritten row and the signed epoch
  (fence id, epoch number, base sequence/hash, grant digest).
- **Acknowledged row**: bytes stay byte-identical; the journal records
  `legacy-witnessed` with the authoritative terminal receipt digest. Coverage is
  later granted only if the recorded acknowledgement verifies under the pinned
  custodian set.
- **No terminal record / no canonical payload**: quarantined as
  `unverifiable-legacy`; exit code 3; REPAIR_REQUIRED remains.
- **Witnessed or checkpointed successor**: the whole suffix is refused and
  quarantined. Do not retry until §7.

Exit codes: `0` complete, `1` error/refusal, `2` usage, `3` pending migration or
blocked/quarantined rows.

## 6. Verify

```sh
custodyctl preflight -outbox ... -json      # expect exit 0
custodyctl inspect  -outbox ... -limit 200 -json
custodyctl status   -outbox ... -json
custodyctl rescan   ... -json               # full-history obligation verification
custodyctl repair   ... -reason "post-migration verification" -json  # only if REPAIR_REQUIRED
```

Acceptance:

- `preflight` exits 0 and reports no legacy rows.
- `status` reports `degraded_reason="" repair_reason=""`.
- `rescan` exits 0.
- The witness accepts the rebuilt chain (drain reaches HEALTHY).
- `MigrationJournal` contains one `payload-compensated` entry per rewritten
  target with non-empty before/after digests and a verifiable proof.
- `custodyctl fence status -outbox ... -json` reports the run's epoch as
  `CLOSED` with the result digest the operator command printed.

## 7. Blocked / quarantined recovery

If preflight or migrate reports a witnessed/checkpointed successor or a
checkpoint contradiction:

1. Stop. Preserve the outbox, journal, effect store, and witness checkpoint
   readback.
2. Do not rewrite the suffix. The witness holds bytes the outbox no longer
   matches; rewriting would fork history.
3. Escalate to the custodian. The only safe recoveries are:
   - restore the outbox from a backup that matches the witness head and re-run
     the verified migration; or
   - a witness-coordinated epoch recovery: the custodian attests the exact
     witnessed prefix, the deployment advances the custody epoch, and the
     suffix is re-custodied under the new epoch. This is an explicit,
     separately authorized forensic operation; this release does not automate
     it.
4. Record the decision in the incident register. A quarantined chain is not a
   release blocker for unrelated deployments, but CRITICAL admission for the
   affected deployment stays closed.

## 8. Crash recovery

The migration transaction is atomic and the journal is committed with it.

- **Crash before the epoch opens**: nothing changed. Re-run `migrate`.
- **Crash after the epoch opens**: custody stays fenced at the witness, and the
  outbox holds a `custody_fence_intent` row for the epoch. Re-run `migrate`
  **with the same grant file**: the nonce is already consumed by that grant,
  which the tool accepts as a resume rather than a replay, and it re-enters the
  same fence identity. If the migration will never complete, release the epoch
  explicitly with `custodyctl fence abort` using the same grant.
- **Crash before commit**: nothing changed in the outbox. Re-run `migrate` with
  the same grant; the epoch is still open and the retry runs inside it.
- **Crash after commit, before drain**: rows are rewritten and the journal entry
  exists. Re-running `migrate` returns `already_done` for that target and closes
  the epoch; the drain completes on the next sender pass.
- **Crash during drain**: the outbox retains the rows; the witness accepts
  identical resubmissions. Restart the sender.

Never restore an old outbox backup over a newer journal without also restoring
the effect store and re-verifying the witness head; the two stores must be
consistent.

## 9. Rollback

There is no in-place rollback of a committed migration. To abandon:

1. Stop the service.
2. Restore both stores from the pre-migration backups.
3. Re-verify the witness head; if the witness advanced past the restored
   outbox, the witness is authoritative and the restored outbox is stale.
4. Re-run preflight. Do not hand-edit.

## 10. Post-incident evidence

Retain: the grant file and digest, the `custody_migration_journal` rows, the
signed migration proofs, the pre/post `preflight` JSON, the witness checkpoint
readback, and the `custody_events` audit log. Bind them to the release artifact
SHA-256 in the qualification matrix.

## 11. Migration epochs (witness fence)

A checkpoint proves the custodian's state at one instant. It does not prove
that no submission is still in flight, so a rewrite under a checkpoint can
fork the two stores when a late submission lands.

```sh
custodyctl fence status -outbox /var/lib/crabbox/custody-outbox.db -json
```

| Epoch state | Meaning | Action |
|---|---|---|
| `OPEN` | custody frozen; a migration is in flight or crashed | resume `migrate` with the same grant, or `fence abort` |
| `CLOSED` | the migration completed; the custodian recorded its result digest | nothing |
| `ABORTED` | released without a result; custody resumed | nothing |

`fence abort` requires the same grant that opened the epoch and is refused if
custody advanced inside the window — that would mean a submission was admitted
while the deployment was frozen, which is an integrity fault to escalate, not
to release.

## 9. Post-review corrections

- **Preflight works on a pre-upgrade journal.** The six-column RC8.3-dev
  journal is read with typed defaults; the additive upgrade still happens only
  on a writable open, so `status`/`inspect`/`preflight` remain read-only.
- **Pin the kernel-relay key in its own file.** Compensated coverage verifies
  the signed before/after proof under `-kernel-trust-roots`. A custodian file
  offered as the kernel set is refused as a role-separation fault, and an empty
  kernel set leaves every compensated row UNRESOLVED with REPAIR_REQUIRED open.
- **A rotation-spanning suffix is refused.** If any row in the suffix was
  signed by a kernel-relay key other than the deployment's current one, the
  rewrite is refused by name; use the §7 witness-coordinated recovery path.
- **Release evidence is anchored outside the bundle.** Verify with the pinned
  key id, never with the key the bundle happens to carry:

  ```sh
  python3 qualification/rc8.3-integrity/tools/verify-evidence-bundle.py <bundle> \
    --root-key-id c1fc37659b9b8f4f41b30bc89288c7334b7eea0628a17eb2897b34236a1379b5
  ```
