# RC8.3 Integrity Closure — Updated Threat Model

Scope: kernel custody outbox, migration/repair authority, custody operator CLI,
and Microsandbox cleanup. Baseline: `0.55.0-rc8.3-dev` (source commit
`0db72fd`). Corrected: `0.55.0-rc8.3-integrity-closure`.

## 1. Assets

- Terminal receipts and their custody envelopes (evidence of external effects).
- The append-only terminal ledger (`execution_requests.terminal_seq`).
- The hash-linked custody outbox and its acknowledgements.
- `REPAIR_REQUIRED` / degraded markers that gate CRITICAL admission.
- Repair-authority and custodian private keys; the pinned trust sets.
- Sandbox runtime catalog (`MSB_HOME`) and the instances it names.

## 2. Adversaries

- **A1 — AI agent / routine evidence signer**: can mint receipts and call
  library APIs, but must not authorize forensic repair.
- **A2 — Malicious or buggy operator tooling**: supplies actor names, flags, or
  grant files.
- **A3 — Same-UID co-tenant**: can write inside shared directories, rename
  directories, and race the runtime catalog.
- **A4 — Network attacker / compromised witness transport**: forges or replays
  checkpoints and acknowledgements.
- **A5 — Crashed process / partial write**: leaves an operation in flight.
- **A6 — Local database writer**: can insert journal or outbox rows, but not
  forge Ed25519 signatures.

Out of scope: root/administrative compromise of the host, a compromised
repair-authority private key, and a compromised Microsandbox runtime binary
(after manifest verification).

## 3. Threats and controls

| ID | Threat | Pre-fix | Post-fix control | Residual |
|---|---|---|---|---|
| T1 | Unverifiable legacy row counted as covered | any non-empty journal action skipped the row | typed `LegacyDisposition`; only `COVERED_VERIFIED` covers; UNRESOLVED/CONTRADICTION preserve `REPAIR_REQUIRED` and block HWM | none known |
| T2 | Journal read failure read as "no classification" | all errors returned `("", nil)` | only `sql.ErrNoRows` is not-found; other errors propagate | none known |
| T3 | Witnessed-legacy row covered without an ack | journal presence was enough | coverage requires a custodian-signed ack binding envelope hash, sequence, execution, deployment, family | ack forgery requires custodian key compromise |
| T4 | Migration changes a row hash and forks the successor chain | successor links left stale | atomic suffix rewrite updates every `previous_checkpoint_hash` and signature; `VerifyChain` proves it | none known |
| T5 | Migration rewrites witnessed/checkpointed history | no preflight | preflight refuses witnessed target/successor, checkpoint coverage, missing/contradictory checkpoint; quarantines the chain | witness-coordinated recovery is manual |
| T6 | Crash mid-migration loses or double-applies work | no transaction-wide protocol | single immediate transaction; signed before/after proof; idempotent replay | none known |
| T7 | Concurrent enqueue forks the chain during migration | no fence | immediate transaction + in-transaction preflight; enqueue serializes behind it and links to the rebuilt head | none known |
| T8 | Repair without a full-history scan | scanner optional | `ErrRepairScannerUnavailable`; no incremental fallback | none known |
| T9 | Caller-supplied actor authorizes repair | actor string + evidence key | detached grant signed by a separately pinned repair-authority key; subject is signature-bound | grant key compromise |
| T10 | Expired/replayed grant reused | no expiry/nonce | RFC3339 window, >=16-byte nonce, durable single-use ledger, deployment/operation scope | in-process caller after consumption is trusted |
| T11 | Stale repair clears a newer contradiction | unconditional marker clear | compare-and-swap on the exact reason inside the write transaction | none known |
| T12 | Documented CLI syntax fails / inspection exhausts memory | global flags; unbounded `Pending()` | per-subcommand flag sets; SQL cursor pagination; bounded JSON caps | operator can request a large `-limit` explicitly |
| T13 | Symlink/ancestor substitution of the runtime catalog | `os.Stat` followed links | `Lstat` refuses a symlink catalog; ancestor walk refuses non-root symlinks, unsafe modes, foreign ownership; canonical path used for runtime | root-owned platform symlinks are trusted |
| T14 | Same-UID catalog replacement between verification and delete | re-check trusted the path | dev/inode/uid identity captured and re-checked at posture time and immediately before delete | in-place modification by a same-UID writer |
| T15 | Inspect-then-delete substitution | one classification | second bounded inspection + catalog re-check immediately before `rm` | msb has no atomic identity-conditioned delete |
| T16 | Crash during cleanup loses the obligation | memory only | durable cleanup intent written before `rm`, cleared only on a resolving outcome; `PendingCleanupObligations` | intent is advisory, not an atomic delete |

## 4. Trust boundaries

1. **Evidence signer → repair authority**: distinct key classes and trust sets.
   Possession of `CRABBOX_EVIDENCE_KEY` is never repair authority.
2. **Journal row → coverage**: a row is a claim; coverage requires signature,
   nonce, hash, sequence, terminal digest, and ack verification.
3. **Outbox → witness**: the witness's signed checkpoint and acks are verified
   under the pinned custodian set; an unverifiable checkpoint is refused.
4. **Executor → runtime catalog**: the catalog path is verified and its
   dev/inode identity is re-checked before destruction.
5. **Operator → deployment**: grants are deployment-scoped; a grant for another
   deployment never verifies.

## 5. Fail-closed invariants

- No unresolved custody contradiction may be classified as verified coverage.
- No high-water advance across an unresolved sequence.
- No CRITICAL admission while `REPAIR_REQUIRED` or degraded is open.
- No migration across a witnessed or checkpointed suffix.
- No repair without a full-history scanner and a live, unconsumed grant.
- No destructive sandbox command against an unclassified, substituted, or
  catalog-replaced occupant.
- No claim of shared-runtime high-assurance cleanup.

## 6. Assumptions

- Ed25519 keys and the pinned trust files are administered out of band.
- The operator host's clock is accurate enough for grant windows.
- SQLite's `BEGIN IMMEDIATE` serializes writers on the outbox file (the DSN sets
  `_txlock=immediate`).
- The witness is independently administered and its custodian key is not shared
  with the kernel.
- Microsandbox 0.7.8 is the pinned runtime; a different version is refused.

## 7. Open risks carried into qualification

- Independent witness, live PostgreSQL, Apple Silicon/HVF, and Linux/KVM lanes
  are not available in this workspace (see `qualification-matrix.json`).
- The `-race` sandboxexecutor package is close to the 20-minute budget
  (1092s observed); a loaded host can time out.
- A compromised repair-authority key is a full-authority event until rotation.
