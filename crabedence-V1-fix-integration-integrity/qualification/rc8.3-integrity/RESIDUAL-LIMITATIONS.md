# RC8.3 Integrity Closure — Residual Limitations

These are explicit, tested-against limits. They are not waived; a release claim
that depends on them must state the dependency.

## R1. No atomic identity-conditioned delete in Microsandbox

`msb rm` resolves the catalog record at the name when it executes. RC8.3
narrows the inspect-then-delete race with:

1. a bounded pre-removal inspection that classifies the occupant;
2. a catalog dev/inode/uid re-check;
3. a second bounded inspection immediately before `rm`;
4. a second catalog re-check;
5. a nonce-bound handle as the deletion key.

A substitution that lands between the final check and the runtime's internal
resolve is still possible. Closing it requires an atomic conditional delete
(name + expected envelope hash) in the runtime or an equivalent enforceable
primitive. Until then:

- high-assurance cleanup is claimed only for the exclusive-runtime posture
  (non-empty namespace + dedicated owner-only `MSB_HOME`);
- shared-runtime high-assurance cleanup is **UNSUPPORTED**, not "best effort".

Tested by: `TestCleanupReinspectCatchesSubstitution`,
`TestCleanupSubstitutionInsideRemovalWindow`,
`TestCleanupRejectsCatalogReplacementInsideWindow`.

## R2. Same-UID catalog interference

A process running as the same UID can write inside the verified catalog and can
modify runtime state in place. Dev/inode identity detects rename/replacement,
not in-place tampering. The posture assumes no same-UID co-tenant shares the
catalog. Deployments that cannot guarantee that must not claim high assurance.

## R3. Repair-authority key compromise

A stolen repair-authority key can sign grants until the key is rotated. The
single-use nonce, short validity window, deployment scope, and operation
allowlist bound the blast radius but do not eliminate it. Rotation is an
explicit incumbent-signed act; a new key never inherits authority silently.

## R4. Local database writer

A local writer can insert journal rows, outbox rows, or nonce rows. Grant
signatures, terminal receipt digests, envelope hashes, verified acks, and nonce
consumption make forged coverage fail closed, but a host compromise is outside
the custody boundary. The outbox directory is owner-only (`0700`), and the trust
files must be owner-only regular files.

## R5. In-process caller after nonce consumption

The durable nonce fence is enforced at the operator surface (`custodyctl`). The
library trusts an in-process caller that has already consumed the nonce, because
the caller and the outbox share the same process boundary. Arbitrary code
execution inside the custody process is out of scope.

## R6. Witness-coordinated recovery is manual

A witnessed or checkpointed suffix is never rewritten automatically. Recovery
requires the custodian to attest the witnessed prefix and the deployment to
advance the custody epoch. This release refuses safely and documents the
protocol; it does not implement the forensic recovery automation.

## R7. Qualification infrastructure gaps

The lanes that were unavailable when the RC8.3-dev baseline was written are
now executed and recorded as PASS in `qualification-matrix.json`: live
PostgreSQL 16 (G8), the independent TLS witness (G11), Apple Silicon/HVF
microVMs (G9), the Rust/Python/Worker/Node/ABI suites (G12–G17), and the
local clean-room reproduction (G21). Their raw logs are attached to the
release bundle and hash-bound by the attestation.

Still BLOCKED, and never reported as PASS:

- Linux/KVM fault-injection (G10) — excluded by operator direction.
- Third-party clean-room (G21 is a *local* reproduction) and third-party
  trust of the release root — both require an external party.

## R8. Race-suite timing

`go test -race` for `internal/sandboxexecutor` observed 1092s (18.2 min) against
the 20-minute package budget. It passed, but a loaded host or parallel package
contention can time out. A timeout is not PASS. Release lanes should give this
package a dedicated budget or investigate the slow fault-injection tests.

## R9. Offline migration checkpoint blind spot

If `custodyctl migrate` is run without `-witness-socket`/`-witness-tls`, it
cannot observe an external checkpoint. The tool reports `checkpoint_verified:
false` and still refuses any suffix it can prove is witnessed locally. Operators
must not run offline migration against a deployment whose witness may hold a
newer checkpoint; the runbook makes this a precondition.

## R10. Kernel-relay pinning is required for compensated coverage

A `payload-compensated` journal entry covers a legacy row only when its
signed before/after proof verifies under the pinned kernel-relay keys in the
trust-roots set. A deployment that pins only custodians has no way to
attribute that proof, so compensated coverage stays UNRESOLVED and
REPAIR_REQUIRED remains open — fail-closed, but it must be resolved by
pinning the kernel-relay key before running `custodyctl migrate`.

## R11. A suffix that spans a key rotation is refused

Migration re-signs every rewritten row with the deployment's current
kernel-relay key. If any row in the suffix was signed by a different key, the
rewritten row would sit at a sequence index outside that key's pinned
`ValidFromIndex` window and would no longer verify. `MigrateLegacySuffix`
therefore refuses the whole operation and names the row; recovery is the
manual witness-coordinated protocol in R6, not an automatic rewrite.

## R12. Release root is pinned locally

The attestation is signed under a release root held outside the repository
and pinned by SHA-256 key id
(`c1fc37659b9b8f4f41b30bc89288c7334b7eea0628a17eb2897b34236a1379b5`).
Verification requires that fingerprint from outside the bundle; the copy
inside the bundle is a distribution convenience only. This is a real
cryptographic anchor for local qualification, not a third-party root: an
external countersignature is still required before anyone else may rely on it.

## R13. A migration epoch suspends custody for the whole deployment

While an epoch is open the witness refuses every submission for that
deployment, and the sender reports the fence rather than a fault. That is
the mechanism, not a defect: it is what makes a rewrite unable to race an
in-flight submission. The operational consequence is that an epoch left
open by a crashed migration suspends custody until an operator resumes the
migration or releases the epoch with `custodyctl fence abort`. Both paths
require the grant that opened the epoch, so an unrelated operator cannot
unfreeze a deployment.

## R14. One epoch at a time, one grant per epoch

The witness admits exactly one open epoch per deployment. A migration that
must resume after a crash re-enters the same fence identity with the same
grant; a fresh grant cannot open a second epoch while one is open, and
cannot close one it did not open. This is deliberate: concurrent migrations
of one deployment have no safe interleaving, and the epoch is the object
that makes that statement enforceable rather than advisory.

## R15. Fence coverage is per deployment, not per row

The epoch freezes the deployment's custody head. It does not assert
anything about rows the witness already holds above that head — those are
refused by preflight (a frozen base at or above the target blocks the
rewrite) rather than reconciled. A custodian that holds a suffix the local
outbox no longer matches is still the R6 manual recovery case.

## R16. External gates remain unexecuted

G31 (external authorization of the release root), G32 (an independently
administered witness in a separate trust domain over authenticated TLS),
G33 (third-party clean-room attestation) and G34 (restricted-deployment
certification by an external assessor) are not executed and are not
claimed. The fence protocol is transport-agnostic — it runs unchanged over
the unix socket and over mutually authenticated TLS — but transport
capability is not independent administration.

## R17. An epoch that committed a migration is closed, never aborted

`fence abort` refuses when the outbox journal shows a migration
committed inside the epoch. Releasing the fence then would let the
sender resume with envelopes the migration has already replaced — the
in-flight corruption the epoch exists to prevent. An epoch in that state
is finished by re-running `migrate` with the same grant (which closes
it), not by releasing it.

The check is local: it reads the outbox journal, which is the same
store the migration wrote. A second host that shares the witness but not
the outbox is outside this check, and would have to be prevented
operationally by scoping a deployment to one outbox.

## R18. CI's deadcode gate is red at baseline, independently of this branch

`ci.yml` runs `deadcode -test ./...` and fails on any output. The frozen
baseline commit already reports 16 unreachable symbols across eight
packages, so the step cannot pass on the tree this branch started from.

This branch is neutral on that set: after the fence work the report is
byte-identical to the baseline report (`diff` of the sorted lists is
empty). Five symbols the fence work initially orphaned —
`Client.ActiveFence`, `Ledger.meta`, `Ledger.MaxEnvelopeEpoch`,
`Ledger.Stored` and `Outbox.CompensateLegacyRow` — were removed rather
than left to enlarge the list.

Resolving the remaining 16 is a separate change. Several are plausibly
reachable only under build tags (`windows`, `smoke`, `witnesslane`) that
`deadcode` does not analyse by default, so each deletion needs checking
against every configuration before it is safe. Doing that inside a
security release would mix unrelated risk into the reviewed diff.
