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

The following could not be executed in this workspace and are recorded as
BLOCKED, not PASS:

- independent witness over authenticated transport (G8);
- live PostgreSQL durability suites (no database service/credentials);
- Apple Silicon/HVF and Linux/KVM sandbox fault-injection lanes (no pinned
  microsandbox runtime or capable Linux host);
- Rust, Python, Worker/Node, and ABI differential suites (toolchains/pinned
  environments not provisioned here);
- externally trusted release-root signing (no release key material).

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
