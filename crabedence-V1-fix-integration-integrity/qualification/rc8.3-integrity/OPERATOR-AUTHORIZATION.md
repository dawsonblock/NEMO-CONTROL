# RC8.3 Operator Authorization Specification

Status: normative for `0.55.0-rc8.3-integrity-closure`.

## 1. Key classes

| Role | Purpose | May authorize repair/migration? |
|---|---|---|
| `kernel-relay` | signs routine custody envelopes and migration proofs | **No** |
| `custodian` | signs witness acknowledgements and checkpoints | **No** |
| `repair-authority` | signs detached operator grants | **Yes** |

The repair-authority key is pinned in a trust set supplied independently of the
custodian and kernel-relay sets (`-repair-trust-roots` /
`CRABEDENCE_REPAIR_TRUST_ROOTS`). A key trusted for one role never resolves for
another: `TrustSet.ResolveAny` matches the role exactly.

An ordinary evidence signer cannot authorize repair even if its signature is
valid. It is not pinned under `repair-authority`, so grant verification fails
with `ErrOperatorAuthorization`.

## 2. Grant document

```json
{
  "schema": "custody-operator-grant-v1",
  "subject": "alice@example.com",
  "role": "repair-authority",
  "deployment_id": "dep-prod-a",
  "operations": ["custody-migrate"],
  "not_before": "2026-10-25T20:00:00Z",
  "expires_at": "2026-10-25T20:15:00Z",
  "nonce": "0123456789abcdef0123456789abcdef",
  "issuer_key_id": "<sha256 fingerprint of the repair-authority public key>",
  "signature": "<base64 Ed25519 signature>"
}
```

Fields:

- `schema` — exact string `custody-operator-grant-v1`.
- `subject` — the operator identity. This is the only actor identity; a
  caller-supplied `-actor` must equal it or the CLI refuses.
- `role` — must be `repair-authority`.
- `deployment_id` — must equal the deployment being operated on. A grant never
  crosses deployments.
- `operations` — exact allowlist. Recognized values: `custody-migrate`,
  `custody-rescan`, `custody-repair`. `custody-repair` does not imply the other
  operations.
- `not_before` / `expires_at` — RFC3339. The grant is valid in
  `[not_before, expires_at)`. Expiry is checked against the operation time.
- `nonce` — at least 16 bytes of unpredictable data, encoded as text. It is
  consumed exactly once in the deployment's durable nonce ledger.
- `issuer_key_id` — lower-case SHA-256 fingerprint of the signing key. It must
  resolve in the pinned repair-authority trust set for the deployment.
- `signature` — Ed25519 over the canonical grant.

## 3. Signing preimage

```
"custody-operator-grant-v1\x00" || JCS(grant without signature)
```

JCS here is the same canonical form the custody envelope uses: sorted keys, no
insignificant whitespace, no HTML escaping. Go's `SignOperatorGrant` produces it;
verification recomputes it. A grant is rejected if the signature does not verify,
the schema differs, the role is not `repair-authority`, the deployment differs,
the operation is not listed, the window is empty or expired, the nonce is short,
or the issuer is not pinned.

## 4. Nonce ledger and replay protection

`operator_nonce_ledger(nonce PRIMARY KEY, subject, operation, grant_digest, used_at)`

- `ConsumeOperatorNonce` inserts the nonce and fails if it already exists. The
  comparison is by `grant_digest`; reusing a nonce with a different grant is
  refused as a replay, not treated as a retry.
- The operator surface (`custodyctl`) consumes the nonce before any mutation.
  The library then requires proof of consumption (`OperatorNonceUsed`) before a
  migration, classification, or repair proceeds.
- A captured grant cannot be replayed against a later invocation: the nonce is
  already spent. A crash after consumption requires a fresh grant; the
  underlying migration is idempotent, so retrying is safe.
- Within one `custodyctl migrate` invocation, one grant covers the whole batch.
  The nonce is consumed once at the entry point, not once per row.

## 5. Authorization by operation

| Operation | Grant operation | Additional requirements |
|---|---|---|
| `custodyctl migrate` | `custody-migrate` | effect store, signer key, custodian trust, repair trust, and a **live verified witness checkpoint** over `-witness-socket`/`-witness-tls`; offline migration is refused |
| `custodyctl rescan` | `custody-rescan` | effect store, signer key, custodian trust, repair trust |
| `custodyctl repair` | `custody-repair` | all of the above, a non-empty `-reason`, an installed full-history scanner, and a live witness transport |
| read-only (`status`, `inspect`, `preflight`) | none | owner-level access to the outbox file |

`-dry-run` verifies the grant, deployment, operation, actor/subject match, and
(for migrate) per-row preflight, but consumes no nonce and mutates nothing.

## 6. Repair preconditions

`OperatorRepair` refuses unless all of the following hold:

1. A grant verifies under the pinned repair-authority set for this deployment.
2. The grant authorizes `custody-repair`, is inside its window, and its nonce is
   consumed.
3. An independent full-history scanner is installed. A missing scanner is
   `ErrRepairScannerUnavailable`; there is no fallback to the incremental scan.
4. A `REPAIR_REQUIRED` marker is open. The exact reason is captured.
5. The full scan completes, the drain verifies the witness checkpoint and all
   acks, readiness is fresh, and no degraded marker or backlog remains.
6. A recomputed `custody-repair-evidence-v1` receipt shows the chain did not
   change during the repair.
7. The marker still equals the reason the scan observed. A concurrent
   contradiction returns `ErrStaleRepairVerification` and the new marker stays.

## 7. Trust-set administration

```json
{
  "version": 1,
  "keys": [
    {
      "role": "repair-authority",
      "key_id": "<fingerprint>",
      "public_key": "<base64 Ed25519 public key>",
      "deployment_id": "dep-prod-a",
      "valid_from_index": 0,
      "valid_until_index": 0
    }
  ]
}
```

- The file must be a regular file, not a symlink, owned by the operator, mode
  `0600` or stricter.
- Rotation successors must carry an incumbent-signed rotation authorization and
  a `valid_from_index` that begins exactly where the incumbent's window ends.
  Authority is never inherited silently.
- Pin the repair-authority anchor out of band. Do not ship it in the same
  bundle as the evidence signer.

## 8. What this does not claim

- A compromised repair-authority key grants full repair authority until
  rotation. Short windows, single-use nonces, and out-of-band pinning limit the
  blast radius but do not eliminate it.
- The library trusts an in-process caller that has already consumed the nonce.
  The durable fence is at the operator surface; arbitrary code execution inside
  the custody process is outside this boundary.
- A local database writer can forge journal rows. Grant signatures, nonce
  consumption, envelope hashes, and verified acknowledgements make forged
  coverage fail closed, but they do not make a compromised host trustworthy.
