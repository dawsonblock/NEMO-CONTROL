# RC8.3 Release Provenance Contract (PR-06)

One authoritative contract replaces the RC8.2 ambiguity where the
signed attestation bound the embedded text inventory while an external
JSON sidecar carried a different hash and structure.

## Authorities

| Artifact | Role | Canonical form |
|---|---|---|
| `release-evidence/source-tree-sha256.txt` (embedded in the archive) | **Authoritative source inventory** — every file's mode, type, SHA-256, path, derived from the git tree (`scripts/generate-source-manifest.sh`). The signed release attestation binds THIS inventory's digest. | Sorted text, one line per entry: `<mode> <type> <sha256> <path>` |
| JSON source-manifest sidecar (`rc75-source-manifest-v1` schema) | **Auxiliary container attestation input** — feeds `verify-rc75-release.py attest`; never the authority the release signature binds. | JSON schema `rc75-source-manifest-v1` |
| `*.attestation.json` + SSH signature | Binds archive SHA-256, manifest root hash, version, commit. Verified only under operator-pinned `allowed-signers` — the bundle's own signer list is never production authorization. | `rc8-release` SSH namespace |

## Rules

1. The embedded text inventory is the sole source-content authority.
   Any verifier comparing a different-structure manifest against the
   signed attestation is comparing the wrong bytes — by contract it
   must identify the inventory by filename, not by "the JSON file".
2. `verify-rc75-release.py` remains the clean-extraction verifier for
   the rc75-schema sidecar path only. Given an RC8.x schema manifest it
   fails fast with a pointer here — never signals tampering and never
   accepts unbound metadata.
3. `rc8_evidence_verify.py` is the RC8 evidence verifier: binds
   source_commit, artifact_sha256 (hashed from file bytes), the test
   inventory digest, and the SSH signature under an externally pinned
   trust store. A missing artifact is a failure.
4. Operator verification path: `scripts/qualify-source-distribution.sh`
   (clean-room extraction → inventory re-hash → closure) followed by
   `scripts/rc8_evidence_verify.py --manifest … --artifact …
   --trust-store <pinned> --require-signature`.
5. RC8.2 signed bytes are immutable. Post-freeze RC8.2 audit addenda
   are separately versioned docs under `docs/rc8.2/`, never bytes
   protected by the RC8.2 signature.

## Tamper coverage

Existing suites cover the required matrix: corrupted archives,
wrong/unauthorized signer (`TestReleaseManifestUnauthorizedSignerRejected`),
every signed-field mutation (`TestReleaseManifestTamperedRejected`),
missing entries, `rc8_evidence_verify_test.py` for manifest/evidence
tampering, and the source-manifest generator tests
(`generate-source-manifest.test.js`).
