# RC8.3 Integrity-Closure Release Evidence (detached)

This directory is outside the source tree so the attestation can bind the
exact final commit and artifact without hash circularity.

## Artifacts

- `source-inventory.txt` — canonical inventory of 4382 tracked entries,
  generated from Git HEAD and worktree bytes (symlink targets hashed as bytes).
- `source-a.zip`, `source-b.zip` — two independent deterministic packages,
  byte-identical (`514f0cd9…`).
- `attestation.json` — detached attestation, **SIGNED** (Ed25519).
- `attestation.canonical.json`, `attestation.sig` — the signed bytes and the
  signature over them.
- `release-root/release-root.pub`, `release-root/key-id.txt` — **distribution
  copy** of the release root public key. Not a trust anchor.
- `packaging.json` — packaging determinism record.
- `qualification-matrix.json`, `logs/` — the gate matrix and its raw logs.

## Trust anchor

The release root is pinned **outside** this bundle by SHA-256 fingerprint:

```
c1fc37659b9b8f4f41b30bc89288c7334b7eea0628a17eb2897b34236a1379b5
```

The private key is never in this repository or this bundle; signing reads
`$RELEASE_ROOT_KEY` (default `~/.config/crabbox/release-root.pem`). A bundle
that carried its own root could be replaced wholesale — new key, new
attestation, new signature — and still verify, so the verifier refuses to run
without an externally supplied anchor.

## Verifying

```sh
# from the source tree, with the pinned fingerprint above
python3 qualification/rc8.3-integrity/tools/verify-evidence-bundle.py <this-dir> \
  --root-key-id c1fc37659b9b8f4f41b30bc89288c7334b7eea0628a17eb2897b34236a1379b5

# attestation only, against a key you hold
python3 qualification/rc8.3-integrity/tools/verify-release-attestation.py <this-dir> \
  --root /path/to/release-root.pub
```

Both verifiers resolve the attestation checker beside themselves, never from
this bundle. `negative-tests.sh` reproduces every tamper case, including a
coherent root substitution.

## Negative fixtures

`tampered.zip`, `swapped-inventory.txt`, `attestation-swapped.json` — inputs for
the tamper tests. Do not distribute.

## Scope

The archive is a corrected development candidate qualified for the macOS
arm64 / Apple Silicon HVF, exclusive-runtime profile. It is **not** qualified
for Linux/KVM (excluded by operator direction), for shared-runtime
high-assurance cleanup (UNSUPPORTED — no atomic identity-conditioned delete in
msb 0.7.8), or for third-party trust without an external countersignature of
the release root. See `qualification/rc8.3-integrity/FINAL-REPORT.md` in the
source tree for the gate matrix.
