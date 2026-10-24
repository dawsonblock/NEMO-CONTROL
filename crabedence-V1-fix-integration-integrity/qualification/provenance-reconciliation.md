# Provenance Reconciliation — v0.54.0 Qualification Candidate

Qualification run ID: `QUAL-2026-10-23-01` (source-identity recertification).
Baseline: Crabedence v0.53.2 / NEMO Relay v0.9.1-rc.4.
Recorded against commit `7761f44` (`docs(provenance): recertify runtime
identity after abi-verdict addition`).

## 1. The discrepancy

| Item | Declared in transfer manifest (stale) | Computed from candidate tree |
|---|---|---|
| Canonical runtime SHA-256 | `e1279ef20acc448ac52a6ac2332c81f71e278b2bf71579160ffc953d0f9567a0` | `905fb5476c556aaa1d2815929249d9c81ffb2c76de6bcf5bae9407ba7495756d` |
| Runtime file count | 1,466 | 1,467 |
| Expanded added-file count | 29 | 30 |
| Frozen source SHA-256 | `05d45ec86b1985b4aa4ba24f1315b96c858c56694c66116eae097cb68de06957` | same — PASS |

The frozen source was untouched; only the canonical runtime tree and its
declared delta drifted.

## 2. Forensic resolution of every delta unit

The drift is fully explained by one intentional changeset:

- **30th added file**: `runtimes/nemo-relay/bridges/nemo-crabedence/examples/abi_verdict.rs`
  — a differential-test binary added by commit `5e64d63`
  (`test(authority): live Go/Rust invocation-ABI differential and fuzz`).
  It is a test artifact, not on any runtime, dispatch, or authorization path.
- **1466 → 1467 file count**: that single file accounts for the +1.
- **29 → 30 expanded added count**: same file, expanded delta accounting.
- **78 modified / 1 removed**: unchanged before and after — class-for-class
  equal under `verify-nemo-transfer.py`.
- **0 symlink / retype / mode changes**: unchanged.

No unexplained modification, deletion, symlink retarget, executable-bit
change, or extra archive member remains.

## 3. Resolution taken

Option (B) from the plan — accept an intentional new change set with review
and requalify from scratch — applied as follows:

1. `scripts/regenerate-nemo-provenance.sh` ran the canonical manifest
   updater (`cmd/nemo-runtime-digest -update`); the manifest now declares
   the computed identity `905fb547…` with the expanded delta 78/30/1.
   Generation and verification remain separate tools; nothing self-repaired.
2. All current-identity restatements in `PROVENANCE.md`, `README.md`, and
   `FINAL_QUALIFICATION_REPORT.md` were updated to `905fb547…` / 1467 / 30.
3. The qualification report was **not** silently carried forward: its verdict
   records that the executed lanes ran against the prior `e1279ef2…`
   identity and that full-lane requalification on `905fb547…` remains open.
4. `bash scripts/check-provenance-docs.sh` and
   `python3 scripts/verify-nemo-transfer.py` both PASS on the new bytes
   (manifest regeneration idempotent, delta class-for-class declared,
   generated provenance blocks match).

## 4. Independent verification receipts

```
python3 scripts/verify-nemo-transfer.py
  ok: source ../NEMO-feat-native-plugin-isolation
      05d45ec86b1985b4aa4ba24f1315b96c858c56694c66116eae097cb68de06957
      (1438 files, 10 symlinks)
  ok: delta 78 modified, 30 added files, 1 removed files,
      0 added links, 0 removed links, 0 retargeted, 0 retyped,
      0 mode changes — all declared
bash scripts/check-provenance-docs.sh
  ok: provenance statistics in dependent docs match
      runtimes/nemo-transfer-manifest.json
```

## 5. Source inventory

`source-inventory.json` in this directory is the deterministic per-entry
inventory of the tracked tree at `7761f44`: 4,104 entries (12 symlinks),
each carrying path, type, Git mode, size, blob SHA-256 (link target for
symlinks), component owner, and provenance class. Regenerate with:

```
node scripts/generate-source-inventory.mjs
```

## 6. Status

- Source identity `905fb547…`: **SOURCE_VERIFIED** at run
  `QUAL-2026-10-23-01`.
- BUILT / TESTED / QUALIFIED / SIGNED / PUBLISHED for the new identity:
  **NOT RUN** — pending Phase-2 lane execution on the candidate bytes.
  Prior-lane evidence is historical context only and does not transfer.
