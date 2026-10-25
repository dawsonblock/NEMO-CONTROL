# RC8.3 Integrity-Closure Release Evidence (detached)

This directory is outside the source tree so the attestation can bind the
exact final commit and artifact without hash circularity.

- `source-inventory.txt` — canonical inventory of 4376 tracked entries,
  generated from Git HEAD and worktree bytes (symlink targets hashed as bytes).
- `source-a.zip`, `source-b.zip` — two independent deterministic packages,
  byte-identical (`59fdea52…`).
- `attestation.json` — detached attestation draft. **UNSIGNED**: signature
  status is BLOCKED because no externally trusted release root or signing key
  is available. Verdict: **NO-GO**.
- `packaging.json` — packaging determinism record.
- `verify-good.log`, `verify-tampered.log`, `verify-swapped.log` — artifact
  hash-binding and tamper rejection evidence.
- `tampered.zip`, `swapped-inventory.txt`, `attestation-swapped.json` —
  negative-test fixtures. Do not distribute.

The archive is a corrected development candidate, not a security-qualified
release. See `qualification/rc8.3-integrity/FINAL-REPORT.md` inside the source
tree for the gate matrix and the conditions to promote.
