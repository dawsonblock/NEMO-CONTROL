# RC8.1 Baseline — Security Closure

Status: PR-00 evidence-truth. Branch `codex/rc8.1-security-closure` descends
from the **executed** RC8 integration HEAD — not the historical RC7.6 parent
and not any ZIP extraction.

## 1. Provenance of the branch point

| Identity | Value |
|---|---|
| Parent commit | `cbe4702e852aa4a44c19111fcdf7ecf21ef0f502` (`codex/rc8-authority-integration` HEAD: G0 + PR-00 + PR-01 + PR-02 + executed G2 evidence) |
| Tree | `771d3ee1786fa5da4a41a36b60390c05e00a380b` |
| Crabedence subtree | `1df60dfbb16c767596bf2487396554a90bbce990` |
| RC7.6 signed-candidate ancestor | `13566f1adf4fd3e3bd94981fe99670dc9de15793` (verified ancestor; byte-exact vs `73815dbd…` manifest — see `docs/rc8/BASELINE.md` §2) |
| Working tree at branch | clean except untracked `node_modules/` (umbrella-root npm artifacts, excluded) |
| Development version | `0.55.0-rc8.1-dev` frozen across VERSION / worker+nemo package files+locks / release-qualification.yml / VERIFY-RELEASE.md (`verify-version-consistency` OK) |

## 2. Toolchain lock (this host)

| Toolchain | Pinned | Resolved |
|---|---|---|
| Go | `go1.26.5` (go.mod toolchain; `GOTOOLCHAIN=local` gate) | fetched via Go toolchain mechanism; `verify-go-toolchain` PASS with `$GOROOT/bin` on PATH |
| Rust | `1.96.1` (`runtimes/nemo-relay/rust-toolchain.toml`) | rustup minimal; rustup resolves 1.96.1 only inside `runtimes/nemo-relay` (bare PATH `rustc` is 1.95.0 — gates must run inside the tree) |
| Node | 24.x | `v24.16.0` on PATH |

## 3. Provenance-managed digests

| Object | SHA-256 |
|---|---|
| `runtimes/nemo-relay` shipped tree (format 2, 1467 files, 10 symlinks) | `14fc142eda18ac4da65d498d4951f65914a175becf2bfff09ab2799043f530e1` |
| Frozen source `NEMO-feat-native-plugin-isolation` (1438 files) | `05d45ec86b1985b4aa4ba24f1315b96c858c56694c66116eae097cb68de06957` |
| `qualification/rc8-required-tests.json` (schema v2, this PR) | `607b960d37a08d559b1bb62f6b51efbab96b71a73a3eb7895360d702ec0540c6` |
| Provenance policy | `0ffe1cc939bcaaf4d4c361d5a58d9bd4e2a39e009f0c89d6809c32988c3feba1` |

## 4. Artifact status

No RC8.1 artifact exists. Any archive claiming RC8.1 identity is not a
signed release. Historical RC7.6 bundles (e.g. `73815dbd…`) are reference
sidecars only — their manifests are never inputs to RC8.1 qualification
(plan §2.7).

## 5. PR-00 defect repairs landed

- `scripts/rc8-evidence-verify.sh` → thin wrapper; implementation moved to
  `scripts/rc8_evidence_verify.py` with schema-specific modes:
  - `release-manifest-v1`: strict key set, duplicate-key rejection,
    `source_commit` (40-hex) and `artifact_sha256` (64-hex) validated
    against **distinct** expectations; artifact FILE BYTES hashed and
    compared to the manifest claim — absent artifact is FAIL; signature
    verified by `ssh-keygen -Y verify` under `rc8-release` namespace
    against an externally supplied `--trust-store`; QUALIFIED claims
    require signature verification.
  - `evidence-record-v1`: per-record schema/type checks; required cases
    must execute exactly once with outcome PASS; duplicate, SKIP/NOT_RUN,
    FAIL, foreign-commit, foreign-deployment, missing-lane, and
    missing-signer records each produce a machine-verifiable reason.
  - Path containment enforced for `artifact_path`/signature references
    (realpath under the manifest dir; traversal and escapes rejected).
- `scripts/rc8_evidence_verify_test.py`: 31-case adversarial suite — all
  plan §2 fixtures (nonexistent/modified artifact, wrong commit,
  unsigned/wrong-signer manifest, unknown schema, wrong field types,
  duplicate/skipped/absent cases, path traversal, symlink swap,
  artifact-hash-equals-commit, foreign-commit/foreign-deployment replay,
  missing host attestation, altered inventory) — 31/31 pass.
- `qualification/rc8-required-tests.json` → schema v2: G1/G2 reconciled to
  real test names (31 executed-gate tests, all verified present);
  G3–G7 carry the plan's normative names as `status: "specified"` forward
  requirements. 62 phantom identifiers eliminated.

## 6. Status corrections

Historical G1/G2 results are **reference evidence on pre-RC8.1 bytes**,
not PASS for this candidate (plan §2.8; INV-6). `QUALIFICATION_MATRIX`
rows are restated accordingly. Qualification claim for this identity:
**NOT QUALIFIED** — no mandatory lane has executed on `cbe4702`+deltas.
