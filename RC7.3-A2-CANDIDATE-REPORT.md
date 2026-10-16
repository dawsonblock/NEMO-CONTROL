# NEMO-CONTROL — RC7.3-A.2 Candidate Report (Phase 1: Evidence Integrity)

Captured: workspace `NEMO-CONTROL`, canonical repo
`crabedence-V1-fix-integration-integrity/`, base commit
`3e89c3cfc901db4437721bdf50a85510a89fc1ca` (branch
`fix/rc7.1-closed-policy-and-recovery`).

All changes are working-tree diffs against that commit — reviewable with
`git diff`. No release status was granted; this is the candidate record.

## What Phase 1 fixed

### 1.1 Test-evidence lifecycle (`scripts/go-test-case-evidence.py`)

The parser now enforces the canonical `go test -json` lifecycle for every
test-scoped event:

    run -> (output | pause | cont)* -> exactly one terminal (pass|fail|skip|bench)

One shared walk (`_scan_stream`) backs BOTH generation (`parse_stream`)
and verification (`verify_stream`) — normalized evidence and verified
evidence can no longer diverge in what a stream means. Rejects:

- terminal outcome or any event without a preceding `run`
- duplicate `run` events for the same test
- duplicate terminal events (counted; ≠1 is a finding)
- any event after a test's terminal outcome, or after a package's
- `pause` while not running, `cont` while not paused
- test-scoped `start`; package-scoped `run`/`pause`/`cont`/`bench`
- a test straddling two package identities; duplicate package `start`
- missing package-level terminal outcome; package-level `fail`/`skip`
  laundered into per-test `pass` records; package `pass` over a derived
  failed/incomplete case
- malformed JSON lines, non-object events, unknown actions, non-string
  Test/Output, non-numeric Elapsed

`runner.arch` is now emitted in canonical goarch spelling
(`amd64`/`arm64`), matching the inventory's `goarch` convention; the
validator's `canon_arch` remains the cross-check for foreign spellings.

Verified empirically against a real `go test -json` stream (subtests,
`pause`/`cont`, skips, package framing all accepted).

### 1.2 Evidence-path confinement (`scripts/lib/qualification-gates.sh`)

`qualification_evidence_path_findings` is now the single admissibility
rule for every digest-bound path (test_suite inventory/results/raw in
the validator, gate evidence in both admission and artifact verifier):

- absolute paths, `.`/`..` segments, empty components → `escape`
- symlinked intermediate directory → `symlink_dir` (→ "escapes the bundle")
- symlinked evidence file → `symlink_file`
- missing, non-regular, unreadable → findings
- physical containment: the file's real parent must resolve under the
  evidence root's real path — alias escapes are caught even with no
  lexical tell

`qualification_evidence_snapshot` copies each admitted file once into a
private scratch dir; digests, inventory comparisons, and stream
re-derivation all read the snapshot — never the live path — so a path
swapped post-validation cannot smuggle different bytes past the digest
binding. An inode change across the copy is reported as `replaced`.

Note for portability: fd-pinning via `exec {fd}<` is bash ≥4.1-only and
is deliberately absent — this repo's shell runs on macOS bash 3.2. The
snapshot+digest construction gives the same guarantee.

### 1.3 Trusted runtime pins (install + verify + admission)

- `verify-msb-runtime-pins.sh`: in qualifying mode (default) a nonzero
  `MSB_PINS_FILE` ≠ the repo manifest is refused outright; the manifest
  must also be byte-identical to `HEAD:qualification/msb-runtime-pins.json`
  when inside a work tree — an uncommitted pin edit cannot qualify.
  `MSB_PINS_NONQUALIFYING=1` is the only escape and labels the result
  "never release evidence". Then: doctor health, pinned version, binary
  sha256, firmware sha256 — all fail-closed.
- `install-msb-runtime.sh`: same qualifying/non-qualifying split for the
  download path.
- `check-release-admission.sh`: a claimed lane with no bundled
  `msb-runtime-pins.json` is an inconsistency; a bundled manifest whose
  sha256 differs from the repository's trusted file is an inconsistency.
- `generate-release-evidence.sh` already ships the manifest copy into
  the bundle (`msb-runtime-pins.json`) — unchanged behavior now asserted.

### 1.4 Platform qualification + CI-runner provenance

- Lane evidence must name the lane's `goos`/`goarch` (canon_arch-
  normalized), the runner os/arch, the toolchain os/arch tail, the
  source commit, and the package identity — all already enforced, now
  exercised by new tests.
- `generate-release-evidence.sh` records `provenance.ci` under GitHub
  Actions (server_url, repository, run_id, run_attempt, job, workflow,
  workflow_ref, sha, event_name, RUNNER_OS/ARCH/ENVIRONMENT, image).
- Imported lane evidence (register_lane_import) must carry `ci` matching
  THIS run's run_id/repository/sha when the record is CI-produced.
- The validator cross-checks `results.ci` against `provenance.ci`:
  CI-claiming evidence under a non-CI record, missing ci under a CI
  record, wrong run_id/repository/sha/workflow_ref, wrong CI runner
  os/arch — each is a finding.
- `check-release-admission.sh` rejects `release-manifest.json`
  `supported_lanes` not backed by `qualified_lanes` — an enabled,
  unqualified backend cannot ship.

## Verification performed

| Check | Result |
| --- | --- |
| `python3 -m py_compile scripts/go-test-case-evidence.py` | PASS |
| `bash -n` on all six modified shell scripts | PASS |
| `node --test` all 102 `scripts/*.test.js` files | **1073/1073 PASS** (with `~/sdk/go1.26.5/bin` on PATH; without it, 6 env failures — `spawnSync go ENOENT` — all re-pass with Go present) |
| Real `go test -json` stream (subtests, pause/cont, skip) through normalizer | PASS |
| **Live Apple lane**: `CRABBOX_MSB_LIVE=1 go test -json -run TestMSBLive ./internal/sandboxexecutor` on pinned msb 0.7.8 + libkrunfw | **14 pass, 1 skip (`TestMSBLiveLinuxKVM` — foreign lane), package pass** — 77 events |
| Normalizer + `--inventory` + `--source-root` coverage on that real stream | PASS, 0 uncovered |
| `--verify` re-derivation vs normalized record on the real stream | PASS, 0 findings |
| `verify-msb-runtime-pins.sh` against host `/Users/dawsonblock/.microsandbox/bin/msb` | **PASS (qualifying mode)** — binary+firmware match trusted pins |

Live-stream artifact digests (local run evidence, not release evidence):

- raw stream `/tmp/msblive-stream.json`: `dc13eba4…7721`
- normalized `/tmp/msblive-cases.json`: `832b7b2c…4e1f`

## Changed-file digests (sha256)

- `scripts/go-test-case-evidence.py` `dac2a4bf…2d20`
- `scripts/lib/qualification-gates.sh` `d3f6ae31…2071`
- `scripts/check-release-admission.sh` `deda93ea…5ced`
- `scripts/verify-release-artifact.sh` `9401b21f…3f45`
- `scripts/verify-msb-runtime-pins.sh` `bb010162…93cd`
- `scripts/install-msb-runtime.sh` `4484f46c…693c`
- `scripts/generate-release-evidence.sh` `3c2b3cfa…90f25`
- `scripts/required-tests.test.js` `d0baa046…2197`
- `scripts/msb-runtime-pins.test.js` (new) `be87dc8a…6a56`

## New/changed adversarial coverage (Phase 1.5 list)

Existing suite already covered: forged inventory digest, swapped
inventory, foreign-lane substitution, wrong lane/runner/commit/toolchain,
aggregate-count forgery, `../` escape, missing file, malformed binding,
duplicate terminal, output-digest mismatch, foreign package, malformed
line, truncated stream, claimed-lane-without-gate, cross-lane gate reuse,
malformed claimed_lanes.

Added this phase:

- terminal outcome with no preceding `run` — rejected
- duplicate `run` event — rejected
- unknown go test action — rejected
- evidence file that is a symlink out of the bundle — rejected
- evidence path through a symlinked directory component — rejected
- claimed lane without bundled trusted pins — rejected (admission)
- substituted bundled pins manifest — rejected (admission)
- `MSB_PINS_FILE` override in qualifying mode — refused
- substituted msb executable reporting the pinned version — refused
- forged pins manifest matching forged bytes — works only in explicit
  NON-QUALIFYING mode (labelled as such)
- lane evidence asserting CI provenance under a non-CI record — rejected
- lane evidence from a different CI run_id — rejected
- lane evidence bound to the record's CI run — accepted
- manifest advertising an unqualified lane — rejected (admission)

## Residual risks / not yet qualified

1. **CI lane is unproven**: the live run above is a LOCAL developer-host
   run. Release qualification requires the same lane under the CI
   workflow with `provenance.ci` bound — plus the linux-kvm lane, which
   this host cannot run (`TestMSBLiveLinuxKVM` correctly skipped).
2. **Pin-change governance is commit-bound, not signature-bound**:
   `verify-msb-runtime-pins.sh` requires the manifest to match HEAD. A
   malicious *commit* would still need source review — "independently
   trusted source or attestation for pin changes" is partially
   delivered (provenance gate + commit binding); cryptographic
   attestation of pin changes is Phase 4 territory.
3. **Snapshot inode race detection is best-effort** — `ls -id` before/
   after copy; the digest binding is the actual guarantee.
4. **Phase 1 does not prove release admission end-to-end** — a full
   `generate-release-evidence.sh` run (all gates incl. worker build,
   go vet, provenance) was not executed; only the qualification
   semantics and the live lane were exercised.
5. Untracked test file `scripts/msb-runtime-pins.test.js` must be
   committed with the rest.

Classification for this phase: **PARTIALLY QUALIFIED** — evidence
integrity controls are repaired and verified locally (including one real
live lane execution), but no CI-authenticated, pins-bound, multi-lane
qualification bundle exists yet.
