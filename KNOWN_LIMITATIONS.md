# Known Limitations — NEMO-CONTROL RC7.4 (`0.54.0-rc.7.4-dev`)

This is a **development candidate**, not a qualified release. Every item below is an explicit
qualification blocker or an honest scope limit — none is counted as satisfied.

## Qualification blockers (mandatory gates not yet satisfiable here)

1. **`linux-kvm` live lane — NOT_RUN.** Requires an amd64 host with `/dev/kvm` (`ubuntu-latest`
   runner in `release-qualification.yml`). Cannot execute on this darwin/arm64 host. The lane is
   claimed by the default inventory, so until it produces passing digest-pinned evidence on the
   exact released commit, the release cannot be marked qualified.
2. **External evidence custody — NOT_RUN.** `SocketCustodian`/`sandbox-custodyd` implement and test
   the custody interface locally (signed, trust-verified acks). No independent third-party custody
   service is deployed; the external-custody release gate is unsatisfied.
3. **Exact-source qualification binding.** Local test results qualify *this working tree*. A release
   is qualified only when the gate runs against the frozen released commit/artifacts — CI-run
   evidence bound to the release commit is required; local PASSes are development evidence only.
4. **Crabbox remote/auditable validation — NOT_RUN.** `.crabbox.yaml` is present; remote execution
   on clean target-platform runners was not exercised in this session.
5. **Live PostgreSQL effect-fabric lanes** — runnable via `scripts/test-live-postgres.sh`; run status
   recorded in `QUALIFICATION_REPORT.md`, not assumed.

## Scope limits (by design, not defects)

- The microVM boundary is the isolation trust root; host-level compromise is out of scope.
- `apple-hypervisor-framework` is the only lane this host can qualify; the distribution does not
  claim Linux support until `linux-kvm` produces its own passing evidence.
- Advisory `history.*`/`research.*` capabilities deliberately have no dispatch/sign power — that is
  a feature of the trust boundary, not a gap.
- Historical qualification artifacts under `qualification/baseline/` and prior CHANGELOG release
  sections describe rc.7.x predecessors and are explicitly historical — never reused for RC7.4.

## Operational notes

- `internal/cli` race tests take ~13 min; use the repository's `-timeout=20m` (a shorter timeout
  looks like a hang).
- The post-dispatch qualification (`CRABBOX_QUALIFICATION_POST_DISPATCH=1`) is ~100s and env-gated.
- The `python:3.12` lane image digests in `qualification/msb-lane-image-pins.json` are per-arch and
  must be re-reviewed if the tag is intentionally advanced — the lane fails if the tag moved.
