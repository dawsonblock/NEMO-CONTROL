# RC8.4 Release Readiness

Release: `0.55.0-rc8.4-dev`
Branch: `codex/rc8.4-transactional-fence-security-closure`
Branch point: `af14d85` (the RC8.3 packaging commit). The source tree it
starts from is byte-identical to the signed RC8.3 source commit
`de71093469f7cd669cb3b67ac88b88ad2cd31d76`.
Baseline decision preserved: **NO-GO** (`release-out/GO-NO-GO.md`).
Baseline artifact: `b263a853090d96c646785f10906c1880e3e34c86c2f6b88318d963a78794f514`.

**Decision: NO-GO.** This branch closes source-level P0/P1 defects. It
does not qualify a release.

## Decision by deployment profile

| Profile | Decision | Basis |
|---|---|---|
| macOS arm64 / Apple Silicon HVF, exclusive runtime | **NO-GO** | Source-level gates pass (G1–G7). No RC8.4 candidate artifact exists, and G31–G34 remain BLOCKED. |
| Linux / KVM | **NO-GO** | Lane not executed. Outside the release claim and explicitly prohibited, not reported as passing. |
| Shared-runtime high assurance | **UNSUPPORTED** | Unchanged: no atomic identity-conditioned delete in msb 0.7.8. |
| Any deployment relying on third-party trust | **NO-GO** | The release root remains locally provisioned and self-pinned. |

## What this branch establishes

- **The fence receipt is no longer mutation authority.** RC8.3 claimed an
  OPEN receipt was bound to one epoch. It was not: the receipt was
  verified locally and never marked consumed, so a saved receipt rewrote
  a second target *after* the witness had recorded CLOSED and resumed
  admitting submissions. `PrepareMigration` now admits exactly one
  transaction and issues a permit naming its target and preimage; the
  local migration transaction marks that permit consumed in the same SQL
  transaction as the rewrite, the journal entry and the signed proof.
- **An epoch cannot be released over a committed rewrite.** RC8.3's
  abort guard checked custody-head movement, a condition the epoch's own
  submission barrier made unreachable; the witness aborted an epoch over
  a committed rewrite. `End` now refuses while a transaction is admitted,
  and `AbortMigration` refuses one with a committed outcome.
- **Rotation cannot mint a shared epoch or a mismatched record.** Twenty
  concurrent rotations used to produce six distinct epochs and a durable
  counter of five. `AdvanceSignerEpoch` is transactional and `Handle`
  signs from one immutable `SignerState` snapshot.
- **Retired keys cannot authorize new work.** Fence requests, receipts,
  permits and checkpoints resolve at the index the record authorizes
  next, so a key whose window closed cannot sign the state that picks a
  migration base, while pre-rotation evidence still verifies through
  `VerifyFenceReceiptHistorical` / `VerifyFencePermitHistorical`.
- **An expired grant no longer strands an epoch.** Recovery is a separate
  repair-authority grant bound to the fence, transaction, original grant
  digest, base and observed local state, with a single-use nonce. The
  abort path revokes the local permit durably before the witness RPC.
- **The qualification matrix and the evidence bundle are checked, not
  trusted.** Under the strict validator the RC8.3 matrix raises 40
  findings; the bundle verifier finds four files in `release-out` that
  ship without being in `SHA256SUMS`, including the release record and
  the release root public key.

## What this branch does not establish

- **No candidate artifact.** Nothing has been packaged, hashed or
  attested for RC8.4. `G0-candidate-identity` is NOT_RUN.
- **No external authorization.** G31 stays BLOCKED. The party holding the
  release key and the party relying on it remain the same party.
- **No independent witness.** G32 stays BLOCKED. The fence lane still
  runs a second key in the same administrative domain.
- **No third-party clean-room.** G33 stays BLOCKED. The bundle verifier
  is a local check, not an independent reproduction.
- **No restricted-deployment certification.** G34 stays BLOCKED.
- **No Linux/KVM qualification.**
- **The witness still cannot verify a remote local commit.** Finalize and
  abort rest on kernel-attested evidence plus the local revocation
  ordering. I-05 is a trust assumption, not a witness-verified invariant,
  and the protocol documentation must keep saying so.
- **A detached operator grant carries no sequence index**, so the trust
  window cannot be applied to it. A retired repair key can still issue
  one. Closing that needs a signer-epoch window in the trust file.
- **The witness never verifies the operator grant** on close or abort: it
  compares grant digests. Any holder of the kernel-relay key can release
  an epoch. Recorded as `D-RC84-08`.

## Defect register

`qualification/rc8.4-integrity/defect-register.json` is the authority.
Entries are keyed `D-RC84-NN` and cross-reference the plan's `F`/`E`
identifiers so the two registers reconcile without renumbering history.
Statuses are `OPEN`, `RED`, `GREEN`, `DEFERRED`, `ACCEPTED`.

## Reproducing the source-level gates

```sh
GOTOOLCHAIN=go1.26.5 go build ./...
GOTOOLCHAIN=go1.26.5 go vet ./...
GOTOOLCHAIN=go1.26.5 go test -race -count=1 ./internal/witness/ ./internal/custody/ ./cmd/custodyctl/
python3 qualification/rc8.4-integrity/tools/test-verify-qualification.py -v
python3 qualification/rc8.4-integrity/tools/test-verify-bundle.py -v
python3 qualification/rc8.4-integrity/tools/verify-qualification.py \
  qualification/rc8.4-integrity/qualification-matrix.json --root .
```

Gate evidence lives in `qualification/rc8.4-integrity/logs/`. A PASS in
`qualification-matrix.json` must name an existing evidence file, a
command and exit code 0; the validator enforces it.

## Gate status

`qualification/rc8.4-integrity/qualification-matrix.json` is the
authority. Gate statuses are only PASS / FAIL / NOT_RUN / BLOCKED.
