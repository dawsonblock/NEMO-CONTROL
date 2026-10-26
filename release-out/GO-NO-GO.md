# RC8.3 Witness-Fence Release Decision

Release: `0.55.0-rc8.3-witness-fence`
Branch: `codex/rc8.3-witness-fence-proof-qualification`
Source commit: `fca7ccd0b2ba4853504597a906ebd0f9b7156f8e` (the commit whose tree
was packaged; the packaging commit adds only `release-out/` and does not
alter source)
Artifact: `NEMO-CONTROL-v0.55.0-rc8.3-witness-fence.zip`
SHA-256: `ef2edf69a2ca5991ce84befee668d6220e9bd28719dc28fa84138c889eeeee9e`
Source inventory SHA-256: `be3ec2d29b3e70d42fb65b7197cee4f9ab2816664ef152e8f09b48a43e2097d6`

## Decision by deployment profile

| Profile | Decision | Basis |
|---|---|---|
| macOS arm64 / Apple Silicon HVF, exclusive runtime | **NO-GO** | Local gates pass (G1–G3, G5–G9, G12–G30). G31 external trust-root authorization, G32 independently administered witness, G33 third-party clean-room and G34 restricted-deployment certification are unexecuted; the attestation for this run is unsigned. |
| Linux / KVM | **NO-GO** | `linux-amd64-kvm` lane not executed (no KVM host). Outside the release claim by operator direction. |
| Shared-runtime high assurance | **UNSUPPORTED** | No atomic identity-conditioned delete in msb 0.7.8. Only the exclusive-catalog posture carries a claim, and that claim is unqualified. |
| Any deployment relying on third-party trust | **NO-GO** | The release root is locally provisioned and self-pinned; an external countersignature is required first. |

No profile is GO. The scoped GO recorded on
`codex/rc8.3-integrity-closure` is withdrawn, because the migration
authority it relied on (a verified checkpoint) is exactly what this
branch replaced with a signed witness epoch.

## What this run actually establishes

- **The two named defects are closed, and were reproduced first.**
  `qualification/rc8.3-integrity/logs/pr00-baseline-repro.log` shows the
  baseline admitting a rewrite under an unpinned key's fingerprint, and
  forking the two custody stores when a submission landed between the
  checkpoint read and the commit. Both are now refused, and the tests
  that prove it are in `g9-rc83-witness-fence`.
- **Migration cannot race an in-flight submission.** The witness freezes
  the deployment at the head the operator observed — admitted only if
  that head is still current, in the same immediate transaction as the
  fence insert — and refuses submissions until the epoch closes. A
  submission racing a fence-begin either commits before the freeze or is
  refused.
- **The proof describes the rewrite it performed.** A correctly signed
  proof that differs from the journal in identity, terminal digest, row
  hash, action, grant or epoch does not verify.
- **The three authorities are separate.** Custodian, kernel-relay and
  repair-authority keys resolve from three role-pinned files; a mixed
  file or a shared key is refused.
- **The operator path works end to end** through the shipped binary
  against a real witness, outbox and effect store.
- **The artifact is reproducible.** Two independent packaging runs over
  the same HEAD produced byte-identical archives, and the extracted
  archive builds and passes its custody and witness tests.

## What this run does not establish

- **No external authorization.** The attestation is **unsigned**: the
  release root private key is held outside this environment and is not
  available here. No signature was fabricated. Any claim of third-party
  trust would be false.
- **No independent witness.** The fence lane runs a second key in the
  same administrative domain, which the plan explicitly calls
  insufficient.
- **No third-party clean-room.** The extraction check above ran on the
  same host under the same operator.
- **No restricted-deployment certification.**
- **No Linux/KVM qualification.**

`qualification/rc8.3-integrity/EXTERNAL-QUALIFICATION.md` specifies
exactly what an external party must do for each of the four, including
the adversarial matrix the independently administered witness must
execute.

## Reproducing the artifact

```sh
python3 crabedence-V1-fix-integration-integrity/qualification/rc8.3-integrity/tools/deterministic-package.py \
  . crabedence-V1-fix-integration-integrity NEMO-CONTROL \
  release-out/NEMO-CONTROL-v0.55.0-rc8.3-witness-fence.zip
shasum -a 256 release-out/NEMO-CONTROL-v0.55.0-rc8.3-witness-fence.zip
```

The rebuild must equal `ef2edf69…`. A different hash on the same commit
means the worktree bytes differ from the tree the inventory describes —
investigate before relying on either.

## Gate evidence

`qualification/rc8.3-integrity/qualification-matrix.json` is the
authority; `RELEASE-RECORD.json` in this directory embeds the same lane
statuses at packaging time. Gate statuses are only PASS / FAIL /
NOT_RUN / BLOCKED.
