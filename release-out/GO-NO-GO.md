# RC8.3 Witness-Fence Release Decision

Release: `0.55.0-rc8.3-witness-fence`
Branch: `codex/rc8.3-witness-fence-proof-qualification`
Source commit: `de71093469f7cd669cb3b67ac88b88ad2cd31d76` (the commit whose tree
was packaged; the packaging commit adds only `release-out/` and does not
alter source)
Artifact: `NEMO-CONTROL-v0.55.0-rc8.3-witness-fence.zip`
SHA-256: `b263a853090d96c646785f10906c1880e3e34c86c2f6b88318d963a78794f514`
Source inventory SHA-256: `750ffcf16c44a8f86b9af29f0d7bacd99b92e5d01b91fc587bf25092880f3b22`

## Decision by deployment profile

| Profile | Decision | Basis |
|---|---|---|
| macOS arm64 / Apple Silicon HVF, exclusive runtime | **NO-GO** | Local gates pass (G1–G3, G5–G9, G12–G30) and the artifact is signed under the pinned local root. G31 external trust-root authorization, G32 independently administered witness, G33 third-party clean-room and G34 restricted-deployment certification are unexecuted. |
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
- **The artifact is reproducible and signed.** Two independent packaging
  runs over the same HEAD produced byte-identical archives; the extracted
  archive verifies against all 4413 inventory records, builds, vets and
  passes its custody race suites; and the attestation verifies under the
  pinned release root with tamper rejection.

## What this run does not establish

- **No external authorization.** The attestation is **signed** under the
  locally provisioned release root `c1fc3765…` — private key outside the
  repository and outside the bundle, public key pinned by SHA-256, and
  verification rejects a wrong root, a wrong pin, a tampered artifact and
  a tampered signature. That makes the artifact verifiable and
  tamper-evident. It does **not** make it externally authorized: the
  party that holds the key and the party that relies on it are the same
  party. G31 stays BLOCKED and any claim of third-party trust would be
  false.
- **No independent witness.** The fence lane runs a second key in the
  same administrative domain, which the plan explicitly calls
  insufficient.
- **No third-party clean-room.** `cleanroom-verify.sh` now verifies all
  4413 inventory records, builds and vets the tree, and runs the custody
  race suites from the extracted bytes with fresh caches — but on the same
  host under the same operator. It is a packaging integrity check, not
  G33.
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

The rebuild must equal `b263a853…`. A different hash on the same commit
means the worktree bytes differ from the tree the inventory describes —
investigate before relying on either.

## Gate evidence

`qualification/rc8.3-integrity/qualification-matrix.json` is the
authority; `RELEASE-RECORD.json` in this directory embeds the same lane
statuses at packaging time. Gate statuses are only PASS / FAIL /
NOT_RUN / BLOCKED.
