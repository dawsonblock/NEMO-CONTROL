# RC8.3 External Qualification — Executable Specification

Release candidate: `0.55.0-rc8.3-witness-fence`
Status: **NOT EXECUTED.** Nothing in this document has been performed by
an external party. It exists so the four unexecuted gates are auditable
work items with acceptance criteria rather than adjectives, and so a
future run produces evidence that can be checked without re-deriving
the intent.

The candidate's local gates (G1–G3, G5–G9, G12–G30) pass. The gates
below are the only reason the release decision is NO-GO.

---

## G31. External trust-root authorization

**Why it is not satisfied locally.** The attestation is signed under a
release root pinned by SHA-256 key id
`c1fc37659b9b8f4f41b30bc89288c7334b7eea0628a17eb2897b34236a1379b5`,
with the private key held outside the repository. That is a real
cryptographic anchor for local qualification and nothing more: the party
that produced the key and the party that relies on it are the same
party. A self-pinned root cannot establish that anyone else authorized
the artifact.

**What an external authority must do.**

1. Receive, out of band, from the release owner:
   - the candidate archive and its SHA-256;
   - the release-root public key and its key id;
   - `qualification/rc8.3-integrity/attestation.json` and its detached
     signature;
   - the source commit the archive was built from.
2. Verify the signature against the key id **it** holds, never against
   a key supplied inside the bundle:

   ```sh
   python3 qualification/rc8.3-integrity/tools/verify-release-attestation.py \
     --root-key-id c1fc37659b9b8f4f41b30bc89288c7334b7eea0628a17eb2897b34236a1379b5 \
     --root <externally-held-root.pub> \
     --attestation attestation.json --signature attestation.sig
   ```
3. Countersign a statement binding the artifact SHA-256, the source
   commit, and the key id under which it verified.

**Acceptance evidence.** The countersigned statement, plus a transcript
of step 2 showing the root resolved from the verifier's own store.

**What is explicitly not enough.** Re-running the local verifier with
the key the bundle carries, or with `--root-key-id` copied from the
bundle README.

---

## G32. Independently administered witness

**Why it is not satisfied locally.** The fence lane runs a second key
over a unix socket in the same administrative domain as the kernel. The
plan calls that insufficient, and it is: a custodian that shares an
administrator with the kernel cannot be independent of it. The protocol
is transport-agnostic and already runs over mutually authenticated TLS,
but transport capability is not independent administration.

**What the custody operator must do.**

1. Provision a host in a separate trust domain: its own operator, its
   own key custody, its own storage, its own audit trail. The kernel
   host must not be able to read, write, or restart it.
2. Generate the witness signing key **on that host**. Export only the
   public key.
3. Pin, on the kernel host, three distinct files: the custodian public
   key (`-custodian-trust-roots`), the kernel-relay public key
   (`-kernel-trust-roots`), and the repair-authority public key
   (`-repair-trust-roots`). The three keys must be distinct; the loader
   refuses anything else.
4. Run the witness with mTLS and a pinned client key fingerprint, and
   the kernel with `-witness-tls <addr> -witness-tls-key <fp>`.
5. Execute the adversarial matrix below **across the trust boundary**,
   not on a loopback harness.

**Adversarial matrix (each row is one test).**

| Injection | Expected result |
|---|---|
| Replay a previously custodied envelope | stored ack returned, no second custody |
| Replay at a different sequence index | duplicate-execution refusal |
| Fork: two divergent records at one index | contradictory-checkpoint refusal |
| Partition the witness mid-drain | kernel DEGRADED; no terminal success claimed |
| Restart the witness mid-migration epoch | epoch still OPEN; submissions still refused |
| Rotate the witness signing key mid-epoch | receipts verify under the pinned window |
| Lost write: witness acknowledges, then loses the row | next drain re-custodies; head reconciles |
| Submission in flight when the epoch opens | refused with `ErrFenced`, not custodied |
| Fence begin naming a stale head | `ErrStaleFenceBase`, no epoch recorded |
| Fence abort after custody advanced | contradiction, epoch stays open |
| Forged fence receipt under an unpinned key | refused at the library boundary |
| Kernel clock skew beyond the grant window | grant refused |

**Acceptance evidence.** Per-row transcripts from the independent host,
the witness's own audit log, and the kernel's `custodyctl fence status`
output for the epoch rows.

---

## G33. Third-party clean-room attestation

**Why it is not satisfied locally.** `cleanroom-verify.sh` extracts the
archive into a fresh directory with fresh caches and rebuilds. It runs
on the same host, with the same toolchain installation, under the same
operator.

**What an external verifier must do.**

1. Start from a host that has never held this repository.
2. Install the pinned toolchains from the repository's
   `rc8.3-toolchain-lock.json` and `DEPENDENCY_AND_TOOLCHAIN_LOCK.json`.
3. Extract the archive and confirm the embedded inventory matches:

   ```sh
   python3 qualification/rc8.3-integrity/tools/verify-artifact.py \
     --artifact <archive.zip> --inventory <archive>.source-manifest.json
   ```
4. Build and run the candidate gates from the extracted tree only.
5. Rebuild the archive from the same commit and compare SHA-256.

**Acceptance evidence.** The verifier's own toolchain versions, the
inventory verification output, the gate logs, and the rebuild hash —
all produced on a host the release owner has no access to.

---

## G34. Restricted-deployment certification

**Why it is not satisfied locally.** The macOS arm64/HVF
exclusive-runtime profile is evidenced by the Apple hypervisor lane
(G9), but no external assessor has examined the deployment posture.

**What an assessor must do.**

1. Confirm the runtime posture on the target host: exclusive
   `MSB_HOME` catalog, owner-only permissions, namespace exclusivity
   re-verified per dispatch and per cleanup, no shared runtime.
2. Confirm the custody configuration: three role-pinned trust files,
   distinct keys, an independently administered witness (G32), and a
   migration epoch closed after the last rewrite.
3. Confirm that CRITICAL admission is refused while custody is
   DEGRADED, REPAIR_REQUIRED, UNVERIFIED_STARTUP, or fenced.
4. Attempt the escapes the residual limitations name (R1, R13–R16) and
   record whether they succeed.

**Acceptance evidence.** A signed assessment per deployment profile,
naming the exact artifact SHA-256 and the host posture observed.

---

## Recording the results

An executed gate updates `qualification/rc8.3-integrity/qualification-matrix.json`:
`status` becomes `PASS` or `FAIL`, `command` and `log` name what ran,
and `log_sha256` binds the evidence. A gate stays `BLOCKED` until it has
been executed by a party that satisfies the independence requirement
above. Editing this document does not execute anything.
