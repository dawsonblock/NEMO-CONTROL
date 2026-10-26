#!/usr/bin/env python3
"""Verify the RC8.3 integrity-closure attestation against a pinned root.

Checks, in order:
  1. the signature block is SIGNED with ed25519 and a key id that
     matches the pinned public key;
  2. the canonical attestation (signature block removed) is byte-
     identical to the signed canonical file;
  3. the Ed25519 signature verifies under the pinned release root;
  4. the artifact SHA-256 and source inventory SHA-256 match.

Any failure is a hard rejection (exit 1). A modified attestation, a
modified signature, a swapped manifest, or a swapped archive fails.

Usage: verify-release-attestation.py <release-dir>
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    base = os.path.abspath(sys.argv[1])
    att_path = os.path.join(base, "attestation.json")
    att = json.load(open(att_path, encoding="utf-8"))
    sig_block = att.get("signature", {})
    if sig_block.get("status") != "SIGNED" or sig_block.get("algorithm") != "ed25519":
        print(f"REJECT: attestation is not signed (status={sig_block.get('status')!r})", file=sys.stderr)
        return 1

    root = os.path.join(base, "release-root")
    pub = os.path.join(root, "release-root.pub")
    der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", pub, "-outform", "DER"])
    key_id = hashlib.sha256(der).hexdigest()
    if sig_block.get("key_id") != key_id:
        print(f"REJECT: signer key id {sig_block.get('key_id')} != pinned {key_id}", file=sys.stderr)
        return 1

    unsigned = dict(att)
    unsigned.pop("signature", None)
    canon = canonical(unsigned)
    signed_path = os.path.join(base, "attestation.canonical.json")
    signed = open(signed_path, "rb").read()
    if canon != signed:
        print("REJECT: attestation canonical bytes differ from the signed canonical file", file=sys.stderr)
        return 1

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(canon)
        tmp_path = tmp.name
    try:
        proc = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub, "-rawin",
             "-in", tmp_path, "-sigfile", os.path.join(base, "attestation.sig")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    finally:
        os.unlink(tmp_path)
    if proc.returncode != 0:
        print(f"REJECT: signature verification failed: {proc.stderr.decode().strip()}", file=sys.stderr)
        return 1

    artifact = os.path.join(base, att["artifact"]["path"])
    got = sha256_file(artifact)
    if got != att["artifact"]["sha256"]:
        print(f"REJECT: artifact sha256 {got} != attested {att['artifact']['sha256']}", file=sys.stderr)
        return 1

    inv = att["source_inventory"]
    inv_path = os.path.join(base, inv["path"])
    got_inv = sha256_file(inv_path)
    if got_inv != inv["sha256"]:
        print(f"REJECT: inventory sha256 {got_inv} != attested {inv['sha256']}", file=sys.stderr)
        return 1

    print(f"OK: signature verified under pinned key {key_id}")
    print(f"OK: artifact {os.path.basename(artifact)} sha256={got}")
    print(f"OK: source inventory {os.path.basename(inv_path)} sha256={got_inv}")
    print(f"verdict={att.get('qualification_verdict')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
