#!/usr/bin/env python3
"""Verify a release archive against a detached attestation.

Checks the artifact SHA-256 and, when present, the embedded source
inventory SHA-256. A mismatch is a hard rejection (exit 1). This is the
hash-binding half of tamper rejection; signature verification against an
externally trusted release root is a separate, currently blocked step.

Usage: verify-artifact.py <attestation.json> <artifact>
"""

import hashlib
import json
import sys


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    att = json.load(open(sys.argv[1], encoding="utf-8"))
    artifact = sys.argv[2]
    want = att["artifact"]["sha256"]
    got = sha256(artifact)
    if got != want:
        print(f"REJECT: artifact sha256 {got} != attested {want}", file=sys.stderr)
        return 1
    inv = att.get("source_inventory", {})
    if inv.get("path") and inv.get("sha256"):
        inv_path = inv["path"]
        if not os.path.isabs(inv_path):
            inv_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[1])), inv_path)
        got_inv = sha256(inv_path)
        if got_inv != inv["sha256"]:
            print(f"REJECT: inventory sha256 {got_inv} != attested {inv['sha256']}", file=sys.stderr)
            return 1
    print(f"OK: {artifact} sha256={got} binds the attestation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
