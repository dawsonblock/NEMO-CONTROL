#!/usr/bin/env python3
"""Verify the RC8.3 integrity-closure attestation against an EXTERNAL anchor.

The trust anchor is never taken from the bundle under review: a bundle
that carries its own root can be replaced wholesale (new key, new
attestation, new signature) and would still verify. The pinned key
identity must therefore come from outside the artifact — either as a
key-id fingerprint or as a public key file held by the reviewer.

Checks, in order:
  1. the signature block is SIGNED with ed25519;
  2. the signer key id equals the externally supplied anchor;
  3. the canonical attestation (signature block removed) is byte-
     identical to the signed canonical file;
  4. the Ed25519 signature verifies under that key;
  5. the artifact and source-inventory hashes match, and both paths stay
     inside the bundle.

Any failure is a hard rejection (exit 1).

Usage:
  verify-release-attestation.py <bundle-dir> --root-key-id <sha256>
  verify-release-attestation.py <bundle-dir> --root <public-key.pem>
  (both may be given; they must agree)
"""

import argparse
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


def key_id_of(pub_path: str) -> str:
    der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", pub_path, "-outform", "DER"])
    return hashlib.sha256(der).hexdigest()


def inside(base: str, path: str) -> bool:
    base = os.path.abspath(base)
    path = os.path.abspath(path)
    return os.path.commonpath([base, path]) == base


def main() -> int:
    ap = argparse.ArgumentParser(description="verify a detached RC8.3 attestation")
    ap.add_argument("bundle")
    ap.add_argument("--root", help="public key file held outside the bundle")
    ap.add_argument("--root-key-id", help="pinned sha256 fingerprint of the release root")
    args = ap.parse_args()

    if not args.root and not args.root_key_id:
        print(
            "REJECT: no external trust anchor supplied — a bundle-selected "
            "release-root.pub is not a trust anchor. Pass --root-key-id or --root.",
            file=sys.stderr,
        )
        return 1

    base = os.path.abspath(args.bundle)
    att_path = os.path.join(base, "attestation.json")
    att = json.load(open(att_path, encoding="utf-8"))
    sig_block = att.get("signature", {})
    if sig_block.get("status") != "SIGNED" or sig_block.get("algorithm") != "ed25519":
        print(f"REJECT: attestation is not signed (status={sig_block.get('status')!r})", file=sys.stderr)
        return 1

    expected = (args.root_key_id or "").strip().lower()
    if args.root:
        if inside(base, args.root):
            print("REJECT: --root must be held outside the bundle under review", file=sys.stderr)
            return 1
        root_id = key_id_of(args.root)
        if expected and expected != root_id:
            print(f"REJECT: --root key id {root_id} != --root-key-id {expected}", file=sys.stderr)
            return 1
        expected = root_id
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        print(f"REJECT: pinned key id {expected!r} is not a sha256 hex fingerprint", file=sys.stderr)
        return 1

    if sig_block.get("key_id") != expected:
        print(f"REJECT: signer key id {sig_block.get('key_id')} != pinned {expected}", file=sys.stderr)
        return 1

    # The bundle may carry a distribution copy of the public key. It is
    # only usable because its identity is already pinned above.
    pub = args.root
    bundled = os.path.join(base, "release-root", "release-root.pub")
    if pub is None:
        if not os.path.exists(bundled):
            print("REJECT: no --root supplied and the bundle carries no release-root.pub", file=sys.stderr)
            return 1
        if key_id_of(bundled) != expected:
            print("REJECT: bundled release-root.pub does not match the pinned key id", file=sys.stderr)
            return 1
        pub = bundled
    elif os.path.exists(bundled) and key_id_of(bundled) != expected:
        print("REJECT: bundled release-root.pub does not match the pinned key id", file=sys.stderr)
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

    for label, key in (("artifact", "artifact"), ("inventory", "source_inventory")):
        meta = att.get(key, {})
        path = os.path.join(base, meta.get("path", ""))
        if not inside(base, path):
            print(f"REJECT: {label} path {meta.get('path')!r} escapes the bundle", file=sys.stderr)
            return 1
        got = sha256_file(path)
        if got != meta.get("sha256"):
            print(f"REJECT: {label} sha256 {got} != attested {meta.get('sha256')}", file=sys.stderr)
            return 1
        print(f"OK: {label} {os.path.basename(path)} sha256={got}")

    print(f"OK: signature verified under pinned key {expected}")
    print(f"verdict={att.get('qualification_verdict')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
