#!/usr/bin/env python3
"""Sign the RC8.3 integrity-closure attestation with a pinned Ed25519 root.

The signature covers the canonical JSON of the attestation with the
`signature` block removed. The block is added after signing, so the
signed bytes never depend on the signature itself.

This root is provisioned locally for the qualification run. It is a
real cryptographic trust anchor (the public key is pinned by SHA-256 and
must be distributed out of band), but it is not a third-party root.

Usage: sign-release-attestation.py <release-dir>
"""

import hashlib
import json
import os
import subprocess
import sys


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
    root = os.path.join(base, "release-root")
    priv = os.path.join(root, "release-root.pem")
    pub = os.path.join(root, "release-root.pub")

    att = json.load(open(att_path, encoding="utf-8"))
    att.pop("signature", None)
    # Make paths relative to the release directory so the attestation is
    # portable and the verifier can resolve them without absolute paths.
    if "artifact" in att:
        att["artifact"]["path"] = os.path.basename(att["artifact"]["path"])
    if "source_inventory" in att:
        att["source_inventory"]["path"] = os.path.basename(att["source_inventory"]["path"])

    canon = canonical(att)
    canon_path = os.path.join(base, "attestation.canonical.json")
    with open(canon_path, "wb") as fh:
        fh.write(canon)

    sig_path = os.path.join(base, "attestation.sig")
    subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-inkey", priv, "-rawin", "-in", canon_path, "-out", sig_path],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", pub, "-outform", "DER"])
    key_id = hashlib.sha256(der).hexdigest()
    att["signature"] = {
        "status": "SIGNED",
        "algorithm": "ed25519",
        "key_id": key_id,
        "root": "release-root/release-root.pub",
        "root_key_id_file": "release-root/key-id.txt",
        "signature_file": "attestation.sig",
        "signed_file": "attestation.canonical.json",
        "covers": "canonical JSON of this attestation with the signature block removed",
        "trust_anchor": "locally provisioned release root pinned by SHA-256; not a third-party root",
    }
    with open(att_path, "w", encoding="utf-8") as fh:
        json.dump(att, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print(f"signed {att_path}")
    print(f"key_id={key_id}")
    print(f"canonical_sha256={sha256_file(canon_path)}")
    print(f"signature_sha256={sha256_file(sig_path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
