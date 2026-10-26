#!/usr/bin/env python3
"""Sign the RC8.3 integrity-closure attestation with an Ed25519 release root.

The signature covers the canonical JSON of the attestation with the
`signature` block removed. The block is added after signing, so the
signed bytes never depend on the signature itself.

The private key MUST live outside this repository and outside the bundle.
A key committed to the tree cannot be a trust anchor — anyone with the
repository could sign a replacement. The bundle receives only a
distribution copy of the public key, and verification still requires the
pinned key id to be supplied from outside.

Usage: sign-release-attestation.py <release-dir>

Key: $RELEASE_ROOT_KEY, default ~/.config/crabbox/release-root.pem
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


def repo_root_of(path: str):
    cur = os.path.dirname(os.path.abspath(path))
    while True:
        if os.path.exists(os.path.join(cur, ".git")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def main() -> int:
    base = os.path.abspath(sys.argv[1])
    key_path = os.environ.get("RELEASE_ROOT_KEY") or os.path.expanduser("~/.config/crabbox/release-root.pem")
    if not os.path.isfile(key_path):
        print(f"REJECT: release root key not found at {key_path} (set RELEASE_ROOT_KEY)", file=sys.stderr)
        return 1
    if os.path.commonpath([os.path.abspath(key_path), base]) == base:
        print("REJECT: the signing key must not live inside the bundle it signs", file=sys.stderr)
        return 1
    if repo_root_of(key_path) is not None:
        print("REJECT: the signing key must not live inside a git repository", file=sys.stderr)
        return 1

    att_path = os.path.join(base, "attestation.json")
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
        ["openssl", "pkeyutl", "-sign", "-inkey", key_path, "-rawin", "-in", canon_path, "-out", sig_path],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    # Distribution copy of the public key. It is not the trust anchor:
    # the verifier requires the key id from outside the bundle.
    root_dir = os.path.join(base, "release-root")
    os.makedirs(root_dir, exist_ok=True)
    pub_der = subprocess.check_output(["openssl", "pkey", "-in", key_path, "-pubout", "-outform", "DER"])
    key_id = hashlib.sha256(pub_der).hexdigest()
    with open(os.path.join(root_dir, "release-root.pub"), "wb") as fh:
        fh.write(subprocess.check_output(["openssl", "pkey", "-in", key_path, "-pubout"]))
    with open(os.path.join(root_dir, "key-id.txt"), "w", encoding="utf-8") as fh:
        fh.write(key_id + "\n")

    att["signature"] = {
        "status": "SIGNED",
        "algorithm": "ed25519",
        "key_id": key_id,
        "root": "release-root/release-root.pub",
        "root_key_id_file": "release-root/key-id.txt",
        "signature_file": "attestation.sig",
        "signed_file": "attestation.canonical.json",
        "covers": "canonical JSON of this attestation with the signature block removed",
        "trust_anchor": (
            "the release root is pinned by SHA-256 outside the bundle; the bundled public key is a "
            "distribution copy only, and verification requires the pinned key id from outside"
        ),
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
