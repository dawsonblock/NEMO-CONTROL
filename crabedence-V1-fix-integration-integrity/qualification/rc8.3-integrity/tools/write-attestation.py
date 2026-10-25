#!/usr/bin/env python3
"""Write the detached RC8.3 integrity-closure attestation draft.

The attestation lives OUTSIDE the source tree so it can bind the exact
final commit and artifact without creating a hash circularity. It is
deliberately unsigned: no externally trusted release root is available in
this environment, so `signature.status` is BLOCKED and the release
decision remains NO-GO.

Usage: write-attestation.py <source-commit> <inventory> <artifact>
                             <logs-dir> <output.json> <verdict>
"""

import hashlib
import json
import os
import sys
import time


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    commit, inventory, artifact, logs_dir, output, verdict = sys.argv[1:7]
    logs = {}
    for name in sorted(os.listdir(logs_dir)):
        if name.endswith(".log"):
            path = os.path.join(logs_dir, name)
            logs[name] = {"path": "logs/" + name, "sha256": sha256(path), "size": os.path.getsize(path)}
    doc = {
        "schema": "rc83-integrity-attestation-v1",
        "release": "0.55.0-rc8.3-integrity-closure",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_commit": commit,
        "source_inventory": {
            "path": inventory,
            "sha256": sha256(inventory),
            "entries": sum(1 for _ in open(inventory, encoding="utf-8")),
        },
        "artifact": {
            "path": artifact,
            "sha256": sha256(artifact),
            "size": os.path.getsize(artifact),
        },
        "test_logs": logs,
        "toolchains": {
            "go": "go1.26.5",
            "rust": "1.96.1",
            "node": "v24.16.0",
            "python": "3.12.0",
            "msb": "0.7.8",
        },
        "signature": {
            "status": "BLOCKED",
            "reason": "no externally trusted release root or release signing key material is available; a locally generated key would not satisfy independent root validation",
            "allowed_signers": None,
        },
        "qualification_verdict": verdict,
    }
    with open(output, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {output} artifact_sha256={doc['artifact']['sha256']} verdict={verdict}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
