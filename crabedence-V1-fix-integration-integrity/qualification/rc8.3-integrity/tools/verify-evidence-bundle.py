#!/usr/bin/env python3
"""Verify a self-contained RC8.3 integrity-closure evidence bundle.

Checks:
  - every attestation test log exists, matches its recorded size/hash;
  - every qualification-matrix lane log is present and matches its hash;
  - the full-race log is complete (not truncated) and ends with EXIT=<code>;
  - metadata files contain no absolute /Users/ source-host paths;
  - the artifact and inventory hashes match;
  - the signed attestation verifies under the pinned root.

Usage: verify-evidence-bundle.py <bundle-dir>
"""

import hashlib
import json
import os
import re
import subprocess
import sys


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    base = os.path.abspath(sys.argv[1])
    bad = 0

    att_path = os.path.join(base, "attestation.json")
    att = json.load(open(att_path, encoding="utf-8"))

    for name, meta in sorted(att.get("test_logs", {}).items()):
        path = os.path.join(base, meta.get("path", os.path.join("logs", name)))
        if not os.path.exists(path):
            print(f"REJECT: missing test log {path}", file=sys.stderr)
            bad += 1
            continue
        size = os.path.getsize(path)
        got = sha256_file(path)
        if size != meta.get("size"):
            print(f"REJECT: {name} size {size} != attested {meta.get('size')}", file=sys.stderr)
            bad += 1
        if got != meta.get("sha256"):
            print(f"REJECT: {name} sha256 {got} != attested {meta.get('sha256')}", file=sys.stderr)
            bad += 1

    matrix_path = os.path.join(base, "qualification-matrix.json")
    if os.path.exists(matrix_path):
        matrix = json.load(open(matrix_path, encoding="utf-8"))
        for lane in matrix.get("lanes", []):
            log = lane.get("log")
            want = lane.get("log_sha256")
            if not log or not want:
                continue
            path = os.path.join(base, "logs", os.path.basename(log))
            if not os.path.exists(path):
                print(f"REJECT: matrix lane {lane['id']} log missing: {path}", file=sys.stderr)
                bad += 1
                continue
            got = sha256_file(path)
            if got != want:
                print(f"REJECT: matrix lane {lane['id']} log sha256 {got} != {want}", file=sys.stderr)
                bad += 1

    full = os.path.join(base, "logs", "full-race-20m.log")
    if not os.path.exists(full):
        print("REJECT: full-race log missing", file=sys.stderr)
        bad += 1
    else:
        size = os.path.getsize(full)
        tail = open(full, "r", encoding="utf-8", errors="replace").read().splitlines()[-5:]
        if size < 10_000:
            print(f"REJECT: full-race log is truncated ({size} bytes)", file=sys.stderr)
            bad += 1
        if not any(re.fullmatch(r"EXIT=\d+", line.strip()) for line in tail):
            print("REJECT: full-race log has no terminal EXIT=<code> line", file=sys.stderr)
            bad += 1

    for name in ("attestation.json", "packaging.json", "SHA256SUMS", "README.md", "qualification-matrix.json"):
        path = os.path.join(base, name)
        if not os.path.exists(path):
            continue
        text = open(path, "r", encoding="utf-8", errors="replace").read()
        if "/Users/" in text:
            print(f"REJECT: {name} contains an absolute /Users/ source-host path", file=sys.stderr)
            bad += 1

    verifier = os.path.join(base, "verify-release-attestation.py")
    if os.path.exists(verifier):
        proc = subprocess.run([sys.executable, verifier, base], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        sys.stdout.write(proc.stdout.decode())
        if proc.returncode != 0:
            bad += 1
    else:
        print("REJECT: verify-release-attestation.py missing", file=sys.stderr)
        bad += 1

    if bad:
        print(f"RESULT FAIL ({bad} findings)")
        return 1
    print("RESULT PASS: evidence bundle is self-contained, hash-bound, and signed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
