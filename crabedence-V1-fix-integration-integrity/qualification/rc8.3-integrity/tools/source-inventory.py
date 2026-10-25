#!/usr/bin/env python3
"""Generate the canonical source inventory for the integrity-closure tree.

Derived from the Git HEAD path list, hashed from worktree bytes (so the
inventory describes the bytes that qualify, not the Git blobs). Symlink
digests are SHA-256 of the link target bytes, never the target's contents.

Usage: source-inventory.py <repo-root> <tree-subdir> <output-file>
"""

import hashlib
import os
import subprocess
import sys


def main() -> int:
    repo, subdir, output = sys.argv[1], sys.argv[2], sys.argv[3]
    raw = subprocess.check_output(
        ["git", "-C", repo, "ls-tree", "-r", "-z", "--full-tree", "HEAD", "--", subdir]
    )
    records = []
    for rec in raw.split(b"\0"):
        if not rec:
            continue
        meta, path = rec.split(b"\t", 1)
        mode, typ, _obj = meta.decode().split(" ")
        path = path.decode()
        rel = os.path.relpath(path, subdir)
        full = os.path.join(repo, path)
        if typ == "blob" and mode == "120000":
            digest = hashlib.sha256(os.readlink(full).encode()).hexdigest()
            kind = "symlink"
        elif typ == "blob":
            h = hashlib.sha256()
            with open(full, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            digest = h.hexdigest()
            kind = "file"
        else:
            raise SystemExit(f"unsupported git object {typ} at {path}")
        records.append((rel, mode, kind, digest))
    records.sort(key=lambda r: r[0].encode())
    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
    with open(output, "w", encoding="utf-8") as fh:
        for rel, mode, kind, digest in records:
            fh.write(f"{mode} {kind} {digest}  {rel}\n")
    h = hashlib.sha256()
    with open(output, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    print(f"entries={len(records)} inventory_sha256={h.hexdigest()} output={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
