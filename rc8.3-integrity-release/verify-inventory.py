#!/usr/bin/env python3
"""Verify an extracted source tree against the canonical inventory.

Checks file bytes, symlink target bytes, and the mode class for every
inventory record. Any mismatch, missing path, or extra path is a hard
failure.

Usage: verify-inventory.py <inventory> <extracted-root>
"""

import hashlib
import os
import sys


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    inv_path, root = sys.argv[1], sys.argv[2]
    expected = {}
    for line in open(inv_path, encoding="utf-8"):
        mode, kind, digest, path = line.split(None, 3)
        expected[path.rstrip("\n")] = (mode, kind, digest)

    seen = set()
    bad = 0
    for path, (mode, kind, digest) in sorted(expected.items()):
        full = os.path.join(root, path)
        if not os.path.lexists(full):
            print(f"MISSING {path}", file=sys.stderr)
            bad += 1
            continue
        if kind == "symlink":
            if not os.path.islink(full):
                print(f"NOT-SYMLINK {path}", file=sys.stderr)
                bad += 1
                continue
            got = hashlib.sha256(os.readlink(full).encode()).hexdigest()
        else:
            if os.path.islink(full) or not os.path.isfile(full):
                print(f"NOT-FILE {path}", file=sys.stderr)
                bad += 1
                continue
            got = sha256_file(full)
            executable = bool(os.stat(full).st_mode & 0o111)
            if (mode == "100755") != executable:
                print(f"MODE {path}: executable={executable} mode={mode}", file=sys.stderr)
                bad += 1
        if got != digest:
            print(f"DIGEST {path}: {got} != {digest}", file=sys.stderr)
            bad += 1
        seen.add(path)

    # Extra regular files/symlinks not represented in the inventory.
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if rel not in expected:
                print(f"EXTRA {rel}", file=sys.stderr)
                bad += 1
        for name in dirnames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                rel = os.path.relpath(full, root)
                if rel not in expected:
                    print(f"EXTRA-SYMLINK {rel}", file=sys.stderr)
                    bad += 1

    print(f"inventory_entries={len(expected)} verified={len(seen)} mismatches={bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
