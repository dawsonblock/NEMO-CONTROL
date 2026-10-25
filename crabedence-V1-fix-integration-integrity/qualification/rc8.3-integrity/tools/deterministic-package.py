#!/usr/bin/env python3
"""Deterministic source packaging for the integrity-closure tree.

Every entry is added in LC_ALL=C path order with a fixed timestamp,
fixed mode, and fixed compression settings, so two runs over the same
HEAD and worktree bytes must produce identical archives.

Usage: deterministic-package.py <repo-root> <tree-subdir> <prefix> <output.zip>
"""

import os
import subprocess
import sys
import zipfile

FIXED_TIME = (2020, 1, 1, 0, 0, 0)


def main() -> int:
    repo, subdir, prefix, output = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    raw = subprocess.check_output(
        ["git", "-C", repo, "ls-tree", "-r", "-z", "--full-tree", "HEAD", "--", subdir]
    )
    entries = []
    for rec in raw.split(b"\0"):
        if not rec:
            continue
        meta, path = rec.split(b"\t", 1)
        mode, typ, _obj = meta.decode().split(" ")
        path = path.decode()
        rel = os.path.relpath(path, subdir)
        entries.append((rel, mode, typ))
    entries.sort(key=lambda e: e[0].encode())

    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for rel, mode, typ in entries:
            full = os.path.join(repo, subdir, rel)
            arcname = f"{prefix}/{rel}"
            info = zipfile.ZipInfo(arcname, date_time=FIXED_TIME)
            info.create_system = 3
            if typ == "blob" and mode == "120000":
                info.external_attr = (0o120777 << 16)
                data = os.readlink(full).encode()
            elif typ == "blob":
                perm = 0o755 if mode == "100755" else 0o644
                info.external_attr = (perm << 16)
                with open(full, "rb") as fh:
                    data = fh.read()
            else:
                raise SystemExit(f"unsupported git object {typ} at {rel}")
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    print(f"entries={len(entries)} output={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
