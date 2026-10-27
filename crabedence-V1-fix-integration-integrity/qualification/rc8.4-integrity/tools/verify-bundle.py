#!/usr/bin/env python3
"""Detached evidence-bundle verifier (RC8.4).

The RC8.3 clean-room script built and vetted the tree, but it ran on the
same host under the same operator and it did not prove that every
shipped byte is accounted for. A bundle verifier has to answer one
question from the shipped files alone: does this directory contain
exactly what it claims, and nothing else?

Checks, in order:

  * SHA256SUMS exists and parses;
  * every path it lists exists in the bundle and matches its digest;
  * every regular file in the bundle is listed (an unlisted file is an
    unaccounted byte, not an extra);
  * no listed path escapes the bundle (absolute, `..`, or symlink);
  * the release record's artifact hash equals the artifact's digest.

No network, no source tree, no cache. Exit 0 only when every check
passes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

SUMS_NAME = "SHA256SUMS"
RECORD_CANDIDATES = ("RELEASE-RECORD.json", "attestation.json")


def sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_sums(path: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                raise ValueError(f"{SUMS_NAME}:{lineno}: not '<digest>  <path>'")
            digest, name = parts[0].strip(), parts[1].strip()
            if len(digest) != 64:
                raise ValueError(f"{SUMS_NAME}:{lineno}: digest is not 64 hex characters")
            entries[name] = digest
    return entries


def normalise(bundle: str, name: str) -> str:
    """Strip a leading `<bundle-basename>/` component.

    RC8.3's manifest was generated from the parent directory, so every
    entry carries the bundle name as a prefix. Accepting both forms is
    not laxness: the check that matters is that the path resolves inside
    the bundle and matches the bytes.
    """
    prefix = os.path.basename(os.path.normpath(bundle)) + "/"
    return name[len(prefix):] if name.startswith(prefix) else name


def contained(bundle: str, name: str) -> bool:
    if os.path.isabs(name) or name.startswith("/"):
        return False
    resolved = os.path.realpath(os.path.join(bundle, name))
    root = os.path.realpath(bundle)
    return resolved == root or resolved.startswith(root + os.sep)


def validate(bundle: str) -> list[str]:
    findings: list[str] = []
    if not os.path.isdir(bundle):
        return [f"{bundle}: not a directory"]

    sums_path = os.path.join(bundle, SUMS_NAME)
    if not os.path.exists(sums_path):
        return [f"{SUMS_NAME}: missing — a bundle without a manifest is not evidence"]

    try:
        listed = parse_sums(sums_path)
    except ValueError as err:
        return [str(err)]
    if not listed:
        return [f"{SUMS_NAME}: lists no files"]

    # 1. every listed path is contained, present and matches.
    for raw_name, digest in listed.items():
        name = normalise(bundle, raw_name)
        if not contained(bundle, name):
            findings.append(f"{raw_name}: path escapes the bundle")
            continue
        target = os.path.join(bundle, name)
        if not os.path.isfile(target):
            findings.append(f"{raw_name}: listed but absent")
            continue
        actual = sha256(target)
        if actual != digest:
            findings.append(f"{raw_name}: digest {actual} does not match the manifest {digest}")

    # 2. every shipped file is accounted for. The manifest may list
    # itself; nothing else may be unlisted.
    accounted = {normalise(bundle, name) for name in listed}
    for root, dirs, files in os.walk(bundle):
        dirs.sort()
        for name in sorted(files):
            rel = os.path.relpath(os.path.join(root, name), bundle)
            if rel == SUMS_NAME:
                continue
            if rel not in accounted:
                findings.append(f"{rel}: shipped but not listed in {SUMS_NAME}")

    # 3. the record's artifact hash is the artifact's hash.
    for candidate in RECORD_CANDIDATES:
        path = os.path.join(bundle, candidate)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                record = json.load(fh)
        except (OSError, json.JSONDecodeError) as err:
            findings.append(f"{candidate}: does not parse: {err}")
            continue
        claimed = None
        artifact = None
        for key in ("artifact", "artifacts"):
            value = record.get(key)
            if isinstance(value, dict):
                claimed = value.get("sha256")
                artifact = value.get("path") or value.get("name")
            elif isinstance(value, str):
                artifact = value
        if claimed and artifact:
            target = os.path.join(bundle, os.path.basename(artifact))
            if not os.path.isfile(target):
                findings.append(f"{candidate}: claims artifact {artifact!r}, which is not in the bundle")
            elif sha256(target) != claimed:
                findings.append(f"{candidate}: artifact digest does not match the artifact")

    return findings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", help="directory containing only shipping materials")
    args = parser.parse_args(argv)

    findings = validate(args.bundle)
    if findings:
        for finding in findings:
            print(f"FAIL: {finding}", file=sys.stderr)
        return 1
    print(f"OK: {args.bundle} — every shipped file is listed and matches")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
