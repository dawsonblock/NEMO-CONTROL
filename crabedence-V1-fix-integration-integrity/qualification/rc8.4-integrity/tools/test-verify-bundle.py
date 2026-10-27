#!/usr/bin/env python3
"""Tests for verify-bundle.py — the negative cases carry the value."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("verify_bundle", os.path.join(HERE, "verify-bundle.py"))
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def digest_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        h.update(fh.read())
    return h.hexdigest()


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.bundle = tempfile.mkdtemp()
        self.write("artifact.zip", b"payload")
        self.write("logs/g1.log", b"ok\n")
        self.write_sums()

    def write(self, name, data):
        path = os.path.join(self.bundle, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)

    def write_sums(self, extra=""):
        names = []
        for root, _dirs, files in os.walk(self.bundle):
            for name in files:
                rel = os.path.relpath(os.path.join(root, name), self.bundle)
                if rel != "SHA256SUMS":
                    names.append(rel)
        body = "".join(f"{digest_of(os.path.join(self.bundle, n))}  {n}\n" for n in sorted(names))
        with open(os.path.join(self.bundle, "SHA256SUMS"), "w", encoding="utf-8") as fh:
            fh.write(body + extra)

    def test_accepts_a_complete_bundle(self):
        self.assertEqual(MODULE.validate(self.bundle), [])

    def test_rejects_missing_manifest(self):
        os.remove(os.path.join(self.bundle, "SHA256SUMS"))
        self.assertTrue(any("missing" in f for f in MODULE.validate(self.bundle)))

    def test_rejects_unlisted_file(self):
        self.write("logs/extra.log", b"surprise")
        findings = MODULE.validate(self.bundle)
        self.assertTrue(any("not listed" in f for f in findings), findings)

    def test_rejects_missing_listed_file(self):
        os.remove(os.path.join(self.bundle, "logs/g1.log"))
        findings = MODULE.validate(self.bundle)
        self.assertTrue(any("absent" in f for f in findings), findings)

    def test_rejects_tampered_bytes(self):
        self.write("logs/g1.log", b"tampered")
        findings = MODULE.validate(self.bundle)
        self.assertTrue(any("does not match the manifest" in f for f in findings), findings)

    def test_rejects_path_traversal(self):
        self.write_sums(extra=f"{'0' * 64}  ../escape\n")
        findings = MODULE.validate(self.bundle)
        self.assertTrue(any("escapes the bundle" in f for f in findings), findings)

    def test_accepts_manifest_prefixed_with_bundle_name(self):
        base = os.path.basename(self.bundle)
        names = []
        for root, _dirs, files in os.walk(self.bundle):
            for name in files:
                rel = os.path.relpath(os.path.join(root, name), self.bundle)
                if rel != "SHA256SUMS":
                    names.append(rel)
        body = "".join(
            f"{digest_of(os.path.join(self.bundle, n))}  {base}/{n}\n" for n in sorted(names)
        )
        with open(os.path.join(self.bundle, "SHA256SUMS"), "w", encoding="utf-8") as fh:
            fh.write(body)
        self.assertEqual(MODULE.validate(self.bundle), [])

    def test_rejects_artifact_digest_mismatch(self):
        record = {"artifact": {"path": "artifact.zip", "sha256": "0" * 64}}
        with open(os.path.join(self.bundle, "RELEASE-RECORD.json"), "w", encoding="utf-8") as fh:
            json.dump(record, fh)
        self.write_sums()
        findings = MODULE.validate(self.bundle)
        self.assertTrue(any("artifact digest does not match" in f for f in findings), findings)


if __name__ == "__main__":
    unittest.main()
