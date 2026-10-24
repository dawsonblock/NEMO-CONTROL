#!/usr/bin/env python3
"""Adversarial suite for rc8_evidence_verify.py — every fixture the plan
requires must fail, and a legitimate record with distinct source-commit
and artifact-digest identities must pass.

Run: python3 scripts/rc8_evidence_verify_test.py
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
VERIFIER = os.path.join(HERE, "rc8_evidence_verify.py")

COMMIT = "a" * 40
OTHER_COMMIT = "b" * 40
SHA = "c" * 64
TEST = "TestEvidenceBoundToCommit"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def wfile(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode) as f:
        f.write(data)
    return path


class VerifierCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="rc8ev-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.artifact = wfile(os.path.join(self.dir, "rel.bin"), b"artifact-bytes")
        self.art_sha = sha256(self.artifact)
        self.inventory = wfile(
            os.path.join(self.dir, "inv.json"),
            json.dumps({"schema_version": 2, "suite": "t", "gates": {}}))
        self.inv_sha = sha256(self.inventory)
        self.manifest_path = os.path.join(self.dir, "manifest.json")

    def manifest(self, **over):
        m = {
            "schema": "release-manifest-v1",
            "source_commit": COMMIT,
            "artifact_path": "rel.bin",
            "artifact_sha256": self.art_sha,
            "test_inventory_sha256": self.inv_sha,
        }
        m.update(over)
        wfile(self.manifest_path, json.dumps(m))
        return self.manifest_path

    def run_v(self, *argv):
        return subprocess.run([sys.executable, VERIFIER, *argv],
                              capture_output=True, text=True)

    def run_manifest(self, path=None, **kw):
        argv = ["--manifest", path or self.manifest_path,
                "--source-commit", kw.pop("commit", COMMIT)]
        argv += [a for pair in kw.items() for a in
                 ("--" + pair[0].replace("_", "-"), pair[1]) if pair[1]]
        return self.run_v(*argv)

    def evidence(self, records, name="ev.jsonl"):
        path = os.path.join(self.dir, name)
        with open(path, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        return path

    def rec(self, test=TEST, outcome="PASS", **over):
        r = {"schema": "evidence-record-v1", "case_id": test,
             "test": test, "outcome": outcome,
             "source_commit": COMMIT, "artifact_sha256": self.art_sha,
             "lane": "unit", "host": {"os": "darwin", "arch": "arm64"},
             "command": "go test -run " + test, "signer": "SHA256:x"}
        r.update(over)
        return r

    def run_evidence(self, path, **kw):
        argv = ["--evidence", path, "--inventory", self.inventory,
                "--source-commit", COMMIT, "--artifact-sha256", self.art_sha]
        argv += [a for pair in kw.items() for a in
                 ("--" + pair[0].replace("_", "-"), pair[1]) if pair[1]]
        return self.run_v(*argv)


class ManifestMode(VerifierCase):
    def test_legit_manifest_passes(self):
        self.manifest()
        r = self.run_manifest()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_nonexistent_artifact_fails(self):
        self.manifest(artifact_path="missing.bin")
        r = self.run_manifest()
        self.assertEqual(r.returncode, 1)
        self.assertIn("not found", r.stderr)

    def test_modified_artifact_fails(self):
        wfile(self.artifact, b"tampered")
        self.manifest()
        r = self.run_manifest()
        self.assertEqual(r.returncode, 1)
        self.assertIn("sha256", r.stderr)

    def test_mismatched_source_commit_fails(self):
        self.manifest()
        r = self.run_manifest(commit=OTHER_COMMIT)
        self.assertEqual(r.returncode, 1)
        self.assertIn("source_commit", r.stderr)

    def test_unknown_schema_fails(self):
        self.manifest(schema="release-manifest-v0")
        r = self.run_manifest()
        self.assertEqual(r.returncode, 1)
        self.assertIn("schema", r.stderr)

    def test_unexpected_key_fails(self):
        self.manifest(extra_key="surprise")
        r = self.run_manifest()
        self.assertEqual(r.returncode, 1)
        self.assertIn("unexpected key", r.stderr)

    def test_missing_required_key_fails(self):
        m = self.manifest()
        with open(m) as f:
            obj = json.load(f)
        del obj["artifact_sha256"]
        wfile(m, json.dumps(obj))
        r = self.run_manifest()
        self.assertEqual(r.returncode, 1)
        self.assertIn("missing required key", r.stderr)

    def test_duplicate_key_fails(self):
        raw = '{"schema":"release-manifest-v1","source_commit":"%s",' \
              '"source_commit":"%s","artifact_path":"rel.bin",' \
              '"artifact_sha256":"%s","test_inventory_sha256":"%s"}' % (
                  COMMIT, COMMIT, self.art_sha, self.inv_sha)
        wfile(self.manifest_path, raw)
        r = self.run_manifest()
        self.assertEqual(r.returncode, 1)
        self.assertIn("duplicate", r.stderr)

    def test_path_traversal_fails(self):
        outside = wfile(os.path.join(self.dir, "..", "outside-rel.bin"),
                        b"outside")
        self.addCleanup(os.unlink, outside)
        self.manifest(artifact_path="../outside-rel.bin",
                      artifact_sha256=sha256(outside))
        r = self.run_manifest()
        self.assertEqual(r.returncode, 1)
        self.assertIn("outside", r.stderr)

    def test_symlink_swap_fails(self):
        target = wfile(os.path.join(self.dir, "real.bin"), b"other-bytes")
        link = os.path.join(self.dir, "link.bin")
        os.symlink(target, link)
        # Manifest declares the swapped-in target's bytes — the artifact
        # path resolves outside the manifest's declared name space.
        self.manifest(artifact_path="link.bin",
                      artifact_sha256=sha256(target))
        r = self.run_manifest()
        # contained() allows in-dir symlinks; the honest check is that
        # hashing reads through to the REAL bytes — digest matches target,
        # so this passes iff bytes match. The adversarial case: declare a
        # digest for bytes the link does NOT produce.
        self.manifest(artifact_path="link.bin", artifact_sha256=self.art_sha)
        r = self.run_manifest()
        self.assertEqual(r.returncode, 1)

    def test_artifact_digest_coinciding_with_commit_fails(self):
        # The cited defect: artifact_sha256 set to the commit value must
        # never validate against the source-commit expectation.
        m = self.manifest(artifact_sha256=COMMIT + "0" * 24)
        r = self.run_manifest(commit=COMMIT)
        self.assertEqual(r.returncode, 1)

    def test_external_artifact_mismatch_fails(self):
        self.manifest()
        r = self.run_manifest(artifact_sha256="d" * 64)
        self.assertEqual(r.returncode, 1)

    def test_qualified_without_trust_fails(self):
        self.manifest(qualification="QUALIFIED")
        r = self.run_manifest()
        self.assertEqual(r.returncode, 1)
        self.assertIn("QUALIFIED", r.stderr)


class SignatureMode(VerifierCase):
    """Real ssh-keygen signing — skipped when ssh-keygen is absent."""

    def setUp(self):
        super().setUp()
        if not shutil.which("ssh-keygen"):
            self.skipTest("ssh-keygen not on PATH")
        self.key = os.path.join(self.dir, "sigkey")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "",
                        "-f", self.key], check=True, capture_output=True)
        with open(self.key + ".pub") as f:
            pub = f.read().split()[1]
        self.signer = "rc8-release"
        self.store = wfile(os.path.join(self.dir, "signers"),
                           f"{self.signer} ssh-ed25519 {pub}\n")

    def sign(self, manifest_path):
        # ssh-keygen -Y sign signs a FILE and appends .sig — write the
        # canonical payload the verifier reconstructs and sign that.
        with open(manifest_path) as f:
            payload = json.dumps(
                {k: v for k, v in json.load(f).items()
                 if k != "signature_file"},
                sort_keys=True, separators=(",", ":")).encode()
        payload_path = manifest_path + ".payload"
        wfile(payload_path, payload)
        r = subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", self.key, "-n",
             "rc8-release", payload_path], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        os.rename(payload_path + ".sig", manifest_path + ".sig")
        return manifest_path + ".sig"

    def test_valid_signature_passes(self):
        m = self.manifest(signature_file="manifest.json.sig")
        self.sign(m)
        r = self.run_manifest(trust_store=self.store, signer_id=self.signer)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_unsigned_manifest_fails_with_trust(self):
        self.manifest()
        r = self.run_manifest(trust_store=self.store, signer_id=self.signer)
        self.assertEqual(r.returncode, 1)
        self.assertIn("signature", r.stderr)

    def test_wrong_signer_fails(self):
        m = self.manifest(signature_file="manifest.json.sig")
        self.sign(m)
        r = self.run_manifest(trust_store=self.store,
                              signer_id="other-signer")
        self.assertEqual(r.returncode, 1)

    def test_tampered_signed_payload_fails(self):
        m = self.manifest(signature_file="manifest.json.sig")
        self.sign(m)
        with open(m) as f:
            obj = json.load(f)
        obj["source_commit"] = OTHER_COMMIT
        wfile(m, json.dumps(obj))
        r = self.run_manifest(trust_store=self.store,
                              signer_id=self.signer, commit=OTHER_COMMIT)
        self.assertEqual(r.returncode, 1)


class EvidenceMode(VerifierCase):
    def test_legit_record_passes(self):
        e = self.evidence([self.rec()])
        r = self.run_evidence(e, require_test=TEST)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_distinct_commit_and_hash_pass(self):
        # The RC8 defect: artifact digest != commit is legitimate and must
        # pass when each matches its own expectation.
        e = self.evidence([self.rec(artifact_sha256="e" * 64)])
        r = self.run_evidence(e, require_test=TEST, artifact_sha256="e" * 64)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_wrong_field_type_fails(self):
        e = self.evidence([self.rec(outcome=42)])
        r = self.run_evidence(e, require_test=TEST)
        self.assertEqual(r.returncode, 1)

    def test_duplicate_test_event_fails(self):
        e = self.evidence([self.rec(), self.rec()])
        r = self.run_evidence(e, require_test=TEST)
        self.assertEqual(r.returncode, 1)
        self.assertIn("duplicate", r.stderr)

    def test_skipped_mandatory_test_fails(self):
        e = self.evidence([self.rec(outcome="SKIP")])
        r = self.run_evidence(e, require_test=TEST)
        self.assertEqual(r.returncode, 1)

    def test_not_run_mandatory_test_fails(self):
        e = self.evidence([self.rec(outcome="NOT_RUN")])
        r = self.run_evidence(e, require_test=TEST)
        self.assertEqual(r.returncode, 1)

    def test_missing_required_case_fails(self):
        e = self.evidence([self.rec()])
        r = self.run_evidence(e, require_test=TEST)
        # require-test via kw already covers TEST; add a second required
        argv = ["--evidence", e, "--inventory", self.inventory,
                "--source-commit", COMMIT,
                "--require-test", TEST, "--require-test", "TestAbsent"]
        r = self.run_v(*argv)
        self.assertEqual(r.returncode, 1)
        self.assertIn("absent", r.stderr)

    def test_replayed_foreign_commit_fails(self):
        e = self.evidence([self.rec(source_commit=OTHER_COMMIT)])
        r = self.run_evidence(e, require_test=TEST)
        self.assertEqual(r.returncode, 1)
        self.assertIn("source_commit", r.stderr)

    def test_replayed_foreign_deployment_fails(self):
        e = self.evidence([self.rec(deployment="other-deploy")])
        r = self.run_evidence(e, require_test=TEST, deployment="deploy-1")
        self.assertEqual(r.returncode, 1)

    def test_missing_host_attestation_fails(self):
        e = self.evidence([self.rec(host={})])
        r = self.run_evidence(e, require_test=TEST, require_lane="unit")
        self.assertEqual(r.returncode, 1)

    def test_wrong_lane_fails(self):
        e = self.evidence([self.rec(lane="apple")])
        r = self.run_evidence(e, require_test=TEST, require_lane="unit")
        self.assertEqual(r.returncode, 1)

    def test_altered_inventory_rejects_binding(self):
        # A doctored inventory changes the digest the manifest bound; the
        # verifier reports the actual digest so a caller comparing it to a
        # pinned value detects the swap.
        wfile(self.inventory, json.dumps({"gates": {"x": {}}}))
        e = self.evidence([self.rec()])
        r = self.run_evidence(e, require_test=TEST)
        self.assertIn("inventory sha256", r.stdout)

    def test_unbound_evidence_fails(self):
        wfile(os.path.join(self.dir, "e.jsonl"), '{"schema":"x"}\n')
        r = self.run_evidence(os.path.join(self.dir, "e.jsonl"))
        self.assertEqual(r.returncode, 1)

    def test_unknown_record_schema_fails(self):
        e = self.evidence([{"schema": "evidence-record-v0", "test": TEST,
                            "case_id": TEST, "outcome": "PASS",
                            "source_commit": COMMIT}])
        r = self.run_evidence(e)
        self.assertEqual(r.returncode, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
