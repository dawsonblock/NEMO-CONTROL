#!/usr/bin/env python3
"""Tests for verify-qualification.py.

The negative cases are the point: a validator that only proves it can
accept a good matrix has not shown it rejects a bad one.
"""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location(
    "verify_qualification", os.path.join(HERE, "verify-qualification.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def lane(**overrides):
    base = {
        "id": "G1",
        "status": "PASS",
        "command": "go build ./...",
        "exit_code": 0,
        "evidence": "logs/g1.log",
    }
    base.update(overrides)
    return base


class ValidateTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.root, "logs"))
        with open(os.path.join(self.root, "logs", "g1.log"), "w", encoding="utf-8") as fh:
            fh.write("ok\n")

    def matrix(self, *lanes):
        return {"schema": "test", "lanes": list(lanes)}

    def test_accepts_a_well_formed_matrix(self):
        self.assertEqual(MODULE.validate(self.matrix(lane()), self.root), [])

    def test_rejects_undeclared_status(self):
        findings = MODULE.validate(self.matrix(lane(status="PARTIAL")), self.root)
        self.assertTrue(any("PARTIAL" in f for f in findings), findings)

    def test_rejects_pass_without_evidence_file(self):
        findings = MODULE.validate(self.matrix(lane(evidence="logs/missing.log")), self.root)
        self.assertTrue(any("does not exist" in f for f in findings), findings)

    def test_rejects_pass_with_nonzero_exit(self):
        findings = MODULE.validate(self.matrix(lane(exit_code=1)), self.root)
        self.assertTrue(any("exit_code" in f for f in findings), findings)

    def test_rejects_pass_without_command(self):
        findings = MODULE.validate(self.matrix(lane(command="")), self.root)
        self.assertTrue(any("no command" in f for f in findings), findings)

    def test_rejects_duplicate_lane_ids(self):
        findings = MODULE.validate(self.matrix(lane(), lane()), self.root)
        self.assertTrue(any("duplicate id" in f for f in findings), findings)

    def test_rejects_not_run_without_reason(self):
        findings = MODULE.validate(self.matrix(lane(status="NOT_RUN", evidence=None)), self.root)
        self.assertTrue(any("no reason" in f for f in findings), findings)

    def test_accepts_not_run_with_reason(self):
        findings = MODULE.validate(
            self.matrix(lane(status="NOT_RUN", evidence=None, notes="no KVM host")), self.root
        )
        self.assertEqual(findings, [])

    def test_rejects_empty_lane_list(self):
        self.assertEqual(MODULE.validate({"lanes": []}, self.root), ["matrix carries no lanes"])


class RealMatrixTests(unittest.TestCase):
    """The RC8.3 matrix must fail this validator: that is the defect."""

    def test_rc83_matrix_is_rejected(self):
        here = os.path.dirname(HERE)
        rc83 = os.path.abspath(os.path.join(here, "..", "rc8.3-integrity", "qualification-matrix.json"))
        if not os.path.exists(rc83):
            self.skipTest("RC8.3 matrix not present")
        with open(rc83, encoding="utf-8") as fh:
            matrix = json.load(fh)
        findings = MODULE.validate(matrix, os.path.dirname(rc83))
        self.assertTrue(
            any("PARTIAL" in f for f in findings),
            f"RC8.3 matrix should carry the undeclared PARTIAL status; findings={findings}",
        )


if __name__ == "__main__":
    unittest.main()
