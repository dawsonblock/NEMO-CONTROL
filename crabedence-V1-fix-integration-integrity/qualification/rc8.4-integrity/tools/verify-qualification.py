#!/usr/bin/env python3
"""Strict qualification-matrix validator (RC8.4).

The RC8.3 matrix carried `status: PARTIAL` on one gate while the release
record declared that gate statuses are only PASS / FAIL / NOT_RUN /
BLOCKED. That is not a cosmetic mismatch: a verifier that accepts an
undeclared status cannot tell an honest partial from a typo, and a
release reader cannot tell either.

This validator enforces the declared enum and the evidence rules a
release decision depends on:

  * every lane has an id and a status from the declared enum;
  * lane ids are unique;
  * a PASS names an evidence file that exists and a command with an
    exit code of 0;
  * a NOT_RUN or BLOCKED lane carries a reason;
  * no lane silently omits its evidence.

Exit 0 when the matrix is well-formed, 1 when any finding is raised.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

ALLOWED = ("PASS", "FAIL", "NOT_RUN", "BLOCKED")
REQUIRED_LANE_KEYS = ("id", "status")


def load_matrix(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def validate(matrix: dict, root: str) -> list[str]:
    findings: list[str] = []
    lanes = matrix.get("lanes")
    if not isinstance(lanes, list) or not lanes:
        return ["matrix carries no lanes"]

    seen: dict[str, int] = {}
    for index, lane in enumerate(lanes):
        where = f"lane[{index}]"
        if not isinstance(lane, dict):
            findings.append(f"{where}: not an object")
            continue
        for key in REQUIRED_LANE_KEYS:
            if not lane.get(key):
                findings.append(f"{where}: missing {key}")
        lane_id = lane.get("id")
        if isinstance(lane_id, str):
            where = f"lane {lane_id!r}"
            if lane_id in seen:
                findings.append(f"{where}: duplicate id (first at lane[{seen[lane_id]}])")
            seen.setdefault(lane_id, index)

        status = lane.get("status")
        if status is None:
            continue
        if status not in ALLOWED:
            findings.append(f"{where}: status {status!r} is not one of {', '.join(ALLOWED)}")
            continue

        if status == "PASS":
            if not lane.get("command"):
                findings.append(f"{where}: PASS carries no command")
            if lane.get("exit_code") != 0:
                findings.append(f"{where}: PASS carries exit_code {lane.get('exit_code')!r}, want 0")
            evidence = lane.get("evidence")
            if not evidence:
                findings.append(f"{where}: PASS carries no evidence path")
            else:
                target = evidence if os.path.isabs(evidence) else os.path.join(root, evidence)
                if not os.path.exists(target):
                    findings.append(f"{where}: evidence {evidence!r} does not exist")
        else:
            if not (lane.get("notes") or lane.get("reason")):
                findings.append(f"{where}: {status} carries no reason")

    return findings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("matrix", help="qualification matrix JSON")
    parser.add_argument(
        "--root",
        default=".",
        help="root that relative evidence paths resolve against (default: cwd)",
    )
    args = parser.parse_args(argv)

    matrix = load_matrix(args.matrix)
    findings = validate(matrix, args.root)
    if findings:
        for finding in findings:
            print(f"FAIL: {finding}", file=sys.stderr)
        return 1
    print(f"OK: {args.matrix} — {len(matrix['lanes'])} lanes, all statuses declared")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
