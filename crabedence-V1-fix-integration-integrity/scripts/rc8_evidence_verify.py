#!/usr/bin/env python3
"""RC8.1 evidence verifier — schema-specific qualification-evidence checks.

Replaces the ad hoc rc8-evidence-verify.sh identity guessing. Every
identity class has its own expectation and its own comparison target:

  source_commit        40-hex Git commit the evidence binds
  source_tree_digest   64-hex tree digest (optional, verified when present)
  artifact_sha256      64-hex digest of the artifact FILE BYTES — hashed
                       here from the file, never trusted from the manifest
  test_inventory_sha256  digest of the required-test inventory in force
  toolchain_lock_digest  digest of the toolchain pin set (optional)
  signature            SSH signature over the canonical manifest payload,
                       verified against an EXTERNALLY pinned trust root

Modes:

  --manifest M.json --artifact PATH --source-commit HEX40
      [--source-tree HEX64] [--inventory I.json]
      [--trust-store FILE --signer-id ID
        [--signature-file PATH]] [--require-signature]

  --evidence E.jsonl --inventory I.json --source-commit HEX40
      [--artifact-sha256 HEX64] [--require-lane L]
      [--require-test T ...] [--require-gate G ...] [--require-signer]

  --artifact PATH --artifact-sha256 HEX64

Exit 0 only when every binding verifies. Exit 1 on any failure.
Exit 2 on usage error. A missing artifact is a FAILURE, not an error —
evidence for bytes that do not exist is no evidence at all.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

SCHEMA_MANIFEST = "release-manifest-v1"
SCHEMA_EVIDENCE = "evidence-record-v1"
SIG_NAMESPACE = "rc8-release"

RE_HEX40 = re.compile(r"^[0-9a-f]{40}$")
RE_HEX64 = re.compile(r"^[0-9a-f]{64}$")

MANIFEST_REQUIRED = {
    "schema": str,
    "source_commit": str,
    "artifact_path": str,
    "artifact_sha256": str,
    "test_inventory_sha256": str,
}
MANIFEST_OPTIONAL = {
    "source_tree_digest": str,
    "toolchain_lock_digest": str,
    "created_at": str,
    "qualification": str,
    "signature_file": str,
}
EVIDENCE_REQUIRED = {
    "schema": str,
    "case_id": str,
    "test": str,
    "outcome": str,
    "source_commit": str,
}
EVIDENCE_OPTIONAL = {
    "artifact_sha256": (str, type(None)),
    "lane": str,
    "host": dict,
    "command": str,
    "started_at": str,
    "duration_ms": (int, float),
    "signer": str,
    "deployment": str,
}
OUTCOMES = {"PASS", "FAIL", "NOT_RUN", "SKIP"}


def fail(msg, failures):
    print(f"FAIL: {msg}", file=sys.stderr)
    failures.append(msg)


def ok(msg):
    print(f"ok: {msg}")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json_strict(path):
    """Parse JSON rejecting duplicate keys. Returns (obj, error)."""
    def no_dupes(pairs):
        seen, out = set(), {}
        for k, v in pairs:
            if k in seen:
                raise ValueError(f"duplicate key {k!r}")
            seen.add(k)
            out[k] = v
        return out
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f, object_pairs_hook=no_dupes), None
    except (json.JSONDecodeError, ValueError, OSError) as e:
        return None, str(e)


def _type_ok(value, types):
    # bool is a subclass of int — JSON true/false must not pass a
    # numeric field's check.
    if isinstance(value, bool):
        return bool in (types if isinstance(types, tuple) else (types,))
    return isinstance(value, types)


def check_keys(obj, required, optional, label, failures, line=""):
    loc = f"line {line}: " if line else ""
    for k in obj:
        if k not in required and k not in optional:
            fail(f"{loc}{label}: unexpected key {k!r}", failures)
    for k, t in required.items():
        if k not in obj:
            fail(f"{loc}{label}: missing required key {k!r}", failures)
        elif not _type_ok(obj[k], t):
            fail(f"{loc}{label}: key {k!r} has wrong type "
                 f"{type(obj[k]).__name__}", failures)
    for k, t in optional.items():
        if k in obj and not _type_ok(obj[k], t):
            fail(f"{loc}{label}: key {k!r} has wrong type "
                 f"{type(obj[k]).__name__}", failures)


def contained(path, root, label, failures):
    """Reject traversal/symlink escapes: resolved path must live under root."""
    try:
        real = os.path.realpath(path)
        realroot = os.path.realpath(root)
        if not (real == realroot or real.startswith(realroot + os.sep)):
            fail(f"{label}: {path} resolves outside {root}", failures)
            return None
        return real
    except OSError as e:
        fail(f"{label}: cannot resolve {path}: {e}", failures)
        return None


def verify_manifest(args, failures):
    m, err = load_json_strict(args.manifest)
    if err:
        fail(f"manifest: {err}", failures)
        return
    if m.get("schema") != SCHEMA_MANIFEST:
        fail(f"manifest: unknown schema {m.get('schema')!r}", failures)
        return
    check_keys(m, MANIFEST_REQUIRED, MANIFEST_OPTIONAL, "manifest", failures)
    if failures:
        return

    # Source identity — compared against the EXPECTED commit, never
    # reused as the artifact expectation (the RC8 defect).
    commit = m["source_commit"].lower()
    if not RE_HEX40.match(commit):
        fail(f"manifest: source_commit malformed: {commit!r}", failures)
    elif commit != args.source_commit.lower():
        fail(f"manifest: source_commit {commit} != expected "
             f"{args.source_commit.lower()}", failures)
    if args.source_tree:
        tree = (m.get("source_tree_digest") or "").lower()
        if tree != args.source_tree.lower():
            fail(f"manifest: source_tree_digest {tree or '<absent>'} != "
                 f"expected {args.source_tree.lower()}", failures)

    # Artifact identity — the manifest's declared sha is a CLAIM; the
    # artifact file's bytes are the EVIDENCE. No artifact: FAIL.
    declared = m["artifact_sha256"].lower()
    if not RE_HEX64.match(declared):
        fail(f"manifest: artifact_sha256 malformed: {declared!r}", failures)
    artifact = args.artifact
    if artifact is None:
        # artifact_path inside the manifest is advisory only — resolve it
        # relative to the manifest dir, contained, then hash it.
        artifact = contained(
            os.path.join(os.path.dirname(os.path.abspath(args.manifest)),
                         m["artifact_path"]),
            os.path.dirname(os.path.abspath(args.manifest)),
            "manifest artifact_path", failures)
        if artifact is None:
            return
    if not os.path.isfile(artifact):
        fail(f"artifact: {artifact} not found — manifest claims bytes "
             f"that do not exist", failures)
    else:
        actual = sha256_file(artifact)
        if actual != declared:
            fail(f"artifact sha256 {actual} != manifest-declared {declared}",
                 failures)
        else:
            ok(f"artifact sha256 == manifest claim ({actual})")

    # External expectation for the artifact when supplied.
    if args.artifact_sha256 and os.path.isfile(artifact):
        if sha256_file(artifact) != args.artifact_sha256.lower():
            fail(f"artifact sha256 != expected "
                 f"{args.artifact_sha256.lower()}", failures)

    # Signature: verified against an EXTERNAL trust root. A digest inside
    # the same unsigned manifest does not authenticate itself.
    if args.trust_store:
        sig_path = args.signature_file or m.get("signature_file")
        if not sig_path:
            fail("manifest signature: trust store supplied but no "
                 "signature file declared", failures)
        else:
            sig_real = contained(
                os.path.join(os.path.dirname(os.path.abspath(args.manifest)),
                             sig_path) if not os.path.isabs(sig_path)
                else sig_path,
                os.path.dirname(os.path.abspath(args.manifest)),
                "signature file", failures)
            if sig_real and not os.path.isfile(sig_real):
                fail(f"manifest signature: {sig_path} not found", failures)
            elif sig_real:
                _verify_ssh_sig(args, m, sig_real, failures)
    elif args.require_signature:
        fail("manifest signature: required but no trust store supplied",
             failures)

    inv = m.get("test_inventory_sha256", "").lower()
    if not RE_HEX64.match(inv):
        fail(f"manifest: test_inventory_sha256 malformed: {inv!r}", failures)
    elif args.inventory:
        # Bind the manifest to the actual inventory bytes — a declared
        # digest is a claim, not evidence.
        if not os.path.isfile(args.inventory):
            fail(f"inventory: {args.inventory} not found", failures)
        else:
            actual_inv = sha256_file(args.inventory)
            if actual_inv != inv:
                fail(f"inventory sha256 {actual_inv} != manifest-declared "
                     f"{inv}", failures)
            else:
                ok(f"test inventory sha256 == manifest claim ({actual_inv})")
    if m.get("qualification", "").upper().startswith("QUALIFIED"):
        if not args.trust_store:
            fail("manifest: QUALIFIED claim without signature verification",
                 failures)


def _canonical_manifest(m):
    """Canonical bytes the signature covers: manifest minus signature_file."""
    payload = {k: v for k, v in m.items() if k != "signature_file"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _verify_ssh_sig(args, manifest, sig_path, failures):
    signer = args.signer_id
    if not signer:
        fail("manifest signature: --signer-id required with --trust-store",
             failures)
        return
    # ssh-keygen -Y verify reads the signed payload on stdin.
    r = subprocess.run(
        ["ssh-keygen", "-Y", "verify", "-f", args.trust_store,
         "-I", signer, "-n", SIG_NAMESPACE, "-s", sig_path],
        input=_canonical_manifest(manifest), capture_output=True)
    if r.returncode != 0:
        fail(f"manifest signature: ssh-keygen verify failed for "
             f"signer {signer!r} under {SIG_NAMESPACE}: "
             f"{r.stderr.decode(errors='replace').strip()}", failures)
    else:
        ok(f"manifest signature valid ({signer}, {SIG_NAMESPACE})")


def verify_evidence(args, failures):
    inv, err = load_json_strict(args.inventory)
    if err:
        fail(f"inventory: {err}", failures)
        return
    if not isinstance(inv, dict) or not isinstance(inv.get("gates"), dict):
        fail("inventory: not a required-tests document", failures)
        return
    inventory_sha = sha256_file(args.inventory)

    required = set(args.require_test or [])
    # --require-gate pulls the required case set from the inventory's
    # own gate declaration — the tool binds evidence to the gate the
    # inventory defines, not to a caller-picked subset.
    for gate in args.require_gate or []:
        entry = inv["gates"].get(gate)
        if not isinstance(entry, dict):
            fail(f"inventory: no such gate {gate!r}", failures)
            continue
        tests = entry.get("required_tests")
        if not isinstance(tests, list) or not all(
                isinstance(t, str) for t in tests):
            fail(f"inventory: gate {gate!r} required_tests malformed",
                 failures)
            continue
        required.update(tests)
    seen = {}
    bound = 0
    for n, raw in enumerate(open(args.evidence, encoding="utf-8"), 1):
        line = raw.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            fail(f"line {n}: not JSON", failures)
            continue
        if rec.get("schema") != SCHEMA_EVIDENCE:
            fail(f"line {n}: unknown schema {rec.get('schema')!r}", failures)
            continue
        check_keys(rec, EVIDENCE_REQUIRED, EVIDENCE_OPTIONAL,
                   "evidence-record", failures, n)
        outcome = rec.get("outcome")
        if outcome not in OUTCOMES:
            fail(f"line {n}: outcome {outcome!r} not in {sorted(OUTCOMES)}",
                 failures)
        commit = rec.get("source_commit", "").lower()
        bound += 1
        if not RE_HEX40.match(commit):
            fail(f"line {n}: source_commit malformed", failures)
        elif commit != args.source_commit.lower():
            fail(f"line {n}: source_commit {commit} != expected "
                 f"{args.source_commit.lower()}", failures)
        if "artifact_sha256" in rec and rec["artifact_sha256"] is not None:
            ah = rec["artifact_sha256"].lower()
            if not RE_HEX64.match(ah):
                fail(f"line {n}: artifact_sha256 malformed", failures)
            elif args.artifact_sha256 and ah != args.artifact_sha256.lower():
                fail(f"line {n}: artifact_sha256 {ah} != expected "
                     f"{args.artifact_sha256.lower()}", failures)
        case = rec.get("case_id") or rec.get("test")
        if case in seen:
            fail(f"line {n}: duplicate case {case!r} (first at line "
                 f"{seen[case]})", failures)
        else:
            seen[case] = n
        if outcome in ("NOT_RUN", "SKIP") and case in required:
            fail(f"line {n}: required case {case!r} {outcome} — "
                 f"not executed evidence", failures)
        if outcome == "FAIL" and case in required:
            fail(f"line {n}: required case {case!r} FAIL", failures)
        if args.require_lane and case in required:
            if rec.get("lane") != args.require_lane:
                fail(f"line {n}: case {case!r} lane "
                     f"{rec.get('lane')!r} != required "
                     f"{args.require_lane!r}", failures)
        if args.require_signer and case in required:
            if not rec.get("signer"):
                fail(f"line {n}: required case {case!r} carries no "
                     f"trusted signer", failures)
        if isinstance(rec.get("host"), dict) and not rec["host"]:
            fail(f"line {n}: empty host attestation", failures)

    missing = required - set(seen)
    for case in sorted(missing):
        fail(f"required case {case!r} absent from evidence", failures)
    if bound == 0:
        fail("no identity-bound records found — unbound evidence", failures)
    if args.deployment and any(
            r != args.deployment for r in _deployments(args.evidence)):
        fail("evidence records deployments other than expected "
             f"{args.deployment!r} — replayed evidence", failures)
    ok(f"evidence: {bound} bound records, inventory sha256 "
       f"{inventory_sha}")


def _deployments(path):
    for raw in open(path, encoding="utf-8"):
        raw = raw.strip()
        if not raw:
            continue
        try:
            yield json.loads(raw).get("deployment")
        except json.JSONDecodeError:
            continue


def verify_artifact(args, failures):
    if not os.path.isfile(args.artifact):
        fail(f"artifact: {args.artifact} not found", failures)
        return
    got = sha256_file(args.artifact)
    if got == args.artifact_sha256.lower():
        ok(f"artifact-sha256 {got}")
    else:
        fail(f"artifact sha256 {got} != expected {args.artifact_sha256}",
             failures)


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--manifest")
    p.add_argument("--evidence")
    p.add_argument("--inventory")
    p.add_argument("--artifact")
    p.add_argument("--source-commit")
    p.add_argument("--source-tree")
    p.add_argument("--artifact-sha256")
    p.add_argument("--trust-store")
    p.add_argument("--signer-id")
    p.add_argument("--signature-file")
    p.add_argument("--require-signature", action="store_true")
    p.add_argument("--require-lane")
    p.add_argument("--require-test", action="append")
    p.add_argument("--require-gate", action="append")
    p.add_argument("--require-signer", action="store_true")
    p.add_argument("--deployment")
    args = p.parse_args()

    modes = [m for m in ("manifest", "evidence") if getattr(args, m)]
    if args.artifact and args.artifact_sha256 and not modes:
        modes = ["artifact"]
    if len(modes) != 1:
        p.error("exactly one mode required")
    if args.source_commit and not RE_HEX40.match(args.source_commit.lower()):
        p.error("--source-commit must be 40 lowercase hex")
    if args.artifact_sha256 and not RE_HEX64.match(
            args.artifact_sha256.lower()):
        p.error("--artifact-sha256 must be 64 lowercase hex")

    failures = []
    if modes[0] == "manifest":
        if not args.source_commit:
            p.error("--source-commit required in manifest mode")
        verify_manifest(args, failures)
    elif modes[0] == "evidence":
        for req in ("inventory", "source_commit"):
            if not getattr(args, req):
                p.error(f"--{req.replace('_','-')} required in evidence mode")
        if not os.path.isfile(args.evidence):
            fail(f"evidence: {args.evidence} not found", failures)
        else:
            verify_evidence(args, failures)
    else:
        verify_artifact(args, failures)

    print(f"== rc8-evidence-verify: {len(failures)} failure(s)")
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
