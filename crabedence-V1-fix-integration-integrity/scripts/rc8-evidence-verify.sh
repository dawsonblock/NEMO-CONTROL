#!/usr/bin/env bash
# RC8.1 evidence verifier — thin wrapper over the schema-specific
# implementation in rc8_evidence_verify.py (kept so existing callers and
# docs keep a stable entry point). See that file for modes and flags.
# NOTE: the interface changed with the schema-specific rewrite —
# --commit/--sha256 became --source-commit/--artifact-sha256, manifest
# mode gained --inventory (digest binding), and evidence mode requires
# --inventory plus optional --require-test/--require-gate sets.
set -euo pipefail
exec python3 "$(dirname "$0")/rc8_evidence_verify.py" "$@"
