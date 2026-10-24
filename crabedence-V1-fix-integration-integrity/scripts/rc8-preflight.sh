#!/usr/bin/env bash
# RC8 preflight: gate orchestrator for the codex/rc8-authority-integration
# branch. Verifies the G0 baseline invariants before development merges and
# re-verifies identity bindings before packaging.
#
#   Usage: rc8-preflight.sh [repo-root]
#   Exit 0 only when every check passes. Exit 2 on usage/environment error.
#
# This script asserts identity — it does not run test suites. Lane evidence
# lives with the gates that produce it (see docs/rc8/QUALIFICATION_MATRIX.md).
set -euo pipefail

ROOT_ARG="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
ROOT="$(cd "$ROOT_ARG" && pwd -P)"

# The crabedence module lives one level below the NEMO-CONTROL workspace root
# on this branch; accept either as the argument and normalize.
if [ -f "$ROOT/go.mod" ]; then
  MODULE="$ROOT"
elif [ -f "$ROOT/crabedence-V1-fix-integration-integrity/go.mod" ]; then
  MODULE="$ROOT/crabedence-V1-fix-integration-integrity"
else
  echo "rc8-preflight: cannot locate crabedence module under $ROOT" >&2
  exit 2
fi

EXPECTED_PARENT="13566f1adf4fd3e3bd94981fe99670dc9de15793"
EXPECTED_VERSION="0.55.0-rc8-dev"

failures=0
check() {
  local name="$1"; shift
  if "$@"; then
    echo "ok: $name"
  else
    echo "FAIL: $name" >&2
    failures=$((failures + 1))
  fi
}

echo "== rc8-preflight: module=$MODULE"

# 1. Git work tree and branch ancestry: the signed-candidate parent must be
#    an ancestor of HEAD (branch may be at the parent or ahead of it).
check "git-worktree" git -C "$ROOT" rev-parse --is-inside-work-tree
check "parent-is-ancestor" \
  git -C "$ROOT" merge-base --is-ancestor "$EXPECTED_PARENT" HEAD

# 2. Clean checkout — tracked files must match the index+HEAD.
dirty="$(git -C "$ROOT" status --porcelain=v1 --untracked-files=no)"
check "clean-checkout" test -z "$dirty"

# 3. Version identity frozen.
check "version-frozen" \
  sh -c "test \"$(cat "$MODULE/VERSION")\" = \"$EXPECTED_VERSION\""

# 4. Toolchain declarations agree with the module.
if [ -f "$MODULE/scripts/verify-version-consistency.mjs" ]; then
  check "version-consistency" node "$MODULE/scripts/verify-version-consistency.mjs"
fi
if [ -f "$MODULE/scripts/verify-go-toolchain.sh" ]; then
  check "go-toolchain" "$MODULE/scripts/verify-go-toolchain.sh" "$MODULE"
fi

# 5. Frozen NEMO boundary: provenance checks must pass if present. The
#    verifier cds to its own module root and takes flags only.
if [ -f "$MODULE/scripts/verify-nemo-provenance.sh" ]; then
  check "nemo-provenance" "$MODULE/scripts/verify-nemo-provenance.sh" --require-source
fi

# 6. No stale qualified status: RC8 must not inherit a PASS it did not earn.
if grep -RInE '"qualification"[[:space:]]*:[[:space:]]*"QUALIFIED"' \
    "$MODULE/qualification" "$MODULE/release" 2>/dev/null; then
  echo "FAIL: stale QUALIFIED status present" >&2
  failures=$((failures + 1))
else
  echo "ok: no-stale-qualified-status"
fi

# 7. RC8 baseline documents exist.
for doc in BASELINE.md INTEGRATION_INVENTORY.md SECURITY_INVARIANTS.md \
           DEPENDENCY_GRAPH.md DEFECT_REGISTER.md QUALIFICATION_MATRIX.md; do
  check "doc-$doc" test -f "$MODULE/docs/rc8/$doc"
done

echo "== rc8-preflight: $failures failure(s)"
[ "$failures" -eq 0 ]
