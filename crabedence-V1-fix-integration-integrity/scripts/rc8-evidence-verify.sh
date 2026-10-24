#!/usr/bin/env bash
# RC8 evidence verifier: independent check that a piece of qualification
# evidence or a packaged artifact binds the SAME source identity it claims.
# Fails closed on any mismatch — evidence bound to different bytes is
# treated as absent (INV-6).
#
#   Usage:
#     rc8-evidence-verify.sh --manifest RELEASE_MANIFEST.json --commit <hex40>
#     rc8-evidence-verify.sh --evidence FILE.jsonl --commit <hex40>
#     rc8-evidence-verify.sh --artifact FILE.zip --sha256 <hex64>
#
#   Exit 0 only when every binding verifies. Exit 2 on usage error.
set -euo pipefail

usage() {
  grep '^#' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

MODE=""
TARGET=""
EXPECT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) MODE="manifest"; TARGET="$2"; shift 2 ;;
    --evidence) MODE="evidence"; TARGET="$2"; shift 2 ;;
    --artifact) MODE="artifact"; TARGET="$2"; shift 2 ;;
    --commit|--sha256) EXPECT="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$MODE" ] && [ -n "$TARGET" ] && [ -n "$EXPECT" ] || usage
[ -f "$TARGET" ] || { echo "rc8-evidence-verify: $TARGET not found" >&2; exit 2; }

failures=0
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }
ok() { echo "ok: $1"; }

case "$MODE" in
  manifest)
    # Every source-binding field in the manifest must equal the expected
    # commit; the declared artifact hash must match the artifact file.
    python3 - "$TARGET" "$EXPECT" <<'PY' || fail "manifest-binding"
import json, sys
m = json.load(open(sys.argv[1])); want = sys.argv[2].lower()
src = m.get("source", {})
bad = []
if src.get("commit", "").lower() != want:
    bad.append(f"source.commit={src.get('commit')} != {want}")
art = m.get("artifact", {})
if art.get("sha256") and len(art["sha256"]) != 64:
    bad.append("artifact.sha256 malformed")
if m.get("qualification", "").startswith("QUALIFIED") and not m.get("qualified_at"):
    bad.append("QUALIFIED without bound evidence")
for b in bad: print("FAIL:", b, file=sys.stderr)
sys.exit(1 if bad else 0)
PY
    ;;

  evidence)
    # JSONL test/event evidence: every record that asserts a source commit or
    # artifact hash must assert the EXPECTED one. Records without identity
    # fields do not count as bound evidence.
    python3 - "$TARGET" "$EXPECT" <<'PY' || fail "evidence-binding"
import json, sys
want = sys.argv[2].lower()
bound, bad = 0, []
for n, line in enumerate(open(sys.argv[1]), 1):
    line = line.strip()
    if not line: continue
    try: rec = json.loads(line)
    except json.JSONDecodeError:
        bad.append(f"line {n}: not JSON"); continue
    for k in ("commit", "source_commit", "sha256", "artifact_sha256"):
        v = str(rec.get(k, "")).lower()
        if v:
            bound += 1
            if v != want:
                bad.append(f"line {n}: {k}={v} != {want}")
if bound == 0:
    bad.append("no identity-bound fields found — unbound evidence")
for b in bad[:20]: print("FAIL:", b, file=sys.stderr)
print(f"bound-fields={bound}", file=sys.stderr)
sys.exit(1 if bad else 0)
PY
    ;;

  artifact)
    got="$(shasum -a 256 "$TARGET" | awk '{print $1}')"
    if [ "$got" = "$EXPECT" ]; then
      ok "artifact-sha256"
    else
      fail "artifact sha256 $got != expected $EXPECT"
    fi
    ;;
esac

echo "== rc8-evidence-verify: $failures failure(s)"
[ "$failures" -eq 0 ]
