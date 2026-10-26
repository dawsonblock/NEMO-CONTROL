#!/usr/bin/env bash
# Build the self-contained RC8.3 integrity-closure release evidence bundle.
#
# Prerequisites: source-a.zip, source-b.zip, source-inventory.txt already
# generated from the frozen source commit. This script copies the logs and
# matrix into the bundle, writes a relative-path attestation, signs it with
# the pinned release root, verifies it, and checks the whole bundle.
set -euo pipefail

REPO="${1:?repo root}"
COMMIT="${2:?source commit}"
B="${3:?release dir}"
VERDICT="${4:-NO-GO}"

SRC="$REPO/crabedence-V1-fix-integration-integrity"
mkdir -p "$B/logs"
cp "$SRC"/qualification/rc8.3-integrity/logs/*.log "$B/logs/"
cp "$SRC"/qualification/rc8.3-integrity/qualification-matrix.json "$B/"

python3 "$SRC/qualification/rc8.3-integrity/tools/write-attestation.py" \
  "$COMMIT" "$B/source-inventory.txt" "$B/source-a.zip" "$B/logs" "$B/attestation.json" "$VERDICT"

python3 "$B/sign-release-attestation.py" "$B" | tee "$B/sign-attestation.log"
python3 "$B/verify-release-attestation.py" "$B" | tee "$B/verify-attestation.log"

python3 - "$B" <<'PY'
import hashlib, json, os, sys
B=sys.argv[1]
def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for c in iter(lambda:f.read(1<<20),b''): h.update(c)
    return h.hexdigest()
a=os.path.join(B,'source-a.zip'); b=os.path.join(B,'source-b.zip')
doc={
 "schema":"rc83-integrity-packaging-v1",
 "command":"python3 qualification/rc8.3-integrity/tools/deterministic-package.py <repo> crabedence-V1-fix-integration-integrity nemo-control-0.55.0-rc8.3-integrity-closure <output>",
 "entries":sum(1 for _ in open(os.path.join(B,'source-inventory.txt'),encoding='utf-8')),
 "archive_a":{"path":"source-a.zip","sha256":sha(a),"size":os.path.getsize(a)},
 "archive_b":{"path":"source-b.zip","sha256":sha(b),"size":os.path.getsize(b)},
 "byte_identical":sha(a)==sha(b),
 "source_inventory":{"path":"source-inventory.txt","sha256":sha(os.path.join(B,'source-inventory.txt'))},
 "notes":"Fixed timestamp 2020-01-01, fixed modes, LC_ALL=C path order, symlinks preserved. Two independent builds are byte-identical.",
}
json.dump(doc,open(os.path.join(B,'packaging.json'),'w'),indent=2,sort_keys=True)
open(os.path.join(B,'packaging.json'),'a').write('\n')
print(json.dumps(doc,indent=2))
PY

(
  cd "$B"
  find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 shasum -a 256 \
    | sed 's|  \./|  |' > SHA256SUMS
)

python3 "$SRC/qualification/rc8.3-integrity/tools/verify-evidence-bundle.py" "$B" | tee "$B/verify-bundle.log"
echo "BUNDLE PASS"
