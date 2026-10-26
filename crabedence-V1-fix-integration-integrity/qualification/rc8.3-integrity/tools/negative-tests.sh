#!/usr/bin/env bash
# Reproducible negative tests for the RC8.3 evidence bundle.
#
# Every case must be REJECTED by verify-release-attestation.py when the
# trust anchor is supplied from outside the bundle. The last case is the
# regression for the original defect: a coherent substitution (new key,
# new attestation, new signature, replaced public key) must fail because
# the pinned key id does not come from the bundle.
#
# Usage: negative-tests.sh <bundle-dir> <pinned-root-key-id> <out-dir>
set -uo pipefail

B="${1:?bundle dir}"
ANCHOR="${2:?pinned root key id}"
OUT="${3:?output dir}"
HERE="$(cd "$(dirname "$0")" && pwd)"
VERIFY="$HERE/verify-release-attestation.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail=0

# expect_reject <name> <bundle> [extra verifier args...]
expect_reject() {
  local name="$1" dir="$2"
  shift 2
  if python3 "$VERIFY" "$dir" --root-key-id "$ANCHOR" "$@" >"$OUT/$name" 2>&1; then
    echo "UNEXPECTED PASS: $name" >&2
    fail=1
  else
    echo "rejected: $name"
  fi
}

copy_bundle() {
  local dst="$1"
  mkdir -p "$dst"
  cp -R "$B"/. "$dst"/
}

# 1. Modified attestation body.
copy_bundle "$WORK/modified"
python3 - "$WORK/modified/attestation.json" <<'PY'
import json, sys
p = sys.argv[1]
a = json.load(open(p))
a["qualification_verdict"] = "GO (rewritten)"
json.dump(a, open(p, "w"), indent=2, sort_keys=True)
open(p, "a").write("\n")
PY
expect_reject verify-attestation-modified.log "$WORK/modified"

# 2. Corrupted signature bytes.
copy_bundle "$WORK/badsig"
python3 - "$WORK/badsig/attestation.sig" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
b[0] ^= 0xFF
open(p, "wb").write(bytes(b))
PY
expect_reject verify-attestation-badsig.log "$WORK/badsig"

# 3. Swapped source inventory.
copy_bundle "$WORK/swapped"
cp "$WORK/swapped/swapped-inventory.txt" "$WORK/swapped/source-inventory.txt"
expect_reject verify-attestation-swapped.log "$WORK/swapped"

# 4. Swapped archive bytes.
copy_bundle "$WORK/tampered"
cp "$WORK/tampered/tampered.zip" "$WORK/tampered/source-a.zip"
expect_reject verify-attestation-tampered.log "$WORK/tampered"

# 5. Wrong pinned root: the signer is not the pinned key.
if python3 "$VERIFY" "$WORK/tampered" --root-key-id "$(printf '0%.0s' {1..64})" >"$OUT/verify-attestation-wrongroot.log" 2>&1; then
  echo "UNEXPECTED PASS: verify-attestation-wrongroot.log" >&2
  fail=1
else
  echo "rejected: verify-attestation-wrongroot.log"
fi

# 6. Coherent forgery: new key, rewritten verdict, re-signed, replaced
#    bundled public key. Only the external anchor can catch this.
copy_bundle "$WORK/forged"
openssl genpkey -algorithm ed25519 -out "$WORK/forged.pem" 2>/dev/null
openssl pkey -in "$WORK/forged.pem" -pubout -out "$WORK/forged/forged.pub" 2>/dev/null
cp "$WORK/forged/forged.pub" "$WORK/forged/release-root/release-root.pub"
python3 - "$WORK/forged" "$WORK/forged.pem" <<'PY'
import hashlib, json, subprocess, sys
base, key = sys.argv[1], sys.argv[2]
att = json.load(open(base + "/attestation.json"))
att["qualification_verdict"] = "GO (forged by a substituted root)"
att["signature"]["key_id"] = hashlib.sha256(
    subprocess.check_output(["openssl", "pkey", "-pubin", "-in", base + "/release-root/release-root.pub", "-outform", "DER"])
).hexdigest()
unsigned = dict(att)
unsigned.pop("signature")
canon = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
open(base + "/attestation.canonical.json", "wb").write(canon)
json.dump(att, open(base + "/attestation.json", "w"), indent=2, sort_keys=True)
open(base + "/canon.bin", "wb").write(canon)
PY
openssl pkeyutl -sign -inkey "$WORK/forged.pem" -rawin -in "$WORK/forged/canon.bin" -out "$WORK/forged/attestation.sig"
rm -f "$WORK/forged/canon.bin"
expect_reject verify-attestation-forgedroot.log "$WORK/forged"

if [ "$fail" -ne 0 ]; then
  echo "NEGATIVE TESTS FAIL"
  exit 1
fi
echo "NEGATIVE TESTS PASS: every tamper case was rejected"
