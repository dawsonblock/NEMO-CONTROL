#!/bin/sh
# RC8.3 clean-room reproduction of a source archive.
#
# The earlier script in the release bundle found the extracted root with
# a case-sensitive glob (`nemo-control-*`) that never matched the
# artifact it was meant to verify, and resolved its inventory verifier
# from the release directory rather than from the tree. Both are fixed
# here: the root is discovered from the archive itself, and the
# verifier ships inside the tree it verifies.
#
# This is a packaging-integrity check on one host. It is NOT G33: a
# third party must run it on a host that has never held this repository
# (see EXTERNAL-QUALIFICATION.md).
#
# Usage: cleanroom-verify.sh <archive> <inventory> <workdir>
set -eu

ARCHIVE="${1:?archive}"
INVENTORY="${2:?inventory}"
WORK="${3:?workdir}"

here=$(cd "$(dirname "$0")" && pwd)

# Go marks module-cache entries read-only (0444 files, 0555 directories),
# so a repeat run cannot unlink them without restoring write permission
# on the directories first.
if [ -e "$WORK" ]; then
	chmod -R u+w "$WORK" 2>/dev/null || true
	rm -rf "$WORK"
fi
mkdir -p "$WORK"
unzip -q "$ARCHIVE" -d "$WORK"

# The archive has exactly one top-level directory; its name is not part
# of the contract, so discover it rather than guessing it.
ROOT=""
for d in "$WORK"/*; do
	[ -d "$d" ] || continue
	if [ -n "$ROOT" ]; then
		echo "clean-room: archive has more than one top-level directory" >&2
		exit 1
	fi
	ROOT="$d"
done
if [ -z "$ROOT" ]; then
	echo "clean-room: archive root not found" >&2
	exit 1
fi
echo "clean-room root: $ROOT"

echo "== inventory =="
python3 "$here/verify-inventory.py" "$INVENTORY" "$ROOT"

# A fresh build cache and module cache, and a read-only module graph:
# the tree may only build from what it declares.
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.5}"
export GOCACHE="$WORK/gocache"
export GOMODCACHE="$WORK/gomodcache"
export GOFLAGS="-mod=readonly"
cd "$ROOT"

echo "== go mod download =="
go mod download

echo "== go build ./... =="
go build ./...

echo "== go vet ./... =="
go vet ./...

echo "== custody and operator race suites =="
go test -race -count=1 -timeout=20m \
	./internal/witness ./internal/custody ./internal/execution \
	./internal/idempotency ./cmd/custodyctl

echo "CLEAN-ROOM PASS"
