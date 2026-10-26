#!/usr/bin/env bash
# Clean-room reproduction of the RC8.3 integrity-closure source archive.
# Extracts the signed archive into a fresh directory, verifies every
# inventory record, then builds and runs the security-critical suites
# with a fresh build cache and a fresh module cache.
set -euo pipefail

ARCHIVE="${1:?archive}"
INVENTORY="${2:?inventory}"
WORK="${3:?workdir}"

rm -rf "$WORK"
mkdir -p "$WORK"
unzip -q "$ARCHIVE" -d "$WORK"
ROOT="$(find "$WORK" -maxdepth 1 -mindepth 1 -type d -name 'nemo-control-*' | head -1)"
if [ -z "$ROOT" ]; then
  echo "clean-room: archive root not found" >&2
  exit 1
fi
echo "clean-room root: $ROOT"

python3 "$(dirname "$0")/verify-inventory.py" "$INVENTORY" "$ROOT"

export GOTOOLCHAIN=go1.26.5
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

echo "== targeted race suites =="
go test -race -count=1 -timeout=10m \
  ./internal/witness ./internal/custody ./internal/execution ./cmd/custodyctl

echo "CLEAN-ROOM PASS"
