#!/bin/sh
# RC8.3 formal full-tree race gate.
#
# The RC8.3 integrity-closure branch recorded this gate two ways: the
# exact `go test -race -timeout=20m ./...` invocation, which fails
# because one package legitimately needs more than the shared budget,
# and an operator-directed `GOFLAGS=-p=4 -timeout=45m` rerun that passed
# but cannot be reproduced from the recorded command alone. Neither is
# a gate: one measures package scheduling, the other measures an
# operator's judgement.
#
# This script is the canonical form. Every package runs in its own
# `go test` process with its own budget, in a deterministic order, and
# the result is recorded per package. A package that is slow cannot
# starve another; a package that fails cannot be hidden by a
# whole-tree exit code; and the evidence names exactly what ran.
#
# Usage:
#   scripts/qualify-race.sh [-o <outdir>] [package ...]
#
# Environment (pinned by the qualification record):
#   GOTOOLCHAIN          Go toolchain to use (default: go1.26.5)
#   RACE_BUDGET          Per-package test budget (default: 45m)
#   RACE_PARALLELISM     Concurrent packages (default: 1 — serial is
#                        the reproducible measurement; raise it only to
#                        trade wall-clock for load sensitivity)
#
# Exit: 0 when every package passed, 1 when any package failed or the
# run could not complete. The summary JSON is written even on failure.
set -eu

GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.5}"
RACE_BUDGET="${RACE_BUDGET:-45m}"
RACE_PARALLELISM="${RACE_PARALLELISM:-1}"
OUTDIR=""
PKGS=""

while [ $# -gt 0 ]; do
	case "$1" in
	-o|--out)
		OUTDIR="$2"
		shift 2
		;;
	-h|--help)
		sed -n '2,30p' "$0"
		exit 0
		;;
	*)
		PKGS="$PKGS $1"
		shift
		;;
	esac
done

if [ -z "$OUTDIR" ]; then
	OUTDIR="qualification/rc8.3-integrity/logs/race-$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "$OUTDIR"

if [ -z "${PKGS# }" ]; then
	PKGS=$(GOTOOLCHAIN="$GOTOOLCHAIN" go list ./... | sort)
fi

SUMMARY="$OUTDIR/summary.json"
RESULTS="$OUTDIR/packages.jsonl"
: >"$RESULTS"

commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
failures=0
total=0

run_one() {
	pkg="$1"
	total=$((total + 1))
	slug=$(printf '%s' "$pkg" | tr '/.' '__')
	log="$OUTDIR/$slug.log"
	begin=$(date -u +%s)
	set +e
	GOTOOLCHAIN="$GOTOOLCHAIN" go test -race -count=1 -timeout="$RACE_BUDGET" "$pkg" >"$log" 2>&1
	code=$?
	set -e
	end=$(date -u +%s)
	elapsed=$((end - begin))
	status=FAIL
	if [ "$code" -eq 0 ]; then
		status=PASS
	else
		failures=$((failures + 1))
	fi
	printf '{"package":"%s","status":"%s","exit_code":%s,"elapsed_seconds":%s,"log":"%s"}\n' \
		"$pkg" "$status" "$code" "$elapsed" "${log#"$OUTDIR"/}" >>"$RESULTS"
	printf '%-6s %8ss  %s\n' "$status" "$elapsed" "$pkg"
}

if [ "$RACE_PARALLELISM" -le 1 ]; then
	for pkg in $PKGS; do
		run_one "$pkg"
	done
else
	# Bounded fan-out without a dependency on GNU parallel or xargs -P
	# semantics: split the package list into N round-robin lanes and run
	# one serial lane per worker.
	lanes=$(mktemp -d)
	trap 'rm -rf "$lanes"' EXIT
	i=0
	for pkg in $PKGS; do
		slot=$((i % RACE_PARALLELISM))
		printf '%s\n' "$pkg" >>"$lanes/$slot"
		i=$((i + 1))
	done
	for lane in "$lanes"/*; do
		(
			while IFS= read -r pkg; do
				[ -n "$pkg" ] || continue
				run_one "$pkg"
			done <"$lane"
		) &
	done
	wait
	# Concurrent appends can interleave; re-sort the evidence so the
	# record is deterministic regardless of scheduling.
	sort -o "$RESULTS" "$RESULTS"
fi

finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
overall=PASS
if [ "$failures" -ne 0 ]; then
	overall=FAIL
fi

python3 - "$SUMMARY" "$RESULTS" <<'PY'
import json, sys
summary_path, results_path = sys.argv[1], sys.argv[2]
rows = []
with open(results_path) as fh:
    for line in fh:
        line = line.strip()
        if line:
            rows.append(json.loads(line))
doc = {
    "schema": "rc83-race-gate-v1",
    "packages": len(rows),
    "passed": sum(1 for r in rows if r["status"] == "PASS"),
    "failed": sum(1 for r in rows if r["status"] != "PASS"),
    "slowest": sorted(
        ({"package": r["package"], "elapsed_seconds": r["elapsed_seconds"]} for r in rows),
        key=lambda r: r["elapsed_seconds"], reverse=True,
    )[:10],
    "results": rows,
}
with open(summary_path, "w") as fh:
    json.dump(doc, fh, indent=1)
    fh.write("\n")
PY

cat >"$OUTDIR/run.json" <<EOF
{
 "schema": "rc83-race-gate-run-v1",
 "commit": "$commit",
 "toolchain": "$GOTOOLCHAIN",
 "per_package_budget": "$RACE_BUDGET",
 "parallelism": $RACE_PARALLELISM,
 "started_at": "$started",
 "finished_at": "$finished",
 "packages": $total,
 "failed": $failures,
 "result": "$overall"
}
EOF

echo "race gate: $overall ($total packages, $failures failed) — evidence in $OUTDIR"
[ "$failures" -eq 0 ]
