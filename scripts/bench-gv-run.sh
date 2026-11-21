#!/usr/bin/env bash
# Benchmark gv_run() with 0, 20 and 200 access rules against a throw-away Redis.
#   bash scripts/bench-gv-run.sh [runs]
# Run it on the base branch and on the branch under test and compare the lines.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHP_BIN="${GV_PHP:-php}"
RPORT="${BENCH_REDIS_PORT:-6399}"
RUNS="${1:-3}"
WORK="$(mktemp -d)"
redis-server --port "$RPORT" --save "" --appendonly no --maxmemory-policy noeviction --dir "$WORK" >/dev/null 2>&1 &
RPID=$!
trap 'kill $RPID 2>/dev/null; rm -rf "$WORK"' EXIT
sleep 0.4
for args in "--rules=0" "--rules=20" "--rules=200" "--rules=200 --values=50" "--rules=200 --regex"; do
	for _ in $(seq 1 "$RUNS"); do
		# shellcheck disable=SC2086
		"$PHP_BIN" ${GV_BENCH_PHPFLAGS:--d opcache.enable_cli=1 -d opcache.file_update_protection=0} "$ROOT/scripts/bench-gv-run.php" --redis-port="$RPORT" $args
	done
done
