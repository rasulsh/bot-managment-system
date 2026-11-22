#!/usr/bin/env bash
# Benchmark gv_run() with 0, 20 and 200 access rules, and with GeoIP, against a throw-away Redis.
#   bash scripts/bench-gv-run.sh [runs]
# Run it on the base branch and on the branch under test and compare the lines.
# The geo rows need guard/geo.php (this branch); on a base without it they are skipped.
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
ARGSETS=("--rules=0" "--rules=20" "--rules=200" "--rules=200 --values=50" "--rules=200 --regex")
if [ -f "$ROOT/guard/geo.php" ]; then
	# --geo-log: the lookup runs on every request, no rules. --geo-rules=200: 200 country rules, the
	# lookup runs once. --geo-ua: 200 UA+country rules whose UA misses, so no lookup at all.
	ARGSETS+=("--geo-log" "--geo-rules=200" "--geo-rules=200 --geo-ua" "--lookup")
fi
if [ -f "$ROOT/guard/iplist.php" ]; then
	# IP lists: a block file, then an allow AND a block file, of 100k IPv4 + 10k IPv6 ranges each: the whole gv_run
	# and the lookup alone.
	ARGSETS+=("--lists=100000,10000 --list-types=block" "--lists=100000,10000" "--list-lookup --list-types=block" "--list-lookup")
fi
if [ -f "$ROOT/guard/captcha.php" ]; then
	# CAPTCHA: 20 captcha rules that never match, one that matches a client holding a CAPTCHA-level token (not asked), and the
	# page generation per level (needs GD).
	ARGSETS+=("--cap-rules=20" "--cap-match" "--cap-gen")
fi
for args in "${ARGSETS[@]}"; do
	for _ in $(seq 1 "$RUNS"); do
		# shellcheck disable=SC2086
		"$PHP_BIN" ${GV_BENCH_PHPFLAGS:--d opcache.enable_cli=1 -d opcache.file_update_protection=0} "$ROOT/scripts/bench-gv-run.php" --redis-port="$RPORT" $args
	done
done
