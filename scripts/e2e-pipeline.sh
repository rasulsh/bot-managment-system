#!/usr/bin/env bash
# Bot Guard end-to-end pipeline test.
#
#   bash scripts/e2e-pipeline.sh
#
# Starts a throw-away stack (PHP built-in server with the guard prepended, a
# private Redis, a temporary log directory), sends real HTTP traffic and then
# checks that every request was captured, stored, joined with its outcome, read
# by the analyzer's snapshot, and shown by the panel's own readers.
#
# Different client addresses are real: Linux answers on all of 127.0.0.0/8, and
# curl --interface picks the source address, so REMOTE_ADDR differs per request.
#
# Needs: php (8.0+), curl, python3, redis-server. Prints PASS/FAIL per check and
# exits 1 if anything failed. Touches nothing outside a temp directory.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHP_BIN="${GV_PHP:-php}"
# The built-in server serves one request at a time unless it has workers.
export PHP_CLI_SERVER_WORKERS="${PHP_CLI_SERVER_WORKERS:-8}"
PORT="${E2E_PORT:-8099}"
RPORT="${E2E_REDIS_PORT:-6390}"
WORK="$(mktemp -d)"
LOGS="$WORK/logs"
mkdir -p "$LOGS"

UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
UA2='Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15'
BASE="http://127.0.0.1:$PORT"

for need in "$PHP_BIN" curl python3 redis-server; do
	command -v "$need" >/dev/null 2>&1 || { echo "ERROR: '$need' is required." >&2; exit 2; }
done

PIDS=()
cleanup() {
	for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
	rm -rf "$WORK"
}
trap cleanup EXIT

# A config the way a fresh install behaves (everything shadow) with ONE change
# for the session scenario: the challenge is enforced, so a token can be earned.
cat > "$WORK/config.php" <<EOF
<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }
\$c = require '$ROOT/scripts/config.dev.php';
\$c['enforce'] = array('block' => false, 'challenge' => true, 'ratelimit' => false);
\$c['signals'] = array('reputation' => false, 'ml' => false, 'clf' => false);
\$c['redis']['port'] = $RPORT;
\$c['log_dir'] = '$LOGS';
\$c['holdout_pct'] = 0;
\$c['geo'] = array('log' => true);
\$c['limits'] = array_merge(\$c['limits'], array('window' => 60, 'device' => 100000, 'ip_ua' => 100000, 'ip' => 100000, 'mint' => 100000));
return \$c;
EOF

# GeoIP: a geoip.dat fixture compiled by the real cron wrapper (scripts/analyzer-cron.sh geo) into
# country.bin; with geo.log on, every row must carry the country (127.0.0.0/8 is US in the fixture).
mkdir -p "$WORK/geo"
python3 -I - "$WORK/geo/geoip.dat" <<'PY'
import sys
def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)
def field(num, payload):
    return varint((num << 3) | 2) + varint(len(payload)) + payload
def entry(tag, nets):
    body = field(1, tag.encode())
    for ip, prefix in nets:
        body += field(2, field(1, bytes(ip)) + varint((2 << 3) | 0) + varint(prefix))
    return field(1, body)
open(sys.argv[1], 'wb').write(entry('us', [((127, 0, 0, 0), 8)]) + entry('IR', [((5, 0, 0, 0), 8)]) + entry('private', [((10, 0, 0, 0), 8)]))
PY
GV_JOBSTATUS_DIR="$WORK" GV_JOBLOG_DIR="$WORK" GV_LOCK_DIR="$WORK" GV_GEO_DIR="$WORK/geo" GV_GEO_MIN_RANGES=1 GV_PYTHON=python3 bash "$ROOT/scripts/analyzer-cron.sh" geo >"$WORK/geo.out" 2>&1 \
	&& echo "PASS  analyzer-cron.sh geo compiled geoip.dat into country.bin" || { echo "FAIL  analyzer-cron.sh geo"; cat "$WORK/geo.out" >&2; GEO_FAILED=1; }
export GV_GEO_DIR="$WORK/geo"

redis-server --port "$RPORT" --save "" --appendonly no --daemonize no --dir "$WORK" >"$WORK/redis.log" 2>&1 &
PIDS+=($!)
# One access rule in monitor mode (scenario 4b): it must reach the logs and the snapshot.
printf '{"rules":[{"id":"pipe1","name":"pipeline","enabled":true,"mode":"monitor","action":"block","priority":10,"skip_verified_bots":true,"ua":{"op":"include","type":"contains","values":["pipeline-rule-bot"]},"path":null,"expires_at":0,"pow_bits":0,"note":"","created_by":"","created_at":0,"updated_at":0}]}' > "$WORK/rules.json"
GV_RULES="$WORK/rules.json" GV_DEV_CONFIG="$WORK/config.php" "$PHP_BIN" -S "0.0.0.0:$PORT" "$ROOT/scripts/dev-router.php" >"$WORK/php.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 50); do
	curl -s -o /dev/null "$BASE/t/404" 2>/dev/null && break
	sleep 0.1
done
curl -s -o /dev/null "$BASE/t/404" || { echo "ERROR: the test server did not start (see $WORK/php.log)" >&2; cat "$WORK/php.log" >&2; exit 2; }
# Warm-up request is itself logged; wipe it so the counts below are exact.
rm -f "$LOGS"/guard-*.jsonl

HDR=(-H "Accept: text/html,application/xhtml+xml" -H "Accept-Language: en-US,en;q=0.9" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: none")
EXPECT="$WORK/expect.tsv"
: > "$EXPECT"
expect() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$EXPECT"; }   # label rows ips devs(-1 = ignore)

# Fetch a page from a given address; the label is carried in the query string.
hit() { # <source-ip> <label> [extra curl args]
	local ip="$1" label="$2"; shift 2
	curl -s -o /dev/null --interface "$ip" -H "User-Agent: $UA" "${HDR[@]}" "$@" "$BASE/?t=$label"
}

solve_and_post() { # <source-ip> <jar> <label> <user-agent>: challenge -> handshake -> token cookie
	local ip="$1" jar="$2" label="$3" ua="$4" body nonce proof
	body="$(curl -s --interface "$ip" -H "User-Agent: $ua" "${HDR[@]}" "$BASE/?t=$label")"
	nonce="$(printf '%s' "$body" | sed -n "s/.*var N = '\([0-9a-f.]*\)'.*/\1/p" | head -1)"
	[ -n "$nonce" ] || { echo "no nonce"; return 1; }
	proof="$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$nonce" 2>/dev/null)"
	curl -s -o /dev/null --interface "$ip" -H "User-Agent: $ua" -H "X-GV: $nonce" -H "X-GV-P: $proof" -c "$jar" -X POST "$BASE/?t=$label"
}

echo "== 1. Different client addresses (5 addresses x 3 requests, no cookies)"
for ip in 127.0.0.11 127.0.0.12 127.0.0.13 127.0.0.14 127.0.0.15; do
	for _ in 1 2 3; do hit "$ip" ips; done
done
expect ips 15 5 -1

echo "== 2. One browser, several tabs at once (shared cookie jar), then a second browser"
JAR1="$WORK/jar1"; JAR2="$WORK/jar2"
solve_and_post 127.0.0.21 "$JAR1" tabs "$UA"            # challenge GET + handshake POST = 2 rows
# The subshell matters: a bare `wait` would also wait for the two servers.
( for _ in 1 2 3 4 5 6; do hit 127.0.0.21 tabs -b "$JAR1" & done; wait )
solve_and_post 127.0.0.22 "$JAR2" tabs2 "$UA2"          # a different browser on another address
for _ in 1 2 3; do hit 127.0.0.22 tabs2 -b "$JAR2" -H "User-Agent: $UA2"; done
expect tabs 8 1 -2          # devs = -2: the verifier checks tokens are consistent, see e2e-verify.php
expect tabs2 5 1 -2

echo "== 3. Concurrency: 200 requests, 20 at a time, 10 addresses"
seq 1 200 | xargs -P 20 -I{} bash -c '
	ip="127.0.1.$(( {} % 10 + 1 ))"
	curl -s -o /dev/null --interface "$ip" -H "User-Agent: '"$UA"'" -H "Accept: text/html" -H "Accept-Language: en" "'"$BASE"'/?t=burst"'
expect burst 200 10 -1

echo "== 4. Other methods, an exempt path and an application 404"
curl -s -o /dev/null --interface 127.0.0.31 -I -H "User-Agent: $UA" "${HDR[@]}" "$BASE/?t=head"
curl -s -o /dev/null --interface 127.0.0.31 -H "User-Agent: $UA" "${HDR[@]}" "$BASE/exempt-me?t=exempt"
# Needs the token earned in scenario 2, or the guard would answer with the challenge page.
curl -s -o /dev/null --interface 127.0.0.21 -b "$JAR1" -H "User-Agent: $UA" "${HDR[@]}" "$BASE/t/404?t=notfound"
expect head 1 1 -1
expect exempt 1 1 -1
expect notfound 1 1 -1

echo "== 4b. An access rule in monitor mode: logged as SH_RULE, never acts"
for _ in 1 2 3; do
	curl -s -o /dev/null --interface 127.0.0.41 -H "User-Agent: x pipeline-rule-bot/1.0" "${HDR[@]}" "$BASE/?t=rulehit"
done
expect rulehit 3 1 -1

echo "== 5. The analyzer snapshot reads the same data"
python3 "$ROOT/analyzer/snapshot.py" --log-dir "$LOGS" --out "$WORK/snapshot.json" >"$WORK/snapshot.out" 2>&1 || cat "$WORK/snapshot.out" >&2

echo "== 6. Verify: log file, panel readers, snapshot"
GV_CONFIG="$WORK/config.php" "$PHP_BIN" "$ROOT/scripts/e2e-verify.php" "$LOGS" "$EXPECT" "$WORK/snapshot.json"
status=$?
# The snapshot carries the per-rule hit counts the Rules page shows.
if python3 -c "import json,sys; r=json.load(open(sys.argv[1])).get('rules',{}).get('pipe1',{}); sys.exit(0 if r.get('h24')==3 and r.get('d7')==3 and r.get('last',0)>0 else 1)" "$WORK/snapshot.json"; then
	echo "PASS  snapshot rules: pipe1 has 3 hits in 24h and 7d"
else
	echo "FAIL  snapshot rules: pipe1 hit counts missing or wrong"
	python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('rules'))" "$WORK/snapshot.json" >&2; cat "$WORK/snapshot.out" >&2; grep -c SH_RULE "$LOGS"/guard-*.jsonl >&2
	status=1
fi
rm -f "$ROOT/analyzer/.rule-hits.json"
# The snapshot's 24 h KPIs, top lists and time zone (dashboard redesign): built from the same rows.
if python3 -c "import json,sys; d=json.load(open(sys.argv[1])); k=d['kpi']['cur']; sys.exit(0 if k['requests']>20 and k['allowed']>0 and 'tz' in d and isinstance(d['tz']['offset'], int) and 'ips' in d['top'] and d['kpi']['window_h']==24 else 1)" "$WORK/snapshot.json"; then
	echo "PASS  snapshot: 24 h KPIs (rolling window), top lists and time zone are present"
else
	echo "FAIL  snapshot: kpi / top / tz missing or empty"
	status=1
fi
# GeoIP logging: every decision row of this run carries the country, and the readers above accepted them.
rows_total=$(cat "$LOGS"/guard-*.jsonl | grep -vc '"o":1')
rows_cc=$(cat "$LOGS"/guard-*.jsonl | grep -c '"cc":"US"')
if [ "$rows_cc" -gt 20 ] && [ "$rows_cc" -le "$rows_total" ]; then
	echo "PASS  geo.log: $rows_cc rows carry cc US (compiled by the cron wrapper, read by the guard)"
else
	echo "FAIL  geo.log: $rows_cc of $rows_total rows carry cc US"
	status=1
fi
[ "${GEO_FAILED:-0}" -eq 0 ] || status=1       # the geo compile step counts too, not only the counts it leads to
exit $status
