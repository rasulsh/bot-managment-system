#!/usr/bin/env bash
# Bot Guard challenge end-to-end test (challenge.test_key switch).
#
#   bash scripts/e2e-challenge.sh
#
# Starts throw-away servers (PHP built-in server with the guard prepended and a
# private Redis) and drives the REAL challenge flow with curl: page shown,
# solved, token earned, access granted; wrong proof, replay, expired nonce and
# forged switch cookie are refused; other visitors are never affected.
# Needs: php (8.0+), curl, redis-server. Touches nothing outside a temp dir.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHP_BIN="${GV_PHP:-php}"
export PHP_CLI_SERVER_WORKERS="${PHP_CLI_SERVER_WORKERS:-8}"
P1="${E2E_PORT:-8111}"; P2=$((P1 + 1)); P3=$((P1 + 2))
RPORT="${E2E_REDIS_PORT:-6391}"
KEY='test-key-0123456789abcdef'
WORK="$(mktemp -d)"
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
HDR=(-H "User-Agent: $UA" -H "Accept: text/html,application/xhtml+xml" -H "Accept-Language: en-US,en;q=0.9" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: none")

for need in "$PHP_BIN" curl redis-server; do
	command -v "$need" >/dev/null 2>&1 || { echo "ERROR: '$need' is required." >&2; exit 2; }
done

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT

# $1 name, $2 enforce.challenge (true/false), $3 test_key, $4 port
start_server() {
	mkdir -p "$WORK/$1/logs"
	cat > "$WORK/$1/config.php" <<CFG
<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }
\$c = require '$ROOT/scripts/config.dev.php';
\$c['enforce'] = array('block' => false, 'challenge' => $2, 'ratelimit' => false);
\$c['signals'] = array('reputation' => false, 'ml' => false, 'clf' => false);
\$c['redis']['port'] = $RPORT;
\$c['log_dir'] = '$WORK/$1/logs';
\$c['holdout_pct'] = 0;
\$c['nonce_ttl'] = 3;
\$c['challenge'] = array('pow_bits' => 12, 'bind_ip' => true, 'test_key' => '$3');
\$c['limits'] = array_merge(\$c['limits'], array('window' => 60, 'device' => 100000, 'ip_ua' => 100000, 'ip' => 100000, 'mint' => 100000));
return \$c;
CFG
	GV_DEV_CONFIG="$WORK/$1/config.php" "$PHP_BIN" -S "127.0.0.1:$4" "$ROOT/scripts/dev-router.php" >"$WORK/$1/php.log" 2>&1 &
	PIDS+=($!)
	for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$4/t/404" 2>/dev/null && break; sleep 0.1; done
}

redis-server --port "$RPORT" --save "" --appendonly no --dir "$WORK" >"$WORK/redis.log" 2>&1 &
PIDS+=($!)
sleep 0.3
start_server enf true "$KEY" "$P1"
start_server mon false "$KEY" "$P2"
start_server off true "" "$P3"

PASS=0; FAIL=0
ok() { if [ "$2" = "1" ]; then PASS=$((PASS + 1)); echo "PASS  $1"; else FAIL=$((FAIL + 1)); echo "FAIL  $1"; fi; }
# eq NAME GOT WANT
eq() { [ "$2" = "$3" ] && ok "$1" 1 || { ok "$1 (got '$2', want '$3')" 0; }; }

code() { curl -s -o /dev/null -w '%{http_code}' "${HDR[@]}" "$@"; }
nonce_of() { sed -n "s/.*var N = '\([^']*\)'.*/\1/p" | head -1; }
# solve NONCE PORT JAR [COUNTER] -> status of the handshake POST
solve() {
	local c="${4:-$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$1" 2>/dev/null)}"
	curl -s -o /dev/null -w '%{http_code}' -X POST -H "User-Agent: $UA" -H "X-GV: $1" -H "X-GV-P: $c" \
		-b "$3" -c "$3" "http://127.0.0.1:$2/"
}
page() { curl -s "${HDR[@]}" -b "$2" -c "$2" "http://127.0.0.1:$1$3"; }   # PORT JAR PATH
status() { code -b "$2" -c "$2" "http://127.0.0.1:$1$3"; }

B1="http://127.0.0.1:$P1"
echo "== A. A normal visitor earns a token (baseline, enforced)"
J="$WORK/a.jar"
eq "A1 no token -> challenge page 503" "$(status $P1 $J /)" 503
N=$(page $P1 $J / | nonce_of)
ok "A2 page carries a nonce" "$([ -n "$N" ] && echo 1 || echo 0)"
eq "A3 correct proof -> 204" "$(solve "$N" $P1 $J)" 204
eq "A4 access granted afterwards -> 200" "$(status $P1 $J /)" 200

echo "== B. The switch: wrong key does nothing"
eq "B1 wrong key -> 200, no redirect" "$(status $P1 $J '/?gv_test=nope')" 200
eq "B2 still 200 afterwards" "$(status $P1 $J /)" 200

echo "== C. The switch: right key shows the real page to this browser"
H=$(curl -s -o /dev/null -D - "${HDR[@]}" -b $J -c $J "$B1/shop?x=1&gv_test=$KEY&y=2")
eq "C1 right key -> 302" "$(echo "$H" | head -1 | awk '{print $2}')" 302
eq "C2 redirect drops the key, keeps the rest" "$(echo "$H" | tr -d '\r' | sed -n 's/^[Ll]ocation: //p')" "/shop?x=1&y=2"
eq "C3 although it holds a valid token, GET -> 503 challenge" "$(status $P1 $J /)" 503
page $P1 $J / | grep -q "var N = '" ; ok "C4 the real page (with nonce) is served" "$([ $? -eq 0 ] && echo 1 || echo 0)"
J2="$WORK/b.jar"
N2=$(page $P1 $J2 / | nonce_of); solve "$N2" $P1 $J2 >/dev/null
eq "C6 a different visitor holding a token still gets 200 while the first is under test" "$(status $P1 $J2 /)" 200

echo "== D. Wrong answers are refused, the page stays"
N=$(page $P1 $J / | nonce_of)
eq "D1 wrong proof -> 403" "$(solve "$N" $P1 $J 1)" 403
eq "D2 garbage nonce -> 403" "$(solve "1.2.3.4" $P1 $J 1)" 403
eq "D3 still challenged after failures" "$(status $P1 $J /)" 503

echo "== E. Expiry and replay"
N=$(page $P1 $J / | nonce_of); C=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$N")
sleep 4
eq "E1 expired nonce (older than nonce_ttl) -> 403" "$(solve "$N" $P1 $J "$C")" 403
N=$(page $P1 $J / | nonce_of); C=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$N")
eq "E2 fresh nonce, correct proof -> 204" "$(solve "$N" $P1 $J "$C")" 204
eq "E3 solving clears the switch: access granted -> 200" "$(status $P1 $J /)" 200
eq "E4 replay of the same nonce -> 403" "$(solve "$N" $P1 $J "$C")" 403
eq "E5 the switch is spent: 200 again" "$(status $P1 $J /)" 200

echo "== F. Forged or expired switch cookie is ignored"
J3="$WORK/f.jar"
N=$(page $P1 $J3 / | nonce_of); solve "$N" $P1 $J3 >/dev/null
eq "F1 forged cookie value -> 200" "$(code -b "$J3" -b '_gvt=9999999999.deadbeef' "$B1/")" 200
EXP=$(( $(date +%s) - 10 ))
eq "F2 unsigned expired cookie -> 200" "$(code -b "$J3" -b "_gvt=$EXP.deadbeef" "$B1/")" 200

echo "== G. Switch is off while test_key is empty"
J4="$WORK/g.jar"
N=$(page $P3 $J4 / | nonce_of); solve "$N" $P3 $J4 >/dev/null
eq "G1 key ignored when disabled -> 200" "$(status $P3 $J4 "/?gv_test=$KEY")" 200
eq "G2 no switch cookie was set -> 200" "$(status $P3 $J4 /)" 200

echo "== H. Monitor mode (challenge not enforced): the tester still sees the page, others never do"
J5="$WORK/h.jar"; J6="$WORK/h2.jar"
eq "H1 visitor without token is NOT challenged in monitor mode" "$(status $P2 $J6 /)" 200
eq "H2 right key -> 302" "$(code -b $J5 -c $J5 "http://127.0.0.1:$P2/?gv_test=$KEY")" 302
eq "H3 tester gets the challenge page" "$(status $P2 $J5 /)" 503
N=$(page $P2 $J5 / | nonce_of)
eq "H4 solve -> 204" "$(solve "$N" $P2 $J5)" 204
eq "H5 afterwards -> 200" "$(status $P2 $J5 /)" 200
eq "H6 other visitor still never challenged" "$(status $P2 $J6 /)" 200

echo "== I. Logging"
n=$(cat "$WORK"/enf/logs/guard-*.jsonl | grep -c '"TEST"')
ok "I1 test challenges are logged with reason TEST ($n rows)" "$([ "$n" -ge 1 ] && echo 1 || echo 0)"

echo
echo "PASS $PASS  FAIL $FAIL"
[ "$FAIL" -eq 0 ]
