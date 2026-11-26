#!/usr/bin/env bash
# Bot Guard access-rules end-to-end test.
#
#   bash scripts/rules-e2e.sh
#
# Starts a throw-away PHP built-in server with the guard prepended, a private
# Redis and a temporary guard/rules.json (GV_RULES), and drives the real
# request flow with curl: block / challenge / log / monitor, and the whole
# precedence chain (exempt path, kill switch, allow override, verified bot,
# unverified and refuted bot, preview fetcher, holdout, expiry).
# The servers run with OPcache off: the built-in server uses opcache.enable (not enable_cli) and revalidates a file only every
# revalidate_freq (2) seconds, so a rules.json or cache rewritten within two seconds of a request was served stale and the test
# raced; production has the same delay unless validate_timestamps is on (docs/06).
# Every enforce toggle is OFF in this server on purpose: rule actions must not
# depend on enforce.block / enforce.challenge.
# GeoIP: a country.bin built by analyzer/geo.py maps 127.0.0.0/8 to US and 5.0.0.0/8 to IR; the
# client address is 127.0.0.1 (US), or 5.x / 9.x through X-Forwarded-For (cdn_ranges trusts the
# loopback proxy here) for an IR and an unplaced visitor.
# IP lists: allow/block lists compiled by analyzer/iplist.py (the worker's compiler) into $WORK/lists; the whole
# precedence chain (allow beats rules and the operator deny, block beats the known-bot pass, both = allow wins
# with the panel warning, kill switch and exempt paths unchanged, no Redis work, broken files fail open).
# CAPTCHA: the image CAPTCHA (rule action `captcha`) end to end - the answer is found by brute force with
# scripts/captcha-solve.php (the nonce carries only an HMAC of it) and the proof of work with scripts/pow-solve.php;
# a second server (enforce.challenge, ratelimit, low device budget, escalation) and a third with GD "missing".
# Needs: php (8.0+), python3 (stdlib only), curl, redis-server. Touches nothing outside a temp dir
# (the kill-switch case creates and removes guard.off in the project root).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHP_BIN="${GV_PHP:-php}"
export PHP_CLI_SERVER_WORKERS="${PHP_CLI_SERVER_WORKERS:-4}"
PORT="${RULES_E2E_PORT:-8131}"
RPORT="${RULES_E2E_REDIS_PORT:-6393}"
WORK="$(mktemp -d)"
RULES="$WORK/rules.json"
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
GBOT='Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'

for need in "$PHP_BIN" python3 curl redis-server redis-cli; do
	command -v "$need" >/dev/null 2>&1 || { echo "ERROR: '$need' is required." >&2; exit 2; }
done

# An operator's own kill switch is put aside while the cases run and put back at the end (it used to be deleted by the cases and the cleanup).
SAVED_OFF=""
if [ -e "$ROOT/guard.off" ]; then SAVED_OFF="$ROOT/guard.off.saved-$$"; mv "$ROOT/guard.off" "$SAVED_OFF"; fi
PIDS=()
cleanup() {
	for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
	rm -f "$ROOT/guard.off"
	[ -z "$SAVED_OFF" ] || mv "$SAVED_OFF" "$ROOT/guard.off"
	rm -rf "$WORK"
}
trap cleanup EXIT

R() { redis-cli -p "$RPORT" "$@" >/dev/null; }

# A holdout salt that puts 127.0.0.1 INSIDE the 5% holdout (to prove a rule is
# never suppressed by it).
SALT=$("$PHP_BIN" -r 'define("GV_BOOT",1); define("GV_NO_AUTORUN",1); require $argv[1]."/guard/guard.php";
	for ($i = 0; $i < 100000; $i++) { if (gv_is_holdout("127.0.0.1", "s$i", 5)) { echo "s$i"; break; } }' "$ROOT")

mkdir -p "$WORK/logs" "$WORK/geo" "$WORK/lists"
# Test fixture only: the ranges are written with the real compiler's file format.
python3 -I - "$ROOT" "$WORK/geo/country.bin" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from analyzer import geo
def net(cidr, cc):
    import ipaddress
    n = ipaddress.ip_network(cidr)
    return (int(n.network_address), int(n.broadcast_address), cc)
v4 = geo.normalize([net('127.0.0.0/8', 'US'), net('5.0.0.0/8', 'IR')])
open(sys.argv[2], 'wb').write(geo.pack(geo.KIND_COUNTRY, v4, [], 1700000000, 'e2e-fixture', ''))
PY
cat > "$WORK/config.php" <<CFG
<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }
\$c = require '$ROOT/scripts/config.dev.php';
\$c['enforce'] = array('block' => false, 'challenge' => false, 'ratelimit' => false);
\$c['signals'] = array('reputation' => false, 'ml' => false, 'clf' => false);
\$c['redis']['port'] = $RPORT;
\$c['log_dir'] = '$WORK/logs';
\$c['holdout_pct'] = 5;
\$c['holdout_salt'] = '$SALT';
\$c['capture_outcomes'] = false;
\$c['cdn_ranges'] = array('127.0.0.1/32');
if (is_file('$WORK/geolog.on')) { \$c['geo'] = array('log' => true); }
\$c['challenge'] = array('pow_bits' => 12, 'bind_ip' => true);
\$c['captcha'] = array('level' => 1, 'max_attempts' => 3, 'ip_budget' => 8, 'ip_window' => 600, 'escalate_score' => 60);
\$c['limits'] = array_merge(\$c['limits'], array('window' => 60, 'device' => 100000, 'ip_ua' => 100000, 'ip' => 100000, 'mint' => 100000, 'bot' => 100000, 'preview' => 100000));
return \$c;
CFG

# rule ID NAME MODE ACTION JSON_UA_VALUES [extra json fields]
rule() {
	printf '{"id":"%s","name":"%s","enabled":true,"mode":"%s","action":"%s","priority":%s,"skip_verified_bots":%s,"ua":{"op":"include","type":"contains","values":%s},"path":null,"expires_at":%s,"pow_bits":%s,"note":"","created_by":"","created_at":0,"updated_at":0}' \
		"$1" "$2" "$3" "$4" "${PRI:-100}" "${SKIP:-true}" "$5" "${EXP:-0}" "${POW:-0}"
}
# grule ID NAME MODE ACTION OP CC_JSON [UA_JSON]  (a country rule, optionally with a UA condition)
grule() {
	local ua=null
	[ -n "${7:-}" ] && ua="{\"op\":\"include\",\"type\":\"contains\",\"values\":$7}"
	printf '{"id":"%s","name":"%s","enabled":true,"mode":"%s","action":"%s","priority":%s,"skip_verified_bots":%s,"ua":%s,"path":null,"country":{"op":"%s","type":"code","values":%s},"expires_at":0,"pow_bits":0,"note":"","created_by":"","created_at":0,"updated_at":0}' \
		"$1" "$2" "$3" "$4" "${PRI:-100}" "${SKIP:-true}" "$ua" "$5" "$6"
}
# Writes rules.json AND the generated cache the way the panel does, so the fast path is the one under test.
write_rules() {
	printf '{"rules":[%s]}' "$(IFS=,; echo "$*")" > "$RULES"
	"$PHP_BIN" -r 'define("GV_BOOT", 1); define("GV_NO_AUTORUN", 1); require $argv[1]."/guard/guard.php";
		file_put_contents($argv[2], gv_rules_cache_source(gv_rules_read($argv[3])));' "$ROOT" "$WORK/rules.cache.php" "$RULES"
}


# ilist ID IDX TYPE MODE ENABLED CIDR...  -> one list (record + source; FORCE=true sets the list's force flag: the compile
# drops loopback / private entries of a block list otherwise); lists_compile writes lists.json and runs the
# worker's compiler (analyzer/iplist.py), exactly what the panel's job does for a big list.
ILS=()
ilist() {
	local id=$1 idx=$2 type=$3 mode=$4 en=$5; shift 5
	ILS+=("{\"id\":\"$id\",\"idx\":$idx,\"name\":\"$id\",\"type\":\"$type\",\"mode\":\"$mode\",\"enabled\":$en,\"force\":${FORCE:-false},\"note\":\"\",\"created_by\":\"\",\"created_at\":0,\"updated_at\":0}")
	printf '%s\n' "$@" > "$WORK/lists/$id.txt"
}
lists_compile() {
	printf '{"v":1,"next_idx":99,"lists":[%s]}' "$(IFS=,; echo "${ILS[*]:-}")" > "$WORK/lists/lists.json"
	if [ -n "${LC_NOW:-}" ]; then
		# compile as of an earlier time (the entries that have since expired are still live then)
		python3 -I - "$ROOT" "$WORK/lists" "$LC_NOW" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from analyzer import iplist
iplist.compile_lists(sys.argv[2], now=int(sys.argv[3]))
PY
	else
		python3 -I "$ROOT/analyzer/iplist.py" --dir "$WORK/lists" >/dev/null 2>&1
	fi
	ILS=()
}

redis-server --port "$RPORT" --save "" --appendonly no --dir "$WORK" >"$WORK/redis.log" 2>&1 &
PIDS+=($!)
sleep 0.3
write_rules
GV_GEO_DIR="$WORK/geo" GV_LISTS_DIR="$WORK/lists" GV_RULES="$RULES" GV_DEV_CONFIG="$WORK/config.php" "$PHP_BIN" -d opcache.enable=0 -S "127.0.0.1:$PORT" "$ROOT/scripts/dev-router.php" >"$WORK/php.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/t/404" 2>/dev/null && break; sleep 0.1; done
# Second server: enforce.challenge and ratelimit ON, a low hourly device budget, CAPTCHA instead of the device 429.
PORT2=$((PORT + 1)); PORT3=$((PORT + 2))
cat > "$WORK/config2.php" <<CFG
<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }
\$c = require '$WORK/config.php';
\$c['enforce'] = array('block' => false, 'challenge' => true, 'ratelimit' => true);
\$c['limits']['device_hour'] = 3;
\$c['holdout_pct'] = 0;                    // 127.0.0.1 is in the holdout of the first server: here the built-in rules are enforced
\$c['captcha']['device_budget'] = true;
return \$c;
CFG
GV_GEO_DIR="$WORK/geo" GV_LISTS_DIR="$WORK/lists" GV_RULES="$RULES" GV_DEV_CONFIG="$WORK/config2.php" "$PHP_BIN" -d opcache.enable=0 -S "127.0.0.1:$PORT2" "$ROOT/scripts/dev-router.php" >"$WORK/php2.log" 2>&1 &
PIDS+=($!)
# Third server: the same config as the first, but GD "missing" (GV_CAPTCHA_NO_GD): a captcha rule falls back to the PoW challenge.
GV_CAPTCHA_NO_GD=1 GV_GEO_DIR="$WORK/geo" GV_LISTS_DIR="$WORK/lists" GV_RULES="$RULES" GV_DEV_CONFIG="$WORK/config.php" "$PHP_BIN" -d opcache.enable=0 -S "127.0.0.1:$PORT3" "$ROOT/scripts/dev-router.php" >"$WORK/php3.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT2/t/404" 2>/dev/null && curl -s -o /dev/null "http://127.0.0.1:$PORT3/t/404" 2>/dev/null && break; sleep 0.1; done

PASS=0; FAIL=0
ok() { if [ "$2" = "1" ]; then PASS=$((PASS + 1)); echo "PASS  $1"; else FAIL=$((FAIL + 1)); echo "FAIL  $1"; fi; }
eq() { [ "$2" = "$3" ] && ok "$1" 1 || ok "$1 (got '$2', want '$3')" 0; }

# get UA PATH [curl args] -> status. Browser-like headers keep the score at 0.
get() {
	local ua="$1" path="$2"; shift 2
	curl -s -o /dev/null -w '%{http_code}' -H "User-Agent: $ua" -H 'Accept: text/html' \
		-H 'Accept-Language: en-US,en;q=0.9' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: none' \
		"$@" "http://127.0.0.1:$PORT$path"
}
body() {
	local ua="$1" path="$2"; shift 2
	curl -s -H "User-Agent: $ua" -H 'Accept: text/html' -H 'Accept-Language: en-US,en;q=0.9' \
		-H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: none' "$@" "http://127.0.0.1:$PORT$path"
}
last_row() { tail -1 "$WORK"/logs/guard-*.jsonl; }
rows() { cat "$WORK"/logs/guard-*.jsonl 2>/dev/null | wc -l | tr -d ' '; }
has() { last_row | grep -q "$1"; }

echo "== A. no rule file content: nothing changes"
eq "A1 a browser is served" "$(get "$UA" /a1)" 200
eq "A2 curl is served (no rules)" "$(get 'curl/8.0' /a2)" 200

echo "== B. block / log / monitor (enforce.* are all off)"
write_rules "$(rule r-evil Evil enforce block '["evilbot"]')" \
	"$(rule r-watch Watch monitor block '["watchbot"]')" \
	"$(rule r-note Note enforce log '["notebot"]')"
eq "B1 enforced block rule -> 403 although enforce.block is off" "$(get 'x evilbot/1' /b1)" 403
has '"RULE:r-evil"'; ok "B2 the row carries RULE:r-evil" "$([ $? -eq 0 ] && echo 1 || echo 0)"
has '"act":"403"'; ok "B3 the row says act 403, sh 0" "$([ $? -eq 0 ] && has '"sh":0' && echo 1 || echo 0)"
eq "B4 the same UA in another case -> 403" "$(get 'X EVILBOT/2' /b4)" 403
eq "B5 a monitor rule never acts" "$(get 'x watchbot' /b5)" 200
has '"SH_RULE:r-watch"'; ok "B6 monitor row carries SH_RULE:r-watch" "$([ $? -eq 0 ] && echo 1 || echo 0)"
eq "B7 a log rule never acts" "$(get 'x notebot' /b7)" 200
has '"RULE:r-note"'; ok "B8 log row carries RULE:r-note" "$([ $? -eq 0 ] && echo 1 || echo 0)"
before=$(rows); get 'x evilbot' /b9 >/dev/null
eq "B9 exactly one log row per request" "$(( $(rows) - before ))" 1
eq "B10 a clean browser is unaffected" "$(get "$UA" /b10)" 200

echo "== C. rule changes apply at once (file read per request), first match by priority"
PRI=20 write_rules "$(rule r-late Late enforce block '["evilbot"]')" \
	"$(PRI=10 rule r-first First monitor block '["evilbot"]')"
eq "C1 the lower priority number runs first: monitor wins, request served" "$(get 'x evilbot' /c1)" 200
has '"SH_RULE:r-first"'; ok "C2 only the first matching rule is reported" "$([ $? -eq 0 ] && ! has 'r-late' && echo 1 || echo 0)"
write_rules "$(EXP=1 rule r-old Old enforce block '["evilbot"]')"
eq "C3 an expired rule is ignored" "$(get 'x evilbot' /c3)" 200
printf 'not json' > "$RULES"
touch -d '+5 seconds' "$RULES"
eq "C4 an invalid rules file (newer than the cache) means no rules" "$(get 'x evilbot' /c4)" 200
has 'x'; ok "C5 ...and the stale cache is reported once in guard-errors.log" "$([ "$(grep -c rules_cache_stale "$WORK/logs/guard-errors.log" 2>/dev/null)" = 1 ] && echo 1 || echo 0)"
rule_stale=$(rule r-hand Hand enforce block '["handbot"]')
printf '{"rules":[%s]}' "$rule_stale" > "$RULES"
touch -d '+10 seconds' "$RULES"
eq "C6 a hand-edited rules.json newer than the cache is used directly" "$(get 'x handbot' /c6)" 403
write_rules
touch -d '+20 seconds' "$WORK/rules.cache.php"

echo "== D. challenge: needs a token, solving it ends the loop"
write_rules "$(rule r-chal Chal enforce challenge '["chalbot"]')"
J="$WORK/d.jar"
eq "D1 no token -> challenge page 503 (enforce.challenge is off)" "$(get 'x chalbot' /d1 -b "$J" -c "$J")" 503
N=$(body 'x chalbot' /d2 -b "$J" -c "$J" | sed -n "s/.*var N = '\([^']*\)'.*/\1/p" | head -1)
ok "D2 the page carries a nonce" "$([ -n "$N" ] && echo 1 || echo 0)"
C=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$N")
eq "D3 solving it gives 204" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'User-Agent: x chalbot' -H "X-GV: $N" -H "X-GV-P: $C" -b "$J" -c "$J" "http://127.0.0.1:$PORT/")" 204
eq "D4 with the token the request passes: no endless loop" "$(get 'x chalbot' /d4 -b "$J" -c "$J")" 200
eq "D5 and again" "$(get 'x chalbot' /d5 -b "$J" -c "$J")" 200
eq "D6 a token-less POST is not challenged (gate_post off)" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'User-Agent: x chalbot' -d a=1 "http://127.0.0.1:$PORT/d6")" 200
has '"act":"challenge"'; ok "D7 ...it is logged as a shadow challenge (sh 1)" "$([ $? -eq 0 ] && has '"sh":1' && echo 1 || echo 0)"
write_rules "$(POW=20 rule r-chal Chal enforce challenge '["chalbot"]')"
N2=$(body 'x chalbot' /d8 | sed -n "s/.*var N = '\([^']*\)'.*/\1/p" | head -1)
ok "D8 the rule's pow_bits (20) is carried by the nonce" "$(echo "$N2" | grep -q '\.20\.' && echo 1 || echo 0)"

echo "== E. precedence"
write_rules "$(rule r-evil Evil enforce block '["evilbot"]')"
eq "E1 exempt path bypasses rules" "$(get 'x evilbot' /exempt-me)" 200
touch "$ROOT/guard.off"
eq "E2 kill switch bypasses rules" "$(get 'x evilbot' /e2)" 200
rm -f "$ROOT/guard.off"
eq "E3 without the kill switch the rule acts again" "$(get 'x evilbot' /e3)" 403
R set "gv:allow:127.0.0.1" 1 EX 60
eq "E4 an operator allow override beats the rule" "$(get 'x evilbot' /e4)" 200
has '"act":"allow_override"'; ok "E5 ...logged as allow_override, no rule reason" "$([ $? -eq 0 ] && ! has 'RULE:' && echo 1 || echo 0)"
R del "gv:allow:127.0.0.1"

write_rules "$(rule r-gbot GBot enforce block '["googlebot"]')"
R set "gv:botok:127.0.0.1" 1 EX 60
eq "E6 verified crawler skips a rule (skip_verified_bots)" "$(get "$GBOT" /e6)" 200
has '"act":"allow_bot"'; ok "E7 ...and takes the normal bot pass" "$([ $? -eq 0 ] && echo 1 || echo 0)"
write_rules "$(SKIP=false rule r-gbot GBot enforce block '["googlebot"]')"
eq "E8 skip_verified_bots=false: a verified crawler is blocked" "$(get "$GBOT" /e8)" 403
write_rules "$(rule r-gbot GBot enforce block '["googlebot"]')"
R del "gv:botok:127.0.0.1"
eq "E9 an UNVERIFIED crawler claim is NOT skipped" "$(get "$GBOT" /e9)" 403
R set "gv:botbad:127.0.0.1" 1 EX 60
eq "E10 a REFUTED crawler claim is NOT skipped" "$(get "$GBOT" /e10)" 403
R del "gv:botbad:127.0.0.1"
write_rules "$(rule r-gbot GBot monitor block '["googlebot"]')"
eq "E11 a monitor rule leaves the unverified bot pass alone" "$(get "$GBOT" /e11)" 200
has '"act":"allow_bot"'; ok "E12 ...the bot row carries SH_RULE too" "$([ $? -eq 0 ] && has '"SH_RULE:r-gbot"' && echo 1 || echo 0)"
write_rules "$(rule r-tg TG enforce block '["telegrambot"]')"
eq "E13 an enforced rule replaces the link-preview pass" "$(get 'TelegramBot (like TwitterBot)' /e13)" 403
write_rules
eq "E14 without the rule the preview pass applies" "$(get 'TelegramBot (like TwitterBot)' /e14)" 200

echo "== F. holdout never suppresses a rule (127.0.0.1 is in the holdout here)"
write_rules "$(rule r-evil Evil enforce block '["evilbot"]')" "$(rule r-chal Chal enforce challenge '["chalbot"]')"
eq "F1 a held-out client is still blocked by the rule" "$(get 'x evilbot' /f1)" 403
has '"hold":1'; ok "F2 ...and the row says it is in the holdout" "$([ $? -eq 0 ] && echo 1 || echo 0)"
eq "F3 a held-out client is still challenged by the rule" "$(get 'x chalbot' /f3)" 503

echo "== H. GeoIP: country rules (client 127.0.0.1 is US; XFF 5.x is IR; XFF 9.x is not in the table)"
R flushall
eq "H0 an IR address through the trusted proxy resolves (no rule yet: served)" "$(get "$UA" /h0 -H 'X-Forwarded-For: 5.1.2.3')" 200
write_rules "$(grule r-us US enforce block include '["US"]')"
eq "H1 include US -> a US client is blocked, although enforce.block is off" "$(get "$UA" /h1)" 403
has '"RULE:r-us"'; ok "H2 the row carries RULE:r-us and the country" "$([ $? -eq 0 ] && has '"cc":"US"' && echo 1 || echo 0)"
eq "H3 an IR client is not touched by include US" "$(get "$UA" /h3 -H 'X-Forwarded-For: 5.1.2.3')" 200
has '"cc":"IR"'; ok "H4 ...and its row carries cc IR (the lookup ran because a rule needed it)" "$([ $? -eq 0 ] && ! has 'RULE:' && echo 1 || echo 0)"
write_rules "$(grule r-noir NotIR enforce block exclude '["IR"]')"
eq "H5 exclude IR -> a US client is blocked" "$(get "$UA" /h5)" 403
eq "H6 exclude IR -> an IR client is served" "$(get "$UA" /h6 -H 'X-Forwarded-For: 5.1.2.3')" 200
eq "H7 exclude IR -> a client with an UNKNOWN country is NOT blocked" "$(get "$UA" /h7 -H 'X-Forwarded-For: 9.9.9.9')" 200
has '"cc":""'; ok "H8 ...its row says the lookup ran and found nothing (cc is empty)" "$([ $? -eq 0 ] && ! has 'RULE:' && echo 1 || echo 0)"
write_rules "$(grule r-ir IR enforce block include '["IR"]')"
eq "H9 include IR -> an unknown country is not blocked either" "$(get "$UA" /h9 -H 'X-Forwarded-For: 9.9.9.9')" 200
eq "H10 include IR -> an IR client is blocked" "$(get "$UA" /h10 -H 'X-Forwarded-For: 5.1.2.3')" 403
write_rules "$(grule r-mon US monitor block include '["US"]')"
eq "H11 a monitor country rule never acts" "$(get "$UA" /h11)" 200
has '"SH_RULE:r-mon"'; ok "H12 ...and is logged as SH_RULE" "$([ $? -eq 0 ] && echo 1 || echo 0)"
write_rules "$(grule r-combo Combo enforce block include '["US"]' '["scraperx"]')"
eq "H13 UA + country: a matching UA from the country is blocked" "$(get 'x scraperx/1' /h13)" 403
eq "H14 UA + country: the same UA from another country is served" "$(get 'x scraperx/1' /h14 -H 'X-Forwarded-For: 5.1.2.3')" 200
eq "H15 UA + country: another UA from the country is served" "$(get "$UA" /h15)" 200
write_rules "$(grule r-chal Chal enforce challenge include '["US"]')"
J="$WORK/h.jar"
eq "H16 a country challenge rule: no token -> challenge page" "$(get "$UA" /h16 -b "$J" -c "$J")" 503
N=$(body "$UA" /h17 -b "$J" -c "$J" | sed -n "s/.*var N = '\([^']*\)'.*/\1/p" | head -1)
C=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$N")
eq "H17 solving it gives 204" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "User-Agent: $UA" -H "X-GV: $N" -H "X-GV-P: $C" -b "$J" -c "$J" "http://127.0.0.1:$PORT/")" 204
eq "H18 with the token the request passes: no endless loop" "$(get "$UA" /h18 -b "$J" -c "$J")" 200
eq "H19 and again" "$(get "$UA" /h19 -b "$J" -c "$J")" 200

echo "== I. GeoIP precedence and the request path"
write_rules "$(grule r-us US enforce block include '["US"]')"
R set "gv:allow:127.0.0.1" 1 EX 60
eq "I1 an operator allow override beats a country rule" "$(get "$UA" /i1)" 200
R del "gv:allow:127.0.0.1"
R set "gv:botok:127.0.0.1" 1 EX 60
eq "I3 a VERIFIED crawler from a US address skips the country rule" "$(get "$GBOT" /i3)" 200
has '"act":"allow_bot"'; ok "I4 ...and takes the normal bot pass" "$([ $? -eq 0 ] && echo 1 || echo 0)"
write_rules "$(SKIP=false grule r-us US enforce block include '["US"]')"
eq "I5 skip_verified_bots=false: the verified crawler is blocked by country" "$(get "$GBOT" /i5)" 403
write_rules "$(grule r-us US enforce block include '["US"]')"
R del "gv:botok:127.0.0.1"
eq "I6 an UNVERIFIED crawler claim from a US address is NOT skipped" "$(get "$GBOT" /i6)" 403
R set "gv:botbad:127.0.0.1" 1 EX 60
eq "I7 a REFUTED crawler claim is NOT skipped" "$(get "$GBOT" /i7)" 403
R del "gv:botbad:127.0.0.1"
eq "I8 an exempt path bypasses a country rule" "$(get "$UA" /exempt-me)" 200
touch "$ROOT/guard.off"
eq "I9 the kill switch bypasses a country rule" "$(get "$UA" /i9)" 200
rm -f "$ROOT/guard.off"
eq "I10 a held-out client (the holdout covers 127.0.0.1) is still blocked by a country rule" "$(get "$UA" /i10)" 403
has '"hold":1'; ok "I11 ...and the row says it is in the holdout" "$([ $? -eq 0 ] && echo 1 || echo 0)"
before=$(rows); get "$UA" /i12 >/dev/null
eq "I12 exactly one log row per request" "$(( $(rows) - before ))" 1

# No extra Redis work: the same request costs the same number of Redis commands with 200 country rules.
cmds() { redis-cli -p "$RPORT" info stats | sed -n 's/^total_commands_processed:\([0-9]*\).*/\1/p' | tr -d '\r'; }
write_rules "$(grule r-never Never enforce block include '["KP"]')"
a=$(cmds); get "$UA" /i13 >/dev/null; b=$(cmds)
many=""; for i in $(seq 1 200); do many="$many$(PRI=$((100 + i)) grule "r-n$i" "N$i" enforce block include '["KP","CU","SY"]'),"; done
write_rules ${many%,}
c=$(cmds); get "$UA" /i14 >/dev/null; d=$(cmds)
eq "I13 200 non-matching country rules add no Redis command (no extra round trip)" "$(( d - c ))" "$(( b - a ))"

echo "== J. GeoIP logging and a broken database"
write_rules
get "$UA" /j1 >/dev/null
has '"cc"'; ok "J1 no geo rule and geo.log off: the row has no cc (the file is never opened)" "$([ $? -ne 0 ] && echo 1 || echo 0)"
touch "$WORK/geolog.on"
get "$UA" /j2 >/dev/null
has '"cc":"US"'; ok "J2 geo.log on: the row carries the country without any rule" "$([ $? -eq 0 ] && echo 1 || echo 0)"
get "$UA" /j3 -H 'X-Forwarded-For: 9.9.9.9' >/dev/null
has '"cc":""'; ok "J3 geo.log on: an unplaced address is logged with an empty country" "$([ $? -eq 0 ] && echo 1 || echo 0)"
rm -f "$WORK/geolog.on"
write_rules "$(grule r-noir NotIR enforce block exclude '["IR"]')"
mv "$WORK/geo/country.bin" "$WORK/geo/country.bin.keep"
eq "J4 database missing: a country rule never matches and the request is served" "$(get "$UA" /j4)" 200
ok "J5 ...and the missing file is reported in guard-errors.log" "$(grep -q geo_missing "$WORK/logs/guard-errors.log" 2>/dev/null && echo 1 || echo 0)"
printf 'GVRGgarbage' > "$WORK/geo/country.bin"
eq "J6 database corrupt: served, never a 500" "$(get "$UA" /j6)" 200
ok "J7 ...and reported as corrupt" "$(grep -q geo_corrupt "$WORK/logs/guard-errors.log" 2>/dev/null && echo 1 || echo 0)"
mv "$WORK/geo/country.bin.keep" "$WORK/geo/country.bin"
eq "J8 the database back: the rule acts again" "$(get "$UA" /j8)" 403

echo "== L. IP lists: block, allow, monitor and the whole precedence chain (the rules, bots and Redis keys are the ones above)"
R flushall
cmds() { redis-cli -p "$RPORT" info stats | sed -n 's/^total_commands_processed:\([0-9]*\).*/\1/p' | tr -d '\r'; }
write_rules
x=$(cmds); idle=$(( $(cmds) - x ))          # what two back-to-back INFO calls count by themselves
eq "L0 no list files: a request is served and the row has no list reason" "$(get "$UA" /l0)" 200
has 'IPL_'; ok "L0b ...no IPL reason" "$([ $? -ne 0 ] && echo 1 || echo 0)"
ilist scrapers 1 block enforce true 203.0.113.0/24 2001:db8::/32 '# comment' 198.51.100.7
lists_compile
eq "L1 an enforced block list refuses a listed address with 403 although enforce.block is off" "$(get "$UA" /l1 -H 'X-Forwarded-For: 203.0.113.9')" 403
has '"IPL_BLOCK:scrapers"'; ok "L2 the row carries IPL_BLOCK:scrapers, act 403, sh 0" "$([ $? -eq 0 ] && has '"act":"403"' && has '"sh":0' && echo 1 || echo 0)"
eq "L3 an address outside the list is served" "$(get "$UA" /l3 -H 'X-Forwarded-For: 203.0.114.9')" 200
eq "L4 a single-address entry and an IPv6 range both match" "$(get "$UA" /l4 -H 'X-Forwarded-For: 198.51.100.7')$(get "$UA" /l4b -H 'X-Forwarded-For: 2001:db8::5')" 403403
eq "L5 the neighbour of a single-address entry is served" "$(get "$UA" /l5 -H 'X-Forwarded-For: 198.51.100.8')" 200
before=$(rows); get "$UA" /l6 -H 'X-Forwarded-For: 203.0.113.9' >/dev/null
eq "L6 exactly one log row per refused request" "$(( $(rows) - before ))" 1
a=$(cmds); get "$UA" /l7 -H 'X-Forwarded-For: 203.0.113.9' >/dev/null; b=$(cmds)
eq "L7 a block-listed request costs ZERO Redis commands" "$(( b - a ))" "$idle"
# no extra Redis round trip for a request the list does not touch: same commands as with no list at all
a=$(cmds); get "$UA" /l8 -H 'X-Forwarded-For: 192.0.2.77' >/dev/null; b=$(cmds)
ilist none 1 block enforce false 1.2.3.4; lists_compile
c=$(cmds); get "$UA" /l8b -H 'X-Forwarded-For: 192.0.2.77' >/dev/null; d=$(cmds)
eq "L8 an unlisted request costs the same Redis commands with an enabled list as with none" "$(( b - a ))" "$(( d - c ))"
ls "$WORK/lists/block.bin" >/dev/null 2>&1; ok "L9 with no enabled list the compiled file is gone: the guard opens nothing" "$([ $? -ne 0 ] && echo 1 || echo 0)"
ilist scrapers 1 block enforce true 203.0.113.0/24 2001:db8::/32 198.51.100.7
lists_compile

echo "-- L: block list vs the known-bot pass"
R set "gv:botok:203.0.113.9" 1 EX 60
eq "L10 a block list beats the known-bot pass: a VERIFIED Googlebot address on the list is refused" "$(get "$GBOT" /l10 -H 'X-Forwarded-For: 203.0.113.9')" 403
R del "gv:botok:203.0.113.9"
eq "L11 a Googlebot CLAIM from a listed address is refused too" "$(get "$GBOT" /l11 -H 'X-Forwarded-For: 203.0.113.10')" 403
eq "L12 the same claim from an unlisted address still takes the bot pass" "$(get "$GBOT" /l12 -H 'X-Forwarded-For: 203.0.114.10')" 200
has '"act":"allow_bot"'; ok "L13 ...as allow_bot" "$([ $? -eq 0 ] && echo 1 || echo 0)"
eq "L14 a link-preview fetcher from a listed address is refused (the preview pass is behind the list)" "$(get 'TelegramBot (like TwitterBot)' /l14 -H 'X-Forwarded-For: 203.0.113.11')" 403

echo "-- L: monitor lists never act"
ilist scrapers 1 block monitor true 203.0.113.0/24
lists_compile
eq "L15 a monitor block list serves the request" "$(get "$UA" /l15 -H 'X-Forwarded-For: 203.0.113.9')" 200
has '"SH_IPL_BLOCK:scrapers"'; ok "L16 ...and logs SH_IPL_BLOCK:scrapers" "$([ $? -eq 0 ] && echo 1 || echo 0)"
ilist scrapers 1 block monitor true 203.0.113.0/24
ilist hard 2 block enforce true 203.0.113.0/24
lists_compile
eq "L17 where a monitor and an enforced list overlap, the enforced list acts" "$(get "$UA" /l17 -H 'X-Forwarded-For: 203.0.113.9')" 403
has '"IPL_BLOCK:hard"'; ok "L18 ...and the row names the enforced list" "$([ $? -eq 0 ] && echo 1 || echo 0)"

echo "-- L: allow list beats rules, scoring, challenge and the operator deny"
ilist partners 1 allow enforce true 127.0.0.1 198.51.100.0/25
lists_compile
write_rules "$(rule r-evil Evil enforce block '["evilbot"]')" "$(rule r-chal Chal enforce challenge '["chalbot"]')"
eq "L19 an allow list beats an enforced block rule" "$(get 'x evilbot' /l19)" 200
has '"act":"allow_override"'; ok "L20 ...logged as allow_override with IPL_ALLOW:partners and no RULE reason" "$([ $? -eq 0 ] && has '"IPL_ALLOW:partners"' && ! has 'RULE:' && echo 1 || echo 0)"
eq "L21 an allow list beats an enforced challenge rule (no challenge page, no token needed)" "$(get 'x chalbot' /l21)" 200
R set "gv:deny:127.0.0.1" 1 EX 60
eq "L22 an allow list beats an operator DENY override (an allow override beats a deny too)" "$(get 'x evilbot' /l22)" 200
R del "gv:deny:127.0.0.1"
a=$(cmds); get 'x evilbot' /l23 >/dev/null; b=$(cmds)
eq "L23 an allow-listed request costs ZERO Redis commands" "$(( b - a ))" "$idle"
eq "L24 an allow list beats the known-bot unverified budget and a fake-bot claim (no Redis verdict is read)" "$(get "$GBOT" /l24)" 200
has '"act":"allow_override"'; ok "L25 ...as allow_override, not allow_bot" "$([ $? -eq 0 ] && echo 1 || echo 0)"
eq "L26 an address outside the allow list is judged as before (the rule blocks it)" "$(get 'x evilbot' /l26 -H 'X-Forwarded-For: 203.0.114.200')" 403
eq "L27 an allow list holding an IPv4 range matches through the proxy header too" "$(get 'x evilbot' /l27 -H 'X-Forwarded-For: 198.51.100.100')" 200
ilist partners 1 allow monitor true 127.0.0.1
lists_compile
eq "L28 a MONITOR allow list does not skip anything: the rule still blocks" "$(get 'x evilbot' /l28)" 403
has '"SH_IPL_ALLOW:partners"'; ok "L29 ...and the row carries SH_IPL_ALLOW:partners next to the rule" "$([ $? -eq 0 ] && has '"RULE:r-evil"' && echo 1 || echo 0)"

echo "-- L: an address in both lists: the allow list wins (and the panel warns)"
ilist partners 1 allow enforce true 203.0.113.64/26
ilist scrapers 2 block enforce true 203.0.113.0/24
lists_compile
eq "L30 in both lists: allowed" "$(get "$UA" /l30 -H 'X-Forwarded-For: 203.0.113.70')" 200
has '"IPL_ALLOW:partners"'; ok "L31 ...as allow_override" "$([ $? -eq 0 ] && has '"allow_override"' && ! has 'IPL_BLOCK' && echo 1 || echo 0)"
eq "L32 the rest of the block range is still refused" "$(get "$UA" /l32 -H 'X-Forwarded-For: 203.0.113.5')" 403
warn=$(GV_LISTS_DIR="$WORK/lists" GV_GEO_DIR="$WORK/geo" "$PHP_BIN" -r 'define("GV_BOOT", 1); define("GV_NO_AUTORUN", 1); define("GP_BOOT", 1); $r = $argv[1];
	require $r . "/guard/guard.php"; require $r . "/panel/config_io.php"; require $r . "/panel/jobs.php"; require $r . "/panel/iplists.php";
	foreach (gp_iplists_warnings(gp_iplists_state()["lists"]) as $w) { echo $w[0], " ", $w[1], "\n"; }' "$ROOT")
ok "L33 the panel's warning lists the conflicting range and both lists" "$(echo "$warn" | grep -q '^conflict 203.0.113.64 - 203.0.113.127 (partners / scrapers)' && echo 1 || echo 0)"

echo "-- L: kill switch, exempt paths and the holdout"
FORCE=true ilist hold 1 block enforce true 127.0.0.1
lists_compile
eq "L34 a held-out client (127.0.0.1 is in the holdout here) is still refused by a block list" "$(get "$UA" /l34)" 403
eq "L35 an exempt path bypasses a block list" "$(get "$UA" /exempt-me)" 200
touch "$ROOT/guard.off"
eq "L36 the kill switch bypasses a block list" "$(get "$UA" /l36)" 200
rm -f "$ROOT/guard.off"
eq "L37 without the kill switch the list acts again" "$(get "$UA" /l37)" 403

echo "-- L: an enforced block list is decided BEFORE the challenge handshake (no nonce claim, no counters, no Redis)"
ilist none 1 block enforce false 1.2.3.4
lists_compile
write_rules "$(rule r-chal Chal enforce challenge '["chalbot"]')"
XF='X-Forwarded-For: 203.0.113.9'
hs() { curl -s -o /dev/null -w '%{http_code}' -X POST -H 'User-Agent: x chalbot' -H "$XF" -H "X-GV: $1" -H "X-GV-P: $2" "http://127.0.0.1:$PORT/"; }
nonce() { body 'x chalbot' "$1" -H "$XF" | sed -n "s/.*var N = '\([^']*\)'.*/\1/p" | head -1; }
N1=$(nonce /l60); C1=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$N1")
N2=$(nonce /l61); C2=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$N2")
N3=$(nonce /l62); C3=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$N3")
ok "L60 three valid challenge nonces were issued to the not-yet-listed address" "$([ -n "$N1" ] && [ -n "$N2" ] && [ -n "$N3" ] && echo 1 || echo 0)"
ilist scrapers 1 block enforce true 203.0.113.0/24
lists_compile
a=$(cmds); code=$(hs "$N1" "$C1"); b=$(cmds)
eq "L61 a block-listed address POSTing a VALID handshake gets 403" "$code" 403
eq "L62 ...with ZERO Redis commands (no nonce claim, no counters)" "$(( b - a ))" "$idle"
has '"IPL_BLOCK:scrapers"'; ok "L63 ...logged once as act 403 with IPL_BLOCK" "$([ $? -eq 0 ] && has '"act":"403"' && echo 1 || echo 0)"
ok "L64 ...and the nonce was NOT claimed: no nonce key exists in Redis" "$([ "$(redis-cli -p "$RPORT" --scan --pattern 'gv:nonce:*' | wc -l | tr -d ' ')" = 0 ] && echo 1 || echo 0)"
ilist scrapers 1 block monitor true 203.0.113.0/24
lists_compile
eq "L65 a MONITOR block list leaves the handshake unchanged: the same valid POST gives 204" "$(hs "$N1" "$C1")" 204
ilist scrapers 1 block enforce true 203.0.113.0/24
ilist partners 2 allow enforce true 203.0.113.9
lists_compile
eq "L66 an enforced ALLOW list for the same address wins over the block list: the handshake goes through (204)" "$(hs "$N2" "$C2")" 204
ilist scrapers 1 block enforce true 203.0.113.0/24
ilist partners 2 allow monitor true 203.0.113.9
lists_compile
eq "L67 a MONITOR allow list does not protect it: the block list answers 403 before the handshake" "$(hs "$N3" "$C3")" 403
eq "L68 an exempt path is not blocked: the handshake POST to it is not refused by the list" "$([ "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'User-Agent: x chalbot' -H "$XF" "http://127.0.0.1:$PORT/exempt-me")" != 403 ] && echo ok)" ok
write_rules

echo "-- L: the compiler enforces the safety caps (an allow 0.0.0.0/0 copied over SFTP must not switch the guard off)"
ilist everyone 1 allow enforce true 0.0.0.0/0 ::/0 64.0.0.0/12 2400::/31
FORCE=true ilist everyone2 2 allow enforce true 0.0.0.0/0 ::/0
lists_compile
write_rules "$(rule r-evil Evil enforce block '["evilbot"]')"
eq "L70 an allow list holding 0.0.0.0/0, ::/0 and a /12 (forced or not): everything is dropped, an enforced block rule still blocks" "$(get 'x evilbot' /l70)" 403
ok "L71 ...no allow file was written at all" "$([ ! -e "$WORK/lists/allow.bin" ] && echo 1 || echo 0)"
ok "L72 ...and lists-status.json records the dropped entries per list and reason (also the forced list's 0/0)" "$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1]))["lists"]; print(1 if d["everyone"]["dropped"]=={"all":2,"allow_wide":2,"wide":0,"protected":0} and d["everyone"]["dropped_huge"]==2 and d["everyone2"]["dropped"]["all"]==2 else 0)' "$WORK/lists/lists-status.json")"
ilist blockall 1 block enforce true 0.0.0.0/0 10.0.0.0/8 127.0.0.1
lists_compile
eq "L73 a block list of 0.0.0.0/0, private and loopback entries drops them all: nobody is refused" "$(get "$UA" /l73)" 200
ok "L74 ...no block file was written" "$([ ! -e "$WORK/lists/block.bin" ] && echo 1 || echo 0)"
write_rules

echo "-- L: broken files fail open, and the dashboard can see them"
ilist scrapers 1 block enforce true 203.0.113.0/24
lists_compile
cp "$WORK/lists/block.bin" "$WORK/lists/block.bin.keep"
printf 'GVRGgarbage' > "$WORK/lists/block.bin"
eq "L38 a corrupt block file: the request is served, never a 500" "$(get "$UA" /l38 -H 'X-Forwarded-For: 203.0.113.9')" 200
ok "L39 ...and reported in guard-errors.log" "$(grep -q geo_corrupt "$WORK/logs/guard-errors.log" 2>/dev/null && echo 1 || echo 0)"
health() { GV_LISTS_DIR="$WORK/lists" GV_GEO_DIR="$WORK/geo" "$PHP_BIN" -r 'define("GV_BOOT", 1); define("GV_NO_AUTORUN", 1); define("GP_BOOT", 1); $r = $argv[1];
	require $r . "/guard/guard.php"; require $r . "/panel/config_io.php"; require $r . "/panel/jobs.php"; require $r . "/panel/iplists.php"; require $r . "/panel/health.php";
	foreach (gp_iplists_health(time(), array()) as $w) { echo $w[0], ":", $w[1], "\n"; }' "$ROOT"; }
ok "L40 the panel raises file_corrupt for it" "$(health | grep -q '^file_corrupt:block' && echo 1 || echo 0)"
rm -f "$WORK/lists/block.bin"
eq "L41 a missing block file while the list is enabled: served (fail-open)" "$(get "$UA" /l41 -H 'X-Forwarded-For: 203.0.113.9')" 200
ok "L42 ...and the panel raises file_missing" "$(health | grep -q '^file_missing:block' && echo 1 || echo 0)"
mv "$WORK/lists/block.bin.keep" "$WORK/lists/block.bin"
ok "L43 the file back: no alert" "$([ -z "$(health)" ] && echo 1 || echo 0)"
eq "L44 ...and the list acts again" "$(get "$UA" /l44 -H 'X-Forwarded-For: 203.0.113.9')" 403
ilist scrapers 1 block enforce true 203.0.113.0/24
lists_compile
printf '%s' '{"v":1,"time":1,"ok":false,"errors":["boom"],"types":{"allow":null,"block":{"built":1}},"lists":{}}' > "$WORK/lists/lists-status.json"
ok "L45 a compile that reported an error raises compile_failed" "$(health | grep -q '^compile_failed:boom' && echo 1 || echo 0)"
lists_compile

# The lists below stay in place for section G: Redis goes down with a block list and an allow list active.
ilist partners 1 allow enforce true 198.51.100.0/25
ilist scrapers 2 block enforce true 203.0.113.0/24
lists_compile
write_rules

echo "== M. Image CAPTCHA (rule action captcha): the flow, the token level, the precedence"
R flushall
ilist none 1 block enforce false 1.2.3.4
lists_compile
write_rules "$(rule r-cap Cap enforce captcha '["capbot"]')"
CJ="$WORK/m.jar"
nonce_of() { sed -n "s/.*var N = '\([^']*\)'.*/\1/p" | head -1; }
# a CAPTCHA page for UA / path / extra curl args -> the page; solve NONCE -> "answer counter"
capget() { body "$1" "$2" "${@:3}"; }
page=$(capget 'x capbot' /m1 -b "$CJ" -c "$CJ")
N=$(printf '%s' "$page" | nonce_of)
eq "M1 an enforced captcha rule: a token-less HTML GET gets the CAPTCHA page (503)" "$(get 'x capbot' /m1b -b "$WORK/m2.jar" -c "$WORK/m2.jar")" 503
ok "M2 the page carries the image as a data URI, a text box, the nonce and NO answer" "$(printf '%s' "$page" | grep -q 'data:image/png;base64,' && printf '%s' "$page" | grep -q 'id="gv-ca"' && [ -n "$N" ] && echo 1 || echo 0)"
has '"cap":"show"'; ok "M3 the row: act challenge, cap show, RULE:r-cap, one row" "$([ $? -eq 0 ] && has '"act":"challenge"' && has '"RULE:r-cap"' && echo 1 || echo 0)"
ok "M4 the nonce is a six-part CAPTCHA nonce, not the PoW one" "$([ "$(printf '%s' "$N" | tr -cd '.' | wc -c | tr -d ' ')" = 5 ] && echo 1 || echo 0)"
ANS=$("$PHP_BIN" "$ROOT/scripts/captcha-solve.php" "$N" 4 2>/dev/null)
POWC=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$N")
cpost() { # NONCE ANSWER POW JAR [extra curl args]
	local n="$1" a="$2" c="$3" j="$4"; shift 4
	curl -s -o /dev/null -w '%{http_code}' -X POST -H 'User-Agent: x capbot' -H "X-GV: $n" -H "X-GV-A: $a" -H "X-GV-P: $c" -b "$j" -c "$j" "$@" "http://127.0.0.1:$PORT/"
}
ok "M5 the solver found the 4-digit answer (the test's OCR)" "$([ -n "$ANS" ] && echo 1 || echo 0)"
eq "M6 a WRONG answer: 422, the page stays" "$(cpost "$N" 0000x "$POWC" "$CJ")" 422
has '"cap":"wrong"'; ok "M7 ...logged as cap wrong (act nonce_bad)" "$([ $? -eq 0 ] && has '"nonce_bad"' && echo 1 || echo 0)"
eq "M8 a bad proof of work with the right answer: 403" "$(cpost "$N" "$ANS" 1 "$CJ")" 403
eq "M9 the right answer: 204 and a token" "$(cpost "$N" "$ANS" "$POWC" "$CJ")" 204
has '"cap":"ok"'; ok "M10 ...logged as token_issued, cap ok, a solve time and tl c" "$([ $? -eq 0 ] && has '"act":"token_issued"' && has '"ct":' && has '"tl":"c"' && echo 1 || echo 0)"
ok "M11 the cookie is a CAPTCHA-level token (four parts, the third is c)" "$(awk '$6=="_gv"{print $7}' "$CJ" | awk -F. '{print (NF==4 && $3=="c") ? 1 : 0}' | head -1)"
eq "M12 with the CAPTCHA-level token the request passes" "$(get 'x capbot' /m12 -b "$CJ")" 200
has '"tl":"c"'; ok "M13 ...and the row says it carried a CAPTCHA-level token" "$([ $? -eq 0 ] && echo 1 || echo 0)"
eq "M14 the same nonce again is a replay: 403" "$(cpost "$N" "$ANS" "$POWC" "$WORK/m3.jar")" 403
# attempts: three wrong answers burn the nonce, even a right one is refused afterwards
page=$(capget 'x capbot' /m15 -b "$WORK/m4.jar" -c "$WORK/m4.jar"); N4=$(printf '%s' "$page" | nonce_of)
ANS4=$("$PHP_BIN" "$ROOT/scripts/captcha-solve.php" "$N4" 4 2>/dev/null); POW4=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$N4")
eq "M15 wrong answer 1 and 2: 422" "$(cpost "$N4" 1111x "$POW4" "$WORK/m4.jar")$(cpost "$N4" 2222x "$POW4" "$WORK/m4.jar")" 422422
eq "M16 wrong answer 3 (max_attempts 3): 403, the nonce is dead" "$(cpost "$N4" 3333x "$POW4" "$WORK/m4.jar")" 403
has '"cap":"fail"'; ok "M17 ...logged as cap fail" "$([ $? -eq 0 ] && echo 1 || echo 0)"
eq "M18 after that even the RIGHT answer is refused" "$(cpost "$N4" "$ANS4" "$POW4" "$WORK/m4.jar")" 403
# a Persian-digit answer is normalised and accepted
page=$(capget 'x capbot' /m19 -b "$WORK/m5.jar" -c "$WORK/m5.jar"); N5=$(printf '%s' "$page" | nonce_of)
ANS5=$("$PHP_BIN" "$ROOT/scripts/captcha-solve.php" "$N5" 4 2>/dev/null); POW5=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$N5")
FA=$("$PHP_BIN" -r '$m = array("0"=>"۰","1"=>"۱","2"=>"۲","3"=>"۳","4"=>"۴","5"=>"۵","6"=>"۶","7"=>"۷","8"=>"۸","9"=>"۹"); echo rawurlencode(strtr($argv[1], $m));' "$ANS5")
eq "M20 the answer typed with Persian digits (percent-encoded in the header) is accepted" "$(cpost "$N5" "$FA" "$POW5" "$WORK/m5.jar")" 204
# a PoW-level token does not satisfy a captcha rule
page=$(body 'x powonly' /m21 -b "$WORK/m6.jar" -c "$WORK/m6.jar")
write_rules "$(rule r-cap Cap enforce captcha '["capbot"]')" "$(rule r-pow Pow enforce challenge '["powonly"]')"
page=$(capget 'x powonly' /m21 -b "$WORK/m6.jar" -c "$WORK/m6.jar"); NP=$(printf '%s' "$page" | nonce_of); CP=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$NP")
eq "M21 a proof-of-work handshake gives a PoW-level token" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'User-Agent: x powonly' -H "X-GV: $NP" -H "X-GV-P: $CP" -b "$WORK/m6.jar" -c "$WORK/m6.jar" "http://127.0.0.1:$PORT/")" 204
eq "M22 that PoW-level token passes the PoW rule" "$(get 'x powonly' /m22 -b "$WORK/m6.jar")" 200
eq "M23 ...but a captcha rule still asks for a CAPTCHA (only a CAPTCHA-level token satisfies it): old tokens count as PoW level" "$(get 'x capbot' /m23 -b "$WORK/m6.jar")" 503
write_rules "$(rule r-cap Cap enforce captcha '["capbot"]')"
eq "M24 a MONITOR captcha rule only logs (SH_RULE), the request is served" "$(write_rules "$(rule r-cap Cap monitor captcha '["capbot"]')"; get 'x capbot' /m24)" 200
write_rules "$(rule r-cap Cap enforce captcha '["capbot"]')"

echo "-- M: where a CAPTCHA is never shown"
ilist partners 1 allow enforce true 127.0.0.1
lists_compile
eq "M30 an enforced ALLOW-LIST address: no CAPTCHA" "$(get 'x capbot' /m30)" 200
ilist none 1 block enforce false 1.2.3.4
lists_compile
R set "gv:allow:127.0.0.1" 1 EX 60
eq "M31 an operator ALLOW override: no CAPTCHA" "$(get 'x capbot' /m31)" 200
R del "gv:allow:127.0.0.1"
eq "M32 an EXEMPT path: no CAPTCHA" "$(get 'x capbot' /exempt-me)" 200
eq "M33 a non-HTML request (Accept: application/json): no CAPTCHA, the normal flow" "$(curl -s -o /dev/null -w '%{http_code}' -H 'User-Agent: x capbot' -H 'Accept: application/json' "http://127.0.0.1:$PORT/m33")" 200
eq "M34 an XMLHttpRequest: no CAPTCHA" "$(get 'x capbot' /m34 -H 'X-Requested-With: XMLHttpRequest')" 200
write_rules "$(SKIP=false rule r-gcap GCap enforce captcha '["googlebot"]')"
R set "gv:botok:127.0.0.1" 1 EX 60
eq "M35 a VERIFIED crawler: never a CAPTCHA, even with skip_verified_bots off" "$(get "$GBOT" /m35)" 200
has '"act":"allow_bot"'; ok "M36 ...it takes the normal bot pass" "$([ $? -eq 0 ] && echo 1 || echo 0)"
R del "gv:botok:127.0.0.1"
eq "M37 an UNVERIFIED crawler claim: a CAPTCHA (it can prove itself)" "$(get "$GBOT" /m37)" 503
write_rules "$(rule r-cap Cap enforce captcha '["capbot"]')"
ilist scrapers 1 block enforce true 127.0.0.1
FORCE=true ilist scrapers 1 block enforce true 127.0.0.1
lists_compile
eq "M38 a BLOCK-LISTED address gets 403, never a CAPTCHA" "$(get 'x capbot' /m38)" 403
ilist none 1 block enforce false 1.2.3.4
lists_compile
eq "M39 a client with no rule match is not asked at all" "$(get "$UA" /m39)" 200

echo "-- M: the per-IP CAPTCHA budget (8 pages / 600 s here) costs no Redis work once it is used up"
R flushall
for i in 1 2 3 4 5 6 7 8; do get 'x capbot' "/m4$i" >/dev/null; done
eq "M40 the 8 pages inside the budget were served and counted" "$(redis-cli -p "$RPORT" get gv:cpi:127.0.0.1 | tr -d '\r')" 8
n0=$(redis-cli -p "$RPORT" dbsize | tr -d '\r'); v0=$(redis-cli -p "$RPORT" get gv:cpi:127.0.0.1 | tr -d '\r')
eq "M41 the 9th page: over the budget -> 429, not a CAPTCHA" "$(get 'x capbot' /m49)" 429
has 'CAPT_BUDGET'; ok "M42 ...logged with CAPT_BUDGET" "$([ $? -eq 0 ] && has '"act":"429"' && echo 1 || echo 0)"
ok "M43 ...and it wrote NOTHING for the CAPTCHA: the counter did not move and no key was created" "$([ "$(redis-cli -p "$RPORT" get gv:cpi:127.0.0.1 | tr -d '\r')" = "$v0" ] && [ "$(redis-cli -p "$RPORT" dbsize | tr -d '\r')" = "$n0" ] && echo 1 || echo 0)"
ok "M44 ...no nonce claim, no attempt counter exists" "$([ "$(redis-cli -p "$RPORT" --scan --pattern 'gv:ca:*' | wc -l | tr -d ' ')" = 0 ] && [ "$(redis-cli -p "$RPORT" --scan --pattern 'gv:nonce:*' | wc -l | tr -d ' ')" = 0 ] && echo 1 || echo 0)"
R flushall

echo "-- M: headless signals, escalation and the device budget"
# escalation in MONITOR mode (server 1, enforce.challenge off): logged, the token is still issued
write_rules "$(rule r-pow Pow enforce challenge '["escbot"]')"
page=$(body 'x escbot' /m50 -b "$WORK/e1.jar" -c "$WORK/e1.jar"); NE=$(printf '%s' "$page" | nonce_of); CE=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$NE")
hpost() { # PORT NONCE POW SIGNALS JAR [UA]
	curl -s -o /dev/null -w '%{http_code}' -D "$WORK/hdr.txt" -X POST -H "User-Agent: ${6:-x escbot}" -H "X-GV: $2" -H "X-GV-P: $3" -H "X-GV-S: $4" -b "$5" -c "$5" "http://127.0.0.1:$1/"
}
eq "M50 a handshake with headless signals (score 105 >= escalate_score 60), enforce.challenge OFF: the token is issued (shadow)" "$(hpost "$PORT" "$NE" "$CE" 'w1.h1.t900' "$WORK/e1.jar")" 204
has 'SH_CAPT_ESC'; ok "M51 ...logged with SH_CAPT_ESC and the score and letters only (hs, hf)" "$([ $? -eq 0 ] && has '"hs":105' && has '"hf":"whu"' && echo 1 || echo 0)"
ok "M52 ...no raw fingerprint value is logged (only the letters)" "$(! has 'SwiftShader' && ! has 'llvmpipe' && ! has 'webdriver' && echo 1 || echo 0)"
page=$(body 'x escbot' /m53 -b "$WORK/e2.jar" -c "$WORK/e2.jar"); NE=$(printf '%s' "$page" | nonce_of); CE=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$NE")
eq "M53 a clean handshake (no signals, or neutral ones) is not escalated" "$(hpost "$PORT" "$NE" "$CE" 'w0.h0.l0.t900' "$WORK/e2.jar")" 204
# server 2: enforce.challenge ON, ratelimit ON, device_hour 3, CAPTCHA instead of the device 429
get2() { local ua="$1" path="$2"; shift 2; curl -s -o /dev/null -w '%{http_code}' -H "User-Agent: $ua" -H 'Accept: text/html' -H 'Accept-Language: en-US,en;q=0.9' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: none' "$@" "http://127.0.0.1:$PORT2$path"; }
body2() { local ua="$1" path="$2"; shift 2; curl -s -H "User-Agent: $ua" -H 'Accept: text/html' -H 'Accept-Language: en-US,en;q=0.9' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: none' "$@" "http://127.0.0.1:$PORT2$path"; }
write_rules
page=$(body2 'x escbot' /m60 -b "$WORK/e3.jar" -c "$WORK/e3.jar"); NE=$(printf '%s' "$page" | nonce_of); CE=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$NE")
eq "M60 server 2 (challenge enforced): the same signals escalate: 202, no token" "$(hpost "$PORT2" "$NE" "$CE" 'w1.h1.t900' "$WORK/e3.jar")" 202
ok "M60b ...and the server-side flag cesc:<ip + UA> exists in Redis" "$([ "$(redis-cli -p "$RPORT" --scan --pattern 'gv:cesc:*' | wc -l | tr -d ' ')" = 1 ] && [ "$(redis-cli -p "$RPORT" ttl "$(redis-cli -p "$RPORT" --scan --pattern 'gv:cesc:*' | head -1)" | tr -d '\r')" -gt 500 ] && echo 1 || echo 0)"
ok "M61 ...a signed flag cookie is set, and no token cookie" "$(grep -q '_gvc' "$WORK/hdr.txt" && ! grep -qi 'set-cookie: _gv=' "$WORK/hdr.txt" && echo 1 || echo 0)"
has2() { tail -1 "$WORK"/logs/guard-*.jsonl | grep -q "$1"; }
has2 '"cap":"esc"'; ok "M62 ...logged as a challenge with CAPT_ESC" "$([ $? -eq 0 ] && has2 'CAPT_ESC' && echo 1 || echo 0)"
page=$(body2 'x escbot' /m63 -b "$WORK/e3.jar" -c "$WORK/e3.jar")
ok "M63 the next page load is the CAPTCHA, not the PoW challenge" "$(printf '%s' "$page" | grep -q 'data:image/png;base64,' && echo 1 || echo 0)"
NE3=$(printf '%s' "$page" | nonce_of); AE3=$("$PHP_BIN" "$ROOT/scripts/captcha-solve.php" "$NE3" 4 2>/dev/null); PE3=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$NE3")
eq "M64 solving it gives a CAPTCHA-level token" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'User-Agent: x escbot' -H "X-GV: $NE3" -H "X-GV-A: $AE3" -H "X-GV-P: $PE3" -b "$WORK/e3.jar" -c "$WORK/e3.jar" "http://127.0.0.1:$PORT2/")" 204
ok "M64b ...and the flag is removed from Redis when the CAPTCHA-level token is issued" "$([ "$(redis-cli -p "$RPORT" --scan --pattern 'gv:cesc:*' | wc -l | tr -d ' ')" = 0 ] && echo 1 || echo 0)"
eq "M65 with it the pages load" "$(get2 'x escbot' /m65 -b "$WORK/e3.jar")" 200

echo "-- M2: the escalation survives a dropped cookie (server-side flag, same ip + UA)"
nkeys() { redis-cli -p "$RPORT" --scan --pattern 'gv:cesc:*' | wc -l | tr -d ' '; }
conns() { redis-cli -p "$RPORT" info stats | sed -n 's/^total_connections_received:\([0-9]*\).*/\1/p' | tr -d '\r'; }
R flushall
# three clients with a PoW challenge in hand: one that will drop its cookie, one that escalates, one that is clean (UA differs: its own flag key)
page=$(body2 'x escbot' /m66a -b "$WORK/e5.jar" -c "$WORK/e5.jar"); NE5=$(printf '%s' "$page" | nonce_of); CE5=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$NE5")
page=$(body2 'x escbot' /m66b -b "$WORK/e4.jar" -c "$WORK/e4.jar"); NE4=$(printf '%s' "$page" | nonce_of); CE4=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$NE4")
page=$(body2 'x escbot' /m66c -b "$WORK/e8.jar" -c "$WORK/e8.jar"); NE8=$(printf '%s' "$page" | nonce_of); CE8=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$NE8")
page=$(body2 'x cleanbot' /m66d -b "$WORK/e6.jar" -c "$WORK/e6.jar"); NE6=$(printf '%s' "$page" | nonce_of); CE6=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$NE6")
a=$(cmds); ca=$(conns); code6=$(hpost "$PORT2" "$NE6" "$CE6" 'w0.h0.l0.t900' "$WORK/e6.jar" 'x cleanbot'); b=$(cmds); cb=$(conns)
CLEAN_CMDS=$(( b - a )); CLEAN_CONNS=$(( cb - ca ))
eq "M66 a clean handshake (escalation on) is not escalated: 204" "$code6" 204
a=$(cmds); ca=$(conns); code4=$(hpost "$PORT2" "$NE4" "$CE4" 'w1.h1.t900' "$WORK/e4.jar"); b=$(cmds); cb=$(conns)
eq "M67 a handshake with the headless signals escalates: 202" "$code4" 202
eq "M68 ...and costs the same number of Redis commands as the clean one (the flag write replaces the flag read) and no extra connection" "$(( b - a )).$(( cb - ca ))" "$CLEAN_CMDS.$CLEAN_CONNS"
eq "M68b ...and ONE connection, as every request"  "$(( cb - ca - 2 ))" 1
eq "M69 the flag exists" "$(nkeys)" 1
code5=$(hpost "$PORT2" "$NE5" "$CE5" 'w0.h0.l0.t900' "$WORK/e5.jar")
eq "M70 the same ip + UA with ANOTHER cookie jar (cookie dropped) and clean signals: 202, no token (the flag, not the cookie, decides)" "$code5" 202
ok "M71 ...no token cookie is set" "$(! grep -qi 'set-cookie: _gv=' "$WORK/hdr.txt" && echo 1 || echo 0)"
page=$(body2 'x escbot' /m72)
ok "M72 a page load with NO cookie at all gets the CAPTCHA" "$(printf '%s' "$page" | grep -q 'data:image/png;base64,' && echo 1 || echo 0)"
ok "M73 ...and another UA from the same address is not affected (its own flag key)" "$([ "$(get2 'x cleanbot' /m73 -b "$WORK/e6.jar")" = 200 ] && echo 1 || echo 0)"
ca=$(conns); get2 'x freshbot' /m72b >/dev/null; cb=$(conns)
eq "M72b the request path reads the flag in its ONE pipeline: a token-less page load opens one connection (no extra round trip)" "$(( cb - ca - 1 ))" 1
NE7=$(printf '%s' "$page" | nonce_of); AE7=$("$PHP_BIN" "$ROOT/scripts/captcha-solve.php" "$NE7" 4 2>/dev/null); PE7=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$NE7")
eq "M74 solving it gives a CAPTCHA-level token" "$(curl -s -o /dev/null -w '%{http_code}' -D "$WORK/hdr.txt" -X POST -H 'User-Agent: x escbot' -H "X-GV: $NE7" -H "X-GV-A: $AE7" -H "X-GV-P: $PE7" -c "$WORK/e7.jar" "http://127.0.0.1:$PORT2/")" 204
eq "M75 ...and the flag is gone" "$(nkeys)" 0
eq "M76 ...the pages load with the token" "$(get2 'x escbot' /m76 -b "$WORK/e7.jar")" 200

echo "== O. temporary challenge / CAPTCHA overrides (gv:chal:<ip>, '1' = challenge, 'c' = CAPTCHA). Server 1 has every enforce switch OFF: the override alone challenges"
write_rules
R flushall
R set "gv:chal:127.0.0.1" 1 EX 60
eq "O1 an override challenges this one client although enforce.challenge is OFF (a rule-like operator action): the check page (503)" "$(get 'x ovrbot' /o1)" 503
has '"ovr":"challenge"'; ok "O2 ...the row: ovr challenge, act challenge, served (sh 0), OVR_CHALLENGE" "$([ $? -eq 0 ] && has '"act":"challenge"' && has '"sh":0' && has '"OVR_CHALLENGE"' && echo 1 || echo 0)"
ok "O3 a client WITHOUT the override is untouched (another address through the trusted proxy)" "$([ "$(get 'x ovrbot' /o3 -H 'X-Forwarded-For: 9.9.9.9')" = 200 ] && echo 1 || echo 0)"
page=$(body 'x ovrbot' /o4 -b "$WORK/o1.jar" -c "$WORK/o1.jar"); NO=$(printf '%s' "$page" | nonce_of); CO=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$NO")
eq "O5 solving the check page gives a token" "$(hpost "$PORT" "$NO" "$CO" 'w0.h0.l0.t900' "$WORK/o1.jar" 'x ovrbot')" 204
eq "O6 with the token the override no longer challenges (no loop)" "$(get 'x ovrbot' /o6 -b "$WORK/o1.jar")" 200
eq "O7 a POST (challenge.gate_post is off: not a gated page) is served, and only LOGGED as a shadow challenge" "$(get 'x ovrbot' /o7 -X POST)" 200
has 'OVR_CHALLENGE'; ok "O7b ...the row carries OVR_CHALLENGE with sh 1" "$([ $? -eq 0 ] && has '"sh":1' && echo 1 || echo 0)"
R del "gv:chal:127.0.0.1"
eq "O8 removing the override: a token-less request is served again" "$(get 'x ovrbot' /o8)" 200

echo "-- O: CAPTCHA override"
R set "gv:chal:127.0.0.1" c EX 60
page=$(body 'x ovrcap' /o10 -b "$WORK/o2.jar" -c "$WORK/o2.jar")
ok "O10 a CAPTCHA override: the next page load is the image CAPTCHA" "$(printf '%s' "$page" | grep -q 'data:image/png;base64,' && echo 1 || echo 0)"
has '"ovr":"captcha"'; ok "O11 ...logged with OVR_CAPTCHA and cap show" "$([ $? -eq 0 ] && has 'OVR_CAPTCHA' && has '"cap":"show"' && echo 1 || echo 0)"
ok "O12 ...counted against the per-IP CAPTCHA budget (read in its own GET: no rule or flag read it)" "$([ "$(redis-cli -p "$RPORT" get gv:cpi:127.0.0.1 | tr -d '\r')" -ge 1 ] && echo 1 || echo 0)"
page=$(body 'x ovrpow' /o12 -b "$WORK/o3.jar" -c "$WORK/o3.jar")
NC=$(printf '%s' "$page" | nonce_of); AC=$("$PHP_BIN" "$ROOT/scripts/captcha-solve.php" "$NC" 4 2>/dev/null); PC=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$NC")
eq "O13 solving it gives a CAPTCHA-level token" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'User-Agent: x ovrpow' -H "X-GV: $NC" -H "X-GV-A: $AC" -H "X-GV-P: $PC" -b "$WORK/o3.jar" -c "$WORK/o3.jar" "http://127.0.0.1:$PORT/")" 204
eq "O14 with a CAPTCHA-level token the override lets the pages through" "$(get 'x ovrpow' /o14 -b "$WORK/o3.jar")" 200
R set "gv:chal:127.0.0.1" 1 EX 60
page=$(body 'x ovrpow2' /o15 -b "$WORK/o4.jar" -c "$WORK/o4.jar"); NP2=$(printf '%s' "$page" | nonce_of); CP2=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$NP2")
eq "O15 a proof-of-work handshake gives a (PoW-level) token under a challenge override" "$(hpost "$PORT" "$NP2" "$CP2" 'w0.h0.l0.t900' "$WORK/o4.jar" 'x ovrpow2')" 204
R set "gv:chal:127.0.0.1" c EX 60
eq "O16 a PROOF-OF-WORK token does not satisfy a CAPTCHA override: the CAPTCHA is shown (503)" "$(get 'x ovrpow2' /o16 -b "$WORK/o4.jar")" 503
R del "gv:chal:127.0.0.1"

echo "-- O: precedence"
R set "gv:chal:127.0.0.1" 1 EX 60
R set "gv:allow:127.0.0.1" 1 EX 60
eq "O20 an ALLOW override beats a challenge override" "$(get 'x ovrbot' /o20)" 200
has '"act":"allow_override"'; ok "O21 ...logged as allow_override" "$([ $? -eq 0 ] && echo 1 || echo 0)"
R del "gv:allow:127.0.0.1"
ilist partners 1 allow enforce true 127.0.0.1
lists_compile
eq "O22 an enforced ALLOW LIST beats a challenge override (the list is checked first, as for a deny)" "$(get 'x ovrbot' /o22)" 200
ilist none 1 block enforce false 1.2.3.4
lists_compile
write_rules "$(rule r-blk Blk enforce block '["ovrbot"]')"
eq "O23 an enforced BLOCK rule keeps priority over a challenge override" "$(get 'x ovrbot' /o23)" 403
write_rules "$(rule r-chl Chl enforce challenge '["ovrbot"]')"
eq "O24 a challenge rule and a challenge override together: one check page" "$(get 'x ovrbot' /o24)" 503
R set "gv:chal:127.0.0.1" c EX 60
page=$(body 'x ovrbot' /o25)
ok "O25 a CAPTCHA override upgrades a rule's plain challenge to the CAPTCHA" "$(printf '%s' "$page" | grep -q 'data:image/png;base64,' && echo 1 || echo 0)"
write_rules
R set "gv:chal:127.0.0.1" 1 EX 60
R set "gv:botok:127.0.0.1" 1 EX 60
eq "O26 a VERIFIED crawler keeps its pass (it cannot solve a challenge)" "$(get "$GBOT" /o26)" 200
has '"act":"allow_bot"'; ok "O27 ...logged as allow_bot" "$([ $? -eq 0 ] && echo 1 || echo 0)"
R del "gv:botok:127.0.0.1"
eq "O28 an EXEMPT path is never challenged" "$(get 'x ovrbot' /exempt-me)" 200
R del "gv:cpi:127.0.0.1"; R set "gv:chal:127.0.0.1" c EX 60
eq "O29 enforced (server 2) the override acts the same: a CAPTCHA override shows the image test there too" "$(body2 'x ovrbot' /o29 | grep -c 'data:image/png;base64,' | tr -d ' ')" 1
R del "gv:chal:127.0.0.1"

echo "-- O: a deny override acts in monitor mode and in the holdout (server 1: every enforce switch OFF, 127.0.0.1 is in the 5% holdout)"
R set "gv:deny:127.0.0.1" 1 EX 60
eq "O40 a DENY override blocks with every enforce switch OFF: 403" "$(get 'x ovrbot' /o40)" 403
has '"ovr":"deny"'; ok "O41 ...logged as a served 403 (sh 0) with OVR_DENY, no SH_ prefix, although the client is in the holdout" "$([ $? -eq 0 ] && has '"act":"403"' && has '"sh":0' && has '"OVR_DENY"' && ! has 'SH_OVR' && has '"hold":1' && echo 1 || echo 0)"
eq "O42 ...also for a POST and for a non-page request" "$(get 'x ovrbot' /o42 -X POST)$(get 'x ovrbot' /o42b -H 'X-Requested-With: XMLHttpRequest')" 403403
R set "gv:chal:127.0.0.1" 1 EX 60
R set "gv:allow:127.0.0.1" 1 EX 60
eq "O43 an ALLOW override still beats the deny" "$(get 'x ovrbot' /o43)" 200
R del "gv:allow:127.0.0.1"
eq "O44 deny beats a challenge override (403, not the check page)" "$(get 'x ovrbot' /o44)" 403
R del "gv:chal:127.0.0.1"
R set "gv:chal:127.0.0.1" c EX 60
touch "$ROOT/guard.off"
eq "O45 the KILL SWITCH stops deny, challenge and CAPTCHA overrides alike: 200" "$(get 'x ovrbot' /o45)$(get 'x ovrbot' /o45b -X POST)" 200200
R set "gv:chal:127.0.0.1" 1 EX 60
eq "O46 ...a challenge override too" "$(get 'x ovrbot' /o46)" 200
R del "gv:chal:127.0.0.1"
eq "O47 ...and the deny" "$(get 'x ovrbot' /o47)" 200
rm -f "$ROOT/guard.off"
eq "O48 the kill switch off again: the deny is back" "$(get 'x ovrbot' /o48)" 403
R del "gv:deny:127.0.0.1"
eq "O49 deny removed: served" "$(get 'x ovrbot' /o49)" 200

echo "-- O: an expired IP-list entry stops matching within a minute, with no nightly compile (the worker's every-minute check)"
FORCE=true ilist exp 1 block enforce true '127.0.0.1  # expires=2026-01-01'
LC_NOW=1767000000 lists_compile
nexp() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("next_expiry", "missing"))' "$WORK/lists/lists-status.json"; }
eq "O50 the entry is live at compile time (2025-12-29): the enforced block list answers 403" "$(get 'x ovrbot' /o50)" 403
ok "O51 ...and the compile stored the earliest future expiry in lists-status.json" "$([ "$(nexp)" -gt 0 ] 2>/dev/null && echo 1 || echo 0)"
cnt=$(python3 -I - "$ROOT" "$WORK/lists" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from analyzer import worker
print("COUNT", worker.recompile_expired_lists(sys.argv[2]))
PY
)
cnt=${cnt##*COUNT }
eq "O52 the worker's check (real time, long after the expiry) recompiles and removes one entry" "$cnt" 1
eq "O53 ...and the very next request is served: the expired entry stopped matching, no nightly job needed" "$(get 'x ovrbot' /o53)" 200
ok "O54 ...its line is gone from the source and next_expiry is 0 (nothing pending: the worker's check is one file read)" "$(! grep -q '127.0.0.1' "$WORK/lists/exp.txt" && [ "$(nexp)" = 0 ] && echo 1 || echo 0)"
cnt2=$(python3 -I - "$ROOT" "$WORK/lists" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from analyzer import worker
print("COUNT", worker.recompile_expired_lists(sys.argv[2]))
PY
)
cnt2=${cnt2##*COUNT }
eq "O55 a second check right after finds nothing to do" "$cnt2" 0
ilist none 1 block enforce false 1.2.3.4
lists_compile

echo "-- O: expiry and cost"
R set "gv:chal:127.0.0.1" 1 PX 400
eq "O30 a challenge override with a TTL acts while it lives" "$(get 'x ovrttl' /o30)" 503
sleep 0.7
eq "O31 ...and the request is back to normal when the TTL has passed" "$(get 'x ovrttl' /o31)" 200
ca=$(conns); get 'x ovrcost' /o32 >/dev/null; cb=$(conns)
R set "gv:chal:127.0.0.1" 1 EX 60
cc=$(conns); get 'x ovrcost' /o33 >/dev/null; cd2=$(conns)
eq "O33 reading the override costs no extra round trip: the same number of connections with and without it (the keys ride in the existing pipeline)" "$(( cd2 - cc ))" "$(( cb - ca ))"
R del "gv:chal:127.0.0.1"
# the cookie as the second signal: an escalated client whose flag is NOT in Redis (written by a handshake while Redis was down, or evicted) still gets the CAPTCHA
code8=$(hpost "$PORT2" "$NE8" "$CE8" 'w1.h1.t900' "$WORK/e8.jar"); R flushall
eq "M77 e8 escalates (202) and its Redis flag is removed again (flushall)" "$code8.$(nkeys)" "202.0"
page=$(body2 'x escbot' /m78 -b "$WORK/e8.jar")
ok "M78 ...the cookie alone still sends it to the CAPTCHA (Redis has no flag)" "$(printf '%s' "$page" | grep -q 'data:image/png;base64,' && echo 1 || echo 0)"
# the device budget: a PoW-level token over device_hour (3) gets a CAPTCHA instead of a 429
page=$(body2 'x devbot' /m70 -b "$WORK/d1.jar" -c "$WORK/d1.jar"); ND=$(printf '%s' "$page" | nonce_of); CD=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$ND")
curl -s -o /dev/null -X POST -H 'User-Agent: x devbot' -H "X-GV: $ND" -H "X-GV-P: $CD" -b "$WORK/d1.jar" -c "$WORK/d1.jar" "http://127.0.0.1:$PORT2/"
codes=""; for i in 1 2 3; do codes="$codes$(get2 'x devbot' "/m7$i" -b "$WORK/d1.jar")"; done
eq "M71 three requests inside the hourly device budget" "$codes" 200200200
page=$(body2 'x devbot' /m74 -b "$WORK/d1.jar")
ok "M72 the 4th (over device_hour) is a CAPTCHA page, not a 429" "$(printf '%s' "$page" | grep -q 'data:image/png;base64,' && echo 1 || echo 0)"
has2 'DEV_HOUR'; ok "M73 ...logged with DEV_HOUR as a challenge with cap show" "$([ $? -eq 0 ] && has2 '"cap":"show"' && echo 1 || echo 0)"
ND4=$(printf '%s' "$page" | nonce_of); AD4=$("$PHP_BIN" "$ROOT/scripts/captcha-solve.php" "$ND4" 4 2>/dev/null); PD4=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$ND4")
eq "M74 solved: a CAPTCHA-level token" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'User-Agent: x devbot' -H "X-GV: $ND4" -H "X-GV-A: $AD4" -H "X-GV-P: $PD4" -b "$WORK/d1.jar" -c "$WORK/d1.jar" "http://127.0.0.1:$PORT2/")" 204
eq "M75 a CAPTCHA-level token is waived from the hourly and daily device budgets" "$(get2 'x devbot' /m75 -b "$WORK/d1.jar")" 200
# server 3: GD "missing"
get3() { local ua="$1" path="$2"; shift 2; curl -s -H "User-Agent: $ua" -H 'Accept: text/html' -H 'Accept-Language: en-US,en;q=0.9' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: none' "$@" "http://127.0.0.1:$PORT3$path"; }
write_rules "$(rule r-cap Cap enforce captcha '["capbot"]')"
page=$(get3 'x capbot' /m80)
ok "M80 GD missing: the captcha rule falls back to the proof-of-work challenge (no image)" "$(printf '%s' "$page" | grep -q "var N = '" && ! printf '%s' "$page" | grep -q 'data:image' && echo 1 || echo 0)"
NG=$(printf '%s' "$page" | nonce_of)
ok "M81 ...with a normal four-part nonce" "$([ "$(printf '%s' "$NG" | tr -cd '.' | wc -c | tr -d ' ')" = 3 ] && echo 1 || echo 0)"
R flushall

# The lists below stay in place for section G: Redis goes down with a block list and an allow list active.
ilist partners 1 allow enforce true 198.51.100.0/25
ilist scrapers 2 block enforce true 203.0.113.0/24
lists_compile
write_rules

echo "== G. Redis down: rules still apply (they need no Redis), the request never fails"
write_rules "$(rule r-evil Evil enforce block '["evilbot"]')" "$(rule r-gbot GBot enforce block '["googlebot"]')" \
	"$(SKIP=false PRI=50 rule r-gnoskip GNoSkip enforce block '["bingbot"]')"
redis-cli -p "$RPORT" shutdown nosave >/dev/null 2>&1
sleep 0.3
eq "G1 block rule with Redis down -> 403" "$(get 'x evilbot' /g1)" 403
eq "G2 a clean request with Redis down -> 200" "$(get "$UA" /g2)" 200
has '"rd":1'; ok "G3 ...logged as degraded" "$([ $? -eq 0 ] && echo 1 || echo 0)"
eq "G4 Redis down: a known-bot UA keeps its pass and the skipping rule does not fire" "$(get "$GBOT" /g4)" 200
has '"act":"allow_bot"'; ok "G5 ...as allow_bot, with the reason RULE_SKIP_DEGRADED" "$([ $? -eq 0 ] && has '"RULE_SKIP_DEGRADED"' && echo 1 || echo 0)"
eq "G6 Redis down: a rule with skip_verified_bots off still blocks a known-bot UA" "$(get 'Mozilla/5.0 (compatible; bingbot/2.0)' /g6)" 403
eq "G7 Redis down: a UA that is not a known bot is still blocked" "$(get 'x evilbot' /g7)" 403
eq "G8 Redis down: a block-listed address is refused (the lists need no Redis)" "$(get "$UA" /g8 -H 'X-Forwarded-For: 203.0.113.9')" 403
eq "G9 Redis down: an allow-listed address is let through, even with an enforced block rule" "$(get 'x evilbot' /g9 -H 'X-Forwarded-For: 198.51.100.9')" 200
has '"IPL_ALLOW:partners"'; ok "G10 ...logged with IPL_ALLOW (RULE_SKIP_DEGRADED above is unaffected by the lists)" "$([ $? -eq 0 ] && echo 1 || echo 0)"
eq "G11 Redis down: a Googlebot UA from a listed block address is refused, not passed as a degraded known bot" "$(get "$GBOT" /g11 -H 'X-Forwarded-For: 203.0.113.9')" 403
eq "G12 Redis down: the degraded known-bot pass still works from an unlisted address" "$(get "$GBOT" /g12)" 200
has '"RULE_SKIP_DEGRADED"'; ok "G13 ...with RULE_SKIP_DEGRADED, as before" "$([ $? -eq 0 ] && echo 1 || echo 0)"

echo "== K. Redis down and a country rule: a crawler is never blocked by country during an outage"
write_rules "$(grule r-noir NotIR enforce block exclude '["IR"]')"
eq "K1 country rule 'not IR -> block', Googlebot UA from a US address, Redis down: the crawler is served" "$(get "$GBOT" /k1)" 200
has '"act":"allow_bot"'; ok "K2 ...as allow_bot with RULE_SKIP_DEGRADED, and the country is logged" "$([ $? -eq 0 ] && has '"RULE_SKIP_DEGRADED"' && has '"cc":"US"' && echo 1 || echo 0)"
eq "K3 the same rule, a browser UA from the US, Redis down: blocked (no Redis needed)" "$(get "$UA" /k3)" 403
eq "K4 the same rule, an IR client, Redis down: served" "$(get "$UA" /k4 -H 'X-Forwarded-For: 5.1.2.3')" 200
write_rules "$(SKIP=false grule r-noir NotIR enforce block exclude '["IR"]')"
eq "K5 skip_verified_bots off: Redis down, the crawler UA is blocked by country (the operator asked for it)" "$(get "$GBOT" /k5)" 403
write_rules "$(grule r-noir NotIR enforce block exclude '["IR"]')"
eq "K6 Bingbot UA from a US address, Redis down: served" "$(get 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)' /k6)" 200
eq "K7 a fake crawler UA that is not in known_bots is still blocked" "$(get 'Mozilla/5.0 (compatible; Notabot/2.0)' /k7)" 403

echo "== K2. CAPTCHA with Redis down: attempts are not counted, so every guess must cost CPU (a proof of work of >= 20 bits BOUND to the typed answer, and an answer of at least 6 characters)"
write_rules "$(rule r-cap Cap enforce captcha '["capbot"]')" "$(SKIP=false PRI=50 rule r-gcap GCap enforce captcha '["googlebot"]')"
page=$(body 'x capbot' /k20 -b "$WORK/k2.jar" -c "$WORK/k2.jar"); NK=$(printf '%s' "$page" | nonce_of)
ok "K20 Redis down: the CAPTCHA page is still served (no budget can be read)" "$(printf '%s' "$page" | grep -q 'data:image/png;base64,' && echo 1 || echo 0)"
has 'CAPT_DEGRADED'; ok "K20b ...logged with CAPT_DEGRADED, the page carries a proof of work of 20 bits (a six-part nonce) and the answer has 6 digits, not the 4 of level 1" "$([ $? -eq 0 ] && printf '%s' "$page" | grep -q "B = 20," && [ "$(printf '%s' "$NK" | tr -cd '.' | wc -c | tr -d ' ')" = 5 ] && echo 1 || echo 0)"
AK=$("$PHP_BIN" "$ROOT/scripts/captcha-solve.php" "$NK" 6 2>/dev/null)
eq "K20c ...the answer of the degraded CAPTCHA is 6 digits (a 4-digit search finds nothing)" "$("$PHP_BIN" "$ROOT/scripts/captcha-solve.php" "$NK" 4 2>/dev/null | wc -c | tr -d ' ').${#AK}" "0.6"
P1=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$NK" 1111x); P2=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$NK" 2222x); PK=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$NK" "$AK")
eq "K21 Redis down: a proof solved for ONE answer does not carry over to another guess (403 pow_bad)" "$(cpost "$NK" 2222x "$P1" "$WORK/k2.jar")" 403
eq "K21b Redis down: each wrong guess WITH its own proof is a plain 422 (no counter: the number of guesses is bounded only by the CPU they cost and the time limit, see docs/06)" "$(cpost "$NK" 1111x "$P1" "$WORK/k2.jar")$(cpost "$NK" 2222x "$P2" "$WORK/k2.jar")" 422422
eq "K22 Redis down: the right answer with its own proof still gives a CAPTCHA-level token" "$(cpost "$NK" "$AK" "$PK" "$WORK/k2.jar")" 204
eq "K23 Redis down: a bad proof of work is refused" "$(cpost "$NK" "$AK" 1 "$WORK/k2.jar")" 403
page=$(body2 'x escbot' /k23 -b "$WORK/e8.jar")
ok "K23b Redis down: an escalated client whose cookie is the only signal still gets the CAPTCHA (and the degraded proof)" "$(printf '%s' "$page" | grep -q "B = 20," && echo 1 || echo 0)"
eq "K24 Redis down: a known-bot UA keeps its pass; a captcha rule never asks a crawler (RULE_SKIP_DEGRADED)" "$(get "$GBOT" /k24)" 200
has '"RULE_SKIP_DEGRADED"'; ok "K25 ...with the reason on the row" "$([ $? -eq 0 ] && echo 1 || echo 0)"
write_rules

echo
echo "PASS $PASS  FAIL $FAIL"
[ "$FAIL" -eq 0 ]
