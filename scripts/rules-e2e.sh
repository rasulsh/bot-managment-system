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
# Every enforce toggle is OFF in this server on purpose: rule actions must not
# depend on enforce.block / enforce.challenge.
# GeoIP: a country.bin built by analyzer/geo.py maps 127.0.0.0/8 to US and 5.0.0.0/8 to IR; the
# client address is 127.0.0.1 (US), or 5.x / 9.x through X-Forwarded-For (cdn_ranges trusts the
# loopback proxy here) for an IR and an unplaced visitor.
# IP lists: allow/block lists compiled by analyzer/iplist.py (the worker's compiler) into $WORK/lists; the whole
# precedence chain (allow beats rules and the operator deny, block beats the known-bot pass, both = allow wins
# with the panel warning, kill switch and exempt paths unchanged, no Redis work, broken files fail open).
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

PIDS=()
cleanup() {
	for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
	rm -f "$ROOT/guard.off"
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
	python3 -I "$ROOT/analyzer/iplist.py" --dir "$WORK/lists" >/dev/null 2>&1
	ILS=()
}

redis-server --port "$RPORT" --save "" --appendonly no --dir "$WORK" >"$WORK/redis.log" 2>&1 &
PIDS+=($!)
sleep 0.3
write_rules
GV_GEO_DIR="$WORK/geo" GV_LISTS_DIR="$WORK/lists" GV_RULES="$RULES" GV_DEV_CONFIG="$WORK/config.php" "$PHP_BIN" -S "127.0.0.1:$PORT" "$ROOT/scripts/dev-router.php" >"$WORK/php.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/t/404" 2>/dev/null && break; sleep 0.1; done

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

echo
echo "PASS $PASS  FAIL $FAIL"
[ "$FAIL" -eq 0 ]
