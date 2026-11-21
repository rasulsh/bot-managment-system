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
# Needs: php (8.0+), curl, redis-server. Touches nothing outside a temp dir
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

for need in "$PHP_BIN" curl redis-server redis-cli; do
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

mkdir -p "$WORK/logs"
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
\$c['challenge'] = array('pow_bits' => 12, 'bind_ip' => true);
\$c['limits'] = array_merge(\$c['limits'], array('window' => 60, 'device' => 100000, 'ip_ua' => 100000, 'ip' => 100000, 'mint' => 100000, 'bot' => 100000, 'preview' => 100000));
return \$c;
CFG

# rule ID NAME MODE ACTION JSON_UA_VALUES [extra json fields]
rule() {
	printf '{"id":"%s","name":"%s","enabled":true,"mode":"%s","action":"%s","priority":%s,"skip_verified_bots":%s,"ua":{"op":"include","type":"contains","values":%s},"path":null,"expires_at":%s,"pow_bits":%s,"note":"","created_by":"","created_at":0,"updated_at":0}' \
		"$1" "$2" "$3" "$4" "${PRI:-100}" "${SKIP:-true}" "$5" "${EXP:-0}" "${POW:-0}"
}
# Writes rules.json AND the generated cache the way the panel does, so the fast path is the one under test.
write_rules() {
	printf '{"rules":[%s]}' "$(IFS=,; echo "$*")" > "$RULES"
	"$PHP_BIN" -r 'define("GV_BOOT", 1); define("GV_NO_AUTORUN", 1); require $argv[1]."/guard/guard.php";
		file_put_contents($argv[2], gv_rules_cache_source(gv_rules_read($argv[3])));' "$ROOT" "$WORK/rules.cache.php" "$RULES"
}

redis-server --port "$RPORT" --save "" --appendonly no --dir "$WORK" >"$WORK/redis.log" 2>&1 &
PIDS+=($!)
sleep 0.3
write_rules
GV_RULES="$RULES" GV_DEV_CONFIG="$WORK/config.php" "$PHP_BIN" -S "127.0.0.1:$PORT" "$ROOT/scripts/dev-router.php" >"$WORK/php.log" 2>&1 &
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

echo
echo "PASS $PASS  FAIL $FAIL"
[ "$FAIL" -eq 0 ]
