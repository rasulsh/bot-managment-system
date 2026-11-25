#!/usr/bin/env bash
# Byte-identity check: on every ALLOW path the guard must leave the response
# exactly as the application produced it. Compares full responses (status line,
# headers, body) with the guard running against the same requests with the kill
# switch (guard.off) present.
#
#   php -S 127.0.0.1:8080 scripts/dev-router.php &
#   bash scripts/identity-check.sh http://127.0.0.1:8080
#
# Local dev router only (it toggles <repo>/guard.off and seeds Redis keys).
set -uo pipefail

BASE="${1:-}"
[ -z "$BASE" ] && { echo "Usage: bash scripts/identity-check.sh <BASE_URL>"; exit 2; }
BASE="${BASE%/}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHP_BIN="${GV_PHP:-php}"
REDIS_CLI="${REDIS_CLI:-redis-cli}"
REDIS_ARGS="${REDIS_ARGS:--h 127.0.0.1 -p 6379}"
CLIENT_IP="${GV_CLIENT_IP:-127.0.0.1}"
CHROME_UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
GOOGLEBOT_UA='Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
# An operator's own kill switch is put aside while the checks run and put back afterwards (it used to be deleted).
SAVED_OFF=""
if [ -e "$ROOT/guard.off" ]; then SAVED_OFF="$ROOT/guard.off.saved-$$"; mv "$ROOT/guard.off" "$SAVED_OFF"; fi
restore_off() { rm -f "$ROOT/guard.off"; [ -z "$SAVED_OFF" ] || mv "$SAVED_OFF" "$ROOT/guard.off"; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"; restore_off' EXIT
failed=0

rcli() { $REDIS_CLI $REDIS_ARGS "$@" 2>/dev/null; }
clear_counters() {
	for pattern in 'gv:ri:*' 'gv:riu:*' 'gv:rd:*' 'gv:rb:*' 'gv:hp:*' 'gv:hpn:*' 'gv:hpd:*'; do
		keys=$(rcli --scan --pattern "$pattern")
		[ -n "$keys" ] && echo "$keys" | xargs -r $REDIS_CLI $REDIS_ARGS del >/dev/null 2>&1
	done
}

# fetch <out-prefix> <path> [curl args...]: status line + headers (minus Date) + body
fetch() {
	local out="$1" path="$2"; shift 2
	curl -s -D "$out.h" -o "$out.b" "$@" "$BASE$path"
	grep -vi '^date:' "$out.h" | tr -d '\r' | sort > "$out.hs"
}

compare() {   # <label> <path> [curl args...]
	local label="$1" path="$2"; shift 2
	rm -f "$ROOT/guard.off"; clear_counters
	fetch "$TMP/on" "$path" "$@"
	touch "$ROOT/guard.off"; clear_counters
	fetch "$TMP/off" "$path" "$@"
	rm -f "$ROOT/guard.off"
	if cmp -s "$TMP/on.b" "$TMP/off.b" && cmp -s "$TMP/on.hs" "$TMP/off.hs"; then
		printf 'PASS  %-18s %-14s identical (%s, %s bytes)\n' "$label" "$path" "$(head -1 "$TMP/on.h" | tr -d '\r' | cut -d' ' -f2)" "$(wc -c < "$TMP/on.b" | tr -d ' ')"
	else
		printf 'FAIL  %-18s %-14s DIFFERS\n' "$label" "$path"
		diff "$TMP/on.hs" "$TMP/off.hs" | head -5
		cmp "$TMP/on.b" "$TMP/off.b" | head -2
		failed=$((failed + 1))
	fi
}

pair=$("$PHP_BIN" "$ROOT/scripts/holdout-probe.php" --outside 2>/dev/null)
dev="${pair%% *}"; tok="${pair##* }"
if [ -z "$dev" ]; then echo "SKIP: could not mint a token (is the dev config in use?)"; exit 0; fi
nav=(-H "User-Agent: $CHROME_UA" -H 'Accept: text/html,application/xhtml+xml' -H 'Accept-Language: en-US' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: none')

paths=(/ /t/headers /t/404 /t/500 /t/big /t/nolength)

echo "-- allow (tokened navigation)"
for p in "${paths[@]}"; do compare allow "$p" "${nav[@]}" -H "Cookie: _gv=$tok"; done

echo "-- exempt"
compare exempt /exempt-me "${nav[@]}"

echo "-- allow_bot (verified crawler)"
rcli setex "gv:botok:$CLIENT_IP" 120 1 >/dev/null
for p in / /t/headers /t/big; do compare allow_bot "$p" -H "User-Agent: $GOOGLEBOT_UA" -H 'Accept: text/html'; done
rcli del "gv:botok:$CLIENT_IP" >/dev/null

echo "-- allow_override (operator allow on a device the score would block)"
rcli setex "gv:rep:$dev" 120 80 >/dev/null
rcli setex "gv:allow:$dev" 120 1 >/dev/null
for p in / /t/headers /t/nolength; do compare allow_override "$p" "${nav[@]}" -H "Cookie: _gv=$tok"; done
rcli del "gv:rep:$dev" "gv:allow:$dev" >/dev/null

clear_counters
[ "$failed" -eq 0 ] && { echo "OK: every allow path is byte-identical with the guard on and off."; exit 0; }
echo "FAIL: $failed comparison(s) differ."; exit 1
