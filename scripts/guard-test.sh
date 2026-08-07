#!/usr/bin/env bash
# Bot Guard HTTP test matrix.
#
# Run against the local dev router:
#   php -S 127.0.0.1:8080 scripts/dev-router.php &
#   bash scripts/guard-test.sh http://127.0.0.1:8080
#
# Or against any deployment. The "expected(enforced)" column assumes a config
# with every enforce toggle on and the exemptions of scripts/config.dev.php.
set -uo pipefail

BASE_URL="${1:-}"
if [ -z "$BASE_URL" ]; then
	echo "Usage: bash scripts/guard-test.sh <BASE_URL>"
	echo "Example: bash scripts/guard-test.sh http://127.0.0.1:8080"
	exit 1
fi
BASE_URL="${BASE_URL%/}"

CHROME_UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
ACCEPT_HTML='text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'

# Full browser-like header set: enough headers to clear FEW_HDR and score 0.
browser() {
	curl -sk \
		-H "User-Agent: $CHROME_UA" \
		-H "Accept: $ACCEPT_HTML" \
		-H 'Accept-Language: en-US,en;q=0.9' \
		-H 'Sec-Fetch-Mode: navigate' \
		-H 'Sec-Fetch-Site: none' \
		"$@"
}

row() {
	printf '%-44s | %-6s | %-18s | %s\n' "$1" "$2" "$3" "$4"
}

echo "Bot Guard HTTP test matrix against $BASE_URL"
echo
printf '%-44s | %-6s | %-18s | %s\n' 'case' 'got' 'expected(monitor)' 'expected(enforced)'
printf -- '---------------------------------------------+--------+--------------------+-------------------\n'

# 1. No User-Agent on a navigation: UA_EMPTY + NO_AL + FEW_HDR = 70 >= 60.
got=$(curl -sk -o /dev/null -w '%{http_code}' -H 'User-Agent:' -H "Accept: $ACCEPT_HTML" "$BASE_URL/")
row '1 GET / with no User-Agent' "$got" '200' '403'

# 2. Scripted client on a navigation: UA_SCRIPT + NO_AL + FEW_HDR = 60 >= 60.
got=$(curl -sk -o /dev/null -w '%{http_code}' -H 'User-Agent: python-requests/2.31' -H "Accept: $ACCEPT_HTML" "$BASE_URL/")
row '2 GET / as python-requests' "$got" '200' '403 or 503'

# 3. Clean browser navigation without a token: score 0, challenge by rule (c).
got=$(browser -o /dev/null -w '%{http_code}' "$BASE_URL/")
row '3 GET / as a browser, no cookie' "$got" '200' '503'

# 4. Full handshake: challenge -> POST X-GV -> token cookie -> allowed.
jar=$(mktemp)
body=$(browser "$BASE_URL/")
nonce=$(printf '%s' "$body" | sed -n "s/.*'X-GV': '\([0-9a-f.]*\)'.*/\1/p" | head -1)
if [ -z "$nonce" ]; then
	row '4a extract nonce from challenge body' 'none' 'n/a (no challenge)' 'nonce found'
	row '4b POST handshake with X-GV' 'SKIP' 'n/a' '204'
	row '4c GET / with the issued cookie' 'SKIP' 'n/a' '200'
else
	row '4a extract nonce from challenge body' 'ok' 'n/a (no challenge)' 'nonce found'
	got=$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H "X-GV: $nonce" -c "$jar" "$BASE_URL/")
	row '4b POST handshake with X-GV' "$got" '204' '204'
	got=$(browser -o /dev/null -w '%{http_code}' -b "$jar" "$BASE_URL/")
	row '4c GET / with the issued cookie' "$got" '200' '200'
fi
rm -f "$jar"

# 5. Honeypot fires regardless of the enforce toggles.
got=$(browser -o /dev/null -w '%{http_code}' "$BASE_URL/old-archive")
row '5 GET the honeypot path' "$got" '404' '404'

# 6. Exemption proof (requires exempt_paths to contain /exempt-me).
got=$(browser -o /dev/null -w '%{http_code}' "$BASE_URL/exempt-me")
row '6 GET /exempt-me' "$got" '200' '200'

# 7. XHR POST without a cookie must never be challenged.
got=$(browser -o /dev/null -w '%{http_code}' -X POST -H 'X-Requested-With: XMLHttpRequest' -d 'a=1' "$BASE_URL/")
row '7 POST as XHR without a cookie' "$got" '200' '200'

# 8. Rate limit: 30 rapid navigations from one UA. Needs Redis.
codes=''
saw429=0
for i in $(seq 1 30); do
	c=$(browser -o /dev/null -w '%{http_code}' "$BASE_URL/?rl=$i")
	codes="$codes $c"
	[ "$c" = '429' ] && saw429=1
done
if [ "$saw429" = '1' ]; then
	row '8 30 rapid GETs from one UA' '429' '200' '429 once over limit'
else
	last=$(printf '%s' "$codes" | awk '{print $NF}')
	row '8 30 rapid GETs from one UA' "$last" '200' '429 once over limit'
	echo
	echo "SKIP-note: case 8 saw no 429. Rate limiting needs Redis; without it the"
	echo "guard runs in degraded mode (rd=1 in the logs) and all counters stay 0."
fi

# --- Phase 2: verdicts injected into Redis ---------------------------------
#
# These cases seed the keys the Python analyzer would normally write and check
# the documented effect. They need redis-cli and a reachable Redis; without one
# they SKIP, and the Phase 1 outcomes above are still the pass.
echo
GOOGLEBOT_UA='Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
REDIS_CLI="${REDIS_CLI:-redis-cli}"
REDIS_ARGS="${REDIS_ARGS:--h 127.0.0.1 -p 6379}"

redis_up=0
if command -v "$REDIS_CLI" >/dev/null 2>&1; then
	if [ "$($REDIS_CLI $REDIS_ARGS ping 2>/dev/null)" = 'PONG' ]; then
		redis_up=1
	fi
fi

if [ "$redis_up" = '0' ]; then
	row '9 known bot with gv:botok seeded' 'SKIP' 'n/a' 'allow_bot 200'
	row '10 known bot with gv:botbad seeded' 'SKIP' 'n/a' '403 with BOT_FAKE'
	row '11 device with gv:rep seeded' 'SKIP' 'n/a' 'esc raised'
	row '12 device with gv:ml seeded' 'SKIP' 'n/a' 'esc raised'
	echo
	echo "SKIP-note: cases 9-12 need redis-cli and a reachable Redis to seed"
	echo "verdicts. Without Redis the guard has no verdicts to read and behaves"
	echo "exactly as it did in Phase 1 - that is the expected degraded result."
else
	# The client IP the dev server sees. Verdict keys are per address.
	CLIENT_IP="${GV_CLIENT_IP:-127.0.0.1}"
	# Case 5 left a honeypot mark on this address (+40 HP_HIST) and case 8 blew
	# through the tiny dev limits. Clear both so each case below isolates the
	# one Phase 2 signal it is meant to demonstrate.
	$REDIS_CLI $REDIS_ARGS del "gv:botok:$CLIENT_IP" "gv:botbad:$CLIENT_IP" \
		"gv:hp:$CLIENT_IP" >/dev/null 2>&1

	# Clear the rate counters so the cases below exercise the verdict path
	# rather than the 429.
	for pattern in 'gv:ri:*' 'gv:riu:*' 'gv:rd:*' 'gv:rb:*'; do
		keys=$($REDIS_CLI $REDIS_ARGS --scan --pattern "$pattern" 2>/dev/null)
		[ -n "$keys" ] && echo "$keys" | xargs -r $REDIS_CLI $REDIS_ARGS del >/dev/null 2>&1
	done

	# 9. A forward-confirmed bot keeps its Phase 1 pass and is stamped botv=ok.
	$REDIS_CLI $REDIS_ARGS setex "gv:botok:$CLIENT_IP" 120 1 >/dev/null 2>&1
	got=$(curl -sk -o /dev/null -w '%{http_code}' -H "User-Agent: $GOOGLEBOT_UA" \
		-H "Accept: $ACCEPT_HTML" "$BASE_URL/?gv=botok")
	row '9 known bot with gv:botok seeded' "$got" '200' '200 allow_bot'
	$REDIS_CLI $REDIS_ARGS del "gv:botok:$CLIENT_IP" >/dev/null 2>&1

	# 10. An impersonator loses the pass and is scored: NO_AL + FEW_HDR + BOT_FAKE.
	$REDIS_CLI $REDIS_ARGS setex "gv:botbad:$CLIENT_IP" 120 1 >/dev/null 2>&1
	got=$(curl -sk -o /dev/null -w '%{http_code}' -H "User-Agent: $GOOGLEBOT_UA" \
		-H "Accept: $ACCEPT_HTML" "$BASE_URL/?gv=botbad")
	row '10 known bot with gv:botbad seeded' "$got" '200' '403'
	$REDIS_CLI $REDIS_ARGS del "gv:botbad:$CLIENT_IP" >/dev/null 2>&1

	# 11/12. Reputation and anomaly level on a real device. Complete the
	# handshake first: the device_id is the leading field of the token cookie.
	jar=$(mktemp)
	body=$(browser "$BASE_URL/?gv=seed")
	nonce=$(printf '%s' "$body" | sed -n "s/.*'X-GV': '\([0-9a-f.]*\)'.*/\1/p" | head -1)
	dev=''
	if [ -n "$nonce" ]; then
		curl -sk -o /dev/null -X POST -H "X-GV: $nonce" -c "$jar" "$BASE_URL/" >/dev/null 2>&1
		dev=$(awk '$6 == "_gv" {print $7}' "$jar" | head -1 | cut -d. -f1)
	fi

	if [ -z "$dev" ]; then
		row '11 device with gv:rep seeded' 'SKIP' 'n/a' 'esc raised'
		row '12 device with gv:ml seeded' 'SKIP' 'n/a' 'esc raised'
		echo
		echo "SKIP-note: cases 11-12 need a completed handshake to obtain a device_id."
	else
		# A tokened device is normally allowed; a high reputation must block it.
		$REDIS_CLI $REDIS_ARGS setex "gv:rep:$dev" 120 80 >/dev/null 2>&1
		got=$(browser -o /dev/null -w '%{http_code}' -b "$jar" "$BASE_URL/?gv=rep")
		row '11 device with gv:rep=80 seeded' "$got" '200' '403'
		$REDIS_CLI $REDIS_ARGS del "gv:rep:$dev" >/dev/null 2>&1

		# 100 * 0.4 = 40 on its own is below the block score, so pair it with a
		# mild reputation to show the two signals folding together.
		$REDIS_CLI $REDIS_ARGS setex "gv:ml:$dev" 120 100 >/dev/null 2>&1
		got=$(browser -o /dev/null -w '%{http_code}' -b "$jar" "$BASE_URL/?gv=ml")
		row '12 device with gv:ml=100 seeded' "$got" '200' '200 (40 < block score)'
		$REDIS_CLI $REDIS_ARGS setex "gv:rep:$dev" 120 25 >/dev/null 2>&1
		got=$(browser -o /dev/null -w '%{http_code}' -b "$jar" "$BASE_URL/?gv=both")
		row '12b gv:ml=100 plus gv:rep=25' "$got" '200' '403'
		$REDIS_CLI $REDIS_ARGS del "gv:ml:$dev" "gv:rep:$dev" >/dev/null 2>&1
	fi
	rm -f "$jar"
fi

echo
echo "Inspect the log directory for one JSONL line per request above."
echo "Phase 2 fields to watch: botv, rep, ml, and esc next to sc."
echo "Default deployment path: <guard>/logs/guard-$(date +%Y%m%d).jsonl"
echo "Dev router (scripts/config.dev.php) path: ${TMPDIR:-/tmp}/gv-logs/guard-$(date +%Y%m%d).jsonl"
