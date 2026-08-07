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

echo
echo "Inspect the log directory for one JSONL line per request above."
echo "Default deployment path: <guard>/logs/guard-$(date +%Y%m%d).jsonl"
echo "Dev router (scripts/config.dev.php) path: ${TMPDIR:-/tmp}/gv-logs/guard-$(date +%Y%m%d).jsonl"
