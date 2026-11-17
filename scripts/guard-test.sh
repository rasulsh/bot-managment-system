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

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHP_BIN="${GV_PHP:-php}"

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

# The handshake needs the nonce's binding (same User-Agent) and its proof of
# work. This is what a bot would have to implement.
handshake() {   # $1 nonce, $2 cookie jar, [$3 user agent] -> prints the HTTP status
	local n="$1" jar="$2" ua="${3:-$CHROME_UA}" c
	c=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$n" 2>/dev/null)
	curl -sk -o /dev/null -w '%{http_code}' -X POST -H "User-Agent: $ua" \
		-H "X-GV: $n" -H "X-GV-P: $c" -c "$jar" "$BASE_URL/"
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
nonce=$(printf '%s' "$body" | sed -n "s/.*var N = '\([0-9a-f.]*\)'.*/\1/p" | head -1)
if [ -z "$nonce" ]; then
	row '4a extract nonce from challenge body' 'none' 'n/a (no challenge)' 'nonce found'
	row '4b POST handshake with X-GV' 'SKIP' 'n/a' '204'
	row '4c GET / with the issued cookie' 'SKIP' 'n/a' '200'
else
	row '4a extract nonce from challenge body' 'ok' 'n/a (no challenge)' 'nonce found'
	got=$(handshake "$nonce" "$jar")
	row '4b POST handshake with X-GV' "$got" '204' '204'
	got=$(browser -o /dev/null -w '%{http_code}' -b "$jar" "$BASE_URL/")
	row '4c GET / with the issued cookie' "$got" '200' '200'
fi
rm -f "$jar"

# 4d-4h. Challenge hardening. Each case fetches its own nonce.
fresh_nonce() {   # $1 = optional extra curl args (e.g. another User-Agent)
	browser "$BASE_URL/?gv=n$RANDOM" | sed -n "s/.*var N = '\([0-9a-f.]*\)'.*/\1/p" | head -1
}
n1=$(fresh_nonce)
if [ -n "$n1" ]; then
	pow=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$n1")
	# Same nonce, replayed 6 times with a valid proof: exactly one token.
	ok_count=0
	for i in $(seq 1 6); do
		c=$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H "User-Agent: $CHROME_UA" \
			-H "X-GV: $n1" -H "X-GV-P: $pow" "$BASE_URL/")
		[ "$c" = '204' ] && ok_count=$((ok_count + 1))
	done
	row '4d one nonce replayed 6x yields tokens' "$ok_count" '6 (no Redis state)' '1'
	n2=$(fresh_nonce)
	got=$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H "User-Agent: $CHROME_UA" -H "X-GV: $n2" "$BASE_URL/")
	row '4e handshake without a proof of work' "$got" '204 (shadow)' '403'
	n3=$(fresh_nonce)
	pow3=$("$PHP_BIN" "$ROOT/scripts/pow-solve.php" "$n3")
	got=$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H 'User-Agent: python-requests/2.31' \
		-H "X-GV: $n3" -H "X-GV-P: $pow3" "$BASE_URL/")
	row '4f nonce used with another User-Agent' "$got" '403' '403'
else
	row '4d-4f challenge hardening' 'SKIP' 'n/a' 'no challenge served'
fi
# The tiny dev limits would otherwise carry these extra requests into case 5+.
if command -v "${REDIS_CLI:-redis-cli}" >/dev/null 2>&1; then
	for pattern in 'gv:ri:*' 'gv:riu:*' 'gv:rd:*' 'gv:mint:*'; do
		keys=$("${REDIS_CLI:-redis-cli}" ${REDIS_ARGS:--h 127.0.0.1 -p 6379} --scan --pattern "$pattern" 2>/dev/null)
		[ -n "$keys" ] && echo "$keys" | xargs -r "${REDIS_CLI:-redis-cli}" ${REDIS_ARGS:--h 127.0.0.1 -p 6379} del >/dev/null 2>&1
	done
fi

# 5. Honeypot fires regardless of the enforce toggles.
got=$(browser -o /dev/null -w '%{http_code}' "$BASE_URL/old-archive")
row '5 GET the honeypot path' "$got" '404' '404'

# 6. Exemption proof (requires exempt_paths to contain /exempt-me).
got=$(browser -o /dev/null -w '%{http_code}' "$BASE_URL/exempt-me")
row '6 GET /exempt-me' "$got" '200' '200'

# 7. XHR POST without a cookie must never be challenged.
got=$(browser -o /dev/null -w '%{http_code}' -X POST -H 'X-Requested-With: XMLHttpRequest' -d 'a=1' "$BASE_URL/")
row '7 POST as XHR without a cookie' "$got" '200' '200'

# 7b-7e. The challenge does not depend on headers the client chooses. A GET
# with curl's default Accept, a GET that claims to be XHR and a GET with no
# Accept at all used to walk past the challenge; each must get it now.
got=$(curl -sk -o /dev/null -w '%{http_code}' -H "User-Agent: $CHROME_UA" -H 'Accept-Language: en-US,en;q=0.9' \
	-H 'Accept-Encoding: gzip' -H 'Sec-Fetch-Mode: cors' "$BASE_URL/product/7b")
row '7b GET with Accept: */*, no cookie' "$got" '200' '503'
got=$(curl -sk -o /dev/null -w '%{http_code}' -H "User-Agent: $CHROME_UA" -H 'Accept-Language: en-US,en;q=0.9' \
	-H 'Accept-Encoding: gzip' -H 'Sec-Fetch-Mode: cors' -H 'Accept: application/json' \
	-H 'X-Requested-With: XMLHttpRequest' "$BASE_URL/product/7c")
row '7c GET claiming XHR, no cookie' "$got" '200' '503'
got=$(curl -sk -o /dev/null -w '%{http_code}' -H "User-Agent: $CHROME_UA" -H 'Accept-Language: en-US,en;q=0.9' \
	-H 'Accept-Encoding: gzip' -H 'Sec-Fetch-Mode: cors' -H 'Accept:' "$BASE_URL/product/7d")
row '7d GET with no Accept header, no cookie' "$got" '200' '503'
# A link-preview fetcher cannot solve a challenge; it passes inside a small
# site-wide budget (needs Redis: without a counter there is no pass).
got=$(curl -sk -o /dev/null -w '%{http_code}' -H 'User-Agent: TelegramBot (like TwitterBot)' -H 'Accept: text/html' "$BASE_URL/product/7e")
row '7e link preview (TelegramBot UA)' "$got" '200' '200 (503 without Redis)'

# 7f-7h. HEAD runs the application like GET, so it is challenged like GET. A
# token-less POST is served (payment callbacks) and only logged as a shadow
# challenge until challenge.gate_post is on. And a parameter exemption cannot be
# borrowed by appending it to an ordinary page URL.
got=$(curl -sk -o /dev/null -w '%{http_code}' -I -H "User-Agent: $CHROME_UA" -H 'Accept-Language: en-US,en;q=0.9' \
	-H 'Accept-Encoding: gzip' -H 'Sec-Fetch-Mode: navigate' "$BASE_URL/product/7f")
row '7f HEAD, no cookie' "$got" '200' '503'
got=$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H "User-Agent: $CHROME_UA" -H 'Accept-Language: en-US,en;q=0.9' \
	-H 'Accept-Encoding: gzip' -H 'Sec-Fetch-Mode: cors' -d 'a=1' "$BASE_URL/product/7g")
row '7g POST, no cookie (gate_post off)' "$got" '200' '200'
got=$(curl -sk -o /dev/null -w '%{http_code}' -H "User-Agent: $CHROME_UA" -H 'Accept: text/html' -H 'Accept-Language: en-US,en;q=0.9' \
	-H 'Accept-Encoding: gzip' -H 'Sec-Fetch-Mode: navigate' "$BASE_URL/product/7h?route=payment/x")
row '7h exempt param on a page URL' "$got" '200' '503'

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
	row '13 allow override on a blocked device' 'SKIP' 'n/a' '200 allow_override'
	row '14 deny override on a clean device' 'SKIP' 'n/a' '403'
	row '15 holdout identity is measured only' 'SKIP' 'n/a' '200 with hold=1'
	row '16 same request outside the holdout' 'SKIP' 'n/a' '403'
	echo
	echo "SKIP-note: cases 9-16 need redis-cli and a reachable Redis to seed"
	echo "verdicts and overrides. Without Redis the guard reads no verdict, no"
	echo "override and no holdout-relevant state, and behaves exactly as it did"
	echo "in Phase 1 - that is the expected degraded result, not a failure."
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
	nonce=$(printf '%s' "$body" | sed -n "s/.*var N = '\([0-9a-f.]*\)'.*/\1/p" | head -1)
	dev=''
	if [ -n "$nonce" ]; then
		handshake "$nonce" "$jar" >/dev/null 2>&1
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

		# 13/14. Operator overrides. Allow short-circuits to 200 with no
		# scoring; deny forces 403. Both are keyed on the device id.
		$REDIS_CLI $REDIS_ARGS setex "gv:rep:$dev" 120 80 >/dev/null 2>&1
		$REDIS_CLI $REDIS_ARGS setex "gv:allow:$dev" 120 1 >/dev/null 2>&1
		got=$(browser -o /dev/null -w '%{http_code}' -b "$jar" "$BASE_URL/?gv=allowovr")
		row '13 allow override on a blocked device' "$got" '200' '200 allow_override'
		$REDIS_CLI $REDIS_ARGS del "gv:allow:$dev" "gv:rep:$dev" >/dev/null 2>&1

		$REDIS_CLI $REDIS_ARGS setex "gv:deny:$dev" 120 1 >/dev/null 2>&1
		got=$(browser -o /dev/null -w '%{http_code}' -b "$jar" "$BASE_URL/?gv=denyovr")
		row '14 deny override on a clean device' "$got" '200' '403'
		$REDIS_CLI $REDIS_ARGS del "gv:deny:$dev" >/dev/null 2>&1

		# 15/16. The holdout. Membership is deterministic per identity, so the
		# matrix asks the guard itself which device id lands in the holdout
		# under the dev config, then mints a real token for it. The dev config
		# publishes its secret, which is exactly what makes this possible here
		# and impossible in production.
		hold_pair=$("$PHP_BIN" "$ROOT/scripts/holdout-probe.php" 2>/dev/null)
		hold_dev="${hold_pair%% *}"
		hold_tok="${hold_pair##* }"
		free_pair=$("$PHP_BIN" "$ROOT/scripts/holdout-probe.php" --outside 2>/dev/null)
		free_dev="${free_pair%% *}"
		free_tok="${free_pair##* }"

		if [ -z "$hold_dev" ] || [ -z "$free_dev" ]; then
			row '15 holdout identity is measured only' 'SKIP' 'n/a' '200 with hold=1'
			row '16 same request outside the holdout' 'SKIP' 'n/a' '403'
			echo
			echo "SKIP-note: could not resolve a holdout identity (is holdout_pct 0?)."
		else
			# Seed a reputation high enough to block, on both identities. The
			# only difference between them is holdout membership.
			$REDIS_CLI $REDIS_ARGS setex "gv:rep:$hold_dev" 120 80 >/dev/null 2>&1
			$REDIS_CLI $REDIS_ARGS setex "gv:rep:$free_dev" 120 80 >/dev/null 2>&1
			got=$(browser -o /dev/null -w '%{http_code}' \
				-H "Cookie: _gv=$hold_tok" "$BASE_URL/?gv=holdout")
			row '15 holdout identity is measured only' "$got" '200' '200 with hold=1'
			got=$(browser -o /dev/null -w '%{http_code}' \
				-H "Cookie: _gv=$free_tok" "$BASE_URL/?gv=enforced")
			row '16 same request outside the holdout' "$got" '200' '403'
			$REDIS_CLI $REDIS_ARGS del "gv:rep:$hold_dev" "gv:rep:$free_dev" >/dev/null 2>&1
		fi
	fi
	rm -f "$jar"

	# 20. Three-state bot verification: a genuine Googlebot smartphone request
	# stays 200 across a simulated resolver outage (nothing is written), and a
	# forged one is still caught. Needs python3 + the analyzer and the dev
	# router's log directory.
	VERIFY_LOG_DIR="${GV_LOG_DIR:-${TMPDIR:-/tmp}/gv-logs}"
	if command -v python3 >/dev/null 2>&1 && [ -d "$VERIFY_LOG_DIR" ]; then
		v=$(python3 "$ROOT/scripts/verify-e2e.py" "$BASE_URL" "$VERIFY_LOG_DIR" 2>/dev/null)
		set -- $v
		row '20a Googlebot smartphone UA, no verdict' "${1:-ERR}" '200' '200'
		row '20b ... across a resolver outage' "${2:-ERR}" '200' '200'
		row '20c ... forged (definitive mismatch)' "${3:-ERR}" '200' '403'
	else
		row '20 three-state verification' 'SKIP' 'n/a' '200 / 200 / 403'
	fi
fi

# --- Phase 4: response outcome capture -------------------------------------
#
# These cases read the log directory directly, so they only run against the
# local dev router. Against a remote deployment they SKIP.
echo
GV_LOG_DIR="${GV_LOG_DIR:-${TMPDIR:-/tmp}/gv-logs}"
LOG_FILE="$GV_LOG_DIR/guard-$(date +%Y%m%d).jsonl"

outcomes_for() {   # $1 = path, prints the st of the newest outcome for that path
	"$JQ_BIN" -s --arg p "$1" '
		(map(select(.o != 1 and .p == $p)) | last) as $d
		| if $d == null then "no-decision"
		  else (map(select(.o == 1 and .rid == $d.rid)) | last) as $o
		       | if $o == null then "no-outcome" else ($o.st|tostring) end
		  end' "$LOG_FILE" 2>/dev/null | tr -d '"'
}

JQ_BIN="${JQ:-jq}"
if ! command -v "$JQ_BIN" >/dev/null 2>&1 || [ ! -r "$LOG_FILE" ]; then
	row '17 outcome line for an allowed 404' 'SKIP' 'n/a' 'st=404'
	row '18 outcome line for a fatal error' 'SKIP' 'n/a' 'st=500'
	row '19 no outcome line for a challenge' 'SKIP' 'n/a' 'none'
	echo
	echo "SKIP-note: cases 17-19 read the guard log directly and need jq plus a"
	echo "readable log directory, so they only run against the local dev router."
	echo "Set GV_LOG_DIR to point at one elsewhere."
else
	jar4=$(mktemp)
	body=$(browser "$BASE_URL/?gv=p4seed")
	nonce=$(printf '%s' "$body" | sed -n "s/.*var N = '\([0-9a-f.]*\)'.*/\1/p" | head -1)
	if [ -n "$nonce" ]; then
		handshake "$nonce" "$jar4" >/dev/null 2>&1
	fi

	# 17. An allowed request the application 404s: the status the guard never
	# saw before this phase.
	got=$(browser -o /dev/null -w '%{http_code}' -b "$jar4" "$BASE_URL/t/404")
	sleep 0.3
	st=$(outcomes_for '/t/404')
	row "17 outcome for an allowed 404 (http $got)" "st=$st" 'st=404' 'st=404'

	# 18. A request that fatals still reaches the shutdown handler.
	got=$(browser -o /dev/null -w '%{http_code}' -b "$jar4" "$BASE_URL/t/fatal")
	sleep 0.3
	st=$(outcomes_for '/t/fatal')
	row "18 outcome for a fatal error (http $got)" "st=$st" 'st=500' 'st=500'

	# 19. A challenge is the guard's own response: no outcome line may exist.
	curl -sk -o /dev/null -w '%{http_code}' -H "User-Agent: $CHROME_UA" \
		-H "Accept: $ACCEPT_HTML" -H 'Accept-Language: en-US' \
		-H 'Sec-Fetch-Mode: navigate' "$BASE_URL/?gv=p4chal" >/dev/null 2>&1
	sleep 0.3
	chal_rid=$("$JQ_BIN" -r -s '(map(select(.o != 1 and .q == "gv=p4chal")) | last | .rid) // ""' \
		"$LOG_FILE" 2>/dev/null)
	if [ -z "$chal_rid" ]; then
		row '19 no outcome line for a challenge' 'SKIP' 'n/a' 'none'
	else
		n_out=$("$JQ_BIN" -s --arg r "$chal_rid" '[.[] | select(.o == 1 and .rid == $r)] | length' \
			"$LOG_FILE" 2>/dev/null)
		row '19 no outcome line for a challenge' "$n_out outcome(s)" '0' '0'
	fi
	rm -f "$jar4"
fi

echo
echo "Inspect the log directory for one JSONL line per request above."
echo "Phase 2 fields to watch: botv, rep, ml, and esc next to sc."
echo "Phase 4: decision lines carry v and rid; outcome lines carry o=1 and the"
echo "same rid. Capture is off unless capture_outcomes is enabled."
echo "Default deployment path: <guard>/logs/guard-$(date +%Y%m%d).jsonl"
echo "Dev router (scripts/config.dev.php) path: ${TMPDIR:-/tmp}/gv-logs/guard-$(date +%Y%m%d).jsonl"
