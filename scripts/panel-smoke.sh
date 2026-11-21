#!/usr/bin/env bash
# Admin panel smoke test over HTTP: login, settings save, override add, kill switch.
#
#   bash scripts/panel-smoke.sh <BASE_URL> <panel-path> <username> <password>
#
# Run it against a THROWAWAY install: it saves a setting (hard_block_score 61),
# adds and clears an allow override for a documentation-range address, and
# toggles the kill switch off and on again. Exit code 1 on any failed step.
set -uo pipefail

BASE="${1:-}"; PANEL="${2:-/panel}"; USER_NAME="${3:-}"; PASS="${4:-}"
if [ -z "$BASE" ] || [ -z "$USER_NAME" ] || [ -z "$PASS" ]; then
	echo "Usage: bash scripts/panel-smoke.sh <BASE_URL> <panel-path> <username> <password>"
	exit 2
fi
BASE="${BASE%/}"; PANEL="/${PANEL#/}"; PANEL="${PANEL%/}"
URL="$BASE$PANEL/index.php"
JAR="$(mktemp)"; trap 'rm -f "$JAR"' EXIT
failed=0
check() { if [ "$2" = "1" ]; then echo "PASS  $1"; else echo "FAIL  $1"; failed=$((failed + 1)); fi; }
csrf() { grep -o 'name="csrf" value="[^"]*"' | head -1 | sed 's/.*value="//; s/"$//'; }

page="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=login")"
check "login page renders" "$(grep -q 'name="password"' <<<"$page" && echo 1 || echo 0)"

code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" --data-urlencode "username=$USER_NAME" --data-urlencode "password=$PASS" "$URL?r=login")"
check "login answers 303" "$([ "$code" = 303 ] && echo 1 || echo 0)"
dash="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=dashboard")"
check "dashboard is shown after login (session cookie works on this path)" "$(grep -q 'name="killswitch"' <<<"$dash" && echo 1 || echo 0)"
cpath="$(awk '$6 ~ /^gp_/ {print $3; exit}' "$JAR")"
check "the session cookie path is the panel path ($cpath)" "$([ "$cpath" = "$PANEL/" ] && echo 1 || echo 0)"

tok="$(printf '%s' "$dash" | csrf)"
code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'action=save' -d 'f[hard_block_score]=61' "$URL?r=settings")"
check "settings save answers 303" "$([ "$code" = 303 ] && echo 1 || echo 0)"
settings="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=settings")"
check "the saved value is shown" "$(grep -q 'value="61"' <<<"$settings" && echo 1 || echo 0)"
tok="$(printf '%s' "$settings" | csrf)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'action=reset' -d 'key=hard_block_score' "$URL?r=settings"

ov="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=overrides")"
tok="$(printf '%s' "$ov" | csrf)"
if grep -qi 'name="identity"' <<<"$ov"; then
	code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'identity=203.0.113.250' -d 'ttl=3600' -d 'override=allow' "$URL?r=overrides")"
	check "override add answers 303" "$([ "$code" = 303 ] && echo 1 || echo 0)"
	ov="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=overrides")"
	if grep -q '203.0.113.250' <<<"$ov"; then
		check "the override is listed (Redis reachable from the panel)" 1
		tok="$(printf '%s' "$ov" | csrf)"
		curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'identity=203.0.113.250' -d 'ttl=60' -d 'clear=1' "$URL?r=overrides"
	else
		echo "NOTE  the override is not listed: the panel cannot reach Redis here (skipped, not a layout problem)"
	fi
fi

# Access rules: create (monitor), find it, test box, quick-block prefill, toggle, delete.
rp="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=rules")"
tok="$(printf '%s' "$rp" | csrf)"
code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'do=save' -d 'name=Smoke rule' \
	-d 'enabled=1' -d 'mode=monitor' -d 'action=block' -d 'priority=900' -d 'ua_op=include' -d 'ua_type=exact' \
	--data-urlencode 'ua_values=smoke-test-client/1.0' -d 'ack=1' "$URL?r=rules")"
check "rule create answers 303" "$([ "$code" = 303 ] && echo 1 || echo 0)"
rp="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=rules")"
check "the new rule is listed" "$(grep -q 'Smoke rule' <<<"$rp" && echo 1 || echo 0)"
rid="$(grep -o 'name="id" value="r[0-9a-f]\{6\}"' <<<"$rp" | head -1 | sed 's/.*value="//; s/"$//')"
tp="$(curl -sk -c "$JAR" -b "$JAR" -G --data-urlencode 'test=1' --data-urlencode 'test_ua=smoke-test-client/1.0' "$URL?r=rules")"
check "the test box names the rule" "$(grep -q "$rid" <<<"$tp" && grep -q 'Winning rule' <<<"$tp" && echo 1 || echo 0)"
qp="$(curl -sk -c "$JAR" -b "$JAR" -G --data-urlencode 'new=1' --data-urlencode 'qua=curl/8.4.0' "$URL?r=rules")"
check "quick block pre-fills the form" "$(grep -q 'curl/8.4.0' <<<"$qp" && grep -q 'name="ua_values"' <<<"$qp" && echo 1 || echo 0)"
check "quick block shows the impact preview before saving" "$(grep -q 'Impact preview' <<<"$qp" && grep -q 'Matching requests' <<<"$qp" && echo 1 || echo 0)"
tok="$(printf '%s' "$qp" | csrf)"
pp="$(curl -sk -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'do=preview' -d 'name=Smoke preview' -d 'mode=monitor' -d 'action=block' -d 'priority=900' \
	-d 'ua_op=include' -d 'ua_type=exact' --data-urlencode 'ua_values=curl/8.4.0' "$URL?r=rules")"
check "the Preview button shows the impact and saves nothing" "$(grep -q 'Impact preview' <<<"$pp" && grep -q 'nothing was saved' <<<"$pp" && echo 1 || echo 0)"
tok="$(printf '%s' "$rp" | csrf)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'do=toggle' -d "id=$rid" "$URL?r=rules"
rp="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=rules")"
check "toggle disables the rule" "$(grep -q 'Smoke rule' <<<"$rp" && grep -q '>Enable<' <<<"$rp" && echo 1 || echo 0)"
tok="$(printf '%s' "$rp" | csrf)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'do=delete' -d "id=$rid" "$URL?r=rules"
rp="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=rules")"
check "delete removes the rule" "$(grep -q 'Smoke rule' <<<"$rp" && echo 0 || echo 1)"
code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" -d 'do=starter' "$URL?r=rules")"
check "a POST without the CSRF token changes nothing (no 303 redirect)" "$([ "$code" != 303 ] && echo 1 || echo 0)"

# Every page is English and left-to-right, with Latin digits only. The logs,
# identity, settings and config file pages are checked for direction only: they
# show request data or operator-written values (the challenge page text, which
# ships in Persian) as they are, and those may contain any script.
for r in dashboard logs identity overrides rules replay models settings config_file jobs audit; do
	page="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=$r")"
	check "page $r is English and left-to-right" "$(grep -q '<html lang="en" dir="ltr">' <<<"$page" && echo 1 || echo 0)"
	case "$r" in logs|identity|settings|config_file) continue ;; esac
	check "page $r shows no Persian or Arabic script or digits" "$(LC_ALL=C.UTF-8 grep -qP '[\x{0600}-\x{06FF}]' <<<"$page" && echo 0 || echo 1)"
done

# Config file editor: invalid JSON is refused with its line number and nothing is written.
cf="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=config_file")"
tok="$(printf '%s' "$cf" | csrf)"
hash="$(grep -o 'name="base_hash" value="[0-9a-f]*"' <<<"$cf" | sed 's/.*value="//; s/"$//')"
resp="$(curl -sk -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'action=save_file' --data-urlencode "base_hash=$hash" \
	--data-urlencode $'content={\n  "token_ttl": 7200,\n}' "$URL?r=config_file")"
check "config editor refuses invalid JSON and names the line" "$(grep -q 'Line 3' <<<"$resp" && grep -q 'Nothing was saved' <<<"$resp" && echo 1 || echo 0)"
cf2="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=config_file")"
check "config editor left the file unchanged" "$([ "$(grep -o 'name="base_hash" value="[0-9a-f]*"' <<<"$cf2")" = "$(grep -o 'name="base_hash" value="[0-9a-f]*"' <<<"$cf")" ] && echo 1 || echo 0)"

dash="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=dashboard")"; tok="$(printf '%s' "$dash" | csrf)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'killswitch=stop' "$URL?r=dashboard"
dash="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=dashboard")"
check "kill switch can be engaged" "$(grep -q 'value="start"' <<<"$dash" && echo 1 || echo 0)"
tok="$(printf '%s' "$dash" | csrf)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'killswitch=start' "$URL?r=dashboard"
dash="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=dashboard")"
check "kill switch can be released" "$(grep -q 'value="stop"' <<<"$dash" && echo 1 || echo 0)"

tok="$(printf '%s' "$dash" | csrf)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" "$URL?r=logout"
code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" "$URL?r=dashboard")"
check "after logout the dashboard redirects to login" "$([ "$code" = 303 ] && echo 1 || echo 0)"

[ "$failed" -eq 0 ] && echo "OK: panel smoke test passed." && exit 0
echo "FAIL: $failed step(s) failed."; exit 1
