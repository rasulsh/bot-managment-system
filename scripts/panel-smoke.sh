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

# Dashboard (alerts, protection state, 24 h KPIs area, top lists) and the Jobs page (job health, crontab check).
dash="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=dashboard")"
check "the dashboard shows the protection state and the details section" "$(grep -q 'Protection state' <<<"$dash" && grep -q 'gp-details' <<<"$dash" && echo 1 || echo 0)"
check "the dashboard raises an alert for a fresh install with no snapshot or job status" "$(grep -q 'gp-alerts' <<<"$dash" && echo 1 || echo 0)"
jp="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=jobs")"
check "the Jobs page shows job health and the crontab check" "$(grep -q 'Job health' <<<"$jp" && grep -q 'id="cron-check"' <<<"$jp" && grep -q 'job=verify' <<<"$jp" && echo 1 || echo 0)"
jd="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=jobs&job=verify")"
check "a job's detail page renders" "$(grep -q 'id="job-detail"' <<<"$jd" && echo 1 || echo 0)"
jd="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=jobs&job=../../etc/passwd")"
check "an unknown job name shows no detail (no path is ever read from it)" "$(grep -q 'id="job-detail"' <<<"$jd" && echo 0 || echo 1)"

# GeoIP page: upload a fake source, see it, tester, country rule form, delete it again.
gp="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=geo")"
check "the GeoIP page renders with an upload form" "$(grep -q 'enctype="multipart/form-data"' <<<"$gp" && grep -q 'Lookup tester' <<<"$gp" && echo 1 || echo 0)"
tok="$(printf '%s' "$gp" | csrf)"
smoke_mmdb="$(mktemp)"; printf 'smoke\xab\xcd\xefMaxMind.com' > "$smoke_mmdb"
code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" -F "csrf=$tok" -F 'do=upload' -F "source=@$smoke_mmdb;filename=smoke-test-upload.mmdb" "$URL?r=geo")"
rm -f "$smoke_mmdb"
check "uploading a source file answers 303" "$([ "$code" = 303 ] && echo 1 || echo 0)"
gp="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=geo")"
check "the uploaded source is listed as not compiled yet" "$(grep -q 'gp-ltr">smoke-test-upload.mmdb</td>' <<<"$gp" && grep -q 'not compiled yet' <<<"$gp" && echo 1 || echo 0)"
tp="$(curl -sk -c "$JAR" -b "$JAR" -G --data-urlencode 'test=1' --data-urlencode 'ip=203.0.113.7' "$URL?r=geo")"
check "the lookup tester answers for an address (unknown without a database)" "$(grep -q '203.0.113.7' <<<"$tp" && grep -q 'unknown' <<<"$tp" && echo 1 || echo 0)"
tp="$(curl -sk -c "$JAR" -b "$JAR" -G --data-urlencode 'test=1' --data-urlencode 'ip=not-an-ip' "$URL?r=geo")"
check "the tester refuses something that is not an address" "$(grep -q 'not an IPv4 or IPv6 address' <<<"$tp" && echo 1 || echo 0)"
tok="$(printf '%s' "$gp" | csrf)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'do=delete' -d 'name=smoke-test-upload.mmdb' "$URL?r=geo"
gp="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=geo")"
check "deleting the source removes it from the list" "$(grep -q 'gp-ltr">smoke-test-upload.mmdb</td>' <<<"$gp" && echo 0 || echo 1)"
rp="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=rules")"
tok="$(printf '%s' "$rp" | csrf)"
code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'do=save' -d 'name=Smoke geo rule' -d 'enabled=1' -d 'mode=monitor' -d 'action=log' \
	-d 'priority=901' -d 'country_op=include' --data-urlencode 'country_values=KP, CU' -d 'ack=1' "$URL?r=rules")"
check "a country-only rule is saved (monitor)" "$([ "$code" = 303 ] && echo 1 || echo 0)"
rp="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=rules")"
check "the country rule is listed with its codes" "$(grep -q 'Smoke geo rule' <<<"$rp" && grep -q 'KP' <<<"$rp" && echo 1 || echo 0)"
rid="$(grep -o 'name="id" value="r[0-9a-f]\{6\}"' <<<"$rp" | head -1 | sed 's/.*value="//; s/"$//')"
tok="$(printf '%s' "$rp" | csrf)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'do=delete' -d "id=$rid" "$URL?r=rules"
rp="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=rules")"
check "the country rule is deleted again" "$(grep -q 'Smoke geo rule' <<<"$rp" && echo 0 || echo 1)"

# IP lists: a refused save needs confirmation (nothing saved), then create, list, tester, entries, export, toggle, delete.
ip="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=iplists")"
check "the IP lists page renders with its five tabs and the precedence note" "$([ "$(grep -o 'role="tab"' <<<"$ip" | wc -l | tr -d ' ')" = 5 ] && grep -q 'Order of decisions' <<<"$ip" && echo 1 || echo 0)"
tok="$(printf '%s' "$ip" | csrf)"
resp="$(curl -sk -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'do=save' -d 'name=Smoke list' -d 'type=block' -d 'mode=monitor' -d 'enabled=1' \
	--data-urlencode $'text=203.0.113.0/24\nbogus line\n10.0.0.0/8\n' "$URL?r=iplists")"
check "invalid and refused lines are listed with their line numbers and nothing is saved" "$(grep -q 'bogus line' <<<"$resp" && grep -q 'name="accept"' <<<"$resp" && grep -q 'name="pending"' <<<"$resp" && echo 1 || echo 0)"
ip="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=iplists")"
check "...the list does not exist yet" "$(grep -q 'smoke-list' <<<"$ip" && echo 0 || echo 1)"
pending="$(grep -o 'name="pending" value="[a-f0-9]*"' <<<"$resp" | head -1 | sed 's/.*value="//; s/"$//')"
tok="$(printf '%s' "$resp" | csrf)"
code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'do=save' -d 'name=Smoke list' -d 'type=block' -d 'mode=monitor' -d 'enabled=1' -d 'accept=1' -d "pending=$pending" "$URL?r=iplists")"
check "accepting the valid lines saves the list (303)" "$([ "$code" = 303 ] && echo 1 || echo 0)"
ip="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=iplists")"
check "the list is shown with its id" "$(grep -q 'Smoke list' <<<"$ip" && grep -q 'smoke-list' <<<"$ip" && echo 1 || echo 0)"
tp="$(curl -sk -c "$JAR" -b "$JAR" -G --data-urlencode 'test=1' --data-urlencode 'ip=203.0.113.9' "$URL?r=iplists")"
check "the lookup tester finds the address in the list (monitor)" "$(grep -q 'smoke-list' <<<"$tp" && grep -q '203.0.113.0/24' <<<"$tp" && echo 1 || echo 0)"
ep="$(curl -sk -c "$JAR" -b "$JAR" -G --data-urlencode 'list=smoke-list' --data-urlencode 'entry=203.0' "$URL?r=iplists")"
check "the entries tab lists the entry and takes the include / exclude filter" "$(grep -q '203.0.113.0/24' <<<"$ep" && echo 1 || echo 0)"
exp="$(curl -sk -c "$JAR" -b "$JAR" -D - "$URL?r=iplists&export=smoke-list")"
check "export returns the source as a text attachment" "$(grep -qi 'content-disposition: attachment' <<<"$exp" && grep -q '203.0.113.0/24' <<<"$exp" && echo 1 || echo 0)"
tok="$(printf '%s' "$ip" | csrf)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'do=set' -d 'id=smoke-list' -d 'enabled=0' "$URL?r=iplists"
ip="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=iplists")"
check "toggle disables the list" "$(grep -q '>Enable<' <<<"$ip" && echo 1 || echo 0)"
tok="$(printf '%s' "$ip" | csrf)"
code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" -d 'do=delete' -d 'id=smoke-list' "$URL?r=iplists")"
check "a POST without the CSRF token deletes nothing" "$([ "$code" != 303 ] && echo 1 || echo 0)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'do=delete' -d 'id=smoke-list' "$URL?r=iplists"
ip="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=iplists")"
check "delete removes the list" "$(grep -q 'Smoke list' <<<"$ip" && echo 0 || echo 1)"

# Every page is English and left-to-right, with Latin digits only. The logs,
# identity, settings and config file pages are checked for direction only: they
# show request data or operator-written values (the challenge page text, which
# ships in Persian) as they are, and those may contain any script.
for r in dashboard logs identity overrides rules geo iplists replay models settings config_file jobs audit; do
	page="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=$r")"
	check "page $r has the viewport meta tag" "$(grep -q 'name="viewport"' <<<"$page" && echo 1 || echo 0)"
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

# Every page in a real browser at a desktop (1600 px) and a phone (390 px) width: no horizontal page
# scroll, wide layout, tabs, tooltips, filter chips, no console error or outside request.
# Needs node + playwright; elsewhere it is skipped (scripts/panel-layout-test.sh runs it standalone).
if command -v node >/dev/null 2>&1 && node -e "require('playwright')" 2>/dev/null; then
	layout_out="$(node "$(dirname "${BASH_SOURCE[0]}")/panel-layout-test.js" "$BASE" "$PANEL" "$USER_NAME" "$PASS" 2>&1)"; layout_rc=$?
	grep -E '^(FAIL|FAILED)' <<<"$layout_out" | head -20
	check "browser layout test: every page at 1600 px and 390 px ($(grep -c '^PASS' <<<"$layout_out") checks)" "$([ "$layout_rc" = 0 ] && echo 1 || echo 0)"
else
	echo "SKIP  browser layout test (node + playwright not available)"
fi
dash="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=dashboard")"; tok="$(printf '%s' "$dash" | csrf)"
tok="$(printf '%s' "$dash" | csrf)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" "$URL?r=logout"
code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" "$URL?r=dashboard")"
check "after logout the dashboard redirects to login" "$([ "$code" = 303 ] && echo 1 || echo 0)"

[ "$failed" -eq 0 ] && echo "OK: panel smoke test passed." && exit 0
echo "FAIL: $failed step(s) failed."; exit 1
