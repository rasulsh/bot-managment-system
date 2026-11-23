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
JAR="$(mktemp)"; OPJ="$(mktemp)"; DMJ="$(mktemp)"; NJ="$(mktemp)"; trap 'rm -f "$JAR" "$OPJ" "$DMJ" "$NJ"' EXIT
newjar() { : > "$NJ"; echo "$NJ"; }
failed=0
check() { if [ "$2" = "1" ]; then echo "PASS  $1"; else echo "FAIL  $1"; failed=$((failed + 1)); fi; }
csrf() { grep -o 'name="csrf" value="[^"]*"' | head -1 | sed 's/.*value="//; s/"$//'; }

page="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=login")"
check "login page renders" "$(grep -q 'name="password"' <<<"$page" && echo 1 || echo 0)"

# Cache busting: every asset URL is versioned, HTML is never cached (browser or LiteSpeed page cache), and a versioned asset may be
# cached for a year. The asset headers are only expected from a REAL web server that honours .htaccess (GP_EXPECT_ASSET_CACHE=1, set
# by .github/ci/webserver-test.sh): PHP's built-in server serves static files with no such header.
hdr="$(curl -sk -D - -o /dev/null -c "$JAR" -b "$JAR" "$URL?r=login")"
# (LiteSpeed itself consumes X-LiteSpeed-Cache-Control and does not pass it on, so on OpenLiteSpeed the header cannot be seen from outside: it is
# checked everywhere else, and the PHP side is covered by panel-selftest.)
check "the login page is never cached: Cache-Control no-store$([ "${GP_SERVER:-}" = ols ] || echo ' and X-LiteSpeed-Cache-Control no-cache')" "$(grep -qi '^cache-control: no-store' <<<"$hdr" && { [ "${GP_SERVER:-}" = ols ] || grep -qi '^x-litespeed-cache-control: no-cache' <<<"$hdr"; } && echo 1 || echo 0)"
css_href="$(grep -o 'href="assets/app\.css?v=[^"]*"' <<<"$page" | head -1 | sed 's/^href="//; s/"$//')"
check "the stylesheet URL carries ?v=<VERSION>-<hash of the file> ($css_href)" "$(grep -Eq '^assets/app\.css\?v=[0-9][0-9A-Za-z._-]*-[0-9a-f]{8}$' <<<"$css_href" && echo 1 || echo 0)"
font_url="$(sed -n "s/.*url('\(assets\/vazirmatn-regular\.woff2?v=[^']*\)').*/\1/p" <<<"$page" | head -1)"
check "both font URLs are versioned too" "$([ "$(grep -o "woff2?v=" <<<"$page" | wc -l | tr -d ' ')" = 2 ] && [ -n "$font_url" ] && echo 1 || echo 0)"
check "no unversioned asset reference is left in the page" "$(grep -Eq "assets/[A-Za-z0-9._-]+[\"')]" <<<"$page" && echo 0 || echo 1)"
if [ -n "$css_href" ]; then
	ah="$(curl -sk -D - -o /dev/null "$BASE$PANEL/$css_href")"
	check "the versioned stylesheet is served (200, text/css)" "$(head -1 <<<"$ah" | grep -q ' 200' && grep -qi '^content-type: text/css' <<<"$ah" && echo 1 || echo 0)"
	if [ "${GP_EXPECT_ASSET_CACHE:-0}" = 1 ]; then
		check "a versioned asset is cacheable for a year: Cache-Control public, max-age=31536000, immutable" "$(grep -qi '^cache-control: public, max-age=31536000, immutable' <<<"$ah" && echo 1 || echo 0)"
		grep -qi '^cache-control: public, max-age=31536000, immutable' <<<"$ah" || { echo "  (headers seen: $(tr -d '\r' <<<"$ah" | tr '\n' '|'))"; }
		uh="$(curl -sk -D - -o /dev/null "$BASE$PANEL/assets/app.css")"
		if [ "${GP_SERVER:-}" = ols ]; then
			echo "NOTE  LiteSpeed has no per-query Header condition: an unversioned asset request is cached like a versioned one there (documented)"
		else
			check "an UNversioned asset request must revalidate (no immutable, never a year)" "$(grep -qi '^cache-control: no-cache' <<<"$uh" && ! grep -qi 'immutable' <<<"$uh" && echo 1 || echo 0)"
		fi
		fh="$(curl -sk -D - -o /dev/null "$BASE$PANEL/$font_url")"
		check "a versioned font is cacheable for a year too" "$(grep -qi '^cache-control: public, max-age=31536000, immutable' <<<"$fh" && echo 1 || echo 0)"
	fi
fi

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
		curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'identity=203.0.113.250' -d 'override=clear' -d 'from=list' "$URL?r=overrides"
		# A temporary challenge with a custom time (minutes) and a CAPTCHA, a quick action from a log row, then the clean-up.
		code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'identity=203.0.113.251' -d 'ttl=3600' -d 'ttl_minutes=15' -d 'override=challenge' "$URL?r=overrides")"
		check "a temporary challenge with a custom time answers 303" "$([ "$code" = 303 ] && echo 1 || echo 0)"
		curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'identity=203.0.113.252' -d 'quick=captcha:3600' -d 'from=quick' --data-urlencode 'back=index.php?r=logs' "$URL?r=overrides"
		ov="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=overrides")"
		check "the challenge and the quick-action CAPTCHA are listed with their kinds and an expiry" "$(grep -q '203.0.113.251' <<<"$ov" && grep -q '203.0.113.252' <<<"$ov" && grep -q 'gp-badge-warn">Challenge' <<<"$ov" && grep -q 'gp-badge-info">CAPTCHA' <<<"$ov" && grep -q ' UTC)' <<<"$ov" && echo 1 || echo 0)"
		code="$(curl -sk -o /dev/null -w '%{http_code}' -D - -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'identity=203.0.113.252' -d 'quick=captcha:3600' -d 'from=quick' --data-urlencode 'back=https://evil.example/' "$URL?r=overrides" | tr -d '\r' | sed -n 's/^[Ll]ocation: //p')"
		check "a quick action never redirects off site (a bad way back falls to the Overrides page)" "$(grep -q 'evil' <<<"$code" && echo 0 || echo 1)"
		for ident in 203.0.113.251 203.0.113.252; do curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d "identity=$ident" -d 'override=clear' "$URL?r=overrides"; done
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

# CAPTCHA: the Settings tab (GD status, preview), a setting saved and reset, the preview route, the rule action.
st="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=settings")"
check "Settings has a CAPTCHA tab with the level, the weights and a GD status line" "$(grep -q 'data-panel="captcha"' <<<"$st" && grep -q 'name="f\[captcha.level\]"' <<<"$st" && grep -q 'name="f\[captcha.w_webdriver\]"' <<<"$st" && grep -q 'id="cap-gd"' <<<"$st" && echo 1 || echo 0)"
tok="$(printf '%s' "$st" | csrf)"
code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'action=save' -d 'f[captcha.level]=3' "$URL?r=settings")"
check "a CAPTCHA level is saved (303)" "$([ "$code" = 303 ] && echo 1 || echo 0)"
st="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=settings")"
check "...and shown" "$(grep -A6 'name="f\[captcha.level\]"' <<<"$st" | grep -q 'value="3"' && echo 1 || echo 0)"
tok="$(printf '%s' "$st" | csrf)"
code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'action=save' -d 'f[captcha.level]=9' "$URL?r=settings")"
check "a CAPTCHA level out of range is refused, not clamped (no redirect)" "$([ "$code" != 303 ] && echo 1 || echo 0)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'action=reset' -d 'key=captcha.level' "$URL?r=settings"
pv="$(curl -sk -c "$JAR" -b "$JAR" -D - -o /dev/null "$URL?r=captcha_preview&level=3&length=5")"
check "the preview route answers a PNG (GD) or 204 (no GD), never an error" "$(grep -qiE '^HTTP/[0-9.]+ (200|204)' <<<"$pv" && { ! grep -qi '^HTTP/[0-9.]+ 200' <<<"$pv" || grep -qi 'content-type: image/png' <<<"$pv"; } && echo 1 || echo 0)"
code="$(curl -sk -o /dev/null -w '%{http_code}' "$URL?r=captcha_preview")"
check "the preview needs a login (no session: not an image)" "$([ "$code" != 200 ] && echo 1 || echo 0)"
qp="$(curl -sk -c "$JAR" -b "$JAR" -G --data-urlencode 'new=1' "$URL?r=rules")"
check "the rule form offers the action Image CAPTCHA" "$(grep -q 'value="captcha"' <<<"$qp" && grep -q 'Image CAPTCHA' <<<"$qp" && echo 1 || echo 0)"

# Dashboard (alerts, protection state, 24 h KPIs area, top lists) and the Jobs page (job health, crontab check).
dash="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=dashboard")"
check "the dashboard shows the protection state and the details section" "$(grep -q 'Protection state' <<<"$dash" && grep -q 'gp-details' <<<"$dash" && echo 1 || echo 0)"
check "the dashboard raises an alert for a fresh install with no snapshot or job status" "$(grep -q 'gp-alerts' <<<"$dash" && echo 1 || echo 0)"
jp="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=jobs")"
check "the Jobs page shows the file permission check" "$(grep -q 'id="perms"' <<<"$jp" && echo 1 || echo 0)"
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
check "the uploaded source is listed as not compiled yet" "$(grep -q 'gp-ltr gp-col-name">smoke-test-upload.mmdb</td>' <<<"$gp" && grep -q 'not compiled yet' <<<"$gp" && echo 1 || echo 0)"
tp="$(curl -sk -c "$JAR" -b "$JAR" -G --data-urlencode 'test=1' --data-urlencode 'ip=203.0.113.7' "$URL?r=geo")"
check "the lookup tester answers for an address (unknown without a database)" "$(grep -q '203.0.113.7' <<<"$tp" && grep -q 'unknown' <<<"$tp" && echo 1 || echo 0)"
tp="$(curl -sk -c "$JAR" -b "$JAR" -G --data-urlencode 'test=1' --data-urlencode 'ip=not-an-ip' "$URL?r=geo")"
check "the tester refuses something that is not an address" "$(grep -q 'not an IPv4 or IPv6 address' <<<"$tp" && echo 1 || echo 0)"
tok="$(printf '%s' "$gp" | csrf)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'do=delete' -d 'name=smoke-test-upload.mmdb' "$URL?r=geo"
gp="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=geo")"
check "deleting the source removes it from the list" "$(grep -q 'gp-ltr gp-col-name">smoke-test-upload.mmdb</td>' <<<"$gp" && echo 0 || echo 1)"
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
check "the IP lists page renders with its six tabs and the precedence note" "$([ "$(grep -o 'role="tab"' <<<"$ip" | wc -l | tr -d ' ')" = 6 ] && grep -q 'Order of decisions' <<<"$ip" && echo 1 || echo 0)"
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
for r in dashboard logs live identity overrides rules geo iplists replay models settings config_file jobs audit update; do
	page="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=$r")"
	check "page $r has the viewport meta tag" "$(grep -q 'name="viewport"' <<<"$page" && echo 1 || echo 0)"
	check "page $r is English and left-to-right" "$(grep -q '<html lang="en" dir="ltr">' <<<"$page" && echo 1 || echo 0)"
	case "$r" in logs|live|identity|settings|config_file) continue ;; esac
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

# Roles. The admin creates a Monitoring operator and a Demo user through the Users page, then each of them signs in once and
# visits every page: allowed pages answer 200, every other page 403; POSTs are refused with 403 (operator) and the effect is
# checked; the demo dashboard carries the banner and no links into the detail pages; a disabled user's session ends at once.
OP_NAME="smoke-op"; OP_PASS="operator-smoke-pass-1"; DM_NAME="smoke-demo"; DM_PASS="demo-smoke-pass-12345"
uform() { curl -sk -c "$JAR" -b "$JAR" "$URL?r=users"; }
upost() { local t; t="$(uform | csrf)"; curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" --data-urlencode "csrf=$t" "$@" "$URL?r=users"; }
ul="$(uform)"
check "the admin can open the Users page (list, create form)" "$(grep -q 'name="do" value="create"' <<<"$ul" && echo 1 || echo 0)"
check "the admin creates a Monitoring operator (303)" "$([ "$(upost -d do=create --data-urlencode "username=$OP_NAME" -d role=operator --data-urlencode "password=$OP_PASS")" = 303 ] && echo 1 || echo 0)"
check "the admin creates a Demo user (303)" "$([ "$(upost -d do=create --data-urlencode "username=$DM_NAME" -d role=demo --data-urlencode "password=$DM_PASS")" = 303 ] && echo 1 || echo 0)"
upost -d do=create -d username=smoke-short -d role=demo -d password=short >/dev/null
ul="$(uform)"
check "a short password is refused (no such user is created)" "$(! grep -q 'smoke-short' <<<"$ul" && echo 1 || echo 0)"
check "the Users page lists both, with the role labels" "$(grep -q 'Monitoring operator' <<<"$ul" && grep -q "$DM_NAME" <<<"$ul" && echo 1 || echo 0)"
filtered="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=users&role=demo&role_op=not")"
check "the Users filters include / exclude (role is not demo hides the demo user)" "$(grep -q "$OP_NAME" <<<"$filtered" && ! grep -q "$DM_NAME" <<<"$filtered" && echo 1 || echo 0)"
rlogin() { curl -sk -o /dev/null -w '%{http_code}' -c "$1" -b "$1" --data-urlencode "username=$2" --data-urlencode "password=$3" "$URL?r=login"; }
check "the operator signs in (303)" "$([ "$(rlogin "$OPJ" "$OP_NAME" "$OP_PASS")" = 303 ] && echo 1 || echo 0)"
check "the demo user signs in (303)" "$([ "$(rlogin "$DMJ" "$DM_NAME" "$DM_PASS")" = 303 ] && echo 1 || echo 0)"
code_of() { curl -sk -o /dev/null -w '%{http_code}' -c "$1" -b "$1" "$URL?r=$2"; }
for r in dashboard logs live identity overrides rules geo iplists replay models settings jobs audit account; do
	check "operator: page $r answers 200" "$([ "$(code_of "$OPJ" "$r")" = 200 ] && echo 1 || echo 0)"
done
lp="$(curl -sk -D - -c "$OPJ" -b "$OPJ" "$URL?r=live&poll=1&minutes=60")"
check "the Live poll answers JSON, never cached, for an operator (a read of the log: no Redis, no write)" "$(grep -qi '^content-type: application/json' <<<"$lp" && grep -qi '^cache-control: no-store' <<<"$lp" && grep -q '"ok":true' <<<"$lp" && echo 1 || echo 0)"
check "the Live poll answers 403 to the demo user and is not JSON for a logged-out client" "$([ "$(code_of "$DMJ" 'live&poll=1')" = 403 ] && ! curl -sk "$URL?r=live&poll=1" | grep -q '"ok":true' && echo 1 || echo 0)"
for r in config_file update users; do
	check "operator: page $r answers 403" "$([ "$(code_of "$OPJ" "$r")" = 403 ] && echo 1 || echo 0)"
done
for r in dashboard account; do
	check "demo: page $r answers 200" "$([ "$(code_of "$DMJ" "$r")" = 200 ] && echo 1 || echo 0)"
done
for r in logs live identity overrides rules geo iplists replay models settings jobs audit config_file update users captcha_preview; do
	check "demo: page $r answers 403" "$([ "$(code_of "$DMJ" "$r")" = 403 ] && echo 1 || echo 0)"
done
dd="$(curl -sk -c "$DMJ" -b "$DMJ" "$URL?r=dashboard")"
check "demo: the dashboard shows the banner, and no link into a detail page (logs, identity, jobs, settings, users)" "$(grep -q 'sensitive data hidden' <<<"$dd" && ! grep -qE 'r=(logs|identity|jobs|settings|users|audit|rules)' <<<"$dd" && echo 1 || echo 0)"
od="$(curl -sk -c "$OPJ" -b "$OPJ" "$URL?r=dashboard")"
check "operator: the navigation shows no Config file, Update or Users entry and the top bar names the role" "$(! grep -qE 'r=(config_file|update|users)' <<<"$od" && grep -q 'Monitoring operator' <<<"$od" && echo 1 || echo 0)"
otok="$(curl -sk -c "$OPJ" -b "$OPJ" "$URL?r=account" | csrf)"
opost() { curl -sk -o /dev/null -w '%{http_code}' -c "$OPJ" -b "$OPJ" --data-urlencode "csrf=$otok" "$@"; }
check "operator: a settings save is refused with 403" "$([ "$(opost -d action=save -d 'f[hard_block_score]=77' "$URL?r=settings")" = 403 ] && echo 1 || echo 0)"
sv="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=settings")"
check "...and the value was not saved" "$(! grep -q 'value="77"' <<<"$sv" && echo 1 || echo 0)"
ks_before="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=dashboard" | grep -c 'value="stop"')"
kc="$(opost -d "killswitch=$([ "$ks_before" -gt 0 ] && echo stop || echo start)" "$URL?r=dashboard")"
ks_after="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=dashboard" | grep -c 'value="stop"')"
check "operator: flipping the kill switch is refused with 403 and the switch did not change" "$([ "$kc" = 403 ] && [ "$ks_before" = "$ks_after" ] && echo 1 || echo 0)"
check "operator: creating a user, an override, a rule, a job and an update are all refused with 403" "$([ "$(opost -d do=create -d username=smoke-hack -d role=admin -d password=hacked-password-1 "$URL?r=users")" = 403 ] && [ "$(opost -d action=add -d ip=203.0.113.9 "$URL?r=overrides")" = 403 ] && [ "$(opost -d do=save "$URL?r=rules")" = 403 ] && [ "$(opost -d job=verify "$URL?r=jobs")" = 403 ] && [ "$(opost -d do=upload "$URL?r=update")" = 403 ] && echo 1 || echo 0)"
ul="$(uform)"
check "...and no such user exists" "$(! grep -q 'smoke-hack' <<<"$ul" && echo 1 || echo 0)"
check "operator: creating, updating and deleting an IP feed are refused with 403 (admin only)" "$([ "$(opost -d do=feed_save -d name=Hack --data-urlencode "url=https://example.com/x" -d dest=allow "$URL?r=iplists")" = 403 ] && [ "$(opost -d do=feed_update -d id=hack "$URL?r=iplists")" = 403 ] && [ "$(opost -d do=feed_delete -d id=hack "$URL?r=iplists")" = 403 ] && echo 1 || echo 0)"
# Captured first: "curl | grep -q" can end with curl's SIGPIPE status under pipefail even when grep matched (a big page, a slower server).
ipf="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=iplists")"
check "the IP lists page has the Feeds tab with the CDN warning (admin)" "$(grep -q "CDN ranges do not belong in an allow list" <<<"$ipf" && echo 1 || echo 0)"
check "operator: clearing a login lockout is refused with 403 (admin only)" "$([ "$(opost -d do=unlock -d unlock_all=1 "$URL?r=users")" = 403 ] && echo 1 || echo 0)"
check "the admin clears a login lockout from the Users page (303, back to the section, with a message)" "$([ "$(upost -d do=unlock -d unlock_all=1)" = 303 ] && echo 1 || echo 0)"
uloc="$(t="$(uform | csrf)"; curl -sk -o /dev/null -D - -c "$JAR" -b "$JAR" --data-urlencode "csrf=$t" -d do=unlock -d unlock_all=1 "$URL?r=users" | tr -d '\r' | sed -n 's/^[Ll]ocation: //p')"
check "the redirect after an action ends in #msg-<section> (users-unlock)" "$(grep -q '#msg-users-unlock$' <<<"$uloc" && echo 1 || echo 0)"
uafter="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=users")"
check "the Users page draws the result inside its own section, not at the top of the page" "$(grep -q 'id="msg-users-unlock"' <<<"$uafter" && ! grep -q 'id="msg-top"' <<<"$uafter" && echo 1 || echo 0)"
check "the demo user cannot POST either (settings and users: 403)" "$([ "$(curl -sk -o /dev/null -w '%{http_code}' -c "$DMJ" -b "$DMJ" --data-urlencode "csrf=$(curl -sk -c "$DMJ" -b "$DMJ" "$URL?r=account" | csrf)" -d action=save "$URL?r=settings")" = 403 ] && echo 1 || echo 0)"
check "a POST to a read-only role without the CSRF token is no use either" "$([ "$(curl -sk -o /dev/null -w '%{http_code}' -c "$OPJ" -b "$OPJ" -d action=save "$URL?r=settings")" = 403 ] && echo 1 || echo 0)"
# (A wrong current password and wrong sign-ins are covered by panel-selftest; here each one would count against the sign-in limit of 127.0.0.1,
# which the three CI layouts share through Redis, so this script makes only ONE failed sign-in, the disabled-user check below.)
check "operator: changing your OWN password works (current password required), the session stays signed in" "$([ "$(opost -d do=password --data-urlencode "current=$OP_PASS" -d new=operator-new-pass-2 -d repeat=operator-new-pass-2 "$URL?r=account")" = 303 ] && [ "$(code_of "$OPJ" dashboard)" = 200 ] && echo 1 || echo 0)"
OP_PASS="operator-new-pass-2"
check "...the new password signs in" "$([ "$(rlogin "$(newjar)" "$OP_NAME" "$OP_PASS")" = 303 ] && echo 1 || echo 0)"
check "the admin disables the operator (303)" "$([ "$(upost -d do=disable --data-urlencode "username=$OP_NAME")" = 303 ] && echo 1 || echo 0)"
check "...and the operator's open session ends on its next request (redirect to login)" "$([ "$(code_of "$OPJ" dashboard)" = 303 ] && echo 1 || echo 0)"
dl="$(curl -sk -c "$(newjar)" --data-urlencode "username=$OP_NAME" --data-urlencode "password=$OP_PASS" "$URL?r=login")"
check "...a disabled user cannot sign in and the message is the generic one" "$(grep -q 'Wrong username or password' <<<"$dl" && echo 1 || echo 0)"
upost -d do=delete --data-urlencode "username=$USER_NAME" >/dev/null; upost -d do=disable --data-urlencode "username=$USER_NAME" >/dev/null
ul="$(uform)"
check "the admin cannot disable or delete their own account" "$(grep -q "$USER_NAME" <<<"$ul" && [ "$(code_of "$JAR" dashboard)" = 200 ] && echo 1 || echo 0)"
check "the admin deletes the operator and the demo user (303)" "$([ "$(upost -d do=delete --data-urlencode "username=$OP_NAME")" = 303 ] && [ "$(upost -d do=delete --data-urlencode "username=$DM_NAME")" = 303 ] && echo 1 || echo 0)"
check "...and the deleted demo user's session ends too" "$([ "$(code_of "$DMJ" dashboard)" = 303 ] && echo 1 || echo 0)"

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
