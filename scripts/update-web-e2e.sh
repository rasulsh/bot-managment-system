#!/usr/bin/env bash
# The in-panel updater against a REAL web server (the CI "webservers" job: Apache and OpenLiteSpeed, in every layout).
#
#   bash scripts/update-web-e2e.sh <BASE_URL> <panel-path> <install-dir> <password>
#
# scripts/update-e2e.sh uses PHP's built-in server, which ignores .htaccess; this one goes through the real rewrite rules, so
# it catches a web path that the server blocks (a production update once stayed "Waiting for the check" because panel/.htaccess
# did not allow recover.php in its RewriteRule list). It runs as root, the install belongs to the web user. What it does, in
# the install it is given (it leaves the install as it found it):
#   A  upload a ZIP, apply with the password, the health check through panel/recover.php (a 303 to the result, never a 403), the
#      recovery token, recover.php without / with a wrong token answers the application's bare 404, Roll back from the page
#   B  the check from INSIDE the panel ("Run the check now", no recover.php needed), then the web recovery with the token, once
#   C  an update whose new code is broken (a fatal error): the check through recover.php rolls it back by itself
#   D  the check and the rollback from the shell (php updates/verify.php, php updates/rollback.php)
# Needs: curl, python3, php, the install writable by the web user. Exit 1 when a check fails.
set -uo pipefail
BASE="${1:-}"; PANEL="${2:-}"; INST="${3:-}"; PASS="${4:-}"
if [ -z "$BASE" ] || [ -z "$PANEL" ] || [ -z "$INST" ] || [ -z "$PASS" ]; then
	echo "Usage: bash scripts/update-web-e2e.sh <BASE_URL> <panel-path> <install-dir> <password>"; exit 2
fi
BASE="${BASE%/}"; PANEL="/${PANEL#/}"; PANEL="${PANEL%/}"
URL="$BASE$PANEL/index.php"; RC="$BASE$PANEL/recover.php"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"; JAR="$WORK/jar"
trap 'rm -rf "$WORK"' EXIT
failed=0
check() { if [ "$2" = "1" ]; then echo "PASS  $1"; else echo "FAIL  $1"; failed=$((failed + 1)); fi; }
csrf() { grep -o 'name="csrf" value="[^"]*"' | head -1 | sed 's/.*value="//; s/"$//'; }
has() { grep -q -- "$1" <<<"$2" && echo 1 || echo 0; }
loc_of() { tr -d '\r' | awk 'tolower($1)=="location:" {print $2; exit}'; }
code_of_head() { tr -d '\r' | awk 'NR==1 {print $2}'; }
web_user() { if command -v runuser >/dev/null 2>&1 && id www-data >/dev/null 2>&1; then runuser -u www-data -- "$@"; else "$@"; fi; }

CUR="$(tr -d '[:space:]' < "$INST/VERSION")"
GOOD=2099.01.01; BROKEN=2099.02.02
python3 "$HERE/update-fixture.py" "$INST" "$WORK" "$GOOD" "$BROKEN" || { echo "FAIL  could not build the fixture ZIPs"; exit 1; }

page() { curl -s -c "$JAR" -b "$JAR" "$URL?r=$1"; }
login() {
	curl -s -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "username=admin" --data-urlencode "password=$PASS" "$URL?r=login"
	check "signed in; the Update page opens (version $CUR)" "$(has "$CUR" "$(page update)")"
	CSS_BEFORE="$(css_of "$(page update)")"
}
css_of() { grep -o 'assets/app\.css?v=[^"]*' <<<"$1" | head -1; }
upload() {   # <zip> -> plan id
	local tok h
	tok="$(page update | csrf)"
	h="$(curl -s -o /dev/null -D - -c "$JAR" -b "$JAR" -F "csrf=$tok" -F do=upload -F "zip=@$1" "$URL?r=update")"
	sed -n 's/.*plan=\([a-f0-9]*\).*/\1/p' <<<"$(loc_of <<<"$h")"
}
apply() {   # <plan id> -> the Location of the response (the web path of the check)
	local tok
	tok="$(curl -s -c "$JAR" -b "$JAR" "$URL?r=update&plan=$1" | csrf)"
	curl -s -o /dev/null -D - -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d "plan=$1" -d do=apply -d "confirm[git_present]=1" --data-urlencode "password=$PASS" "$URL?r=update" | loc_of
}
stamp_of() { sed -n 's/.*ts=\([0-9]\{8\}-[0-9]\{6\}[-0-9]*\).*/\1/p' <<<"$1"; }
# What a browser does after the check: follow the Location, or (after a fatal error PHP has set status 500) the meta refresh.
next_of() { local raw="$1" l; l="$(loc_of <<<"$raw")"; [ -n "$l" ] || l="$(tr -d '\r' <<<"$raw" | sed -n 's/.*http-equiv="refresh" content="0;url=\([^"]*\)".*/\1/p' | sed 's/&amp;/\&/g')"; printf '%s' "$l"; }
state_clean() { [ "$(tr -d '[:space:]' < "$INST/VERSION")" = "$CUR" ] && [ ! -e "$INST/guard.off" ] && [ ! -e "$INST/docs/E2E-NEW.md" ] && echo 1 || echo 0; }

login

# ---- recover.php without a token: the application's own bare 404 (text/plain, empty), not the server's 403 or 404 page
rc_h="$(curl -s -D - -o /dev/null "$RC")"; rc_b="$(curl -s "$RC")"
check "recover.php without a token answers the application's bare 404 (not the server's 403)" "$([ "$(code_of_head <<<"$rc_h")" = 404 ] && [ -z "$rc_b" ] && grep -qi '^content-type: *text/plain' <<<"$rc_h" && echo 1 || echo 0)"
rc_h="$(curl -s -D - -o /dev/null "$RC?token=00000000000000000000000000000000")"; rc_b="$(curl -s "$RC?token=00000000000000000000000000000000")"
check "recover.php with a wrong token answers the same bare 404" "$([ "$(code_of_head <<<"$rc_h")" = 404 ] && [ -z "$rc_b" ] && grep -qi '^content-type: *text/plain' <<<"$rc_h" && echo 1 || echo 0)"
check "recover.php?a=verify without a key answers the same bare 404" "$([ "$(curl -s -o /dev/null -w '%{http_code}' "$RC?a=verify&ts=20260101-000000&k=x")" = 404 ] && [ -z "$(curl -s "$RC?a=verify&ts=20260101-000000&k=x")" ] && echo 1 || echo 0)"

# ---- A: the web path of the check, the token, the page's Roll back
echo "--- A: apply, check through recover.php, token, roll back from the page"
plan="$(upload "$WORK/good.zip")"
check "A: the ZIP is staged (plan id)" "$([ ${#plan} -eq 16 ] && echo 1 || echo 0)"
vloc="$(apply "$plan")"
stamp="$(stamp_of "$vloc")"
check "A: apply redirects to recover.php?a=verify with the update's stamp and key" "$(has 'recover.php?a=verify' "$vloc")"
check "A: the update is applied and the guard is switched off while it waits" "$([ "$(tr -d '[:space:]' < "$INST/VERSION")" = "$GOOD" ] && [ -e "$INST/guard.off" ] && echo 1 || echo 0)"
w="$(page update)"
check "A: the Update page shows the waiting alert with the Run-the-check button" "$([ "$(has 'id="update-waiting"' "$w")" = 1 ] && [ "$(has 'name="do" value="verify"' "$w")" = 1 ] && echo 1 || echo 0)"
raw="$(curl -s -i "$BASE$PANEL/$vloc")"
vcode="$(code_of_head <<<"$raw")"
check "A: panel/recover.php?a=verify reaches the check through the web server (a redirect, NOT the server's 403; status $vcode)" "$([ "$vcode" = 303 ] && echo 1 || echo 0)"
next="$(next_of "$raw")"
res="$(curl -s -c "$JAR" -b "$JAR" "$BASE$PANEL/$next")"
check "A: the result page says the new code passed the health check" "$(has 'passed the health check' "$res")"
check "A: the files are the new version and guard.off is gone" "$([ "$(tr -d '[:space:]' < "$INST/VERSION")" = "$GOOD" ] && [ ! -e "$INST/guard.off" ] && echo 1 || echo 0)"
CSS_AFTER="$(css_of "$(page update)")"
check "A: the first page after the update already carries the NEW asset URLs (?v= changed from '$CSS_BEFORE')" "$([ -n "$CSS_BEFORE" ] && [ -n "$CSS_AFTER" ] && [ "$CSS_BEFORE" != "$CSS_AFTER" ] && grep -q "v=$GOOD-" <<<"$CSS_AFTER" && echo 1 || echo 0)"
token="$(grep -o '<code class="gp-mono">[a-f0-9]\{32\}</code>' <<<"$res" | head -1 | sed 's/<[^>]*>//g')"
check "A: the recovery token is shown once" "$([ ${#token} -eq 32 ] && echo 1 || echo 0)"
tok="$(page update | csrf)"
curl -s -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d do=rollback -d "stamp=$stamp" "$URL?r=update"
check "A: Roll back on the Update page restores the previous version" "$(state_clean)"

# ---- B: the check inside the panel, then the web recovery
echo "--- B: Run the check now (inside the panel), recovery with the token"
plan="$(upload "$WORK/good.zip")"
vloc="$(apply "$plan")"; stamp="$(stamp_of "$vloc")"
tok="$(page update | csrf)"
h="$(curl -s -o /dev/null -D - -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d do=verify -d "stamp=$stamp" "$URL?r=update")"
next="$(next_of "$h")"
check "B: the in-panel check redirects to the result page (no recover.php involved)" "$(has "res=ok" "$next")"
res="$(curl -s -c "$JAR" -b "$JAR" "$BASE$PANEL/$next")"
check "B: the result page says the new code passed the health check" "$(has 'passed the health check' "$res")"
check "B: the version is new and guard.off is gone" "$([ "$(tr -d '[:space:]' < "$INST/VERSION")" = "$GOOD" ] && [ ! -e "$INST/guard.off" ] && echo 1 || echo 0)"
token="$(grep -o '<code class="gp-mono">[a-f0-9]\{32\}</code>' <<<"$res" | head -1 | sed 's/<[^>]*>//g')"
check "B: recover.php with the valid token reaches the rollback code (a page offering the rollback)" "$(has 'Roll back now' "$(curl -s "$RC?token=$token")")"
out="$(curl -s -d "token=$token" "$RC")"
check "B: the token rolls the update back from the web" "$([ "$(has 'Rolled back.' "$out")" = 1 ] && [ "$(state_clean)" = 1 ] && echo 1 || echo 0)"
check "B: the token is single use (the same bare 404 afterwards)" "$([ "$(curl -s -o /dev/null -w '%{http_code}' -d "token=$token" "$RC")" = 404 ] && echo 1 || echo 0)"

# ---- C: broken new code, automatic rollback through recover.php
echo "--- C: broken update, automatic rollback"
plan="$(upload "$WORK/broken.zip")"
check "C: the broken ZIP parses, so it is staged" "$([ ${#plan} -eq 16 ] && echo 1 || echo 0)"
vloc="$(apply "$plan")"; stamp="$(stamp_of "$vloc")"
raw="$(curl -s -i "$BASE$PANEL/$vloc")"
next="$(next_of "$raw")"
check "C: the check ran through recover.php and sent the browser on (Location or meta refresh, not the server's 403)" "$(has 'res=rolled' "$next")"
res="$(curl -s -c "$JAR" -b "$JAR" "$BASE$PANEL/$next")"
check "C: the result page says it was rolled back automatically" "$(has 'rolled back automatically' "$res")"
check "C: the old version is running again and guard.off is gone" "$(state_clean)"
check "C: the panel still works" "$(has 'data-chip="kill"' "$(page dashboard)")"

# ---- D: the shell
echo "--- D: the check and the rollback from the shell"
plan="$(upload "$WORK/good.zip")"
vloc="$(apply "$plan")"; stamp="$(stamp_of "$vloc")"
out="$(web_user php "$INST/updates/verify.php" "$stamp" 2>&1)"; rc=$?
check "D: php updates/verify.php <stamp> passes ($out)" "$([ "$rc" = 0 ] && [ "$(has 'OK' "$out")" = 1 ] && [ ! -e "$INST/guard.off" ] && echo 1 || echo 0)"
out="$(web_user php "$INST/updates/rollback.php" 2>&1)"; rc=$?
check "D: php updates/rollback.php restores the previous version" "$([ "$rc" = 0 ] && [ "$(state_clean)" = 1 ] && echo 1 || echo 0)"

[ "$failed" -eq 0 ] && echo "OK: the updater passed the real web server test." && exit 0
echo "FAIL: $failed step(s) failed."; exit 1
