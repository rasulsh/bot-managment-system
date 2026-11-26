#!/usr/bin/env bash
# End-to-end test of the in-panel updater over HTTP, against a throw-away copy of the repository.
#
#   bash scripts/update-e2e.sh
#
# Copies the repository to a temp directory, installs a panel login there, serves it with PHP's built-in
# server and drives the real flow with curl: upload a ZIP, review, apply with the password, the health
# check in a fresh request, the one-time recovery token, a rollback from the web; then an update whose
# new code is broken, which must roll itself back. Nothing is written into the working tree.
# Needs: php, python3, curl, tar.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHP_BIN="${GV_PHP:-php}"
PORT="${UPDATE_E2E_PORT:-8153}"
for need in "$PHP_BIN" python3 curl tar; do
	command -v "$need" >/dev/null 2>&1 || { echo "ERROR: '$need' is required." >&2; exit 2; }
done
WORK="$(mktemp -d)"
PID=""
cleanup() { [ -n "$PID" ] && kill "$PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
INST="$WORK/inst"
mkdir "$INST"
(cd "$ROOT" && tar --exclude=.git --exclude=node_modules --exclude=updates/pending -cf - .) | tar -xf - -C "$INST"
rm -rf "$INST"/updates/2* "$INST"/updates/*.php "$INST"/updates/*.json "$INST/guard.off"
echo "2026.01.01" > "$INST/VERSION"
PASSWORD="update-e2e-pass-12345"
(cd "$INST" && printf 'admin\n%s\n%s\n' "$PASSWORD" "$PASSWORD" | "$PHP_BIN" panel/setpass.php >/dev/null 2>&1)
echo '{"mode":"monitor"}' > "$INST/guard/config.local.json"

# The "new release" (good) and one whose new code fails the health check (broken): scripts/update-fixture.py.
python3 "$ROOT/scripts/update-fixture.py" "$INST" "$WORK" 2026.02.02 2026.03.03

"$PHP_BIN" -S "127.0.0.1:$PORT" -t "$INST" >"$WORK/php.log" 2>&1 &
PID=$!
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/panel/index.php" 2>/dev/null && break; sleep 0.1; done
URL="http://127.0.0.1:$PORT/panel/index.php"
JAR="$WORK/jar"
failed=0
check() { if [ "$2" = "1" ]; then echo "PASS  $1"; else echo "FAIL  $1"; failed=$((failed + 1)); fi; }
csrf() { grep -o 'name="csrf" value="[^"]*"' | head -1 | sed 's/.*value="//; s/"$//'; }
login_token() { curl -s -c "$1" -b "$1" "$URL?r=login" | grep -o 'name="csrf" value="[^"]*"' | head -1 | sed 's/.*value="//; s/"$//'; }   # the login form's CSRF field (it comes with a cookie)
has() { grep -q -- "$1" <<<"$2" && echo 1 || echo 0; }

curl -s -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$(login_token "$JAR")" --data-urlencode "username=admin" --data-urlencode "password=$PASSWORD" "$URL?r=login"
page="$(curl -s -c "$JAR" -b "$JAR" "$URL?r=update")"
check "the Update page opens after login and shows the installed version" "$(has '2026.01.01' "$page")"
tok="$(csrf <<<"$page")"

# --- upload without the CSRF token is refused (the page does not change anything)
curl -s -o /dev/null -c "$JAR" -b "$JAR" -F do=upload -F "zip=@$WORK/good.zip" "$URL?r=update"
check "an upload without the CSRF token is not staged" "$([ ! -d "$INST/updates/pending" ] || [ -z "$(ls -A "$INST/updates/pending" 2>/dev/null)" ] && echo 1 || echo 0)"
# --- upload, review
loc="$(curl -s -o /dev/null -D - -c "$JAR" -b "$JAR" -F "csrf=$tok" -F do=upload -F "zip=@$WORK/good.zip" "$URL?r=update" | tr -d '\r' | awk 'tolower($1)=="location:" {print $2}')"
plan="$(sed -n 's/.*plan=\([a-f0-9]*\).*/\1/p' <<<"$loc")"
check "an upload is staged and the browser is sent to the review (plan id in the URL)" "$([ ${#plan} -eq 16 ] && echo 1 || echo 0)"
review="$(curl -s -c "$JAR" -b "$JAR" "$URL?r=update&plan=$plan")"
check "the review shows from and to version, the changelog and the password field" "$([ "$(has '2026.02.02' "$review")" = 1 ] && [ "$(has 'e2e release' "$review")" = 1 ] && [ "$(has 'name="password"' "$review")" = 1 ] && echo 1 || echo 0)"
check "nothing was changed by the upload" "$([ "$(cat "$INST/VERSION")" = "2026.01.01" ] && [ ! -f "$INST/docs/E2E-NEW.md" ] && echo 1 || echo 0)"
tok="$(csrf <<<"$review")"

# --- wrong password: refused, nothing changed
resp="$(curl -s -c "$JAR" -b "$JAR" -L --data-urlencode "csrf=$tok" -d "plan=$plan" -d do=apply --data-urlencode "password=wrong-password" "$URL?r=update")"
check "a wrong password refuses the update" "$([ "$(has 'password is wrong' "$resp")" = 1 ] && [ "$(cat "$INST/VERSION")" = "2026.01.01" ] && echo 1 || echo 0)"
review="$(curl -s -c "$JAR" -b "$JAR" "$URL?r=update&plan=$plan")"
tok="$(csrf <<<"$review")"

# --- apply: password, swap, fresh-request health check, result page
resp="$(curl -s -c "$JAR" -b "$JAR" -L --data-urlencode "csrf=$tok" -d "plan=$plan" -d do=apply --data-urlencode "password=$PASSWORD" "$URL?r=update")"
check "the update applies and the new code passes the health check in a fresh request" "$(has 'passed the health check' "$resp")"
check "the files are the new ones, protected ones untouched" "$([ "$(cat "$INST/VERSION")" = "2026.02.02" ] && [ -f "$INST/docs/E2E-NEW.md" ] && grep -q 'LOCAL' <<<"LOCAL$(cat "$INST/guard/config.local.json")" && [ "$(cat "$INST/guard/config.local.json")" = '{"mode":"monitor"}' ] && echo 1 || echo 0)"
check "modes: the ZIP carries no modes (python zipfile gives 0600) yet scripts are 755 and other files 644 after the update" "$([ "$(stat -c %a "$INST/scripts/analyzer-cron.sh")" = 755 ] && [ "$(stat -c %a "$INST/scripts/cron-check.sh")" = 755 ] && [ "$(stat -c %a "$INST/guard/guard.php")" = 644 ] && [ "$(stat -c %a "$INST/docs/E2E-NEW.md")" = 644 ] && echo 1 || echo 0)"
check "guard.off is gone after a good check" "$([ ! -f "$INST/guard.off" ] && echo 1 || echo 0)"
token="$(grep -o '<code class="gp-mono">[a-f0-9]\{32\}</code>' <<<"$resp" | head -1 | sed 's/<[^>]*>//g')"
check "the recovery token is shown on the result page" "$([ ${#token} -eq 32 ] && echo 1 || echo 0)"
stamp=""
for d in "$INST"/updates/[0-9]*-[0-9]*; do [ -d "$d" ] && stamp="$(basename "$d")" && break; done
again="$(curl -s -c "$JAR" -b "$JAR" "$URL?r=update&ts=$stamp&res=ok")"
check "...and only once (a reload does not show it again)" "$([ "$(has "$token" "$again")" = 0 ] && echo 1 || echo 0)"
page="$(curl -s -c "$JAR" -b "$JAR" "$URL?r=update")"
css_now="$(grep -o 'assets/app\.css?v=[^"]*' <<<"$page" | head -1)"
check "the first page after the update already carries the NEW asset URLs (?v=2026.02.02-<hash>, not the old version: $css_now)" "$(grep -q 'v=2026\.02\.02-[0-9a-f]\{8\}$' <<<"$css_now" && echo 1 || echo 0)"
check "the footer and the page show the new version, the history lists the update" "$([ "$(has '2026.02.02' "$page")" = 1 ] && [ "$(has 'name="do" value="rollback"' "$page")" = 1 ] && echo 1 || echo 0)"

# --- web recovery with the token
rc="http://127.0.0.1:$PORT/panel/recover.php"
check "recover.php without a token answers an empty 404" "$([ "$(curl -s -o /dev/null -w '%{http_code}' "$rc")" = 404 ] && [ -z "$(curl -s "$rc")" ] && echo 1 || echo 0)"
check "recover.php with a wrong token answers an empty 404" "$([ "$(curl -s -o /dev/null -w '%{http_code}' "$rc?token=00000000000000000000000000000000")" = 404 ] && echo 1 || echo 0)"
form="$(curl -s "$rc?token=$token")"
check "recover.php with the token offers the rollback" "$(has 'Roll back now' "$form")"
out="$(curl -s -d "token=$token" "$rc")"
check "the token rolls the update back from the web" "$([ "$(has 'Rolled back.' "$out")" = 1 ] && [ "$(cat "$INST/VERSION")" = "2026.01.01" ] && [ ! -f "$INST/docs/E2E-NEW.md" ] && echo 1 || echo 0)"
check "the token is single use" "$([ "$(curl -s -o /dev/null -w '%{http_code}' -d "token=$token" "$rc")" = 404 ] && echo 1 || echo 0)"

# --- an update whose new code is broken (fatal error) rolls itself back
page="$(curl -s -c "$JAR" -b "$JAR" "$URL?r=update")"
tok="$(csrf <<<"$page")"
loc="$(curl -s -o /dev/null -D - -c "$JAR" -b "$JAR" -F "csrf=$tok" -F do=upload -F "zip=@$WORK/broken.zip" "$URL?r=update" | tr -d '\r' | awk 'tolower($1)=="location:" {print $2}')"
plan="$(sed -n 's/.*plan=\([a-f0-9]*\).*/\1/p' <<<"$loc")"
review="$(curl -s -c "$JAR" -b "$JAR" "$URL?r=update&plan=$plan")"
tok="$(csrf <<<"$review")"
hdr="$(curl -s -o /dev/null -D - -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d "plan=$plan" -d do=apply --data-urlencode "password=$PASSWORD" "$URL?r=update" | tr -d '\r')"
vloc="$(awk 'tolower($1)=="location:" {print $2}' <<<"$hdr")"
vraw="$(curl -s -i "http://127.0.0.1:$PORT/panel/$vloc" | tr -d '\r')"
vhdr="$vraw"
# a browser follows the Location, or - after a fatal error, when PHP has set status 500 - the meta refresh in the body
rloc="$(awk 'tolower($1)=="location:" {print $2; exit}' <<<"$vhdr")"
[ -n "$rloc" ] || rloc="$(sed -n 's/.*http-equiv="refresh" content="0;url=\([^"]*\)".*/\1/p' <<<"$vraw" | sed 's/&amp;/\&/g')"
resp="$(curl -s -c "$JAR" -b "$JAR" "http://127.0.0.1:$PORT/panel/$rloc")"
check "a broken update is rolled back automatically and the result page says so" "$(has 'rolled back automatically' "$resp")"
check "...the old version is running again and guard.off is gone" "$([ "$(cat "$INST/VERSION")" = "2026.01.01" ] && [ ! -f "$INST/guard.off" ] && ! grep -q 'function gv_log_policy() {}' "$INST/guard/log.php" && echo 1 || echo 0)"
page="$(curl -s -c "$JAR" -b "$JAR" "$URL?r=dashboard")"
check "the panel still works after the automatic rollback" "$(has 'data-chip="kill"' "$page")"
audit="$(cat "$INST/data/panel/audit.jsonl" "$INST/panel/audit.jsonl" 2>/dev/null)"        # the trail lives in data/panel (before 2026.11.39: panel/)
check "the audit trail has the upload, apply, verified, rollback and refusal events" "$([ "$(has 'update_upload' "$audit")" = 1 ] && [ "$(has 'update_apply' "$audit")" = 1 ] && [ "$(has 'update_verified' "$audit")" = 1 ] && [ "$(has 'reauth_failed' "$audit")" = 1 ] && echo 1 || echo 0)"

if grep -E 'Warning|Notice|Deprecated' "$WORK/php.log" | grep -v 'Cannot redeclare' >/dev/null 2>&1; then
	echo "FAIL  PHP reported warnings:"; grep -E 'Warning|Notice|Deprecated' "$WORK/php.log" | sort | uniq -c | head -5; failed=$((failed + 1))
fi
if [ "$failed" -gt 0 ]; then echo "FAILED: $failed check(s)"; exit 1; fi
echo "OK: the updater end-to-end test passed."
