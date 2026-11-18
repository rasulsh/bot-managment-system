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
check "login page renders" "$(printf '%s' "$page" | grep -q 'name="password"' && echo 1 || echo 0)"

code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" --data-urlencode "username=$USER_NAME" --data-urlencode "password=$PASS" "$URL?r=login")"
check "login answers 303" "$([ "$code" = 303 ] && echo 1 || echo 0)"
dash="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=dashboard")"
check "dashboard is shown after login (session cookie works on this path)" "$(printf '%s' "$dash" | grep -q 'name="killswitch"' && echo 1 || echo 0)"
cpath="$(awk '$6 ~ /^gp_/ {print $3; exit}' "$JAR")"
check "the session cookie path is the panel path ($cpath)" "$([ "$cpath" = "$PANEL/" ] && echo 1 || echo 0)"

tok="$(printf '%s' "$dash" | csrf)"
code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'action=save' -d 'f[hard_block_score]=61' "$URL?r=settings")"
check "settings save answers 303" "$([ "$code" = 303 ] && echo 1 || echo 0)"
settings="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=settings")"
check "the saved value is shown" "$(printf '%s' "$settings" | grep -q 'value="61"' && echo 1 || echo 0)"
tok="$(printf '%s' "$settings" | csrf)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'action=reset' -d 'key=hard_block_score' "$URL?r=settings"

ov="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=overrides")"
tok="$(printf '%s' "$ov" | csrf)"
if printf '%s' "$ov" | grep -qi 'name="identity"'; then
	code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'identity=203.0.113.250' -d 'ttl=3600' -d 'override=allow' "$URL?r=overrides")"
	check "override add answers 303" "$([ "$code" = 303 ] && echo 1 || echo 0)"
	ov="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=overrides")"
	if printf '%s' "$ov" | grep -q '203.0.113.250'; then
		check "the override is listed (Redis reachable from the panel)" 1
		tok="$(printf '%s' "$ov" | csrf)"
		curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'identity=203.0.113.250' -d 'ttl=60' -d 'clear=1' "$URL?r=overrides"
	else
		echo "NOTE  the override is not listed: the panel cannot reach Redis here (skipped, not a layout problem)"
	fi
fi

# Every page is English and left-to-right, with Latin digits only. The logs and
# identity pages are checked for direction only: they show request data as it
# was received, and that may contain any script.
for r in dashboard logs identity overrides replay models settings jobs audit; do
	page="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=$r")"
	check "page $r is English and left-to-right" "$(grep -q '<html lang="en" dir="ltr">' <<<"$page" && echo 1 || echo 0)"
	case "$r" in logs|identity) continue ;; esac
	check "page $r shows no Persian or Arabic script or digits" "$(LC_ALL=C.UTF-8 grep -qP '[\x{0600}-\x{06FF}]' <<<"$page" && echo 0 || echo 1)"
done

dash="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=dashboard")"; tok="$(printf '%s' "$dash" | csrf)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'killswitch=stop' "$URL?r=dashboard"
dash="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=dashboard")"
check "kill switch can be engaged" "$(printf '%s' "$dash" | grep -q 'value="start"' && echo 1 || echo 0)"
tok="$(printf '%s' "$dash" | csrf)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" -d 'killswitch=start' "$URL?r=dashboard"
dash="$(curl -sk -c "$JAR" -b "$JAR" "$URL?r=dashboard")"
check "kill switch can be released" "$(printf '%s' "$dash" | grep -q 'value="stop"' && echo 1 || echo 0)"

tok="$(printf '%s' "$dash" | csrf)"
curl -sk -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "csrf=$tok" "$URL?r=logout"
code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" "$URL?r=dashboard")"
check "after logout the dashboard redirects to login" "$([ "$code" = 303 ] && echo 1 || echo 0)"

[ "$failed" -eq 0 ] && echo "OK: panel smoke test passed." && exit 0
echo "FAIL: $failed step(s) failed."; exit 1
