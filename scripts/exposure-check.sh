#!/usr/bin/env bash
# Bot Guard deployment self-check: are the sensitive files reachable over HTTP?
#
#   bash scripts/exposure-check.sh <BASE_URL> [panel-path|none]
#
# Pass "none" as the panel path when the panel is not installed: the panel is
# optional, and without this the check failed on a site that simply has none.
#
#   BASE_URL     where the repository root would be served if it were inside the
#                document root, e.g. https://example.com or https://example.com/bot-guard
#                (with the recommended layout it is simply your site's URL: every
#                path below is then expected to be 404).
#   panel-path   URL path of the admin panel (default /panel). With the symlink
#                layout of docs/03-SETUP.md this is the name you chose, e.g. /gv-admin.
#
# GET only, no credentials, no state changes: safe to run against production.
# Exit code 0 when nothing sensitive answers 200 and the panel entry point and
# its stylesheet load; 1 otherwise; 2 on bad usage.
set -uo pipefail

BASE_URL="${1:-}"
PANEL_PATH="${2:-/panel}"
NO_PANEL=0
if [ "$PANEL_PATH" = "none" ]; then NO_PANEL=1; PANEL_PATH="/panel"; fi
if [ -z "$BASE_URL" ]; then
	echo "Usage: bash scripts/exposure-check.sh <BASE_URL> [panel-path]"
	echo "Example: bash scripts/exposure-check.sh https://example.com /gv-admin"
	exit 2
fi
BASE_URL="${BASE_URL%/}"
PANEL_PATH="/${PANEL_PATH#/}"
PANEL_PATH="${PANEL_PATH%/}"
CURL=(curl -sk --max-time 15 -A 'bot-guard-exposure-check/1')

TODAY="$(date +%Y%m%d)"
SENSITIVE=(
	"/logs/guard-$TODAY.jsonl"
	"/logs/guard-errors.log"
	"/logs/.redis-down"
	"/guard/config.php"
	"/guard/config.local.json"
	"/guard/guard.php"
	"/guard/config.php.bak"
	"/guard/config.php~"
	"/guard/config.php.save"
	"/guard/config.php.orig"
	"/panel/panel.config.php"
	"/panel/audit.jsonl"
	"/panel/views/layout.php"
	"/analyzer/snapshot.json"
	"/analyzer/model.joblib"
	"/analyzer/config.py"
	"/.git/HEAD"
	"/.git/config"
	"/README.md"
	"/ROLLOUT.md"
	"/docs/03-SETUP.md"
	"/guard.off"
	"/scripts/config.dev.php"
	"/scripts/guard-selftest.php"
	"/prepend.php"
	"/.htaccess"
)

failures=0
warnings=0

# A site that answers 200 for every unknown path (a soft 404) would make every
# line below look exposed. Fetch a path that cannot exist and remember its body.
probe_body="$("${CURL[@]}" "$BASE_URL/gv-exposure-probe-$RANDOM$RANDOM-nonexistent" 2>/dev/null)"
probe_code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE_URL/gv-exposure-probe-$RANDOM$RANDOM-nonexistent" 2>/dev/null)"
soft404=0
[ "$probe_code" = "200" ] && soft404=1

echo "Bot Guard exposure check against $BASE_URL (panel at $PANEL_PATH)"
echo
printf '%-34s | %s\n' 'path' 'result'
printf -- '-----------------------------------+--------------------------------\n'

for path in "${SENSITIVE[@]}"; do
	code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE_URL$path" 2>/dev/null)"
	[ -z "$code" ] && code="000"
	if [ "$code" = "200" ]; then
		if [ "$soft404" = "1" ] && [ "$("${CURL[@]}" "$BASE_URL$path" 2>/dev/null)" = "$probe_body" ]; then
			printf '%-34s | %s\n' "$path" "200 (same as a nonexistent path: soft-404 site, inconclusive)"
			warnings=$((warnings + 1))
		else
			printf '%-34s | %s\n' "$path" "200  EXPOSED"
			failures=$((failures + 1))
		fi
	elif [ "$code" = "000" ]; then
		printf '%-34s | %s\n' "$path" "no response (is $BASE_URL reachable?)"
		failures=$((failures + 1))
	else
		printf '%-34s | %s\n' "$path" "$code ok"
	fi
done

echo
if [ "$NO_PANEL" = "1" ]; then
	echo "Panel: not installed (skipped; anything under /panel was already tested above)"
else
echo "Panel:"
# Both the directory URL (what an operator types) and index.php must load.
for entry_path in "$PANEL_PATH/" "$PANEL_PATH/index.php"; do
entry="$("${CURL[@]}" -o /dev/null -w '%{http_code} %{size_download}' "$BASE_URL$entry_path" 2>/dev/null)"
case "$entry" in
	200\ *|302\ *|303\ *) printf '%-34s | %s\n' "$entry_path" "${entry%% *} ok" ;;
	"404 0")
		# index.php deliberately answers a bare, empty 404 until `php panel/setpass.php`
		# has been run: the PHP file executed, so the layout is right.
		printf '%-34s | %s\n' "$entry_path" "404 (empty body: panel code runs, credentials not installed yet - run php panel/setpass.php)" ;;
	*) printf '%-34s | %s\n' "$entry_path" "${entry%% *}  PANEL ENTRY POINT DOES NOT LOAD"; failures=$((failures + 1)) ;;
esac
done
css="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE_URL$PANEL_PATH/assets/app.css" 2>/dev/null)"
if [ "$css" = "200" ]; then
	printf '%-34s | %s\n' "$PANEL_PATH/assets/app.css" "200 ok"
else
	printf '%-34s | %s\n' "$PANEL_PATH/assets/app.css" "$css  PANEL STYLESHEET DOES NOT LOAD"
	failures=$((failures + 1))
fi
# Inside the panel directory only index.php and static assets may be served.
for path in "$PANEL_PATH/panel.config.php" "$PANEL_PATH/audit.jsonl" "$PANEL_PATH/auth.php" "$PANEL_PATH/views/login.php"; do
	code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE_URL$path" 2>/dev/null)"
	if [ "$code" = "200" ] && [ "$soft404" = "0" ]; then
		printf '%-34s | %s\n' "$path" "200  EXPOSED"
		failures=$((failures + 1))
	elif [ "$code" = "000" ]; then
		printf '%-34s | %s\n' "$path" "no response"
		failures=$((failures + 1))
	else
		printf '%-34s | %s\n' "$path" "$code ok"
	fi
done
fi

echo
if [ "$warnings" -gt 0 ]; then
	echo "NOTE: $warnings path(s) were inconclusive because the site answers 200 for unknown paths."
fi
if [ "$failures" -gt 0 ]; then
	echo "FAIL: $failures problem(s). Fix them before enabling any enforce toggle (see docs/03-SETUP.md, 'Layout')."
	exit 1
fi
echo "OK: no sensitive path answered 200 and the panel entry point and stylesheet load."
exit 0
