#!/usr/bin/env bash
# shellcheck disable=SC2034  # the JS_* variables are read by scripts/lib-jobstatus.sh
# IP range feeds: fetch the feeds whose schedule is due (panel: IP lists -> Feeds).
#
# Normally started as `scripts/analyzer-cron.sh feeds` (it hands over to this script); cron example, once a day:
#   27 3 * * * bash /full/path/bot-guard/scripts/analyzer-cron.sh feeds >/dev/null 2>&1
#
# Runs scripts/feeds-sync.php with the same PHP as the other jobs (GV_PHP, else php on PATH, always `php -q`). Each feed is fetched
# over HTTPS only, IPv4 only; a failed fetch keeps the last good entries. The run is recorded for the job-health page
# (analyzer/.jobstatus-feeds.json, logs/jobs.log) like every other job; it fails (exit 1) when a feed failed.
set -uo pipefail
umask 022          # see analyzer-cron.sh

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHP_BIN="${GV_PHP:-php}"
JS_ROOT="$REPO"
# shellcheck source=lib-jobstatus.sh
. "$REPO/scripts/lib-jobstatus.sh"
js_begin feeds
js_lowprio_detect                    # nice -n 19 / ionice -c3 when they exist (recorded as "lowprio" in the job status)
js_php_resolve
PHP_BIN="${GV_PHP:-php}"
js_php_check "$PHP_BIN"

LOCK="${GV_LOCK_DIR:-$REPO/analyzer}/.feeds.lock"
run_job() {
	if ! command -v flock >/dev/null 2>&1; then
		${JS_LOWPRIO[@]+"${JS_LOWPRIO[@]}"} "$PHP_BIN" -q "$REPO/scripts/feeds-sync.php"
		return $?
	fi
	flock -n -E 99 "$LOCK" ${JS_LOWPRIO[@]+"${JS_LOWPRIO[@]}"} "$PHP_BIN" -q "$REPO/scripts/feeds-sync.php"
}

js_exec run_job
status="$JS_EXIT"
if [ "$status" -eq 99 ]; then
	echo "Another feeds run is already in progress; skipping this firing."
	js_skipped
	JS_EXIT=0
	exit 0
fi
exit "$status"
