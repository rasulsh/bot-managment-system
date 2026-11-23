#!/usr/bin/env bash
# shellcheck disable=SC2034  # the JS_* variables are read by scripts/lib-jobstatus.sh
# Bot Guard analyzer cron wrapper.
#
#   scripts/analyzer-cron.sh verify     fast reverse-DNS loop
#   scripts/analyzer-cron.sh nightly    behavioural scoring + anomaly levels
#   scripts/analyzer-cron.sh train      nightly run that trains a CANDIDATE model
#   scripts/analyzer-cron.sh train-clf  nightly run that trains a CANDIDATE classifier
#
# train / train-clf produce a candidate for review, never the live model: like
# the panel's train jobs they pass --candidate, so a weekly cron cannot silently
# replace the live model. Promotion is a separate, explicit step (panel
# "promote" or analyzer/ctl.py promote).
#   scripts/analyzer-cron.sh report     period report, useful as a weekly mail
#   scripts/analyzer-cron.sh snapshot   dashboard snapshot for the admin panel
#   scripts/analyzer-cron.sh worker     drain the panel's job queue
#   scripts/analyzer-cron.sh geo        compile geo/*.mmdb / geoip.dat into country.bin / asn.bin
#   scripts/analyzer-cron.sh feeds      fetch the IP range feeds that are due (panel: IP lists -> Feeds; PHP only, hands over to feeds-cron.sh)
#
# Each mode takes its own flock, so overlapping cron firings queue-and-skip
# instead of writing partial verdicts on top of each other.
#
# Cron example (the PATH line first: cron's own PATH can find a php that is not the command line build, e.g. cPanel's php-cgi):
#   PATH=/usr/local/bin:/usr/bin:/bin
#   */10 * * * * bash /full/path/bot-guard/scripts/analyzer-cron.sh verify    >/dev/null 2>&1
#   17 4   * * * bash /full/path/bot-guard/scripts/analyzer-cron.sh nightly   >/dev/null 2>&1
#   41 5   * * 0 bash /full/path/bot-guard/scripts/analyzer-cron.sh train     >/dev/null 2>&1
#   11 6   * * 0 bash /full/path/bot-guard/scripts/analyzer-cron.sh train-clf >/dev/null 2>&1
#   30 7   * * 1 bash /full/path/bot-guard/scripts/analyzer-cron.sh report | mail -s "Bot Guard weekly" you@example.com
#   */15 * * * * bash /full/path/bot-guard/scripts/analyzer-cron.sh snapshot  >/dev/null 2>&1
#   *    * * * * bash /full/path/bot-guard/scripts/analyzer-cron.sh worker    >/dev/null 2>&1
#   23 3   1 * * bash /full/path/bot-guard/scripts/analyzer-cron.sh geo       >/dev/null 2>&1   # only when GeoIP rules are used
#   27 3   * * * bash /full/path/bot-guard/scripts/analyzer-cron.sh feeds     >/dev/null 2>&1   # only when an IP feed has a schedule
#
# report writes to stdout on purpose so it can be piped or mailed. Pass
# GV_REPORT_HTML=/path/to/file.html to also write the standalone HTML version.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${GV_PYTHON:-python3}"
MODE="${1:-}"

# feeds is a PHP job (it needs no Python): hand over before anything Python-specific runs.
if [ "$MODE" = feeds ]; then exec bash "$ROOT/scripts/feeds-cron.sh"; fi

case "$MODE" in
	verify)    SCRIPT="analyzer/run_verify.py";  ARGS=() ;;
	nightly)   SCRIPT="analyzer/run_nightly.py"; ARGS=() ;;
	train)     SCRIPT="analyzer/run_nightly.py"; ARGS=(--train --candidate) ;;
	train-clf) SCRIPT="analyzer/run_nightly.py"; ARGS=(--train-clf --candidate) ;;
	snapshot)  SCRIPT="analyzer/snapshot.py";    ARGS=() ;;
	worker)    SCRIPT="analyzer/worker.py";      ARGS=() ;;
	geo)       SCRIPT="analyzer/geo.py";         ARGS=() ;;
	report)
		SCRIPT="analyzer/report.py"
		ARGS=()
		if [ -n "${GV_REPORT_HTML:-}" ]; then
			ARGS=(--html "$GV_REPORT_HTML")
		fi
		;;
	*)
		echo "Usage: $(basename "$0") {verify|nightly|train|train-clf|report|snapshot|worker|geo|feeds}"
		exit 1
		;;
esac

# Every mode that writes models or verdicts shares ONE lock: nightly, the two
# training modes and the worker (which runs the same code in-process) must never
# run side by side. Read-mostly modes keep a lock of their own.
case "$MODE" in
	nightly|train|train-clf|worker) LOCK="${GV_LOCK_DIR:-$ROOT/analyzer}/.write.lock" ;;
	*)                              LOCK="${GV_LOCK_DIR:-$ROOT/analyzer}/.$MODE.lock" ;;
esac

# Job status (scripts/lib-jobstatus.sh): every run records its start, end, exit code, duration, the last
# error lines and whether it was skipped by the lock, in analyzer/.jobstatus-<mode>.json and logs/jobs.log;
# a failure also leaves its captured stderr in logs/jobs-errors.log. A trap records a crash or a signal.
# report keeps its stdout untouched (it is piped to mail); everything else is replayed unchanged.
JS_ROOT="$ROOT"
# shellcheck source=lib-jobstatus.sh
. "$ROOT/scripts/lib-jobstatus.sh"
js_begin "$MODE"
# The php the Python side runs to read the guard's settings: GV_PHP (exported, so analyzer/bridge.py sees it) or the first php on PATH.
[ -n "${GV_PHP:-}" ] && export GV_PHP
js_php_check "${GV_PHP:-php}"
[ "$MODE" = report ] && JS_PASS_STDOUT=1

# Preflight: a Python that cannot import the packages used to make every job "succeed" while storing
# nothing. Now it is a recorded failure with the fix in the message.
if ! js_preflight "$PYTHON" "$MODE"; then
	exit 3
fi

run_job() {
	if ! command -v flock >/dev/null 2>&1; then
		echo "flock not available: running $MODE without a lock"
		"$PYTHON" "$ROOT/$SCRIPT" ${ARGS[@]+"${ARGS[@]}"}
		return $?
	fi
	# -E 99 makes "could not take the lock" distinguishable from the job's own
	# exit status, so an overlapping firing is a clean skip rather than an error.
	flock -n -E 99 "$LOCK" "$PYTHON" "$ROOT/$SCRIPT" ${ARGS[@]+"${ARGS[@]}"}
}

js_exec run_job
status="$JS_EXIT"

if [ "$status" -eq 99 ]; then
	echo "Another $MODE run is already in progress; skipping this firing."
	js_skipped
	JS_EXIT=0
	exit 0
fi

# The crontab check (scripts/cron-check.sh) is refreshed into analyzer/.cron-check.json for a panel that
# cannot run it itself. At most every 10 minutes, best effort, never part of the job's result.
CC="${GV_JOBSTATUS_DIR:-$ROOT/analyzer}/.cron-check.json"
if [ ! -f "$CC" ] || [ -n "$(find "$CC" -mmin +10 2>/dev/null)" ]; then
	( bash "$ROOT/scripts/cron-check.sh" --json > "$CC.tmp$$" 2>/dev/null && mv -f "$CC.tmp$$" "$CC" ) >/dev/null 2>&1 || rm -f "$CC.tmp$$"
fi
exit "$status"
