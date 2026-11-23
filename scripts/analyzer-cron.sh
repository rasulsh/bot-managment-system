#!/usr/bin/env bash
# shellcheck disable=SC2034  # the JS_* variables are read by scripts/lib-jobstatus.sh
# Bot Guard analyzer cron wrapper.
#
#   scripts/analyzer-cron.sh verify     fast reverse-DNS loop
#
# The Python is GV_PYTHON from the environment, else GV_PYTHON read from your crontab, else <install-dir>/.venv/bin/python, else python3
# (the choice is recorded as "python" in analyzer/.jobstatus-<mode>.json), so `bash scripts/analyzer-cron.sh nightly` works from an SSH shell.
#
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
#   scripts/analyzer-cron.sh worker     drain the panel's job queue (takes the write lock itself, only around a job that writes)
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
# Cron often runs with umask 002, which made everything a job writes group-writable (model.joblib, the status and state files, the lock
# holder). The files are created 0644 (directories 0755); analyzer/fsmode.py also sets explicit modes where Python creates files.
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON=""
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

# Everything that writes models or verdicts shares ONE lock, analyzer/.write.lock: nightly, the two training modes and the worker's
# write jobs (which run the same code in-process) must never run side by side.
#   * nightly / train / train-clf are daily or weekly: when the lock is busy they WAIT for it (flock -w, GV_LOCK_WAIT seconds, default
#     900) instead of skipping. The worker runs every minute and usually starts in the same second (04:17 for nightly), so skipping
#     meant nightly almost never ran. If the lock is still busy after the wait the run is recorded as "skipped (lock busy after N s)".
#   * worker does NOT take the lock here: analyzer/worker.py takes it itself, only while it runs a job that writes models or
#     verdicts (an empty queue or a read-only job needs none). The wrapper only keeps two workers from overlapping (.worker.lock, -n).
#   * every other mode keeps a lock of its own and skips (-n) when it is busy.
WRITE_LOCK="${GV_LOCK_DIR:-$ROOT/analyzer}/.write.lock"
LOCK_WAIT=0
case "$MODE" in
	nightly|train|train-clf)
		LOCK="$WRITE_LOCK"
		LOCK_WAIT="${GV_LOCK_WAIT:-900}"
		case "$LOCK_WAIT" in ''|*[!0-9]*) LOCK_WAIT=900 ;; esac
		;;
	*) LOCK="${GV_LOCK_DIR:-$ROOT/analyzer}/.$MODE.lock" ;;
esac

# Job status (scripts/lib-jobstatus.sh): every run records its start, end, exit code, duration, the last
# error lines and whether it was skipped by the lock, in analyzer/.jobstatus-<mode>.json and logs/jobs.log;
# a failure also leaves its captured stderr in logs/jobs-errors.log. A trap records a crash or a signal.
# report keeps its stdout untouched (it is piped to mail); everything else is replayed unchanged.
JS_ROOT="$ROOT"
# shellcheck source=lib-jobstatus.sh
. "$ROOT/scripts/lib-jobstatus.sh"
js_begin "$MODE"
# Which Python: GV_PYTHON from the environment, else from the crontab, else <install-dir>/.venv/bin/python, else python3 (js_python_resolve).
# A job run by hand from an SSH shell has no GV_PYTHON, and python3 alone has none of the packages.
js_python_resolve
# The php the Python side runs to read the guard's settings: GV_PHP (exported, so analyzer/bridge.py sees it) or the first php on PATH;
# a php that is not the command-line build falls back to /usr/local/bin/php before the warning below (js_php_resolve).
js_php_resolve
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
	if [ "$LOCK_WAIT" -gt 0 ]; then
		# Wait for the write lock; once held, record who holds it ("<mode> <pid> <start>": the pid is this shell, which then
		# becomes the job with exec, so it stays valid) for the run that has to give up, then run the job.
		flock -w "$LOCK_WAIT" -E 99 "$LOCK" bash -c 'printf "%s %s %s\n" "$1" "$$" "$(date +%s)" > "$2" 2>/dev/null; shift 2; exec "$@"' _ \
			"$MODE" "$WRITE_LOCK.holder" "$PYTHON" "$ROOT/$SCRIPT" ${ARGS[@]+"${ARGS[@]}"}
		return $?
	fi
	flock -n -E 99 "$LOCK" "$PYTHON" "$ROOT/$SCRIPT" ${ARGS[@]+"${ARGS[@]}"}
}

js_exec run_job
status="$JS_EXIT"

if [ "$status" -eq 99 ]; then
	if [ "$LOCK_WAIT" -gt 0 ]; then
		holder="$(js_lock_holder "$WRITE_LOCK.holder")"
		echo "The write lock stayed busy for $LOCK_WAIT s${holder:+ (held by $holder)}; skipping this $MODE run."
		js_skipped "$LOCK_WAIT" "$holder"
	else
		echo "Another $MODE run is already in progress; skipping this firing."
		js_skipped
	fi
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
