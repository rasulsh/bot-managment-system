#!/usr/bin/env bash
# shellcheck disable=SC2034  # JS_* are read by the scripts that source this file
# Job status recording for the cron wrappers (sourced by analyzer-cron.sh and
# guard-logrotate.sh; not run by itself).
#
# Every run of every mode leaves:
#   <status dir>/.jobstatus-<mode>.json   the latest state, read LIVE by the panel
#   <status dir>/.jobstate-<mode>         numbers that survive runs (last success / failure, skip count)
#   <log dir>/jobs.log                    one JSON line per run (start, end, exit, duration, mode, error summary)
#   <log dir>/jobs-errors.log             on failure: the captured stderr, capped at 64 KiB
#
# Why a wrapper records this and not the job: cron sends output to /dev/null, a job
# that crashes cannot report its own crash, and a wrong GV_PYTHON makes it exit 0
# having done nothing. A trap records the failure even when the wrapper itself dies.
#
# The wrapper captures stderr itself, so nothing is lost when cron discards it, then
# prints it again unchanged. Secrets are redacted before anything is written to disk.
#
# Environment: GV_JOBSTATUS_DIR (default <repo>/analyzer), GV_JOBLOG_DIR (default <repo>/logs
# or the configured log_dir), GV_PHP (the PHP used to look up secrets to redact).
#
# Status values: ok | warning (exit 0 but the job said it did nothing useful) | failed | skipped.

JS_ROOT="${JS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
JS_STATUS_DIR="${GV_JOBSTATUS_DIR:-$JS_ROOT/analyzer}"
JS_MODE=""
JS_START=0
JS_TMP=""
JS_OUT=""
JS_ERR=""
JS_DONE=0
JS_EXIT=0
JS_NOTE=""            # a reason set by the wrapper itself (preflight failure ...)
JS_EXTRA_RESULT=""    # a result JSON object the wrapper itself produced (logrotate)
JS_WARN_EXTRA=""      # wrapper-level warning text

# js_php_check [php]: a php that is not the command-line build (cPanel cron's default PATH finds php-cgi first: it prints HTTP
# headers and used to make every config read fail) gets ONE job warning naming the binary and the fix.
js_php_check() {
	local bin="${1:-${GV_PHP:-php}}" t sapi
	command -v "$bin" >/dev/null 2>&1 || return 0
	t="$(mktemp 2>/dev/null)" || return 0
	printf '<?php echo PHP_SAPI;' > "$t"
	sapi="$("$bin" -q "$t" 2>/dev/null | tail -n 1)"
	rm -f "$t"
	case "$sapi" in cli|'') return 0 ;; esac
	JS_WARN_EXTRA="${JS_WARN_EXTRA:+$JS_WARN_EXTRA
}php binary $(command -v "$bin") is the $sapi SAPI, not the command line one: add PATH=/usr/local/bin:/usr/bin:/bin to the crontab or set GV_PHP=/full/path/to/the/php-cli"
}

js_log_dir() {
	if [ -n "${GV_JOBLOG_DIR:-}" ]; then echo "$GV_JOBLOG_DIR"; return; fi
	local d=""
	if command -v "${GV_PHP:-php}" >/dev/null 2>&1; then
		d="$("${GV_PHP:-php}" -q "$JS_ROOT/scripts/config-dump.php" --get log_dir 2>/dev/null | head -1)"
	fi
	[ -n "$d" ] && [ -d "$d" ] && { echo "$d"; return; }
	echo "$JS_ROOT/logs"
}

# JSON string body (no quotes) from stdin: ASCII only, newlines as \n.
js_esc() {
	tr -cd '\11\12\40-\176' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' | awk 'BEGIN{ORS=""} {if (NR>1) print "\\n"; print}'
}

# Redact secrets from stdin. Exact values (secret, salt, Redis and panel credentials) come from
# scripts/secret-values.php; generic patterns catch "password=...", "AUTH ..." and "secret: ..." even
# when PHP is unavailable.
js_redact() {
	local rules
	rules="$(mktemp 2>/dev/null)" || { cat; return; }
	{
		if command -v "${GV_PHP:-php}" >/dev/null 2>&1; then
			"${GV_PHP:-php}" -q "$JS_ROOT/scripts/secret-values.php" 2>/dev/null | while IFS= read -r v; do
				[ "${#v}" -ge 6 ] || continue
				printf 's/%s/[REDACTED]/g\n' "$(printf '%s' "$v" | sed -e 's/[][\.*^$/&]/\\&/g')"
			done
		fi
		printf '%s\n' \
			's/\(password\|passwd\|secret\|salt\|token\)\([=:] *\)[^ ,;"'"'"']*/\1\2[REDACTED]/Ig' \
			's/\(AUTH\) [^ ]*/\1 [REDACTED]/g'
	} > "$rules" 2>/dev/null
	sed -f "$rules" 2>/dev/null || cat
	rm -f "$rules"
}

js_state_get() {   # key -> number (0 when absent)
	local v
	v="$(sed -n "s/^$1=\([0-9][0-9]*\)\$/\1/p" "$JS_STATUS_DIR/.jobstate-$JS_MODE" 2>/dev/null | head -1)"
	echo "${v:-0}"
}

js_state_write() {   # last_success last_failure skipped runs failures
	local f="$JS_STATUS_DIR/.jobstate-$JS_MODE"
	printf 'last_success=%s\nlast_failure=%s\nskipped=%s\nruns=%s\nfailures=%s\n' "$1" "$2" "$3" "$4" "$5" > "$f.tmp$$" 2>/dev/null \
		&& mv -f "$f.tmp$$" "$f" 2>/dev/null
	return 0
}

# Begin a run: remember the mode and the start time, create the capture files, and arm the
# traps so a crash or a signal still records a failure.
js_begin() {
	JS_MODE="$1"
	JS_START="$(date +%s)"
	JS_DONE=0
	JS_TMP="$(mktemp -d 2>/dev/null)" || JS_TMP=""
	if [ -n "$JS_TMP" ]; then JS_OUT="$JS_TMP/out"; JS_ERR="$JS_TMP/err"; : > "$JS_OUT"; : > "$JS_ERR"; fi
	trap 'js_on_exit $?' EXIT
	trap 'exit 143' TERM
	trap 'exit 130' INT
	trap 'exit 129' HUP
}

# Run a command with stderr (and stdout, unless $JS_PASS_STDOUT=1) captured, then replay both
# unchanged. Sets JS_EXIT. Never aborts the caller (set -e safe).
js_exec() {
	local rc=0
	if [ -z "$JS_TMP" ]; then "$@" || rc=$?; JS_EXIT=$rc; return 0; fi
	if [ "${JS_PASS_STDOUT:-0}" = 1 ]; then
		"$@" 2>"$JS_ERR" || rc=$?
	else
		"$@" >"$JS_OUT" 2>"$JS_ERR" || rc=$?
		cat "$JS_OUT"
	fi
	cat "$JS_ERR" >&2
	JS_EXIT=$rc
	return 0
}

# A run that found another run holding the lock: not a failure, but not invisible.
js_skipped() {
	local runs failures skipped ls lf
	ls="$(js_state_get last_success)"; lf="$(js_state_get last_failure)"
	skipped=$(( $(js_state_get skipped) + 1 ))
	runs="$(js_state_get runs)"; failures="$(js_state_get failures)"
	js_state_write "$ls" "$lf" "$skipped" "$runs" "$failures"
	JS_NOTE="skipped: another $JS_MODE run holds the lock"
	JS_STATUS_OVERRIDE="skipped"
}

js_on_exit() {
	local rc="$1"
	set +e                 # the wrappers run under set -e; recording must never be cut short by one failing step
	[ "$JS_DONE" = 1 ] && return 0
	JS_DONE=1
	js_write "$rc"
	[ -n "$JS_TMP" ] && rm -rf "$JS_TMP"
	return 0
}

# Write the status file, the state numbers and the log lines for this run.
js_write() {
	local rc="$1" end status dur ls lf skipped runs failures warns err_text first result log_dir
	end="$(date +%s)"
	dur=$((end - JS_START))
	ls="$(js_state_get last_success)"; lf="$(js_state_get last_failure)"
	skipped="$(js_state_get skipped)"; runs="$(js_state_get runs)"; failures="$(js_state_get failures)"
	warns=""; result=""
	if [ -n "$JS_TMP" ]; then
		warns="$(cat "$JS_OUT" "$JS_ERR" 2>/dev/null | sed -n 's/^GV_JOB_WARN: //p' | head -5)"
		result="$(cat "$JS_OUT" "$JS_ERR" 2>/dev/null | sed -n 's/^GV_JOB_RESULT: //p' | tail -1)"
	fi
	[ -n "$JS_WARN_EXTRA" ] && warns="${warns:+$warns
}$JS_WARN_EXTRA"
	[ -n "$JS_EXTRA_RESULT" ] && result="$JS_EXTRA_RESULT"
	if [ "${JS_STATUS_OVERRIDE:-}" = "skipped" ]; then
		status="skipped"
	else
		runs=$((runs + 1))
		if [ "$rc" -ne 0 ]; then
			status="failed"; lf="$end"; failures=$((failures + 1))
		else
			ls="$end"
			if [ -n "$warns" ]; then status="warning"; else status="ok"; fi
		fi
	fi
	# The error text: the wrapper's own note first, else the last lines of stderr that are not report markers.
	err_text=""
	if [ -n "$JS_NOTE" ]; then err_text="$JS_NOTE"; fi
	if [ "$status" = "failed" ] || [ "$status" = "warning" ]; then
		if [ -n "$JS_TMP" ] && [ -s "$JS_ERR" ]; then
			err_text="${err_text:+$err_text
}$(grep -v '^GV_JOB_' "$JS_ERR" 2>/dev/null | tail -5 | js_redact | cut -c1-300)"
		fi
		if [ "$status" = "failed" ] && [ -z "$err_text" ] && [ -n "$JS_TMP" ] && [ -s "$JS_OUT" ]; then
			err_text="$(tail -3 "$JS_OUT" | js_redact | cut -c1-300)"
		fi
		[ "$status" = "failed" ] && [ -z "$err_text" ] && err_text="exit code $rc with no output"
		[ "$status" = "warning" ] && err_text="${warns%%
*}"
	fi
	err_text="$(printf '%s' "$err_text" | head -c 1000)"
	first="$(printf '%s' "$err_text" | head -1 | cut -c1-200)"
	[ "${JS_STATUS_OVERRIDE:-}" = "skipped" ] || js_state_write "$ls" "$lf" "$skipped" "$runs" "$failures"

	mkdir -p "$JS_STATUS_DIR" 2>/dev/null
	local f="$JS_STATUS_DIR/.jobstatus-$JS_MODE.json" wj="" w
	while IFS= read -r w; do
		[ -n "$w" ] || continue
		wj="${wj:+$wj,}\"$(printf '%s' "$w" | js_redact | cut -c1-300 | js_esc)\""
	done <<EOF
$warns
EOF
	printf '{"v":1,"mode":"%s","status":"%s","last_start":%s,"last_end":%s,"last_success":%s,"last_failure":%s,"last_exit":%s,"duration":%s,"skipped":%s,"runs":%s,"failures":%s,"last_error":"%s","warnings":[%s],"result_json":"%s","python":"%s"}\n' \
		"$JS_MODE" "$status" "$JS_START" "$end" "$ls" "$lf" "$rc" "$dur" "$skipped" "$runs" "$failures" \
		"$(printf '%s' "$err_text" | js_esc)" "$wj" "$(printf '%s' "$result" | js_redact | head -c 2000 | js_esc)" "$(printf '%s' "${PYTHON:-}" | js_esc)" \
		> "$f.tmp$$" 2>/dev/null && mv -f "$f.tmp$$" "$f" 2>/dev/null

	# jobs.log: one line per run; jobs-errors.log: the full stderr of a failure.
	log_dir="$(js_log_dir)"
	if [ -d "$log_dir" ] || mkdir -p "$log_dir" 2>/dev/null; then
		printf '{"ts":%s,"mode":"%s","status":"%s","exit":%s,"start":%s,"end":%s,"duration":%s,"error":"%s"}\n' \
			"$end" "$JS_MODE" "$status" "$rc" "$JS_START" "$end" "$dur" "$(printf '%s' "$first" | js_esc)" >> "$log_dir/jobs.log" 2>/dev/null
		if [ "$status" = "failed" ] && [ -n "$JS_TMP" ]; then
			{
				printf '=== %s %s exit %s (started %s, %ss) ===\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$JS_MODE" "$rc" "$JS_START" "$dur"
				[ -n "$JS_NOTE" ] && printf '%s\n' "$JS_NOTE"
				tail -c 65536 "$JS_ERR" 2>/dev/null
				[ -s "$JS_ERR" ] || tail -c 4096 "$JS_OUT" 2>/dev/null
			} | js_redact >> "$log_dir/jobs-errors.log" 2>/dev/null
		fi
	fi
	return 0
}

# Preflight: can the chosen Python import what this mode needs? On failure record it as a failed
# run with a message that says what to do, and exit non-zero (never a silent success).
js_preflight() {   # <python> <mode>
	local py="$1" mode="$2" need="redis" out
	case "$mode" in nightly|train|train-clf) need="redis, numpy, sklearn" ;; report|geo) need="" ;; esac
	if ! command -v "$py" >/dev/null 2>&1 && [ ! -x "$py" ]; then
		JS_NOTE="preflight: Python not found: $py (set GV_PYTHON=/path/to/venv/bin/python in the crontab)"
		echo "ERROR: $JS_NOTE" >&2
		return 3
	fi
	[ -n "$need" ] || return 0
	if ! out="$("$py" -c "import $need" 2>&1)"; then
		JS_NOTE="preflight: $py cannot import: $(printf '%s' "$out" | tail -1 | cut -c1-160). Install analyzer/requirements.txt for it, or set GV_PYTHON to the virtualenv's python in the crontab."
		echo "ERROR: $JS_NOTE" >&2
		return 3
	fi
	return 0
}
