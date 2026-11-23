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

umask 022   # whoever sources this library: its files are never group-writable, whatever cron's umask is (logs keep the modes of their own writers)

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
JS_LOCK_HOLDER=""     # who held the lock a skipped run found (e.g. "worker"), when known
JS_PYTHON_DESC=""     # "<python> (source: environment|crontab|venv|default)", recorded as "python" in the status file

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
# Correct the modes of the status files this wrapper owns: a run under cron's umask 002 (an earlier version) left them group-writable.
# Only regular files in the status directory, only ours, only group / other write is removed (nothing under logs/ is touched).
js_tidy_modes() {
	[ -d "$JS_STATUS_DIR" ] || return 0
	find "$JS_STATUS_DIR" -maxdepth 1 -type f -user "$(id -u)" -perm /022 \
		\( -name '.jobstatus-*' -o -name '.jobstate-*' -o -name '.lastrun-*' -o -name '.laststats-*' -o -name '.write.lock*' -o -name '.cron-check*' -o -name '.perm-check*' \) \
		-exec chmod go-w {} + 2>/dev/null
	return 0
}

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
	js_tidy_modes
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

# The value of NAME= in the user's crontab (the same parser as cron-check.sh), or nothing. Uses the SYSTEM python3 (standard library only),
# never GV_PYTHON: it is asked exactly when GV_PYTHON is not set.
js_crontab_env() {
	local sys="" c
	for c in /usr/bin/python3 /usr/local/bin/python3; do [ -x "$c" ] && { sys="$c"; break; }; done     # the system one first: python3 on PATH may be a virtualenv's or a stand-in
	[ -n "$sys" ] || sys="$(command -v python3 || command -v python || true)"
	[ -n "$sys" ] || return 0
	"$sys" "$JS_ROOT/scripts/cron_check.py" --get-env "$1" 2>/dev/null | head -1
	return 0
}

# Which Python runs the job, and why. Sets PYTHON and JS_PYTHON_DESC. Order:
#   1. GV_PYTHON from the environment          (cron with GV_PYTHON= in its crontab, or an exported variable)
#   2. GV_PYTHON from the user's crontab       (an operator running the job by hand over SSH has no GV_PYTHON, but the crontab names it)
#   3. <install-dir>/.venv/bin/python          when it exists and is executable
#   4. python3                                 whatever is first on PATH (usually without the packages: the preflight then says so)
# A crontab value that is not an executable file is ignored (step 3 / 4 follow).
js_python_resolve() {
	local src cand
	if [ -n "${GV_PYTHON:-}" ]; then
		PYTHON="$GV_PYTHON"; src="environment"
	else
		cand="$(js_crontab_env GV_PYTHON)"
		if [ -n "$cand" ] && [ -f "$cand" ] && [ -x "$cand" ]; then
			PYTHON="$cand"; src="crontab"
		elif [ -f "$JS_ROOT/.venv/bin/python" ] && [ -x "$JS_ROOT/.venv/bin/python" ]; then
			PYTHON="$JS_ROOT/.venv/bin/python"; src="venv"
		else
			PYTHON="python3"; src="default"
		fi
	fi
	JS_PYTHON_DESC="$PYTHON (source: $src)"
}

# The SAPI of a php binary ("cli", "cgi-fcgi", ...), or nothing when it cannot be run.
js_php_sapi() {
	local bin="$1" t
	command -v "$bin" >/dev/null 2>&1 || return 0
	t="$(mktemp 2>/dev/null)" || return 0
	printf '<?php echo PHP_SAPI;' > "$t"
	"$bin" -q "$t" 2>/dev/null | tail -n 1
	rm -f "$t"
	return 0
}

# When the php that would run (GV_PHP, else php on PATH) is not the command-line build (cPanel's default PATH finds php-cgi first), try
# /usr/local/bin/php (GV_PHP_FALLBACK overrides it, for tests) before failing: if THAT is a CLI build, GV_PHP is set to it for this run
# and the jobs it starts. Call before js_php_check, which warns when no CLI php is found.
js_php_resolve() {
	local cur="${GV_PHP:-php}" fb="${GV_PHP_FALLBACK:-/usr/local/bin/php}" sapi from
	sapi="$(js_php_sapi "$cur")"
	case "$sapi" in cli|'') return 0 ;; esac
	[ -f "$fb" ] && [ -x "$fb" ] || return 0
	from="$(command -v "$cur" 2>/dev/null)"
	[ "$from" != "$fb" ] || return 0
	[ "$(js_php_sapi "$fb")" = cli ] || return 0
	GV_PHP="$fb"
	export GV_PHP
	echo "note: $from is the $sapi SAPI, not the command line build; using $fb (set GV_PHP or add PATH=/usr/local/bin:/usr/bin:/bin to the crontab to make this explicit)" >&2
	return 0
}

# Who holds a write lock right now, from its holder file ("<mode> <pid> <start>"): prints the mode when that process is alive, else nothing.
# The holder file is written by whoever takes the lock (analyzer-cron.sh for nightly / train / train-clf, analyzer/worker.py for a write job).
js_lock_holder() {
	local f="$1" mode pid
	[ -r "$f" ] || return 0
	read -r mode pid _ < "$f" 2>/dev/null || return 0
	case "$pid" in ''|*[!0-9]*) return 0 ;; esac
	kill -0 "$pid" 2>/dev/null && printf '%s' "$mode"
	return 0
}

# A run that found another run holding the lock: not a failure, but not invisible.
#   js_skipped [waited-seconds] [holder-mode]
# With no argument (a `flock -n` mode) the note says another run holds the lock; with the seconds waited (a mode that WAITS for the
# lock, GV_LOCK_WAIT) it reads "skipped (lock busy after N s)". The holder, when known, is named and stored (lock_holder) so the panel can say who.
js_skipped() {
	local runs failures skipped ls lf waited="${1:-}" holder="${2:-}"
	ls="$(js_state_get last_success)"; lf="$(js_state_get last_failure)"
	skipped=$(( $(js_state_get skipped) + 1 ))
	runs="$(js_state_get runs)"; failures="$(js_state_get failures)"
	js_state_write "$ls" "$lf" "$skipped" "$runs" "$failures"
	if [ -n "$waited" ]; then JS_NOTE="skipped (lock busy after $waited s)"; else JS_NOTE="skipped: another run holds the lock"; fi
	[ -n "$holder" ] && JS_NOTE="$JS_NOTE, held by $holder"
	JS_LOCK_HOLDER="$holder"
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
	local rc="$1" end status dur ls lf skipped runs failures warns notes err_text first result log_dir
	end="$(date +%s)"
	dur=$((end - JS_START))
	ls="$(js_state_get last_success)"; lf="$(js_state_get last_failure)"
	skipped="$(js_state_get skipped)"; runs="$(js_state_get runs)"; failures="$(js_state_get failures)"
	warns=""; notes=""; result=""
	if [ -n "$JS_TMP" ]; then
		warns="$(cat "$JS_OUT" "$JS_ERR" 2>/dev/null | sed -n 's/^GV_JOB_WARN: //p' | head -5)"
		notes="$(cat "$JS_OUT" "$JS_ERR" 2>/dev/null | sed -n 's/^GV_JOB_INFO: //p' | head -5)"      # informational: never a warning
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
	local f="$JS_STATUS_DIR/.jobstatus-$JS_MODE.json" wj="" w nj=""
	while IFS= read -r w; do
		[ -n "$w" ] || continue
		wj="${wj:+$wj,}\"$(printf '%s' "$w" | js_redact | cut -c1-300 | js_esc)\""
	done <<EOF
$warns
EOF
	while IFS= read -r w; do
		[ -n "$w" ] || continue
		nj="${nj:+$nj,}\"$(printf '%s' "$w" | js_redact | cut -c1-300 | js_esc)\""
	done <<EOF
$notes
EOF
	printf '{"v":1,"mode":"%s","status":"%s","last_start":%s,"last_end":%s,"last_success":%s,"last_failure":%s,"last_exit":%s,"duration":%s,"skipped":%s,"runs":%s,"failures":%s,"last_error":"%s","warnings":[%s],"result_json":"%s","python":"%s","lock_holder":"%s","notes":[%s]}\n' \
		"$JS_MODE" "$status" "$JS_START" "$end" "$ls" "$lf" "$rc" "$dur" "$skipped" "$runs" "$failures" \
		"$(printf '%s' "$err_text" | js_esc)" "$wj" "$(printf '%s' "$result" | js_redact | head -c 2000 | js_esc)" "$(printf '%s' "${JS_PYTHON_DESC:-${PYTHON:-}}" | js_esc)" \
		"$(printf '%s' "$JS_LOCK_HOLDER" | js_esc)" "$nj" \
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
		JS_NOTE="preflight: Python not found: ${JS_PYTHON_DESC:-$py} (set GV_PYTHON=/path/to/venv/bin/python in the crontab)"
		echo "ERROR: $JS_NOTE" >&2
		return 3
	fi
	[ -n "$need" ] || return 0
	if ! out="$("$py" -c "import $need" 2>&1)"; then
		JS_NOTE="preflight: ${JS_PYTHON_DESC:-$py} cannot import: $(printf '%s' "$out" | tail -1 | cut -c1-160). Install analyzer/requirements.txt for it, or set GV_PYTHON to the virtualenv's python in the crontab."
		echo "ERROR: $JS_NOTE" >&2
		return 3
	fi
	return 0
}
