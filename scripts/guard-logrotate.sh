#!/usr/bin/env bash
# shellcheck disable=SC2034  # the JS_* variables are read by scripts/lib-jobstatus.sh
# Daily rotation for the Bot Guard JSONL logs.
# Gzips every finished day, drops archives older than the retention window and,
# when a size cap is set, the oldest archives until the logs fit under it.
# Cron example (03:10 every day):
#   10 3 * * * bash /full/path/bot-guard/scripts/guard-logrotate.sh >/dev/null 2>&1
#
# Settings come from the guard's effective config (guard/config.php plus the
# panel overlay), read through scripts/config-dump.php:
#   log_dir             where the logs are
#   log_retention_days  archives older than this are deleted (default 60 here and in the guard; the config.php of a NEW install sets 30)
#   log_max_mb          total size cap for logs/ in MiB, 0 = no cap (default 0)
# Environment overrides: GV_LOG_DIR, GV_RETENTION_DAYS, GV_MAX_MB, GV_MIN_IDLE_MINUTES. GV_PHP names
# the PHP binary (cron has a minimal PATH). Without PHP the defaults apply.
#
# Every run writes logs/.last-rotate (one JSON line) for the panel dashboard, and records its
# status for the job-health page (scripts/lib-jobstatus.sh: analyzer/.jobstatus-logrotate.json,
# logs/jobs.log): files gzipped, files deleted, bytes freed and why (retention, size cap, or the
# free-disk floor log_min_free_mb), plus a failure with its error text.
#
# The free-disk floor only REPORTS by default. The disk is shared with the whole server (backups,
# other sites): a full disk that is not the logs' fault must never make this script delete the
# training history. Deleting for the floor is opt-in (log_floor_delete), never touches an archive
# newer than log_floor_keep_days (default 7), and removes at most 10 files per run.
#
# What this script is careful about:
#   * It never compresses the live file. The guard names its file by PHP's date and this script runs in the shell's time zone, and
#     the two can differ (and cron's php may use another php.ini than the web server's), so "today" is NOT taken from the clock: the
#     file with the NEWEST date in its name is the one the guard is writing, and every older day is finished. A finished day is also
#     left alone while it was written to in the last GV_MIN_IDLE_MINUTES (default 10), for requests still in flight at midnight.
#     (Before 2026.11.38 the day was taken from the shell's date and an idle time of 60 minutes: when the two time zones differed,
#     yesterday's file could be skipped as "live" for hours, and on a site that logs all day nothing was compressed.)
#   * It never overwrites an archive and never leaves two copies of a day. The archive is written as <day>.jsonl.gz.tmp (a copy of
#     the existing archive followed by the new rows, when the day was already archived and written to again), verified with
#     gzip -t, renamed over <day>.jsonl.gz, and only then is the plain file removed. An interruption leaves the plain file (the
#     next run starts again) or, after the rename, both files with the archive not older: the next run verifies the archive and
#     removes the plain file. The analyzer reads only one of the two (analyzer/logs.py day_files).
#   * The work runs at idle priority (nice -n 19, ionice -c3 when they exist) and gzip -6; a run takes a lock, so two runs never
#     compress the same day together.
#   * It only touches regular files. A directory, FIFO or symlink that happens
#     to be named like a log is skipped, so a planted symlink cannot make a root
#     cron job compress some other file, and one odd entry cannot stop the run.
#   * One failure does not abort the rest: retention still runs, and the exit
#     status is non-zero so cron can report it.
#   * Every skipped or failed day is reported with its reason (the output, the job status "result" and logs/.last-rotate).
set -uo pipefail
umask 022          # cron may run with 002; what this script creates (status files, the .last-rotate marker) is not group-writable. Logs keep their own modes.

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHP_BIN="${GV_PHP:-php}"
JS_ROOT="$REPO"
# shellcheck source=lib-jobstatus.sh
. "$REPO/scripts/lib-jobstatus.sh"
js_begin logrotate
js_php_resolve                       # a non-CLI php on PATH: try /usr/local/bin/php before the warning
PHP_BIN="${GV_PHP:-php}"
js_php_check "$PHP_BIN"
js_lowprio_detect                    # nice -n 19 / ionice -c3 when they exist (recorded as "lowprio" in the job status)

# One effective setting, or nothing when PHP or the key is unavailable.
cfg_get() {
	"$PHP_BIN" -q "$REPO/scripts/config-dump.php" --get "$1" 2>/dev/null
}
# A whole number at least $2, else the default $3.
int_or() {
	case "$1" in ''|*[!0-9]*) echo "$3" ;; *) if [ "$1" -ge "$2" ]; then echo "$1"; else echo "$3"; fi ;; esac
}

LOG_DIR="${GV_LOG_DIR:-$(cfg_get log_dir)}"
[ -n "$LOG_DIR" ] || LOG_DIR="$REPO/logs"
RETENTION_DAYS="$(int_or "${GV_RETENTION_DAYS:-$(cfg_get log_retention_days)}" 1 60)"
MAX_MB="$(int_or "${GV_MAX_MB:-$(cfg_get log_max_mb)}" 0 0)"
MIN_FREE_MB="$(int_or "${GV_MIN_FREE_MB:-$(cfg_get log_min_free_mb)}" 0 200)"
FLOOR_DELETE="${GV_FLOOR_DELETE:-$(cfg_get log_floor_delete)}"
FLOOR_KEEP_DAYS="$(int_or "${GV_FLOOR_KEEP_DAYS:-$(cfg_get log_floor_keep_days)}" 1 7)"
FLOOR_MAX_FILES=10
MIN_IDLE_MINUTES="$(int_or "${GV_MIN_IDLE_MINUTES:-}" 0 10)"

# The job logs live in the same directory: tell the status writer where.
export GV_JOBLOG_DIR="$LOG_DIR"

if [ ! -d "$LOG_DIR" ]; then
	echo "Bot Guard log rotation: log directory not found: $LOG_DIR"
	JS_WARN_EXTRA="the log directory was not found: $LOG_DIR, nothing was rotated"
	exit 0
fi

total_bytes() {
	find "$LOG_DIR" -maxdepth 1 -type f \( -name 'guard-*' -o -name 'jobs*.log*' \) -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}'
}
bytes_before="$(total_bytes)"
reasons=""
gzipped=0
skipped=0
failed=0
skipped_live=0
skipped_idle=0
fail_notes=""

# One lock: a second run (cron fires hourly, or somebody runs it by hand) never compresses the same day at the same time.
if command -v flock >/dev/null 2>&1 && { exec 9>"$LOG_DIR/.logrotate.lock"; } 2>/dev/null; then
	if ! flock -n 9; then
		echo "Another log rotation is already running; skipping this one."
		js_skipped
		JS_EXIT=0
		exit 0
	fi
fi

# Leftovers of an interrupted run: a half-written archive is never used.
find "$LOG_DIR" -maxdepth 1 -type f -name 'guard-*.jsonl.gz.tmp' -mmin +30 -delete 2>/dev/null

# The live file is the one with the newest date in its name (see the header): finished days are the older ones.
NEWEST="$(find "$LOG_DIR" -maxdepth 1 -type f -name 'guard-????????.jsonl' -printf '%f\n' 2>/dev/null | sort | tail -1)"

# compress_day <plain file>: archive one finished day atomically. Returns 0 on success.
compress_day() {
	local f="$1" gz="$1.gz" tmp="$1.gz.tmp" rc=0
	if [ -e "$gz" ] || [ -L "$gz" ]; then
		[ -f "$gz" ] && [ ! -L "$gz" ] || { fail_notes="${fail_notes}${fail_notes:+; }$(basename "$gz") is not a regular file"; return 1; }
		if [ ! "$f" -nt "$gz" ]; then
			# The archive is not older than the plain file: an interrupted earlier run (or a copy). Verify it, then drop the plain file.
			if gzip -t -- "$gz" 2>/dev/null; then rm -f -- "$f" && return 0; fi
			fail_notes="${fail_notes}${fail_notes:+; }$(basename "$gz") failed gzip -t, the plain file was kept"
			return 1
		fi
		# Compressed once and written to again since: archive + the new rows, as one verified archive.
		{ cat -- "$gz" && ${JS_LOWPRIO[@]+"${JS_LOWPRIO[@]}"} gzip -6 -c -- "$f"; } > "$tmp" 2>/dev/null || rc=$?
	else
		${JS_LOWPRIO[@]+"${JS_LOWPRIO[@]}"} gzip -6 -c -- "$f" > "$tmp" 2>/dev/null || rc=$?
	fi
	if [ "$rc" -ne 0 ] || ! gzip -t -- "$tmp" 2>/dev/null; then
		rm -f -- "$tmp"
		fail_notes="${fail_notes}${fail_notes:+; }$(basename "$f"): compressing failed (disk full or no permission?)"
		return 1
	fi
	mv -f -- "$tmp" "$gz" || { rm -f -- "$tmp"; fail_notes="${fail_notes}${fail_notes:+; }$(basename "$f"): could not rename the archive"; return 1; }
	rm -f -- "$f" || { fail_notes="${fail_notes}${fail_notes:+; }$(basename "$f"): archived but the plain file could not be removed"; return 1; }
	return 0
}

while IFS= read -r -d '' f; do
	name="$(basename "$f")"
	if [ "$name" = "$NEWEST" ]; then skipped_live=$((skipped_live + 1)); continue; fi
	if [ -z "$(find "$f" -maxdepth 0 -mmin "+$MIN_IDLE_MINUTES" 2>/dev/null)" ]; then skipped_idle=$((skipped_idle + 1)); continue; fi
	if compress_day "$f"; then gzipped=$((gzipped + 1)); else failed=$((failed + 1)); fi
done < <(find "$LOG_DIR" -maxdepth 1 -type f -name 'guard-????????.jsonl' -print0 | sort -z)

# Anything named like a log that is not a regular file is reported, not touched.
skipped=$(find "$LOG_DIR" -maxdepth 1 -name 'guard-*.jsonl' ! -type f -print | wc -l | tr -d ' ')

# The guard's own error log (guard-errors.log) is tiny and throttled, so it is
# rotated by size rather than by day: past 1 MiB it is archived and restarted.
ERR="$LOG_DIR/guard-errors.log"
if [ -f "$ERR" ] && [ ! -L "$ERR" ] && [ "$(wc -c < "$ERR")" -gt 1048576 ]; then
	ARCH="$LOG_DIR/guard-errors-$(date +%Y%m%d%H%M%S).log"
	if mv -- "$ERR" "$ARCH" && ${JS_LOWPRIO[@]+"${JS_LOWPRIO[@]}"} gzip -6 -- "$ARCH"; then :; else failed=$((failed + 1)); fi
fi
find "$LOG_DIR" -maxdepth 1 -name 'guard-errors-*.log.gz' -type f -mtime "+$RETENTION_DAYS" -delete || failed=$((failed + 1))

# The job logs (jobs.log, jobs-errors.log) are rotated the same way: past 1 MiB they are archived and
# restarted, and archives older than the retention window are deleted.
for jl in jobs jobs-errors; do
	JF="$LOG_DIR/$jl.log"
	if [ -f "$JF" ] && [ ! -L "$JF" ] && [ "$(wc -c < "$JF")" -gt 1048576 ]; then
		JA="$LOG_DIR/$jl-$(date +%Y%m%d%H%M%S).log"
		if mv -- "$JF" "$JA" && ${JS_LOWPRIO[@]+"${JS_LOWPRIO[@]}"} gzip -6 -- "$JA"; then :; else failed=$((failed + 1)); fi
	fi
done
find "$LOG_DIR" -maxdepth 1 \( -name 'jobs-*.log.gz' -o -name 'jobs-errors-*.log.gz' \) -type f -mtime "+$RETENTION_DAYS" -delete || failed=$((failed + 1))

deleted=$(find "$LOG_DIR" -maxdepth 1 -name '*.jsonl.gz' -type f -mtime "+$RETENTION_DAYS" -print -delete | wc -l | tr -d ' ')
[ "$deleted" -eq 0 ] || reasons="retention"

# Size cap: delete the oldest daily archives until every guard-* file together
# fits under log_max_mb. Uncompressed files (today, or a day not yet idle for an
# hour) are never deleted; if they alone are over the cap, that is reported.
capped=0
over=0
floor_deleted=0
floor_limit_hit=0
disk_low=0
if [ "$MAX_MB" -gt 0 ]; then
	limit=$((MAX_MB * 1048576))
	while [ "$(total_bytes)" -gt "$limit" ]; do
		oldest="$(find "$LOG_DIR" -maxdepth 1 -type f \( -name 'guard-*.jsonl.gz' -o -name 'guard-errors-*.log.gz' \) -printf '%T@ %p\n' | sort -n | head -1 | cut -d' ' -f2-)"
		if [ -z "$oldest" ]; then over=1; break; fi
		if rm -f -- "$oldest"; then capped=$((capped + 1)); else failed=$((failed + 1)); break; fi
	done
fi

# Free-disk floor: when the disk holding the logs is below log_min_free_mb the guard has already stopped
# logging. This script always REPORTS that (status warning, jobs.log, dashboard alert). It deletes for it only
# when log_floor_delete is on: the oldest archives first, never an uncompressed file, never an archive newer
# than log_floor_keep_days, and at most FLOOR_MAX_FILES per run (the limit being hit is recorded).
# df sees the filesystem, not the cPanel / CloudLinux user quota (docs/06-KNOWN-LIMITS.md).
free_mb() { df -Pm "$LOG_DIR" 2>/dev/null | awk 'NR==2 {print $4+0}'; }
if [ "$MIN_FREE_MB" -gt 0 ] && [ -n "$(free_mb)" ] && [ "$(free_mb)" -lt "$MIN_FREE_MB" ]; then
	disk_low=1
	if [ "$FLOOR_DELETE" = "true" ]; then
		while [ "$(free_mb)" -lt "$MIN_FREE_MB" ]; do
			if [ "$floor_deleted" -ge "$FLOOR_MAX_FILES" ]; then floor_limit_hit=1; break; fi
			oldest="$(find "$LOG_DIR" -maxdepth 1 -type f \( -name 'guard-*.jsonl.gz' -o -name 'guard-errors-*.log.gz' \) -mtime "+$FLOOR_KEEP_DAYS" -printf '%T@ %p\n' | sort -n | head -1 | cut -d' ' -f2-)"
			[ -n "$oldest" ] || break
			if rm -f -- "$oldest"; then floor_deleted=$((floor_deleted + 1)); else failed=$((failed + 1)); break; fi
		done
	fi
fi
# The user's own quota, when the tools exist (cPanel / CloudLinux): recorded, never acted on.
quota_text=""
for q in quota /usr/bin/quota; do
	if command -v "$q" >/dev/null 2>&1; then
		quota_text="$("$q" -s -w 2>/dev/null | sed -n '3,4p' | tr -s ' ' | tr '\n' ' ' | tr -cd 'A-Za-z0-9 ./:_+%-' | cut -c1-160)"
		break
	fi
done
[ "$capped" -eq 0 ] || reasons="${reasons:+$reasons,}size_cap"
[ "$floor_deleted" -eq 0 ] || reasons="${reasons:+$reasons,}disk_floor"

bytes="$(total_bytes)"
freed=$((bytes_before > bytes ? bytes_before - bytes : 0))
JS_EXTRA_RESULT="$(printf '{"compressed":%s,"deleted_retention":%s,"deleted_size_cap":%s,"deleted_disk_floor":%s,"bytes_freed":%s,"bytes_now":%s,"reasons":"%s","over_cap":%s,"disk_low":%s,"free_mb":%s,"floor_delete":%s,"floor_keep_days":%s,"floor_limit_hit":%s,"quota":"%s","skipped_live":%s,"skipped_idle":%s,"newest":"%s","failed_notes":"%s"}' \
	"$gzipped" "$deleted" "$capped" "$floor_deleted" "$freed" "$bytes" "$reasons" "$over" "$disk_low" "$(free_mb | grep -E '^[0-9]+$' || echo 0)" \
	"$([ "$FLOOR_DELETE" = true ] && echo true || echo false)" "$FLOOR_KEEP_DAYS" "$floor_limit_hit" "$quota_text" "$skipped_live" "$skipped_idle" "${NEWEST#guard-}" "$(printf '%s' "$fail_notes" | js_esc | cut -c1-300)")"
[ "$over" -eq 0 ] || JS_WARN_EXTRA="the uncompressed log files alone exceed log_max_mb (${MAX_MB} MiB)"
if [ "$disk_low" -eq 1 ]; then
	JS_WARN_EXTRA="${JS_WARN_EXTRA:+$JS_WARN_EXTRA
}free disk space is below log_min_free_mb (${MIN_FREE_MB} MiB)$([ "$FLOOR_DELETE" = true ] || echo '; log_floor_delete is off, nothing was deleted for it')$([ "$floor_limit_hit" -eq 0 ] || echo "; stopped at the limit of $FLOOR_MAX_FILES files per run")"
fi
printf '{"ts":%s,"compressed":%s,"deleted":%s,"capped":%s,"over_cap":%s,"failures":%s,"retention_days":%s,"max_mb":%s,"bytes":%s}\n' \
	"$(date +%s)" "$gzipped" "$deleted" "$capped" "$over" "$failed" "$RETENTION_DAYS" "$MAX_MB" "$bytes" \
	> "$LOG_DIR/.last-rotate.tmp" && mv -f -- "$LOG_DIR/.last-rotate.tmp" "$LOG_DIR/.last-rotate" || failed=$((failed + 1))

[ "$skipped_idle" -eq 0 ] || echo "NOTE: $skipped_idle finished day(s) were written to in the last $MIN_IDLE_MINUTES minute(s) and are left for the next run."
[ -z "$fail_notes" ] || echo "FAILED: $fail_notes"
echo "Bot Guard log rotation: compressed $gzipped file(s), deleted $deleted archive(s) older than $RETENTION_DAYS days, $capped more for the ${MAX_MB} MiB cap, skipped $skipped non-regular entr(ies), $failed failure(s) in $LOG_DIR ($bytes bytes now)"
[ "$over" -eq 0 ] || echo "WARNING: the uncompressed log files alone exceed log_max_mb (${MAX_MB} MiB); lower traffic logging (log_skip_paths) or raise the cap."
[ "$disk_low" -eq 0 ] || echo "WARNING: free disk space is below log_min_free_mb (${MIN_FREE_MB} MiB); deleted $floor_deleted archive(s) for it (log_floor_delete=${FLOOR_DELETE:-false}, keeping the last $FLOOR_KEEP_DAYS days)."
[ "$floor_limit_hit" -eq 0 ] || echo "NOTICE: stopped at the limit of $FLOOR_MAX_FILES files per run; the next run continues."
if [ "$failed" -ne 0 ]; then JS_NOTE="$failed failure(s) while rotating logs in $LOG_DIR${fail_notes:+: $fail_notes}"; exit 1; fi
exit 0
