#!/usr/bin/env bash
# Daily rotation for the Bot Guard JSONL logs.
# Gzips every finished day and drops archives older than the retention window.
# Cron example (03:10 every day):
#   10 3 * * * /full/path/bot-guard/scripts/guard-logrotate.sh >/dev/null 2>&1
#
# GV_LOG_DIR overrides the directory (use it when log_dir in guard/config.php
# is not the default <repo>/logs).
#
# What this script is careful about:
#   * It never compresses a file that was written to in the last hour. The
#     guard names its file by PHP's date and this script by the system's; when
#     the two time zones differ, "not today's file" can still be the live one.
#   * It never overwrites an archive. If a .gz for that day already exists the
#     new rows are appended to it as a second gzip member (still one valid .gz).
#   * It only touches regular files. A directory, FIFO or symlink that happens
#     to be named like a log is skipped, so a planted symlink cannot make a root
#     cron job compress some other file, and one odd entry cannot stop the run.
#   * One failure does not abort the rest: retention still runs, and the exit
#     status is non-zero so cron can report it.
set -uo pipefail

LOG_DIR="${GV_LOG_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/logs}"
RETENTION_DAYS=60
MIN_IDLE_MINUTES=60

if [ ! -d "$LOG_DIR" ]; then
	echo "Bot Guard log rotation: log directory not found: $LOG_DIR"
	exit 0
fi

TODAY="guard-$(date +%Y%m%d).jsonl"
gzipped=0
skipped=0
failed=0

while IFS= read -r -d '' f; do
	name="$(basename "$f")"
	[ "$name" = "$TODAY" ] && continue
	if [ -e "$f.gz" ]; then
		# Never overwrite: append as another gzip member, then drop the source.
		if [ -f "$f.gz" ] && [ ! -L "$f.gz" ] && gzip -c -- "$f" >> "$f.gz" && rm -f -- "$f"; then
			gzipped=$((gzipped + 1))
		else
			failed=$((failed + 1))
		fi
		continue
	fi
	if gzip -- "$f"; then
		gzipped=$((gzipped + 1))
	else
		failed=$((failed + 1))
	fi
done < <(find "$LOG_DIR" -maxdepth 1 -type f -name 'guard-*.jsonl' -mmin "+$MIN_IDLE_MINUTES" -print0)

# Anything named like a log that is not a regular file is reported, not touched.
skipped=$(find "$LOG_DIR" -maxdepth 1 -name 'guard-*.jsonl' ! -type f -print | wc -l | tr -d ' ')

# The guard's own error log (guard-errors.log) is tiny and throttled, so it is
# rotated by size rather than by day: past 1 MiB it is archived and restarted.
ERR="$LOG_DIR/guard-errors.log"
if [ -f "$ERR" ] && [ ! -L "$ERR" ] && [ "$(wc -c < "$ERR")" -gt 1048576 ]; then
	ARCH="$LOG_DIR/guard-errors-$(date +%Y%m%d%H%M%S).log"
	if mv -- "$ERR" "$ARCH" && gzip -- "$ARCH"; then :; else failed=$((failed + 1)); fi
fi
find "$LOG_DIR" -maxdepth 1 -name 'guard-errors-*.log.gz' -type f -mtime "+$RETENTION_DAYS" -delete || failed=$((failed + 1))

deleted=$(find "$LOG_DIR" -maxdepth 1 -name '*.jsonl.gz' -type f -mtime "+$RETENTION_DAYS" -print -delete | wc -l | tr -d ' ')

echo "Bot Guard log rotation: compressed $gzipped file(s), deleted $deleted archive(s) older than $RETENTION_DAYS days, skipped $skipped non-regular entr(ies), $failed failure(s) in $LOG_DIR"
[ "$failed" -eq 0 ] || exit 1
exit 0
