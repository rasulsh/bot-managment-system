#!/usr/bin/env bash
# Daily rotation for the Bot Guard JSONL logs.
# Gzips every finished day and drops archives older than the retention window.
# Cron example (03:10 every day):
#   10 3 * * * /full/path/bot-guard/scripts/guard-logrotate.sh >/dev/null 2>&1
set -euo pipefail

LOG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/logs"
RETENTION_DAYS=60

if [ ! -d "$LOG_DIR" ]; then
	echo "Bot Guard log rotation: log directory not found: $LOG_DIR"
	exit 0
fi

TODAY="guard-$(date +%Y%m%d).jsonl"
gzipped=0

for f in "$LOG_DIR"/guard-*.jsonl; do
	[ -e "$f" ] || continue
	[ "$(basename "$f")" = "$TODAY" ] && continue
	gzip -f "$f"
	gzipped=$((gzipped + 1))
done

# The guard's own error log (guard-errors.log) is tiny and throttled, so it is
# rotated by size rather than by day: past 1 MiB it is archived and restarted.
ERR="$LOG_DIR/guard-errors.log"
if [ -f "$ERR" ] && [ "$(wc -c < "$ERR")" -gt 1048576 ]; then
	mv "$ERR" "$LOG_DIR/guard-errors-$(date +%Y%m%d%H%M%S).log"
	gzip -f "$LOG_DIR"/guard-errors-*.log
fi
find "$LOG_DIR" -maxdepth 1 -name 'guard-errors-*.log.gz' -type f -mtime "+$RETENTION_DAYS" -delete

deleted=$(find "$LOG_DIR" -maxdepth 1 -name '*.jsonl.gz' -type f -mtime "+$RETENTION_DAYS" -print -delete | wc -l | tr -d ' ')

echo "Bot Guard log rotation: compressed $gzipped file(s), deleted $deleted archive(s) older than $RETENTION_DAYS days in $LOG_DIR"
