#!/usr/bin/env bash
# Self-test for scripts/guard-logrotate.sh: compression, retention, the size
# cap, the .last-rotate marker and reading settings from the guard config.
# Uses temporary directories only. Exit 0 when everything passes.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROT="$REPO/scripts/guard-logrotate.sh"
PASS=0
FAIL=0
ok() { if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1"; FAIL=$((FAIL + 1)); fi; }
yes_if() { if "$@"; then echo 1; else echo 0; fi; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# The job status files must not land in the repository's analyzer/ directory.
export GV_JOBSTATUS_DIR="$WORK/status"; mkdir -p "$GV_JOBSTATUS_DIR"

day() { date -d "$1 days ago" +%Y%m%d; }
mkfile() {   # <path> <age in days> <size in KiB>
	head -c "$(( $3 * 1024 ))" /dev/urandom | base64 > "$1"
	touch -d "$2 days ago" "$1"
}

# --- 1. compression and retention (environment overrides) ---------------------
L="$WORK/logs1"; mkdir -p "$L"
TODAY="guard-$(date +%Y%m%d).jsonl"
echo '{"a":1}' > "$L/$TODAY"
mkfile "$L/guard-$(day 1).jsonl" 1 4
mkfile "$L/guard-$(day 3).jsonl.gz" 3 4
mkfile "$L/guard-$(day 20).jsonl.gz" 20 4
ln -s /etc/passwd "$L/guard-$(day 5).jsonl"
GV_PHP=/nonexistent GV_LOG_DIR="$L" GV_RETENTION_DAYS=10 GV_MAX_MB=0 bash "$ROT" > "$WORK/out1" 2>&1
ok "exit 0" "$(yes_if [ $? -eq 0 ])"
ok "a finished day is gzipped" "$(yes_if test -f "$L/guard-$(day 1).jsonl.gz" -a ! -e "$L/guard-$(day 1).jsonl")"
ok "today's file is not touched" "$(yes_if [ -f "$L/$TODAY" ])"
ok "an archive inside the retention window is kept" "$(yes_if [ -f "$L/guard-$(day 3).jsonl.gz" ])"
ok "an archive older than the retention window is deleted" "$(yes_if [ ! -e "$L/guard-$(day 20).jsonl.gz" ])"
ok "a symlink named like a log is left alone" "$(yes_if [ -L "$L/guard-$(day 5).jsonl" ])"
ok "the run writes a valid .last-rotate marker" "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d["deleted"]==1 and d["compressed"]==1 and d["retention_days"]==10 else 1)' "$L/.last-rotate" && echo 1 || echo 0)"
ok "no temp marker is left behind" "$(yes_if [ ! -e "$L/.last-rotate.tmp" ])"

# --- 2. size cap: oldest archives go first, today's file never ----------------
L="$WORK/logs2"; mkdir -p "$L"
mkfile "$L/$TODAY" 0 300
for n in 2 3 4 5 6; do mkfile "$L/guard-$(day "$n").jsonl.gz" "$n" 400; done
GV_PHP=/nonexistent GV_LOG_DIR="$L" GV_RETENTION_DAYS=60 GV_MAX_MB=2 bash "$ROT" > "$WORK/out2" 2>&1
total=$(find "$L" -maxdepth 1 -type f -name 'guard-*' -printf '%s\n' | awk '{s+=$1} END {print s+0}')
ok "the logs fit under the cap afterwards ($total bytes <= 2 MiB)" "$(yes_if [ "$total" -le 2097152 ])"
ok "the oldest archives were deleted" "$(yes_if [ ! -e "$L/guard-$(day 6).jsonl.gz" ])"
ok "the newest archive was kept" "$(yes_if [ -f "$L/guard-$(day 2).jsonl.gz" ])"
ok "today's file was kept" "$(yes_if [ -f "$L/$TODAY" ])"
ok "the marker counts the capped archives" "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d["capped"]>=1 and d["over_cap"]==0 and d["max_mb"]==2 else 1)' "$L/.last-rotate" && echo 1 || echo 0)"

# --- 3. live files alone over the cap: reported, not deleted ------------------
L="$WORK/logs3"; mkdir -p "$L"
mkfile "$L/$TODAY" 0 1500
GV_PHP=/nonexistent GV_LOG_DIR="$L" GV_MAX_MB=1 bash "$ROT" > "$WORK/out3" 2>&1
ok "an over-cap live file is reported" "$(grep -q 'WARNING: the uncompressed log files alone exceed' "$WORK/out3" && echo 1 || echo 0)"
ok "and kept" "$(yes_if [ -f "$L/$TODAY" ])"
ok "the marker says over_cap" "$(python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["over_cap"]==1 else 1)' "$L/.last-rotate" && echo 1 || echo 0)"

# --- 4. settings from the guard config (config.php + overlay through PHP) ------
if command -v php >/dev/null 2>&1; then
	L="$WORK/logs4"; mkdir -p "$L"
	mkfile "$L/guard-$(day 4).jsonl.gz" 4 4
	mkfile "$L/guard-$(day 2).jsonl.gz" 2 4
	cat > "$WORK/config.php" <<PHP
<?php return array('secret' => 'x', 'log_dir' => '$L', 'log_retention_days' => 3, 'log_max_mb' => 7);
PHP
	GV_CONFIG="$WORK/config.php" bash "$ROT" > "$WORK/out4" 2>&1
	ok "log_dir and log_retention_days are read from the guard config" "$(yes_if test ! -e "$L/guard-$(day 4).jsonl.gz" -a -f "$L/guard-$(day 2).jsonl.gz")"
	ok "log_max_mb is read from the guard config" "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d["max_mb"]==7 and d["retention_days"]==3 else 1)' "$L/.last-rotate" && echo 1 || echo 0)"
	cat > "$WORK/config-bad.php" <<PHP
<?php return array('secret' => 'x', 'log_dir' => '$L', 'log_retention_days' => 'forever');
PHP
	GV_CONFIG="$WORK/config-bad.php" bash "$ROT" > "$WORK/out5" 2>&1
	ok "an invalid retention value falls back to 60" "$(grep -q 'older than 60 days' "$WORK/out5" && echo 1 || echo 0)"
else
	echo "SKIP  settings from the guard config (php not available)"
fi

# --- 5. a finished day is compressed at the next run, whatever the time zones say ------------------------------------------------
# The guard names its file by PHP's date. When that date is AHEAD of the shell's (a Tehran PHP on a UTC host, from 20:30 UTC), the
# shell's "today" file is already finished; the old script treated it as live and compressed nothing until the next day.
L="$WORK/logs5"; mkdir -p "$L"
printf '{"a":1}\n' > "$L/guard-$(day -1).jsonl"          # the guard's date: tomorrow by the shell's clock; it is the live file
mkfile "$L/guard-$(day 0).jsonl" 0 8                      # the shell's today: finished by the guard's clock
touch -d "3 hours ago" "$L/guard-$(day 0).jsonl"
mkfile "$L/guard-$(day 1).jsonl" 1 8
GV_PHP=/nonexistent GV_LOG_DIR="$L" GV_RETENTION_DAYS=60 bash "$ROT" > "$WORK/out6" 2>&1
ok "a finished day that is 'today' by the shell's clock but older than the newest file is gzipped" "$(yes_if test -f "$L/guard-$(day 0).jsonl.gz" -a ! -e "$L/guard-$(day 0).jsonl")"
ok "yesterday is gzipped too" "$(yes_if test -f "$L/guard-$(day 1).jsonl.gz" -a ! -e "$L/guard-$(day 1).jsonl")"
ok "the newest file (the live one) is never touched" "$(yes_if test -f "$L/guard-$(day -1).jsonl")"
ok "the archive is a valid gzip" "$(yes_if gzip -t "$L/guard-$(day 0).jsonl.gz")"
ok "no temporary archive is left" "$(yes_if test -z "$(find "$L" -maxdepth 1 -name '*.tmp')")"
ok "the marker reports the live file and no failures" "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d["failures"]==0 and d["compressed"]==2 else 1)' "$L/.last-rotate" && echo 1 || echo 0)"
ok "the job result says which file was live" "$(grep -q 'compressed 2 file' "$WORK/out6" && echo 1 || echo 0)"

# A day still being written (idle for less than the threshold) is left for the next run and reported.
L="$WORK/logs6"; mkdir -p "$L"
printf '{"a":1}\n' > "$L/guard-$(day 0).jsonl"
printf '{"b":2}\n' > "$L/guard-$(day 1).jsonl"           # finished, but written to just now (a request in flight at midnight)
GV_PHP=/nonexistent GV_LOG_DIR="$L" bash "$ROT" > "$WORK/out7" 2>&1
ok "a finished day written to a moment ago is not compressed yet" "$(yes_if test -f "$L/guard-$(day 1).jsonl")"
ok "and the run says so" "$(grep -q 'left for the next run' "$WORK/out7" && echo 1 || echo 0)"

# --- 6. never two copies of a day (audit LOG-15), and a day written to after it was archived loses nothing -----------------------
L="$WORK/logs7"; mkdir -p "$L"
printf '{"n":1}\n{"n":2}\n' > "$L/guard-$(day 2).jsonl"
gzip -c "$L/guard-$(day 2).jsonl" > "$L/guard-$(day 2).jsonl.gz"          # an interrupted run: archive written and renamed, plain file not yet removed
touch -d "2 hours ago" "$L/guard-$(day 2).jsonl"
printf '{"n":3}\n' > "$L/guard-$(day 3).jsonl.gz.tmp"                      # a half-written archive from an earlier crash
touch -d "2 hours ago" "$L/guard-$(day 3).jsonl.gz.tmp"
printf '{"x":0}\n' > "$L/guard-$(day 0).jsonl"
GV_PHP=/nonexistent GV_LOG_DIR="$L" bash "$ROT" > "$WORK/out8" 2>&1
ok "archive and plain file both present: the plain file is removed, the archive kept" "$(yes_if test -f "$L/guard-$(day 2).jsonl.gz" -a ! -e "$L/guard-$(day 2).jsonl")"
ok "...and the archive still holds each row exactly once" "$([ "$(zcat "$L/guard-$(day 2).jsonl.gz" | wc -l)" -eq 2 ] && echo 1 || echo 0)"
ok "a stale half-written .gz.tmp is removed" "$(yes_if test ! -e "$L/guard-$(day 3).jsonl.gz.tmp")"

L="$WORK/logs8"; mkdir -p "$L"
printf '{"n":1}\n' | gzip -c > "$L/guard-$(day 2).jsonl.gz"               # compressed once ...
touch -d "5 hours ago" "$L/guard-$(day 2).jsonl.gz"
printf '{"n":2}\n' > "$L/guard-$(day 2).jsonl"                            # ... and written to again afterwards
touch -d "2 hours ago" "$L/guard-$(day 2).jsonl"
printf '{"x":0}\n' > "$L/guard-$(day 0).jsonl"
GV_PHP=/nonexistent GV_LOG_DIR="$L" bash "$ROT" > "$WORK/out9" 2>&1
ok "a day archived and written to again is merged: no row lost" "$([ "$(zcat "$L/guard-$(day 2).jsonl.gz" | tr -d '\n')" = '{"n":1}{"n":2}' ] && echo 1 || echo 0)"
ok "...and the plain file is gone" "$(yes_if test ! -e "$L/guard-$(day 2).jsonl")"

# A second run at the same time is skipped, not run in parallel.
L="$WORK/logs9"; mkdir -p "$L"
printf '{"x":0}\n' > "$L/guard-$(day 0).jsonl"
if command -v flock >/dev/null 2>&1; then
	( flock -n 8 || exit 1; GV_PHP=/nonexistent GV_LOG_DIR="$L" bash "$ROT" > "$WORK/out10" 2>&1 ) 8>"$L/.logrotate.lock"
	ok "a run while another holds the lock is skipped" "$(grep -q 'Another log rotation is already running' "$WORK/out10" && echo 1 || echo 0)"
fi
# The job status records which idle-priority tools were used.
ok "the job status records the idle priority tools used (lowprio)" "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if "lowprio" in d else 1)' "$GV_JOBSTATUS_DIR/.jobstatus-logrotate.json" && echo 1 || echo 0)"

echo
echo "PASS $PASS  FAIL $FAIL"
[ "$FAIL" -eq 0 ]
