#!/usr/bin/env bash
# Self-test for the job status recording (scripts/lib-jobstatus.sh, used by analyzer-cron.sh and
# guard-logrotate.sh): success, failure, a crash recorded by the trap, a lock skip, a bad Python,
# warnings, results, redaction, the 64 KiB cap, and logrotate's own fields. A fake Python stands in for
# the analyzer. Temporary directories only: nothing is written into the repository.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
ok() { if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1"; FAIL=$((FAIL + 1)); fi; }
yes_if() { if "$@"; then echo 1; else echo 0; fi; }
export GV_JOBSTATUS_DIR="$WORK/status" GV_JOBLOG_DIR="$WORK/logs" GV_LOCK_DIR="$WORK/locks"
mkdir -p "$GV_JOBSTATUS_DIR" "$GV_JOBLOG_DIR" "$GV_LOCK_DIR"
# The fake python: "-c import ..." answers by FAKE_IMPORT, a script run behaves by FAKE_MODE.
cat > "$WORK/fakepy" <<'PY'
#!/usr/bin/env bash
if [ "$1" = "-c" ]; then [ "${FAKE_IMPORT:-ok}" = ok ] && exit 0; echo "ModuleNotFoundError: No module named 'redis'" >&2; exit 1; fi
case "${FAKE_MODE:-ok}" in
	ok) echo "did the work" ;;
	result) echo "GV_JOB_RESULT: {\"ml_trained\":true,\"ml_samples\":321}" >&2 ;;
	warn) echo "GV_JOB_WARN: no input rows" >&2; echo "ran" ;;
	fail) echo "Traceback (most recent call last):" >&2; echo "  File x.py, line 1" >&2; echo "ValueError: boom" >&2; exit 1 ;;
	secret) echo "connect failed: AUTH hunter2hunter2 password=letmein99 token: abc123456 and $FAKE_SECRET" >&2; exit 1 ;;
	big) head -c 200000 /dev/zero | tr '\0' 'x' >&2; echo >&2; echo "tail-line" >&2; exit 1 ;;
	sleep) sleep 30 ;;
esac
exit 0
PY
chmod +x "$WORK/fakepy"
export GV_PYTHON="$WORK/fakepy"
status() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d[sys.argv[2]])' "$GV_JOBSTATUS_DIR/.jobstatus-$1.json" "$2" 2>/dev/null; }
CRON="$ROOT/scripts/analyzer-cron.sh"

echo "== success"
FAKE_MODE=ok bash "$CRON" verify > "$WORK/o1" 2>&1; rc=$?
ok "exit 0 and the job's stdout is replayed unchanged" "$(yes_if [ $rc -eq 0 ] && grep -qx 'did the work' "$WORK/o1")"
ok "status ok, exit 0, start <= end, last_success set, no error" "$(yes_if [ "$(status verify status)" = ok ] && [ "$(status verify last_exit)" = 0 ] && [ "$(status verify last_start)" -le "$(status verify last_end)" ] && [ "$(status verify last_success)" -gt 0 ] && [ -z "$(status verify last_error)" ])"
ok "the status file is valid JSON with a duration and a run count" "$(yes_if [ -n "$(status verify duration)" ] && [ "$(status verify runs)" = 1 ])"
ok "jobs.log gets exactly one JSON line for the run" "$(yes_if [ "$(wc -l < "$GV_JOBLOG_DIR/jobs.log")" = 1 ] && python3 -c 'import json,sys; d=json.loads(open(sys.argv[1]).read().splitlines()[0]); sys.exit(0 if d["mode"]=="verify" and d["status"]=="ok" and d["exit"]==0 else 1)' "$GV_JOBLOG_DIR/jobs.log")"
ok "no error log for a success" "$(yes_if [ ! -s "$GV_JOBLOG_DIR/jobs-errors.log" ])"

echo "== a result and a warning"
FAKE_MODE=result bash "$CRON" train > /dev/null 2>&1
ok "a GV_JOB_RESULT line is kept in the status (training result)" "$(yes_if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); r=json.loads(d["result_json"]); sys.exit(0 if r["ml_samples"]==321 else 1)' "$GV_JOBSTATUS_DIR/.jobstatus-train.json")"
FAKE_MODE=warn bash "$CRON" snapshot > /dev/null 2>&1; rc=$?
ok "exit 0 but a GV_JOB_WARN line makes the status 'warning' with the reason (a silent no-op is visible)" "$(yes_if [ $rc -eq 0 ] && [ "$(status snapshot status)" = warning ] && [ "$(status snapshot last_error)" = "no input rows" ] && [ "$(status snapshot last_success)" -gt 0 ])"

echo "== failure"
FAKE_MODE=fail bash "$CRON" nightly > "$WORK/o2" 2> "$WORK/e2"; rc=$?
ok "the job's exit code is the wrapper's, and its stderr is replayed" "$(yes_if [ $rc -eq 1 ] && grep -q 'ValueError: boom' "$WORK/e2")"
ok "status failed, exit 1, last_failure set, the last error lines are kept" "$(yes_if [ "$(status nightly status)" = failed ] && [ "$(status nightly last_exit)" = 1 ] && [ "$(status nightly last_failure)" -gt 0 ] && status nightly last_error | grep -q 'ValueError: boom')"
ok "jobs-errors.log holds the captured stderr with a header" "$(yes_if grep -q 'nightly exit 1' "$GV_JOBLOG_DIR/jobs-errors.log" && grep -q 'ValueError: boom' "$GV_JOBLOG_DIR/jobs-errors.log")"
FAKE_MODE=ok bash "$CRON" nightly > /dev/null 2>&1
ok "a later success keeps the last failure time and the failure count" "$(yes_if [ "$(status nightly status)" = ok ] && [ "$(status nightly last_failure)" -gt 0 ] && [ "$(status nightly failures)" = 1 ] && [ "$(status nightly runs)" = 2 ])"

echo "== bad Python (the silent failure this prevents)"
FAKE_IMPORT=bad bash "$CRON" verify > /dev/null 2> "$WORK/e3"; rc=$?
ok "a Python that cannot import the packages is a non-zero exit with the fix in the message" "$(yes_if [ $rc -eq 3 ] && grep -q 'GV_PYTHON' "$WORK/e3")"
ok "...recorded as a failed run, not a success" "$(yes_if [ "$(status verify status)" = failed ] && status verify last_error | grep -q 'preflight')"
GV_PYTHON=/nonexistent/python bash "$CRON" verify > /dev/null 2>&1; rc=$?
ok "a Python that does not exist is recorded as a failure too" "$(yes_if [ $rc -eq 3 ] && status verify last_error | grep -q 'not found')"
export GV_PYTHON="$WORK/fakepy"

echo "== lock skip"
( export FAKE_MODE=sleep; bash "$CRON" geo > /dev/null 2>&1 & echo $! > "$WORK/pid" ) ; sleep 1
FAKE_MODE=ok bash "$CRON" geo > "$WORK/o4" 2>&1; rc=$?
ok "a firing that finds the lock busy exits 0 and says so" "$(yes_if [ $rc -eq 0 ] && grep -q 'already in progress' "$WORK/o4")"
ok "...and is visible: skipped count, status 'skipped', no failure recorded" "$(yes_if [ "$(status geo status)" = skipped ] && [ "$(status geo skipped)" = 1 ] && [ "$(status geo last_failure)" = 0 ])"
pkill -f "$WORK/fakepy" 2>/dev/null; pkill -f 'flock -n -E 99' 2>/dev/null; sleep 1

echo "== a crash or a signal is recorded by the trap"
( export FAKE_MODE=sleep; bash "$CRON" report > /dev/null 2>&1 & echo $! > "$WORK/pid2" ); sleep 1
W="$(cat "$WORK/pid2")"
pkill -TERM -P "$W" 2>/dev/null; kill -TERM "$W" 2>/dev/null; sleep 2
ok "a wrapper killed by SIGTERM still leaves a failed status (exit 143)" "$(yes_if [ "$(status report status)" = failed ] && [ "$(status report last_exit)" = 143 ])"

echo "== redaction and caps"
cat > "$WORK/config.php" <<'CFG'
<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }
$c = require __DIR__ . '/../scripts/config.dev.php';
CFG
sed -i "s#__DIR__ . '/../scripts/config.dev.php'#'$ROOT/scripts/config.dev.php'#" "$WORK/config.php"
printf "\$c['secret'] = 'sup3rS3cretValue99';\n\$c['redis']['password'] = 'redis-pass-12345';\nreturn \$c;\n" >> "$WORK/config.php"
GV_CONFIG="$WORK/config.php" FAKE_SECRET="leak sup3rS3cretValue99 and redis-pass-12345 end" FAKE_MODE=secret bash "$CRON" worker > /dev/null 2>&1
ALL="$(cat "$GV_JOBLOG_DIR/jobs-errors.log" "$GV_JOBSTATUS_DIR/.jobstatus-worker.json" "$GV_JOBLOG_DIR/jobs.log")"
ok "the configured secret and Redis password never reach the logs or the status" "$(yes_if [ -z "$(grep -c 'sup3rS3cretValue99\|redis-pass-12345' <<<"$ALL" | grep -v '^0$')" ])"
ok "generic patterns (AUTH x, password=x, token: x) are redacted too" "$(yes_if [ -z "$(grep -c 'hunter2hunter2\|letmein99\|abc123456' <<<"$ALL" | grep -v '^0$')" ] && grep -q REDACTED <<<"$ALL")"
: > "$GV_JOBLOG_DIR/jobs-errors.log"
FAKE_MODE=big bash "$CRON" verify > /dev/null 2>&1
ok "the captured stderr in jobs-errors.log is capped near 64 KiB and keeps the END of the output" "$(yes_if [ "$(wc -c < "$GV_JOBLOG_DIR/jobs-errors.log")" -lt 70000 ] && grep -q 'tail-line' "$GV_JOBLOG_DIR/jobs-errors.log")"
ok "the error text in the status file is short" "$(yes_if [ "$(status verify last_error | wc -c)" -lt 1100 ])"
ok "every status file is valid JSON" "$(yes_if python3 -c 'import json,glob,sys; [json.load(open(f)) for f in glob.glob(sys.argv[1]+"/.jobstatus-*.json")]' "$GV_JOBSTATUS_DIR")"

echo "== report keeps its stdout"
FAKE_MODE=ok bash "$CRON" report 2>/dev/null | grep -qx 'did the work'; ok "report's stdout passes straight through (it is piped to mail)" "$(yes_if [ ${PIPESTATUS[0]} -eq 0 ])"

echo "== guard-logrotate.sh records its own fields"
L="$WORK/rot"; mkdir -p "$L"
head -c 4096 /dev/urandom | base64 > "$L/guard-$(date -d '2 days ago' +%Y%m%d).jsonl"; touch -d '2 days ago' "$L/guard-$(date -d '2 days ago' +%Y%m%d).jsonl"
head -c 4096 /dev/urandom | base64 | gzip > "$L/guard-$(date -d '30 days ago' +%Y%m%d).jsonl.gz"; touch -d '30 days ago' "$L/guard-$(date -d '30 days ago' +%Y%m%d).jsonl.gz"
GV_PHP=/nonexistent GV_LOG_DIR="$L" GV_RETENTION_DAYS=10 GV_MIN_FREE_MB=0 GV_JOBLOG_DIR="$L" bash "$ROOT/scripts/guard-logrotate.sh" > /dev/null 2>&1; rc=$?
ok "logrotate status ok, with files gzipped, files deleted and bytes freed" "$(yes_if [ $rc -eq 0 ] && [ "$(status logrotate status)" = ok ] && python3 -c 'import json,sys; r=json.loads(json.load(open(sys.argv[1]))["result_json"]); sys.exit(0 if r["compressed"]==1 and r["deleted_retention"]==1 and r["bytes_freed"]>0 and r["reasons"]=="retention" else 1)' "$GV_JOBSTATUS_DIR/.jobstatus-logrotate.json")"
ok "logrotate writes its jobs.log line" "$(yes_if grep -q '"mode":"logrotate"' "$L/jobs.log")"
for i in 1 2 3; do mkfile() { head -c "$2" /dev/urandom | base64 > "$1"; }; mkfile "$L/guard-$(date -d "$((i + 3)) days ago" +%Y%m%d).jsonl.gz" 300000; touch -d "$((i + 3)) days ago" "$L/guard-$(date -d "$((i + 3)) days ago" +%Y%m%d).jsonl.gz"; done
GV_PHP=/nonexistent GV_LOG_DIR="$L" GV_RETENTION_DAYS=60 GV_MAX_MB=1 GV_MIN_FREE_MB=0 GV_JOBLOG_DIR="$L" bash "$ROOT/scripts/guard-logrotate.sh" > /dev/null 2>&1
ok "a deletion for the size cap is recorded with its reason" "$(yes_if python3 -c 'import json,sys; r=json.loads(json.load(open(sys.argv[1]))["result_json"]); sys.exit(0 if r["deleted_size_cap"]>=1 and "size_cap" in r["reasons"] else 1)' "$GV_JOBSTATUS_DIR/.jobstatus-logrotate.json")"
GV_PHP=/nonexistent GV_LOG_DIR="$L" GV_RETENTION_DAYS=60 GV_MAX_MB=0 GV_MIN_FREE_MB=999999999 GV_JOBLOG_DIR="$L" bash "$ROOT/scripts/guard-logrotate.sh" > /dev/null 2>&1
ok "a deletion for the free-disk floor is recorded with its reason" "$(yes_if python3 -c 'import json,sys; r=json.loads(json.load(open(sys.argv[1]))["result_json"]); sys.exit(0 if r["deleted_disk_floor"]>=1 and "disk_floor" in r["reasons"] else 1)' "$GV_JOBSTATUS_DIR/.jobstatus-logrotate.json")"
GV_PHP=/nonexistent GV_LOG_DIR="$WORK/nodir" GV_JOBLOG_DIR="$L" bash "$ROOT/scripts/guard-logrotate.sh" > /dev/null 2>&1
ok "a missing log directory is a warning, not a silent success" "$(yes_if [ "$(status logrotate status)" = warning ])"

echo
echo "PASS $PASS  FAIL $FAIL"
[ "$FAIL" -eq 0 ]
