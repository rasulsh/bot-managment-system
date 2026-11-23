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
echo "== the free-disk floor: report by default, delete only when allowed, protect recent files, at most 10 per run"
F="$WORK/floor"; mkdir -p "$F"
mkarch() { head -c 2048 /dev/urandom | base64 | gzip > "$1"; touch -d "$2 days ago" "$1"; }
fresh_floor() { rm -f "$F"/guard-*; for i in $(seq 1 15); do mkarch "$F/guard-$(date -d "$((i + 9)) days ago" +%Y%m%d).jsonl.gz" "$((i + 9))"; done; for i in 1 2 3; do mkarch "$F/guard-$(date -d "$i days ago" +%Y%m%d).jsonl.gz" "$i"; done; }
floor_run() { GV_PHP=/nonexistent GV_LOG_DIR="$F" GV_RETENTION_DAYS=365 GV_MAX_MB=0 GV_MIN_FREE_MB=999999999 GV_JOBLOG_DIR="$F" "$@" bash "$ROOT/scripts/guard-logrotate.sh" > "$WORK/floor.out" 2>&1; }
rstat() { python3 -c 'import json,sys; r=json.loads(json.load(open(sys.argv[1]))["result_json"]); print(r[sys.argv[2]])' "$GV_JOBSTATUS_DIR/.jobstatus-logrotate.json" "$1"; }
count_arch() { find "$F" -name 'guard-*.jsonl.gz' | wc -l | tr -d ' '; }
fresh_floor
floor_run env
ok "floor delete OFF (the default): nothing is deleted for a low disk" "$(yes_if [ "$(count_arch)" = 18 ] && [ "$(rstat deleted_disk_floor)" = 0 ])"
ok "...the low-disk condition is reported: status warning, disk_low in the result, the reason in the error, a warning line in jobs.log" "$(yes_if [ "$(status logrotate status)" = warning ] && [ "$(rstat disk_low)" = 1 ] && [ "$(rstat floor_delete)" = false ] && status logrotate last_error | grep -q 'log_floor_delete is off' && grep '"mode":"logrotate"' "$F/jobs.log" | tail -1 | grep -q '"status":"warning"')"
ok "...and the script says so on stdout" "$(yes_if grep -q 'below log_min_free_mb' "$WORK/floor.out")"
fresh_floor
floor_run env GV_FLOOR_DELETE=true GV_FLOOR_KEEP_DAYS=30
ok "floor delete ON with keep_days 30: archives newer than 30 days are never deleted (all 18 are newer)" "$(yes_if [ "$(count_arch)" = 18 ] && [ "$(rstat deleted_disk_floor)" = 0 ])"
fresh_floor
floor_run env GV_FLOOR_DELETE=true GV_FLOOR_KEEP_DAYS=7
ok "floor delete ON, keep_days 7: only the oldest archives go, at most 10 per run, and the limit being hit is recorded" "$(yes_if [ "$(rstat deleted_disk_floor)" = 10 ] && [ "$(count_arch)" = 8 ] && [ "$(rstat floor_limit_hit)" = 1 ] && grep -q 'limit of 10 files' "$WORK/floor.out")"
ok "...the 10 deleted are the OLDEST ones, and every archive from the last 7 days survives" "$(yes_if [ -f "$F/guard-$(date -d '1 days ago' +%Y%m%d).jsonl.gz" ] && [ -f "$F/guard-$(date -d '3 days ago' +%Y%m%d).jsonl.gz" ] && [ ! -e "$F/guard-$(date -d '24 days ago' +%Y%m%d).jsonl.gz" ] && [ -f "$F/guard-$(date -d '10 days ago' +%Y%m%d).jsonl.gz" ])"
ok "...the reason disk_floor is recorded" "$(yes_if python3 -c 'import json,sys; r=json.loads(json.load(open(sys.argv[1]))["result_json"]); sys.exit(0 if "disk_floor" in r["reasons"] else 1)' "$GV_JOBSTATUS_DIR/.jobstatus-logrotate.json")"
floor_run env GV_FLOOR_DELETE=true GV_FLOOR_KEEP_DAYS=7
ok "the next run continues: the remaining old archives go (5 more), recent ones still survive" "$(yes_if [ "$(rstat deleted_disk_floor)" = 5 ] && [ "$(rstat floor_limit_hit)" = 0 ] && [ "$(count_arch)" = 3 ])"
fresh_floor
GV_PHP=/nonexistent GV_LOG_DIR="$F" GV_RETENTION_DAYS=365 GV_MAX_MB=0 GV_MIN_FREE_MB=1 GV_FLOOR_DELETE=true GV_JOBLOG_DIR="$F" bash "$ROOT/scripts/guard-logrotate.sh" > /dev/null 2>&1
ok "plenty of free disk: nothing is reported or deleted for the floor even when allowed" "$(yes_if [ "$(rstat disk_low)" = 0 ] && [ "$(count_arch)" = 18 ] && [ "$(status logrotate status)" = ok ])"
fresh_floor
floor_run env GV_FLOOR_DELETE=true GV_FLOOR_KEEP_DAYS=0
ok "keep_days below 1 falls back to the default of 7 (a typo cannot make every archive deletable)" "$(yes_if [ "$(rstat floor_keep_days)" = 7 ] && [ "$(count_arch)" -ge 8 ])"
fresh_floor
GV_FLOOR_DELETE=true GV_FLOOR_KEEP_DAYS=x floor_run env
ok "a non-numeric keep_days falls back to 7 as well" "$(yes_if [ "$(rstat floor_keep_days)" = 7 ])"
mkdir -p "$WORK/fakebin"; printf '#!/bin/sh\nprintf "Disk quotas for user x (uid 1):\\n     Filesystem   space   quota   limit   grace\\n      /dev/sda1   4096M   5120M   5120M\\n"\n' > "$WORK/fakebin/quota"; chmod +x "$WORK/fakebin/quota"
fresh_floor
floor_run env PATH="$WORK/fakebin:$PATH"
ok "when quota exists its usage is recorded in the status (never acted on)" "$(yes_if [ "$(rstat quota | grep -c 4096M)" = 1 ])"
fresh_floor
floor_run env PATH="/usr/bin:/bin"
ok "when quota does not exist it is skipped silently" "$(if [ -n "$(PATH=/usr/bin:/bin command -v quota)" ]; then echo 1; else yes_if [ -z "$(rstat quota)" ] && [ "$(status logrotate status)" != failed ]; fi)"

GV_PHP=/nonexistent GV_LOG_DIR="$WORK/nodir" GV_JOBLOG_DIR="$L" bash "$ROOT/scripts/guard-logrotate.sh" > /dev/null 2>&1
ok "a missing log directory is a warning, not a silent success" "$(yes_if [ "$(status logrotate status)" = warning ])"

echo "== write lock: nightly / train / train-clf wait, the worker takes it only around a write job"
LK="$WORK/locks"
# holder SECONDS: take analyzer/.write.lock through the real worker.WriteLock for SECONDS seconds (what a running write job of the worker does)
holder() {
	rm -f "$WORK/held"
	( GV_LOCK_DIR="$LK" python3 - "$1" "$ROOT" "$WORK/held" <<'PY'
import sys, time
sys.path.insert(0, sys.argv[2])
from analyzer import worker
l = worker.WriteLock()
assert l.acquire(0)
open(sys.argv[3], 'w').write('held')
time.sleep(float(sys.argv[1]))
l.release()
PY
	) > /dev/null 2>&1 &
	HPID=$!
	for _ in $(seq 1 50); do [ -f "$WORK/held" ] && break; sleep 0.1; done
}
holder 3
t0=$(date +%s)
GV_LOCK_WAIT=20 FAKE_MODE=ok bash "$CRON" nightly > "$WORK/w1" 2>&1; rc=$?
t1=$(date +%s)
wait "$HPID" 2>/dev/null
ok "worker + nightly start together: nightly WAITS for the lock, then runs (exit 0, status ok, it ran after about 3 s, nothing skipped)" "$(yes_if [ $rc -eq 0 ] && [ "$(status nightly status)" = ok ] && [ $((t1 - t0)) -ge 2 ] && [ "$(status nightly skipped)" = 0 ] && grep -qx 'did the work' "$WORK/w1")"
holder 6
FAKE_MODE=ok GV_LOCK_WAIT=1 bash "$CRON" nightly > "$WORK/w2" 2>&1; rc=$?
ok "the wait runs out: exit 0, status skipped, 'skipped (lock busy after 1 s)', the holder (worker) is named and stored, no failure, the job did not run" \
	"$(yes_if [ $rc -eq 0 ] && [ "$(status nightly status)" = skipped ] && status nightly last_error | grep -q 'lock busy after 1 s' && status nightly last_error | grep -q 'held by worker' && [ "$(status nightly lock_holder)" = worker ] && ! grep -qx 'did the work' "$WORK/w2" && [ "$(status nightly skipped)" = 1 ])"
ok "...and the earlier successful run's last_success is kept (a skip never erases it)" "$(yes_if [ "$(status nightly last_success)" -gt 0 ])"
FAKE_MODE=ok GV_LOCK_WAIT=1 bash "$CRON" train > /dev/null 2>&1
FAKE_MODE=ok GV_LOCK_WAIT=1 bash "$CRON" train-clf > /dev/null 2>&1
ok "train and train-clf wait too: both are recorded as skipped (lock busy after 1 s)" "$(yes_if [ "$(status train status)" = skipped ] && [ "$(status train-clf status)" = skipped ] && status train last_error | grep -q 'lock busy after 1 s')"
GV_LOCK_WAIT=0 FAKE_MODE=ok bash "$CRON" nightly > /dev/null 2>&1
ok "GV_LOCK_WAIT=0 means no wait: skipped at once with the plain note" "$(yes_if [ "$(status nightly status)" = skipped ] && status nightly last_error | grep -q 'holds the lock')"
FAKE_MODE=ok bash "$CRON" worker > "$WORK/w3" 2>&1; rc=$?
ok "the worker wrapper does not touch the write lock (python takes it only around a write job): it runs at once while a write job holds it" "$(yes_if [ $rc -eq 0 ] && [ "$(status worker status)" = ok ] && grep -qx 'did the work' "$WORK/w3")"
wait "$HPID" 2>/dev/null
GV_LOCK_WAIT=abc FAKE_MODE=ok bash "$CRON" nightly > /dev/null 2>&1
ok "a garbage GV_LOCK_WAIT falls back to the 900 s default and still runs when the lock is free" "$(yes_if [ "$(status nightly status)" = ok ])"
( exec 9>"$LK/.worker.lock"; flock -n 9; sleep 3 ) > /dev/null 2>&1 &
sleep 0.5
FAKE_MODE=ok bash "$CRON" worker > /dev/null 2>&1
ok "two workers never overlap: a second worker firing is skipped by its own lock" "$(yes_if [ "$(status worker status)" = skipped ])"
wait 2>/dev/null

echo "== which Python runs the job (environment, crontab, .venv, python3) and which php (CLI fallback)"
INST="$WORK/inst"; mkdir -p "$INST/scripts" "$INST/analyzer" "$WORK/bin" "$WORK/cli"
cp "$ROOT/scripts/analyzer-cron.sh" "$ROOT/scripts/lib-jobstatus.sh" "$ROOT/scripts/cron_check.py" "$ROOT/scripts/cron-check.sh" "$INST/scripts/"
# mkpy FILE NAME: a Python stand-in that passes the import preflight and says who ran (and which php it was given)
mkpy() { mkdir -p "$(dirname "$1")"; printf '#!/usr/bin/env bash\nif [ "$1" = "-c" ]; then exit 0; fi\necho "ran-by-%s php=${GV_PHP:-none}"\n' "$2" > "$1"; chmod +x "$1"; }
mkpy "$WORK/py-env" env; mkpy "$WORK/py-cron" cron; mkpy "$WORK/bin/python3" default
printf '#!/usr/bin/env bash\nif [ "$1" = "-l" ]; then [ -f "%s/crontab.txt" ] && cat "%s/crontab.txt" || { echo "no crontab for tester" >&2; exit 1; }; fi\n' "$WORK" "$WORK" > "$WORK/bin/crontab"; chmod +x "$WORK/bin/crontab"
byhand() {   # the wrapper as an operator runs it over SSH: no GV_PYTHON, no GV_PHP, our fake crontab and python3 first on PATH
	env -u GV_PYTHON -u GV_PHP PATH="$WORK/bin:$PATH" GV_PHP_FALLBACK=/nonexistent bash "$INST/scripts/analyzer-cron.sh" "$@"
}
printf '%s\n' "GV_PYTHON=$WORK/py-cron" '*/10 * * * * bash /x/scripts/analyzer-cron.sh verify' > "$WORK/crontab.txt"
GV_PYTHON="$WORK/py-env" PATH="$WORK/bin:$PATH" bash "$INST/scripts/analyzer-cron.sh" verify > "$WORK/p1" 2>&1
ok "GV_PYTHON in the environment wins (even over the crontab): used, and recorded as '(source: environment)'" "$(yes_if grep -q 'ran-by-env' "$WORK/p1" && [ "$(status verify python)" = "$WORK/py-env (source: environment)" ])"
byhand verify > "$WORK/p2" 2>&1
ok "no GV_PYTHON (an SSH shell): the one in the user's crontab is used, recorded as '(source: crontab)'" "$(yes_if grep -q 'ran-by-cron' "$WORK/p2" && [ "$(status verify python)" = "$WORK/py-cron (source: crontab)" ] && [ "$(status verify status)" = ok ])"
printf '%s\n' 'GV_PYTHON="/nonexistent/venv/bin/python"' > "$WORK/crontab.txt"
byhand verify > "$WORK/p3" 2>&1
ok "a crontab GV_PYTHON that is not an executable file is ignored (falls through to python3 here)" "$(yes_if grep -q 'ran-by-default' "$WORK/p3" && [ "$(status verify python)" = "python3 (source: default)" ])"
mkpy "$INST/.venv/bin/python" venv
byhand verify > "$WORK/p4" 2>&1
ok "then <install-dir>/.venv/bin/python when it exists and is executable ('(source: venv)')" "$(yes_if grep -q 'ran-by-venv' "$WORK/p4" && [ "$(status verify python)" = "$INST/.venv/bin/python (source: venv)" ])"
printf '%s\n' "GV_PYTHON=$WORK/py-cron" > "$WORK/crontab.txt"
byhand verify > "$WORK/p5" 2>&1
ok "the crontab still comes before the .venv" "$(yes_if grep -q 'ran-by-cron' "$WORK/p5")"
chmod -x "$INST/.venv/bin/python"; rm -f "$WORK/crontab.txt"
byhand verify > "$WORK/p6" 2>&1
ok "an unreadable crontab and a non-executable .venv python: python3 ('(source: default)')" "$(yes_if grep -q 'ran-by-default' "$WORK/p6" && [ "$(status verify python)" = "python3 (source: default)" ])"
printf '#!/usr/bin/env bash\nif [ "$1" = "-c" ]; then echo "ModuleNotFoundError: No module named numpy" >&2; exit 1; fi\n' > "$WORK/bin/python3"; chmod +x "$WORK/bin/python3"
byhand nightly > "$WORK/p7" 2>&1; rc=$?
ok "the bare python3 without the packages still fails the preflight (a recorded failure that names which Python was chosen and why)" "$(yes_if [ $rc -eq 3 ] && [ "$(status nightly status)" = failed ] && status nightly last_error | grep -q 'python3 (source: default)' && status nightly last_error | grep -q numpy)"
rm -rf "$INST/.venv"; mkpy "$WORK/bin/python3" default
# php: a non-CLI php on PATH falls back to /usr/local/bin/php (GV_PHP_FALLBACK in the test) when that one is the CLI build
printf '#!/usr/bin/env bash\necho cgi-fcgi\n' > "$WORK/bin/php"; chmod +x "$WORK/bin/php"
printf '#!/usr/bin/env bash\necho cli\n' > "$WORK/cli/php"; chmod +x "$WORK/cli/php"
env -u GV_PYTHON -u GV_PHP PATH="$WORK/bin:$PATH" GV_PHP_FALLBACK="$WORK/cli/php" bash "$INST/scripts/analyzer-cron.sh" verify > "$WORK/q1" 2> "$WORK/q1e"
ok "php on PATH is the cgi-fcgi SAPI: /usr/local/bin/php (the CLI build) is used instead and passed on as GV_PHP, with a note, and the run is ok (no warning)" "$(yes_if grep -q "php=$WORK/cli/php" "$WORK/q1" && grep -q 'cgi-fcgi SAPI' "$WORK/q1e" && [ "$(status verify status)" = ok ])"
env -u GV_PYTHON -u GV_PHP PATH="$WORK/bin:$PATH" GV_PHP_FALLBACK=/nonexistent bash "$INST/scripts/analyzer-cron.sh" verify > "$WORK/q2" 2>&1
ok "...and without a CLI fallback the warning about the cgi php stays (status warning, no GV_PHP invented)" "$(yes_if [ "$(status verify status)" = warning ] && status verify warnings | grep -q 'cgi-fcgi' && grep -q 'php=none' "$WORK/q2")"
printf '#!/usr/bin/env bash\necho cli\n' > "$WORK/bin/php"
env -u GV_PYTHON -u GV_PHP PATH="$WORK/bin:$PATH" GV_PHP_FALLBACK="$WORK/cli/php" bash "$INST/scripts/analyzer-cron.sh" verify > "$WORK/q3" 2> "$WORK/q3e"
ok "a CLI php on PATH is left alone (no fallback, no note)" "$(yes_if grep -q 'php=none' "$WORK/q3" && ! grep -q 'SAPI' "$WORK/q3e" && [ "$(status verify status)" = ok ])"
rm -f "$WORK/bin/php" "$WORK/crontab.txt"

echo "== feeds (PHP job behind analyzer-cron.sh feeds)"
FD="$WORK/feeds"; mkdir -p "$FD/lists" "$FD/logs"
unset GV_PHP
export GV_LISTS_DIR="$FD/lists" GV_OVERLAY="$FD/ov.json" GV_AUDIT="$FD/audit.jsonl"
bash "$CRON" feeds > "$WORK/f0" 2>&1; rc=$?
ok "analyzer-cron.sh feeds with no feed configured exits 0 and records an ok run (no Python needed: the fake Python is never asked)" "$(yes_if [ $rc -eq 0 ] && [ "$(status feeds status)" = ok ] && grep -q 'No feed is due' "$WORK/f0")"
printf '%s\n' '{"v":1,"feeds":[{"id":"t1","name":"T1","url":"https://127.0.0.1/x","format":"auto","dest":"allow","mode":"monitor","enabled":true,"schedule":"daily","note":"","force":false}]}' > "$FD/lists/feeds.json"
bash "$CRON" feeds > "$WORK/f1" 2>&1; rc=$?
ok "a feed that fails (here: refused by the SSRF guard) makes the run failed, exit 1, with the reason in the error text" "$(yes_if [ $rc -eq 1 ] && [ "$(status feeds status)" = failed ] && [ "$(status feeds last_error | grep -c ssrf)" = 1 ])"
ok "...and the feed keeps its error and streak in lists/feeds.json (last good entries untouched)" "$(yes_if python3 -c 'import json,sys; f=json.load(open(sys.argv[1]))["feeds"][0]["st"]; sys.exit(0 if f["fail_streak"]==1 and "ssrf" in f["error"] else 1)' "$FD/lists/feeds.json")"
unset GV_LISTS_DIR GV_OVERLAY GV_AUDIT

echo
echo "PASS $PASS  FAIL $FAIL"
[ "$FAIL" -eq 0 ]
