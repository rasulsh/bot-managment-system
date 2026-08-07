#!/usr/bin/env bash
# Bot Guard analyzer cron wrapper.
#
#   scripts/analyzer-cron.sh verify    fast reverse-DNS loop
#   scripts/analyzer-cron.sh nightly   behavioural scoring + anomaly levels
#   scripts/analyzer-cron.sh train     nightly run that also retrains the model
#
# Each mode takes its own flock, so overlapping cron firings queue-and-skip
# instead of writing partial verdicts on top of each other.
#
# Cron example:
#   */10 * * * * /full/path/bot-guard/scripts/analyzer-cron.sh verify  >/dev/null 2>&1
#   17 4   * * * /full/path/bot-guard/scripts/analyzer-cron.sh nightly >/dev/null 2>&1
#   41 5   * * 0 /full/path/bot-guard/scripts/analyzer-cron.sh train   >/dev/null 2>&1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${GV_PYTHON:-python3}"
MODE="${1:-}"

case "$MODE" in
	verify)  SCRIPT="analyzer/run_verify.py";  ARGS=() ;;
	nightly) SCRIPT="analyzer/run_nightly.py"; ARGS=() ;;
	train)   SCRIPT="analyzer/run_nightly.py"; ARGS=(--train) ;;
	*)
		echo "Usage: $(basename "$0") {verify|nightly|train}"
		exit 1
		;;
esac

LOCK="$ROOT/analyzer/.$MODE.lock"

if ! command -v flock >/dev/null 2>&1; then
	echo "flock not available: running $MODE without a lock"
	exec "$PYTHON" "$ROOT/$SCRIPT" ${ARGS[@]+"${ARGS[@]}"}
fi

# -E 99 makes "could not take the lock" distinguishable from the job's own
# exit status, so an overlapping firing is a clean skip rather than an error.
set +e
flock -n -E 99 "$LOCK" "$PYTHON" "$ROOT/$SCRIPT" ${ARGS[@]+"${ARGS[@]}"}
status=$?
set -e

if [ "$status" -eq 99 ]; then
	echo "Another $MODE run is already in progress; skipping this firing."
	exit 0
fi
exit "$status"
