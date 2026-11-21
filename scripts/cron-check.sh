#!/usr/bin/env bash
# Check that the crontab of the current user has every Bot Guard entry, correctly.
#
#   scripts/cron-check.sh           human report; exit 0 = all required entries present and right,
#                                   1 = something required is missing or wrong, 2 = crontab unreadable
#   scripts/cron-check.sh --json    the same as JSON (the panel reads it)
#
# Tries /usr/bin/crontab.cagefs -l (CloudLinux / CageFS), then crontab -l. Reads only; changes nothing.
# Uses the SYSTEM python3 (standard library only), not GV_PYTHON: it must work when the
# virtualenv is exactly what is broken. All output is English.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
	echo "ERROR: python3 was not found, so the crontab cannot be checked. Compare it by hand with docs/03-SETUP.md (Step 4)."
	exit 2
fi
exec "$PY" "$HERE/cron_check.py" "$@"
