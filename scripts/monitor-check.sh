#!/usr/bin/env bash
# Monitor mode must be inert: with secret = CHANGE_ME every enforce toggle is
# forced off, so NOTHING the guard (including the proof of work, the replay
# check and the mint limit) may ever block, challenge or rate-limit a request.
#
#   bash scripts/monitor-check.sh [port]
#
# Starts the dev router with the dev config but the default secret, runs the HTTP
# matrix against it and fails if any row answers 403, 429, 503 or 204 where the
# matrix documents a plain 200 for monitor mode.
set -uo pipefail
PORT="${1:-8095}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
cat > "$TMP/config.php" <<CONF
<?php if (!defined('GV_BOOT')) { exit; }
\$c = require '$ROOT/scripts/config.dev.php';
\$c['secret'] = 'CHANGE_ME';
\$c['log_dir'] = '$TMP/logs';
return \$c;
CONF
GV_DEV_CONFIG="$TMP/config.php" php -S "127.0.0.1:$PORT" "$ROOT/scripts/dev-router.php" >/dev/null 2>&1 &
server=$!
trap 'kill $server 2>/dev/null; rm -rf "$TMP"' EXIT
sleep 1
GV_LOG_DIR="$TMP/logs" bash "$ROOT/scripts/guard-test.sh" "http://127.0.0.1:$PORT" > "$TMP/matrix.txt" 2>&1
bad=$(awk -F'|' '/^[0-9]+[a-z]? / && $2 ~ /^ *(403|429|503|204) *$/' "$TMP/matrix.txt")
if [ -n "$bad" ]; then
	echo "FAIL: monitor mode blocked, challenged or limited a request:"
	echo "$bad"
	exit 1
fi
echo "OK: with secret = CHANGE_ME no request was blocked, challenged or rate-limited."
