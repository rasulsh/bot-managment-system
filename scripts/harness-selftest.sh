#!/usr/bin/env bash
# Self-test of the test harness itself (audit LOG-16 / LOG-17): the HTTP matrix must FAIL when a row is wrong, and the end-to-end scripts must
# leave an operator's own guard.off alone. Throw-away directories and a throw-away Python server only.
#   bash scripts/harness-selftest.sh
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
PID=""
cleanup() { [ -n "$PID" ] && kill "$PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
PASS=0; FAIL=0
ok() { if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1"; FAIL=$((FAIL + 1)); fi; }
yes_if() { if "$@"; then echo 1; else echo 0; fi; }

# A server that answers 200 to everything: row 1 of the matrix (no User-Agent) is documented to be 403 when enforced.
cat > "$WORK/s.py" <<'PY'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def _r(self):
        self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'ok')
    do_GET = do_POST = do_HEAD = _r
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
PY
PORT="${HARNESS_SELFTEST_PORT:-8198}"
python3 "$WORK/s.py" "$PORT" & PID=$!
for _ in $(seq 1 30); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.1; done
out="$(bash "$REPO/scripts/guard-test.sh" "http://127.0.0.1:$PORT" 2>&1)"; rc=$?
ok "guard-test.sh exits non-zero when a row is wrong (it always exited 0)" "$(yes_if [ "$rc" -ne 0 ])"
ok "...and names the failing row and what it expected" "$(grep -q "FAIL  1 GET / with no User-Agent: got '200', expected '403'" <<<"$out" && echo 1 || echo 0)"
GV_MATRIX_ASSERT=0 bash "$REPO/scripts/guard-test.sh" "http://127.0.0.1:$PORT" >/dev/null 2>&1; rc2=$?
ok "GV_MATRIX_ASSERT=0 keeps the old print-only behaviour (for a deployment in monitor mode)" "$(yes_if [ "$rc2" -eq 0 ])"
kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""

# An existing guard.off survives identity-check.sh (the trap used to delete it).
T="$WORK/tree"; mkdir -p "$T/scripts"
cp "$REPO/scripts/identity-check.sh" "$T/scripts/"
printf 'stopped by the operator\n' > "$T/guard.off"
bash "$T/scripts/identity-check.sh" "http://127.0.0.1:1" >/dev/null 2>&1
ok "identity-check.sh puts the operator's guard.off back (content unchanged)" "$(yes_if [ "$(cat "$T/guard.off" 2>/dev/null)" = 'stopped by the operator' ])"
ok "...and leaves no 'saved' copy behind" "$(yes_if test -z "$(find "$T" -name 'guard.off.saved-*')")"
# And the same for rules-e2e.sh's cleanup trap.
grep -q 'guard.off.saved' "$REPO/scripts/rules-e2e.sh" && grep -q 'mv "$SAVED_OFF" "$ROOT/guard.off"' "$REPO/scripts/rules-e2e.sh"
ok "rules-e2e.sh saves and restores guard.off the same way" "$(yes_if [ $? -eq 0 ])"
# monitor-check.sh gives up with an error when its server never answers (it used to sleep 1 second and carry on).
cp "$REPO/scripts/monitor-check.sh" "$REPO/scripts/guard-test.sh" "$REPO/scripts/dev-router.php" "$REPO/scripts/config.dev.php" "$T/scripts/"
mkdir -p "$T/bin"; printf '#!/bin/sh\nexit 1\n' > "$T/bin/php"; chmod +x "$T/bin/php"      # a php that dies at once: the server never comes up
mout="$(PATH="$T/bin:$PATH" bash "$T/scripts/monitor-check.sh" 8196 2>&1)"; mrc=$?
ok "monitor-check.sh fails with an error when its test server does not come up" "$(grep -q 'test server did not start' <<<"$mout" && [ "$mrc" -ne 0 ] && echo 1 || echo 0)"

echo
echo "PASS $PASS  FAIL $FAIL"
[ "$FAIL" -eq 0 ]
