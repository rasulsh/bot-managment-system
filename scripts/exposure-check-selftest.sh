#!/usr/bin/env bash
# Self-test for scripts/exposure-check.sh on a site that answers 200 for every unknown path (a "soft 404"), against a throw-away
# Python server. The panel-probe loop used to print "200 ok" for ANY 200 on such a site, so an exposed panel/users.json went unseen.
#   bash scripts/exposure-check-selftest.sh
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${EXPOSURE_SELFTEST_PORT:-8197}"
WORK="$(mktemp -d)"
PID=""
cleanup() { [ -n "$PID" ] && kill "$PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
PASS=0; FAIL=0
ok() { if [ "$2" = 1 ]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1"; FAIL=$((FAIL + 1)); fi; }
yes_if() { if "$@"; then echo 1; else echo 0; fi; }

cat > "$WORK/server.py" <<'PY'
import http.server, sys
EXPOSED = set(sys.argv[2].split(','))
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?')[0]
        body = b'{"admin":{"hash":"x"}}' if path in EXPOSED else b'<html>Sorry, nothing here (but with status 200)</html>'
        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
PY
start() { python3 "$WORK/server.py" "$PORT" "$1" & PID=$!; for _ in $(seq 1 30); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.1; done; }
stop() { kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""; }

# 1. A soft-404 site that really serves the panel's users file: it must be reported EXPOSED and fail.
start "/gv-admin/users.json"
out="$(bash "$REPO/scripts/exposure-check.sh" "http://127.0.0.1:$PORT" /gv-admin 2>&1)"; rc=$?
stop
ok "a soft-404 site serving /gv-admin/users.json: reported EXPOSED" "$(grep -q '/gv-admin/users.json *| 200  EXPOSED' <<<"$out" && echo 1 || echo 0)"
ok "...and the run fails" "$(yes_if [ "$rc" -ne 0 ])"

# 2. A soft-404 site that serves nothing real: the panel probes are inconclusive, never "ok", and the run does not fail on them.
start "/nothing-real"
out="$(bash "$REPO/scripts/exposure-check.sh" "http://127.0.0.1:$PORT" /gv-admin 2>&1)"
stop
ok "a soft-404 site: a panel probe that returns the soft page is 'inconclusive', not 'ok'" "$(grep -q '/gv-admin/users.json *| 200 (same as a nonexistent path' <<<"$out" && echo 1 || echo 0)"
ok "...none of them is reported as ok" "$(grep -q '/gv-admin/users.json *| 200 ok' <<<"$out" && echo 0 || echo 1)"

# 3. The probe list names the files an operator would otherwise forget.
for p in /scripts/config-dump.php /scripts/secret-values.php /scripts/gen-reason-docs.php /lists/feeds.json /panel/users.json /panel/audit.jsonl; do
	ok "the probe list has $p" "$(grep -qF "\"$p\"" "$REPO/scripts/exposure-check.sh" && echo 1 || echo 0)"
done

echo
echo "PASS $PASS  FAIL $FAIL"
[ "$FAIL" -eq 0 ]
