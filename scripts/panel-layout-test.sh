#!/usr/bin/env bash
# Panel layout test in a real browser, against a throw-away copy of the panel.
#
#   bash scripts/panel-layout-test.sh [screenshot-dir]
#
# Copies the repository to a temp directory (nothing is written into the working tree),
# installs a panel login there, writes sample log rows, serves it with PHP's built-in
# server and runs scripts/panel-layout-test.js (Playwright) at 1600 px and 390 px.
# Needs: php, node, playwright (NODE_PATH or a global install) with Chromium.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHP_BIN="${GV_PHP:-php}"
PORT="${LAYOUT_PORT:-8151}"
SHOTS="${1:-}"
for need in "$PHP_BIN" node tar; do
	command -v "$need" >/dev/null 2>&1 || { echo "ERROR: '$need' is required." >&2; exit 2; }
done
node -e "require('playwright')" 2>/dev/null || { echo "SKIP: playwright is not installed (set NODE_PATH or npm i playwright)"; exit 0; }
WORK="$(mktemp -d)"
PID=""
cleanup() { [ -n "$PID" ] && kill "$PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
mkdir "$WORK/bg"
(cd "$ROOT" && tar --exclude=.git --exclude=node_modules -cf - .) | tar -xf - -C "$WORK/bg"
(cd "$WORK/bg" && printf 'admin\nlayout-pass-12345\nlayout-pass-12345\n' | "$PHP_BIN" panel/setpass.php >/dev/null 2>&1)
# Sample traffic so the log, identity and dashboard pages have something to show.
mkdir -p "$WORK/bg/logs"
python3 - "$WORK/bg/logs/guard-$(date +%Y%m%d).jsonl" <<'PY'
import json, sys, time
now = time.time()
rows = []
for i in range(60):
    bad = i % 3 == 0
    rows.append({'v': 5, 'rid': '%012x' % i, 'ts': now - i * 40, 'ip': '203.0.113.%d' % (5 + i % 4), 'ua': 'curl/8.4.0' if bad else 'Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0 Safari/537.36',
                 'uah': 'a' * 12, 'm': 'GET', 'p': '/shop/item-%d' % i, 'q': '', 'aj': 0, 'nav': 1, 'gate': 1, 'tok': 'm' if bad else 'v', 'dev': '' if bad else 'dev%d' % (i % 5),
                 'sf': 'navigate', 'al': 1, 'hc': 8, 'sc': 40 if bad else 0, 'esc': 40 if bad else 0, 'rs': ['UA_SCRIPT', 'SH_RULE:r1'] if bad else [], 'cd': 1, 'cdh': 1, 'cdd': 1, 'ciu': 1, 'ci': 1,
                 'rd': 0, 'hp': 0, 'bot': '', 'ref': '', 'botv': '', 'rep': 0, 'ml': -1, 'clf': -1, 'hold': 0, 'ovr': '', 'act': '403' if bad else 'allow', 'sh': 1 if bad else 0,
                 'cc': 'IR' if i % 2 else 'US', 'asn': 12880 if i % 2 else 15169, 'ms': 1.2})
open(sys.argv[1], 'w').write('\n'.join(json.dumps(r) for r in rows) + '\n')
PY
# Audit entries with long unbroken values: they must wrap, not widen the page.
python3 - "$WORK/bg/panel/audit.jsonl" <<'PY'
import json, sys, time
rows = [{'ts': time.time() - i, 'event': 'config', 'actor': 'admin', 'ip': '203.0.113.1', 'key': 'exempt_paths',
         'old': ['/a' * 200], 'new': {'x': 'y' * 300, 'list': ['/long-path-%d' % n * 5 for n in range(8)]}} for i in range(5)]
open(sys.argv[1], 'w').write('\n'.join(json.dumps(r) for r in rows) + '\n')
PY
"$PHP_BIN" -S "127.0.0.1:$PORT" -t "$WORK/bg" >"$WORK/php.log" 2>&1 &
PID=$!
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/panel/index.php" 2>/dev/null && break; sleep 0.1; done
[ -n "$SHOTS" ] && mkdir -p "$SHOTS"
node "$ROOT/scripts/panel-layout-test.js" "http://127.0.0.1:$PORT" /panel admin layout-pass-12345 "$SHOTS"
