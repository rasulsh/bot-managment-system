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
# A Monitoring operator and a Demo user (the page checks per role run at both widths).
(cd "$WORK/bg" && "$PHP_BIN" -r 'define("GP_BOOT",1);define("GV_BOOT",1);define("GV_NO_AUTORUN",1);require "panel/config_io.php";require "panel/auth.php";
	$a=gp_users_create("admin","layout-op","operator","op-layout-pass-12345");$b=gp_users_create("admin","layout-demo","demo","demo-layout-pass-12345");exit(($a[0]&&$b[0])?0:1);') \
	|| { echo "ERROR: could not create the role users"; exit 2; }
# Two rules and one IP list in monitor mode (the dashboard's rollout readiness card) and one enforced rule.
(cd "$WORK/bg" && "$PHP_BIN" -r 'define("GP_BOOT",1);define("GV_BOOT",1);define("GV_NO_AUTORUN",1);
	foreach (array("config_io","auth","acl","demo","data","jobs","update","replay","filters","ui","reasons","overrides","live","dash","health","geo","rules","iplists","feeds") as $f) { require_once "panel/$f.php"; }
	$r1 = gp_rule_blank(); $r1["id"]="r1a2b3c"; $r1["name"]="Scripted clients"; $r1["action"]="block"; $r1["ua"]["values"]=array("curl","python-requests");
	$r2 = gp_rule_blank(); $r2["id"]="st-curl"; $r2["name"]="Headless browsers"; $r2["action"]="captcha"; $r2["ua"]["values"]=array("HeadlessChrome");
	$r3 = gp_rule_blank(); $r3["id"]="enf1abc"; $r3["name"]="Known bad path"; $r3["action"]="block"; $r3["mode"]="enforce"; $r3["priority"]=200; $r3["ua"]=null; $r3["path"]=array("op"=>"include","type"=>"prefix","values"=>array("/wp-login"));
	$w = gp_rules_write(array($r1,$r2,$r3));
	$l = gp_iplists_save(array("name"=>"Hosting ranges","type"=>"block","mode"=>"monitor","enabled"=>"1","text"=>"198.51.100.0/24\n203.0.113.0/28\n"), null, "admin", "127.0.0.1");
	exit(($w[0] && $l["ok"]) ? 0 : 1);') || { echo "ERROR: could not create the sample rules and list"; exit 2; }
# Sample traffic so the log, identity and dashboard pages have something to show.
mkdir -p "$WORK/bg/logs"
# Two uploaded GeoIP sources that were never compiled (the GeoIP page warns and shows them in the table).
mkdir -p "$WORK/bg/geo"
printf x > "$WORK/bg/geo/GeoLite2-ASN.mmdb"; printf x > "$WORK/bg/geo/GeoLite2-Country.mmdb"
python3 - "$WORK/bg/logs/guard-$(date +%Y%m%d).jsonl" <<'PY'
import json, sys, time
now = time.time()
rows = []
# oldest first, like the guard writes it (the Live page tails the file in order)
for i in range(59, -1, -1):
    bad = i % 3 == 0
    rows.append({'v': 5, 'rid': '%012x' % i, 'ts': now - i * 40, 'ip': '203.0.113.%d' % (5 + i % 4), 'ua': 'curl/8.4.0' if bad else 'Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0 Safari/537.36',
                 'uah': 'a' * 12, 'm': 'GET', 'p': '/shop/item-%d' % i, 'q': '', 'aj': 0, 'nav': 1, 'gate': 1, 'tok': 'm' if bad else 'v', 'dev': '' if bad else 'dev%d' % (i % 5),
                 'sf': 'navigate', 'al': 1, 'hc': 8, 'sc': 40 if bad else 0, 'esc': 40 if bad else 0, 'rs': ['UA_SCRIPT', 'SH_RULE:r1'] if bad else [], 'cd': 1, 'cdh': 1, 'cdd': 1, 'ciu': 1, 'ci': 1,
                 'rd': 0, 'hp': 0, 'bot': '', 'ref': '', 'botv': '', 'rep': 0, 'ml': -1, 'clf': -1, 'hold': 0, 'ovr': '', 'act': '403' if bad else 'allow', 'sh': 1 if bad else 0,
                 'cc': 'IR' if i % 2 else 'US', 'asn': 12880 if i % 2 else 15169, 'ms': 1.2})
open(sys.argv[1], 'w').write('\n'.join(json.dumps(r) for r in rows) + '\n')
PY
# Job status, a snapshot with 24 h KPIs and top lists, so the dashboard and the Jobs page have real content:
# one job failing, one late, one that did nothing useful, the rest fine.
python3 - "$WORK/bg/analyzer" <<'PY'
import json, os, sys, time
d = sys.argv[1]
now = int(time.time())
def status(mode, **kw):
    base = {'v': 1, 'mode': mode, 'status': 'ok', 'last_start': now - 40, 'last_end': now - 30, 'last_success': now - 30, 'last_failure': 0, 'last_exit': 0,
            'duration': 8, 'skipped': 0, 'runs': 12, 'failures': 0, 'last_error': '', 'warnings': [], 'result_json': '', 'python': '/usr/bin/python3'}
    base.update(kw)
    json.dump(base, open(os.path.join(d, '.jobstatus-%s.json' % mode), 'w'))
for m in ('worker', 'snapshot', 'logrotate'):
    status(m)
status('verify', status='failed', last_exit=1, last_failure=now - 120, last_success=now - 3600, failures=3, last_error='Traceback (most recent call last):\nValueError: redis refused the connection')
status('nightly', last_success=now - 3 * 86400, last_end=now - 3 * 86400)
status('train', status='warning', warnings=['model training produced no candidate: skipped: 12 clean sessions is below ml_min_train=200'], last_error='model training produced no candidate',
       last_success=now - 3600, result_json=json.dumps({'ml_trained': False, 'ml_samples': 12}))
cur = {'requests': 1840, 'allowed': 1500, 'blocked': 210, 'limited': 12, 'challenged': 96, 'challenge_success': 91.4, 'token_issued': 88, 'rule_hits': 140, 'honeypot': 6, 'degraded': 0, 'would_act': 340}
prev = {'requests': 1500, 'allowed': 1320, 'blocked': 120, 'limited': 12, 'challenged': 40, 'challenge_success': 96.0, 'token_issued': 38, 'rule_hits': 0, 'honeypot': 9, 'degraded': 0, 'would_act': 200}
sys.path.insert(0, os.path.dirname(d))
from analyzer import snapshot as snap_mod
import random
rnd = random.Random(7)
syn = []
for h in range(168, -1, -1):
    base = 40 + int(35 * (1 + __import__('math').sin(h / 3.8)))
    for _ in range(base):
        r = rnd.random()
        ua = 'curl/8.4.0' if r < 0.22 else 'Mozilla/5.0 Chrome/130.0'
        act, sh, rs = 'allow', 0, []
        if r < 0.10: act, rs = '403', ['SH_RULE:r1a2b3c']
        elif r < 0.14: act, sh, rs = '403', 1, ['SH_RULE:r1a2b3c']
        elif r < 0.22: act, sh, rs = 'challenge', 1, ['SH_IPL_BLOCK:hosting-ranges']
        elif r < 0.27: act = 'challenge'
        elif r < 0.29: act = '429'
        syn.append({'ts': now - h * 3600 + rnd.random() * 3500, 'act': act, 'sh': sh, 'rs': rs, 'ip': '203.0.113.%d' % rnd.randint(1, 60), 'dev': 'dev%d' % rnd.randint(1, 80), 'ua': ua,
                    'p': '/shop/item-%d' % rnd.randint(1, 9), 'cc': rnd.choice(['IR', 'US', 'DE', 'IR']), 'asn': rnd.choice([12880, 15169, 24940]), 'tok': 'v' if r > 0.5 else 'm',
                    'cap': 'show' if 0.27 < r < 0.28 else ''})
dash = snap_mod.build_dash([x for x in syn if x['ts'] >= now - 86400], syn, now)
json.dump({'generated_at': now - 300, 'dash': dash, 'tz': {'name': 'UTC', 'offset': 0}, 'traffic': {'requests': 1840, 'devices': 310, 'addresses': 280, 'degraded': 0},
           'decisions': {'allow': 1500, '403': 210, 'challenge': 96, '429': 12}, 'kpi': {'cur': cur, 'prev': prev, 'window_h': 24},
           'top': {'rules': [['st-curl', 90], ['r1a2b3c', 50]], 'reasons': [['UA_SCRIPT', 190], ['NO_AL', 40]], 'ips': [['203.0.113.5', 80], ['198.51.100.9', 60]], 'devices': [['dev3', 30]],
                   'uas': [['curl/8.4.0', 120], ['python-requests/2.31', 60]], 'paths': [['/shop/item-1', 40], ['/login', 22]], 'countries': [['IR', 900], ['US', 400]]}},
          open(os.path.join(d, 'snapshot.json'), 'w'))
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
LAYOUT_LOG_FILE="$WORK/bg/logs/guard-$(date +%Y%m%d).jsonl" node "$ROOT/scripts/panel-layout-test.js" "http://127.0.0.1:$PORT" /panel admin layout-pass-12345 "$SHOTS" layout-op op-layout-pass-12345 layout-demo demo-layout-pass-12345
rc=$?
# A PHP warning, notice, deprecation or fatal error on any page is a failure too.
if grep -E 'Warning|Notice|Deprecated|Fatal error|Parse error' "$WORK/php.log" >/dev/null 2>&1; then
	echo "FAIL  PHP reported problems while the pages were rendered:"; grep -E 'Warning|Notice|Deprecated|Fatal error|Parse error' "$WORK/php.log" | sort | uniq -c | head -10
	rc=1
fi
exit $rc
