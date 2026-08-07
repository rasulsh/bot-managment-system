<?php
// Bot Guard CLI self-test. Run: php scripts/guard-selftest.php
// Exit code 0 when every non-SKIP assertion passes, 1 otherwise.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

define('GV_BOOT', 1);
require __DIR__ . '/../guard/guard.php';

$GV_PASS = 0;
$GV_FAIL = 0;
$GV_SKIP = 0;

function t_ok($name, $cond) {
	global $GV_PASS, $GV_FAIL;
	if ($cond) {
		$GV_PASS++;
		echo "PASS  " . $name . "\n";
	} else {
		$GV_FAIL++;
		echo "FAIL  " . $name . "\n";
	}
}

function t_skip($name, $why) {
	global $GV_SKIP;
	$GV_SKIP++;
	echo "SKIP  " . $name . " (" . $why . ")\n";
}

function t_section($name) {
	echo "\n-- " . $name . "\n";
}

// A complete, clean browser facts array. Override any key per test.
function t_facts(array $over = array()) {
	$base = array(
		'ip'      => '203.0.113.7',
		'method'  => 'GET',
		'path'    => '/',
		'query'   => '',
		'params'  => array(),
		'ua'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
			. '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
		'accept'  => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'al'      => 'en-US,en;q=0.9',
		'sf'      => 'navigate',
		'xrw'     => '',
		'xgv'     => '',
		'referer' => '',
		'hc'      => 12,
		'https'   => false,
		'cookie'  => '',
	);
	return array_merge($base, $over);
}

$secret = 'selftest-secret';

// --------------------------------------------------------------------------
t_section('Token');

$tok = gv_tok_make($secret);
$dev = gv_tok_check($tok, $secret, 604800);
t_ok('token roundtrip returns a device id', is_string($dev) && strlen($dev) === 24 && ctype_xdigit($dev));

$old  = bin2hex(random_bytes(12)) . '.' . (time() - 1000);
$old .= '.' . hash_hmac('sha256', $old, $secret);
t_ok('token expired by ttl fails', gv_tok_check($old, $secret, 100) === false);
t_ok('token inside ttl passes', gv_tok_check($old, $secret, 5000) !== false);

$parts = explode('.', $tok);
$bad   = $parts[0] . '.' . $parts[1] . '.' . strrev($parts[2]);
t_ok('token with tampered signature fails', gv_tok_check($bad, $secret, 604800) === false);
t_ok('token signed with another secret fails', gv_tok_check($tok, 'other-secret', 604800) === false);
t_ok('malformed token fails', gv_tok_check('not-a-token', $secret, 604800) === false);
t_ok('empty token fails', gv_tok_check('', $secret, 604800) === false);

// --------------------------------------------------------------------------
t_section('Nonce');

$nonce = gv_nonce_make($secret);
t_ok('nonce roundtrip passes', gv_nonce_check($nonce, $secret, 120) === true);

$oldn  = (time() - 500) . '.' . bin2hex(random_bytes(8));
$oldn .= '.' . hash_hmac('sha256', $oldn, $secret);
t_ok('nonce expired by ttl fails', gv_nonce_check($oldn, $secret, 120) === false);
t_ok('nonce with tampered signature fails', gv_nonce_check($nonce . 'x', $secret, 120) === false);
t_ok('malformed nonce fails', gv_nonce_check('abc', $secret, 120) === false);

// --------------------------------------------------------------------------
t_section('CIDR matcher');

t_ok('ip inside /24 matches', gv_cidr_match('192.168.1.55', '192.168.1.0/24') === true);
t_ok('ip outside /24 does not match', gv_cidr_match('192.168.2.55', '192.168.1.0/24') === false);
t_ok('/32 exact match', gv_cidr_match('10.0.0.1', '10.0.0.1/32') === true);
t_ok('/32 neighbour does not match', gv_cidr_match('10.0.0.2', '10.0.0.1/32') === false);
t_ok('/0 matches everything', gv_cidr_match('8.8.8.8', '0.0.0.0/0') === true);
t_ok('bare address behaves as /32', gv_cidr_match('10.0.0.1', '10.0.0.1') === true);
t_ok('invalid ip returns false', gv_cidr_match('not-an-ip', '10.0.0.0/8') === false);
t_ok('invalid cidr returns false', gv_cidr_match('10.0.0.1', '10.0.0.0/99') === false);
t_ok('ipv6 input returns false', gv_cidr_match('2001:db8::1', '10.0.0.0/8') === false);

// --------------------------------------------------------------------------
t_section('Client IP resolution');

$srv = array('REMOTE_ADDR' => '198.51.100.9', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4, 5.6.7.8');
t_ok('remote addr outside cdn ranges wins',
	gv_client_ip($srv, array('203.0.113.0/24')) === '198.51.100.9');
t_ok('no cdn ranges configured means remote addr wins',
	gv_client_ip($srv, array()) === '198.51.100.9');

$srv2 = array('REMOTE_ADDR' => '203.0.113.10', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4, 5.6.7.8');
t_ok('remote addr inside cdn range takes last xff entry',
	gv_client_ip($srv2, array('203.0.113.0/24')) === '5.6.7.8');

$srv3 = array('REMOTE_ADDR' => '203.0.113.10', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4, junk');
t_ok('invalid last xff entry falls back to remote addr',
	gv_client_ip($srv3, array('203.0.113.0/24')) === '203.0.113.10');

$srv4 = array('REMOTE_ADDR' => '203.0.113.10');
t_ok('missing xff falls back to remote addr',
	gv_client_ip($srv4, array('203.0.113.0/24')) === '203.0.113.10');

// --------------------------------------------------------------------------
t_section('Navigation and AJAX classification');

t_ok('clean browser GET is a navigation', gv_is_nav(t_facts()) === true);
t_ok('clean browser GET is not ajax', gv_is_ajax(t_facts()) === false);
t_ok('x-requested-with marks ajax', gv_is_ajax(t_facts(array('xrw' => 'XMLHttpRequest'))) === true);
t_ok('x-requested-with is never a navigation',
	gv_is_nav(t_facts(array('xrw' => 'XMLHttpRequest'))) === false);
t_ok('json GET is ajax', gv_is_ajax(t_facts(array('accept' => 'application/json'))) === true);
t_ok('post is never a navigation', gv_is_nav(t_facts(array('method' => 'POST'))) === false);

// --------------------------------------------------------------------------
t_section('Static scoring');

$r = gv_score(t_facts(), false);
t_ok('clean full browser scores 0 with no reasons', $r[0] === 0 && $r[1] === array());

$r = gv_score(t_facts(array('ua' => '')), false);
t_ok('empty UA scores 40 as UA_EMPTY', $r[0] === 40 && $r[1] === array('UA_EMPTY'));

$r = gv_score(t_facts(array('ua' => 'python-requests/2.31.0')), false);
t_ok('scripted UA scores 30 as UA_SCRIPT', $r[0] === 30 && $r[1] === array('UA_SCRIPT'));

$r = gv_score(t_facts(array('ua' => 'curl/8.5.0')), false);
t_ok('curl UA scores 30 as UA_SCRIPT', $r[0] === 30 && $r[1] === array('UA_SCRIPT'));

$r = gv_score(t_facts(array('sf' => '')), false);
t_ok('Chrome 126 without Sec-Fetch-Mode scores 20 as NO_SF', $r[0] === 20 && $r[1] === array('NO_SF'));

$r = gv_score(t_facts(array('ua' => 'Mozilla/5.0 (compatible; Chrome/60.0)', 'sf' => '')), false);
t_ok('old Chrome without Sec-Fetch-Mode is not penalised', $r[0] === 0 && $r[1] === array());

$r = gv_score(t_facts(array('al' => '')), false);
t_ok('navigation without Accept-Language scores 15 as NO_AL', $r[0] === 15 && $r[1] === array('NO_AL'));

$r = gv_score(t_facts(array('al' => '', 'accept' => 'application/json')), false);
t_ok('non-navigation without Accept-Language is not penalised', $r[0] === 0 && $r[1] === array());

$r = gv_score(t_facts(array('hc' => 3)), false);
t_ok('fewer than 5 headers scores 15 as FEW_HDR', $r[0] === 15 && $r[1] === array('FEW_HDR'));

$r = gv_score(t_facts(), true);
t_ok('honeypot history scores 40 as HP_HIST', $r[0] === 40 && $r[1] === array('HP_HIST'));

$r = gv_score(t_facts(array('ua' => '', 'al' => '', 'hc' => 2)), false);
t_ok('empty UA plus no Accept-Language plus few headers reaches the block score',
	$r[0] === 70 && $r[1] === array('UA_EMPTY', 'NO_AL', 'FEW_HDR'));

// --------------------------------------------------------------------------
t_section('Exemptions and known bots');

$ex = array('/internal-cron.php', '/rest/');
t_ok('exact exempt path matches', gv_is_exempt(t_facts(array('path' => '/internal-cron.php')), $ex, array()) === true);
t_ok('exempt path prefix matches', gv_is_exempt(t_facts(array('path' => '/rest/v2/posts')), $ex, array()) === true);
t_ok('other path is not exempt', gv_is_exempt(t_facts(array('path' => '/shop')), $ex, array()) === false);

$ep = array('route' => array('payment/', 'api/'));
t_ok('exempt param prefix matches',
	gv_is_exempt(t_facts(array('params' => array('route' => 'payment/callback'))), array(), $ep) === true);
t_ok('other param value is not exempt',
	gv_is_exempt(t_facts(array('params' => array('route' => 'product/product'))), array(), $ep) === false);

$bots = array('googlebot', 'bingbot');
t_ok('googlebot UA matches', gv_match_bot('Mozilla/5.0 (compatible; Googlebot/2.1)', $bots) === 'googlebot');
t_ok('browser UA does not match a bot', gv_match_bot(t_facts()['ua'], $bots) === '');
t_ok('empty UA does not match a bot', gv_match_bot('', $bots) === '');

// --------------------------------------------------------------------------
t_section('RESP serialization');

t_ok('gv_resp_encode produces the exact RESP byte string',
	gv_resp_encode(array('INCR', 'gv:x')) === "*2\r\n\$4\r\nINCR\r\n\$4\r\ngv:x\r\n");
t_ok('gv_resp_encode handles three arguments',
	gv_resp_encode(array('SETEX', 'gv:hp:1.2.3.4', '1')) === "*3\r\n\$5\r\nSETEX\r\n\$13\r\ngv:hp:1.2.3.4\r\n\$1\r\n1\r\n");

// --------------------------------------------------------------------------
t_section('Redis degraded mode');

$t = microtime(true);
$conn = gv_redis_connect(array('host' => '127.0.0.1', 'port' => 63999, 'timeout' => 0.05));
$took = microtime(true) - $t;
t_ok('connect to a closed port returns false', $conn === false);
t_ok('connect to a closed port fails in under 0.2 s (took '
	. number_format($took, 4) . ' s)', $took < 0.2);
t_ok('commands on a false connection return false', gv_redis_cmd(false, array('PING')) === false);
t_ok('counter bump on a false connection returns 0', gv_bump(false, 'gv:x', 60) === 0);

// --------------------------------------------------------------------------
t_section('Logger');

$tmp = sys_get_temp_dir() . '/gv-selftest-' . getmypid();
$facts = t_facts(array('referer' => 'https://example.com/a/b?c=d'));
$state = array('tok' => 'v', 'dev' => 'abc123', 'sc' => 15, 'rs' => array('FEW_HDR'),
	'cd' => 1, 'ciu' => 2, 'ci' => 3, 'rd' => 0, 'hp' => 0, 'bot' => '');
gv_log(gv_log_row($facts, $state, 'allow', 0, microtime(true) - 0.01), $tmp);

$file = $tmp . '/guard-' . date('Ymd') . '.jsonl';
t_ok('log file was created', is_file($file));

$lines = is_file($file) ? file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : array();
t_ok('log file holds exactly one line', count($lines) === 1);

$row = count($lines) === 1 ? json_decode($lines[0], true) : null;
t_ok('log line is valid JSON', is_array($row));

$schema = array('ts', 'ip', 'ua', 'uah', 'm', 'p', 'q', 'aj', 'nav', 'tok', 'dev', 'sf',
	'al', 'hc', 'sc', 'rs', 'cd', 'ciu', 'ci', 'rd', 'hp', 'bot', 'ref', 'act', 'sh', 'ms');
t_ok('log line carries every schema key in order', is_array($row) && array_keys($row) === $schema);
t_ok('referer is reduced to its host', is_array($row) && $row['ref'] === 'example.com');
t_ok('navigation and ajax flags are recorded',
	is_array($row) && $row['nav'] === 1 && $row['aj'] === 0);
t_ok('guard wall time is recorded', is_array($row) && $row['ms'] >= 10 && $row['ms'] < 1000);

if (is_file($file)) { @unlink($file); }
if (is_dir($tmp)) { @rmdir($tmp); }

// --------------------------------------------------------------------------
t_section('Redis roundtrip (optional)');

$redis_bin = trim((string)@shell_exec('command -v redis-server 2>/dev/null'));
if ($redis_bin === '') {
	t_skip('redis INCR/EXPIRE roundtrip', 'redis-server not installed in this environment');
} else {
	$port = 63790;
	$pid  = sys_get_temp_dir() . '/gv-selftest-redis-' . getmypid() . '.pid';
	@shell_exec(escapeshellarg($redis_bin) . ' --port ' . $port . ' --bind 127.0.0.1'
		. ' --save "" --appendonly no --daemonize yes --pidfile ' . escapeshellarg($pid)
		. ' >/dev/null 2>&1');
	$conn = false;
	for ($i = 0; $i < 50 && !$conn; $i++) {
		$conn = gv_redis_connect(array('host' => '127.0.0.1', 'port' => $port, 'timeout' => 0.2));
		if (!$conn) { usleep(100000); }
	}
	if (!$conn) {
		t_skip('redis INCR/EXPIRE roundtrip', 'local redis-server did not start');
	} else {
		$key = 'gv:selftest:' . getmypid();
		gv_redis_cmd($conn, array('DEL', $key));
		t_ok('redis PING replies PONG', gv_redis_cmd($conn, array('PING')) === 'PONG');
		t_ok('redis INCR returns 1 on a fresh key', gv_r_incr($conn, $key) === 1);
		t_ok('redis INCR returns 2 on the second call', gv_r_incr($conn, $key) === 2);
		t_ok('redis EXPIRE returns 1', gv_r_expire($conn, $key, 60) === 1);
		t_ok('redis TTL is set', (int)gv_redis_cmd($conn, array('TTL', $key)) > 0);
		t_ok('redis GET returns the bulk string', gv_r_get($conn, $key) === '2');
		t_ok('redis GET on a missing key returns null', gv_r_get($conn, $key . ':missing') === null);
		t_ok('redis SETEX returns OK', gv_r_setex($conn, $key . ':hp', 60, '1') === 'OK');
		t_ok('redis error reply returns false', gv_redis_cmd($conn, array('INCR')) === false);
		t_ok('counter bump against live redis counts up', gv_bump($conn, $key . ':b', 60) === 1
			&& gv_bump($conn, $key . ':b', 60) === 2);
		gv_redis_cmd($conn, array('FLUSHALL'));
		gv_redis_cmd($conn, array('SHUTDOWN', 'NOSAVE'));
		gv_redis_close($conn);
	}
	if (is_file($pid)) { @unlink($pid); }
}

// --------------------------------------------------------------------------
echo "\n";
echo "PASS " . $GV_PASS . "  FAIL " . $GV_FAIL . "  SKIP " . $GV_SKIP . "\n";
exit($GV_FAIL === 0 ? 0 : 1);
