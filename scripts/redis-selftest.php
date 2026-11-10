<?php
// Bot Guard Redis self-test. Run: php scripts/redis-selftest.php
// Spawns its own throwaway redis-server instances (no auth, requirepass, ACL,
// unix socket) and exercises the guard's Redis contract against each:
// round trips per path, fail-fast, circuit breaker, error log, authentication,
// db selection and key prefix isolation.
// Exit code 0 when every non-SKIP assertion passes, 1 otherwise.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

define('GV_BOOT', 1);
define('GV_NO_AUTORUN', 1);
require __DIR__ . '/../guard/guard.php';

$GV_PASS = 0; $GV_FAIL = 0; $GV_SKIP = 0;
function t_ok($name, $cond) {
	global $GV_PASS, $GV_FAIL;
	if ($cond) { $GV_PASS++; echo "PASS  $name\n"; } else { $GV_FAIL++; echo "FAIL  $name\n"; }
}
function t_skip($name, $why) { global $GV_SKIP; $GV_SKIP++; echo "SKIP  $name ($why)\n"; }
function t_section($name) { echo "\n-- $name\n"; }

// ---- scaffolding ---------------------------------------------------------

$T_DIR = sys_get_temp_dir() . '/gv-redis-selftest-' . getmypid();
@mkdir($T_DIR, 0775, true);
$T_PIDS = array();
$T_AUDIT_BACKUP = is_file(__DIR__ . '/../panel/audit.jsonl') ? file_get_contents(__DIR__ . '/../panel/audit.jsonl') : null;

function t_cleanup() {
	global $T_DIR, $T_PIDS, $T_AUDIT_BACKUP;
	// The panel tests enqueue jobs, which append to the real panel/audit.jsonl:
	// put it back exactly as it was.
	$audit = __DIR__ . '/../panel/audit.jsonl';
	if ($T_AUDIT_BACKUP === null) { @unlink($audit); } else { @file_put_contents($audit, $T_AUDIT_BACKUP); }
	foreach ($T_PIDS as $pid) { @posix_kill($pid, 15); }
	$files = @glob($T_DIR . '/{,.}*', GLOB_BRACE);
	foreach ((array)$files as $f) { if (is_file($f)) { @unlink($f); } }
	foreach ((array)@glob($T_DIR . '/*', GLOB_ONLYDIR) as $d) {
		foreach ((array)@glob($d . '/{,.}*', GLOB_BRACE) as $f) { if (is_file($f)) { @unlink($f); } }
		@rmdir($d);
	}
	@rmdir($T_DIR);
}
register_shutdown_function('t_cleanup');

// Start a redis-server with extra args. Returns array(port, sock) or null.
function t_redis_start($port, array $extra = array(), $sock = '') {
	global $T_DIR, $T_PIDS;
	$bin = trim((string)@shell_exec('command -v redis-server 2>/dev/null'));
	if ($bin === '') { return null; }
	$pid = $T_DIR . '/redis-' . $port . '.pid';
	$cmd = escapeshellarg($bin) . ' --port ' . (int)$port . ' --bind 127.0.0.1 --save "" --appendonly no'
		. ' --daemonize yes --pidfile ' . escapeshellarg($pid) . ' --dir ' . escapeshellarg($T_DIR);
	if ($sock !== '') { $cmd .= ' --unixsocket ' . escapeshellarg($sock) . ' --unixsocketperm 700'; }
	foreach ($extra as $e) { $cmd .= ' ' . $e; }
	@shell_exec($cmd . ' >/dev/null 2>&1');
	for ($i = 0; $i < 50; $i++) {
		$c = @stream_socket_client('tcp://127.0.0.1:' . $port, $en, $es, 0.2);
		if ($c) {
			fclose($c);
			if (is_file($pid)) { $T_PIDS[] = (int)trim(file_get_contents($pid)); }
			return array($port, $sock);
		}
		usleep(100000);
	}
	return null;
}

function t_cfg(array $redis = array(), array $over = array()) {
	global $T_DIR;
	$d = array(
		'secret' => 'rt-secret', 'cookie_name' => '_gv', 'token_ttl' => 604800, 'nonce_ttl' => 120,
		'enforce' => array('block' => true, 'challenge' => true, 'ratelimit' => true),
		'signals' => array('reputation' => true, 'ml' => true, 'clf' => true),
		'holdout_pct' => 0, 'capture_outcomes' => false,
		'limits' => array('window' => 60, 'device' => 1000, 'ip_ua' => 1000, 'ip' => 1000, 'bot' => 1000),
		'honeypot_path' => '/old-archive', 'exempt_paths' => array(), 'known_bots' => array('googlebot'),
		'log_dir' => $T_DIR . '/logs',
		'redis' => array_merge(array('host' => '127.0.0.1', 'port' => 63800, 'timeout' => 0.05,
			'breaker_ttl' => 5), $redis),
	);
	return array_replace_recursive($d, $over);
}

// Write a config file and run one guarded request in a child process.
function t_probe(array $cfg, array $server = array(), array $cookie = array()) {
	global $T_DIR;
	$path = $T_DIR . '/cfg-' . md5(serialize($cfg)) . '.php';
	file_put_contents($path, '<?php if (!defined("GV_BOOT")) { exit; } return ' . var_export($cfg, true) . ';');
	$in = json_encode(array('config' => $path, 'server' => $server, 'cookie' => $cookie));
	$cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/request-probe.php');
	$p = proc_open($cmd, array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes);
	fwrite($pipes[0], $in); fclose($pipes[0]);
	$out = stream_get_contents($pipes[1]); fclose($pipes[1]);
	stream_get_contents($pipes[2]); fclose($pipes[2]);
	proc_close($p);
	$lines = array_filter(explode("\n", trim($out)));
	$r = json_decode((string)end($lines), true);
	return is_array($r) ? $r : array('rt' => -1, 'bytes' => -1, 'ms' => -1);
}

// Last decision row in the guard log of $cfg.
function t_lastrow(array $cfg) {
	$files = glob($cfg['log_dir'] . '/guard-*.jsonl');
	if (!$files) { return null; }
	$lines = file(end($files), FILE_IGNORE_NEW_LINES);
	return json_decode(end($lines), true);
}

function t_nav() {
	return array('HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36',
		'HTTP_ACCEPT' => 'text/html,application/xhtml+xml', 'HTTP_ACCEPT_LANGUAGE' => 'en',
		'HTTP_SEC_FETCH_MODE' => 'navigate', 'HTTP_ACCEPT_ENCODING' => 'gzip', 'HTTP_CONNECTION' => 'keep-alive',
		'HTTP_HOST' => 'x', 'HTTP_COOKIE' => 'a=b', 'HTTP_UPGRADE_INSECURE_REQUESTS' => '1');
}

function t_rm_logs() {
	global $T_DIR;
	foreach ((array)glob($T_DIR . '/logs/{,.}*', GLOB_BRACE) as $f) { if (is_file($f)) { @unlink($f); } }
}

// ---- servers --------------------------------------------------------------

$plain = t_redis_start(63800);
if (!$plain) {
	t_skip('redis suite', 'redis-server not available');
	echo "\nPASS $GV_PASS  FAIL $GV_FAIL  SKIP $GV_SKIP\n";
	exit(0);
}
$R = array('host' => '127.0.0.1', 'port' => 63800);
$cx = gv_redis_connect($R + array('timeout' => 0.2));
gv_redis_cmd($cx, array('FLUSHALL'));

// --------------------------------------------------------------------------
t_section('Pipeline primitive');

$conn = gv_redis_connect($R + array('timeout' => 0.2));
gv_redis_rt(true);
$r = gv_redis_pipeline($conn, array(array('SET', 'pp:a', '1'), array('GET', 'pp:a'), array('GET', 'pp:none'),
	array('INCR', 'pp:a'), array('INCR', 'pp:x', 'extra'), array('PING')));
t_ok('a pipeline is one round trip', gv_redis_rt() === 1);
t_ok('a pipeline returns one reply per command, in order',
	is_array($r) && $r[0] === 'OK' && $r[1] === '1' && $r[2] === null && $r[3] === 2 && $r[5] === 'PONG');
t_ok('an error reply fails only its own command', $r[4] === false);
t_ok('an error reply does not kill the connection', gv_redis_alive($conn) && gv_r_get($conn, 'pp:a') === '2');
t_ok('an empty pipeline is a no-op', gv_redis_pipeline($conn, array()) === array());
t_ok('a pipeline on a dead connection returns false', gv_redis_pipeline(false, array(array('PING'))) === false);
gv_redis_cmd($conn, array('LPUSH', 'pp:l', 'a', 'b'));
$ml = gv_redis_cmd($conn, array('LRANGE', 'pp:l', '0', '-1'));
t_ok('multi-bulk replies parse into arrays', $ml === array('b', 'a'));
gv_redis_close($conn);

// --------------------------------------------------------------------------
t_section('Counters never exist without a TTL');

$conn = gv_redis_connect($R + array('timeout' => 0.2));
gv_redis_cmd($conn, array('DEL', 'ct:a', 'ct:b'));
t_ok('first bump counts 1, then 2, 3', gv_bump($conn, 'ct:a', 60) === 1 && gv_bump($conn, 'ct:a', 60) === 2
	&& gv_bump($conn, 'ct:a', 60) === 3);
t_ok('the first bump leaves a TTL', (int)gv_redis_cmd($conn, array('TTL', 'ct:a')) > 0);
// The expiry race: the key exists WITHOUT a TTL (as if it expired between SET NX
// and INCR and INCR re-created it bare).
gv_redis_cmd($conn, array('SET', 'ct:b', '5'));
t_ok('a TTL-less counter still counts on', gv_bump($conn, 'ct:b', 60) === 6);
t_ok('a TTL-less counter is repaired with an EXPIRE', (int)gv_redis_cmd($conn, array('TTL', 'ct:b')) > 0);
$counts = gv_bump_many($conn, array(array('ct:m1', 60), array('ct:m2', 60), array('ct:m1', 60)));
t_ok('several counters are bumped in one call, in order', $counts === array(1, 1, 2));
gv_redis_rt(true);
gv_bump_many($conn, array(array('ct:m3', 60), array('ct:m4', 60), array('ct:m5', 60)));
t_ok('three counters cost one round trip', gv_redis_rt() === 1);
gv_redis_close($conn);

// --------------------------------------------------------------------------
t_section('Round trips per request path (healthy Redis)');

$cfg = t_cfg();
$tok = gv_tok_make('rt-secret');
$dev = gv_tok_check($tok, 'rt-secret', 604800);
gv_redis_cmd($cx, array('FLUSHALL'));
t_rm_logs();
$p = t_probe($cfg, t_nav(), array('_gv' => $tok));
$row = t_lastrow($cfg);
t_ok('a tokened navigation costs at most 2 round trips (' . $p['rt'] . ')', $p['rt'] >= 1 && $p['rt'] <= 2);
t_ok('a tokened navigation is allowed with zero guard output', $row['act'] === 'allow' && $p['bytes'] === 0);
t_ok('a tokened navigation counted its three counters', $row['cd'] === 1 && $row['ciu'] === 1 && $row['ci'] === 1 && $row['rd'] === 0);

$p = t_probe($cfg, t_nav());
t_ok('a token-less navigation (challenge) costs at most 2 round trips (' . $p['rt'] . ')', $p['rt'] <= 2);

gv_redis_cmd($cx, array('SET', 'gv:allow:' . $dev, '1', 'EX', '60'));
$p = t_probe($cfg, t_nav(), array('_gv' => $tok));
$row = t_lastrow($cfg);
t_ok('an allow override costs 1 round trip and counts nothing', $p['rt'] === 1 && $row['act'] === 'allow_override' && $row['cd'] === 0);
gv_redis_cmd($cx, array('DEL', 'gv:allow:' . $dev));

$bot = t_nav(); $bot['HTTP_USER_AGENT'] = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
gv_redis_cmd($cx, array('SET', 'gv:botok:198.51.100.9', '1', 'EX', '60'));
gv_redis_cmd($cx, array('DEL', 'gv:rb:198.51.100.9', 'gv:ri:198.51.100.9'));
$p = t_probe($cfg, $bot);
$row = t_lastrow($cfg);
t_ok('a verified bot costs at most 2 round trips (' . $p['rt'] . ')', $p['rt'] <= 2);
t_ok('the bot pass bumps only rb', $row['act'] === 'allow_bot' && $row['botv'] === 'ok'
	&& gv_redis_cmd($cx, array('GET', 'gv:rb:198.51.100.9')) === '1'
	&& gv_redis_cmd($cx, array('GET', 'gv:ri:198.51.100.9')) === null);
gv_redis_cmd($cx, array('DEL', 'gv:botok:198.51.100.9'));

$hp = t_nav(); $hp['REQUEST_URI'] = '/old-archive';
$p = t_probe($cfg, $hp);
$row = t_lastrow($cfg);
t_ok('the honeypot costs at most 2 round trips (' . $p['rt'] . ') and fires', $p['rt'] <= 2 && $row['act'] === '404_hp'
	&& gv_redis_cmd($cx, array('GET', 'gv:hp:198.51.100.9')) === '1');
t_ok('the honeypot fires even with every enforce toggle off', (function () use ($cx) {
	global $T_DIR;
	gv_redis_cmd($cx, array('DEL', 'gv:hp:198.51.100.9'));
	$c = t_cfg(array(), array('enforce' => array('block' => false, 'challenge' => false, 'ratelimit' => false)));
	$hp = t_nav(); $hp['REQUEST_URI'] = '/old-archive';
	t_probe($c, $hp);
	return gv_redis_cmd($cx, array('GET', 'gv:hp:198.51.100.9')) === '1';
})());
gv_redis_cmd($cx, array('FLUSHALL'));

// --------------------------------------------------------------------------
t_section('Fail-fast and the late-reply hazard');

$hole = @stream_socket_server('tcp://127.0.0.1:0', $en, $es);
$hn = stream_socket_get_name($hole, false);
$hole_port = (int)substr($hn, strrpos($hn, ':') + 1);
$HR = array('host' => '127.0.0.1', 'port' => $hole_port, 'timeout' => 0.05);
$L = $T_DIR . '/ff';
$conn = gv_redis_connect($HR, $L);
$t = microtime(true);
$a = gv_redis_cmd($conn, array('GET', 'k1'));
$first = microtime(true) - $t;
$t = microtime(true);
$b = gv_redis_cmd($conn, array('GET', 'k2'));
$c2 = gv_redis_pipeline($conn, array(array('GET', 'k3'), array('GET', 'k4')));
$rest = microtime(true) - $t;
t_ok('a stalled command fails after one timeout (' . round($first * 1000) . ' ms)', $a === false && $first < 0.5);
t_ok('the connection is closed after the first failure', !gv_redis_alive($conn));
t_ok('later commands are instant no-ops (' . round($rest * 1000, 2) . ' ms)', $b === false && $c2 === false && $rest < 0.01);

// Late reply: the server answers AFTER the client gave up. Nothing may read it.
$conn = gv_redis_connect($HR, $L, false);
gv_redis_cmd($conn, array('GET', 'late'));            // times out, connection dropped
$srv = @stream_socket_accept($hole, 0.2);
if ($srv) {
	@fwrite($srv, "\$4\r\nLATE\r\n");                  // the late reply
	usleep(20000);
}
$again = gv_redis_cmd($conn, array('GET', 'next'));
t_ok('a late reply is never consumed by a later command', $again === false && !gv_redis_alive($conn));
$conn2 = gv_redis_connect($HR, $L, false);
t_ok('a fresh connection starts clean', $conn2 !== false && gv_redis_alive($conn2));
gv_redis_close($conn2);

// --------------------------------------------------------------------------
t_section('Black hole and refused port (full request)');

$cfgH = t_cfg(array('port' => $hole_port), array('log_dir' => $T_DIR . '/hole'));
@mkdir($T_DIR . '/hole');
$tok = gv_tok_make('rt-secret');
$base = t_probe(t_cfg(array('port' => 63800), array('log_dir' => $T_DIR . '/ok')), t_nav(), array('_gv' => $tok));
$p1 = t_probe($cfgH, t_nav(), array('_gv' => $tok));
$row = t_lastrow($cfgH);
t_ok('black hole: the request pays about one timeout, not N (' . $p1['ms'] . ' ms)', $p1['ms'] < 400);
t_ok('black hole: logged degraded (rd=1) and still allowed with zero output',
	$row['rd'] === 1 && $row['act'] === 'allow' && $p1['bytes'] === 0);
t_ok('black hole: the breaker marker exists', is_file($T_DIR . '/hole/.redis-down'));
$p2 = t_probe($cfgH, t_nav(), array('_gv' => $tok));
t_ok('black hole: the next request skips Redis entirely (' . $p2['ms'] . ' ms, rt ' . $p2['rt'] . ')',
	$p2['rt'] === 0 && $p2['ms'] < $p1['ms'] && $p2['ms'] < 30);
$row = t_lastrow($cfgH);
t_ok('black hole: a skipped request is still logged rd=1', $row['rd'] === 1);
t_ok('the error log names the failure', is_file($T_DIR . '/hole/guard-errors.log')
	&& strpos(file_get_contents($T_DIR . '/hole/guard-errors.log'), 'redis_timeout') !== false);
fclose($hole);

$dead_port = 63999;
$cfgD = t_cfg(array('port' => $dead_port), array('log_dir' => $T_DIR . '/dead'));
$p = t_probe($cfgD, t_nav(), array('_gv' => $tok));
$row = t_lastrow($cfgD);
t_ok('connection refused: no measurable delay (' . $p['ms'] . ' ms) and rd=1', $p['ms'] < 100 && $row['rd'] === 1);
t_ok('connection refused: the error log says redis_connect',
	strpos(file_get_contents($T_DIR . '/dead/guard-errors.log'), 'redis_connect') !== false);

// --------------------------------------------------------------------------
t_section('Circuit breaker window and probe');

$BL = $T_DIR . '/br';
$M = $BL . '/.redis-down';
@mkdir($BL);
$bcfg = $R + array('timeout' => 0.2, 'breaker_ttl' => 5);
touch($M, time() - 2);
t_ok('inside the window the connect is skipped', gv_redis_connect($bcfg, $BL) === false);
touch($M, time() - 10);
$probe = gv_redis_connect($bcfg, $BL);
t_ok('after the window the first request probes', $probe !== false);
clearstatcache(true, $M);
$mt = filemtime($M);
t_ok('the prober refreshed the marker BEFORE probing (no herd)', time() - $mt < 2);
t_ok('a concurrent request still skips', gv_redis_connect($bcfg, $BL) === false);
gv_redis_ctx(array('probe' => true));     // (that call reset the per-request flag; a real request connects once)
gv_redis_cmd($probe, array('PING'));
clearstatcache(true, $M);
t_ok('a successful command clears the marker', !is_file($M));
gv_redis_close($probe);
touch($M, time() - 10);
t_ok('breaker_ttl 0 disables the breaker', ($c = gv_redis_connect($bcfg + array('breaker_ttl' => 0), $BL)) !== false);
gv_redis_close($c);
t_ok('the panel can bypass the breaker', ($c = gv_redis_connect($bcfg, $BL, false)) !== false);
gv_redis_close($c);
@unlink($M);

// --------------------------------------------------------------------------
t_section('Error log');

$EL = $T_DIR . '/el';
gv_errlog('alpha', 'first', $EL);
gv_errlog('alpha', 'second', $EL);
gv_errlog('beta', 'other', $EL);
$lines = file($EL . '/guard-errors.log', FILE_IGNORE_NEW_LINES);
t_ok('one line per code per minute', count($lines) === 2);
t_ok('a line carries timestamp, code and message', preg_match('/^\S+ alpha first$/', $lines[0]) === 1);
gv_errlog('bad code!', "line\nbreak", $EL);
$all = file_get_contents($EL . '/guard-errors.log');
t_ok('codes and messages are sanitised to one line', substr_count($all, "\n") === 3);


// ==========================================================================
// Work item 3: authentication, db selection, key prefix
// ==========================================================================

$ver = '';
$info = (string)gv_redis_cmd($cx, array('INFO', 'server'));
if (preg_match('/redis_version:(\S+)/', $info, $m)) { $ver = $m[1]; }
$major = (int)$ver;
echo "\n(redis-server $ver)\n";

// What does this server really say to AUTH when no password is configured?
$raw = @stream_socket_client('tcp://127.0.0.1:63800', $en, $es, 1);
fwrite($raw, gv_resp_encode(array('AUTH', 'whatever')));
echo "(observed reply to AUTH without a configured password: " . trim((string)fgets($raw)) . ")\n";
fclose($raw);

$auth = t_redis_start(63801, array('--requirepass', 's3cret'));
$acl  = t_redis_start(63802);
$sock = $T_DIR . '/redis.sock';
$unix = t_redis_start(63803, array(), $sock);
if ($acl && $major >= 6) {
	$ac = gv_redis_connect(array('port' => 63802, 'timeout' => 0.2));
	gv_redis_cmd($ac, array('ACL', 'SETUSER', 'gvuser', 'on', '>aclpass', '~*', '+@all'));
	gv_redis_close($ac);
}

function t_mkdir_log($name) { global $T_DIR; $d = $T_DIR . '/' . $name; @mkdir($d); return $d; }

// --------------------------------------------------------------------------
t_section('Authentication modes');

$LD = t_mkdir_log('auth1');
$c = gv_redis_connect(array('port' => 63800, 'timeout' => 0.2), $LD);
t_ok('no auth server, no password: works exactly as before', $c && gv_redis_cmd($c, array('PING')) === 'PONG');
gv_redis_rt(true); gv_redis_close($c);
$c = gv_redis_connect(array('port' => 63800, 'timeout' => 0.2), $LD);
t_ok('no password and db 0: the handshake costs zero round trips', gv_redis_rt() === 0);
gv_redis_close($c);

if (!$auth) { t_skip('requirepass matrix', 'could not start a second redis'); }
else {
	$LD = t_mkdir_log('auth2');
	gv_redis_rt(true);
	$c = gv_redis_connect(array('port' => 63801, 'timeout' => 0.2, 'password' => 's3cret'), $LD);
	t_ok('requirepass + correct password: works', $c && gv_redis_cmd($c, array('PING')) === 'PONG');
	t_ok('AUTH costs exactly one extra round trip', gv_redis_rt() === 2);
	gv_redis_close($c);

	$LD = t_mkdir_log('auth3');
	$c = gv_redis_connect(array('port' => 63801, 'timeout' => 0.2, 'password' => 'WRONG-pass'), $LD);
	t_ok('requirepass + wrong password: degraded (no connection)', $c === false);
	t_ok('wrong password arms the breaker', is_file($LD . '/.redis-down'));
	t_ok('wrong password is logged as redis_auth', strpos((string)@file_get_contents($LD . '/guard-errors.log'), 'redis_auth') !== false);
	t_ok('the password never appears in the error log', strpos((string)@file_get_contents($LD . '/guard-errors.log'), 'WRONG-pass') === false);

	$LD = t_mkdir_log('auth4');
	$c = gv_redis_connect(array('port' => 63801, 'timeout' => 0.2), $LD);
	$r = $c ? gv_redis_cmd($c, array('GET', 'x')) : false;
	t_ok('requirepass + no password: the first command fails and the connection dies', $r === false && !gv_redis_alive($c));
	t_ok('requirepass + no password is logged as redis_auth', strpos((string)@file_get_contents($LD . '/guard-errors.log'), 'redis_auth') !== false);

	// Full requests: the site must keep working (200, zero guard output, rd=1).
	$tok = gv_tok_make('rt-secret');
	foreach (array('wrong password' => array('password' => 'nope'), 'no password' => array()) as $label => $extra) {
		$cfgA = t_cfg(array('port' => 63801) + $extra, array('log_dir' => t_mkdir_log('auth-' . md5($label))));
		$p = t_probe($cfgA, t_nav(), array('_gv' => $tok));
		$row = t_lastrow($cfgA);
		t_ok("requirepass + $label: the request is allowed, untouched and logged rd=1",
			$p['bytes'] === 0 && $row['act'] === 'allow' && $row['rd'] === 1);
	}
	$cfgA = t_cfg(array('port' => 63801, 'password' => 's3cret'), array('log_dir' => t_mkdir_log('auth-ok')));
	$p = t_probe($cfgA, t_nav(), array('_gv' => $tok));
	$row = t_lastrow($cfgA);
	t_ok('requirepass + correct password: a full request counts (rd=0, ci=1), 3 round trips incl. AUTH',
		$row['rd'] === 0 && $row['ci'] === 1 && $p['rt'] === 3);
}

$LD = t_mkdir_log('auth5');
$c = gv_redis_connect(array('port' => 63800, 'timeout' => 0.2, 'password' => 'unneeded'), $LD);
t_ok('no auth server + password set: still works', $c && gv_redis_cmd($c, array('PING')) === 'PONG');
t_ok('...and the mismatch is noted once in the error log',
	strpos((string)@file_get_contents($LD . '/guard-errors.log'), 'redis_auth_unneeded') !== false);
t_ok('...without arming the breaker', !is_file($LD . '/.redis-down'));
gv_redis_close($c);

if ($acl && $major >= 6) {
	$LD = t_mkdir_log('acl');
	$c = gv_redis_connect(array('port' => 63802, 'timeout' => 0.2, 'username' => 'gvuser', 'password' => 'aclpass'), $LD);
	t_ok('ACL user + password: works', $c && gv_redis_cmd($c, array('SET', 'acl:k', '1')) === 'OK');
	gv_redis_close($c);
	$c = gv_redis_connect(array('port' => 63802, 'timeout' => 0.2, 'username' => 'gvuser', 'password' => 'bad'), $LD);
	t_ok('ACL user + wrong password: degraded', $c === false);
} else {
	t_skip('ACL user', 'needs Redis >= 6 (found ' . $ver . ')');
}

if ($unix) {
	$LD = t_mkdir_log('unix');
	$c = gv_redis_connect(array('socket' => $sock, 'port' => 1, 'timeout' => 0.2), $LD);
	t_ok('unix socket: works and ignores host/port', $c && gv_redis_cmd($c, array('PING')) === 'PONG');
	gv_redis_close($c);
	$cfgU = t_cfg(array('socket' => $sock, 'port' => 1), array('log_dir' => t_mkdir_log('unix2')));
	$tok = gv_tok_make('rt-secret');
	$p = t_probe($cfgU, t_nav(), array('_gv' => $tok));
	$row = t_lastrow($cfgU);
	t_ok('unix socket: a full request counts and costs at most 2 round trips', $row['rd'] === 0 && $row['ci'] === 1 && $p['rt'] <= 2);
} else {
	t_skip('unix socket', 'could not start redis on a socket');
}

$LD = t_mkdir_log('db');
$c = gv_redis_connect(array('port' => 63800, 'timeout' => 0.2, 'db' => 1), $LD);
gv_redis_cmd($c, array('SET', 'dbtest:k', 'in-db-1'));
gv_redis_close($c);
$c0 = gv_redis_connect(array('port' => 63800, 'timeout' => 0.2), $LD);
$c1 = gv_redis_connect(array('port' => 63800, 'timeout' => 0.2, 'db' => 1), $LD);
t_ok('db = 1: keys land in db 1 and not in db 0', gv_r_get($c1, 'dbtest:k') === 'in-db-1' && gv_r_get($c0, 'dbtest:k') === null);
gv_redis_close($c0); gv_redis_close($c1);
$c = gv_redis_connect(array('port' => 63800, 'timeout' => 0.2, 'db' => 9999), $LD);
t_ok('an impossible db is a failed connection, not a fatal', $c === false);

// --------------------------------------------------------------------------
t_section('Key prefix');

t_ok('an empty prefix gives the legacy key names byte for byte',
	(function () { gv_redis_prefix(''); return gv_key('rb:1.2.3.4') === 'gv:rb:1.2.3.4' && gp_key('jobs') === 'gp:jobs'; })());
foreach (array('shop1:', 'a_b.c-d:', str_repeat('x', 32)) as $good) {
	t_ok("prefix '$good' is accepted", gv_redis_prefix_valid($good));
}
foreach (array('has space', 'glob*', 'q?', 'br[ack]', str_repeat('x', 33), "new\nline", 'ünï', 'back\\slash') as $badp) {
	t_ok('prefix ' . json_encode($badp) . ' is rejected', !gv_redis_prefix_valid($badp));
}
$LD = t_mkdir_log('prefix-bad');
t_ok('an invalid prefix makes Redis unavailable rather than being altered',
	gv_redis_connect(array('port' => 63800, 'prefix' => 'bad prefix'), $LD) === false);
t_ok('...and is reported in the error log', strpos((string)@file_get_contents($LD . '/guard-errors.log'), 'redis_prefix') !== false);
gv_redis_prefix('');

// Two installs on one server: counters, overrides, verdicts, honeypot all isolated.
gv_redis_cmd($cx, array('FLUSHALL'));
$tok = gv_tok_make('rt-secret');
$dev = gv_tok_check($tok, 'rt-secret', 604800);
$cfgS1 = t_cfg(array('prefix' => 'shop1:'), array('log_dir' => t_mkdir_log('pfx1')));
$cfgS2 = t_cfg(array('prefix' => 'shop2:'), array('log_dir' => t_mkdir_log('pfx2')));
t_probe($cfgS1, t_nav(), array('_gv' => $tok));
t_probe($cfgS1, t_nav(), array('_gv' => $tok));
t_probe($cfgS2, t_nav(), array('_gv' => $tok));
t_ok('prefix: every counter lands under the prefix',
	gv_redis_cmd($cx, array('GET', 'shop1:gv:ri:198.51.100.9')) === '2'
	&& gv_redis_cmd($cx, array('GET', 'shop2:gv:ri:198.51.100.9')) === '1'
	&& gv_redis_cmd($cx, array('GET', 'gv:ri:198.51.100.9')) === null);
t_ok('prefix: the two installs count independently', t_lastrow($cfgS1)['ci'] === 2 && t_lastrow($cfgS2)['ci'] === 1);
gv_redis_cmd($cx, array('SET', 'shop1:gv:deny:198.51.100.9', '1', 'EX', '60'));
t_probe($cfgS1, t_nav(), array('_gv' => $tok));
t_probe($cfgS2, t_nav(), array('_gv' => $tok));
t_ok('prefix: an override in one install does not touch the other',
	t_lastrow($cfgS1)['ovr'] === 'deny' && t_lastrow($cfgS2)['ovr'] === '');
gv_redis_cmd($cx, array('SET', 'shop2:gv:botok:198.51.100.9', '1', 'EX', '60'));
$bot = t_nav(); $bot['HTTP_USER_AGENT'] = 'Googlebot/2.1';
t_probe($cfgS1, $bot); $r1 = t_lastrow($cfgS1);
t_probe($cfgS2, $bot); $r2 = t_lastrow($cfgS2);
t_ok('prefix: a verdict is only seen by its own install', $r1['botv'] === '' && $r2['botv'] === 'ok');
$noPfx = array();
foreach ((array)gv_redis_cmd($cx, array('KEYS', 'gv:*')) as $k) { $noPfx[] = $k; }
t_ok('prefix: no un-prefixed gv: key leaked while prefixes were in use', $noPfx === array());

// Panel side: listings, overrides, job queue, login limiter, all prefixed.
define('GP_BOOT', 1);
define('GP_SELFTEST', 1);
require_once __DIR__ . '/../panel/config_io.php';
require_once __DIR__ . '/../panel/auth.php';
require_once __DIR__ . '/../panel/data.php';
require_once __DIR__ . '/../panel/jobs.php';
function t_panel_as($prefix, $name) {
	global $T_DIR;
	$path = $T_DIR . '/panelcfg-' . $name . '.php';
	file_put_contents($path, '<?php if (!defined("GV_BOOT")) { exit; } return ' . var_export(t_cfg(array('prefix' => $prefix),
		array('log_dir' => $T_DIR . '/pnl-' . $name)), true) . ';');
	putenv('GV_CONFIG=' . $path);
	gp_redis(true);
}
gv_redis_cmd($cx, array('FLUSHALL'));
t_panel_as('shop1:', 'a');
t_ok('panel: an override is written under the prefix', gp_override_set('allow', 'ident-one', 3600)
	&& gv_redis_cmd($cx, array('GET', 'shop1:gv:allow:ident-one')) === '1');
t_panel_as('shop2:', 'b');
gp_override_set('deny', 'ident-two', 3600);
$list2 = gp_overrides_list();
t_ok('panel: the listing shows only its own install, prefix stripped',
	count($list2) === 1 && $list2[0]['identity'] === 'ident-two' && $list2[0]['kind'] === 'deny');
t_panel_as('shop1:', 'a');
$list1 = gp_overrides_list();
t_ok('panel: the other install lists its own override', count($list1) === 1 && $list1[0]['identity'] === 'ident-one');
t_ok('panel: ctl-style clear removes only its own', gp_override_clear('ident-one')
	&& gv_redis_cmd($cx, array('GET', 'shop1:gv:allow:ident-one')) === null
	&& gv_redis_cmd($cx, array('GET', 'shop2:gv:deny:ident-two')) === '1');
$job = gp_job_enqueue('snapshot', array(), 'tester');
t_ok('panel: a job lands in the prefixed queue', $job['ok']
	&& (int)gv_redis_cmd($cx, array('LLEN', 'shop1:gp:jobs')) === 1 && gv_redis_cmd($cx, array('LLEN', 'gp:jobs')) === 0);
t_ok('panel: the job list shows it', count(gp_job_list()) === 1);
t_panel_as('shop2:', 'b');
t_ok('panel: the other install sees no jobs', count(gp_job_list()) === 0);
t_ok('panel: login attempts are counted under the prefix', gp_attempts_bump('bucketx', 300) === 1
	&& gv_redis_cmd($cx, array('GET', 'shop2:gp:login:bucketx')) === '1' && gp_attempts_get('bucketx', 300) === 1);
t_panel_as('shop1:', 'a');
t_ok('panel: ...and not visible to the other install', gp_attempts_get('bucketx', 300) === 0);
putenv('GV_CONFIG');
gp_redis(true);

// Login limiter must stay fail-closed to the file when Redis is down.
t_panel_as('', 'down');
$dead = $T_DIR . '/panelcfg-dead.php';
file_put_contents($dead, '<?php if (!defined("GV_BOOT")) { exit; } return ' . var_export(t_cfg(array('port' => 63998),
	array('log_dir' => $T_DIR . '/pnl-dead')), true) . ';');
putenv('GV_CONFIG=' . $dead);
gp_redis(true);
$bk = 'down-' . bin2hex(random_bytes(3));
$counts = array();
for ($i = 0; $i < GP_LOGIN_MAX_ATTEMPTS + 1; $i++) { $counts[] = gp_attempts_bump($bk, GP_LOGIN_WINDOW); }
t_ok('login limiter with Redis down still counts (file fallback)', $counts[0] === 1 && end($counts) === GP_LOGIN_MAX_ATTEMPTS + 1);
@unlink(gp_attempts_file($bk));
putenv('GV_CONFIG');
gp_redis(true);

// --------------------------------------------------------------------------
t_section('Source audit: every key goes through the helpers');

$offenders = array();
$skip = array(realpath(__DIR__ . '/../guard/redis.php'), realpath(__DIR__ . '/../analyzer/redis_io.py'));
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__ . '/..', FilesystemIterator::SKIP_DOTS));
foreach ($it as $f) {
	$path = $f->getPathname();
	if (!preg_match('/\.(php|py|sh)$/', $path)) { continue; }
	if (preg_match('#/(\.git|\.venv|docs|node_modules)/#', $path)) { continue; }
	if (preg_match('#(selftest|guard-test\.sh|verify-e2e|redis-selftest)#', basename($path))) { continue; }
	if (in_array(realpath($path), $skip, true)) { continue; }
	foreach (file($path) as $n => $line) {
		if (preg_match('/[\'"]g[vp]:/', $line)) { $offenders[] = substr($path, strlen(__DIR__) - 7) . ':' . ($n + 1); }
	}
}
t_ok('no raw gv:/gp: key literal outside the key helpers and tests' . ($offenders ? ' (' . implode(', ', $offenders) . ')' : ''), !$offenders);
$conns = array();
foreach (array('guard', 'panel') as $dir) {
	foreach (glob(__DIR__ . "/../$dir/*.php") as $path) {
		if (basename($path) === 'redis.php') { continue; }
		if (preg_match('/stream_socket_client|pfsockopen|fsockopen|new Redis\b/', file_get_contents($path))) { $conns[] = basename($path); }
	}
}
t_ok('nothing opens Redis except the shared connect function' . ($conns ? ' (' . implode(', ', $conns) . ')' : ''), !$conns);

echo "\nPASS $GV_PASS  FAIL $GV_FAIL  SKIP $GV_SKIP\n";
exit($GV_FAIL === 0 ? 0 : 1);
