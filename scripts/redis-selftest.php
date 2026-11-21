<?php
// Bot Guard Redis self-test. Run: php scripts/redis-selftest.php
// Spawns its own throwaway redis-server instances (no auth, requirepass, ACL,
// unix socket) and exercises the guard's Redis contract against each:
// round trips per path, fail-fast, circuit breaker, error log, authentication,
// db selection and key prefix isolation.
// Exit code 0 when every non-SKIP assertion passes, 1 otherwise.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
if (PHP_VERSION_ID < 80000) { fwrite(STDERR, 'Bot Guard requires PHP 8.0 or newer (found ' . PHP_VERSION . ").\n"); exit(1); }

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
	foreach ((array)@glob($T_DIR . '/redis-*.pid') as $pf) { $T_PIDS[] = (int)trim((string)@file_get_contents($pf)); }
	foreach ($T_PIDS as $pid) { if ($pid > 1) { @posix_kill($pid, 15); } }
	usleep(200000);
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
	// GV_REDIS_BIN selects the server under test (CI runs the suite against several
	// Redis major versions).
	$bin = (string)getenv('GV_REDIS_BIN');
	if ($bin === '') { $bin = trim((string)@shell_exec('command -v redis-server 2>/dev/null')); }
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
	// E_ALL with display_errors on: any notice or deprecation the guard raises on
	// the way to the host application would be printed into its response, and
	// shows up here as guard output (bytes > 0).
	$cmd = escapeshellarg(PHP_BINARY) . ' -d display_errors=1 -d error_reporting=-1 -d html_errors=0 '
		. escapeshellarg(__DIR__ . '/request-probe.php');
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
t_section('No guard output on any allow path (E_ALL, display_errors=1)');

gv_redis_cmd($cx, array('FLUSHALL'));
$tokq = gv_tok_make('rt-secret');
$devq = gv_tok_check($tokq, 'rt-secret', 604800);
$paths = array();
$paths['allow'] = t_probe(t_cfg(), t_nav(), array('_gv' => $tokq));
$ex = t_nav(); $ex['REQUEST_URI'] = '/exempt-me/x';
$paths['exempt'] = t_probe(t_cfg(array(), array('exempt_paths' => array('/exempt-me'))), $ex);
gv_redis_cmd($cx, array('SET', 'gv:botok:198.51.100.9', '1', 'EX', '60'));
$gb = t_nav(); $gb['HTTP_USER_AGENT'] = 'Googlebot/2.1';
$paths['allow_bot'] = t_probe(t_cfg(), $gb);
gv_redis_cmd($cx, array('DEL', 'gv:botok:198.51.100.9'));
gv_redis_cmd($cx, array('SET', 'gv:allow:' . $devq, '1', 'EX', '60'));
$paths['allow_override'] = t_probe(t_cfg(), t_nav(), array('_gv' => $tokq));
gv_redis_cmd($cx, array('DEL', 'gv:allow:' . $devq));
$paths['monitor allow (challenge would fire)'] = t_probe(t_cfg(array(), array('enforce' => array('block' => false, 'challenge' => false, 'ratelimit' => false))), t_nav());
$paths['Redis down'] = t_probe(t_cfg(array('port' => 63996), array('log_dir' => $T_DIR . '/q-down')), t_nav(), array('_gv' => $tokq));
$paths['config unreadable (fail-open)'] = t_probe(array('redis' => 'not-an-array', 'secret' => 'x', 'log_dir' => $T_DIR . '/q-bad'), t_nav());
foreach ($paths as $label => $res) {
	t_ok("zero bytes of guard output: $label", $res['bytes'] === 0 && $res['code'] === false);
}

t_section('Swallowed exceptions are logged (config that does not parse)');

$defdir = realpath(__DIR__ . '/..') . '/logs';
$errlog = $defdir . '/guard-errors.log';
$had_dir = is_dir($defdir);
$old_err = is_file($errlog) ? file_get_contents($errlog) : null;
foreach ((array)glob($defdir . '/.err-guard_exception') as $m) { @unlink($m); }
@unlink($errlog);
$badcfg = $T_DIR . '/syntax-error.php';
file_put_contents($badcfg, "<?php if (!defined('GV_BOOT')) { exit; }\nreturn array('secret' => ;\n");
$sock = @stream_socket_server('tcp://127.0.0.1:0', $en, $es);
$sn = stream_socket_get_name($sock, false);
$sport = (int)substr($sn, strrpos($sn, ':') + 1);
fclose($sock);
$srv = proc_open(escapeshellarg(PHP_BINARY) . ' -S 127.0.0.1:' . $sport . ' ' . escapeshellarg(__DIR__ . '/dev-router.php'),
	array(1 => array('file', '/dev/null', 'w'), 2 => array('file', '/dev/null', 'w')), $sp, null, array('GV_DEV_CONFIG' => $badcfg));
usleep(700000);
$resp = @file_get_contents('http://127.0.0.1:' . $sport . '/', false, stream_context_create(array('http' => array('ignore_errors' => true))));
proc_terminate($srv);
t_ok('a config that does not parse still serves the site (fail-open)', is_string($resp) && strpos($resp, 'OK') !== false);
$logged = is_file($errlog) ? file_get_contents($errlog) : '';
t_ok('...and the exception is recorded in guard-errors.log', strpos($logged, 'guard_exception') !== false && strpos($logged, 'ParseError') !== false);
@unlink($errlog);
foreach ((array)glob($defdir . '/.err-guard_exception') as $m) { @unlink($m); }
if ($old_err !== null) { file_put_contents($errlog, $old_err); }
if (!$had_dir) { @rmdir($defdir); }

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
// One read that timed out may be a pause, not an outage: it leaves a strike and
// the breaker arms on the second one.
t_ok('black hole: one timeout leaves a strike, the breaker is not armed yet',
	is_file($T_DIR . '/hole/.redis-slow') && !is_file($T_DIR . '/hole/.redis-down'));
$p1b = t_probe($cfgH, t_nav(), array('_gv' => $tok));
t_ok('black hole: the second timeout arms the breaker', is_file($T_DIR . '/hole/.redis-down') && $p1b['bytes'] === 0);
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
	if (preg_match('#(selftest|guard-test\.sh|identity-check|verify-e2e|redis-selftest|rules-e2e)#', basename($path))) { continue; }
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


// ==========================================================================
// Work item 4: the handshake (single use, bound, proof of work, metered)
// ==========================================================================

function t_solve($nonce) {
	$p = gv_nonce_parse($nonce);
	for ($c = 0; $c < 50000000; $c++) { if (gv_pow_ok($nonce, (string)$c, $p[1])) { return (string)$c; } }
	return '0';
}
function t_post(array $cfg, $nonce, $counter, $ua, $ip = '198.51.100.9') {
	return t_probe($cfg, array('REQUEST_METHOD' => 'POST', 'HTTP_USER_AGENT' => $ua, 'HTTP_X_GV' => $nonce,
		'HTTP_X_GV_P' => (string)$counter, 'REMOTE_ADDR' => $ip));
}
function t_rows(array $cfg) {
	$out = array();
	foreach ((array)glob($cfg['log_dir'] . '/guard-*.jsonl') as $f) {
		foreach (file($f, FILE_IGNORE_NEW_LINES) as $l) { $out[] = json_decode($l, true); }
	}
	return $out;
}
$UA = 'Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0 Safari/537.36';

t_section('Handshake: single use, binding, proof of work');

gv_redis_cmd($cx, array('FLUSHALL'));
$cfgH = t_cfg(array(), array('log_dir' => t_mkdir_log('hs1'), 'challenge' => array('pow_bits' => 10),
	'limits' => array('mint' => 100000, 'ip' => 100000, 'ip_ua' => 100000)));
$n = gv_nonce_make('rt-secret', $UA, '198.51.100.9', 10);
$c = t_solve($n);
$codes = array();
for ($i = 0; $i < 300; $i++) { $codes[] = t_post($cfgH, $n, $c, $UA)['code']; }
$rows = t_rows($cfgH);
$acts = array_count_values(array_column($rows, 'act'));
t_ok('one nonce replayed 300 times yields exactly 1 token',
	count(array_keys($codes, 204, true)) === 1 && ($acts['token_issued'] ?? 0) === 1);
t_ok('...and 299 logged nonce_replay rejections (403)', ($acts['nonce_replay'] ?? 0) === 299 && count(array_keys($codes, 403, true)) === 299);

$n2 = gv_nonce_make('rt-secret', $UA, '198.51.100.9', 10);
$c2 = t_solve($n2);
$p = t_post($cfgH, $n2, $c2, 'curl/8.0');
t_ok('a nonce issued to UA A is rejected from UA B', $p['code'] === 403 && t_lastrow($cfgH)['act'] === 'nonce_bad');
$p = t_post($cfgH, $n2, $c2, $UA, '203.0.113.77');
t_ok('a nonce issued to IP A is rejected from IP B', $p['code'] === 403 && t_lastrow($cfgH)['act'] === 'nonce_bad');
$p = t_post($cfgH, $n2, $c2, $UA);
t_ok('the rejected attempts did not burn the nonce for its rightful owner', $p['code'] === 204);

$n3 = gv_nonce_make('rt-secret', $UA, '198.51.100.9', 10);
$p = t_post($cfgH, $n3, '', $UA);
t_ok('no proof of work: rejected (pow_bad)', $p['code'] === 403 && t_lastrow($cfgH)['act'] === 'pow_bad');
$p = t_post($cfgH, $n3, '0123', $UA);
t_ok('a nonce that failed its proof is burned: a later correct proof cannot reuse it',
	$p['code'] === 403 && t_lastrow($cfgH)['act'] === 'nonce_replay');
$n4 = gv_nonce_make('rt-secret', $UA, '198.51.100.9', 10);
$wrong = '1';
while (gv_pow_ok($n4, $wrong, 10)) { $wrong = (string)((int)$wrong + 1); }
t_ok('a wrong counter is rejected', t_post($cfgH, $n4, $wrong, $UA)['code'] === 403);

$cfgB = t_cfg(array(), array('log_dir' => t_mkdir_log('hs-bind'), 'challenge' => array('pow_bits' => 0, 'bind_ip' => false)));
$nb = gv_nonce_make('rt-secret', $UA, '', 0);
t_ok('bind_ip = false: the same nonce works from another address', t_post($cfgB, $nb, '', $UA, '203.0.113.200')['code'] === 204);

// Monitor mode: nothing new may block, whatever is wrong with the request.
$cfgM = t_cfg(array(), array('log_dir' => t_mkdir_log('hs-mon'), 'challenge' => array('pow_bits' => 10),
	'enforce' => array('block' => false, 'challenge' => false, 'ratelimit' => false)));
$nm = gv_nonce_make('rt-secret', $UA, '198.51.100.9', 10);
$p1 = t_post($cfgM, $nm, '', $UA);
$r1 = t_lastrow($cfgM);
$p2 = t_post($cfgM, $nm, '', $UA);
$r2 = t_lastrow($cfgM);
t_ok('monitor mode: a missing proof is logged (pow_bad, sh=1) but the token is still issued',
	$p1['code'] === 204 && $r1['act'] === 'pow_bad' && $r1['sh'] === 1);
t_ok('monitor mode: a replay is logged (nonce_replay, sh=1) but not refused',
	$p2['code'] === 204 && $r2['act'] === 'nonce_replay' && $r2['sh'] === 1);
$cfgC = t_cfg(array(), array('log_dir' => t_mkdir_log('hs-chg'), 'secret' => 'CHANGE_ME', 'challenge' => array('pow_bits' => 10)));
$nc = gv_nonce_make('CHANGE_ME', $UA, '198.51.100.9', 10);
$p = t_post($cfgC, $nc, '', $UA);
t_ok('secret = CHANGE_ME forces monitor mode for the new checks too', $p['code'] === 204 && t_lastrow($cfgC)['sh'] === 1);

t_section('Handshake: minting is metered');

gv_redis_cmd($cx, array('FLUSHALL'));
$cfgL = t_cfg(array(), array('log_dir' => t_mkdir_log('mint'), 'challenge' => array('pow_bits' => 0),
	'limits' => array('mint' => 5, 'ip' => 100000, 'ip_ua' => 100000)));
$codes = array();
for ($i = 0; $i < 8; $i++) { $codes[] = t_post($cfgL, gv_nonce_make('rt-secret', $UA, '198.51.100.9', 0), '', $UA)['code']; }
t_ok('more than limits.mint mints per window are refused with 429 when enforce.ratelimit is on',
	array_slice($codes, 0, 5) === array(204, 204, 204, 204, 204) && array_slice($codes, 5) === array(429, 429, 429));
$last = t_lastrow($cfgL);
t_ok('...logged as mint_limited with sh=0', $last['act'] === 'mint_limited' && $last['sh'] === 0);
t_ok('another IP is unaffected', t_post($cfgL, gv_nonce_make('rt-secret', $UA, '198.51.100.55', 0), '', $UA, '198.51.100.55')['code'] === 204);
gv_redis_cmd($cx, array('SET', 'gv:allow:198.51.100.9', '1', 'EX', '60'));
t_ok('an allow-listed IP is never refused a token', t_post($cfgL, gv_nonce_make('rt-secret', $UA, '198.51.100.9', 0), '', $UA)['code'] === 204);
gv_redis_cmd($cx, array('DEL', 'gv:allow:198.51.100.9'));
t_ok('handshake POSTs bump the ordinary ip and ip_ua counters',
	(int)gv_redis_cmd($cx, array('GET', 'gv:ri:198.51.100.9')) >= 9);

gv_redis_cmd($cx, array('FLUSHALL'));
$cfgS = t_cfg(array(), array('log_dir' => t_mkdir_log('mint-shadow'), 'challenge' => array('pow_bits' => 0),
	'enforce' => array('block' => true, 'challenge' => true, 'ratelimit' => false),
	'limits' => array('mint' => 3, 'ip' => 100000, 'ip_ua' => 100000)));
$codes = array();
for ($i = 0; $i < 6; $i++) { $codes[] = t_post($cfgS, gv_nonce_make('rt-secret', $UA, '198.51.100.9', 0), '', $UA)['code']; }
$rows = t_rows($cfgS);
t_ok('with enforce.ratelimit off the mint limit only logs (sh=1) and every token is still issued',
	$codes === array(204, 204, 204, 204, 204, 204) && end($rows)['act'] === 'mint_limited' && end($rows)['sh'] === 1);

// Only an issued token counts toward limits.mint.
gv_redis_cmd($cx, array('FLUSHALL'));
$cfgM2 = t_cfg(array(), array('log_dir' => t_mkdir_log('mint-pow'), 'challenge' => array('pow_bits' => 10),
	'limits' => array('mint' => 5, 'ip' => 100000, 'ip_ua' => 100000)));
$nm2 = gv_nonce_make('rt-secret', $UA, '198.51.100.9', 10);
for ($i = 0; $i < 100; $i++) { t_post($cfgM2, $nm2, '', $UA); }
t_ok('100 POSTs of one nonce without a proof leave the mint counter at 0',
	(int)gv_redis_cmd($cx, array('GET', 'gv:mint:198.51.100.9')) === 0);
$nh = gv_nonce_make('rt-secret', $UA, '198.51.100.9', 10);
t_ok('...so the next honest visitor on that IP still gets a token', t_post($cfgM2, $nh, t_solve($nh), $UA)['code'] === 204);
t_ok('...and counts exactly once', (int)gv_redis_cmd($cx, array('GET', 'gv:mint:198.51.100.9')) === 1);
$nr = gv_nonce_make('rt-secret', $UA, '198.51.100.9', 10);
$cr = t_solve($nr);
t_post($cfgM2, $nr, $cr, $UA);
for ($i = 0; $i < 50; $i++) { t_post($cfgM2, $nr, $cr, $UA); }
t_ok('50 replays of an issued nonce do not add to the mint counter (2 tokens issued)',
	(int)gv_redis_cmd($cx, array('GET', 'gv:mint:198.51.100.9')) === 2);
$hit = 0;
for ($i = 0; $i < 6; $i++) { $nx = gv_nonce_make('rt-secret', $UA, '198.51.100.9', 10); $hit = t_post($cfgM2, $nx, t_solve($nx), $UA)['code']; }
t_ok('refusals at the limit are given back: the counter stays at the limit', $hit === 429
	&& (int)gv_redis_cmd($cx, array('GET', 'gv:mint:198.51.100.9')) === 5);

t_section('Handshake: Redis down');

$cfgD2 = t_cfg(array('port' => 63997), array('log_dir' => t_mkdir_log('hs-down'), 'challenge' => array('pow_bits' => 10)));
$nd = gv_nonce_make('rt-secret', $UA, '198.51.100.9', 10);
$cd = t_solve($nd);
$p1 = t_post($cfgD2, $nd, $cd, $UA);
$row = t_lastrow($cfgD2);
t_ok('Redis down: a human still passes the challenge (204, rd=1)', $p1['code'] === 204 && $row['rd'] === 1 && $row['act'] === 'token_issued');
t_ok('Redis down: proof of work and binding still apply',
	t_post($cfgD2, gv_nonce_make('rt-secret', $UA, '198.51.100.9', 10), '', $UA)['code'] === 403
	&& t_post($cfgD2, $nd, $cd, 'curl/8')['code'] === 403);
$hole2 = @stream_socket_server('tcp://127.0.0.1:0', $en, $es);
$hn2 = stream_socket_get_name($hole2, false);
$cfgH2 = t_cfg(array('port' => (int)substr($hn2, strrpos($hn2, ':') + 1)), array('log_dir' => t_mkdir_log('hs-hole'), 'challenge' => array('pow_bits' => 0)));
$ph = t_post($cfgH2, gv_nonce_make('rt-secret', $UA, '198.51.100.9', 0), '', $UA);
t_ok('Redis stalled: the handshake pays one timeout, then succeeds', $ph['code'] === 204 && $ph['ms'] < 400);
fclose($hole2);

t_section('Handshake: round trips');

gv_redis_cmd($cx, array('FLUSHALL'));
$cfgR = t_cfg(array(), array('log_dir' => t_mkdir_log('hs-rt'), 'challenge' => array('pow_bits' => 0)));
$pr = t_post($cfgR, gv_nonce_make('rt-secret', $UA, '198.51.100.9', 0), '', $UA);
t_ok('a handshake costs one round trip (' . $pr['rt'] . ')', $pr['rt'] === 1 && $pr['code'] === 204);

// --------------------------------------------------------------------------
t_section('Slow-scraper defences: gate, long-window budgets, preview budget');

gv_redis_cmd($cx, array('FLUSHALL'));
$cfgG = t_cfg(array(), array('log_dir' => t_mkdir_log('gate'),
	'limits' => array('device_hour' => 3, 'device_day' => 5, 'preview' => 2),
	'known_bots' => array('googlebot', 'adsbot-google'), 'preview_bots' => array('telegrambot')));
$bare = array('HTTP_USER_AGENT' => t_nav()['HTTP_USER_AGENT'], 'HTTP_ACCEPT' => '*/*', 'HTTP_HOST' => 'x',
	'HTTP_ACCEPT_ENCODING' => 'gzip', 'HTTP_CONNECTION' => 'keep-alive', 'HTTP_ACCEPT_LANGUAGE' => 'en',
	'HTTP_SEC_FETCH_MODE' => 'cors');
$p = t_probe($cfgG, $bare);
$row = t_lastrow($cfgG);
t_ok('a token-less GET with Accept: */* is challenged (503), not served',
	$p['code'] === 503 && $row['act'] === 'challenge' && $row['nav'] === 0 && $row['gate'] === 1);
$xhr = $bare; $xhr['HTTP_X_REQUESTED_WITH'] = 'XMLHttpRequest'; $xhr['HTTP_ACCEPT'] = 'application/json';
$p = t_probe($cfgG, $xhr);
t_ok('claiming to be XHR does not skip the challenge', $p['code'] === 503);
$noacc = $bare; unset($noacc['HTTP_ACCEPT']);
$p = t_probe($cfgG, $noacc);
t_ok('sending no Accept header does not skip the challenge', $p['code'] === 503);
$p = t_probe($cfgG, array_merge($bare, array('REQUEST_METHOD' => 'POST')));
$row = t_lastrow($cfgG);
t_ok('a token-less POST is served untouched and logged as a shadow challenge',
	$p['bytes'] === 0 && $row['act'] === 'challenge' && $row['sh'] === 1 && $row['gate'] === 1);
$cfgGP = $cfgG; $cfgGP['challenge'] = array('gate_post' => true); $cfgGP['log_dir'] = t_mkdir_log('gate-post');
$p = t_probe($cfgGP, array_merge($bare, array('REQUEST_METHOD' => 'POST')));
t_ok('with challenge.gate_post a token-less POST is challenged', $p['code'] === 503);
$p = t_probe($cfgGP, array_merge($bare, array('REQUEST_METHOD' => 'POST')), array('_gv' => gv_tok_make('rt-secret')));
t_ok('...and a POST carrying a token is not', $p['bytes'] === 0);
$p = t_probe($cfgG, array_merge($bare, array('REQUEST_METHOD' => 'HEAD')));
t_ok('a token-less HEAD is challenged like a GET', $p['code'] === 503);
$p = t_probe($cfgG, array_merge($bare, array('REQUEST_METHOD' => 'OPTIONS')));
$row = t_lastrow($cfgG);
t_ok('OPTIONS (CORS preflight) is never challenged', $p['bytes'] === 0 && $row['act'] === 'allow' && $row['gate'] === 0);
$tokG = gv_tok_make('rt-secret');
$p = t_probe($cfgG, $xhr, array('_gv' => $tokG));
$row = t_lastrow($cfgG);
t_ok('a real browser XHR carries the token and is allowed untouched', $p['bytes'] === 0 && $row['act'] === 'allow');
$cfgT = t_cfg(array(), array('log_dir' => t_mkdir_log('gate-old'), 'challenge' => array('trust_headers' => true)));
$p = t_probe($cfgT, $bare);
$row = t_lastrow($cfgT);
t_ok('trust_headers = true is the old behaviour (rollback switch)',
	$p['bytes'] === 0 && $row['act'] === 'allow' && $row['gate'] === 0);
$cfgM = t_cfg(array(), array('log_dir' => t_mkdir_log('gate-mon'),
	'enforce' => array('block' => false, 'challenge' => false, 'ratelimit' => false)));
$p = t_probe($cfgM, $bare);
$row = t_lastrow($cfgM);
t_ok('monitor mode only records the would-be challenge (sh=1, zero output)',
	$p['bytes'] === 0 && $row['act'] === 'challenge' && $row['sh'] === 1);

// Long-window budgets: one token, a slow client, addresses changing every request.
gv_redis_cmd($cx, array('FLUSHALL'));
$tokS = gv_tok_make('rt-secret');
$devS = gv_tok_check($tokS, 'rt-secret', 604800);
$acts = array(); $rts = array();
for ($i = 1; $i <= 6; $i++) {
	$srv = t_nav(); $srv['REMOTE_ADDR'] = '203.0.113.' . $i;      // a new address every time
	$p = t_probe($cfgG, $srv, array('_gv' => $tokS));
	$row = t_lastrow($cfgG);
	$acts[] = $row['act']; $rts[] = $p['rt'];
}
t_ok('the hourly device budget follows the token across changing addresses (' . implode(',', $acts) . ')',
	$acts === array('allow', 'allow', 'allow', '429', '429', '429'));
t_ok('the row names the budget and carries both counters',
	in_array('DEV_HOUR', $row['rs'], true) && in_array('DEV_DAY', $row['rs'], true)
	&& $row['cdh'] === 6 && $row['cdd'] === 6 && $row['ci'] === 1);
t_ok('the budgets ride in the existing counter round trip (max ' . max($rts) . ')', max($rts) <= 2);
$ttl_h = gv_redis_cmd($cx, array('TTL', 'gv:rdh:' . $devS));
$ttl_d = gv_redis_cmd($cx, array('TTL', 'gv:rdd:' . $devS));
t_ok('the budget counters expire after an hour and a day', $ttl_h > 3500 && $ttl_h <= 3600 && $ttl_d > 86300 && $ttl_d <= 86400);
gv_redis_cmd($cx, array('SET', 'gv:rdh:' . $devS, '0'));
gv_redis_cmd($cx, array('EXPIRE', 'gv:rdh:' . $devS, '3600'));
$p = t_probe($cfgG, t_nav(), array('_gv' => $tokS));
$row = t_lastrow($cfgG);
t_ok('the daily budget holds on its own after the hour resets',
	$row['act'] === '429' && $row['rs'] === array('DEV_DAY') && $row['cdh'] === 1);
$cfgGM = $cfgG; $cfgGM['enforce']['ratelimit'] = false; $cfgGM['log_dir'] = t_mkdir_log('gate-shadow');
$p = t_probe($cfgGM, t_nav(), array('_gv' => $tokS));
$row = t_lastrow($cfgGM);
t_ok('with enforce.ratelimit off an exhausted budget is shadow only', $p['bytes'] === 0 && $row['act'] === '429' && $row['sh'] === 1);
gv_redis_cmd($cx, array('SET', 'gv:allow:' . $devS, '1', 'EX', '60'));
$p = t_probe($cfgG, t_nav(), array('_gv' => $tokS));
$row = t_lastrow($cfgG);
t_ok('an operator allow rescues a device that is over its budget', $p['bytes'] === 0 && $row['act'] === 'allow_override');

// Preview fetchers: one small site-wide budget per name, however many addresses.
gv_redis_cmd($cx, array('FLUSHALL'));
$acts = array();
for ($i = 1; $i <= 4; $i++) {
	$srv = array('HTTP_USER_AGENT' => 'TelegramBot (like TwitterBot)', 'HTTP_ACCEPT' => 'text/html',
		'HTTP_HOST' => 'x', 'REMOTE_ADDR' => '203.0.113.' . (50 + $i));
	$p = t_probe($cfgG, $srv);
	$row = t_lastrow($cfgG);
	$acts[] = $row['act'];
}
t_ok('a link preview passes inside the budget, then is treated like anyone else (' . implode(',', $acts) . ')',
	$acts === array('allow_preview', 'allow_preview', 'challenge', 'challenge'));
t_ok('the preview budget is one counter for the name, not one per address',
	gv_redis_cmd($cx, array('GET', 'gv:rp:telegrambot')) === '4');
gv_redis_cmd($cx, array('DEL', 'gv:rp:telegrambot'));
gv_redis_cmd($cx, array('SET', 'gv:deny:203.0.113.99', '1', 'EX', '60'));
$p = t_probe($cfgG, array('HTTP_USER_AGENT' => 'TelegramBot (like TwitterBot)', 'HTTP_ACCEPT' => 'text/html',
	'HTTP_HOST' => 'x', 'REMOTE_ADDR' => '203.0.113.99'));
$row = t_lastrow($cfgG);
t_ok('an operator deny on the address beats the preview pass', $p['code'] === 403 && $row['act'] === '403' && $row['ovr'] === 'deny');
$cfgPD = t_cfg(array('port' => 63997), array('log_dir' => t_mkdir_log('prev-down'), 'preview_bots' => array('telegrambot')));
$p = t_probe($cfgPD, array('HTTP_USER_AGENT' => 'TelegramBot (like TwitterBot)', 'HTTP_ACCEPT' => 'text/html', 'HTTP_HOST' => 'x'));
$row = t_lastrow($cfgPD);
t_ok('Redis down: no preview pass, the stateless challenge still applies', $p['code'] === 503 && $row['act'] === 'challenge' && $row['rd'] === 1);
$ads = array('HTTP_USER_AGENT' => 'AdsBot-Google (+http://www.google.com/adsbot.html)', 'HTTP_ACCEPT' => 'text/html', 'HTTP_HOST' => 'x');
$p = t_probe($cfgG, $ads);
$row = t_lastrow($cfgG);
t_ok('AdsBot-Google takes the known-bot pass under its own name', $p['bytes'] === 0 && $row['act'] === 'allow_bot' && $row['bot'] === 'adsbot-google');
gv_redis_cmd($cx, array('SET', 'gv:botbad:198.51.100.9', '1', 'EX', '60'));
$p = t_probe($cfgG, $ads);
$row = t_lastrow($cfgG);
t_ok('a forged AdsBot-Google (failed reverse DNS) loses the pass', $row['act'] !== 'allow_bot' && $row['botv'] === 'bad' && $p['bytes'] > 0);
gv_redis_cmd($cx, array('FLUSHALL'));

// --------------------------------------------------------------------------
t_section('Review hardening: shadowed rules, exemptions, networks, bot pass, cookies');

// A rule in shadow must not cancel the rules below it.
gv_redis_cmd($cx, array('FLUSHALL'));
$cfgS = t_cfg(array(), array('log_dir' => t_mkdir_log('shadow-rl'), 'limits' => array('ip_ua' => 3),
	'enforce' => array('block' => true, 'challenge' => true, 'ratelimit' => false)));
$codes = array();
for ($i = 0; $i < 6; $i++) { $p = t_probe($cfgS, t_nav()); $codes[] = $p['code']; }
$row = t_lastrow($cfgS);
t_ok('rate limit in shadow: a token-less client over the limit is STILL challenged (' . implode(',', $codes) . ')',
	$codes === array(503, 503, 503, 503, 503, 503));
t_ok('...and the row says what was served and what was shadowed', $row['act'] === 'challenge' && $row['sh'] === 0 && in_array('SH_429', $row['rs'], true));
$cfgB = t_cfg(array(), array('log_dir' => t_mkdir_log('shadow-bl'),
	'enforce' => array('block' => false, 'challenge' => true, 'ratelimit' => true)));
$p = t_probe($cfgB, array('HTTP_ACCEPT' => 'text/html', 'HTTP_HOST' => 'x'));        // empty UA: score >= 60
$row = t_lastrow($cfgB);
t_ok('block in shadow: the worst-scoring client is still challenged', $p['code'] === 503 && $row['act'] === 'challenge' && in_array('SH_403', $row['rs'], true));
$cfgM2 = t_cfg(array(), array('log_dir' => t_mkdir_log('shadow-all'),
	'enforce' => array('block' => false, 'challenge' => false, 'ratelimit' => false)));
$p = t_probe($cfgM2, array('HTTP_ACCEPT' => 'text/html', 'HTTP_HOST' => 'x'));
$row = t_lastrow($cfgM2);
t_ok('everything in shadow: zero output, the highest would-be action logged', $p['bytes'] === 0 && $row['act'] === '403' && $row['sh'] === 1);

// Exemptions a client cannot award itself.
$cfgE = t_cfg(array(), array('log_dir' => t_mkdir_log('exempt2'), 'exempt_paths' => array('/admin/'),
	'exempt_params' => array('route' => array('payment/'))));
$get = function ($cfg, $uri, $qs, $extra = array()) {
	parse_str($qs, $g);
	return t_probe($cfg, array_merge(t_nav(), array('REQUEST_URI' => $uri . ($qs !== '' ? '?' . $qs : ''), 'QUERY_STRING' => $qs), $extra));
};
$p = $get($cfgE, '/index.php', 'route=payment/zarinpal/callback');
$probe_has_get = (t_lastrow($cfgE)['act'] === 'exempt');
if ($probe_has_get) {
	t_ok('a callback on the front controller is exempt', $p['bytes'] === 0);
	$p = $get($cfgE, '/product/ps5-slim', 'route=payment/x');
	t_ok('the same parameter appended to a product URL is challenged', $p['code'] === 503 && t_lastrow($cfgE)['act'] === 'challenge');
} else {
	t_skip('exempt_params end to end', 'the probe does not populate $_GET');
}
$p = $get($cfgE, '/admin/../product/x', '');
t_ok('a dot-segment path under an exempt prefix is challenged', $p['code'] === 503);
$p = $get($cfgE, '/admin/index.php', '');
t_ok('the real exempt path still is exempt', $p['bytes'] === 0 && t_lastrow($cfgE)['act'] === 'exempt');

// IPv6: one /64, one counter.
gv_redis_cmd($cx, array('FLUSHALL'));
$cfg6 = t_cfg(array(), array('log_dir' => t_mkdir_log('v6'), 'limits' => array('ip' => 3)));
$tok6 = gv_tok_make('rt-secret');
$acts = array();
for ($i = 1; $i <= 5; $i++) {
	$srv = t_nav(); $srv['REMOTE_ADDR'] = '2001:db8:aa:bb::' . dechex($i * 7919);
	$srv['HTTP_USER_AGENT'] .= ' v' . $i;                       // a new UA too: only the network counter is shared
	t_probe($cfg6, $srv, array('_gv' => $tok6));
	$acts[] = t_lastrow($cfg6)['act'];
}
t_ok('addresses of one IPv6 /64 share the per-IP limit (' . implode(',', $acts) . ')',
	$acts === array('allow', 'allow', 'allow', '429', '429'));
t_ok('the counter key is the /64, and the row keeps the full address',
	gv_redis_cmd($cx, array('GET', 'gv:ri:2001:db8:aa:bb::/64')) === '5' && strpos(t_lastrow($cfg6)['ip'], '2001:db8:aa:bb::') === 0);
$srv = t_nav(); $srv['REMOTE_ADDR'] = '2001:db8:aa:cc::1';
t_probe($cfg6, $srv, array('_gv' => $tok6));
t_ok('a different /64 has its own counter', t_lastrow($cfg6)['ci'] === 1);
gv_redis_cmd($cx, array('SET', 'gv:deny:203.0.113.77', '1', 'EX', '60'));
$srv = t_nav(); $srv['REMOTE_ADDR'] = '::ffff:203.0.113.77';
$p = t_probe($cfg6, $srv, array('_gv' => $tok6));
t_ok('an IPv4-mapped address meets the override set on the IPv4 address', $p['code'] === 403 && t_lastrow($cfg6)['ip'] === '203.0.113.77');

// Bot pass: an operator deny wins, and unverified claims share one budget.
gv_redis_cmd($cx, array('FLUSHALL'));
$cfgK = t_cfg(array(), array('log_dir' => t_mkdir_log('botpass'), 'known_bots' => array('googlebot'),
	'limits' => array('bot_unverified' => 3)));
$gb = function ($ip) { return array('HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
	'HTTP_ACCEPT' => 'text/html', 'HTTP_HOST' => 'x', 'REMOTE_ADDR' => $ip); };
$acts = array();
for ($i = 1; $i <= 5; $i++) { t_probe($cfgK, $gb('198.51.100.' . $i)); $acts[] = t_lastrow($cfgK)['act']; }
t_ok('unverified Googlebot claims from changing addresses share ONE budget (' . implode(',', $acts) . ')',
	$acts === array('allow_bot', 'allow_bot', 'allow_bot', 'challenge', 'challenge'));
$row = t_lastrow($cfgK);
t_ok('past the budget the claim is judged like any client, and still logged for verification',
	$row['bot'] === 'googlebot' && in_array('BOT_UNVERIFIED', $row['rs'], true));
gv_redis_cmd($cx, array('SET', 'gv:botok:66.249.66.1', '1', 'EX', '60'));
$acts = array();
for ($i = 0; $i < 4; $i++) { $p = t_probe($cfgK, $gb('66.249.66.1')); $acts[] = t_lastrow($cfgK)['act']; }
t_ok('a VERIFIED crawler is outside that budget', $acts === array('allow_bot', 'allow_bot', 'allow_bot', 'allow_bot') && $p['bytes'] === 0);
t_ok('...and does not draw on it', gv_redis_cmd($cx, array('GET', 'gv:rbu:googlebot')) === '5');
gv_redis_cmd($cx, array('SET', 'gv:deny:66.249.66.1', '1', 'EX', '60'));
$p = t_probe($cfgK, $gb('66.249.66.1'));
t_ok('an operator deny beats the bot pass', $p['code'] === 403 && t_lastrow($cfgK)['ovr'] === 'deny');
$cfgKD = t_cfg(array('port' => 63997), array('log_dir' => t_mkdir_log('botpass-down'), 'known_bots' => array('googlebot')));
$p = t_probe($cfgKD, $gb('198.51.100.9'));
t_ok('Redis down: the crawler pass stays open (documented)', $p['bytes'] === 0 && t_lastrow($cfgKD)['act'] === 'allow_bot');

// Cookies.
$cfgC = t_cfg(array(), array('log_dir' => t_mkdir_log('cookie')));
$good = gv_tok_make('rt-secret');
$p = t_probe($cfgC, array_merge(t_nav(), array('HTTP_COOKIE' => '_gv[]=x')), array('_gv' => array('x')));
t_ok('Cookie: _gv[]=x raises no warning: just the challenge page', $p['code'] === 503 && $p['bytes'] > 1000);
$out_len = $p['bytes'];
$p = t_probe($cfgC, t_nav());
t_ok('...byte for byte the size of an ordinary challenge', abs($p['bytes'] - $out_len) < 8);
$p = t_probe($cfgC, array_merge(t_nav(), array('HTTP_COOKIE' => '_gv=stale-junk; _gv=' . $good)), array('_gv' => 'stale-junk'));
t_ok('a stale cookie in front of a valid one no longer locks the visitor in a challenge loop',
	$p['bytes'] === 0 && t_lastrow($cfgC)['act'] === 'allow' && t_lastrow($cfgC)['tok'] === 'v');
$p = t_probe($cfgC, array_merge(t_nav(), array('HTTP_COOKIE' => '_gv=junk1; _gv=junk2')), array('_gv' => 'junk1'));
t_ok('two invalid cookies are still a challenge', $p['code'] === 503 && t_lastrow($cfgC)['tok'] === 'b');

// Handshake in monitor mode.
$cfgHM = t_cfg(array(), array('log_dir' => t_mkdir_log('hs-mon'),
	'enforce' => array('block' => false, 'challenge' => false, 'ratelimit' => false)));
$p = t_probe($cfgHM, array('REQUEST_METHOD' => 'POST', 'HTTP_USER_AGENT' => 'x', 'HTTP_X_GV' => 'garbage', 'HTTP_X_GV_P' => '1'));
$row = t_lastrow($cfgHM);
t_ok('monitor mode refuses nothing: a bad nonce is logged in shadow and the request runs',
	$p['bytes'] === 0 && ($p['code'] ?? 200) !== 403 && $row['act'] === 'nonce_bad' && $row['sh'] === 1);
$p = t_probe($cfgC, array('REQUEST_METHOD' => 'POST', 'HTTP_USER_AGENT' => 'x', 'HTTP_X_GV' => 'garbage', 'HTTP_X_GV_P' => '1'));
t_ok('with the challenge enforced a bad nonce is still a 403', $p['code'] === 403 && t_lastrow($cfgC)['sh'] === 0);

// Guard answers must not be cacheable by LiteSpeed.
t_ok('403, 429 and the challenge page send X-LiteSpeed-Cache-Control: no-cache',
	substr_count(file_get_contents(__DIR__ . '/../guard/guard.php'), "header('X-LiteSpeed-Cache-Control: no-cache')") === 2
	&& substr_count(file_get_contents(__DIR__ . '/../guard/challenge.php'), "header('X-LiteSpeed-Cache-Control: no-cache')") === 1);

// --------------------------------------------------------------------------
t_section('Review hardening: a Redis that answers but will not count');

gv_redis_cmd($cx, array('FLUSHALL'));
$cfgO = t_cfg(array(), array('log_dir' => t_mkdir_log('oom')));
$tokO = gv_tok_make('rt-secret');
$old_policy = gv_redis_cmd($cx, array('CONFIG', 'GET', 'maxmemory-policy'));
gv_redis_cmd($cx, array('CONFIG', 'SET', 'maxmemory-policy', 'noeviction'));
gv_redis_cmd($cx, array('CONFIG', 'SET', 'maxmemory', '1'));
$p = t_probe($cfgO, t_nav(), array('_gv' => $tokO));
$row = t_lastrow($cfgO);
gv_redis_cmd($cx, array('CONFIG', 'SET', 'maxmemory', '0'));
if (is_array($old_policy) && isset($old_policy[1])) { gv_redis_cmd($cx, array('CONFIG', 'SET', 'maxmemory-policy', $old_policy[1])); }
t_ok('out-of-memory Redis: the request is allowed with zero output', $p['bytes'] === 0 && $row['act'] === 'allow');
t_ok('...but the row is marked degraded instead of looking healthy (rd=1, counters 0)', $row['rd'] === 1 && $row['ci'] === 0);
t_ok('...and guard-errors.log names it', is_file($cfgO['log_dir'] . '/guard-errors.log')
	&& strpos(file_get_contents($cfgO['log_dir'] . '/guard-errors.log'), 'redis_cmd_error') !== false);
$p = t_probe($cfgO, t_nav(), array('_gv' => $tokO));
t_ok('once Redis counts again the row is healthy', t_lastrow($cfgO)['rd'] === 0 && t_lastrow($cfgO)['ci'] === 1);

// Breaker marker: a future mtime is stale, and an unwritable log dir moves it.
$cfgF = t_cfg(array(), array('log_dir' => t_mkdir_log('future')));
touch($cfgF['log_dir'] . '/.redis-down', time() + 3600);
$p = t_probe($cfgF, t_nav(), array('_gv' => $tokO));
t_ok('a breaker marker dated in the future does not switch Redis off', t_lastrow($cfgF)['rd'] === 0 && $p['rt'] >= 1);
gv_redis_ctx(array('log_dir' => $cfgF['log_dir']));
t_ok('the marker lives in the log directory when it is writable', gv_breaker_path() === $cfgF['log_dir'] . '/.redis-down');
if (function_exists('posix_geteuid') && posix_geteuid() !== 0) {
	$ro = t_mkdir_log('readonly'); chmod($ro, 0555);
	gv_redis_ctx(array('log_dir' => $ro));
	t_ok('...and moves to the temp directory when it is not',
		strpos(gv_breaker_path(), rtrim(sys_get_temp_dir(), '/')) === 0 && strpos(gv_breaker_path(), $ro) === false);
	chmod($ro, 0755);
} else {
	t_skip('breaker marker fallback', 'running as root: every directory is writable');
}
// --------------------------------------------------------------------------
t_section('Log storage: skipped paths and the free-space floor (real requests)');

$cfgL = t_cfg(array(), array('log_dir' => t_mkdir_log('skip1'), 'capture_outcomes' => true,
	'exempt_paths' => array('/gv-admin/', '/pay/'), 'log_skip_paths' => array('/gv-admin/'), 'log_min_free_mb' => 0));
$r1 = t_nav(); $r1['REQUEST_URI'] = '/gv-admin/index.php?r=logs';
$p = t_probe($cfgL, $r1);
t_ok('a log_skip_paths request writes no line at all (decision or outcome)', t_rows($cfgL) === array() && $p['bytes'] === 0);
$r2 = t_nav(); $r2['REQUEST_URI'] = '/pay/callback';
t_probe($cfgL, $r2);
$rows = t_rows($cfgL);
t_ok('an exempt path that is not skipped is still logged (act=exempt)', count($rows) >= 1 && $rows[0]['act'] === 'exempt' && $rows[0]['p'] === '/pay/callback');
$r3 = t_nav(); $r3['REQUEST_URI'] = '/gv-admin/../product/1';
t_probe($cfgL, $r3);
t_ok('a dot-segment path cannot hide itself under a skipped prefix', (bool)array_filter(t_rows($cfgL), function ($r) { return isset($r['p']) && $r['p'] === '/gv-admin/../product/1'; }));
$r4 = t_nav(); $r4['REQUEST_URI'] = '/product/2';
t_probe($cfgL, $r4);
t_ok('ordinary requests are logged as before', t_lastrow($cfgL)['p'] === '/product/2');

$cfgD = t_cfg(array(), array('log_dir' => t_mkdir_log('diskfloor'), 'log_min_free_mb' => 1000000));
$p = t_probe($cfgD, t_nav());
t_ok('below the free-space floor nothing is logged and the guard still answers', t_rows($cfgD) === array() && $p['rt'] !== -1);
t_ok('...and guard-errors.log says why (disk_low)', is_file($cfgD['log_dir'] . '/guard-errors.log')
	&& strpos(file_get_contents($cfgD['log_dir'] . '/guard-errors.log'), 'disk_low') !== false);
$cfgD['log_min_free_mb'] = 0;
t_probe($cfgD, t_nav());
t_ok('with the floor off (0) the same request is logged', count(t_rows($cfgD)) >= 1);

gv_redis_ctx(array('log_dir' => $T_DIR));
gv_redis_cmd($cx, array('FLUSHALL'));

echo "\nPASS $GV_PASS  FAIL $GV_FAIL  SKIP $GV_SKIP\n";
exit($GV_FAIL === 0 ? 0 : 1);
