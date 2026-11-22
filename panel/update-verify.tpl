<?php
// Bot Guard update health check. Written to updates/verify.php by the updater BEFORE it applies an
// update, from the code that is running at that moment. The updater sends the browser here in a FRESH
// request right after the files were swapped, so what runs is the NEW code, judged by OLD code.
//
//   Web:    <panel-url>/recover.php?a=verify&ts=<stamp>&k=<key>     (the updater builds this link)
//   Shell:  php <install-dir>/updates/verify.php <stamp>
//
// It loads the guard and the panel libraries, reads the configuration, loads rules / IP lists / GeoIP and
// runs one synthetic request through gv_run() in dry-run mode (nothing is logged, no output is sent). Any
// exception, parse error or fatal error - including one that kills this request - rolls the update back
// automatically with updates/rollback.php. On success it removes guard.off only when the updater created it.
if (!defined('GP_RECOVER_WEB') && PHP_SAPI !== 'cli') { http_response_code(404); exit; }

$GPV = array('stamp' => '', 'stage' => 'start', 'done' => false);

function gpv_dir() { return __DIR__; }
function gpv_root() { return dirname(__DIR__); }

function gpv_manifest() {
	global $GPV;
	$raw = @file_get_contents(gpv_dir() . '/' . $GPV['stamp'] . '/manifest.json');
	$d = is_string($raw) ? json_decode($raw, true) : null;
	return is_array($d) ? $d : null;
}

function gpv_manifest_save(array $m) {
	global $GPV;
	$p = gpv_dir() . '/' . $GPV['stamp'] . '/manifest.json';
	$tmp = $p . '.tmp' . bin2hex(random_bytes(3));
	if (@file_put_contents($tmp, json_encode($m, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)) !== false) { @chmod($tmp, 0600); @rename($tmp, $p); }
}

// Keep the newest N updates (backups included); older directories are deleted.
function gpv_prune($keep) {
	$all = array();
	foreach ((array)@scandir(gpv_dir()) as $n) {
		if (preg_match('/^\d{8}-\d{6}(-\d+)?$/', $n) && is_dir(gpv_dir() . '/' . $n)) { $all[] = $n; }
	}
	rsort($all, SORT_STRING);
	foreach (array_slice($all, max(1, (int)$keep)) as $n) {
		$base = gpv_dir() . '/' . $n;
		$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
		foreach ($it as $f) { $f->isDir() && !$f->isLink() ? @rmdir($f->getPathname()) : @unlink($f->getPathname()); }
		@rmdir($base);
	}
}

// Decide once, at the end of this request (also reached after a fatal error through the shutdown function).
function gpv_finish($ok, $detail) {
	global $GPV;
	if ($GPV['done']) { return; }
	$GPV['done'] = true;
	while (ob_get_level() > 0) { @ob_end_clean(); }
	$m = gpv_manifest();
	$keep = 3;
	if ($ok) {
		if ($m !== null) {
			$m['status'] = 'ok';
			$m['verified_at'] = time();
			gpv_manifest_save($m);
			if (!empty($m['guard_off_created']) && is_file(gpv_root() . '/guard.off')) { @unlink(gpv_root() . '/guard.off'); }
			$keep = isset($m['keep']) ? (int)$m['keep'] : 3;
		}
		gpv_prune($keep);
		$out = 'ok';
	} else {
		$rb = array(false, array('rollback script missing'));
		if (is_file(gpv_dir() . '/rollback.php')) {
			if (!defined('GP_ROLLBACK_LIB')) { define('GP_ROLLBACK_LIB', 1); }
			require_once gpv_dir() . '/rollback.php';
			$rb = gprb_run(gpv_root(), $GPV['stamp']);
		}
		$m = gpv_manifest();
		if ($m !== null) {
			$m['verify_failed'] = substr((string)$detail, 0, 500);
			$m['auto_rollback'] = $rb[0];
			if ($rb[0]) { $m['status'] = 'rolled_back'; }
			gpv_manifest_save($m);
		}
		if ($rb[0]) { @unlink(gpv_dir() . '/recovery.json'); @unlink(gpv_dir() . '/' . $GPV['stamp'] . '/token.once'); }
		$out = $rb[0] ? 'rolled' : 'rollback_failed';
	}
	if (PHP_SAPI === 'cli') {
		echo ($ok ? 'OK: the update passed the health check.' : 'FAILED: ' . $detail . ($out === 'rolled' ? ' - rolled back automatically.' : ' - ROLLBACK ALSO FAILED, run updates/rollback.php.')) . "\n";
		exit($ok ? 0 : 1);
	}
	// Back to the Update page. After a fatal error PHP has already set status 500 and a browser does not follow a
	// Location on a 500, so the body carries a meta refresh and a link as well.
	$next = 'index.php?r=update&ts=' . rawurlencode($GPV['stamp']) . '&res=' . $out;
	if (!headers_sent()) {
		header_remove();
		http_response_code(303);
		header('Cache-Control: no-store');
		header('Content-Type: text/html; charset=utf-8');
		header('Location: ' . $next);
	}
	echo '<!doctype html><html lang="en" dir="ltr"><meta charset="utf-8"><meta name="robots" content="noindex">'
		. '<meta http-equiv="refresh" content="0;url=' . htmlspecialchars($next, ENT_QUOTES, 'UTF-8') . '"><title>Bot Guard update</title>'
		. '<body style="font-family:sans-serif;padding:2rem"><a href="' . htmlspecialchars($next, ENT_QUOTES, 'UTF-8') . '">Continue</a></body></html>';
	exit;
}

function gpv_fail($detail) { gpv_finish(false, $detail); }

function gpv_shutdown() {
	global $GPV;
	if ($GPV['done']) { return; }
	$e = error_get_last();
	if ($e !== null && in_array($e['type'], array(E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_RECOVERABLE_ERROR), true)) {
		gpv_fail('fatal error at stage ' . $GPV['stage'] . ': ' . $e['message'] . ' in ' . basename($e['file']) . ':' . $e['line']);
		return;
	}
	// The synthetic request ended with exit (a 403, a challenge, a 429 are all fine decisions).
	if ($GPV['stage'] === 'run') { gpv_finish(true, ''); return; }
	gpv_fail('the check stopped at stage ' . $GPV['stage'] . ' without a result');
}

function gpv_main($stamp, $key) {
	global $GPV;
	if (!preg_match('/^\d{8}-\d{6}(-\d+)?$/', (string)$stamp)) { http_response_code(404); exit; }
	$GPV['stamp'] = $stamp;
	$m = gpv_manifest();
	// Web: the one-time key from the updater, and only while the update is waiting for its check.
	if (PHP_SAPI !== 'cli') {
		if ($m === null || ($m['status'] ?? '') !== 'applied' || !isset($m['verify_key']) || !is_string($key)
			|| !hash_equals((string)$m['verify_key'], $key)) {
			usleep(300000);
			http_response_code(404);
			exit;
		}
	} elseif ($m === null) { echo "Unknown update.\n"; exit(2); }

	ini_set('display_errors', '0');
	@set_time_limit(60);
	ob_start();
	register_shutdown_function('gpv_shutdown');
	$root = gpv_root();
	try {
		$GPV['stage'] = 'syntax';
		foreach (array('panel/index.php', 'guard/guard.php', 'prepend.php') as $rel) {
			token_get_all((string)file_get_contents($root . '/' . $rel), TOKEN_PARSE);
		}
		if (!defined('GV_BOOT')) { define('GV_BOOT', 1); }
		if (!defined('GV_NO_AUTORUN')) { define('GV_NO_AUTORUN', 1); }
		$GPV['stage'] = 'guard';
		require_once $root . '/guard/guard.php';
		$GPV['stage'] = 'config';
		$cfg = gv_cfg_load();
		if (!is_array($cfg) || !isset($cfg['redis'], $cfg['log_dir'])) { return gpv_fail('the configuration did not load'); }
		$GPV['stage'] = 'panel';
		if (!defined('GP_BOOT')) { define('GP_BOOT', 1); }
		foreach (array('config_io', 'auth', 'data', 'jobs', 'health', 'filters', 'ui', 'rules', 'geo', 'iplists', 'perms', 'replay', 'update') as $lib) {
			if (is_file($root . '/panel/' . $lib . '.php')) { require_once $root . '/panel/' . $lib . '.php'; }
		}
		$lang = require $root . '/panel/lang.php';
		if (!is_array($lang) || count($lang) < 50) { return gpv_fail('panel/lang.php did not load'); }
		foreach (glob($root . '/panel/views/*.php') as $v) { token_get_all((string)file_get_contents($v), TOKEN_PARSE); }
		$GPV['stage'] = 'data';
		if (function_exists('gv_rules_load')) { gv_rules_load(); }
		if (function_exists('gv_iplist_check')) { gv_iplist_check('192.0.2.1'); }
		if (function_exists('gv_geo_country')) { gv_geo_country('192.0.2.1', true); }
		$GPV['stage'] = 'run';
		define('GV_DRY_RUN', 1);
		$_SERVER = array_merge($_SERVER, array('REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/gv-update-check', 'REMOTE_ADDR' => '192.0.2.77',
			'HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36',
			'HTTP_ACCEPT' => 'text/html,application/xhtml+xml', 'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.9'));
		unset($_SERVER['QUERY_STRING']);
		$_GET = array(); $_POST = array(); $_COOKIE = array();
		gv_run(microtime(true));
		gpv_finish(true, '');
	} catch (\Throwable $e) {
		gpv_fail(get_class($e) . ' at stage ' . $GPV['stage'] . ': ' . $e->getMessage() . ' (' . basename($e->getFile()) . ':' . $e->getLine() . ')');
	}
}

if (PHP_SAPI === 'cli') { gpv_main(isset($argv[1]) ? $argv[1] : '', ''); }
else { gpv_main(isset($_GET['ts']) && is_string($_GET['ts']) ? $_GET['ts'] : '', isset($_GET['k']) ? $_GET['k'] : ''); }
