<?php
// Test helper: run ONE guarded request in a child process and report what it
// cost. Reads a JSON object on stdin:
//   {"config": "/path/to/config.php", "server": {...}, "cookie": {...}}
// and prints one JSON line: {"rt": <redis round trips>, "bytes": <guard output>,
// "ms": <elapsed>}. CLI only; used by redis-selftest.php and the web-server CI.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

$gv_in = json_decode((string)stream_get_contents(STDIN), true);
if (!is_array($gv_in) || empty($gv_in['config'])) { fwrite(STDERR, "bad input\n"); exit(2); }
putenv('GV_CONFIG=' . $gv_in['config']);
define('GV_BOOT', 1);
define('GV_NO_AUTORUN', 1);
require __DIR__ . '/../guard/guard.php';

$_SERVER = array_merge(array(
	'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/', 'REMOTE_ADDR' => '198.51.100.9',
), isset($gv_in['server']) ? $gv_in['server'] : array());
$_COOKIE = isset($gv_in['cookie']) ? $gv_in['cookie'] : array();
$_GET = array();

$gv_start = microtime(true);
ob_start();
register_shutdown_function(function () use ($gv_start) {
	$out = (string)ob_get_clean();
	echo json_encode(array('rt' => gv_redis_rt(), 'bytes' => strlen($out), 'code' => http_response_code(),
		'ms' => round((microtime(true) - $gv_start) * 1000, 2))) . "\n";
});
try {
	gv_run(microtime(true));
} catch (\Throwable $e) {
	gv_errlog('probe_exception', $e->getMessage());
}
