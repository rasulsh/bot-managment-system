<?php
// Benchmark of one request-log append, idle and under disk load (PR K).
//
//   php scripts/bench-log-append.php [--n=20000] [--dir=/path/on/the/disk/to/test] [--timeout-ms=50]
//   (dd if=/dev/zero of=/path/on/the/same/disk/load bs=1M count=4000 oflag=direct &) ; php scripts/bench-log-append.php
//
// Times, per call, (a) the previous writer, file_put_contents(FILE_APPEND | LOCK_EX), and (b) gv_log() as it is now (non-blocking flock
// with a bounded retry). Prints p50 / p99 / max in microseconds. A command-line tool; the web server never runs it.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
define('GV_BOOT', 1);
require __DIR__ . '/../guard/guard.php';

$n = 20000; $timeout = 50; $dir = sys_get_temp_dir() . '/gv-bench-append-' . getmypid();
foreach (array_slice($argv, 1) as $a) {
	if (strncmp($a, '--n=', 4) === 0) { $n = max(100, (int)substr($a, 4)); }
	elseif (strncmp($a, '--timeout-ms=', 13) === 0) { $timeout = (int)substr($a, 13); }
	elseif (strncmp($a, '--dir=', 6) === 0) { $dir = rtrim(substr($a, 6), '/') . '/gv-bench-append-' . getmypid(); }
}
@mkdir($dir, 0775, true);
gv_log_policy(array('skip' => false, 'min_free' => 0, 'timeout_ms' => $timeout));
$row = array('v' => 5, 'rid' => 'a1b2c3d4e5f6', 'ts' => microtime(true), 'ip' => '203.0.113.7', 'ua' => str_repeat('Mozilla/5.0 ', 8), 'p' => '/product/12345', 'act' => 'allow', 'rs' => array('RULE:x'));

function pct(array $v, $p) { sort($v); return $v[(int)min(count($v) - 1, floor(count($v) * $p))]; }

$old = array(); $file = $dir . '/old.jsonl';
// The previous gv_log() body: policy check, encode, one file_put_contents. (The encode and the checks are in both timings.)
for ($i = 0; $i < $n; $i++) { $t = hrtime(true); if (is_dir($dir) && gv_log_allowed($dir)) { $l = json_encode($row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); @file_put_contents($file, $l . "\n", FILE_APPEND | LOCK_EX); } $old[] = (hrtime(true) - $t) / 1000; }
$new = array();
for ($i = 0; $i < $n; $i++) { $t = hrtime(true); gv_log($row, $dir); $new[] = (hrtime(true) - $t) / 1000; }
printf("previous (file_put_contents LOCK_EX): n=%d p50=%dus p99=%dus max=%dus\n", $n, pct($old, .5), pct($old, .99), max($old));
printf("now      (gv_log, timeout %d ms)     : n=%d p50=%dus p99=%dus max=%dus\n", $timeout, $n, pct($new, .5), pct($new, .99), max($new));
foreach ((array)glob($dir . '/{,.}*', GLOB_BRACE) as $f) { if (is_file($f)) { @unlink($f); } }
@rmdir($dir);
