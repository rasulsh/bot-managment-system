<?php
// Request-path micro-benchmark: times gv_run() in-process on an ALLOWED request
// (valid token, clean browser headers) against a real Redis.
//
//   php scripts/bench-gv-run.php [--n=3000] [--rules=0] [--values=5] [--redis-port=6399]
//
// --rules=N writes N non-matching access rules into a temp rules file (GV_RULES)
// first, so the same script measures the cost of the rule engine: run it on the
// base branch (which ignores GV_RULES) and on the branch under test.
// Prints p50 / p99 / max in microseconds. Test tooling only: needs a running
// Redis (scripts/bench-gv-run.sh starts a throw-away one).
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

$opt = getopt('', array('n::', 'rules::', 'values::', 'redis-port::', 'regex::'));
$n      = isset($opt['n']) ? (int)$opt['n'] : 3000;
$nrules = isset($opt['rules']) ? (int)$opt['rules'] : 0;
$nvals  = isset($opt['values']) ? (int)$opt['values'] : 5;
$port   = isset($opt['redis-port']) ? (int)$opt['redis-port'] : 6399;
$regex  = isset($opt['regex']);
$tmp    = sys_get_temp_dir() . '/gv-bench-' . getmypid();
@mkdir($tmp . '/logs', 0775, true);

// Config: every enforce switch off and limits out of reach, so the loop never
// exits (a 429 or a challenge would end the process).
file_put_contents($tmp . '/config.php', "<?php\nif (!defined('GV_BOOT')) { exit; }\n\$c = require " . var_export(__DIR__ . '/config.dev.php', true) . ";\n"
	. "\$c['enforce'] = array('block' => false, 'challenge' => false, 'ratelimit' => false);\n"
	. "\$c['holdout_pct'] = 0; \$c['capture_outcomes'] = false;\n"
	. "\$c['redis']['port'] = $port; \$c['redis']['timeout'] = 0.5; \$c['log_dir'] = " . var_export($tmp . '/logs', true) . ";\n"
	. "\$c['limits'] = array_merge(\$c['limits'], array('window' => 3600, 'device' => 1000000, 'ip_ua' => 1000000, 'ip' => 1000000, 'device_hour' => 1000000, 'device_day' => 1000000));\n"
	. "return \$c;\n");
putenv('GV_CONFIG=' . $tmp . '/config.php');

// N rules that do not match the benchmark client: the realistic case, where
// every rule is evaluated and none fires.
if ($nrules > 0) {
	$rules = array();
	for ($i = 0; $i < $nrules; $i++) {
		$vals = array();
		for ($j = 0; $j < $nvals; $j++) { $vals[] = 'scraper-' . $i . '-' . $j . ($regex ? '/\d+' : '/1.0'); }
		$types = array('contains', 'exact', 'prefix', 'regex');
		$type = $regex ? 'regex' : $types[$i % 4];
		$rules[] = array('id' => 'b' . sprintf('%05d', $i), 'name' => 'bench ' . $i, 'enabled' => true, 'mode' => 'enforce',
			'action' => 'block', 'priority' => 100 + $i, 'skip_verified_bots' => true,
			'ua' => array('op' => 'include', 'type' => $type, 'values' => $vals), 'path' => null,
			'expires_at' => 0, 'pow_bits' => 0, 'note' => '', 'created_by' => '', 'created_at' => 0, 'updated_at' => 0);
	}
	putenv('GV_RULES=' . $tmp . '/rules.json');
}

define('GV_BOOT', 1);
require __DIR__ . '/../guard/guard.php';
$cfg = gv_cfg_load();
if ($nrules > 0) {
	// Written the way the panel writes it (stamped) when the engine exists.
	file_put_contents($tmp . '/rules.json', function_exists('gv_rules_encode') ? gv_rules_encode($rules) : json_encode(array('rules' => $rules)));
}

$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
$_COOKIE = array('_gv' => gv_tok_make($cfg['secret']));
$samples = array();
for ($i = 0; $i < $n + 300; $i++) {
	$_SERVER = array('REMOTE_ADDR' => '203.0.113.' . (1 + ($i % 200)), 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/p/' . $i,
		'QUERY_STRING' => '', 'HTTP_USER_AGENT' => $ua, 'HTTP_ACCEPT' => 'text/html', 'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.9',
		'HTTP_SEC_FETCH_MODE' => 'navigate', 'HTTP_HOST' => 'x', 'HTTP_ACCEPT_ENCODING' => 'gzip', 'HTTP_CONNECTION' => 'keep-alive',
		'HTTP_COOKIE' => '_gv=' . $_COOKIE['_gv']);
	$t = hrtime(true);
	gv_run(microtime(true));
	$us = (hrtime(true) - $t) / 1000;
	if ($i >= 300) { $samples[] = $us; }     // 300 warm-up requests are discarded
}
sort($samples);
$pct = function ($p) use ($samples) { return $samples[(int)min(count($samples) - 1, floor($p * count($samples)))]; };
printf("rules=%d values=%d%s n=%d  p50=%.0fus  p99=%.0fus  max=%.0fus  (php %s)\n", $nrules, $nvals, $regex ? ' regex' : '', count($samples),
	$pct(0.5), $pct(0.99), end($samples), PHP_VERSION);
foreach ((array)glob($tmp . '/{,logs/}{,.}*', GLOB_BRACE) as $f) { if (is_file($f)) { @unlink($f); } }
@rmdir($tmp . '/logs'); @rmdir($tmp);
