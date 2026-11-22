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

$opt = getopt('', array('n::', 'rules::', 'values::', 'redis-port::', 'regex::', 'geo-rules::', 'geo-ranges::', 'geo-log::', 'geo-ua::', 'lookup::', 'match::', 'lists::', 'list-lookup::', 'list-types::', 'cap-gen::', 'cap-match::', 'cap-rules::', 'esc::'));
$n      = isset($opt['n']) ? (int)$opt['n'] : 3000;
$nrules = isset($opt['rules']) ? (int)$opt['rules'] : 0;
$nvals  = isset($opt['values']) ? (int)$opt['values'] : 5;
$port   = isset($opt['redis-port']) ? (int)$opt['redis-port'] : 6399;
$regex  = isset($opt['regex']);
// GeoIP: --geo-rules=N writes N country-only rules that never match the client (the
// realistic case); --geo-ua makes them UA + country rules (the UA misses, so the geo
// lookup never runs); --geo-log turns geo.log on (lookup on every request, no rules);
// --geo-ranges sets the size of the generated country database (default 150000 IPv4).
$ngeo   = isset($opt['geo-rules']) ? (int)$opt['geo-rules'] : 0;
$geoua  = isset($opt['geo-ua']);
$geolog = isset($opt['geo-log']);
$granges = isset($opt['geo-ranges']) ? (int)$opt['geo-ranges'] : 150000;
$lookup_only = isset($opt['lookup']);
// IP lists: --lists=N4,N6 writes an allow AND a block file of N4 IPv4 + N6 IPv6 ranges each (none of
// them covers the benchmark client); --list-lookup times gv_iplist_check() alone.
$lists_spec = isset($opt['lists']) ? array_map('intval', explode(',', (string)$opt['lists'] . ',0')) : null;
$list_lookup = isset($opt['list-lookup']);
// --esc: escalation enforced (the request reads the server-side flag cesc:<ip+UA> in its one pipeline).
// CAPTCHA: --cap-gen times the image + page generation at every level; --cap-rules=N writes N captcha rules that never match
// (the cost of having them); --cap-match writes one captcha rule that MATCHES the benchmark client, which holds a CAPTCHA-level
// token, so it is not asked: the request path of a request that does NOT get a CAPTCHA although a captcha rule applies.
$cap_gen = isset($opt['cap-gen']);
$cap_rules = isset($opt['cap-rules']) ? (int)$opt['cap-rules'] : 0;
$cap_match = isset($opt['cap-match']);
$list_types = (isset($opt['list-types']) && $opt['list-types'] === 'block') ? array('block' => 9) : array('allow' => 7, 'block' => 9);   // --list-types=block: only a block file
$esc_on = isset($opt['esc']);        // --esc: escalation enforced (enforce.challenge on, captcha.escalate_score 60): the request also reads cesc:<ip+UA>
$match_only = isset($opt['match']);     // --match: gv_rules_match() alone, country already known (no lookup)
$tmp    = sys_get_temp_dir() . '/gv-bench-' . getmypid();
@mkdir($tmp . '/logs', 0775, true);

// Config: every enforce switch off and limits out of reach, so the loop never
// exits (a 429 or a challenge would end the process).
file_put_contents($tmp . '/config.php', "<?php\nif (!defined('GV_BOOT')) { exit; }\n\$c = require " . var_export(__DIR__ . '/config.dev.php', true) . ";\n"
	. "\$c['enforce'] = array('block' => false, 'challenge' => false, 'ratelimit' => false);\n"
	. "\$c['holdout_pct'] = 0; \$c['capture_outcomes'] = false;\n"
	. "\$c['redis']['port'] = $port; \$c['redis']['timeout'] = 0.5; \$c['log_dir'] = " . var_export($tmp . '/logs', true) . ";\n"
	. "\$c['limits'] = array_merge(\$c['limits'], array('window' => 3600, 'device' => 1000000, 'ip_ua' => 1000000, 'ip' => 1000000, 'device_hour' => 1000000, 'device_day' => 1000000));\n"
	. ($geolog ? "\$c['geo'] = array('log' => true);\n" : '')
	. ($esc_on ? "\$c['enforce']['challenge'] = true; \$c['captcha']['escalate_score'] = 60;\n" : '')
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

if ($cap_rules > 0 || $cap_match) {
	$rules = array();
	for ($i = 0; $i < ($cap_match ? 1 : $cap_rules); $i++) {
		$rules[] = array('id' => 'c' . sprintf('%05d', $i), 'name' => 'cap ' . $i, 'enabled' => true, 'mode' => 'enforce',
			'action' => 'captcha', 'priority' => 100 + $i, 'skip_verified_bots' => true,
			'ua' => array('op' => 'include', 'type' => 'contains', 'values' => array($cap_match ? 'Mozilla' : 'scraper-' . $i)), 'path' => null,
			'expires_at' => 0, 'pow_bits' => 0, 'note' => '', 'created_by' => '', 'created_at' => 0, 'updated_at' => 0);
	}
	putenv('GV_RULES=' . $tmp . '/rules.json');
	$nrules = count($rules);
}

// The generated GeoIP database (guard/geo.php exists only from the GeoIP release on).
if ($ngeo > 0 || $geolog || $lookup_only) {
	require_once __DIR__ . '/geo-fixture.php';
	@mkdir($tmp . '/geo', 0775, true);
	$g = gf_random(1, $granges, 20000);
	file_put_contents($tmp . '/geo/country.bin', gf_pack(1, $g[0], $g[1]));
	unset($g);
	gc_collect_cycles();
	putenv('GV_GEO_DIR=' . $tmp . '/geo');
}
if ($lists_spec !== null || $list_lookup) {
	require_once __DIR__ . '/geo-fixture.php';
	@mkdir($tmp . '/lists', 0775, true);
	$n4 = $lists_spec ? $lists_spec[0] : 100000;
	$n6 = $lists_spec ? $lists_spec[1] : 10000;
	foreach ($list_types as $lt => $seed) {
		$g = gf_random(3, $n4, $n6, $seed);
		// keep the benchmark client (203.0.113.0/24) out of every range
		$g[0] = array_values(array_filter($g[0], function ($r) { return $r[1] < 3405803776 || $r[0] > 3405804031; }));
		file_put_contents($tmp . '/lists/' . $lt . '.bin', gf_pack(3, $g[0], $g[1]));
		unset($g);
	}
	gc_collect_cycles();                    // the generator's arrays are tens of MB: do not time gv_run next to them
	putenv('GV_LISTS_DIR=' . $tmp . '/lists');
}
if ($ngeo > 0) {
	$rules = array();
	for ($i = 0; $i < $ngeo; $i++) {
		$rules[] = array('id' => 'g' . sprintf('%05d', $i), 'name' => 'geo ' . $i, 'enabled' => true, 'mode' => 'enforce',
			'action' => 'block', 'priority' => 100 + $i, 'skip_verified_bots' => true,
			'ua' => $geoua ? array('op' => 'include', 'type' => 'contains', 'values' => array('scraper-' . $i)) : null, 'path' => null,
			'country' => array('op' => 'include', 'type' => 'code', 'values' => array('KP', 'CU', 'SY', 'ZW', 'XK')),
			'asn' => null, 'expires_at' => 0, 'pow_bits' => 0, 'note' => '', 'created_by' => '', 'created_at' => 0, 'updated_at' => 0);
	}
	putenv('GV_RULES=' . $tmp . '/rules.json');
	$nrules = $ngeo;
}

define('GV_BOOT', 1);
require __DIR__ . '/../guard/guard.php';
$cfg = gv_cfg_load();
if ($nrules > 0) {
	// Written the way the panel writes it (stamped) when the engine exists.
	file_put_contents($tmp . '/rules.json', function_exists('gv_rules_encode') ? gv_rules_encode($rules) : json_encode(array('rules' => $rules)));
	// ...and the generated cache the panel writes next to it.
	if (function_exists('gv_rules_cache_source')) { file_put_contents($tmp . '/rules.cache.php', gv_rules_cache_source($rules)); }
}

$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
$bench_cleanup = function () use ($tmp) {
	foreach ((array)glob($tmp . '/{,logs/,geo/,lists/}{,.}*', GLOB_BRACE) as $f) { if (is_file($f)) { @unlink($f); } }
	@rmdir($tmp . '/logs'); @rmdir($tmp . '/geo'); @rmdir($tmp . '/lists'); @rmdir($tmp);
};
if ($match_only) {
	// The rule loop alone: the rules the run would load, the client's country supplied
	// (so no file is opened), 20000 evaluations, none of them matching.
	$loaded = gv_rules_load();
	$f = array('ua' => $ua, 'path' => '/p/1', 'ip' => '203.0.113.5', 'cc' => 'IR', 'asn' => 12880);
	$now = time();
	for ($i = 0; $i < 500; $i++) { gv_rules_match($f, $loaded, $now); }
	$m = array();
	for ($i = 0; $i < 20000; $i++) { $t = hrtime(true); gv_rules_match($f, $loaded, $now); $m[] = (hrtime(true) - $t) / 1000; }
	sort($m);
	printf("rule loop rules=%d%s  p50=%.1fus p99=%.1fus max=%.0fus  (php %s)\n", count($loaded), $geoua ? ' ua+country' : '',
		$m[(int)(0.5 * count($m))], $m[(int)(0.99 * count($m))], end($m), PHP_VERSION);
	$bench_cleanup();
	exit;
}
if ($cap_gen) {
	// The CAPTCHA page generation per level: the answer, the PNG and the whole HTML page (everything gv_captcha_serve does,
	// minus the output). p50 / p99 over 400 pages per level, GD, the shipped font, PHP in-process.
	foreach (array(1, 2, 3, 4, 5) as $lv) {
		$pp = gv_captcha_params(array('captcha' => array('level' => $lv)));
		$img = array(); $page = array(); $bytes = 0;
		for ($i = 0; $i < 420; $i++) {
			$t = hrtime(true);
			$ans = gv_captcha_answer($pp['length'], $pp['charset']);
			$png = gv_captcha_image($ans, $pp);
			$t1 = hrtime(true);
			$nonce = gv_captcha_nonce_make($cfg['secret'], 'ua', '1.2.3.4', 16, $pp['time'], $ans);
			ob_start(); gv_captcha_render($nonce, $cfg['strings'], 16, $png, $pp); $html = ob_get_clean();
			$t2 = hrtime(true);
			if ($i >= 20) { $img[] = ($t1 - $t) / 1000; $page[] = ($t2 - $t) / 1000; $bytes = strlen($html); }
		}
		sort($img); sort($page);
		printf("captcha level %d  (%d %s, %s warp, %s noise, %s overlap)  image p50=%.0fus p99=%.0fus | whole page p50=%.0fus p99=%.0fus  html=%d bytes  (php %s)\n", $lv, $pp['length'], $pp['charset'], $pp['warp'], $pp['noise'], $pp['overlap'],
			$img[(int)(0.5 * count($img))], $img[(int)(0.99 * count($img))], $page[(int)(0.5 * count($page))], $page[(int)(0.99 * count($page))], $bytes, PHP_VERSION);
	}
	$bench_cleanup();
	exit;
}
if ($list_lookup) {
	// The IP list lookup alone (both files, no match): a fresh request (reset state, open + search both
	// files) and the search with the files already open. Addresses are random, IPv4 and IPv6 mixed 10:1.
	mt_srand(13);
	$rand_ip = function () { return mt_rand(0, 10) === 0 ? '2001:db8:' . dechex(mt_rand(0, 65535)) . '::' . dechex(mt_rand(1, 65535)) : long2ip(mt_rand(16777216, 4278190080)); };
	$warm = array(); $cold = array();
	gv_iplist_check('1.1.1.1');
	for ($i = 0; $i < 20000; $i++) { $ip = $rand_ip(); $t = hrtime(true); gv_iplist_check($ip); $warm[] = (hrtime(true) - $t) / 1000; }
	for ($i = 0; $i < 10000; $i++) { $ip = $rand_ip(); gv_geo_state(true); $t = hrtime(true); gv_iplist_check($ip); $cold[] = (hrtime(true) - $t) / 1000; }
	// And the "no enabled list" cost: both files absent.
	putenv('GV_LISTS_DIR=' . $tmp . '/nolists');
	$none = array();
	for ($i = 0; $i < 10000; $i++) { gv_geo_state(true); $t = hrtime(true); gv_iplist_check('203.0.113.9'); $none[] = (hrtime(true) - $t) / 1000; }
	sort($warm); sort($cold); sort($none);
	$p = function ($a, $q) { return $a[(int)($q * count($a))]; };
	printf("iplist lookup %d+%d ranges per type, " . (count($list_types) === 1 ? 'block only' : 'allow+block') . "  fresh request (open+search) p50=%.1fus p99=%.1fus max=%.0fus | files open p50=%.1fus p99=%.1fus | no lists p50=%.1fus p99=%.1fus  (php %s)\n",
		$n4, $n6, $p($cold, 0.5), $p($cold, 0.99), end($cold), $p($warm, 0.5), $p($warm, 0.99), $p($none, 0.5), $p($none, 0.99), PHP_VERSION);
	$bench_cleanup();
	exit;
}
if ($lookup_only) {
	// The GeoIP lookup alone: p50/p99 of gv_geo_country() over random addresses (the file
	// already open, as for every request after the first lookup), and of a first lookup
	// in a fresh request (fopen + header + size check + search).
	mt_srand(11);
	$warm = array(); $cold = array();
	gv_geo_country('1.1.1.1');
	for ($i = 0; $i < 20000; $i++) {
		$ip = long2ip(mt_rand(16777216, 4278190080));
		$t = hrtime(true); gv_geo_country($ip); $warm[] = (hrtime(true) - $t) / 1000;
	}
	for ($i = 0; $i < 5000; $i++) {
		$ip = long2ip(mt_rand(16777216, 4278190080));
		gv_geo_state(true);
		$t = hrtime(true); gv_geo_country($ip); $cold[] = (hrtime(true) - $t) / 1000;
	}
	sort($warm); sort($cold);
	printf("geo lookup ranges=%d  warm p50=%.1fus p99=%.1fus max=%.0fus | fresh request (open+lookup) p50=%.1fus p99=%.1fus max=%.0fus  (php %s)\n",
		$granges, $warm[(int)(0.5 * count($warm))], $warm[(int)(0.99 * count($warm))], end($warm),
		$cold[(int)(0.5 * count($cold))], $cold[(int)(0.99 * count($cold))], end($cold), PHP_VERSION);
	$bench_cleanup();
	exit;
}

$_COOKIE = array('_gv' => gv_tok_make($cfg['secret'], '', ($cap_match && function_exists('gv_tok_parse')) ? 'c' : 'p'));
$samples = array();
for ($i = 0; $i < $n + 300; $i++) {
	$_SERVER = array('REMOTE_ADDR' => '203.0.113.' . (1 + ($i % 200)), 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/p/' . $i,
		'QUERY_STRING' => '', 'HTTP_USER_AGENT' => $ua, 'HTTP_ACCEPT' => 'text/html', 'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.9',
		'HTTP_SEC_FETCH_MODE' => 'navigate', 'HTTP_HOST' => 'x', 'HTTP_ACCEPT_ENCODING' => 'gzip', 'HTTP_CONNECTION' => 'keep-alive',
		'HTTP_COOKIE' => '_gv=' . $_COOKIE['_gv']);
	if (function_exists('gv_geo_state')) { gv_geo_state(true); }     // a fresh request: nothing carried over
	$t = hrtime(true);
	gv_run(microtime(true));
	$us = (hrtime(true) - $t) / 1000;
	if ($i >= 300) { $samples[] = $us; }     // 300 warm-up requests are discarded
}
sort($samples);
$pct = function ($p) use ($samples) { return $samples[(int)min(count($samples) - 1, floor($p * count($samples)))]; };
printf("rules=%d%s%s%s values=%d%s n=%d  p50=%.0fus  p99=%.0fus  max=%.0fus  (php %s)\n", $nrules, $ngeo ? ' geo' . ($geoua ? '+ua' : '') : '', $geolog ? ' geo.log' : '', $lists_spec ? ' iplists=' . $lists_spec[0] . '+' . $lists_spec[1] . (count($list_types) === 1 ? ' block-only' : ' allow+block') : '' . ($cap_match ? ' captcha-rule-matches(c-token)' : ($cap_rules ? ' captcha-rules' : '')), $nvals, $regex ? ' regex' : '', count($samples),
	$pct(0.5), $pct(0.99), end($samples), PHP_VERSION);
$bench_cleanup();
