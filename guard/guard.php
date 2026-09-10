<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }

// Request flow and decision logic.
// Superglobals are read in exactly one place (the facts step of gv_run).
// Everything below that point receives explicit parameters, so scoring,
// CIDR matching and client-IP resolution stay pure and unit-testable.

require_once __DIR__ . '/redis.php';
require_once __DIR__ . '/log.php';
require_once __DIR__ . '/challenge.php';
require_once __DIR__ . '/outcome.php';

// --------------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------------

// Merge a loaded config over the shipped defaults so a partial or damaged
// config file can never produce a missing-key notice in the request path.
function gv_cfg_defaults(array $cfg) {
	$d = array(
		'secret'           => 'CHANGE_ME',
		'cookie_name'      => '_gv',
		'token_ttl'        => 604800,
		'nonce_ttl'        => 120,
		'hard_block_score' => 60,
		'honeypot_path'    => '/old-archive',
		'exempt_paths'     => array(),
		'exempt_params'    => array(),
		'known_bots'       => array(),
		'cdn_ranges'       => array(),
		'log_dir'          => dirname(__DIR__) . '/logs',
		'ml_weight'        => 0.4,
		'clf_weight'       => 0.5,
		'holdout_pct'      => 0,
		'holdout_salt'     => 'CHANGE_ME_TOO',
		'capture_outcomes' => false,
		'bot_suffixes'     => array(
			'googlebot' => array('.googlebot.com', '.google.com'),
			'bingbot'   => array('.search.msn.com'),
		),
	);
	foreach ($d as $k => $v) {
		if (!isset($cfg[$k])) { $cfg[$k] = $v; }
	}
	$enforce = array('block' => false, 'challenge' => false, 'ratelimit' => false);
	if (!isset($cfg['enforce']) || !is_array($cfg['enforce'])) { $cfg['enforce'] = array(); }
	$cfg['enforce'] = array_merge($enforce, $cfg['enforce']);
	// Phase 2 signals merge exactly like enforce, so a Phase 1 config file
	// without them keeps working and stays in shadow.
	$signals = array('reputation' => false, 'ml' => false, 'clf' => false);
	if (!isset($cfg['signals']) || !is_array($cfg['signals'])) { $cfg['signals'] = array(); }
	$cfg['signals'] = array_merge($signals, $cfg['signals']);
	$limits = array('window' => 300, 'device' => 150, 'ip_ua' => 400, 'ip' => 1200, 'bot' => 600);
	if (!isset($cfg['limits']) || !is_array($cfg['limits'])) { $cfg['limits'] = array(); }
	$cfg['limits'] = array_merge($limits, $cfg['limits']);
	$redis = array('host' => '127.0.0.1', 'port' => 6379, 'timeout' => 0.05);
	if (!isset($cfg['redis']) || !is_array($cfg['redis'])) { $cfg['redis'] = array(); }
	$cfg['redis'] = array_merge($redis, $cfg['redis']);
	$strings = array(
		'lang'     => 'en',
		'dir'      => 'ltr',
		'title'    => 'Please wait a moment...',
		'sub'      => 'We are checking your browser.',
		'noscript' => 'Please enable JavaScript and cookies to continue.',
	);
	if (!isset($cfg['strings']) || !is_array($cfg['strings'])) { $cfg['strings'] = array(); }
	$cfg['strings'] = array_merge($strings, $cfg['strings']);
	foreach (array('exempt_paths', 'exempt_params', 'known_bots', 'cdn_ranges', 'bot_suffixes') as $k) {
		if (!is_array($cfg[$k])) { $cfg[$k] = array(); }
	}
	return $cfg;
}

// --------------------------------------------------------------------------
// Config overlay (Phase 5)
//
// guard/config.local.json is a flat JSON object of dotted keys, written only by
// the admin panel. It lives here rather than in panel/ for two reasons: the
// panel is optional and deleting it must change nothing, and the validation
// applied when the panel WRITES a key has to be the same code that runs when
// the guard READS it - not a copy that can drift.
//
// secret, holdout_salt and the panel credentials are deliberately absent from
// the whitelist. There is no UI for them and no overlay path to them.
// --------------------------------------------------------------------------

// Overlay whitelist: dotted key => (type, min, max). Anything not listed here
// is discarded on read and refused on write.
function gv_overlay_whitelist() {
	return array(
		'enforce.block'      => array('bool'),
		'enforce.challenge'  => array('bool'),
		'enforce.ratelimit'  => array('bool'),
		'signals.reputation' => array('bool'),
		'signals.ml'         => array('bool'),
		'signals.clf'        => array('bool'),
		'hard_block_score'   => array('int', 10, 200),
		'ml_weight'          => array('float', 0.0, 2.0),
		'clf_weight'         => array('float', 0.0, 2.0),
		'limits.window'      => array('int', 30, 3600),
		'limits.device'      => array('int', 1, 100000),
		'limits.ip_ua'       => array('int', 1, 100000),
		'limits.ip'          => array('int', 1, 100000),
		'limits.bot'         => array('int', 1, 100000),
		'holdout_pct'        => array('int', 0, 5),
		'capture_outcomes'   => array('bool'),
		'exempt_paths'       => array('paths'),
		'exempt_params'      => array('params'),
		'known_bots'         => array('bots'),
		'honeypot_path'      => array('hppath'),
	);
}

// Validate one overlay value. Returns array(ok, value_or_error_code).
// Out-of-range values are REJECTED, never clamped: silently clamping a number
// the operator typed hides the mistake instead of reporting it.
function gv_overlay_validate($key, $value) {
	$rules = gv_overlay_whitelist();
	if (!isset($rules[$key])) { return array(false, 'unknown_key'); }
	$spec = $rules[$key];
	$type = $spec[0];

	if ($type === 'bool') {
		if (!is_bool($value)) { return array(false, 'not_bool'); }
		return array(true, $value);
	}
	if ($type === 'int') {
		if (is_bool($value) || !is_int($value)) { return array(false, 'not_int'); }
		if ($value < $spec[1] || $value > $spec[2]) { return array(false, 'out_of_range'); }
		return array(true, $value);
	}
	if ($type === 'float') {
		if (is_bool($value) || (!is_int($value) && !is_float($value))) {
			return array(false, 'not_number');
		}
		$value = (float)$value;
		if (!is_finite($value)) { return array(false, 'not_number'); }
		if ($value < $spec[1] || $value > $spec[2]) { return array(false, 'out_of_range'); }
		return array(true, $value);
	}
	if ($type === 'paths') {
		if (!is_array($value) || gv_is_assoc($value)) { return array(false, 'not_list'); }
		if (count($value) > 50) { return array(false, 'too_many'); }
		$out = array();
		foreach ($value as $entry) {
			if (!is_string($entry) || $entry === '') { return array(false, 'not_string'); }
			if (strlen($entry) > 200) { return array(false, 'too_long'); }
			if (substr($entry, 0, 1) !== '/') { return array(false, 'must_start_slash'); }
			$out[] = $entry;
		}
		return array(true, $out);
	}
	if ($type === 'params') {
		if (!is_array($value)) { return array(false, 'not_map'); }
		if (count($value) > 20) { return array(false, 'too_many'); }
		$out = array();
		foreach ($value as $name => $values) {
			if (!is_string($name) || $name === '' || strlen($name) > 100) {
				return array(false, 'bad_param_name');
			}
			if (!is_array($values) || gv_is_assoc($values)) { return array(false, 'not_list'); }
			if (count($values) > 50) { return array(false, 'too_many'); }
			$clean = array();
			foreach ($values as $entry) {
				if (!is_string($entry) || $entry === '') { return array(false, 'not_string'); }
				if (strlen($entry) > 200) { return array(false, 'too_long'); }
				$clean[] = $entry;
			}
			$out[$name] = $clean;
		}
		return array(true, $out);
	}
	if ($type === 'bots') {
		if (!is_array($value) || gv_is_assoc($value)) { return array(false, 'not_list'); }
		if (count($value) > 20) { return array(false, 'too_many'); }
		$out = array();
		foreach ($value as $entry) {
			if (!is_string($entry) || $entry === '') { return array(false, 'not_string'); }
			if (!preg_match('/^[a-z0-9._-]+$/', $entry)) { return array(false, 'bad_charset'); }
			$out[] = $entry;
		}
		return array(true, $out);
	}
	if ($type === 'hppath') {
		if (!is_string($value) || $value === '') { return array(false, 'not_string'); }
		if (strlen($value) > 100) { return array(false, 'too_long'); }
		if (substr($value, 0, 1) !== '/') { return array(false, 'must_start_slash'); }
		return array(true, $value);
	}
	return array(false, 'unknown_type');
}

// True when an array has any non-sequential key, i.e. it is a map not a list.
function gv_is_assoc(array $value) {
	$i = 0;
	foreach ($value as $k => $_v) {
		if ($k !== $i) { return true; }
		$i++;
	}
	return false;
}

// Read and validate the overlay. Returns a flat array of accepted dotted keys.
//
// Every failure path returns an empty array or drops the offending key alone.
// A missing, unreadable, malformed or non-object file is ignored in silence:
// the panel must never be able to take the guard down by writing a bad file,
// and a warning here could reach output on the allow path.
function gv_overlay_read($path) {
	try {
		if (!is_string($path) || $path === '' || !is_file($path)) { return array(); }
		$raw = @file_get_contents($path);
		if ($raw === false || $raw === '' || strlen($raw) > 262144) { return array(); }
		$data = json_decode($raw, true);
		if (!is_array($data) || !gv_is_assoc($data)) {
			// A JSON list, scalar or null is not an overlay object.
			if ($data !== array()) { return array(); }
			return array();
		}
		$out = array();
		foreach ($data as $key => $value) {
			if (!is_string($key)) { continue; }
			$check = gv_overlay_validate($key, $value);
			if ($check[0]) { $out[$key] = $check[1]; }   // one bad key, not the file
		}
		return $out;
	} catch (\Throwable $e) {
		return array();
	}
}

// Apply a validated flat overlay onto a config array, resolving dotted keys.
function gv_overlay_apply(array $cfg, array $flat) {
	foreach ($flat as $key => $value) {
		$parts = explode('.', $key);
		if (count($parts) === 1) {
			$cfg[$parts[0]] = $value;
		} elseif (count($parts) === 2) {
			if (!isset($cfg[$parts[0]]) || !is_array($cfg[$parts[0]])) {
				$cfg[$parts[0]] = array();
			}
			$cfg[$parts[0]][$parts[1]] = $value;
		}
	}
	return $cfg;
}

function gv_overlay_path() {
	return __DIR__ . '/config.local.json';
}

// Load the active config: GV_CONFIG env override, else guard/config.php,
// then the panel's JSON overlay on top.
// Safety rule: an unconfigured secret forces monitor mode.
function gv_cfg_load() {
	$path = getenv('GV_CONFIG');
	if (!is_string($path) || $path === '' || !is_file($path)) {
		$path = __DIR__ . '/config.php';
	}
	$cfg = require $path;
	if (!is_array($cfg)) { $cfg = array(); }
	$cfg = gv_cfg_defaults($cfg);
	// Merge order: shipped defaults -> PHP config -> JSON overlay.
	$cfg = gv_overlay_apply($cfg, gv_overlay_read(gv_overlay_path()));
	if ((string)$cfg['secret'] === 'CHANGE_ME') {
		$cfg['enforce']['block']     = false;
		$cfg['enforce']['challenge'] = false;
		$cfg['enforce']['ratelimit'] = false;
	}
	return $cfg;
}

// --------------------------------------------------------------------------
// Pure helpers
// --------------------------------------------------------------------------

// IPv4 CIDR membership. Invalid input returns false, never an exception.
function gv_cidr_match($ip, $cidr) {
	if (!is_string($ip) || !is_string($cidr)) { return false; }
	$pos = strpos($cidr, '/');
	if ($pos === false) {
		$net  = $cidr;
		$bits = 32;
	} else {
		$net  = substr($cidr, 0, $pos);
		$tail = substr($cidr, $pos + 1);
		if ($tail === '' || !ctype_digit($tail)) { return false; }
		$bits = (int)$tail;
	}
	if ($bits < 0 || $bits > 32) { return false; }
	if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) { return false; }
	if (filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) { return false; }
	if ($bits === 0) { return true; }
	$a = ip2long($ip);
	$b = ip2long($net);
	if ($a === false || $b === false) { return false; }
	$mask = (0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF;
	return (($a & $mask) === ($b & $mask));
}

// Resolve the client IP. X-Forwarded-For is trusted only when REMOTE_ADDR is
// inside a configured CDN range, and then only its LAST entry (the hop the CDN
// itself observed); earlier entries are client-controlled and forgeable.
function gv_client_ip(array $server, array $cdn_ranges) {
	$remote = isset($server['REMOTE_ADDR']) ? (string)$server['REMOTE_ADDR'] : '';
	if ($remote === '' || empty($cdn_ranges)) { return $remote; }
	$trusted = false;
	foreach ($cdn_ranges as $cidr) {
		if (gv_cidr_match($remote, $cidr)) { $trusted = true; break; }
	}
	if (!$trusted) { return $remote; }
	$xff = isset($server['HTTP_X_FORWARDED_FOR']) ? (string)$server['HTTP_X_FORWARDED_FOR'] : '';
	if ($xff === '') { return $remote; }
	$parts = explode(',', $xff);
	$last  = trim($parts[count($parts) - 1]);
	if ($last === '' || filter_var($last, FILTER_VALIDATE_IP) === false) { return $remote; }
	return $last;
}

// Count request headers: getallheaders() when the SAPI provides it, else the
// HTTP_* entries of the server array.
function gv_header_count(array $server) {
	if (function_exists('getallheaders')) {
		$h = @getallheaders();
		if (is_array($h) && count($h) > 0) { return count($h); }
	}
	$n = 0;
	foreach ($server as $k => $v) {
		if (strncmp($k, 'HTTP_', 5) === 0) { $n++; }
	}
	return $n;
}

// Gather every fact the guard needs from the request. The only caller passes
// the superglobals; every other function takes this array.
function gv_facts(array $server, array $get, array $cookie, array $cfg) {
	$uri  = isset($server['REQUEST_URI']) ? (string)$server['REQUEST_URI'] : '/';
	$path = parse_url($uri, PHP_URL_PATH);
	if (!is_string($path) || $path === '') { $path = '/'; }
	$https = false;
	if (!empty($server['HTTPS']) && strtolower((string)$server['HTTPS']) !== 'off') { $https = true; }
	if (isset($server['HTTP_X_FORWARDED_PROTO']) && strtolower((string)$server['HTTP_X_FORWARDED_PROTO']) === 'https') { $https = true; }
	$name = (string)$cfg['cookie_name'];
	return array(
		'rid'     => gv_rid(),
		'ip'      => gv_client_ip($server, $cfg['cdn_ranges']),
		'method'  => isset($server['REQUEST_METHOD']) ? strtoupper((string)$server['REQUEST_METHOD']) : 'GET',
		'path'    => $path,
		'query'   => isset($server['QUERY_STRING']) ? (string)$server['QUERY_STRING'] : '',
		'params'  => $get,
		'ua'      => isset($server['HTTP_USER_AGENT']) ? (string)$server['HTTP_USER_AGENT'] : '',
		'accept'  => isset($server['HTTP_ACCEPT']) ? (string)$server['HTTP_ACCEPT'] : '',
		'al'      => isset($server['HTTP_ACCEPT_LANGUAGE']) ? (string)$server['HTTP_ACCEPT_LANGUAGE'] : '',
		'sf'      => isset($server['HTTP_SEC_FETCH_MODE']) ? (string)$server['HTTP_SEC_FETCH_MODE'] : '',
		'xrw'     => isset($server['HTTP_X_REQUESTED_WITH']) ? (string)$server['HTTP_X_REQUESTED_WITH'] : '',
		'xgv'     => isset($server['HTTP_X_GV']) ? (string)$server['HTTP_X_GV'] : '',
		'referer' => isset($server['HTTP_REFERER']) ? (string)$server['HTTP_REFERER'] : '',
		'hc'      => gv_header_count($server),
		'https'   => $https,
		'cookie'  => isset($cookie[$name]) ? (string)$cookie[$name] : '',
	);
}

// AJAX: an explicit X-Requested-With, or a GET whose Accept does not ask for HTML.
function gv_is_ajax(array $f) {
	if ((string)$f['xrw'] !== '') { return true; }
	if ((string)$f['method'] === 'GET' && stripos((string)$f['accept'], 'text/html') === false) { return true; }
	return false;
}

// Navigation: a top-level HTML page load. Sec-Fetch-Mode: navigate strengthens
// the signal but its absence never negates it (old browsers do not send it).
function gv_is_nav(array $f) {
	if ((string)$f['method'] !== 'GET') { return false; }
	if (stripos((string)$f['accept'], 'text/html') === false) { return false; }
	if (gv_is_ajax($f)) { return false; }
	return true;
}

// Major version claimed by a modern browser UA, or 0 when none is claimed.
function gv_ua_modern_major($ua) {
	$m = array();
	if (preg_match('#(?:Chrome|Firefox|Edg)/(\d+)#i', (string)$ua, $m)) { return (int)$m[1]; }
	return 0;
}

// Static request scoring. Returns array(score, reasons[]). Pure.
function gv_score(array $f, $hp_hist) {
	$score   = 0;
	$reasons = array();
	$ua      = isset($f['ua']) ? (string)$f['ua'] : '';
	if (trim($ua) === '') {
		$score += 40;
		$reasons[] = 'UA_EMPTY';
	}
	$lua = strtolower($ua);
	$sig = array(
		'python-requests', 'python-urllib', 'curl/', 'wget/', 'go-http-client',
		'scrapy', 'okhttp', 'libwww', 'httpclient', 'java/', 'node-fetch', 'axios/',
	);
	foreach ($sig as $s) {
		if ($lua !== '' && strpos($lua, $s) !== false) {
			$score += 30;
			$reasons[] = 'UA_SCRIPT';
			break;
		}
	}
	if (gv_is_nav($f) && (string)$f['al'] === '') {
		$score += 15;
		$reasons[] = 'NO_AL';
	}
	if (gv_ua_modern_major($ua) >= 80 && (string)$f['sf'] === '') {
		$score += 20;
		$reasons[] = 'NO_SF';
	}
	if ((int)$f['hc'] < 5) {
		$score += 15;
		$reasons[] = 'FEW_HDR';
	}
	if ($hp_hist) {
		$score += 40;
		$reasons[] = 'HP_HIST';
	}
	return array($score, $reasons);
}

// Exemption test: path prefix, or a configured query parameter whose value
// prefix-matches. Pure.
function gv_is_exempt(array $f, array $exempt_paths, array $exempt_params) {
	$path = (string)$f['path'];
	foreach ($exempt_paths as $p) {
		$p = (string)$p;
		if ($p !== '' && strncmp($path, $p, strlen($p)) === 0) { return true; }
	}
	$params = isset($f['params']) && is_array($f['params']) ? $f['params'] : array();
	foreach ($exempt_params as $name => $prefixes) {
		if (!isset($params[$name]) || !is_string($params[$name])) { continue; }
		$value = $params[$name];
		foreach ((array)$prefixes as $pre) {
			$pre = (string)$pre;
			if ($pre !== '' && strncmp($value, $pre, strlen($pre)) === 0) { return true; }
		}
	}
	return false;
}

// Known-bot UA match. Returns the matched name or "". Pure.
function gv_match_bot($ua, array $known_bots) {
	$lua = strtolower((string)$ua);
	if ($lua === '') { return ''; }
	foreach ($known_bots as $b) {
		$b = strtolower((string)$b);
		if ($b !== '' && strpos($lua, $b) !== false) { return $b; }
	}
	return '';
}

// Fixed-window counter. Returns the current count, or 0 in degraded mode.
//
// The first write uses SET key 1 EX window NX, which sets the value and the
// expiry atomically: the key can never exist without a TTL. The old
// INCR-then-EXPIRE sequence left a TTL-less key behind if the process died or
// EXPIRE failed between the two commands, and once such a key crossed the limit
// the identity was 429'd forever. Subsequent hits INCR the key that already
// carries its TTL. Counting is unchanged (first hit 1, then 2, 3, ...) and a
// failed read still folds to 0 (fail-open).
function gv_bump($conn, $key, $window) {
	if (!$conn) { return 0; }
	$set = gv_r_set_nx_ex($conn, $key, $window, 1);
	if ($set === 'OK') { return 1; }              // created with a TTL in one command
	$n = gv_r_incr($conn, $key);                  // already existed
	if ($n === false || $n === null) { return 0; }
	return (int)$n;
}

// --------------------------------------------------------------------------
// Logging
// --------------------------------------------------------------------------

// Build the log row in the documented key order. Pure.
function gv_log_row(array $f, array $st, $act, $sh, $t0) {
	$ua  = (string)$f['ua'];
	$ref = '';
	if ((string)$f['referer'] !== '') {
		$host = parse_url((string)$f['referer'], PHP_URL_HOST);
		if (is_string($host)) { $ref = gv_cut($host, 100); }
	}
	return array(
		'v'   => 4,
		'rid' => isset($f['rid']) ? (string)$f['rid'] : '',
		'ts'  => round(microtime(true), 3),
		'ip'  => (string)$f['ip'],
		'ua'  => gv_cut($ua, 120),
		'uah' => substr(md5($ua), 0, 12),
		'm'   => (string)$f['method'],
		'p'   => gv_cut((string)$f['path'], 200),
		'q'   => gv_cut((string)$f['query'], 100),
		'aj'  => gv_is_ajax($f) ? 1 : 0,
		'nav' => gv_is_nav($f) ? 1 : 0,
		'tok' => (string)$st['tok'],
		'dev' => (string)$st['dev'],
		'sf'  => (string)$f['sf'],
		'al'  => ((string)$f['al'] !== '') ? 1 : 0,
		'hc'  => (int)$f['hc'],
		'sc'  => (int)$st['sc'],
		'esc' => (int)$st['esc'],
		'rs'  => array_values($st['rs']),
		'cd'  => (int)$st['cd'],
		'ciu' => (int)$st['ciu'],
		'ci'  => (int)$st['ci'],
		'rd'  => (int)$st['rd'],
		'hp'  => (int)$st['hp'],
		'bot' => (string)$st['bot'],
		'ref' => $ref,
		'botv' => (string)$st['botv'],
		'rep' => (int)$st['rep'],
		'ml'  => (int)$st['ml'],
		'clf' => (int)$st['clf'],
		'hold' => (int)$st['hold'],
		'ovr' => (string)$st['ovr'],
		'act' => (string)$act,
		'sh'  => (int)$sh,
		'ms'  => round((microtime(true) - $t0) * 1000, 2),
	);
}

// Emit the single log line for this request.
function gv_emit(array $f, array $st, $act, $sh, $t0, $log_dir) {
	gv_log(gv_log_row($f, $st, $act, $sh, $t0), $log_dir);
}

// Arm outcome capture. Called immediately before every gv_run() path that
// RETURNS, and before none that exits.
//
// The distinction is the whole point: a return means the host application is
// about to run and produce a response nobody has recorded yet. An exit means
// the guard produced the response itself, and gv_log_row already recorded what
// it was in act - a second line describing our own 403 would be noise.
function gv_arm_outcome(array $cfg, array $f, $log_dir) {
	if (empty($cfg['capture_outcomes'])) { return; }
	gv_capture_outcome(isset($f['rid']) ? $f['rid'] : '', $log_dir);
}

// Default per-request state, filled in as the flow progresses.
// botv/rep/ml/clf carry the offline verdicts: '' means no bot verdict was read,
// 0 is a neutral reputation, and -1 means no level was available.
// hold marks a request in the measured-but-never-enforced slice; ovr records an
// operator override.
function gv_state_new() {
	return array(
		'tok' => 'm', 'dev' => '', 'sc' => 0, 'rs' => array(),
		'cd'  => 0, 'ciu' => 0, 'ci' => 0, 'rd' => 0, 'hp' => 0, 'bot' => '',
		'botv' => '', 'rep' => 0, 'ml' => -1, 'clf' => -1, 'esc' => 0,
		'hold' => 0, 'ovr' => '',
	);
}

// --------------------------------------------------------------------------
// Phase 2 verdicts
// --------------------------------------------------------------------------

// Read the offline bot verification verdict for an address.
// Returns 'bad', 'ok' or '' (no verdict / degraded mode). A bad verdict wins.
//
// The === '1' comparison is load-bearing: gv_r_get returns the string on a hit,
// null on a miss and FALSE on a command error or read timeout. Comparing
// against null treated a stalled Redis as a bad verdict, which stamped
// BOT_FAKE (+35) on a real crawler that will never solve a challenge. A read
// that failed is no signal at all.
function gv_bot_verdict($conn, $ip) {
	if (!$conn) { return ''; }
	if (gv_r_get($conn, 'gv:botbad:' . $ip) === '1') { return 'bad'; }
	if (gv_r_get($conn, 'gv:botok:' . $ip) === '1') { return 'ok'; }
	return '';
}

// --------------------------------------------------------------------------
// Phase 3 holdout
// --------------------------------------------------------------------------

// Deterministic holdout membership. Identity is the device id when the client
// has one, else its address. Returns false whenever holdout is disabled.
//
// Determinism is the whole point: an identity that flickered in and out of the
// holdout between requests would give useless measurements and an erratic
// experience. The 5% ceiling is deliberate - this is a measurement sample, not
// a bypass, and every request inside it is traffic nobody is protected from.
// The & 0x7FFFFFFF is not decoration: crc32 returns a signed int, and on a
// 32-bit PHP build roughly half of all identities hash negative, where the
// modulo is also negative and the comparison is always true. That would put
// half the traffic in the holdout instead of the configured few percent -
// exactly the bypass the clamp exists to prevent. Masking the sign bit costs
// one bit of a CRC and keeps the distribution uniform on every build.
function gv_is_holdout($ident, $salt, $pct) {
	$pct = (int)$pct;
	if ($pct <= 0 || (string)$ident === '') { return false; }
	if ($pct > 5) { $pct = 5; }
	return ((crc32((string)$salt . '|' . (string)$ident) & 0x7FFFFFFF) % 10000) < ($pct * 100);
}

// Fold the offline verdicts into the static score. Pure.
//
// Shadow-first: each signal is only ADDED when its toggle is on. With every
// toggle off the effective score equals the static score exactly, so the
// verdicts are visible in the logs long before they can change an outcome.
// BOT_FAKE is deliberately not gated here - it is already part of the static
// score, because an impersonator is a hard signal, not a shadow one.
//
// The signature stays plain values on purpose: this function is mirrored in
// analyzer/decision.py and parity-tested case by case against it.
function gv_effective_score($sc, $rep, $ml, $clf, array $cfg) {
	$esc = (int)$sc;
	if (!empty($cfg['signals']['reputation']) && (int)$rep !== 0) {
		$esc += (int)$rep;
	}
	if (!empty($cfg['signals']['ml']) && (int)$ml >= 0) {
		$esc += (int)round((int)$ml * (float)$cfg['ml_weight']);
	}
	if (!empty($cfg['signals']['clf']) && (int)$clf >= 0) {
		$esc += (int)round((int)$clf * (float)$cfg['clf_weight']);
	}
	return $esc;
}

// Read an operator override. Returns 'allow', 'deny' or ''.
//
// Allow wins over deny: the operator's most specific intent is assumed to be
// the rescue, and a permissive override is the five-second fix when a real
// customer is stuck. Every read uses === '1' so a failed read is no signal.
//
// Both allow-by-device and allow-by-ip are honoured: a stuck customer who never
// completed the handshake has only an IP (no device id), and allow-by-ip is the
// documented rescue for that case. The per-device allow is checked first so a
// device allow still overrides an IP deny for the same client, and the IP allow
// is checked before the IP deny so allow-wins holds for IP identities too.
function gv_override($conn, $ip, $dev) {
	if (!$conn) { return ''; }
	if ($dev !== '' && gv_r_get($conn, 'gv:allow:' . $dev) === '1') { return 'allow'; }
	if ($ip  !== '' && gv_r_get($conn, 'gv:allow:' . $ip)  === '1') { return 'allow'; }
	if ($dev !== '' && gv_r_get($conn, 'gv:deny:' . $dev) === '1') { return 'deny'; }
	if (gv_r_get($conn, 'gv:deny:' . $ip) === '1') { return 'deny'; }
	return '';
}

// The Phase 1 decision, unchanged except that it now judges the effective
// score and honours a deny override. First match wins. Pure.
function gv_decide($esc, $over, $nav, $tok, $hard_block_score, $ovr) {
	if ($ovr === 'deny') { return '403'; }
	if ((int)$esc >= (int)$hard_block_score && $nav) { return '403'; }
	if ($over) { return '429'; }
	// Only navigations reach this rule, so POST, XHR and REST clients are
	// never challenged: payment callbacks and webhooks stay untouched.
	if ($nav && $tok !== 'v') { return 'challenge'; }
	return 'allow';
}

// Whether the holdout slice should suppress enforcement of the intended action.
// The holdout measures the guard's own classifier decisions without bias, so a
// held-out 403/challenge is recorded but not enforced. Two things are never
// suppressed: a 429 (resource protection, not a classification) and an explicit
// operator deny (an action, not a classification, and the documented manual
// block). Pure, so the gate stays testable in isolation.
function gv_holdout_suppresses($hold, $ovr, $intended) {
	if ((int)$hold !== 1) { return false; }
	if ($ovr === 'deny') { return false; }
	return $intended === '403' || $intended === 'challenge';
}

// --------------------------------------------------------------------------
// Responses
// --------------------------------------------------------------------------

function gv_send_403() {
	if (!headers_sent()) {
		http_response_code(403);
		header('Content-Type: text/plain; charset=utf-8');
		header('Cache-Control: no-store');
		header('X-Robots-Tag: noindex');
	}
	echo "403 Forbidden\n";
}

function gv_send_429() {
	if (!headers_sent()) {
		http_response_code(429);
		header('Retry-After: 60');
		header('Content-Type: text/plain; charset=utf-8');
		header('Cache-Control: no-store');
		header('X-Robots-Tag: noindex');
	}
	echo "429 Too Many Requests\n";
}

function gv_send_404() {
	if (!headers_sent()) {
		http_response_code(404);
		header('Content-Type: text/html; charset=utf-8');
		header('Cache-Control: no-store');
		header('X-Robots-Tag: noindex');
	}
	echo "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>404 Not Found</title></head>"
		. "<body><h1>404 Not Found</h1></body></html>\n";
}

// --------------------------------------------------------------------------
// Request flow
// --------------------------------------------------------------------------

function gv_run($t0) {
	// 1. Config and facts. The only place superglobals are read.
	$cfg = gv_cfg_load();
	$f   = gv_facts($_SERVER, $_GET, $_COOKIE, $cfg);
	$log = (string)$cfg['log_dir'];
	$st  = gv_state_new();

	// 2. Verify handshake intercept. Runs before exemptions so the challenge
	// page can always complete its own POST back to the same URL.
	if ($f['method'] === 'POST' && $f['xgv'] !== '') {
		if (gv_nonce_check($f['xgv'], $cfg['secret'], $cfg['nonce_ttl'])) {
			$token = gv_tok_make($cfg['secret']);
			$dev   = gv_tok_check($token, $cfg['secret'], $cfg['token_ttl']);
			gv_set_token_cookie($cfg, $token, $f['https']);
			$st['tok'] = 'v';
			$st['dev'] = ($dev === false) ? '' : $dev;
			gv_emit($f, $st, 'token_issued', 0, $t0, $log);
			if (!headers_sent()) { http_response_code(204); }
			exit;
		}
		gv_emit($f, $st, 'nonce_bad', 0, $t0, $log);
		if (!headers_sent()) { http_response_code(403); }
		exit;
	}

	// 3. Exemptions. CLI was already excluded by prepend.php.
	if (gv_is_exempt($f, $cfg['exempt_paths'], $cfg['exempt_params'])) {
		gv_emit($f, $st, 'exempt', 0, $t0, $log);
		gv_arm_outcome($cfg, $f, $log);
		return;
	}

	// 4. Redis. A failed connect means degraded mode, never a bypass.
	$conn = gv_redis_connect($cfg['redis']);
	if (!$conn) { $st['rd'] = 1; }

	// 5. Known bots. Still no live reverse DNS: DNS latency does not belong in
	// the request path. The Phase 2 analyzer verifies out of band and leaves a
	// verdict here, so this step costs one cheap GET.
	//
	// This pass runs BEFORE the honeypot check (step 6) by design: a UA claiming
	// a known bot takes the pass and is never honeypot-labelled until run_verify
	// writes a 'bad' verdict out of band. So the honeypot is not a defense
	// against fake-bot UAs - reordering it ahead of this would instead risk
	// honeypot-labelling real crawlers, which is the worse failure. See #17.
	$bot      = gv_match_bot($f['ua'], $cfg['known_bots']);
	$bot_over = false;
	$bot_fake = false;
	if ($bot !== '') {
		$st['bot'] = $bot;
		$verdict = gv_bot_verdict($conn, $f['ip']);
		if ($verdict === 'bad') {
			// An impersonator must be judged, not trusted. Revoke the pass and
			// fall through into normal scoring like any other client.
			$st['botv'] = 'bad';
			$bot_fake   = true;
		} else {
			if ($verdict === 'ok') { $st['botv'] = 'ok'; }
			if ($conn) {
				$n = gv_bump($conn, 'gv:rb:' . $f['ip'], $cfg['limits']['window']);
				if ($n > (int)$cfg['limits']['bot']) { $bot_over = true; }
			}
			if (!$bot_over) {
				gv_emit($f, $st, 'allow_bot', 0, $t0, $log);
				gv_redis_close($conn);
				gv_arm_outcome($cfg, $f, $log);
				return;
			}
		}
	}

	// 6. Honeypot. Fires regardless of the enforce toggles: it is labelling data.
	if ($f['path'] === (string)$cfg['honeypot_path']) {
		if ($conn) { gv_r_setex($conn, 'gv:hp:' . $f['ip'], 604800, '1'); }
		$st['hp'] = 1;
		gv_emit($f, $st, '404_hp', 0, $t0, $log);
		gv_redis_close($conn);
		gv_send_404();
		exit;
	}

	// 7. Token.
	if ($f['cookie'] !== '') {
		$dev = gv_tok_check($f['cookie'], $cfg['secret'], $cfg['token_ttl']);
		if ($dev === false) {
			$st['tok'] = 'b';
		} else {
			$st['tok'] = 'v';
			$st['dev'] = $dev;
		}
	}

	// 7b. Offline verdicts for real users. All three are per device, because
	// they describe a browsing identity rather than an address. is_numeric()
	// rejects both a miss (null) and a failed read (false), so a stalled Redis
	// leaves the neutral sentinels in place.
	if ($st['dev'] !== '' && $conn) {
		$rep = gv_r_get($conn, 'gv:rep:' . $st['dev']);
		$st['rep'] = is_numeric($rep) ? (int)$rep : 0;
		$ml = gv_r_get($conn, 'gv:ml:' . $st['dev']);
		$st['ml'] = is_numeric($ml) ? (int)$ml : -1;
		$clf = gv_r_get($conn, 'gv:clf:' . $st['dev']);
		$st['clf'] = is_numeric($clf) ? (int)$clf : -1;
	}

	// 7c. Operator overrides. An allow short-circuits everything below it: no
	// scoring, no counters, no challenge. It is deliberately not gated by any
	// enforce toggle, because a permissive override can only ever make the
	// guard less strict and must work the instant it is set.
	if ($conn) {
		$st['ovr'] = gv_override($conn, $f['ip'], $st['dev']);
		if ($st['ovr'] === 'allow') {
			gv_emit($f, $st, 'allow_override', 0, $t0, $log);
			gv_redis_close($conn);
			gv_arm_outcome($cfg, $f, $log);
			return;                               // zero bytes of output
		}
	}

	// 8. Static score. gv_score stays pure and Phase 1 shaped; the Phase 2
	// contributions are folded in below.
	$hp_hist = false;
	if ($conn && gv_r_get($conn, 'gv:hp:' . $f['ip']) === '1') { $hp_hist = true; }
	$scored    = gv_score($f, $hp_hist);
	$st['sc']  = $scored[0];
	$st['rs']  = $scored[1];
	if ($bot_fake) {
		// Part of the static score on purpose: it counts whatever the signal
		// toggles say, because a revoked bot claim is not a shadow signal.
		$st['sc'] += 35;
		$st['rs'][] = 'BOT_FAKE';
	}

	// 9. Rate counters. Skipped entirely in degraded mode; values stay 0.
	$over = $bot_over;
	if ($conn) {
		if ($st['dev'] !== '') {
			$st['cd'] = gv_bump($conn, 'gv:rd:' . $st['dev'], $cfg['limits']['window']);
			if ($st['cd'] > (int)$cfg['limits']['device']) { $over = true; }
		}
		$uah = substr(md5((string)$f['ua']), 0, 12);
		$st['ciu'] = gv_bump($conn, 'gv:riu:' . md5($f['ip'] . '|' . $uah), $cfg['limits']['window']);
		if ($st['ciu'] > (int)$cfg['limits']['ip_ua']) { $over = true; }
		$st['ci'] = gv_bump($conn, 'gv:ri:' . $f['ip'], $cfg['limits']['window']);
		if ($st['ci'] > (int)$cfg['limits']['ip']) { $over = true; }
	}
	gv_redis_close($conn);

	// 10. Decision, now judging the effective score.
	$st['esc'] = gv_effective_score($st['sc'], $st['rep'], $st['ml'], $st['clf'], $cfg);
	$nav       = gv_is_nav($f);
	$intended  = gv_decide($st['esc'], $over, $nav, $st['tok'], $cfg['hard_block_score'],
		$st['ovr']);

	// 11. Act. Every branch logs exactly one line.
	if ($intended === 'allow') {
		gv_emit($f, $st, 'allow', 0, $t0, $log);
		gv_arm_outcome($cfg, $f, $log);
		return;                                   // zero bytes of output
	}
	if ($intended === '403') {
		$enforced = !empty($cfg['enforce']['block']);
	} elseif ($intended === '429') {
		$enforced = !empty($cfg['enforce']['ratelimit']);
	} else {
		$enforced = !empty($cfg['enforce']['challenge']);
	}

	// Holdout: a small deterministic slice measured but never enforced against.
	// It is the only source of outcome data this system has not already biased
	// with its own gating, and the only way to estimate false negatives.
	// Applied at the gate, so the intended action is still computed and logged.
	$st['hold'] = gv_is_holdout(($st['dev'] !== '' ? $st['dev'] : $f['ip']),
		$cfg['holdout_salt'], $cfg['holdout_pct']) ? 1 : 0;
	if (gv_holdout_suppresses($st['hold'], $st['ovr'], $intended)) {
		// Recorded as would-have-happened and allowed: the holdout measures the
		// guard's own classifier decisions without enforcing them. An operator
		// deny is exempt (see gv_holdout_suppresses) and still enforces, subject
		// only to enforce.block, already applied above.
		$enforced = false;
	}

	if (!$enforced) {
		// Monitor mode or holdout: record what would have happened and allow.
		// The application runs, so this path is armed like any other allow -
		// and it is where the holdout's outcome data comes from.
		gv_emit($f, $st, $intended, 1, $t0, $log);
		gv_arm_outcome($cfg, $f, $log);
		return;
	}
	gv_emit($f, $st, $intended, 0, $t0, $log);
	if ($intended === '403') { gv_send_403(); exit; }
	if ($intended === '429') { gv_send_429(); exit; }
	gv_challenge_render(gv_nonce_make($cfg['secret']), $cfg['strings']);
	exit;
}

$gv_t0 = microtime(true);
// GV_NO_AUTORUN lets the admin panel load this file as a library - it needs
// gv_cfg_load() and the overlay validators, and must not run a request cycle
// on itself. prepend.php never defines it, so the guard still runs normally
// in front of the host application.
if (PHP_SAPI !== 'cli' && !defined('GV_NO_AUTORUN')) {
	try {
		gv_run($gv_t0);
	} catch (\Throwable $e) {
		// fail-open: never break the host application
	}
}
