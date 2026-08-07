<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }

// Request flow and decision logic.
// Superglobals are read in exactly one place (the facts step of gv_run).
// Everything below that point receives explicit parameters, so scoring,
// CIDR matching and client-IP resolution stay pure and unit-testable.

require_once __DIR__ . '/redis.php';
require_once __DIR__ . '/log.php';
require_once __DIR__ . '/challenge.php';

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

// Load the active config: GV_CONFIG env override, else guard/config.php.
// Safety rule: an unconfigured secret forces monitor mode.
function gv_cfg_load() {
	$path = getenv('GV_CONFIG');
	if (!is_string($path) || $path === '' || !is_file($path)) {
		$path = __DIR__ . '/config.php';
	}
	$cfg = require $path;
	if (!is_array($cfg)) { $cfg = array(); }
	$cfg = gv_cfg_defaults($cfg);
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
function gv_bump($conn, $key, $window) {
	if (!$conn) { return 0; }
	$n = gv_r_incr($conn, $key);
	if ($n === false || $n === null) { return 0; }
	$n = (int)$n;
	if ($n === 1) { gv_r_expire($conn, $key, $window); }
	return $n;
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

// Fold the Phase 2 verdicts into the static score. Pure.
//
// Shadow-first: each signal is only ADDED when its toggle is on. With both
// toggles off the effective score equals the static score exactly, so the
// verdicts are visible in the logs long before they can change an outcome.
// BOT_FAKE is deliberately not gated here - it is already part of the static
// score, because an impersonator is a hard signal, not a shadow one.
function gv_effective_score($sc, $rep, $ml, array $cfg) {
	$esc = (int)$sc;
	if (!empty($cfg['signals']['reputation']) && (int)$rep !== 0) {
		$esc += (int)$rep;
	}
	if (!empty($cfg['signals']['ml']) && (int)$ml >= 0) {
		$esc += (int)round((int)$ml * (float)$cfg['ml_weight']);
	}
	return $esc;
}

// Read an operator override. Returns 'allow', 'deny' or ''.
//
// Allow wins over deny: the operator's most specific intent is assumed to be
// the rescue, and a permissive override is the five-second fix when a real
// customer is stuck. Every read uses === '1' so a failed read is no signal.
function gv_override($conn, $ip, $dev) {
	if (!$conn) { return ''; }
	if ($dev !== '' && gv_r_get($conn, 'gv:allow:' . $dev) === '1') { return 'allow'; }
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
		return;
	}

	// 4. Redis. A failed connect means degraded mode, never a bypass.
	$conn = gv_redis_connect($cfg['redis']);
	if (!$conn) { $st['rd'] = 1; }

	// 5. Known bots. Still no live reverse DNS: DNS latency does not belong in
	// the request path. The Phase 2 analyzer verifies out of band and leaves a
	// verdict here, so this step costs one cheap GET.
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

	// 7b. Phase 2 verdicts for real users. Both are per device, because they
	// describe a browsing identity rather than an address.
	if ($st['dev'] !== '' && $conn) {
		$rep = gv_r_get($conn, 'gv:rep:' . $st['dev']);
		$st['rep'] = is_numeric($rep) ? (int)$rep : 0;
		$ml = gv_r_get($conn, 'gv:ml:' . $st['dev']);
		$st['ml'] = is_numeric($ml) ? (int)$ml : -1;
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
	$st['esc'] = gv_effective_score($st['sc'], $st['rep'], $st['ml'], $cfg);
	$nav       = gv_is_nav($f);
	$intended  = gv_decide($st['esc'], $over, $nav, $st['tok'], $cfg['hard_block_score'],
		$st['ovr']);

	// 11. Act. Every branch logs exactly one line.
	if ($intended === 'allow') {
		gv_emit($f, $st, 'allow', 0, $t0, $log);
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
	if ($st['hold'] === 1 && ($intended === '403' || $intended === 'challenge')) {
		// 429 is never held out: rate limiting is resource protection, not
		// classification, and the holdout must not become a way to hammer a site.
		$enforced = false;
	}

	if (!$enforced) {
		// Monitor mode or holdout: record what would have happened and allow.
		gv_emit($f, $st, $intended, 1, $t0, $log);
		return;
	}
	gv_emit($f, $st, $intended, 0, $t0, $log);
	if ($intended === '403') { gv_send_403(); exit; }
	if ($intended === '429') { gv_send_429(); exit; }
	gv_challenge_render(gv_nonce_make($cfg['secret']), $cfg['strings']);
	exit;
}

$gv_t0 = microtime(true);
if (PHP_SAPI !== 'cli') {
	try {
		gv_run($gv_t0);
	} catch (\Throwable $e) {
		// fail-open: never break the host application
	}
}
