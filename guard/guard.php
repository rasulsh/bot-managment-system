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
		'preview_bots'     => array(),
		// exempt_params only count on these exact paths: the front controller. On
		// any other path (an SEO URL) the parameter is something the client added.
		'exempt_params_paths' => array('/', '/index.php'),
		'cdn_ranges'       => array(),
		'log_dir'          => dirname(__DIR__) . '/logs',
		// Log storage. log_skip_paths: path prefixes never written to the log
		// (the guard still decides for them). The rest is read by
		// scripts/guard-logrotate.sh (retention, total size cap) and by the
		// logger (min free space, 0 = off).
		'log_skip_paths'   => array(),
		'log_retention_days' => 60,
		'log_max_mb'       => 0,
		'log_min_free_mb'  => 200,
		'ml_weight'        => 0.4,
		'clf_weight'       => 0.5,
		'holdout_pct'      => 0,
		'holdout_salt'     => 'CHANGE_ME_TOO',
		'capture_outcomes' => false,
		'bot_suffixes'     => array(
			'googlebot'             => array('.googlebot.com', '.google.com'),
			'adsbot-google'         => array('.googlebot.com', '.google.com'),
			'mediapartners-google'  => array('.googlebot.com', '.google.com'),
			'google-inspectiontool' => array('.googlebot.com', '.google.com'),
			'storebot-google'       => array('.googlebot.com', '.google.com'),
			'googleother'           => array('.googlebot.com', '.google.com'),
			'bingbot'               => array('.search.msn.com'),
			'adidxbot'              => array('.search.msn.com'),
			'bingpreview'           => array('.search.msn.com'),
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
	$limits = array('window' => 300, 'device' => 150, 'ip_ua' => 400, 'ip' => 1200, 'bot' => 600,
		'mint' => 300, 'device_hour' => 400, 'device_day' => 1500, 'preview' => 20,
		'bot_unverified' => 300);
	if (!isset($cfg['limits']) || !is_array($cfg['limits'])) { $cfg['limits'] = array(); }
	$cfg['limits'] = array_merge($limits, $cfg['limits']);
	// Challenge hardening. pow_bits is the proof-of-work difficulty (0 disables it);
	// bind_ip ties a nonce to the IP it was issued to.
	// trust_headers restores the old rule where only a GET that asks for HTML
	// is challenged; see gv_is_gate.
	$challenge = array('pow_bits' => 16, 'bind_ip' => true, 'trust_headers' => false,
		'gate_post' => false, 'test_key' => '');
	if (!isset($cfg['challenge']) || !is_array($cfg['challenge'])) { $cfg['challenge'] = array(); }
	$cfg['challenge'] = array_merge($challenge, $cfg['challenge']);
	$redis = array('host' => '127.0.0.1', 'port' => 6379, 'socket' => '',
		'username' => '', 'password' => '', 'db' => 0, 'prefix' => '',
		'timeout' => 0.05, 'breaker_ttl' => 5);
	if (!isset($cfg['redis']) || !is_array($cfg['redis'])) { $cfg['redis'] = array(); }
	$cfg['redis'] = array_merge($redis, $cfg['redis']);
	$strings = array(
		'lang'     => 'en',
		'dir'      => 'ltr',
		'title'    => 'Please wait a moment...',
		'sub'      => 'We are checking your browser.',
		'noscript' => 'Please enable JavaScript and cookies to continue.',
		'failed'   => 'We could not verify your browser.',
		'retry'    => 'Try again',
		'nocookie' => 'Your browser is not keeping cookies. Please enable cookies for this site and try again.',
	);
	if (!isset($cfg['strings']) || !is_array($cfg['strings'])) { $cfg['strings'] = array(); }
	$cfg['strings'] = array_merge($strings, $cfg['strings']);
	// config.php is hand-edited and nothing validated it: a typo in a limit either
	// blocked everybody ('device' => 0) or silently switched counting off (a
	// window Redis rejects). A limit that is not a positive whole number falls
	// back to its default, and so does a lifetime.
	foreach ($limits as $k => $v) {
		$cur = isset($cfg['limits'][$k]) ? $cfg['limits'][$k] : $v;
		$cfg['limits'][$k] = ((is_int($cur) || (is_string($cur) && ctype_digit($cur))) && (int)$cur >= 1) ? (int)$cur : $v;
	}
	foreach (array('token_ttl' => 604800, 'nonce_ttl' => 120) as $k => $v) {
		$cur = isset($cfg[$k]) ? $cfg[$k] : $v;
		$cfg[$k] = ((is_int($cur) || (is_string($cur) && ctype_digit($cur))) && (int)$cur >= 1) ? (int)$cur : $v;
	}
	// Log storage numbers: retention at least one day, the two MiB limits at
	// least 0 (0 = off). Anything else falls back to the default.
	foreach (array('log_retention_days' => array(60, 1), 'log_max_mb' => array(0, 0), 'log_min_free_mb' => array(200, 0)) as $k => $d) {
		$cur = isset($cfg[$k]) ? $cfg[$k] : $d[0];
		$cfg[$k] = ((is_int($cur) || (is_string($cur) && ctype_digit($cur))) && (int)$cur >= $d[1]) ? (int)$cur : $d[0];
	}
	// 'false' and 'off' are non-empty strings: without this they read as ON.
	foreach (array('enforce', 'signals') as $grp) {
		if (!isset($cfg[$grp]) || !is_array($cfg[$grp])) { continue; }
		foreach ($cfg[$grp] as $k => $v) {
			if (!is_bool($v)) { $cfg[$grp][$k] = (bool)filter_var($v, FILTER_VALIDATE_BOOLEAN); }
		}
	}
	foreach (array('exempt_paths', 'exempt_params', 'exempt_params_paths', 'known_bots', 'preview_bots', 'cdn_ranges', 'bot_suffixes', 'log_skip_paths') as $k) {
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
		'limits.mint'        => array('int', 1, 100000),
		'limits.device_hour' => array('int', 1, 1000000),
		'limits.device_day'  => array('int', 1, 1000000),
		'limits.preview'     => array('int', 1, 100000),
		'limits.bot_unverified' => array('int', 1, 100000),
		'challenge.gate_post' => array('bool'),
		'challenge.pow_bits' => array('int', 0, 22),
		'holdout_pct'        => array('int', 0, 5),
		'capture_outcomes'   => array('bool'),
		'exempt_paths'       => array('paths'),
		'exempt_params'      => array('params'),
		'known_bots'         => array('bots'),
		'preview_bots'       => array('bots'),
		'honeypot_path'      => array('hppath'),
		// Tokens and the challenge.
		'token_ttl'          => array('int', 3600, 2592000),
		'nonce_ttl'          => array('int', 30, 900),
		'challenge.bind_ip'  => array('bool'),
		// challenge.trust_headers is deliberately NOT here: it is a rollback
		// switch that lets any client skip the challenge by omitting an Accept
		// header, so it stays a deliberate edit of guard/config.php.
		// Where exempt_params count, which proxies may name the client, and the
		// reverse-DNS suffixes that verify each known bot (read by the analyzer).
		'exempt_params_paths' => array('exactpaths'),
		// Log storage.
		'log_skip_paths'     => array('paths'),
		'log_retention_days' => array('int', 1, 3650),
		'log_max_mb'         => array('int', 0, 10000000),
		'log_min_free_mb'    => array('int', 0, 1000000),
		'cdn_ranges'         => array('cidrs4'),
		'bot_suffixes'       => array('suffixes'),
		// The visitor-facing challenge page. Rendered escaped by challenge.php.
		'strings.lang'       => array('lang'),
		'strings.dir'        => array('enum', array('ltr', 'rtl')),
		'strings.title'      => array('text', 200),
		'strings.sub'        => array('text', 300),
		'strings.noscript'   => array('text', 300),
		'strings.failed'     => array('text', 300),
		'strings.retry'      => array('text', 60),
		'strings.nocookie'   => array('text', 300),
		// Analyzer operation. The guard never reads these; the analyzer picks
		// them up through scripts/config-dump.php (analyzer/config.py load()).
		'analyzer.window_days'      => array('int', 1, 60),
		'analyzer.session_gap_s'    => array('int', 60, 86400),
		'analyzer.rep_ttl'          => array('int', 3600, 7776000),
		'analyzer.ml_ttl'           => array('int', 3600, 2592000),
		'analyzer.botv_ttl'         => array('int', 3600, 2592000),
		'analyzer.botbad_ttl'       => array('int', 300, 86400),
		'analyzer.dns_canary'       => array('host'),
		'analyzer.ml_min_train'     => array('int', 10, 1000000),
		'analyzer.contamination'    => array('float', 0.001, 0.49),
		'analyzer.clf_min_positive' => array('int', 1, 100000),
		'analyzer.clf_target_precision' => array('float', 0.5, 1.0),
		'analyzer.path_listing'     => array('regexes'),
		'analyzer.path_detail'      => array('regexes'),
		'analyzer.report_days'      => array('int', 1, 90),
		'analyzer.report_top_n'     => array('int', 1, 200),
		'analyzer.challenge_success_target' => array('float', 0.5, 1.0),
		'analyzer.snapshot_days'    => array('int', 1, 14),
		'analyzer.job_ttl'          => array('int', 3600, 604800),
		'analyzer.worker_max_jobs'  => array('int', 1, 50),
	);
}

// One line of operator text: a string without control characters, bounded.
function gv_overlay_text_ok($value, $max) {
	if (!is_string($value)) { return 'not_string'; }
	if (strlen($value) > $max) { return 'too_long'; }
	if (!preg_match('//u', $value)) { return 'not_utf8'; }
	if (preg_match('/[\x00-\x1F\x7F]/', $value)) { return 'control_chars'; }
	return '';
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
			// "/" exempts the whole site: one click would switch the guard off.
			if (strlen($entry) < 3) { return array(false, 'too_broad'); }
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
			// A short or generic fragment ("a", "mozilla") matches every browser.
			if (strlen($entry) < 6 || in_array($entry, array('mozilla', 'chrome', 'safari', 'firefox',
				'android', 'iphone', 'windows', 'applewebkit', 'gecko', 'mobile', 'linux'), true)) {
				return array(false, 'too_broad');
			}
			$out[] = $entry;
		}
		return array(true, $out);
	}
	if ($type === 'hppath') {
		if (!is_string($value) || $value === '') { return array(false, 'not_string'); }
		if (strlen($value) > 100) { return array(false, 'too_long'); }
		if (substr($value, 0, 1) !== '/') { return array(false, 'must_start_slash'); }
		if (strlen($value) < 4) { return array(false, 'too_broad'); }   // "/" would 404 the home page
		return array(true, $value);
	}
	if ($type === 'exactpaths') {
		// Exact paths, so "/" is allowed here (unlike exempt_paths prefixes).
		if (!is_array($value) || gv_is_assoc($value)) { return array(false, 'not_list'); }
		if (count($value) > 20) { return array(false, 'too_many'); }
		foreach ($value as $entry) {
			if (!is_string($entry) || $entry === '') { return array(false, 'not_string'); }
			if (strlen($entry) > 200) { return array(false, 'too_long'); }
			if (substr($entry, 0, 1) !== '/') { return array(false, 'must_start_slash'); }
			if (preg_match('/[\s\x00-\x1F]/', $entry)) { return array(false, 'control_chars'); }
		}
		return array(true, array_values($value));
	}
	if ($type === 'cidrs4') {
		if (!is_array($value) || gv_is_assoc($value)) { return array(false, 'not_list'); }
		if (count($value) > 100) { return array(false, 'too_many'); }
		foreach ($value as $entry) {
			if (!is_string($entry) || !preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/', $entry, $m)
				|| ip2long($m[1]) === false || (int)$m[2] > 32) {
				return array(false, 'bad_cidr');
			}
			// Trusting X-Forwarded-For from a /0../7 would let half the internet
			// choose its own address.
			if ((int)$m[2] < 8) { return array(false, 'too_broad'); }
		}
		return array(true, array_values($value));
	}
	if ($type === 'suffixes') {
		if (!is_array($value) || !gv_is_assoc($value)) { return array(false, 'not_map'); }
		if (count($value) > 30) { return array(false, 'too_many'); }
		$out = array();
		foreach ($value as $name => $list) {
			if (!is_string($name) || !preg_match('/^[a-z0-9._-]{3,40}$/', $name)) { return array(false, 'bad_param_name'); }
			if (!is_array($list) || gv_is_assoc($list) || !$list) { return array(false, 'not_list'); }
			if (count($list) > 10) { return array(false, 'too_many'); }
			foreach ($list as $suffix) {
				// A suffix starts with a dot so "evilgooglebot.com" cannot match ".googlebot.com",
				// and has at least one more dot so it is never a bare top-level domain.
				if (!is_string($suffix) || !preg_match('/^\.[a-z0-9-]+(\.[a-z0-9-]+)+$/', $suffix)) {
					return array(false, 'bad_suffix');
				}
			}
			$out[$name] = array_values($list);
		}
		return array(true, $out);
	}
	if ($type === 'lang') {
		if (!is_string($value) || !preg_match('/^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$/', $value)) { return array(false, 'bad_lang'); }
		return array(true, $value);
	}
	if ($type === 'enum') {
		if (!is_string($value) || !in_array($value, $spec[1], true)) { return array(false, 'not_allowed'); }
		return array(true, $value);
	}
	if ($type === 'text') {
		$err = gv_overlay_text_ok($value, $spec[1]);
		if ($err !== '') { return array(false, $err); }
		if (trim($value) === '') { return array(false, 'empty'); }
		return array(true, $value);
	}
	if ($type === 'host') {
		if (!is_string($value) || strlen($value) > 253
			|| !preg_match('/^(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i', $value)) {
			return array(false, 'bad_host');
		}
		return array(true, strtolower($value));
	}
	if ($type === 'regexes') {
		// Python reads these (re module). Only checked here for size and for
		// compiling as PCRE, which rejects the usual typos; the analyzer
		// additionally drops any pattern its own engine refuses.
		if (!is_array($value) || gv_is_assoc($value)) { return array(false, 'not_list'); }
		if (count($value) > 20) { return array(false, 'too_many'); }
		foreach ($value as $re) {
			$err = gv_overlay_text_ok($re, 200);
			if ($err !== '') { return array(false, $err); }
			if ($re === '' || @preg_match('#' . str_replace('#', '\\#', $re) . '#', '') === false) {
				return array(false, 'bad_regex');
			}
		}
		return array(true, array_values($value));
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
	// An empty secret is as unconfigured as the placeholder: anybody can compute
	// an HMAC with an empty key.
	if (!is_string($cfg['secret']) || $cfg['secret'] === '' || $cfg['secret'] === 'CHANGE_ME') {
		$cfg['secret'] = 'CHANGE_ME';
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

// One spelling per address, so a counter, a verdict and an operator override
// all land on the same key: IPv6 in its canonical compressed lower-case form,
// and an IPv4-mapped IPv6 address (::ffff:1.2.3.4) as the IPv4 address it is.
// Anything that is not an address is returned unchanged.
function gv_ip_canon($ip) {
	$ip = (string)$ip;
	if ($ip === '' || strpos($ip, ':') === false) { return $ip; }
	$bin = @inet_pton($ip);
	if ($bin === false || strlen($bin) !== 16) { return $ip; }
	if (substr($bin, 0, 12) === "\0\0\0\0\0\0\0\0\0\0\xff\xff") {
		$v4 = @inet_ntop(substr($bin, 12));
		return is_string($v4) ? $v4 : $ip;
	}
	$out = @inet_ntop($bin);
	return is_string($out) ? $out : $ip;
}

// The network a rate counter is keyed by. An IPv4 address counts as itself. An
// IPv6 client is handed a /64 and can use a new address out of it for every
// request, so per-address counters never fill; all of a /64 shares one counter.
function gv_ip_net($ip) {
	$ip = (string)$ip;
	if (strpos($ip, ':') === false) { return $ip; }
	$bin = @inet_pton($ip);
	if ($bin === false || strlen($bin) !== 16) { return $ip; }
	$net = @inet_ntop(substr($bin, 0, 8) . "\0\0\0\0\0\0\0\0");
	return is_string($net) ? $net . '/64' : $ip;
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
	$ip   = gv_ip_canon(gv_client_ip($server, $cfg['cdn_ranges']));
	$cookies = gv_cookie_values($name, $cookie, isset($server['HTTP_COOKIE']) ? $server['HTTP_COOKIE'] : '');
	return array(
		'rid'     => gv_rid(),
		'ip'      => $ip,
		'ipn'     => gv_ip_net($ip),
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
		'xgvp'    => isset($server['HTTP_X_GV_P']) ? (string)$server['HTTP_X_GV_P'] : '',
		'referer' => isset($server['HTTP_REFERER']) ? (string)$server['HTTP_REFERER'] : '',
		'hc'      => gv_header_count($server),
		'https'   => $https,
		'cookie'  => $cookies ? $cookies[0] : '',
		'cookies' => $cookies,
		'testck'  => (isset($cookie[$name . 't']) && is_string($cookie[$name . 't'])) ? $cookie[$name . 't'] : '',
	);
}

// Every value the client sent for the token cookie, PHP's own pick first.
//
// Two reasons this is not just $_COOKIE[$name]. `Cookie: _gv[]=x` makes PHP
// build an array, and casting that to string raised a warning any visitor could
// trigger. And when a browser holds two cookies of the same name (an old one
// from another path or domain next to the fresh one) PHP keeps only the first:
// if that is the stale one the visitor is challenged forever. So every
// candidate is collected and the caller accepts the first that verifies.
function gv_cookie_values($name, array $cookie, $raw) {
	$out = array();
	if (isset($cookie[$name]) && is_string($cookie[$name]) && $cookie[$name] !== '') {
		$out[] = $cookie[$name];
	}
	if (is_string($raw) && $raw !== '' && strlen($raw) <= 16384) {
		foreach (explode(';', $raw) as $pair) {
			$eq = strpos($pair, '=');
			if ($eq === false || trim(substr($pair, 0, $eq)) !== $name) { continue; }
			$v = urldecode(trim(substr($pair, $eq + 1)));
			if ($v !== '' && !in_array($v, $out, true)) { $out[] = $v; }
			if (count($out) >= 4) { break; }
		}
	}
	return $out;
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

// Gate: a request that must carry a valid token. Every GET is one.
//
// gv_is_nav stays a DESCRIPTION of the request (it feeds the log, the score and
// the analyzer's features) but it reads Accept and X-Requested-With, which the
// client chooses. Deciding the challenge on it let any client through that did
// not ask for HTML - the default of curl and of every HTTP library. A real
// browser's XHR and fetch() carry the token cookie its page load obtained, so
// they are unaffected; server-to-server GETs (feeds, callbacks, cron URLs,
// monitors) must be listed in exempt_paths / exempt_params, as they always had
// to be. POST is never gated: the handshake itself is a POST, and payment
// callbacks and webhooks stay untouched.
//
// $trust_headers = true is the old behaviour (gate only what looks like a
// navigation). It exists as a rollback switch, not as a recommended setting.
//
// HEAD is gated like GET: it runs the application just the same. OPTIONS never
// is (a CORS preflight carries no cookies). Every other method (POST, PUT, ...)
// is gated too, because most applications render the same page for a POST as
// for a GET, which made POST the next way round the challenge. But a POST is
// also how a payment gateway calls back, so that half is only ENFORCED when
// challenge.gate_post is on (gv_gate_enforced); until then it is logged as a
// shadow challenge, which shows exactly which endpoints would be affected.
function gv_is_gate(array $f, $trust_headers = false) {
	$m = (string)$f['method'];
	if ($trust_headers) { return gv_is_nav($f); }
	return $m !== 'OPTIONS';
}

// Whether the page rules (challenge, score block) are enforced for this method.
function gv_gate_enforced(array $f, $gate_post) {
	$m = (string)$f['method'];
	if ($m === 'GET' || $m === 'HEAD') { return true; }
	return (bool)$gate_post;
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
//
// Two ways a client could award itself an exemption are closed here:
//   * a path that only LOOKS like it is under an exempt prefix. The web server
//     resolves "/admin/../product/x" to "/product/x" before the application sees
//     it, so a path with a dot segment, an empty segment or an encoded slash or
//     dot is never exempt by prefix.
//   * exempt_params on an SEO URL. "?route=payment/x" appended to a product URL
//     is just a parameter the client typed. A parameter exemption only counts on
//     the front controller ($param_paths, by default "/" and "/index.php"),
//     where the parameter really selects what runs.
function gv_is_exempt(array $f, array $exempt_paths, array $exempt_params, $param_paths = null) {
	$path = (string)$f['path'];
	if (gv_path_has_prefix($path, $exempt_paths)) { return true; }
	if (is_array($param_paths) && !in_array($path, $param_paths, true)) { return false; }
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

// Prefix match for exempt_paths and log_skip_paths. A path with a dot
// segment, an empty segment or an encoded slash, dot or backslash never
// matches (see gv_is_exempt): "/gv-admin/../product/x" is not under /gv-admin/.
function gv_path_has_prefix($path, array $prefixes) {
	$path = (string)$path;
	if (strpos($path, '/.') !== false || strpos($path, '//') !== false
		|| stripos($path, '%2f') !== false || stripos($path, '%2e') !== false
		|| stripos($path, '%5c') !== false || strpos($path, '\\') !== false) {
		return false;
	}
	foreach ($prefixes as $p) {
		$p = (string)$p;
		if ($p !== '' && strncmp($path, $p, strlen($p)) === 0) { return true; }
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

// Fixed-window counters, any number in ONE round trip. $items is a list of
// array(key, window); returns the matching list of counts (0 in degraded mode).
//
// Per counter the pipeline is SET key 0 EX window NX, INCR key, TTL key. The SET
// creates the key WITH its TTL, so a counter normally cannot exist without one.
// The one remaining race - the key expires between SET NX and INCR, so INCR
// re-creates it bare - is caught by the TTL reply (-1) and repaired with an
// EXPIRE. Counting is unchanged (first hit 1, then 2, 3, ...) and a failed read
// still folds to 0 (fail-open).
function gv_bump_many($conn, array $items, array $extra = array(), &$extra_out = null) {
	$counts = array_fill(0, count($items), 0);
	$extra_out = array_fill(0, count($extra), false);
	if (!gv_redis_alive($conn) || (!$items && !$extra)) { return $counts; }
	// $extra commands ride in the same write (and the same round trip) ahead of
	// the counters; their replies come back in $extra_out.
	$cmds = array_values($extra);
	$n0 = count($cmds);
	foreach ($items as $it) {
		foreach (gv_bump_cmds($it[0], $it[1]) as $c) { $cmds[] = $c; }
	}
	$r = gv_redis_pipeline($conn, $cmds);
	if ($r === false) { return $counts; }
	for ($i = 0; $i < $n0; $i++) { $extra_out[$i] = $r[$i]; }
	$repair = array();
	foreach ($items as $i => $it) {
		$res = gv_bump_result($r[$n0 + $i * 3 + 1], $r[$n0 + $i * 3 + 2]);
		$counts[$i] = $res[0];
		if ($res[1]) { $repair[] = array('EXPIRE', $it[0], (string)(int)$it[1]); }
	}
	if ($repair) { gv_redis_pipeline($conn, $repair); }
	return $counts;
}

// One counter. Returns the current count, or 0 in degraded mode.
function gv_bump($conn, $key, $window) {
	$n = gv_bump_many($conn, array(array($key, $window)));
	return $n[0];
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
		'v'   => 5,
		'rid' => isset($f['rid']) ? (string)$f['rid'] : '',
		'ts'  => round(microtime(true), 3),
		'ip'  => (string)$f['ip'],
		'ua'  => gv_cut($ua, 120),
		'uah' => substr(md5($ua), 0, 12),
		'm'   => gv_cut((string)$f['method'], 16),
		'p'   => gv_cut((string)$f['path'], 200),
		'q'   => gv_cut((string)$f['query'], 100),
		'aj'  => gv_is_ajax($f) ? 1 : 0,
		'nav' => gv_is_nav($f) ? 1 : 0,
		'gate' => (int)($st['gate'] ?? 0),
		'tok' => (string)$st['tok'],
		'dev' => (string)$st['dev'],
		'sf'  => gv_cut((string)$f['sf'], 32),
		'al'  => ((string)$f['al'] !== '') ? 1 : 0,
		'hc'  => (int)$f['hc'],
		'sc'  => (int)$st['sc'],
		'esc' => (int)$st['esc'],
		'rs'  => array_values($st['rs']),
		'cd'  => (int)$st['cd'],
		'cdh' => (int)($st['cdh'] ?? 0),
		'cdd' => (int)($st['cdd'] ?? 0),
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

// Last Redis step of a request: record degraded mode (rd=1) when the
// connection was never opened or died on the way (fail-fast closes it), then
// release it. Call it BEFORE the log line, which reads $st['rd'].
//
// A Redis that answers but refuses to count (see gv_bump_result) is degraded
// too: rd=1 on the row, and one line in guard-errors.log.
function gv_finish($conn, array &$st) {
	if (!gv_redis_alive($conn)) { $st['rd'] = 1; }
	$c = gv_redis_ctx();
	if (!empty($c['cmd_err'])) {
		$st['rd'] = 1;
		gv_errlog('redis_cmd_error', 'Redis refused a counter write (read-only, out of memory or loading?)');
		gv_redis_ctx(array('cmd_err' => false));
	}
	gv_redis_close($conn);
}

// Default per-request state, filled in as the flow progresses.
// botv/rep/ml/clf carry the offline verdicts: '' means no bot verdict was read,
// 0 is a neutral reputation, and -1 means no level was available.
// hold marks a request in the measured-but-never-enforced slice; ovr records an
// operator override.
function gv_state_new() {
	return array(
		'tok' => 'm', 'dev' => '', 'sc' => 0, 'rs' => array(), 'gate' => 0,
		'cd'  => 0, 'cdh' => 0, 'cdd' => 0, 'ciu' => 0, 'ci' => 0, 'rd' => 0, 'hp' => 0, 'bot' => '',
		'botv' => '', 'rep' => 0, 'ml' => -1, 'clf' => -1, 'esc' => 0,
		'hold' => 0, 'ovr' => '',
	);
}

// --------------------------------------------------------------------------
// Phase 2 verdicts
// --------------------------------------------------------------------------

// Fold the two bot verdict reads into 'bad', 'ok' or '' (no verdict). Pure.
// A bad verdict wins.
//
// The === '1' comparison is load-bearing: a read returns the string on a hit,
// null on a miss and FALSE on a command error or read timeout. Comparing
// against null treated a stalled Redis as a bad verdict, which stamped
// BOT_FAKE (+35) on a real crawler that will never solve a challenge. A read
// that failed is no signal at all.
function gv_bot_verdict_from($botbad, $botok) {
	if ($botbad === '1') { return 'bad'; }
	if ($botok === '1') { return 'ok'; }
	return '';
}

// Read the offline bot verification verdict for an address (one round trip).
function gv_bot_verdict($conn, $ip) {
	if (!gv_redis_alive($conn)) { return ''; }
	$r = gv_redis_pipeline($conn, array(
		array('GET', gv_key('botbad:' . $ip)),
		array('GET', gv_key('botok:' . $ip)),
	));
	if ($r === false) { return ''; }
	return gv_bot_verdict_from($r[0], $r[1]);
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
// Round half away from zero, to an int, the same on every PHP version.
//
// PHP's own round() is not: up to 8.3 it pre-rounds to the precision a double
// holds (0.7 * 85 = 59.49999999999999 becomes 60), and 8.4 removed that step (it
// gives 59). The guard and the analyzer's replay must agree to the point, because
// a score one short of hard_block_score is the difference between a block and a
// pass. So the noise is removed explicitly, by taking the decimal text of the
// value at 12 places, and only then is it rounded. analyzer/decision.py php_round()
// does exactly the same, and scripts/panel and analyzer selftests compare the two.
function gv_round_int($x) {
	$v = (float)sprintf('%.12F', (float)$x);
	return (int)($v >= 0 ? floor($v + 0.5) : ceil($v - 0.5));
}

// The signature stays plain values on purpose: this function is mirrored in
// analyzer/decision.py and parity-tested case by case against it.
function gv_effective_score($sc, $rep, $ml, $clf, array $cfg) {
	$esc = (int)$sc;
	if (!empty($cfg['signals']['reputation']) && (int)$rep !== 0) {
		$esc += (int)$rep;
	}
	if (!empty($cfg['signals']['ml']) && (int)$ml >= 0) {
		$esc += gv_round_int((int)$ml * (float)$cfg['ml_weight']);
	}
	if (!empty($cfg['signals']['clf']) && (int)$clf >= 0) {
		$esc += gv_round_int((int)$clf * (float)$cfg['clf_weight']);
	}
	return $esc;
}

// Fold the override reads into 'allow', 'deny' or ''. Pure.
//
// Allow wins over deny: the operator's most specific intent is assumed to be
// the rescue, and a permissive override is the five-second fix when a real
// customer is stuck. Every comparison uses === '1' so a failed read is no signal.
//
// Both allow-by-device and allow-by-ip are honoured: a stuck customer who never
// completed the handshake has only an IP (no device id), and allow-by-ip is the
// documented rescue for that case. The per-device allow is checked first so a
// device allow still overrides an IP deny for the same client, and the IP allow
// is checked before the IP deny so allow-wins holds for IP identities too.
// A key that was not read (no device id) is passed as null.
function gv_override_from($allow_dev, $allow_ip, $deny_dev, $deny_ip) {
	if ($allow_dev === '1') { return 'allow'; }
	if ($allow_ip  === '1') { return 'allow'; }
	if ($deny_dev  === '1') { return 'deny'; }
	if ($deny_ip   === '1') { return 'deny'; }
	return '';
}

// Read an operator override (one round trip). Returns 'allow', 'deny' or ''.
function gv_override($conn, $ip, $dev) {
	if (!gv_redis_alive($conn)) { return ''; }
	$cmds = array(
		'allow_dev' => ($dev !== '') ? array('GET', gv_key('allow:' . $dev)) : null,
		'allow_ip'  => ($ip  !== '') ? array('GET', gv_key('allow:' . $ip))  : null,
		'deny_dev'  => ($dev !== '') ? array('GET', gv_key('deny:' . $dev))  : null,
		'deny_ip'   => array('GET', gv_key('deny:' . $ip)),
	);
	$send = array_values(array_filter($cmds));
	$r = gv_redis_pipeline($conn, $send);
	if ($r === false) { return ''; }
	$v = array();
	$i = 0;
	foreach ($cmds as $label => $cmd) { $v[$label] = ($cmd === null) ? null : $r[$i++]; }
	return gv_override_from($v['allow_dev'], $v['allow_ip'], $v['deny_dev'], $v['deny_ip']);
}

// The Phase 1 decision, unchanged except that it now judges the effective
// score and honours a deny override. First match wins. Pure.
//
// $nav is "this request is subject to the page rules". gv_run passes the gate
// (gv_is_gate), which no longer depends on client-chosen headers; replay passes
// the logged gate. The parameter keeps its name because analyzer/decision.py
// mirrors this function argument for argument.
function gv_decide($esc, $over, $nav, $tok, $hard_block_score, $ovr) {
	if ($ovr === 'deny') { return '403'; }
	if ((int)$esc >= (int)$hard_block_score && $nav) { return '403'; }
	if ($over) { return '429'; }
	// Only gated requests reach this rule, so a POST is never challenged:
	// payment callbacks and webhooks stay untouched.
	if ($nav && $tok !== 'v') { return 'challenge'; }
	return 'allow';
}

// The action this request is actually SERVED, given which rules are switched on.
//
// gv_decide names the first rule that matches. That alone is not enough to act
// on: when the matching rule is switched off (or held out), the request used to
// be allowed outright, so the rules below it never ran. With rate limiting still
// in shadow, a token-less client that went over a limit was no longer
// challenged for the rest of the window; with blocking in shadow, the
// worst-scoring clients skipped the challenge a clean one got. So the rules that
// are off are masked out and the decision is taken again: what comes back is the
// highest-priority rule that both matches and is enforced, or 'allow'.
//
// $page says whether the page rules (score block, challenge) are enforced for
// this request's method (gv_gate_enforced). Pure.
function gv_served($esc, $over, $gate, $tok, $hard_block_score, $ovr, array $enforce, $hold, $page) {
	$block = !empty($enforce['block']);
	$a = gv_decide(
		($block && $page && (int)$hold !== 1) ? $esc : -1,   // a score nobody enforces
		$over && !empty($enforce['ratelimit']),
		$gate && $page,
		$tok, max(0, (int)$hard_block_score),
		$block ? $ovr : '');                                   // an operator deny needs enforce.block
	if ($a === 'challenge' && (empty($enforce['challenge']) || (int)$hold === 1)) { return 'allow'; }
	return $a;
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
		header('X-LiteSpeed-Cache-Control: no-cache');
		header('Content-Type: text/plain; charset=utf-8');
		header('Cache-Control: no-store');
		header('X-Robots-Tag: noindex');
	}
	echo "403 Forbidden\n";
}

function gv_send_429() {
	if (!headers_sent()) {
		http_response_code(429);
		header('X-LiteSpeed-Cache-Control: no-cache');
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
	gv_log_policy(array(
		'skip'     => gv_path_has_prefix($f['path'], (array)$cfg['log_skip_paths']),
		'min_free' => max(0, (int)$cfg['log_min_free_mb']),
	));
	$st  = gv_state_new();
	gv_redis_ctx(array('log_dir' => $log));       // where swallowed errors are reported

	// 2. Verify handshake intercept. Runs before exemptions so the challenge
	// page can always complete its own POST back to the same URL.
	//
	// The handshake is metered and single-use. Everything that needs no storage
	// (signature, binding to UA and IP, age, proof of work) is checked first; then
	// ONE Redis round trip claims the nonce id (SET NX = single use), reads the
	// IP's allow override and bumps the ip, ip_ua and mint counters. Redis down:
	// the handshake stays open (fail-open) and only the stateless checks apply.
	if ($f['method'] === 'POST' && $f['xgv'] !== '') {
		$bind_ip = !empty($cfg['challenge']['bind_ip']);
		$valid   = gv_nonce_check($f['xgv'], $cfg['secret'], $cfg['nonce_ttl'], $f['ua'],
			$bind_ip ? $f['ip'] : '');
		$parsed  = $valid ? gv_nonce_parse($f['xgv']) : false;
		// Proof of work is one hash and needs no storage: check it BEFORE Redis so a
		// request that cannot become a token never touches the mint counter.
		$pow_ok  = $parsed ? gv_pow_ok($f['xgv'], $f['xgvp'], $parsed[1]) : false;
		$window  = $cfg['limits']['window'];

		$conn  = gv_redis_connect($cfg['redis'], $log);
		$extra = array(array('GET', gv_key('allow:' . $f['ip'])));
		if ($parsed) {
			// The claim outlives the nonce by a margin: a nonce stays valid for
			// nonce_ttl by ITS timestamp, so a claim of exactly nonce_ttl could
			// expire first on a node whose clock runs ahead and reopen the replay.
			$extra[] = array('SET', gv_key('nonce:' . $parsed[0]), '1', 'EX',
				(string)(max(1, (int)$cfg['nonce_ttl']) + 60), 'NX');
		}
		$items = array(
			array(gv_key('riu:' . md5($f['ipn'] . '|' . substr(md5((string)$f['ua']), 0, 12))), $window),
			array(gv_key('ri:' . $f['ipn']), $window),
		);
		$mint_at = -1;                                // only a request that could become a token counts
		if ($parsed && $pow_ok) {
			$mint_at = count($items);
			$items[] = array(gv_key('mint:' . $f['ipn']), $window);
		}
		$counts = gv_bump_many($conn, $items, $extra, $reads);
		$st['ciu'] = $counts[0];
		$st['ci']  = $counts[1];
		$allowed_ip = ($reads[0] === '1');
		$replay     = ($parsed && $reads[1] === null);      // false (error) is no verdict
		$mint_n     = ($mint_at >= 0) ? $counts[$mint_at] : 0;
		// limits.mint counts tokens ISSUED. The bump rode in the same round trip as
		// the nonce claim, so give it back when this turns out to be a replay or a
		// refusal (the counter must not grow for requests that got no token).
		$mint_refused = ($mint_n > (int)$cfg['limits']['mint']) && !$allowed_ip
			&& !empty($cfg['enforce']['ratelimit']);
		if ($mint_at >= 0 && ($replay || $mint_refused) && gv_redis_alive($conn)) {
			gv_redis_cmd($conn, array('DECR', gv_key('mint:' . $f['ipn'])));
		}
		gv_finish($conn, $st);

		if (!$valid) {
			if (empty($cfg['enforce']['challenge'])) {
				// Monitor-first holds here too: with the challenge off nothing is
				// refused. The request is logged as a shadow rejection and handed
				// to the application like any other POST.
				gv_emit($f, $st, 'nonce_bad', 1, $t0, $log);
				gv_arm_outcome($cfg, $f, $log);
				return;
			}
			gv_emit($f, $st, 'nonce_bad', 0, $t0, $log);
			if (!headers_sent()) { http_response_code(403); }
			exit;
		}

		// New rejections are shadow-first like every other enforcement: with
		// enforce.challenge off they are logged (sh=1) and the token is still
		// issued, so monitor mode can never lock anybody out of anything.
		$reject = '';
		if ($replay) {
			$reject = 'nonce_replay';
		} elseif (!$pow_ok) {
			$reject = 'pow_bad';
		}
		$act = 'token_issued';
		$sh  = 0;
		if ($reject !== '') {
			if (!empty($cfg['enforce']['challenge'])) {
				gv_emit($f, $st, $reject, 0, $t0, $log);
				if (!headers_sent()) { http_response_code(403); }
				exit;
			}
			$act = $reject;                       // shadow: logged, token still issued
			$sh  = 1;
		} else {
			// Mint metering. An allow-listed IP is never refused a token.
			$over = ($mint_n > (int)$cfg['limits']['mint'])
				|| ($st['ci'] > (int)$cfg['limits']['ip'])
				|| ($st['ciu'] > (int)$cfg['limits']['ip_ua']);
			if ($over && !$allowed_ip) {
				if (!empty($cfg['enforce']['ratelimit'])) {
					gv_emit($f, $st, 'mint_limited', 0, $t0, $log);
					gv_send_429();
					exit;
				}
				$act = 'mint_limited';            // shadow: logged, token still issued
				$sh  = 1;
			}
		}
		// The device id is derived from the nonce, not drawn at random: if the
		// single-use claim is ever unavailable (Redis down, flushed), replaying
		// one nonce yields the SAME device again instead of a stock of fresh
		// identities, each with its own budgets.
		$token = gv_tok_make($cfg['secret'], $parsed ? $parsed[0] : '');
		$dev   = gv_tok_check($token, $cfg['secret'], $cfg['token_ttl']);
		gv_set_token_cookie($cfg, $token, $f['https']);
		if ($f['testck'] !== '') { gv_test_cookie($cfg, '', time() - 3600, $f['https']); }
		$st['tok'] = 'v';
		$st['dev'] = ($dev === false) ? '' : $dev;
		// One log line per request. A shadowed rejection still issues the token,
		// so its act is the would-be action with sh=1 (consumers count it as issued).
		gv_emit($f, $st, $act, $sh, $t0, $log);
		if (!headers_sent()) { http_response_code(204); }
		exit;
	}

	// 2b. Operator test switch (challenge.test_key). Needs the key AND a real
	// secret. The key sets a signed 10 minute cookie and redirects to the same URL
	// without it; while the cookie is valid this browser gets the real challenge
	// page on every GET, whatever its token or the enforce mode. Nobody else is
	// affected and nothing is exempted or relaxed. Solving the page clears it.
	$tkey = (string)$cfg['challenge']['test_key'];
	if ($tkey !== '' && $cfg['secret'] !== 'CHANGE_ME' && $f['method'] === 'GET') {
		if (isset($f['params']['gv_test']) && is_string($f['params']['gv_test'])
			&& hash_equals($tkey, $f['params']['gv_test'])) {
			gv_test_cookie($cfg, gv_test_make($cfg['secret']), time() + 600, $f['https']);
			$keep = array();
			foreach (explode('&', $f['query']) as $kv) {
				if ($kv !== '' && strncmp($kv, 'gv_test=', 8) !== 0) { $keep[] = $kv; }
			}
			if (!headers_sent()) {
				header('Cache-Control: no-store');
				header('Location: /' . ltrim($f['path'], '/') . ($keep ? '?' . implode('&', $keep) : ''), true, 302);
			}
			exit;
		}
		if ($f['testck'] !== '' && gv_test_ok($f['testck'], $cfg['secret'])) {
			$st['rs'][] = 'TEST';
			gv_emit($f, $st, 'challenge', 0, $t0, $log);
			$bits  = max(0, min(24, (int)$cfg['challenge']['pow_bits']));
			$nonce = gv_nonce_make($cfg['secret'], $f['ua'], !empty($cfg['challenge']['bind_ip']) ? $f['ip'] : '', $bits);
			gv_challenge_render($nonce, $cfg['strings'], $bits);
			exit;
		}
	}

	// 3. Exemptions. CLI was already excluded by prepend.php.
	if (gv_is_exempt($f, $cfg['exempt_paths'], $cfg['exempt_params'], $cfg['exempt_params_paths'])) {
		gv_emit($f, $st, 'exempt', 0, $t0, $log);
		gv_arm_outcome($cfg, $f, $log);
		return;
	}

	// Whether this request must carry a token. Recorded on every row from here
	// on, so replay can re-decide from the log alone.
	$gate = gv_is_gate($f, !empty($cfg['challenge']['trust_headers']));
	$st['gate'] = $gate ? 1 : 0;

	// 4. Token. A pure HMAC check, so it can run before Redis is opened: the
	// device id is needed to build the batched reads below. The result stays in
	// locals and reaches $st at the point it always did (step 7), so the logged
	// row of a bot pass or a honeypot hit is unchanged.
	$tok = 'm';
	$dev = '';
	foreach ($f['cookies'] as $cand) {
		$d = gv_tok_check($cand, $cfg['secret'], $cfg['token_ttl']);
		if ($d === false) {
			$tok = 'b';
		} else {
			$tok = 'v';
			$dev = $d;
			break;
		}
	}

	// 5. Redis. A failed connect means degraded mode, never a bypass. At most
	// two round trips follow: ONE pipeline of every GET this request can need,
	// then (only on the paths that count) ONE pipeline of counters. A transport
	// failure closes the connection (fail-fast), so a stalled Redis costs one
	// timeout, and the breaker makes the next requests skip it altogether.
	$conn = gv_redis_connect($cfg['redis'], $log);
	$bot   = gv_match_bot($f['ua'], $cfg['known_bots']);
	$is_hp = ($f['path'] === (string)$cfg['honeypot_path']);

	$reads = array();
	if ($bot !== '') {
		$reads['botbad'] = array('GET', gv_key('botbad:' . $f['ip']));
		$reads['botok']  = array('GET', gv_key('botok:' . $f['ip']));
	}
	if (!$is_hp) {
		if ($dev !== '') {
			$reads['rep']       = array('GET', gv_key('rep:' . $dev));
			$reads['ml']        = array('GET', gv_key('ml:' . $dev));
			$reads['clf']       = array('GET', gv_key('clf:' . $dev));
			$reads['allow_dev'] = array('GET', gv_key('allow:' . $dev));
			$reads['deny_dev']  = array('GET', gv_key('deny:' . $dev));
		}
		if ($f['ip'] !== '') { $reads['allow_ip'] = array('GET', gv_key('allow:' . $f['ip'])); }
		$reads['deny_ip'] = array('GET', gv_key('deny:' . $f['ip']));
		$reads['hp']      = array('GET', gv_key('hp:' . $f['ip']));
	}
	$val = array();                               // label => reply; empty = no signal
	if ($reads && gv_redis_alive($conn)) {
		$r = gv_redis_pipeline($conn, array_values($reads));
		if ($r !== false) { $val = array_combine(array_keys($reads), $r); }
	}
	$rv = function ($label) use ($val) { return isset($val[$label]) ? $val[$label] : false; };

	// Known bots. Still no live reverse DNS: DNS latency does not belong in
	// the request path. The Phase 2 analyzer verifies out of band and leaves a
	// verdict here, so this step costs nothing beyond the batched GETs above.
	//
	// This pass runs BEFORE the honeypot check by design: a UA claiming
	// a known bot takes the pass and is never honeypot-labelled until run_verify
	// writes a 'bad' verdict out of band. So the honeypot is not a defense
	// against fake-bot UAs - reordering it ahead of this would instead risk
	// honeypot-labelling real crawlers, which is the worse failure. See #17.
	//
	// Two limits on the pass. An operator deny on the address beats it. And a
	// claim nobody has verified yet (no 'ok' verdict for this address) draws on
	// ONE site-wide budget per bot name, limits.bot_unverified: without it a
	// client that changes address for every request could say "Googlebot" and
	// read the whole catalogue before any verdict existed. A verified crawler is
	// outside that budget. Redis down: the pass stays open (a crawler shown 503s
	// for the length of an outage costs more than it saves).
	$bot_over = false;
	$bot_fake = false;
	if ($bot !== '' && $rv('deny_ip') === '1') {
		$st['bot'] = $bot;
		$bot = '';                                    // denied: judged like anyone else
	}
	if ($bot !== '') {
		$st['bot'] = $bot;
		$verdict = gv_bot_verdict_from($rv('botbad'), $rv('botok'));
		if ($verdict === 'bad') {
			// An impersonator must be judged, not trusted. Revoke the pass and
			// fall through into normal scoring like any other client.
			$st['botv'] = 'bad';
			$bot_fake   = true;
		} else {
			if ($verdict === 'ok') { $st['botv'] = 'ok'; }
			// The pass bumps only its own counters (rb, rbu), never rd/riu/ri.
			$unverified_over = false;
			if (gv_redis_alive($conn)) {
				$items = array(array(gv_key('rb:' . $f['ipn']), $cfg['limits']['window']));
				if ($verdict !== 'ok') { $items[] = array(gv_key('rbu:' . $bot), $cfg['limits']['window']); }
				$n = gv_bump_many($conn, $items);
				if ($n[0] > (int)$cfg['limits']['bot']) { $bot_over = true; }
				if (isset($n[1]) && $n[1] > (int)$cfg['limits']['bot_unverified']) { $unverified_over = true; }
			}
			if ($unverified_over && !$bot_over) {
				// Over the shared budget and unverified: no pass, and no 429
				// either - it is handled like any other client from here on.
				$st['rs'][] = 'BOT_UNVERIFIED';
				$bot = '';
			} elseif (!$bot_over) {
				gv_finish($conn, $st);
				gv_emit($f, $st, 'allow_bot', 0, $t0, $log);
				gv_arm_outcome($cfg, $f, $log);
				return;
			}
		}
	}

	// 5b. Link-preview fetchers (Telegram, WhatsApp, ...). They cannot solve a
	// challenge and publish nothing to verify them by, so the pass is not a
	// trust decision: it is a small SITE-WIDE budget per fetcher name. Real
	// previews are a trickle. A scraper that borrows the User-Agent shares that
	// one budget across all of its addresses, uses it up and is then handled
	// like any other client - changing IP does not buy a new budget.
	// No Redis, no pass: without a counter the budget cannot be enforced. An
	// operator deny on the address still wins.
	if ($bot === '' && !$is_hp && $rv('deny_ip') !== '1' && gv_redis_alive($conn)) {
		$pv = gv_match_bot($f['ua'], $cfg['preview_bots']);
		if ($pv !== '') {
			$n = gv_bump($conn, gv_key('rp:' . $pv), $cfg['limits']['window']);
			if ($n >= 1 && $n <= (int)$cfg['limits']['preview']) {
				$st['bot'] = $pv;
				gv_finish($conn, $st);
				gv_emit($f, $st, 'allow_preview', 0, $t0, $log);
				gv_arm_outcome($cfg, $f, $log);
				return;
			}
		}
	}

	// 6. Honeypot. Fires regardless of the enforce toggles: it is labelling data.
	if ($is_hp) {
		if (gv_redis_alive($conn)) { gv_r_setex($conn, gv_key('hp:' . $f['ip']), 604800, '1'); }
		$st['hp'] = 1;
		gv_finish($conn, $st);
		gv_emit($f, $st, '404_hp', 0, $t0, $log);
		gv_send_404();
		exit;
	}

	// 7. Token (verified in step 4).
	$st['tok'] = $tok;
	$st['dev'] = $dev;

	// 7b. Offline verdicts for real users. All three are per device, because
	// they describe a browsing identity rather than an address. is_numeric()
	// rejects both a miss (null) and a failed read (false), so a stalled Redis
	// leaves the neutral sentinels in place.
	if ($st['dev'] !== '') {
		$rep = $rv('rep');
		$st['rep'] = is_numeric($rep) ? (int)$rep : 0;
		$ml = $rv('ml');
		$st['ml'] = is_numeric($ml) ? (int)$ml : -1;
		$clf = $rv('clf');
		$st['clf'] = is_numeric($clf) ? (int)$clf : -1;
	}

	// 7c. Operator overrides. An allow short-circuits everything below it: no
	// scoring, no counters, no challenge. It is deliberately not gated by any
	// enforce toggle, because a permissive override can only ever make the
	// guard less strict and must work the instant it is set.
	$st['ovr'] = gv_override_from(
		($st['dev'] !== '') ? $rv('allow_dev') : null, $rv('allow_ip'),
		($st['dev'] !== '') ? $rv('deny_dev') : null, $rv('deny_ip'));
	if ($st['ovr'] === 'allow') {
		gv_finish($conn, $st);
		gv_emit($f, $st, 'allow_override', 0, $t0, $log);
		gv_arm_outcome($cfg, $f, $log);
		return;                                   // zero bytes of output
	}

	// 8. Static score. gv_score stays pure and Phase 1 shaped; the Phase 2
	// contributions are folded in below.
	$hp_hist   = ($rv('hp') === '1');
	$scored    = gv_score($f, $hp_hist);
	$st['sc']  = $scored[0];
	$st['rs']  = array_merge($scored[1], $st['rs']);
	if ($bot_fake) {
		// Part of the static score on purpose: it counts whatever the signal
		// toggles say, because a revoked bot claim is not a shadow signal.
		$st['sc'] += 35;
		$st['rs'][] = 'BOT_FAKE';
	}

	// 9. Rate counters, all in one round trip. Skipped entirely in degraded
	// mode; values stay 0.
	$over = $bot_over;
	if (gv_redis_alive($conn)) {
		$window = $cfg['limits']['window'];
		$items = array();
		// The device token gets two more budgets on fixed long windows. The short
		// window above only sees speed; a scraper that paces itself (one page
		// every few seconds, around the clock) never trips it, whatever address
		// it comes from, but it cannot stay under an hourly and a daily budget
		// and still fetch a catalogue. Counted per token, so a rotating IP
		// changes nothing. Same round trip as the other counters.
		if ($st['dev'] !== '') {
			$items[] = array(gv_key('rd:' . $st['dev']), $window);
			$items[] = array(gv_key('rdh:' . $st['dev']), 3600);
			$items[] = array(gv_key('rdd:' . $st['dev']), 86400);
		}
		$uah = substr(md5((string)$f['ua']), 0, 12);
		$items[] = array(gv_key('riu:' . md5($f['ipn'] . '|' . $uah)), $window);
		$items[] = array(gv_key('ri:' . $f['ipn']), $window);
		$counts = gv_bump_many($conn, $items);
		if ($st['dev'] !== '') {
			$st['cd'] = array_shift($counts);
			if ($st['cd'] > (int)$cfg['limits']['device']) { $over = true; }
			$st['cdh'] = array_shift($counts);
			if ($st['cdh'] > (int)$cfg['limits']['device_hour']) { $over = true; $st['rs'][] = 'DEV_HOUR'; }
			$st['cdd'] = array_shift($counts);
			if ($st['cdd'] > (int)$cfg['limits']['device_day']) { $over = true; $st['rs'][] = 'DEV_DAY'; }
		}
		$st['ciu'] = $counts[0];
		if ($st['ciu'] > (int)$cfg['limits']['ip_ua']) { $over = true; }
		$st['ci'] = $counts[1];
		if ($st['ci'] > (int)$cfg['limits']['ip']) { $over = true; }
	}
	gv_finish($conn, $st);

	// 10. Decision, now judging the effective score.
	$st['esc'] = gv_effective_score($st['sc'], $st['rep'], $st['ml'], $st['clf'], $cfg);
	$intended  = gv_decide($st['esc'], $over, $gate, $st['tok'], $cfg['hard_block_score'],
		$st['ovr']);

	// 11. Act. Every branch logs exactly one line.
	if ($intended === 'allow') {
		gv_emit($f, $st, 'allow', 0, $t0, $log);
		gv_arm_outcome($cfg, $f, $log);
		return;                                   // zero bytes of output
	}

	// Holdout: a small deterministic slice measured but never enforced against.
	// It is the only source of outcome data this system has not already biased
	// with its own gating, and the only way to estimate false negatives.
	// Applied at the gate, so the intended action is still computed and logged.
	$st['hold'] = gv_is_holdout(($st['dev'] !== '' ? $st['dev'] : $f['ip']),
		$cfg['holdout_salt'], $cfg['holdout_pct']) ? 1 : 0;
	// What is actually served: the first rule that matches AND is enforced. The
	// holdout suppresses the classifier's own decisions (score block, challenge)
	// but never a 429 (resource protection) or an operator deny (an action); a
	// deny is passed through gv_served untouched by the holdout for that reason.
	$page   = gv_gate_enforced($f, !empty($cfg['challenge']['gate_post']));
	$served = gv_served($st['esc'], $over, $gate, $st['tok'], $cfg['hard_block_score'], $st['ovr'],
		$cfg['enforce'], $st['hold'], $page);
	if ($st['ovr'] === 'deny' && !empty($cfg['enforce']['block'])) { $served = '403'; }

	if ($served === 'allow') {
		// Monitor mode or holdout: record what would have happened and allow.
		// The application runs, so this path is armed like any other allow -
		// and it is where the holdout's outcome data comes from.
		gv_emit($f, $st, $intended, 1, $t0, $log);
		gv_arm_outcome($cfg, $f, $log);
		return;
	}
	if ($served !== $intended) {
		// A higher rule matched but is in shadow, and a lower one is enforced.
		// One row per request: it carries what was served, and names the
		// shadowed rule in rs so the would-be action is not lost.
		$st['rs'][] = 'SH_' . $intended;
	}
	gv_emit($f, $st, $served, 0, $t0, $log);
	$intended = $served;
	if ($intended === '403') { gv_send_403(); exit; }
	if ($intended === '429') { gv_send_429(); exit; }
	$bits  = max(0, min(24, (int)$cfg['challenge']['pow_bits']));
	$nonce = gv_nonce_make($cfg['secret'], $f['ua'], !empty($cfg['challenge']['bind_ip']) ? $f['ip'] : '', $bits);
	gv_challenge_render($nonce, $cfg['strings'], $bits);
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
		// fail-open: never break the host application, but leave a trace. This also
		// covers a config file that does not parse; gv_errlog falls back to the
		// shipped log directory when no config was loaded.
		gv_errlog('guard_exception', get_class($e) . ': ' . $e->getMessage()
			. ' @ ' . basename($e->getFile()) . ':' . $e->getLine());
	}
}
