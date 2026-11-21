<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

require_once __DIR__ . '/data.php';
require_once __DIR__ . '/geo.php';

// Access rules: reading, writing, form parsing, warnings, the test box and the impact preview.
//
// The rule model and its validation live in guard/rules.php. The panel never
// carries a copy: gp_rules_write() calls gv_rules_validate_list(), the same code
// the guard runs when it reads the file.
//
// guard/rules.json is written with a temp file + rename() under a lock, so the
// guard (which reads it on every request) never sees a half-written file.

// The file as the panel sees it. 'state' is 'missing', 'ok' or 'invalid'
// (unreadable JSON, wrong shape, or at least one rule the guard would drop).
// Writing over an invalid file would silently delete the rules the guard has
// been ignoring, so every write refuses until the operator discards them.
function gp_rules_state() {
	$path = gv_rules_path();
	$out = array('state' => 'missing', 'rules' => array(), 'dropped' => 0, 'path' => $path);
	if (!is_file($path)) { return $out; }
	$raw = @file_get_contents($path);
	if ($raw === false || trim($raw) === '') { $out['state'] = 'ok'; return $out; }
	$data = json_decode($raw, true);
	if (strlen($raw) > GV_RULES_MAX_BYTES || !is_array($data) || !isset($data['rules']) || !is_array($data['rules'])
		|| ($data['rules'] && gv_is_assoc($data['rules']))) {
		$out['state'] = 'invalid';
		return $out;
	}
	$out['rules'] = gv_rules_read($path);
	$out['dropped'] = count($data['rules']) - count($out['rules']);
	$out['state'] = $out['dropped'] > 0 ? 'invalid' : 'ok';
	return $out;
}

// Write the whole rule list. Returns array(ok, errors). Never writes a list the
// guard would not accept.
function gp_rules_write(array $rules) {
	$check = gv_rules_validate_list(array_values($rules), true);
	if (!$check[0]) { return array(false, $check[1]); }
	// Sorted by priority (stable) so the guard can use the list as it is.
	$sorted = $check[1];
	usort($sorted, function ($a, $b) { return $a['priority'] <=> $b['priority']; });
	$json = gv_rules_encode($sorted);
	if ($json === false || strlen($json) > GV_RULES_MAX_BYTES - 1024) { return array(false, array(-1 => array('_list' => 'too_big'))); }
	$path = gv_rules_path();
	if (!is_writable(dirname($path)) || (is_file($path) && !is_writable($path))) { return array(false, array(-1 => array('_write' => 'write_failed'))); }
	$tmp = $path . '.tmp' . getmypid();
	if (@file_put_contents($tmp, $json, LOCK_EX) === false) { return array(false, array(-1 => array('_write' => 'write_failed'))); }
	@chmod($tmp, 0640);
	if (!@rename($tmp, $path)) { @unlink($tmp); return array(false, array(-1 => array('_write' => 'write_failed'))); }
	// The generated cache the guard includes (written AFTER the JSON, so it is
	// never older than it). If it cannot be written the guard falls back to the
	// JSON and says so, so the save still counts.
	gp_rules_cache_write($sorted);
	return array(true, array());
}

// Write guard/rules.cache.php (temp + rename, then drop it from OPcache).
function gp_rules_cache_write(array $sorted) {
	$cache = gv_rules_cache_path();
	$tmp = $cache . '.tmp' . getmypid();
	if (@file_put_contents($tmp, gv_rules_cache_source($sorted), LOCK_EX) === false) { return false; }
	@chmod($tmp, 0640);
	if (!@rename($tmp, $cache)) { @unlink($tmp); return false; }
	if (function_exists('opcache_invalidate')) { @opcache_invalidate($cache, true); }
	return true;
}

// Read-modify-write under one lock. $fn receives the current list and returns
// the new list, or a string error key. Audits every rule that changed.
// Returns array(ok, error_key, errors).
function gp_rules_update($fn, $event, $actor, $client_ip) {
	$lock = @fopen(gv_rules_path() . '.lock', 'c');
	if ($lock) { @flock($lock, LOCK_EX); }
	try {
		$st = gp_rules_state();
		if ($st['state'] === 'invalid') { return array(false, 'rules_file_invalid', array()); }
		$old = $st['rules'];
		$new = $fn($old);
		if (is_string($new)) { return array(false, $new, array()); }
		$w = gp_rules_write($new);
		if (!$w[0]) { return array(false, isset($w[1][-1]['_write']) ? 'write_failed' : 'rules_invalid', $w[1]); }
		$before = array(); foreach ($old as $r) { $before[$r['id']] = $r; }
		$after = array();  foreach ($new as $r) { $after[$r['id']] = $r; }
		foreach ($after as $id => $r) {
			if (!isset($before[$id]) || $before[$id] != $r) {
				gp_audit_append(array('event' => $event, 'actor' => (string)$actor, 'ip' => (string)$client_ip,
					'key' => $id, 'old' => isset($before[$id]) ? $before[$id] : null, 'new' => $r));
			}
		}
		foreach ($before as $id => $r) {
			if (!isset($after[$id])) {
				gp_audit_append(array('event' => $event, 'actor' => (string)$actor, 'ip' => (string)$client_ip,
					'key' => $id, 'old' => $r, 'new' => null));
			}
		}
		return array(true, '', array());
	} finally {
		if ($lock) { @flock($lock, LOCK_UN); @fclose($lock); }
	}
}

function gp_rule_new_id(array $rules) {
	$taken = array();
	foreach ($rules as $r) { $taken[$r['id']] = true; }
	do { $id = 'r' . bin2hex(random_bytes(3)); } while (isset($taken[$id]));
	return $id;
}

function gp_rules_lines($text) {
	$out = array();
	foreach (preg_split('/\R/', (string)$text) as $line) {
		$line = trim($line);
		if ($line !== '') { $out[] = $line; }
	}
	return $out;
}

// A new rule with every default, used to pre-fill the form.
function gp_rule_blank() {
	return array(
		'id' => '', 'name' => '', 'enabled' => true, 'mode' => 'monitor', 'action' => 'challenge',
		'priority' => 100, 'skip_verified_bots' => true,
		'ua' => array('op' => 'include', 'type' => 'contains', 'values' => array()),
		'path' => null, 'country' => null, 'asn' => null, 'expires_at' => 0, 'pow_bits' => 0, 'note' => '',
		'created_by' => '', 'created_at' => 0, 'updated_at' => 0,
	);
}

// Country codes or AS numbers typed into one box: separated by spaces, commas or
// new lines. Codes are upper-cased; "AS13335" and "13335" both mean 13335.
function gp_rules_geo_tokens($text, $asn) {
	$out = array();
	foreach (preg_split('/[\s,;]+/', (string)$text, -1, PREG_SPLIT_NO_EMPTY) as $t) {
		$t = $asn ? preg_replace('/^AS/i', '', $t) : strtoupper($t);
		if (!in_array($t, $out, true)) { $out[] = $t; }
	}
	return $out;
}

// Rule fields from the form. Types are coerced just far enough for the guard's
// validator to judge them; nothing is trusted here.
function gp_rule_from_post(array $p, ?array $existing = null) {
	$rule = gp_rule_blank();
	if ($existing) { $rule = array_merge($rule, $existing); }
	$rule['id'] = isset($p['id']) && is_string($p['id']) ? trim($p['id']) : '';
	$rule['name'] = isset($p['name']) && is_string($p['name']) ? trim($p['name']) : '';
	$rule['enabled'] = !empty($p['enabled']);
	$rule['skip_verified_bots'] = !empty($p['skip_verified_bots']);
	$rule['mode'] = isset($p['mode']) && is_string($p['mode']) ? $p['mode'] : '';
	$rule['action'] = isset($p['action']) && is_string($p['action']) ? $p['action'] : '';
	$pri = isset($p['priority']) && is_string($p['priority']) ? trim($p['priority']) : '';
	$rule['priority'] = preg_match('/^\d{1,9}$/', $pri) ? (int)$pri : $pri;
	$bits = isset($p['pow_bits']) && is_string($p['pow_bits']) ? trim($p['pow_bits']) : '0';
	$rule['pow_bits'] = ($bits === '') ? 0 : (preg_match('/^\d{1,3}$/', $bits) ? (int)$bits : $bits);
	$rule['note'] = isset($p['note']) && is_string($p['note']) ? trim($p['note']) : '';
	foreach (array('ua', 'path') as $k) {
		$vals = gp_rules_lines(isset($p[$k . '_values']) && is_string($p[$k . '_values']) ? $p[$k . '_values'] : '');
		if (!$vals) { $rule[$k] = null; continue; }
		$rule[$k] = array(
			'op'   => (isset($p[$k . '_op']) && $p[$k . '_op'] === 'exclude') ? 'exclude' : 'include',
			'type' => $k === 'path' ? 'prefix' : (isset($p['ua_type']) && is_string($p['ua_type']) ? $p['ua_type'] : ''),
			'values' => $vals,
		);
	}
	foreach (array('country' => false, 'asn' => true) as $k => $is_asn) {
		$vals = gp_rules_geo_tokens(isset($p[$k . '_values']) && is_string($p[$k . '_values']) ? $p[$k . '_values'] : '', $is_asn);
		$rule[$k] = $vals ? array('op' => (isset($p[$k . '_op']) && $p[$k . '_op'] === 'exclude') ? 'exclude' : 'include',
			'type' => $is_asn ? 'number' : 'code', 'values' => $vals) : null;
	}
	// Expiry: a date (end of that day, UTC) or never.
	$d = isset($p['expires_date']) && is_string($p['expires_date']) ? trim($p['expires_date']) : '';
	if ($d === '') { $rule['expires_at'] = 0; }
	elseif (preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $d, $m) && checkdate((int)$m[2], (int)$m[3], (int)$m[1])) {
		$rule['expires_at'] = gmmktime(23, 59, 59, (int)$m[2], (int)$m[3], (int)$m[1]);
	} else { $rule['expires_at'] = -1; }
	return $rule;
}

// Samples of current real browsers live in guard/rules.php (the regex timing check on
// save uses them too).
function gp_rules_browser_samples() { return gv_rules_browser_samples(); }

// Non-blocking warnings for a rule about to be saved. Returns a list of
// array(code, detail). Pure: the config is passed in.
function gp_rule_warnings(array $rule, array $cfg, $geo = null) {
	$out = array();
	$has_geo = (!empty($rule['country']) && is_array($rule['country'])) || (!empty($rule['asn']) && is_array($rule['asn']));
	if ($has_geo) {
		if (($rule['action'] === 'block' || $rule['action'] === 'challenge') && empty($rule['skip_verified_bots'])) {
			$out[] = array('geo_bots', '');
		}
		$c = !empty($rule['country']) && is_array($rule['country']) ? $rule['country'] : null;
		if ($c && $c['op'] === 'exclude' && in_array('IR', $c['values'], true) && $rule['action'] === 'block') {
			$out[] = array('geo_exclude_ir', '');
		}
		if (is_array($geo)) {
			$need = array();
			if ($c && !($geo['country'] && $geo['country']['valid'])) { $need[] = 'country.bin'; }
			if (!empty($rule['asn']) && !($geo['asn'] && $geo['asn']['valid'])) { $need[] = 'asn.bin'; }
			if ($need) { $out[] = array('geo_nodb', implode(', ', $need)); }
			elseif ($c && $geo['countries']) {
				$missing = array_values(array_diff($c['values'], $geo['countries']));
				if ($missing) { $out[] = array('geo_code_absent', implode(', ', array_slice($missing, 0, 8))); }
			}
		}
	}
	if (!empty($rule['ua']) && is_array($rule['ua'])) {
		$cond = array_merge($rule, array('path' => null));
		$hit = array();
		foreach (array_merge((array)$cfg['known_bots'], (array)$cfg['preview_bots']) as $bot) {
			if (gv_rule_matches($cond, array('ua' => 'Mozilla/5.0 (compatible; ' . $bot . '/2.1)', 'path' => '/'))) { $hit[] = $bot; }
		}
		if ($hit) { $out[] = array('bots', implode(', ', array_slice($hit, 0, 8))); }
		$hit = array();
		foreach (gp_rules_browser_samples() as $label => $ua) {
			if (gv_rule_matches($cond, array('ua' => $ua, 'path' => '/'))) { $hit[] = $label; }
		}
		if ($hit) { $out[] = array('browsers', implode(', ', $hit)); }
		if ($rule['ua']['type'] === 'contains' && $rule['ua']['op'] === 'include') {
			foreach ($rule['ua']['values'] as $v) {
				if ($v !== GV_RULE_EMPTY && strlen($v) < 4) { $out[] = array('short', $v); break; }
			}
		}
	}
	if (!empty($rule['path']) && is_array($rule['path']) && $rule['path']['op'] === 'include') {
		$over = array();
		foreach ((array)$cfg['exempt_paths'] as $ex) {
			foreach ($rule['path']['values'] as $p) {
				if (strncmp($p, $ex, strlen($ex)) === 0 || strncmp($ex, $p, strlen($p)) === 0) { $over[] = $ex; }
			}
		}
		if ($over) { $out[] = array('exempt', implode(', ', array_unique($over))); }
	}
	if ($rule['action'] === 'captcha' && !gv_captcha_available()) { $out[] = array('captcha_gd', ''); }
	if (!empty($rule['path']) && is_array($rule['path']) && $rule['path']['op'] === 'exclude' && $rule['mode'] === 'enforce' && $rule['action'] !== 'log') {
		$out[] = array('wide', '');
	}
	return $out;
}

// The test box: which rules would match this client, and what happens.
// Pure. $verified = the client is a known bot with a verified 'ok' verdict.
function gp_rules_test(array $rules, $ua, $path, $verified, array $cfg, $now, $ip = '') {
	$f = array('ua' => (string)$ua, 'path' => (string)$path === '' ? '/' : (string)$path);
	// With an address the country and ASN come from the compiled databases; without
	// one they are unknown, and an unknown value never matches a geo condition.
	$ip = gp_geo_clean_ip($ip);
	$f['ip'] = $ip;
	$f['cc'] = $ip === '' ? '' : gv_geo_country($ip, true);
	$f['asn'] = $ip === '' ? 0 : gv_geo_asn($ip, true);
	$bot = gv_match_bot($f['ua'], (array)$cfg['known_bots']);
	$all = gv_rules_match_all($f, $rules, $now);
	$winner = null;
	$skipped = array();
	foreach ($all as $r) {
		if ($verified && $bot !== '' && !empty($r['skip_verified_bots'])) { $skipped[] = $r['id']; continue; }
		$winner = $r;
		break;
	}
	return array('bot' => $bot, 'matches' => $all, 'winner' => $winner, 'skipped' => $skipped,
		'ip' => $ip, 'cc' => $f['cc'], 'asn' => $f['asn']);
}

// A short human summary of one condition, for the table.
function gp_rule_cond_text($label, $cond) {
	if (!is_array($cond)) { return ''; }
	$vals = array();
	foreach ($cond['values'] as $v) { $vals[] = '"' . (strlen($v) > 40 ? substr($v, 0, 40) . '...' : $v) . '"'; }
	$type = ($cond['type'] === 'code' || $cond['type'] === 'number') ? 'is' : $cond['type'];
	return $label . ' ' . ($cond['op'] === 'exclude' ? 'NOT ' : '') . $type . ' ' . implode(' / ', array_slice($vals, 0, 4))
		. (count($vals) > 4 ? ' +' . (count($vals) - 4) : '');
}

// The Rules table filters (include / exclude, see panel/filters.php): action, mode and
// state are choices; cc and asn match the codes a rule's conditions list; ua and q are
// text (q searches name, note and every condition value). Pure.
function gp_rules_filter_spec() {
	return array('action' => 'choice', 'mode' => 'choice', 'state' => 'choice', 'cc' => array('choice', 'ci' => true),
		'asn' => 'choice', 'ua' => 'text', 'q' => 'text');
}

function gp_rules_filter_from_request(array $get) {
	return gp_filter_parse($get, gp_rules_filter_spec());
}

function gp_rules_filter_match(array $rule, array $f, $now) {
	$state = empty($rule['enabled']) ? 'disabled' : (((int)$rule['expires_at'] !== 0 && (int)$rule['expires_at'] <= $now) ? 'expired' : 'active');
	$vals = function ($c) { return (is_array($c) && isset($c['values'])) ? $c['values'] : array(); };
	$country = $vals($rule['country'] ?? null);
	$asn = $vals($rule['asn'] ?? null);
	$ua = $vals($rule['ua'] ?? null);
	foreach (array('action' => $rule['action'], 'mode' => $rule['mode'], 'state' => $state) as $k => $val) {
		if (isset($f[$k]) && !gp_filter_test('choice', $f[$k], $val)) { return false; }
	}
	// "country is IR" means: the rule has a country condition that lists IR. A rule with
	// no country condition is a KNOWN "no country condition" (not an unknown country), so
	// "is not IR" includes it; "(none)" lists those rules, "is not (none)" the others.
	if (isset($f['cc']) && !gp_filter_test('choice', $f['cc'], $country, true, false)) { return false; }
	if (isset($f['asn']) && !gp_filter_test('choice', $f['asn'], $asn, false, false)) { return false; }
	if (isset($f['ua']) && !gp_filter_test('text', $f['ua'], implode("\n", $ua))) { return false; }
	if (isset($f['q'])) {
		$hay = $rule['name'] . ' ' . $rule['note'] . ' ' . implode(' ', $ua) . ' ' . implode(' ', $country) . ' ' . implode(' ', $asn)
			. ' ' . (isset($rule['path']['values']) ? implode(' ', $rule['path']['values']) : '');
		if (!gp_filter_test('text', $f['q'], $hay)) { return false; }
	}
	return true;
}

// Impact preview: what would this rule have matched in the recent logs?
//
// Reuses the log reader's caps (GP_MAX_SCAN_BYTES, GP_MAX_SCAN_LINES): newest
// rows first, today's file then the day before, stopping at the first cap. The
// time range actually covered is returned so the page can state it. The log
// keeps only the first 120 characters of a UA, so an exact or regex rule on a
// longer UA can under-count; the page says so.
function gp_log_scan(array $dates, callable $each) {
	$meta = array('scanned_lines' => 0, 'scanned_bytes' => 0, 'capped' => false, 'files' => 0, 'newest' => 0.0, 'oldest' => 0.0);
	foreach ($dates as $d) {
		if ($meta['capped']) { break; }
		$fh = @fopen(gp_log_file($d), 'rb');
		if (!$fh) { continue; }
		$meta['files']++;
		$pos = (int)filesize(gp_log_file($d));
		$carry = '';
		while ($pos > 0 && !$meta['capped']) {
			$read = (int)min(65536, $pos, GP_MAX_SCAN_BYTES - $meta['scanned_bytes']);
			if ($read <= 0) { $meta['capped'] = true; break; }
			$pos -= $read;
			if (fseek($fh, $pos, SEEK_SET) !== 0) { break; }
			$data = fread($fh, $read);
			if ($data === false) { break; }
			$meta['scanned_bytes'] += strlen($data);
			$parts = explode("\n", $data . $carry);
			$carry = ($pos > 0) ? array_shift($parts) : '';
			for ($i = count($parts) - 1; $i >= 0; $i--) {
				$line = trim($parts[$i]);
				if ($line === '') { continue; }
				if (++$meta['scanned_lines'] > GP_MAX_SCAN_LINES) { $meta['capped'] = true; break; }
				$row = json_decode($line, true);
				if (!is_array($row) || (isset($row['o']) && $row['o'] === 1)) { continue; }
				$ts = isset($row['ts']) ? (float)$row['ts'] : 0.0;
				if ($ts > $meta['newest']) { $meta['newest'] = $ts; }
				if ($ts > 0 && ($meta['oldest'] === 0.0 || $ts < $meta['oldest'])) { $meta['oldest'] = $ts; }
				$each($row);
			}
		}
		fclose($fh);
	}
	if ($meta['scanned_bytes'] >= GP_MAX_SCAN_BYTES) { $meta['capped'] = true; }
	return $meta;
}

// Fold decision rows into the impact of one rule. Pure over $rows (an iterable of
// log rows), so it is tested without files. Rows of a verified crawler are not
// counted when the rule skips them.
function gp_rules_impact_fold(array $rule, array $rows) {
	$out = gp_rules_impact_new($rule);
	$ips = array(); $devs = array(); $paths = array();
	foreach ($rows as $row) { gp_rules_impact_row($rule, $row, $out, $ips, $devs, $paths); }
	return gp_rules_impact_finish($out, $ips, $devs, $paths);
}

// The empty result. geo_*: for a rule with a country / ASN condition, how many rows
// had the value in the log (logged), had it resolved from the CURRENT database by
// the row's address (lookup), or could not be evaluated at all (none).
function gp_rules_impact_new(array $rule) {
	return array('requests' => 0, 'ips' => 0, 'devices' => 0, 'tokened' => 0, 'paths' => array(), 'scanned' => 0,
		'geo' => (!empty($rule['country']) || !empty($rule['asn'])), 'geo_logged' => 0, 'geo_lookup' => 0, 'geo_none' => 0,
		'captcha' => (isset($rule['action']) && $rule['action'] === 'captcha'), 'captcha_would' => 0);
}

function gp_rules_impact_row(array $rule, array $row, array &$out, array &$ips, array &$devs, array &$paths) {
	$out['scanned']++;
	// A captcha rule never asks a verified crawler, whatever skip_verified_bots says.
	if ((!empty($rule['skip_verified_bots']) || (isset($rule['action']) && $rule['action'] === 'captcha')) && (string)($row['botv'] ?? '') === 'ok') { return; }
	$f = array('ua' => (string)($row['ua'] ?? ''), 'path' => (string)($row['p'] ?? '/'));
	if ($out['geo']) {
		// The value logged with the row wins; a row from before geo logging was on is
		// resolved from the current database by its address; with neither it is unknown.
		$ip = (isset($row['ip']) && is_string($row['ip'])) ? gv_ip_canon($row['ip']) : '';
		$src = 'logged';
		foreach (array('cc' => array('country', GV_GEO_COUNTRY), 'asn' => array('asn', GV_GEO_ASN)) as $k => $need) {
			if (empty($rule[$need[0]])) { continue; }
			if (isset($row[$k]) && (is_string($row[$k]) || is_int($row[$k]))) { $f[$k] = $row[$k]; }
			elseif ($ip !== '' && gv_geo_open($need[1], null, true) !== null) {
				$f[$k] = ($k === 'cc') ? gv_geo_country($ip, true) : gv_geo_asn($ip, true);
				if ($src === 'logged') { $src = 'lookup'; }
			} else { $f[$k] = ($k === 'cc') ? '' : 0; $src = 'none'; }
		}
		$out['geo_' . $src]++;
	}
	if (!gv_rule_matches($rule, $f)) { return; }
	$out['requests']++;
	if (isset($row['ip']) && is_string($row['ip']) && $row['ip'] !== '') { $ips[$row['ip']] = true; }
	if (isset($row['dev']) && is_string($row['dev']) && $row['dev'] !== '') { $devs[$row['dev']] = true; }
	if ((string)($row['tok'] ?? '') === 'v') { $out['tokened']++; }
	// How many of the matched requests would get a CAPTCHA: an HTML request (nav) that needed a token (gate; older rows
	// without it count as gated), without a CAPTCHA-level token (tl), that was not exempt or let through by an allow
	// override or list. The rest of the matched requests would keep their normal flow.
	if (!empty($out['captcha']) && !empty($row['nav']) && (!isset($row['gate']) || !empty($row['gate'])) && (string)($row['tl'] ?? '') !== 'c'
		&& !in_array((string)($row['act'] ?? ''), array('exempt', 'allow_override'), true)) { $out['captcha_would']++; }
	$p = $f['path'];
	if (isset($paths[$p]) || count($paths) < 2000) { $paths[$p] = (isset($paths[$p]) ? $paths[$p] : 0) + 1; }
}

function gp_rules_impact_finish(array $out, array $ips, array $devs, array $paths) {
	arsort($paths);
	$out['paths'] = array_slice($paths, 0, 5, true);
	$out['ips'] = count($ips);
	$out['devices'] = count($devs);
	// Red: more than 50 distinct devices, or any matched request that held a valid token.
	$out['danger'] = ($out['devices'] > 50 || $out['tokened'] > 0);
	return $out;
}

function gp_rules_impact(array $rule) {
	$out = gp_rules_impact_new($rule);
	$ips = array(); $devs = array(); $paths = array();
	$meta = gp_log_scan(gp_log_dates(2), function ($row) use ($rule, &$out, &$ips, &$devs, &$paths) {
		gp_rules_impact_row($rule, $row, $out, $ips, $devs, $paths);
	});
	$out = gp_rules_impact_finish($out, $ips, $devs, $paths);
	$out['meta'] = $meta;
	return $out;
}

// Handle one POST action. Returns array(ok, message_key, errors, details, draft).
function gp_rules_action($action, array $p, $actor, $client_ip, array $cfg) {
	$res = array('ok' => false, 'msg' => 'err_generic', 'errors' => array(), 'details' => array(), 'draft' => null, 'warnings' => array(), 'impact' => null);
	$now = time();
	$id = isset($p['id']) && is_string($p['id']) ? $p['id'] : '';

	if ($action === 'save' || $action === 'preview') {
		$rule = gp_rule_from_post($p);
		$res['draft'] = $rule;
		$new = ($rule['id'] === '');
		$st = gp_rules_state();
		if ($new) { $rule['id'] = gp_rule_new_id($st['rules']); }
		$rule['updated_at'] = $now;
		$old = null;
		foreach ($st['rules'] as $r) { if ($r['id'] === $rule['id']) { $old = $r; } }
		if (!$new && $old === null) { $res['msg'] = 'rule_not_found'; return $res; }
		$rule['created_at'] = $old ? $old['created_at'] : $now;
		$rule['created_by'] = $old ? $old['created_by'] : (string)$actor;
		$deep = gv_rule_validate($rule, true);
		if (!$deep[0]) {
			$res['msg'] = 'rules_invalid';
			$res['errors'] = $deep[1];
			$res['details'] = isset($deep[2]) ? $deep[2] : array();
			return $res;
		}
		$res['draft'] = $deep[1];
		$res['draft']['id'] = $new ? '' : $deep[1]['id'];      // a new rule gets its id when it is saved
		// The impact preview: always on "Preview", and required before a rule goes from
		// monitor (or from nothing) to enforce, so the operator sees what it would have hit.
		$to_enforce = ($deep[1]['mode'] === 'enforce' && $deep[1]['action'] !== 'log' && ($old === null || $old['mode'] !== 'enforce'));
		if ($action === 'preview' || $to_enforce) {
			$res['impact'] = gp_rules_impact($deep[1]);
		}
		if ($action === 'preview') { $res['msg'] = 'rule_preview'; return $res; }
		// Warnings are shown once; "Save anyway" (ack=1) goes through.
		$res['warnings'] = gp_rule_warnings($deep[1], $cfg, gp_geo_status());
		if ($to_enforce) { array_unshift($res['warnings'], array($res['impact']['danger'] ? 'enforce_danger' : 'enforce', '')); }
		if ($res['warnings'] && empty($p['ack'])) { $res['msg'] = 'rule_warnings'; return $res; }
		$r = gp_rules_update(function ($rules) use ($deep, $new) {
			$out = array();
			$done = false;
			foreach ($rules as $x) {
				if ($x['id'] === $deep[1]['id']) { $out[] = $deep[1]; $done = true; } else { $out[] = $x; }
			}
			if (!$done) { $out[] = $deep[1]; }
			return $out;
		}, $new ? 'rule_create' : 'rule_update', $actor, $client_ip);
		$res['ok'] = $r[0];
		$res['msg'] = $r[0] ? 'rule_saved' : $r[1];
		$res['errors'] = $r[2];
		return $res;
	}

	if ($action === 'toggle' || $action === 'delete' || $action === 'duplicate' || $action === 'move') {
		$dir = (isset($p['dir']) && $p['dir'] === 'up') ? 'up' : 'down';
		$r = gp_rules_update(function ($rules) use ($action, $id, $dir, $actor, $now) {
			$idx = -1;
			foreach ($rules as $i => $x) { if ($x['id'] === $id) { $idx = $i; } }
			if ($idx < 0) { return 'rule_not_found'; }
			if ($action === 'toggle') {
				$rules[$idx]['enabled'] = !$rules[$idx]['enabled'];
				$rules[$idx]['updated_at'] = $now;
			} elseif ($action === 'delete') {
				array_splice($rules, $idx, 1);
			} elseif ($action === 'duplicate') {
				$copy = $rules[$idx];
				$copy['id'] = gp_rule_new_id($rules);
				$copy['name'] = substr($copy['name'], 0, 71) . ' (copy)';
				$copy['enabled'] = false;
				$copy['mode'] = 'monitor';
				$copy['created_by'] = (string)$actor;
				$copy['created_at'] = $copy['updated_at'] = $now;
				$copy['priority'] = min(100000, $copy['priority'] + 1);
				$rules[] = $copy;
			} else {
				// Reorder by priority: swap with the neighbour in priority order,
				// then renumber 10, 20, 30... so there is always room between rules.
				usort($rules, function ($a, $b) { return $a['priority'] <=> $b['priority']; });
				foreach ($rules as $i => $x) { if ($x['id'] === $id) { $idx = $i; } }
				$j = $dir === 'up' ? $idx - 1 : $idx + 1;
				if ($j < 0 || $j >= count($rules)) { return $rules; }
				$tmp = $rules[$idx]; $rules[$idx] = $rules[$j]; $rules[$j] = $tmp;
				foreach ($rules as $i => $x) {
					if ($rules[$i]['priority'] !== ($i + 1) * 10) { $rules[$i]['priority'] = ($i + 1) * 10; $rules[$i]['updated_at'] = $now; }
				}
			}
			return $rules;
		}, 'rule_' . ($action === 'move' ? 'reorder' : $action), $actor, $client_ip);
		$res['ok'] = $r[0];
		$res['msg'] = $r[0] ? 'rule_done' : $r[1];
		return $res;
	}

	if ($action === 'starter') {
		$r = gp_rules_update(function ($rules) use ($actor, $now) {
			$have = array();
			foreach ($rules as $x) { $have[$x['id']] = true; }
			foreach (gv_rules_starter() as $s) {
				if (isset($have[$s['id']])) { continue; }
				$s['created_at'] = $s['updated_at'] = $now;
				$s['created_by'] = (string)$actor;
				$rules[] = $s;
			}
			return $rules;
		}, 'rule_starter', $actor, $client_ip);
		$res['ok'] = $r[0];
		$res['msg'] = $r[0] ? 'rule_starter_done' : $r[1];
		return $res;
	}

	if ($action === 'discard_invalid') {
		// Rewrite the file with only the rules the guard accepts.
		$st = gp_rules_state();
		$w = gp_rules_write($st['rules']);
		if ($w[0]) {
			gp_audit_append(array('event' => 'rule_discard_invalid', 'actor' => (string)$actor, 'ip' => (string)$client_ip,
				'key' => 'rules.json', 'old' => $st['dropped'], 'new' => count($st['rules'])));
		}
		$res['ok'] = $w[0];
		$res['msg'] = $w[0] ? 'rule_done' : 'write_failed';
		return $res;
	}
	return $res;
}

// Pre-fill for the "Quick block" button on a log row: an exact UA rule in
// monitor mode. The log keeps only the first 120 characters of a UA, so a
// longer one becomes a prefix rule (an exact match on the cut text never fires).
function gp_rule_from_ua($ua) {
	$rule = gp_rule_blank();
	$ua = (string)$ua;
	$rule['name'] = 'Block: ' . gv_cut($ua === '' ? 'empty UA' : $ua, 50);
	$rule['mode'] = 'monitor';
	$rule['action'] = 'block';
	if ($ua === '') {
		$rule['ua'] = array('op' => 'include', 'type' => 'exact', 'values' => array(GV_RULE_EMPTY));
	} else {
		$rule['ua'] = array('op' => 'include', 'type' => (strlen($ua) >= 120 ? 'prefix' : 'exact'), 'values' => array($ua));
	}
	return $rule;
}
