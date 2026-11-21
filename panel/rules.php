<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// Access rules: reading, writing, form parsing, warnings and the test box.
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
	return array(true, array());
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
		'path' => null, 'expires_at' => 0, 'pow_bits' => 0, 'note' => '',
		'created_by' => '', 'created_at' => 0, 'updated_at' => 0,
	);
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
	// Expiry: a date (end of that day, UTC) or never.
	$d = isset($p['expires_date']) && is_string($p['expires_date']) ? trim($p['expires_date']) : '';
	if ($d === '') { $rule['expires_at'] = 0; }
	elseif (preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $d, $m) && checkdate((int)$m[2], (int)$m[3], (int)$m[1])) {
		$rule['expires_at'] = gmmktime(23, 59, 59, (int)$m[2], (int)$m[3], (int)$m[1]);
	} else { $rule['expires_at'] = -1; }
	return $rule;
}

// Samples of current real browsers: a rule that matches any of these would
// lock real visitors out. Kept short and current; extend it, do not trust it.
function gp_rules_browser_samples() {
	return array(
		'Chrome (Windows)' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
		'Chrome (macOS)' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
		'Chrome (Linux)' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
		'Chrome (Android)' => 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36',
		'Firefox (Windows)' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0',
		'Firefox (Android)' => 'Mozilla/5.0 (Android 14; Mobile; rv:132.0) Gecko/132.0 Firefox/132.0',
		'Safari (macOS)' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15',
		'Safari (iPhone)' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
		'Edge (Windows)' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
		'Samsung Internet' => 'Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36',
	);
}

// Non-blocking warnings for a rule about to be saved. Returns a list of
// array(code, detail). Pure: the config is passed in.
function gp_rule_warnings(array $rule, array $cfg) {
	$out = array();
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
	if (!empty($rule['path']) && is_array($rule['path']) && $rule['path']['op'] === 'exclude' && $rule['mode'] === 'enforce' && $rule['action'] !== 'log') {
		$out[] = array('wide', '');
	}
	return $out;
}

// The test box: which rules would match this client, and what happens.
// Pure. $verified = the client is a known bot with a verified 'ok' verdict.
function gp_rules_test(array $rules, $ua, $path, $verified, array $cfg, $now) {
	$f = array('ua' => (string)$ua, 'path' => (string)$path === '' ? '/' : (string)$path);
	$bot = gv_match_bot($f['ua'], (array)$cfg['known_bots']);
	$all = gv_rules_match_all($f, $rules, $now);
	$winner = null;
	$skipped = array();
	foreach ($all as $r) {
		if ($verified && $bot !== '' && !empty($r['skip_verified_bots'])) { $skipped[] = $r['id']; continue; }
		$winner = $r;
		break;
	}
	return array('bot' => $bot, 'matches' => $all, 'winner' => $winner, 'skipped' => $skipped);
}

// A short human summary of one condition, for the table.
function gp_rule_cond_text($label, $cond) {
	if (!is_array($cond)) { return ''; }
	$vals = array();
	foreach ($cond['values'] as $v) { $vals[] = '"' . (strlen($v) > 40 ? substr($v, 0, 40) . '...' : $v) . '"'; }
	return $label . ' ' . ($cond['op'] === 'exclude' ? 'NOT ' : '') . $cond['type'] . ' ' . implode(' / ', array_slice($vals, 0, 4))
		. (count($vals) > 4 ? ' +' . (count($vals) - 4) : '');
}

// Table filters: each field has an operator, "is" (default) or "is not"
// (<key>_op=not). Choice fields allow several comma-separated values. Pure.
function gp_rules_filter_from_request(array $get) {
	$out = array();
	foreach (array('action', 'mode', 'state') as $k) {
		$v = isset($get[$k]) && is_string($get[$k]) ? trim($get[$k]) : '';
		if ($v !== '') { $out[$k] = array_slice(array_filter(array_map('trim', explode(',', substr($v, 0, 100)))), 0, 5); }
		if (isset($out[$k])) { $out[$k . '_op'] = (isset($get[$k . '_op']) && $get[$k . '_op'] === 'not') ? 'not' : 'is'; }
	}
	$q = isset($get['q']) && is_string($get['q']) ? trim(substr($get['q'], 0, 100)) : '';
	if ($q !== '') { $out['q'] = $q; $out['q_op'] = (isset($get['q_op']) && $get['q_op'] === 'not') ? 'not' : 'is'; }
	return $out;
}

function gp_rules_filter_match(array $rule, array $f, $now) {
	$state = empty($rule['enabled']) ? 'disabled' : (((int)$rule['expires_at'] !== 0 && (int)$rule['expires_at'] <= $now) ? 'expired' : 'active');
	foreach (array('action' => $rule['action'], 'mode' => $rule['mode'], 'state' => $state) as $k => $val) {
		if (!isset($f[$k])) { continue; }
		$in = in_array($val, $f[$k], true);
		if (($f[$k . '_op'] === 'not') ? $in : !$in) { return false; }
	}
	if (isset($f['q'])) {
		$hay = $rule['name'] . ' ' . $rule['note'] . ' ' . (isset($rule['ua']['values']) ? implode(' ', $rule['ua']['values']) : '')
			. ' ' . (isset($rule['path']['values']) ? implode(' ', $rule['path']['values']) : '');
		$has = stripos($hay, $f['q']) !== false;
		if (($f['q_op'] === 'not') ? $has : !$has) { return false; }
	}
	return true;
}

// Handle one POST action. Returns array(ok, message_key, errors, details, draft).
function gp_rules_action($action, array $p, $actor, $client_ip, array $cfg) {
	$res = array('ok' => false, 'msg' => 'err_generic', 'errors' => array(), 'details' => array(), 'draft' => null, 'warnings' => array());
	$now = time();
	$id = isset($p['id']) && is_string($p['id']) ? $p['id'] : '';

	if ($action === 'save') {
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
		// Warnings are shown once; "Save anyway" (ack=1) goes through.
		$res['warnings'] = gp_rule_warnings($deep[1], $cfg);
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
