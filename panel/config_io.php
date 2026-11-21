<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// Overlay writing and the audit trail.
//
// The panel NEVER writes PHP. Configuration changes are written as JSON to
// guard/config.local.json, because a panel that rewrites executable config from
// form input is a code-injection hole in a security tool.
//
// Validation is not reimplemented here. gv_overlay_validate() in guard/guard.php
// is the single definition, so what the panel accepts on write is exactly what
// the guard accepts on read, permanently.

// The panel loads the guard as a LIBRARY: it needs gv_cfg_load() and the
// overlay validators, and must never run a guard request cycle on itself.
// GV_BOOT satisfies the direct-access guard every guard/*.php carries;
// GV_NO_AUTORUN suppresses the request-flow entry at the bottom of guard.php.
if (!defined('GV_BOOT')) { define('GV_BOOT', 1); }
if (!defined('GV_NO_AUTORUN')) { define('GV_NO_AUTORUN', 1); }

require_once __DIR__ . '/../guard/guard.php';

function gp_audit_path() {
	// GV_AUDIT lets the test harness keep the trail out of the working tree, like GV_CONFIG.
	$env = getenv('GV_AUDIT');
	if (is_string($env) && $env !== '') { return $env; }
	return __DIR__ . '/audit.jsonl';
}

// Append one line to the audit trail. Append-only by design: the panel offers
// no delete. This is what later connects "the false-positive rate jumped on
// Tuesday" to "hard_block_score was lowered on Tuesday", and in a security tool
// an untraceable config change is unacceptable.
function gp_audit_append(array $row) {
	try {
		$row = array_merge(array('ts' => round(microtime(true), 3)), $row);
		// Bounded fields. The login form writes the attempted username here
		// before any authentication: unbounded, one megabyte-long "username"
		// filled the tail the audit view reads and hid every real entry.
		foreach (array('actor' => 64, 'ip' => 64, 'key' => 100, 'event' => 40) as $field => $max) {
			if (isset($row[$field])) {
				$v = is_scalar($row[$field]) ? (string)$row[$field] : '';
				$row[$field] = strlen($v) > $max ? substr($v, 0, $max) . '...' : $v;
			}
		}
		$flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
		if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) { $flags |= JSON_INVALID_UTF8_SUBSTITUTE; }
		$line = json_encode($row, $flags);
		if ($line === false) { return false; }
		$ok = @file_put_contents(gp_audit_path(), $line . "\n", FILE_APPEND | LOCK_EX);
		if ($ok !== false) { @chmod(gp_audit_path(), 0640); }
		return $ok !== false;
	} catch (\Throwable $e) {
		return false;
	}
}

// Read the audit trail newest-first, bounded. Never loads the whole file when
// it has grown: it reads the tail and parses only that.
// Audit rows against a parsed filter (panel/filters.php): event and actor are
// choices / identities, q is a text search over the whole row. Pure.
function gp_audit_match(array $row, array $f) {
	if (isset($f['event']) && !gp_filter_test('choice', $f['event'], (string)($row['event'] ?? ''))) { return false; }
	if (isset($f['actor']) && !gp_filter_test('ident', $f['actor'], (string)($row['actor'] ?? ''))) { return false; }
	if (isset($f['q']) && !gp_filter_test('text', $f['q'], json_encode($row))) { return false; }
	return true;
}

// $filter: a search string (contains), or a parsed filter array (see gp_audit_match).
function gp_audit_read($limit = 200, $filter = '') {
	$path = gp_audit_path();
	if (!is_file($path)) { return array(); }
	// An exclude filter needs more lines to find enough rows: scan a bigger tail.
	$lines = gp_tail_lines($path, max(1, (int)$limit) * (is_array($filter) ? 20 : 4), 1048576);
	$out = array();
	foreach (array_reverse($lines) as $line) {
		$row = json_decode($line, true);
		if (!is_array($row)) { continue; }
		if (is_array($filter)) {
			if (!gp_audit_match($row, $filter)) { continue; }
		} elseif ($filter !== '') {
			$hay = strtolower(json_encode($row));
			if (strpos($hay, strtolower($filter)) === false) { continue; }
		}
		$out[] = $row;
		if (count($out) >= (int)$limit) { break; }
	}
	return $out;
}

// Read at most $max_lines trailing lines of a file, scanning at most $max_bytes.
// Shared by the audit reader and the log explorer: no panel code may ever load
// a whole file into memory.
function gp_tail_lines($path, $max_lines, $max_bytes) {
	$out = array();
	$fh = @fopen($path, 'rb');
	if (!$fh) { return $out; }
	try {
		$size = filesize($path);
		if ($size === false || $size === 0) { return $out; }
		$chunk = 65536;
		$pos = $size;
		$buffer = '';
		$scanned = 0;
		while ($pos > 0 && count($out) < $max_lines && $scanned < $max_bytes) {
			// The byte cap has to bound the read itself, not merely be checked
			// after it: one chunk larger than the cap would otherwise pull the
			// whole file into memory, which is the thing this exists to prevent.
			$read = (int)min($chunk, $pos, $max_bytes - $scanned);
			if ($read <= 0) { break; }
			$pos -= $read;
			if (fseek($fh, $pos, SEEK_SET) !== 0) { break; }
			$data = fread($fh, $read);
			if ($data === false) { break; }
			$scanned += strlen($data);
			$buffer = $data . $buffer;
			$parts = explode("\n", $buffer);
			$buffer = array_shift($parts);       // possibly partial first line
			// Lines within this chunk, oldest-first. The outer loop walks from
			// newer bytes to older, so this whole block is older than anything
			// already in $out - prepend it. Appending each block instead left a
			// multi-chunk result scrambled by chunk (only a single-chunk window
			// came out ordered), which array_reverse in gp_audit_read then turned
			// into a wrong newest-first order once audit.jsonl passed 64 KiB.
			$chunk_lines = array();
			foreach ($parts as $line) {
				$line = trim($line);
				if ($line !== '') { $chunk_lines[] = $line; }
			}
			$out = array_merge($chunk_lines, $out);
			if (count($out) >= $max_lines) { break; }
		}
		if ($pos === 0 && trim($buffer) !== '' && count($out) < $max_lines) {
			// The final leftover is the oldest line of all; prepend it so the
			// whole result stays oldest-first.
			array_unshift($out, trim($buffer));
		}
	} catch (\Throwable $e) {
		// fall through with whatever was read
	}
	fclose($fh);
	// gp_tail_lines returns oldest-first across any number of chunks.
	return $out;
}

// Analyzer defaults for the analyzer.* panel keys. They mirror DEFAULTS in
// analyzer/config.py (scripts/panel-selftest.php compares the two), so the
// settings form shows the value in force and a save does not pin defaults.
function gp_analyzer_defaults() {
	return array('window_days' => 7, 'session_gap_s' => 1800, 'rep_ttl' => 1209600, 'ml_ttl' => 86400,
		'botv_ttl' => 86400, 'botbad_ttl' => 3600, 'dns_canary' => 'www.google.com', 'ml_min_train' => 200,
		'contamination' => 0.05, 'clf_min_positive' => 50, 'clf_target_precision' => 0.98,
		'path_listing' => array(), 'path_detail' => array(), 'report_days' => 7, 'report_top_n' => 20,
		'challenge_success_target' => 0.95, 'snapshot_days' => 1, 'job_ttl' => 86400, 'worker_max_jobs' => 4,
		'interval_verify' => 10, 'interval_worker' => 1, 'interval_snapshot' => 15, 'interval_nightly' => 1440, 'interval_logrotate' => 1440,
		'interval_train' => 10080, 'interval_train_clf' => 10080, 'interval_geo' => 43200, 'interval_report' => 10080);
}

// The effective configuration as the panel shows it: the guard's, plus the
// analyzer block (defaults under whatever the overlay sets).
function gp_effective_config() {
	$cfg = gv_cfg_load();
	$cfg['analyzer'] = array_merge(gp_analyzer_defaults(),
		isset($cfg['analyzer']) && is_array($cfg['analyzer']) ? $cfg['analyzer'] : array());
	return $cfg;
}

// Current effective overlay, as a flat validated array.
function gp_overlay_current() {
	return gv_overlay_read(gv_overlay_path());
}

// Compute the diff between the current overlay and a proposed set of changes.
// Returns array of array(key, old, new). Used to show the operator exactly what
// a save will do before it does it.
function gp_overlay_diff(array $proposed) {
	$current = gp_overlay_current();
	$effective = gp_effective_config();
	$out = array();
	foreach ($proposed as $key => $value) {
		$old = array_key_exists($key, $current)
			? $current[$key]
			: gp_effective_value($effective, $key);
		if (gp_value_equal($old, $value)) { continue; }
		$out[] = array('key' => $key, 'old' => $old, 'new' => $value);
	}
	return $out;
}

// Read a dotted key out of a resolved config array.
function gp_effective_value(array $cfg, $key) {
	$parts = explode('.', $key);
	$node = $cfg;
	foreach ($parts as $part) {
		if (!is_array($node) || !array_key_exists($part, $node)) { return null; }
		$node = $node[$part];
	}
	return $node;
}

function gp_value_equal($a, $b) {
	if (is_float($a) || is_float($b)) {
		if (!is_numeric($a) || !is_numeric($b)) { return false; }
		return abs((float)$a - (float)$b) < 1e-9;
	}
	return $a === $b;
}

// Validate and persist a set of overlay changes.
//
// Returns array('ok' => bool, 'errors' => array(key => code),
//               'applied' => array(key => value)).
// Nothing is written when any key fails: a half-applied settings form is worse
// than a rejected one, because the operator believes all of it took effect.
function gp_config_save(array $proposed, $actor, $client_ip) {
	$errors = array();
	$clean = array();
	// The form posts every field. Only the ones that differ from the value in
	// force are validated and written: a value that came from a hand-edited
	// config.php (outside the panel's range, say) must not block every other
	// change on the page.
	$changed_only = array();
	foreach (gp_overlay_diff($proposed) as $change) { $changed_only[$change['key']] = $proposed[$change['key']]; }
	$proposed = $changed_only;
	foreach ($proposed as $key => $value) {
		$check = gv_overlay_validate($key, $value);
		if ($check[0]) {
			$clean[$key] = $check[1];
		} else {
			$errors[$key] = $check[1];
		}
	}
	if ($errors) {
		return array('ok' => false, 'errors' => $errors, 'applied' => array());
	}

	// Read, merge and write under one lock. Without it two saves at the same
	// moment each merged into the overlay they had read, and the later rename
	// silently discarded the other one's change while both reported success.
	$lock = @fopen(gv_overlay_path() . '.lock', 'c');
	if ($lock) { @flock($lock, LOCK_EX); }
	try {
		$diff = gp_overlay_diff($clean);
		if (!$diff) {
			return array('ok' => true, 'errors' => array(), 'applied' => array());
		}
		// Only the keys that actually change go into the overlay. The form posts
		// every field; merging all of them pinned each one to today's value, so
		// a later edit of config.php for any of them was silently shadowed.
		$changed = array();
		foreach ($diff as $change) { $changed[$change['key']] = $clean[$change['key']]; }
		$merged = array_merge(gp_overlay_current(), $changed);
		if (!gp_overlay_write($merged)) {
			return array('ok' => false, 'errors' => array('_write' => 'write_failed'),
				'applied' => array());
		}
	} finally {
		if ($lock) { @flock($lock, LOCK_UN); @fclose($lock); }
	}

	foreach ($diff as $change) {
		gp_audit_append(array(
			'event' => 'config',
			'actor' => (string)$actor,
			'ip'    => (string)$client_ip,
			'key'   => $change['key'],
			'old'   => $change['old'],
			'new'   => $change['new'],
		));
	}
	return array('ok' => true, 'errors' => array(), 'applied' => $clean);
}

// Remove a key from the overlay, letting guard/config.php show through again.
function gp_config_reset($key, $actor, $client_ip) {
	$current = gp_overlay_current();
	if (!array_key_exists($key, $current)) { return true; }
	$old = $current[$key];
	unset($current[$key]);
	if (!gp_overlay_write($current)) { return false; }
	gp_audit_append(array('event' => 'config_reset', 'actor' => (string)$actor,
		'ip' => (string)$client_ip, 'key' => $key, 'old' => $old, 'new' => null));
	return true;
}

// Atomic write: temp file in the same directory, then rename(). A partially
// written overlay must never be observable by the guard, which reads this file
// on every single request. The previous version is backed up first; when the
// backup fails nothing is written.
function gp_overlay_write(array $flat) {
	try {
		$flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
		if (defined('JSON_PRETTY_PRINT')) { $flags |= JSON_PRETTY_PRINT; }
		// An empty overlay must still be a JSON object, never [].
		$json = $flat ? json_encode($flat, $flags) : '{}';
		if ($json === false) { return false; }
		// The guard ignores an overlay over 256 KiB as a whole. Writing one would
		// report "saved" and silently switch every panel setting off.
		if (strlen($json) > 200000) { return false; }
		if (!is_writable(dirname(gv_overlay_path()))) { return false; }
		if (!gp_overlay_backup_current()) { return false; }
		return gp_overlay_write_raw($json . "\n");
	} catch (\Throwable $e) {
		return false;
	}
}

// --------------------------------------------------------------------------
// Backups of the overlay
//
// Every write of guard/config.local.json (settings form, reset, file editor)
// first copies the current file into guard/config-backups/. The newest
// GP_BACKUP_KEEP copies are kept. guard/.htaccess denies the whole directory
// to the web, and the supported layout keeps guard/ outside the web root.
// --------------------------------------------------------------------------

define('GP_BACKUP_KEEP', 20);

function gp_backup_dir() {
	return dirname(gv_overlay_path()) . '/config-backups';
}

// Copy the current overlay into the backup directory. True when there was
// nothing to back up. False only when a backup was needed and failed, in
// which case the caller must not overwrite the file.
function gp_overlay_backup_current() {
	$path = gv_overlay_path();
	if (!is_file($path)) { return true; }
	$dir = gp_backup_dir();
	if (!is_dir($dir)) { @mkdir($dir, 0750, true); }
	if (!is_dir($dir) || !is_writable($dir)) { return false; }
	// Microseconds in the name keep the order right when several saves happen
	// within one second; the random part keeps two processes apart.
	$now = microtime(true);
	$name = 'config.local.' . date('Ymd-His', (int)$now) . '-' . sprintf('%06d', (int)(($now - floor($now)) * 1000000))
		. '-' . bin2hex(random_bytes(3)) . '.json';
	if (!@copy($path, $dir . '/' . $name)) { return false; }
	@chmod($dir . '/' . $name, 0640);
	$all = gp_overlay_backups();
	foreach (array_slice($all, GP_BACKUP_KEEP) as $old) { @unlink($dir . '/' . $old['name']); }
	return true;
}

// Backups, newest first: array of array(name, time, size).
function gp_overlay_backups() {
	$out = array();
	foreach ((array)glob(gp_backup_dir() . '/config.local.*.json') as $file) {
		$name = basename($file);
		if (!gp_backup_name_ok($name)) { continue; }
		$out[] = array('name' => $name, 'time' => (int)@filemtime($file), 'size' => (int)@filesize($file));
	}
	usort($out, function ($a, $b) { return strcmp($b['name'], $a['name']); });
	return $out;
}

// Only names this code generates; never a path, never "..".
function gp_backup_name_ok($name) {
	return is_string($name) && preg_match('/^config\.local\.\d{8}-\d{6}-\d{6}-[0-9a-f]{6}\.json$/', $name) === 1;
}

function gp_overlay_backup_read($name) {
	if (!gp_backup_name_ok($name)) { return null; }
	$file = gp_backup_dir() . '/' . $name;
	if (!is_file($file) || filesize($file) > 262144) { return null; }
	$raw = @file_get_contents($file);
	return $raw === false ? null : $raw;
}

// --------------------------------------------------------------------------
// The overlay file editor
//
// The operator may edit guard/config.local.json as text. Nothing is written
// unless the WHOLE text passes: strict JSON, an object, no duplicate keys,
// every key on the whitelist and every value accepted by gv_overlay_validate(),
// the same rule the guard applies on every request. The file stays JSON, so
// this is not a code editor: the panel still never writes PHP.
// --------------------------------------------------------------------------

function gp_overlay_file_raw() {
	$path = gv_overlay_path();
	if (!is_file($path)) { return "{}\n"; }
	$raw = @file_get_contents($path);
	return ($raw === false || $raw === '') ? "{}\n" : $raw;
}

// Strict JSON scan that knows WHERE it failed. json_decode() only says
// "Syntax error"; an operator needs the line and column. Returns
// array('error' => message or '', 'offset' => byte offset of the error,
// 'keys' => array(top-level key => line), 'dupes' => array(key => line)).
function gp_json_scan($text) {
	$st = array('s' => (string)$text, 'i' => 0, 'n' => strlen((string)$text), 'depth' => 0,
		'keys' => array(), 'dupes' => array());
	try {
		gp_json_ws($st);
		if ($st['i'] >= $st['n']) { throw new \RuntimeException('The file is empty. An empty overlay is {}.'); }
		gp_json_value($st);
		gp_json_ws($st);
		if ($st['i'] < $st['n']) { throw new \RuntimeException('Unexpected text after the end of the JSON object.'); }
		return array('error' => '', 'offset' => 0, 'keys' => $st['keys'], 'dupes' => $st['dupes']);
	} catch (\RuntimeException $e) {
		return array('error' => $e->getMessage(), 'offset' => min($st['i'], $st['n']), 'keys' => $st['keys'], 'dupes' => $st['dupes']);
	}
}

function gp_json_ws(array &$st) {
	while ($st['i'] < $st['n'] && strpos(" \t\r\n", $st['s'][$st['i']]) !== false) { $st['i']++; }
}

function gp_json_line(array $st, $offset) {
	return substr_count(substr($st['s'], 0, $offset), "\n") + 1;
}

function gp_json_value(array &$st) {
	if ($st['i'] >= $st['n']) { throw new \RuntimeException('Unexpected end of file: a value is missing.'); }
	$c = $st['s'][$st['i']];
	if ($c === '{') { gp_json_object($st); return; }
	if ($c === '[') { gp_json_array($st); return; }
	if ($c === '"') { gp_json_string($st); return; }
	foreach (array('true', 'false', 'null') as $word) {
		if (substr($st['s'], $st['i'], strlen($word)) === $word) { $st['i'] += strlen($word); return; }
	}
	if (preg_match('/\G-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/', $st['s'], $m, 0, $st['i'])) {
		$st['i'] += strlen($m[0]);
		return;
	}
	if ($c === "'") { throw new \RuntimeException('JSON strings use double quotes ("), not single quotes.'); }
	throw new \RuntimeException('Unexpected character ' . json_encode($c) . ': expected a value (string, number, true, false, null, object or list).');
}

function gp_json_string(array &$st) {
	$start = $st['i'];
	$st['i']++;
	while ($st['i'] < $st['n']) {
		$c = $st['s'][$st['i']];
		if ($c === '"') { $st['i']++; return json_decode(substr($st['s'], $start, $st['i'] - $start)); }
		if ($c === '\\') {
			$next = $st['i'] + 1 < $st['n'] ? $st['s'][$st['i'] + 1] : '';
			if ($next === 'u') {
				if (!preg_match('/\G[0-9a-fA-F]{4}/', $st['s'], $m, 0, $st['i'] + 2)) {
					$st['i']++;
					throw new \RuntimeException('Bad \\u escape: four hex digits expected.');
				}
				$st['i'] += 6;
				continue;
			}
			if ($next === '' || strpos('"\\/bfnrt', $next) === false) {
				$st['i']++;
				throw new \RuntimeException('Bad escape sequence in a string.');
			}
			$st['i'] += 2;
			continue;
		}
		if (ord($c) < 0x20) { throw new \RuntimeException('A string cannot contain a line break or control character; close it with " first.'); }
		$st['i']++;
	}
	$st['i'] = $start;
	throw new \RuntimeException('This string is never closed (missing ").');
}

function gp_json_object(array &$st) {
	$st['depth']++;
	if ($st['depth'] > 32) { throw new \RuntimeException('Nested too deeply.'); }
	$top = $st['depth'] === 1;
	$st['i']++;
	gp_json_ws($st);
	if ($st['i'] < $st['n'] && $st['s'][$st['i']] === '}') { $st['i']++; $st['depth']--; return; }
	while (true) {
		gp_json_ws($st);
		if ($st['i'] >= $st['n'] || $st['s'][$st['i']] !== '"') {
			throw new \RuntimeException(($st['i'] < $st['n'] && $st['s'][$st['i']] === '}')
				? 'Trailing comma before }: remove the last comma.'
				: 'A key in double quotes is expected here.');
		}
		$at = $st['i'];
		$key = gp_json_string($st);
		if ($top) {
			$line = gp_json_line($st, $at);
			if (isset($st['keys'][$key])) { $st['dupes'][$key] = $line; }
			$st['keys'][$key] = $line;
		}
		gp_json_ws($st);
		if ($st['i'] >= $st['n'] || $st['s'][$st['i']] !== ':') { throw new \RuntimeException('A colon (:) is expected after the key.'); }
		$st['i']++;
		gp_json_ws($st);
		gp_json_value($st);
		gp_json_ws($st);
		if ($st['i'] < $st['n'] && $st['s'][$st['i']] === ',') { $st['i']++; continue; }
		if ($st['i'] < $st['n'] && $st['s'][$st['i']] === '}') { $st['i']++; $st['depth']--; return; }
		throw new \RuntimeException('A comma (,) or } is expected here.');
	}
}

function gp_json_array(array &$st) {
	$st['depth']++;
	if ($st['depth'] > 32) { throw new \RuntimeException('Nested too deeply.'); }
	$st['i']++;
	gp_json_ws($st);
	if ($st['i'] < $st['n'] && $st['s'][$st['i']] === ']') { $st['i']++; $st['depth']--; return; }
	while (true) {
		gp_json_ws($st);
		if ($st['i'] < $st['n'] && $st['s'][$st['i']] === ']') { throw new \RuntimeException('Trailing comma before ]: remove the last comma.'); }
		gp_json_value($st);
		gp_json_ws($st);
		if ($st['i'] < $st['n'] && $st['s'][$st['i']] === ',') { $st['i']++; continue; }
		if ($st['i'] < $st['n'] && $st['s'][$st['i']] === ']') { $st['i']++; $st['depth']--; return; }
		throw new \RuntimeException('A comma (,) or ] is expected here.');
	}
}

// Check overlay text. Returns array('ok', 'errors' => list of array(line,
// column, key, message), 'values' => validated flat array).
function gp_overlay_file_check($text) {
	$errors = array();
	$text = (string)$text;
	if (strlen($text) > 200000) {
		return array('ok' => false, 'values' => array(),
			'errors' => array(array('line' => 1, 'column' => 1, 'key' => '', 'message' => gp_overlay_msg('file_too_large'))));
	}
	if (!preg_match('//u', $text)) {
		return array('ok' => false, 'values' => array(),
			'errors' => array(array('line' => 1, 'column' => 1, 'key' => '', 'message' => gp_overlay_msg('not_utf8'))));
	}
	$scan = gp_json_scan($text);
	if ($scan['error'] !== '') {
		$before = substr($text, 0, $scan['offset']);
		$nl = strrpos($before, "\n");
		$col = $nl === false ? strlen($before) + 1 : strlen($before) - $nl;
		return array('ok' => false, 'values' => array(), 'errors' => array(array(
			'line' => substr_count($before, "\n") + 1, 'column' => $col, 'key' => '', 'message' => $scan['error'])));
	}
	$data = json_decode($text, true);
	if (!is_array($data) || ($data !== array() && !gv_is_assoc($data)) || ltrim($text)[0] !== '{') {
		return array('ok' => false, 'values' => array(), 'errors' => array(array(
			'line' => 1, 'column' => 1, 'key' => '', 'message' => gp_overlay_msg('not_object'))));
	}
	foreach ($scan['dupes'] as $key => $line) {
		$errors[] = array('line' => $line, 'column' => 1, 'key' => $key, 'message' => gp_overlay_msg('duplicate'));
	}
	$values = array();
	foreach ($data as $key => $value) {
		$key = (string)$key;
		$check = gv_overlay_validate($key, $value);
		if ($check[0]) { $values[$key] = $check[1]; continue; }
		$errors[] = array('line' => isset($scan['keys'][$key]) ? $scan['keys'][$key] : 1, 'column' => 1,
			'key' => $key, 'message' => gp_overlay_msg($check[1], $key));
	}
	usort($errors, function ($a, $b) { return $a['line'] - $b['line']; });
	return array('ok' => !$errors, 'errors' => $errors, 'values' => $values);
}

// Validate and save overlay text. $base_hash is the sha256 of the file the
// editor was opened on: when the file changed since (another tab, the
// settings form), nothing is written and the operator is told.
// Returns check() plus 'changed' (bool) and 'conflict' (bool).
function gp_overlay_file_save($text, $base_hash, $actor, $client_ip) {
	$text = str_replace("\r\n", "\n", (string)$text);
	$check = gp_overlay_file_check($text);
	$check['changed'] = false;
	$check['conflict'] = false;
	if (!$check['ok']) { return $check; }
	$lock = @fopen(gv_overlay_path() . '.lock', 'c');
	if ($lock) { @flock($lock, LOCK_EX); }
	try {
		$current_raw = gp_overlay_file_raw();
		if (!hash_equals(hash('sha256', $current_raw), (string)$base_hash)) {
			$check['ok'] = false;
			$check['conflict'] = true;
			$check['errors'][] = array('line' => 1, 'column' => 1, 'key' => '', 'message' => gp_overlay_msg('conflict'));
			return $check;
		}
		if (rtrim($current_raw) === rtrim($text)) { return $check; }
		$before = gp_overlay_current();
		if (!gp_overlay_backup_current()) {
			$check['ok'] = false;
			$check['errors'][] = array('line' => 1, 'column' => 1, 'key' => '', 'message' => gp_overlay_msg('backup_failed'));
			return $check;
		}
		if (!gp_overlay_write_raw(rtrim($text) . "\n")) {
			$check['ok'] = false;
			$check['errors'][] = array('line' => 1, 'column' => 1, 'key' => '', 'message' => gp_overlay_msg('write_failed'));
			return $check;
		}
		$check['changed'] = true;
	} finally {
		if ($lock) { @flock($lock, LOCK_UN); @fclose($lock); }
	}
	$after = $check['values'];
	foreach (array_unique(array_merge(array_keys($before), array_keys($after))) as $key) {
		$old = array_key_exists($key, $before) ? $before[$key] : null;
		$new = array_key_exists($key, $after) ? $after[$key] : null;
		if ($old === $new) { continue; }
		gp_audit_append(array('event' => 'config_file', 'actor' => (string)$actor,
			'ip' => (string)$client_ip, 'key' => $key, 'old' => $old, 'new' => $new));
	}
	return $check;
}

// One readable sentence per validation code. $key adds the allowed range or
// values where the whitelist knows them.
function gp_overlay_msg($code, $key = '') {
	$rules = gv_overlay_whitelist();
	$spec = ($key !== '' && isset($rules[$key])) ? $rules[$key] : null;
	$text = gp_cio_t('verr_' . $code);
	if ($text === 'verr_' . $code) { $text = $code; }
	if ($spec !== null && ($spec[0] === 'int' || $spec[0] === 'float') && in_array($code, array('out_of_range', 'not_int', 'not_number'), true)) {
		$text .= ' ' . sprintf(gp_cio_t('verr_range_hint'), $spec[1], $spec[2]);
	}
	if ($spec !== null && $spec[0] === 'enum') {
		$text .= ' ' . sprintf(gp_cio_t('verr_enum_hint'), implode(', ', $spec[1]));
	}
	return $text;
}

// gp_t() lives in the front controller; this file is also used without it.
function gp_cio_t($key) {
	return function_exists('gp_t') ? gp_t($key) : $key;
}

// Atomic write of already validated text (see gp_overlay_write()).
function gp_overlay_write_raw($text) {
	try {
		$path = gv_overlay_path();
		$dir = dirname($path);
		if (!is_dir($dir) || !is_writable($dir)) { return false; }
		if (strlen($text) > 200000) { return false; }
		$tmp = $path . '.tmp' . bin2hex(random_bytes(4));
		if (@file_put_contents($tmp, $text, LOCK_EX) === false) {
			@unlink($tmp);
			return false;
		}
		@chmod($tmp, 0640);
		if (!@rename($tmp, $path)) {
			@unlink($tmp);
			return false;
		}
		return true;
	} catch (\Throwable $e) {
		return false;
	}
}
