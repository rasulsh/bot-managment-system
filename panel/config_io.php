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
	return __DIR__ . '/audit.jsonl';
}

// Append one line to the audit trail. Append-only by design: the panel offers
// no delete. This is what later connects "the false-positive rate jumped on
// Tuesday" to "hard_block_score was lowered on Tuesday", and in a security tool
// an untraceable config change is unacceptable.
function gp_audit_append(array $row) {
	try {
		$row = array_merge(array('ts' => round(microtime(true), 3)), $row);
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
function gp_audit_read($limit = 200, $filter = '') {
	$path = gp_audit_path();
	if (!is_file($path)) { return array(); }
	$lines = gp_tail_lines($path, max(1, (int)$limit) * 4, 1048576);
	$out = array();
	foreach (array_reverse($lines) as $line) {
		$row = json_decode($line, true);
		if (!is_array($row)) { continue; }
		if ($filter !== '') {
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
			foreach ($parts as $line) {
				$line = trim($line);
				if ($line !== '') { $out[] = $line; }
			}
			if (count($out) >= $max_lines) { break; }
		}
		if ($pos === 0 && trim($buffer) !== '' && count($out) < $max_lines) {
			array_unshift($out, trim($buffer));
		}
	} catch (\Throwable $e) {
		// fall through with whatever was read
	}
	fclose($fh);
	// gp_tail_lines returns oldest-first within the scanned window.
	return $out;
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
	$effective = gv_cfg_load();
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

	$diff = gp_overlay_diff($clean);
	if (!$diff) {
		return array('ok' => true, 'errors' => array(), 'applied' => array());
	}

	$merged = array_merge(gp_overlay_current(), $clean);
	if (!gp_overlay_write($merged)) {
		return array('ok' => false, 'errors' => array('_write' => 'write_failed'),
			'applied' => array());
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
// on every single request.
function gp_overlay_write(array $flat) {
	try {
		$path = gv_overlay_path();
		$dir = dirname($path);
		if (!is_dir($dir) || !is_writable($dir)) { return false; }
		$flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
		if (defined('JSON_PRETTY_PRINT')) { $flags |= JSON_PRETTY_PRINT; }
		// An empty overlay must still be a JSON object, never [].
		$json = $flat ? json_encode($flat, $flags) : '{}';
		if ($json === false) { return false; }
		$tmp = $path . '.tmp' . bin2hex(random_bytes(4));
		if (@file_put_contents($tmp, $json . "\n", LOCK_EX) === false) {
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
