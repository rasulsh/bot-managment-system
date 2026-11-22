<?php
// Bot Guard rollback. Written to updates/rollback.php by the updater BEFORE it applies an update,
// from the code that is running at that moment. It has no dependency on any other file of the
// install (not the guard, not the panel), so it works when the new code is broken.
//
//   Shell:  php <install-dir>/updates/rollback.php            roll back the newest update
//           php <install-dir>/updates/rollback.php --list     list the updates that can be rolled back
//           php <install-dir>/updates/rollback.php <stamp>    roll back that update and every newer one
//   Web:    <panel-url>/recover.php with the one-time recovery token shown after the update
//           (valid 24 hours, single use, stored hashed in updates/recovery.json).
//
// It restores the files saved in updates/<stamp>/backup/ according to updates/<stamp>/manifest.json,
// deletes the files the update added, checks every sha256 afterwards and clears OPcache.
if (!defined('GP_ROLLBACK_LIB') && PHP_SAPI !== 'cli' && !defined('GP_RECOVER_WEB')) { http_response_code(404); exit; }

// $GLOBALS['gprb_dir'] lets the panel (and its self-test) point a loaded copy at another updates/ directory.
function gprb_dir() { return isset($GLOBALS['gprb_dir']) ? $GLOBALS['gprb_dir'] : __DIR__; }
function gprb_root() { return dirname(__DIR__); }

function gprb_json_read($path) {
	$raw = @file_get_contents($path);
	$d = is_string($raw) ? json_decode($raw, true) : null;
	return is_array($d) ? $d : null;
}

function gprb_json_write($path, array $data) {
	$tmp = $path . '.tmp' . bin2hex(random_bytes(4));
	if (@file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)) === false) { return false; }
	if (!@rename($tmp, $path)) { @unlink($tmp); return false; }
	return true;
}

// Update stamps (updates/<stamp>/), newest first.
function gprb_stamps($dir = null) {
	$dir = $dir === null ? gprb_dir() : $dir;
	$out = array();
	foreach ((array)@scandir($dir) as $n) {
		if (preg_match('/^\d{8}-\d{6}(-\d+)?$/', $n) && is_file($dir . '/' . $n . '/manifest.json')) { $out[] = $n; }
	}
	rsort($out, SORT_STRING);
	return $out;
}

// A manifest path must be a plain relative path: it is joined to the install directory.
function gprb_safe_path($p) {
	return is_string($p) && $p !== '' && $p[0] !== '/' && strpos($p, '..') === false
		&& strpos($p, "\\") === false && strpos($p, "\0") === false && !preg_match('/^[A-Za-z]:/', $p);
}

function gprb_opcache($file) {
	if (isset($GLOBALS['gp_upd_opcache_hook']) && is_callable($GLOBALS['gp_upd_opcache_hook'])) {
		call_user_func($GLOBALS['gp_upd_opcache_hook'], $file);
	}
	if (function_exists('opcache_invalidate')) { @opcache_invalidate($file, true); }
}

function gprb_prune_dirs($root, $rel) {
	$d = dirname($rel);
	while ($d !== '.' && $d !== '' && $d !== '/') {
		if (!@rmdir($root . '/' . $d)) { break; }     // not empty (or not ours): stop
		$d = dirname($d);
	}
}

// Roll back ONE update. Returns array(ok, message). Nothing is changed when a backup is missing or damaged.
function gprb_one($root, $stamp, array &$log) {
	$dir = gprb_dir() . '/' . $stamp;
	$m = gprb_json_read($dir . '/manifest.json');
	if ($m === null || !isset($m['files']) || !is_array($m['files'])) { return array(false, 'manifest unreadable: ' . $stamp); }
	if (($m['status'] ?? '') === 'rolled_back') { $log[] = $stamp . ': already rolled back'; return array(true, 'already'); }
	foreach ($m['files'] as $f) {
		if (!is_array($f) || !isset($f['path']) || !gprb_safe_path($f['path'])) { return array(false, 'unsafe path in manifest'); }
		if (!empty($f['before'])) {
			$b = $dir . '/backup/' . $f['path'];
			if (!is_file($b) || hash_file('sha256', $b) !== $f['before']) { return array(false, 'backup missing or damaged: ' . $f['path']); }
		}
	}
	$bad = 0;
	foreach ($m['files'] as $f) {
		$target = $root . '/' . $f['path'];
		if (empty($f['before'])) {                      // added by the update: remove it again
			if (is_file($target) || is_link($target)) { @unlink($target); }
			gprb_prune_dirs($root, $f['path']);
		} else {                                        // changed or removed: put the old bytes back
			$b = $dir . '/backup/' . $f['path'];
			if (!is_dir(dirname($target))) { @mkdir(dirname($target), 0755, true); }
			$tmp = $target . '.rb' . bin2hex(random_bytes(3));
			if (!@copy($b, $tmp) || !@rename($tmp, $target)) { @unlink($tmp); $bad++; $log[] = 'could not restore ' . $f['path']; continue; }
			@chmod($target, isset($f['mode_before']) ? (int)$f['mode_before'] : 0644);
		}
		if (substr($f['path'], -4) === '.php' || substr($f['path'], -4) === '.tpl') { gprb_opcache($target); }
	}
	foreach ($m['files'] as $f) {                        // verify
		$target = $root . '/' . $f['path'];
		$ok = empty($f['before']) ? !file_exists($target) : (is_file($target) && hash_file('sha256', $target) === $f['before']);
		if (!$ok) { $bad++; $log[] = 'mismatch after restore: ' . $f['path']; }
	}
	$inst = gprb_dir() . '/installed.json';
	if (array_key_exists('installed_prev', $m) && $m['installed_prev'] !== null) { gprb_json_write($inst, $m['installed_prev']); }
	elseif (array_key_exists('installed_prev', $m)) { @unlink($inst); }
	if (!empty($m['guard_off_created']) && is_file($root . '/guard.off')) { @unlink($root . '/guard.off'); }
	$m['status'] = $bad === 0 ? 'rolled_back' : 'rollback_failed';
	$m['rolled_back_at'] = time();
	gprb_json_write($dir . '/manifest.json', $m);
	$log[] = $stamp . ': ' . ($bad === 0 ? 'restored ' . count($m['files']) . ' file(s)' : 'FAILED, ' . $bad . ' problem(s)');
	return array($bad === 0, $bad === 0 ? 'ok' : 'verify failed');
}

// Roll back $stamp and every newer update that is not rolled back yet, newest first. Returns array(ok, log[]).
function gprb_run($root, $stamp, $dir_unused = null) {
	$log = array();
	$todo = array();
	foreach (gprb_stamps() as $s) { if (strcmp($s, $stamp) >= 0) { $todo[] = $s; } }
	if (!in_array($stamp, $todo, true)) { return array(false, array('unknown update ' . $stamp)); }
	foreach ($todo as $s) {                                // already newest first
		$r = gprb_one($root, $s, $log);
		if (!$r[0]) { return array(false, $log); }
	}
	return array(true, $log);
}

// The update to roll back by default: the newest one that has not been rolled back.
function gprb_latest() {
	foreach (gprb_stamps() as $s) {
		$m = gprb_json_read(gprb_dir() . '/' . $s . '/manifest.json');
		if (is_array($m) && ($m['status'] ?? '') !== 'rolled_back') { return $s; }
	}
	return '';
}

function gprb_token_ok($token) {
	$r = gprb_json_read(gprb_dir() . '/recovery.json');
	if ($r === null || !is_string($token) || $token === '' || strlen($token) > 128) { return false; }
	if (!isset($r['hash'], $r['expires']) || time() > (int)$r['expires']) { return false; }
	return hash_equals((string)$r['hash'], hash('sha256', $token));
}

function gprb_main_cli(array $argv) {
	if (in_array('--list', $argv, true)) {
		foreach (gprb_stamps() as $s) {
			$m = gprb_json_read(gprb_dir() . '/' . $s . '/manifest.json');
			echo $s . '  ' . ($m['from'] ?? '?') . ' -> ' . ($m['to'] ?? '?') . '  ' . ($m['status'] ?? '?') . "\n";
		}
		return 0;
	}
	$stamp = isset($argv[1]) && $argv[1] !== '' ? $argv[1] : gprb_latest();
	if ($stamp === '') { echo "Nothing to roll back.\n"; return 1; }
	$r = gprb_run(gprb_root(), $stamp);
	foreach ($r[1] as $line) { echo $line . "\n"; }
	if ($r[0]) { @unlink(gprb_dir() . '/recovery.json'); echo "Rolled back. If the site still misbehaves, restart PHP-FPM / reset OPcache.\n"; return 0; }
	echo "Rollback FAILED. Nothing further was changed.\n";
	return 1;
}

function gprb_main_web() {
	if (!headers_sent()) {
		header('Content-Type: text/html; charset=utf-8');
		header('X-Robots-Tag: noindex, nofollow');
		header('Cache-Control: no-store');
	}
	$token = '';
	if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') { $token = is_string($_POST['token'] ?? null) ? $_POST['token'] : ''; }
	else { $token = is_string($_GET['token'] ?? null) ? $_GET['token'] : ''; }
	if (!gprb_token_ok($token)) {
		usleep(400000);
		if (!headers_sent()) {
			http_response_code(404);
			header('Content-Type: text/plain; charset=utf-8');
		}
		return;
	}
	$e = function ($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); };
	$stamp = gprb_latest();
	echo '<!doctype html><html lang="en" dir="ltr"><meta charset="utf-8"><meta name="robots" content="noindex"><title>Bot Guard recovery</title>'
		. '<body style="font-family:sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem"><h1>Bot Guard recovery</h1>';
	if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
		$r = $stamp === '' ? array(false, array('Nothing to roll back.')) : gprb_run(gprb_root(), $stamp);
		if ($r[0]) { @unlink(gprb_dir() . '/recovery.json'); }
		echo '<p><strong>' . ($r[0] ? 'Rolled back.' : 'Rollback failed.') . '</strong></p><pre>' . $e(implode("\n", $r[1])) . '</pre>';
		if ($r[0]) { echo '<p>The token is now used up. If the site still shows old behaviour, reset OPcache or restart PHP.</p>'; }
	} elseif ($stamp === '') {
		echo '<p>Nothing to roll back.</p>';
	} else {
		$m = gprb_json_read(gprb_dir() . '/' . $stamp . '/manifest.json');
		echo '<p>Roll back the update <code>' . $e($stamp) . '</code> (' . $e($m['from'] ?? '?') . ' to ' . $e($m['to'] ?? '?') . ')? '
			. 'The saved files are restored and the files the update added are removed.</p>'
			. '<form method="post"><input type="hidden" name="token" value="' . $e($token) . '"><button type="submit">Roll back now</button></form>';
	}
	echo '</body></html>';
}

if (!defined('GP_ROLLBACK_LIB')) {
	if (PHP_SAPI === 'cli') { exit(gprb_main_cli($argv)); }
	gprb_main_web();
}
