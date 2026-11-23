<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// File permission health check.
//
// Looks for the permission mistakes that break an install silently:
//   * a file or directory that is group- or world-writable (anybody on a shared host could change the code),
//   * a cron script that is not executable (a crontab line that calls it directly then fails without a word),
//   * a secret file that is readable by everybody (guard/config.php holds the secret and the Redis password,
//     panel/panel.config.php the login hash).
// Reads only: lstat() on every entry of the install, skipping .venv, .git and logs. The result is cached for an
// hour in analyzer/.perm-check.json (the scan is cheap, but the dashboard loads often) and recomputed after an
// update. Plain functions, no shell.

define('GP_PERM_TTL', 3600);
define('GP_PERM_MAX_ENTRIES', 200000);       // a safety stop for a runaway tree; hitting it is reported (truncated), never silent
define('GP_PERM_SAMPLE', 8);

// Install files that hold secrets. panel/users.json is listed for the user store that arrives with panel roles;
// it is only judged when it exists.
function gp_perm_secret_files() {
	return array('guard/config.php', 'panel/panel.config.php', 'guard/config.local.json', 'panel/users.json');
}

// Top-level names the scan never enters: the virtualenv, git and logs/ (the guard and the wrappers give logs their own modes). EVERYTHING else is
// scanned, dotfiles and the analyzer's data files included, so the result is the same set every time (it used to differ with who ran the scan).
function gp_perm_skip() { return array('.venv', '.git', 'logs'); }

function gp_perm_cache_path() { return gp_status_dir() . '/.perm-check.json'; }

function gp_perm_cache_clear() { @unlink(gp_perm_cache_path()); }

// Scan the install. Pure apart from the file system. $root defaults to this install.
function gp_perm_scan_now($root = null, $now = null) {
	$root = rtrim($root === null ? dirname(__DIR__) : $root, '/');
	$now = ($now === null || (int)$now <= 0) ? time() : (int)$now;       // a zero "now" must never become the scan's timestamp (it showed as 20,780 days ago)
	$out = array('v' => 1, 'time' => $now, 'root' => $root, 'scanned' => 0, 'truncated' => false, 'unreadable' => array(),
		'writable_dirs' => 0, 'writable_files' => 0, 'writable_sample' => array(), 'cron_not_exec' => array(), 'secret_readable' => array());
	$skip = gp_perm_skip();
	$stack = array('');
	while ($stack) {
		$rel = array_pop($stack);
		$dir = $rel === '' ? $root : $root . '/' . $rel;
		$names = @scandir($dir);          // sorted: the order (and so a cap, if one is ever hit) is the same every time
		if (!is_array($names)) {
			// A directory this process cannot list (another owner, mode 0700) is NOT "no problems": say the scan is incomplete.
			if (count($out['unreadable']) < GP_PERM_SAMPLE) { $out['unreadable'][] = $rel === '' ? '.' : $rel; } else { $out['unreadable_more'] = true; }
			continue;
		}
		foreach ($names as $n) {
			if ($n === '.' || $n === '..') { continue; }
			$r = $rel === '' ? $n : $rel . '/' . $n;
			if ($rel === '' && in_array($n, $skip, true)) { continue; }
			if (++$out['scanned'] > GP_PERM_MAX_ENTRIES) { $out['truncated'] = true; break 2; }
			$p = $root . '/' . $r;
			$st = @lstat($p);
			if ($st === false || ($st['mode'] & 0170000) === 0120000) { continue; }        // a symlink's own mode means nothing
			$isdir = ($st['mode'] & 0170000) === 0040000;
			if (($st['mode'] & 0022) !== 0) {
				if ($isdir) { $out['writable_dirs']++; } else { $out['writable_files']++; }
				if (count($out['writable_sample']) < GP_PERM_SAMPLE) { $out['writable_sample'][] = sprintf('%04o %s', $st['mode'] & 0777, $r . ($isdir ? '/' : '')); }
			}
			if ($isdir) { $stack[] = $r; }
		}
		rsort($stack, SORT_STRING);       // popped in ascending order
	}
	foreach ((array)glob($root . '/scripts/*.sh') as $f) {
		if (!is_file($f) || is_link($f)) { continue; }
		if (((int)@fileperms($f) & 0111) === 0) { $out['cron_not_exec'][] = 'scripts/' . basename($f); }
	}
	foreach (gp_perm_secret_files() as $rel) {
		$f = $root . '/' . $rel;
		if (is_file($f) && !is_link($f) && (((int)@fileperms($f)) & 0004) !== 0) { $out['secret_readable'][] = $rel; }
	}
	sort($out['cron_not_exec']);
	return $out;
}

// The cached scan (an hour), or a fresh one. $force skips the cache. Never throws.
function gp_perm_scan($force = false, $now = null, $root = null) {
	$now = ($now === null || (int)$now <= 0) ? time() : (int)$now;
	$root = rtrim($root === null ? dirname(__DIR__) : $root, '/');
	$cf = gp_perm_cache_path();
	if (!$force && is_file($cf)) {
		$d = json_decode((string)@file_get_contents($cf), true);
		if (is_array($d) && isset($d['time'], $d['root']) && (int)$d['time'] > 0 && $d['root'] === $root && $now - (int)$d['time'] < GP_PERM_TTL && $now >= (int)$d['time'] - 60) { return $d; }
	}
	$s = gp_perm_scan_now($root, $now);
	$tmp = $cf . '.tmp' . getmypid();
	if (@file_put_contents($tmp, json_encode($s), LOCK_EX) !== false) { @chmod($tmp, 0640); if (!@rename($tmp, $cf)) { @unlink($tmp); } }
	return $s;
}

// Whether the scan found anything.
function gp_perm_has_issues(array $s) {
	return $s['writable_dirs'] > 0 || $s['writable_files'] > 0 || $s['cron_not_exec'] || $s['secret_readable'];
}

// The exact commands that fix what the scan found. Paths are shell-quoted. Order: secrets, scripts, writable.
function gp_perm_fix_commands(array $s) {
	$root = $s['root'];
	$q = function ($v) { return escapeshellarg($v); };
	$cmds = array();
	foreach ($s['secret_readable'] as $rel) { $cmds[] = 'chmod 600 ' . $q($root . '/' . $rel); }
	if ($s['cron_not_exec']) { $cmds[] = 'chmod 755 ' . $q($root) . '/scripts/*.sh'; }
	$prune = '\( -path ' . $q($root . '/.venv') . ' -o -path ' . $q($root . '/.git') . ' -o -path ' . $q($root . '/logs') . ' \) -prune -o';
	if ($s['writable_dirs'] > 0) { $cmds[] = 'find ' . $q($root) . ' ' . $prune . ' -type d -perm /022 -exec chmod go-w {} +'; }
	if ($s['writable_files'] > 0) { $cmds[] = 'find ' . $q($root) . ' ' . $prune . ' -type f -perm /022 -exec chmod go-w {} +'; }
	return $cmds;
}
