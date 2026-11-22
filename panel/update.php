<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// In-panel updater: apply a GitHub ZIP of this repository without SSH or git.
//
// Flow (docs/09-ADMIN-PANEL.md, "Update"):
//   1. gp_upd_stage()   read the ZIP, validate every entry, parse-check every PHP file, stage the files
//                       in updates/pending/<id>/ and compute the plan. Nothing in the install changes.
//   2. gp_upd_apply()   after the operator confirmed with the password: write updates/<stamp>/manifest.json,
//                       back up every file that changes, write the recovery scripts from THIS (old) code,
//                       create guard.off, swap the files in with write-temp-then-rename.
//   3. updates/verify.php (a fresh request, written in step 2 from the old code) loads the new code and
//                       runs one synthetic request; failure rolls back automatically.
//   gp_upd_rollback()   restores a backup through updates/rollback.php, the same script the shell and
//                       panel/recover.php use, so there is one implementation of "put the old files back".
//
// Plain functions, no shell, no git, no Composer. ZipArchive when present, otherwise a small pure-PHP reader
// (stored and deflated entries, gzinflate from zlib).

require_once __DIR__ . '/geo.php';              // gp_ini_bytes()
require_once __DIR__ . '/jobs.php';             // gp_job_enqueue()

define('GP_UPD_MAX_ZIP', 30 * 1048576);         // the ZIP of this repository is well under 1 MB; 30 MB is generous
define('GP_UPD_MAX_FILES', 3000);
define('GP_UPD_MAX_FILE', 10 * 1048576);
define('GP_UPD_MAX_UNPACKED', 100 * 1048576);
define('GP_UPD_KEEP', 3);                       // updates kept for rollback
define('GP_UPD_PENDING_TTL', 3600);             // a staged ZIP is discarded after an hour
define('GP_UPD_TOKEN_TTL', 86400);              // recovery token validity

// Top-level directories an update may write into. Anything else in the ZIP is refused (".github" is ignored).
function gp_upd_tree() { return array('guard', 'panel', 'analyzer', 'scripts', 'docs', 'geo', 'lists', 'logs', 'updates'); }
// Allowed file extensions, and the few allowed dot / extension-less names.
function gp_upd_exts() { return array('php', 'py', 'sh', 'md', 'txt', 'json', 'css', 'js', 'woff2', 'ttf', 'png', 'tpl'); }
function gp_upd_names() { return array('.htaccess', '.gitkeep', '.gitignore', 'VERSION', 'LICENSE'); }
// Files that must be in every ZIP: without them it is not this project.
function gp_upd_required() { return array('VERSION', 'prepend.php', 'guard/guard.php', 'panel/index.php'); }
// Scripts a crontab line may call: a change to one of them deserves a look at the crontab.
function gp_upd_cron_files() { return array('scripts/analyzer-cron.sh', 'scripts/cron-check.sh', 'scripts/lib-jobstatus.sh', 'scripts/guard-logrotate.sh', 'scripts/cron_check.py'); }

// The install directory. The self-test points it at a scratch copy through $gp_upd_root.
function gp_upd_root() {
	global $gp_upd_root;
	return (isset($gp_upd_root) && is_string($gp_upd_root) && $gp_upd_root !== '') ? rtrim($gp_upd_root, '/') : dirname(__DIR__);
}
function gp_upd_dir() { return gp_upd_root() . '/updates'; }

function gp_upd_version($root = null) {
	$p = ($root === null ? gp_upd_root() : $root) . '/VERSION';
	$v = is_file($p) ? trim((string)@file_get_contents($p)) : '';
	return preg_match('/^[0-9][0-9A-Za-z._-]{0,31}$/', $v) ? $v : '';
}

function gp_upd_audit($event, $actor, $key, $old = null, $new = null) {
	gp_audit_append(array('event' => $event, 'actor' => (string)$actor, 'ip' => gp_client_ip(), 'key' => (string)$key, 'old' => $old, 'new' => $new));
}

function gp_upd_fail($key, $detail = '') { return array('ok' => false, 'error' => $key, 'detail' => $detail); }

function gp_upd_json_read($path) {
	$raw = @file_get_contents($path);
	$d = is_string($raw) ? json_decode($raw, true) : null;
	return is_array($d) ? $d : null;
}

function gp_upd_json_write($path, array $data) {
	$tmp = $path . '.tmp' . bin2hex(random_bytes(4));
	if (@file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)) === false) { return false; }
	if (!@rename($tmp, $path)) { @unlink($tmp); return false; }
	return true;
}

function gp_upd_rmtree($dir) {
	if (!is_dir($dir) || is_link($dir)) { return; }
	foreach ((array)@scandir($dir) as $n) {
		if ($n === '.' || $n === '..') { continue; }
		$p = $dir . '/' . $n;
		if (is_dir($p) && !is_link($p)) { gp_upd_rmtree($p); } else { @unlink($p); }
	}
	@rmdir($dir);
}

// --------------------------------------------------------------------------
// Protected files (one list: panel/update-protected.txt, plus the .gitignore patterns)
// --------------------------------------------------------------------------

// Patterns from a protected-list or .gitignore text.
function gp_upd_parse_patterns($text) {
	$out = array();
	foreach (preg_split('/\r?\n/', (string)$text) as $line) {
		$line = trim($line);
		if ($line === '' || $line[0] === '#' || $line[0] === '!') { continue; }
		$out[] = ltrim($line, '/');
	}
	return $out;
}

// All patterns that protect a path: the installed list, the list shipped inside the ZIP (if any) and the
// .gitignore of both. $staged: array(rel => contents) of the files that matter, or empty.
function gp_upd_patterns(array $staged = array()) {
	$root = gp_upd_root();
	$texts = array();
	foreach (array('panel/update-protected.txt', '.gitignore') as $rel) {
		if (is_file($root . '/' . $rel)) { $texts[] = (string)@file_get_contents($root . '/' . $rel); }
		if (isset($staged[$rel])) { $texts[] = (string)$staged[$rel]; }
	}
	return array_values(array_unique(gp_upd_parse_patterns(implode("\n", $texts))));
}

function gp_upd_is_protected($rel, array $patterns) {
	$base = basename($rel);
	foreach ($patterns as $pat) {
		$match = false;
		if (substr($pat, -1) === '/') {                       // directory
			$d = rtrim($pat, '/');
			if (strpos($d, '/') === false) {
				$segs = explode('/', $rel);
				array_pop($segs);
				foreach ($segs as $s) { if ($s === $d || fnmatch($d, $s)) { $match = true; break; } }
			} else {
				$match = (strncmp($rel, $d . '/', strlen($d) + 1) === 0);
			}
		} elseif (strpos($pat, '/') === false) {              // a name, in any directory
			$match = ($base === $pat || fnmatch($pat, $base));
		} else {
			$match = ($rel === $pat || fnmatch($pat, $rel));
		}
		if ($match) {
			// Directory patterns protect data, never the .htaccess / .gitkeep files of the repository.
			if (($base === '.htaccess' || $base === '.gitkeep') && $pat !== $rel && strpos($pat, $base) === false) { continue; }
			return true;
		}
	}
	return false;
}

// --------------------------------------------------------------------------
// ZIP reading: ZipArchive, or a pure-PHP reader. Both give the same entry list.
// --------------------------------------------------------------------------

function gp_upd_zip_backend($force = '') {
	if ($force === 'pure') { return function_exists('gzinflate') ? 'pure' : ''; }
	if ($force === 'ziparchive') { return class_exists('ZipArchive') ? 'ziparchive' : ''; }
	if (class_exists('ZipArchive')) { return 'ziparchive'; }
	return function_exists('gzinflate') ? 'pure' : '';
}

// Open a ZIP. Returns array(ok, zip) or a failure: zip = array(backend, path, entries, h).
// An entry: name, dir, size, csize, method, crc, mode (unix permission and type bits, 0 when unknown), symlink, enc, off.
function gp_upd_zip_open($path, $force = '') {
	$backend = gp_upd_zip_backend($force);
	if ($backend === '') { return gp_upd_fail('upd_err_nozip'); }
	if (!is_file($path) || !is_readable($path)) { return gp_upd_fail('upd_err_unreadable'); }
	return $backend === 'ziparchive' ? gp_upd_zip_open_za($path) : gp_upd_zip_open_pure($path);
}

function gp_upd_zip_open_za($path) {
	$za = new ZipArchive();
	$rc = $za->open($path);
	if ($rc !== true) { return gp_upd_fail('upd_err_notzip', (string)$rc); }
	$entries = array();
	for ($i = 0; $i < $za->numFiles; $i++) {
		$st = $za->statIndex($i);
		if (!is_array($st)) { $za->close(); return gp_upd_fail('upd_err_notzip', 'entry ' . $i); }
		$opsys = 0; $attr = 0;
		$za->getExternalAttributesIndex($i, $opsys, $attr);
		$mode = ($opsys === ZipArchive::OPSYS_UNIX) ? (($attr >> 16) & 0xFFFF) : 0;
		$entries[] = array('name' => (string)$st['name'], 'dir' => substr((string)$st['name'], -1) === '/', 'size' => (int)$st['size'],
			'csize' => (int)$st['comp_size'], 'method' => (int)$st['comp_method'], 'crc' => (int)$st['crc'], 'mode' => $mode,
			'symlink' => ($mode & 0170000) === 0120000, 'enc' => (isset($st['encryption_method']) && (int)$st['encryption_method'] !== 0), 'off' => $i);
	}
	return array('ok' => true, 'zip' => array('backend' => 'ziparchive', 'path' => $path, 'entries' => $entries, 'h' => $za));
}

function gp_upd_zip_open_pure($path) {
	$fh = @fopen($path, 'rb');
	if (!$fh) { return gp_upd_fail('upd_err_unreadable'); }
	$size = (int)filesize($path);
	$tail = min($size, 65557);
	fseek($fh, $size - $tail);
	$buf = (string)fread($fh, $tail);
	$pos = strrpos($buf, "PK\x05\x06");
	if ($pos === false || strlen($buf) - $pos < 22) { fclose($fh); return gp_upd_fail('upd_err_notzip', 'no end record'); }
	$e = unpack('vdisk/vcddisk/vn_disk/vn_total/Vcd_size/Vcd_off/vclen', substr($buf, $pos + 4, 18));
	if ($e['n_total'] === 0xFFFF || $e['cd_size'] === 0xFFFFFFFF || $e['cd_off'] === 0xFFFFFFFF) { fclose($fh); return gp_upd_fail('upd_err_zip64'); }
	if ($e['disk'] !== 0 || $e['cddisk'] !== 0) { fclose($fh); return gp_upd_fail('upd_err_notzip', 'multi-disk'); }
	if ($e['cd_off'] + $e['cd_size'] > $size || $e['cd_size'] > 16 * 1048576) { fclose($fh); return gp_upd_fail('upd_err_notzip', 'bad directory'); }
	fseek($fh, $e['cd_off']);
	$cd = $e['cd_size'] > 0 ? (string)fread($fh, $e['cd_size']) : '';
	$entries = array();
	$o = 0;
	for ($i = 0; $i < $e['n_total']; $i++) {
		if (substr($cd, $o, 4) !== "PK\x01\x02" || strlen($cd) - $o < 46) { fclose($fh); return gp_upd_fail('upd_err_notzip', 'bad entry ' . $i); }
		$h = unpack('vmade/vneed/vflags/vmethod/vtime/vdate/Vcrc/Vcsize/Vsize/vnlen/velen/vclen/vdisk/viattr/Veattr/Voff', substr($cd, $o + 4, 42));
		$name = (string)substr($cd, $o + 46, $h['nlen']);
		$o += 46 + $h['nlen'] + $h['elen'] + $h['clen'];
		$mode = (($h['made'] >> 8) === 3) ? (($h['eattr'] >> 16) & 0xFFFF) : 0;
		$entries[] = array('name' => $name, 'dir' => substr($name, -1) === '/', 'size' => (int)$h['size'], 'csize' => (int)$h['csize'],
			'method' => (int)$h['method'], 'crc' => (int)$h['crc'], 'mode' => $mode, 'symlink' => ($mode & 0170000) === 0120000,
			'enc' => ($h['flags'] & 1) === 1, 'off' => (int)$h['off']);
	}
	return array('ok' => true, 'zip' => array('backend' => 'pure', 'path' => $path, 'entries' => $entries, 'h' => $fh));
}

// The bytes of one entry, or false (damaged, wrong checksum, unsupported method).
function gp_upd_zip_read(array $zip, array $e) {
	if ($e['size'] > GP_UPD_MAX_FILE) { return false; }
	if ($zip['backend'] === 'ziparchive') {
		$d = $zip['h']->getFromIndex($e['off']);
		return (is_string($d) && strlen($d) === $e['size']) ? $d : false;
	}
	$fh = $zip['h'];
	fseek($fh, $e['off']);
	$lh = (string)fread($fh, 30);
	if (strlen($lh) < 30 || substr($lh, 0, 4) !== "PK\x03\x04") { return false; }
	$l = unpack('vnlen/velen', substr($lh, 26, 4));
	fseek($fh, $e['off'] + 30 + $l['nlen'] + $l['elen']);
	$raw = $e['csize'] > 0 ? (string)fread($fh, $e['csize']) : '';
	if (strlen($raw) !== $e['csize']) { return false; }
	if ($e['method'] === 0) { $d = $raw; }
	elseif ($e['method'] === 8) { $d = @gzinflate($raw, $e['size'] + 1); }
	else { return false; }
	if (!is_string($d) || strlen($d) !== $e['size']) { return false; }
	return (crc32($d) & 0xFFFFFFFF) === ($e['crc'] & 0xFFFFFFFF) ? $d : false;
}

function gp_upd_zip_close(array $zip) {
	if ($zip['backend'] === 'ziparchive') { @$zip['h']->close(); } else { @fclose($zip['h']); }
}

// --------------------------------------------------------------------------
// Names
// --------------------------------------------------------------------------

// Refuse a name that could leave the install directory. Returns '' when fine, else a detail.
function gp_upd_bad_name($name) {
	if ($name === '' || strlen($name) > 300) { return 'empty or too long'; }
	if (strpos($name, "\\") !== false) { return 'backslash'; }
	if (preg_match('/[\x00-\x1f\x7f]/', $name)) { return 'control character'; }
	if ($name[0] === '/') { return 'absolute path'; }
	if (preg_match('/^[A-Za-z]:/', $name)) { return 'drive letter'; }
	$segs = explode('/', rtrim($name, '/'));
	foreach ($segs as $s) {
		if ($s === '' || $s === '.' || $s === '..') { return 'path traversal'; }
	}
	return '';
}

// Is this file name acceptable (extension or one of the few special names)?
function gp_upd_name_ok($rel) {
	$base = basename($rel);
	if (in_array($base, gp_upd_names(), true)) { return true; }
	$dot = strrpos($base, '.');
	if ($dot === false || $dot === 0) { return false; }
	return in_array(strtolower(substr($base, $dot + 1)), gp_upd_exts(), true);
}

// The ZIP entries as install-relative paths (the single top folder GitHub adds is removed).
// Returns array(ok, files => rel => entry, ignored => n) or a failure.
function gp_upd_entries(array $zip) {
	foreach ($zip['entries'] as $e) {
		$bad = gp_upd_bad_name($e['name']);
		if ($bad !== '') { return gp_upd_fail('upd_err_path', $e['name'] . ' (' . $bad . ')'); }
		if ($e['symlink']) { return gp_upd_fail('upd_err_symlink', $e['name']); }
		if ($e['enc']) { return gp_upd_fail('upd_err_encrypted', $e['name']); }
		if (!$e['dir'] && !in_array($e['method'], array(0, 8), true)) { return gp_upd_fail('upd_err_method', $e['name']); }
	}
	// One top folder shared by every entry, and not itself a directory of the project: strip it.
	$strip = '';
	$first = null;
	$single = count($zip['entries']) > 0;
	foreach ($zip['entries'] as $e) {
		$n = rtrim($e['name'], '/');
		$seg = explode('/', $n);
		if (count($seg) === 1 && !$e['dir']) { $single = false; break; }      // a file at the top: no wrapper folder
		if ($first === null) { $first = $seg[0]; } elseif ($first !== $seg[0]) { $single = false; break; }
	}
	if ($single && $first !== null && !in_array($first, gp_upd_tree(), true) && $first !== '.github') { $strip = $first . '/'; }
	$files = array();
	$ignored = 0;
	foreach ($zip['entries'] as $e) {
		$n = rtrim($e['name'], '/');
		if ($strip !== '') {
			if ($n === rtrim($strip, '/')) { continue; }
			$n = substr($n, strlen($strip));
		}
		if ($e['dir'] || $n === '') { continue; }
		$seg = explode('/', $n);
		if ($seg[0] === '.github') { $ignored++; continue; }              // CI files: not part of an install
		if ($seg[0] === '.git') { return gp_upd_fail('upd_err_tree', $n); }
		if (count($seg) > 1 && !in_array($seg[0], gp_upd_tree(), true)) { return gp_upd_fail('upd_err_tree', $n); }
		if (!gp_upd_name_ok($n)) { return gp_upd_fail('upd_err_ext', $n); }
		if (isset($files[$n])) { return gp_upd_fail('upd_err_dup', $n); }
		if ($e['size'] > GP_UPD_MAX_FILE) { return gp_upd_fail('upd_err_toobig', $n); }
		$files[$n] = $e;
	}
	return array('ok' => true, 'files' => $files, 'ignored' => $ignored);
}

// --------------------------------------------------------------------------
// Step 1: stage and plan
// --------------------------------------------------------------------------

function gp_upd_pending_gc() {
	$base = gp_upd_dir() . '/pending';
	foreach ((array)@scandir($base) as $n) {
		if ($n === '.' || $n === '..') { continue; }
		$m = (int)@filemtime($base . '/' . $n);
		if ($m > 0 && time() - $m > GP_UPD_PENDING_TTL) { gp_upd_rmtree($base . '/' . $n); }
	}
}

// The php.ini ceiling for an upload, and our own cap: the smaller of the two.
function gp_upd_upload_limit() {
	$l = function_exists('gp_geo_upload_limit') ? gp_geo_upload_limit() : 0;
	return $l > 0 ? min($l, GP_UPD_MAX_ZIP) : GP_UPD_MAX_ZIP;
}

// CHANGELOG.md sections (## version) newer than $from and up to $to, newest first.
function gp_upd_changelog($text, $from, $to) {
	$out = array();
	if (!preg_match_all('/^## +(\S+)[ \t]*\r?\n(.*?)(?=^## |\z)/ms', (string)$text, $m, PREG_SET_ORDER)) { return $out; }
	foreach ($m as $sec) {
		$v = $sec[1];
		if (version_compare($v, $to, '>')) { continue; }
		if ($from !== '' && version_compare($v, $from, '<=')) { continue; }
		$out[] = array('version' => $v, 'text' => substr(trim($sec[2]), 0, 2000));
		if (count($out) >= 20) { break; }
	}
	return $out;
}

// Validate a ZIP and stage it. Nothing in the install is changed. Returns array(ok, plan) or a failure.
function gp_upd_stage($zip_path, $orig_name = '', $actor = '', $force_backend = '') {
	$root = gp_upd_root();
	$size = is_file($zip_path) ? (int)filesize($zip_path) : -1;
	if ($size < 0) { return gp_upd_fail('upd_err_unreadable'); }
	if ($size > GP_UPD_MAX_ZIP) { return gp_upd_fail('upd_err_zipbig', (string)GP_UPD_MAX_ZIP); }
	$head = (string)@file_get_contents($zip_path, false, null, 0, 4);
	if ($head !== "PK\x03\x04" && $head !== "PK\x05\x06") { return gp_upd_fail('upd_err_notzip'); }
	$open = gp_upd_zip_open($zip_path, $force_backend);
	if (!$open['ok']) { return $open; }
	$zip = $open['zip'];
	$res = gp_upd_stage_open($zip, $root, $orig_name, $actor);
	gp_upd_zip_close($zip);
	return $res;
}

function gp_upd_stage_open(array $zip, $root, $orig_name, $actor) {
	if (count($zip['entries']) > GP_UPD_MAX_FILES) { return gp_upd_fail('upd_err_toomany', (string)GP_UPD_MAX_FILES); }
	$ent = gp_upd_entries($zip);
	if (!$ent['ok']) { return $ent; }
	$files = $ent['files'];
	foreach (gp_upd_required() as $rel) {
		if (!isset($files[$rel])) { return gp_upd_fail('upd_err_required', $rel); }
	}
	$total = 0;
	foreach ($files as $e) { $total += $e['size']; }
	if ($total > GP_UPD_MAX_UNPACKED) { return gp_upd_fail('upd_err_unpacked', (string)GP_UPD_MAX_UNPACKED); }

	// Patterns: the installed list plus the one in the ZIP (a file protected by either is skipped).
	$extra = array();
	foreach (array('panel/update-protected.txt', '.gitignore') as $rel) {
		if (isset($files[$rel])) { $d = gp_upd_zip_read($zip, $files[$rel]); if ($d !== false) { $extra[$rel] = $d; } }
	}
	$patterns = gp_upd_patterns($extra);

	$pdir = gp_upd_dir() . '/pending';
	if (!is_dir(gp_upd_dir()) && !@mkdir(gp_upd_dir(), 0755, true)) { return gp_upd_fail('upd_err_nowrite', gp_upd_dir()); }
	if (!is_dir($pdir) && !@mkdir($pdir, 0700, true)) { return gp_upd_fail('upd_err_nowrite', $pdir); }
	gp_upd_pending_gc();
	$free = @disk_free_space($pdir);
	if ($free !== false && $free < $total * 2 + 4 * 1048576) { return gp_upd_fail('upd_err_disk'); }
	$id = bin2hex(random_bytes(8));
	$sdir = $pdir . '/' . $id . '/files';
	if (!@mkdir($sdir, 0700, true)) { return gp_upd_fail('upd_err_nowrite', $pdir); }

	$plan_files = array();
	$skipped = array();
	foreach ($files as $rel => $e) {
		if (gp_upd_is_protected($rel, $patterns)) { $skipped[] = $rel; continue; }
		$data = gp_upd_zip_read($zip, $e);
		if ($data === false) { gp_upd_rmtree($pdir . '/' . $id); return gp_upd_fail('upd_err_damaged', $rel); }
		if (preg_match('/\.(php|tpl)$/', $rel)) {
			try { token_get_all($data, TOKEN_PARSE); }
			catch (\Throwable $t) { gp_upd_rmtree($pdir . '/' . $id); return gp_upd_fail('upd_err_parse', $rel . ': ' . $t->getMessage() . ' (line ' . $t->getLine() . ')'); }
		}
		$dest = $sdir . '/' . $rel;
		if (!is_dir(dirname($dest)) && !@mkdir(dirname($dest), 0700, true)) { gp_upd_rmtree($pdir . '/' . $id); return gp_upd_fail('upd_err_nowrite', $pdir); }
		if (@file_put_contents($dest, $data) === false) { gp_upd_rmtree($pdir . '/' . $id); return gp_upd_fail('upd_err_nowrite', $pdir); }
		$exec = ($e['mode'] & 0111) !== 0;
		$plan_files[$rel] = array('path' => $rel, 'sha' => hash('sha256', $data), 'size' => strlen($data), 'exec' => $exec);
	}

	// Compare with what is installed.
	$add = array(); $chg = array(); $same = 0;
	foreach ($plan_files as $rel => $f) {
		$cur = $root . '/' . $rel;
		if (!is_file($cur)) { $add[] = $rel; }
		elseif (hash_file('sha256', $cur) !== $f['sha']) { $chg[] = $rel; }
		else { $same++; }
	}
	$inst = gp_upd_json_read(gp_upd_dir() . '/installed.json');
	$removed = array();
	if ($inst !== null && isset($inst['files']) && is_array($inst['files'])) {
		foreach ($inst['files'] as $rel => $sha) {
			if (!is_string($rel) || isset($plan_files[$rel]) || isset($files[$rel])) { continue; }
			if (gp_upd_bad_name($rel) !== '' || gp_upd_is_protected($rel, $patterns) || !gp_upd_name_ok($rel)) { continue; }
			if (is_file($root . '/' . $rel)) { $removed[] = $rel; }
		}
	}
	sort($add); sort($chg); sort($removed); sort($skipped);

	$from = gp_upd_version($root);
	$to = trim((string)@file_get_contents($sdir . '/VERSION'));
	if (!preg_match('/^[0-9][0-9A-Za-z._-]{0,31}$/', $to)) { gp_upd_rmtree($pdir . '/' . $id); return gp_upd_fail('upd_err_version', substr($to, 0, 40)); }
	$warn = array();
	if ($from === '') { $warn[] = 'no_from_version'; }
	else {
		$c = version_compare($to, $from);
		if ($c < 0) { $warn[] = 'downgrade'; } elseif ($c === 0) { $warn[] = 'same_version'; }
	}
	if (in_array('analyzer/requirements.txt', array_merge($add, $chg), true)) { $warn[] = 'requirements_changed'; }
	if (array_intersect(gp_upd_cron_files(), array_merge($add, $chg))) { $warn[] = 'cron_scripts_changed'; }
	if (is_dir($root . '/.git')) { $warn[] = 'git_present'; }
	if ($inst === null) { $warn[] = 'first_update'; }

	$clog = isset($plan_files['CHANGELOG.md']) ? gp_upd_changelog((string)@file_get_contents($sdir . '/CHANGELOG.md'), $from, $to) : array();
	$plan = array('id' => $id, 'created' => time(), 'actor' => (string)$actor, 'zip_name' => substr(preg_replace('/[^A-Za-z0-9._-]/', '_', basename((string)$orig_name)), 0, 80),
		'backend' => $zip['backend'], 'from' => $from, 'to' => $to, 'files' => array_values($plan_files),
		'add' => $add, 'change' => $chg, 'remove' => $removed, 'unchanged' => $same, 'protected_skipped' => $skipped,
		'ignored' => $ent['ignored'], 'warnings' => $warn, 'changelog' => $clog);
	if (!gp_upd_json_write($pdir . '/' . $id . '/plan.json', $plan)) { gp_upd_rmtree($pdir . '/' . $id); return gp_upd_fail('upd_err_nowrite', $pdir); }
	return array('ok' => true, 'plan' => $plan);
}

// Handle the uploaded file of the Update form. Returns array(ok, id, error, detail).
function gp_upd_upload(array $file, $actor) {
	$err = isset($file['error']) ? (int)$file['error'] : UPLOAD_ERR_NO_FILE;
	if ($err === UPLOAD_ERR_INI_SIZE || $err === UPLOAD_ERR_FORM_SIZE) { return array(false, '', 'upd_err_phplimit', gp_bytes(gp_upd_upload_limit())); }
	if ($err !== UPLOAD_ERR_OK) { return array(false, '', 'upd_err_upload', (string)$err); }
	$tmp = isset($file['tmp_name']) ? (string)$file['tmp_name'] : '';
	if (!is_uploaded_file($tmp) && !(defined('GP_TEST_UPLOADS') && is_file($tmp))) { return array(false, '', 'upd_err_upload', 'not an upload'); }
	$name = isset($file['name']) ? (string)$file['name'] : '';
	if (strtolower(substr($name, -4)) !== '.zip') { return array(false, '', 'upd_err_notzip_name', ''); }
	$r = gp_upd_stage($tmp, $name, $actor);
	if (!$r['ok']) {
		gp_upd_audit('update_refused', $actor, $r['error'], null, array('file' => substr(basename($name), 0, 80), 'detail' => substr((string)$r['detail'], 0, 200)));
		return array(false, '', $r['error'], (string)$r['detail']);
	}
	$p = $r['plan'];
	gp_upd_audit('update_upload', $actor, $p['id'], null, array('file' => $p['zip_name'], 'from' => $p['from'], 'to' => $p['to'],
		'add' => count($p['add']), 'change' => count($p['change']), 'remove' => count($p['remove'])));
	return array(true, $p['id'], '', '');
}

// A staged plan by id, with its files checked again (they sit on disk between two requests).
function gp_upd_plan_load($id) {
	if (!is_string($id) || !preg_match('/^[a-f0-9]{16}$/', $id)) { return null; }
	$dir = gp_upd_dir() . '/pending/' . $id;
	$plan = gp_upd_json_read($dir . '/plan.json');
	if ($plan === null || !isset($plan['files']) || (time() - (int)($plan['created'] ?? 0)) > GP_UPD_PENDING_TTL) { return null; }
	foreach ($plan['files'] as $f) {
		$p = $dir . '/files/' . $f['path'];
		if (!is_file($p) || hash_file('sha256', $p) !== $f['sha']) { return null; }
	}
	return $plan;
}

function gp_upd_plan_discard($id) {
	if (is_string($id) && preg_match('/^[a-f0-9]{16}$/', $id)) { gp_upd_rmtree(gp_upd_dir() . '/pending/' . $id); }
}

// --------------------------------------------------------------------------
// Step 2: apply
// --------------------------------------------------------------------------

// Run an OPcache invalidation for a changed file. The self-test sets $gp_upd_opcache_hook to see the calls.
function gp_upd_opcache($file) {
	global $gp_upd_opcache_hook;
	if (isset($gp_upd_opcache_hook) && is_callable($gp_upd_opcache_hook)) { call_user_func($gp_upd_opcache_hook, $file); }
	if (function_exists('opcache_invalidate')) { @opcache_invalidate($file, true); }
}

function gp_upd_load_rollback() {
	$p = gp_upd_dir() . '/rollback.php';
	if (!is_file($p)) { return false; }
	if (!defined('GP_ROLLBACK_LIB')) { define('GP_ROLLBACK_LIB', 1); }
	$GLOBALS['gprb_dir'] = gp_upd_dir();
	if (!function_exists('gprb_run')) { require $p; }
	return function_exists('gprb_run');
}

// Is every directory the update will write into writable? Returns the first problem or ''.
function gp_upd_writable_problem(array $plan) {
	$root = gp_upd_root();
	foreach (array_merge($plan['add'], $plan['change'], $plan['remove']) as $rel) {
		$p = $root . '/' . $rel;
		if (is_file($p)) { if (!is_writable($p) || !is_writable(dirname($p))) { return $rel; } continue; }
		$d = dirname($p);
		while (!is_dir($d) && $d !== $root && strlen($d) > strlen($root)) { $d = dirname($d); }
		if (!is_writable($d)) { return $rel; }
	}
	if (!is_writable($root) || !is_writable(gp_upd_dir())) { return 'updates/'; }
	return '';
}

// Apply a staged plan. $opts: confirm => list of warning ids the operator confirmed.
// Returns array(ok, stamp, verify_key, token) or a failure. The new files are NOT yet checked: the caller sends
// the browser to updates/verify.php (panel/recover.php?a=verify), which rolls back on its own when the check fails.
function gp_upd_apply($id, $actor, array $opts = array()) {
	$plan = gp_upd_plan_load($id);
	if ($plan === null) { return gp_upd_fail('upd_err_nopending'); }
	$need = array_intersect(array('downgrade', 'same_version', 'git_present'), $plan['warnings']);
	$have = isset($opts['confirm']) && is_array($opts['confirm']) ? $opts['confirm'] : array();
	if (array_diff($need, $have)) { return gp_upd_fail('upd_err_confirm', implode(',', array_diff($need, $have))); }
	$root = gp_upd_root();
	$udir = gp_upd_dir();
	if (!is_dir($udir) && !@mkdir($udir, 0755, true)) { return gp_upd_fail('upd_err_nowrite', $udir); }
	$lock = @fopen($udir . '/.lock', 'c');
	if (!$lock || !@flock($lock, LOCK_EX | LOCK_NB)) { return gp_upd_fail('upd_err_busy'); }
	$res = gp_upd_apply_locked($plan, $actor, $root, $udir);
	@flock($lock, LOCK_UN);
	@fclose($lock);
	return $res;
}

function gp_upd_apply_locked(array $plan, $actor, $root, $udir) {
	// A previous update still waiting for its health check blocks a new one.
	foreach (gp_upd_history(1) as $h) {
		if ($h['status'] === 'applied' || $h['status'] === 'applying') { return gp_upd_fail('upd_err_unverified', $h['stamp']); }
	}
	$bad = gp_upd_writable_problem($plan);
	if ($bad !== '') { return gp_upd_fail('upd_err_notwritable', $bad); }
	$sdir = $udir . '/pending/' . $plan['id'] . '/files';
	$new_bytes = 0; $old_bytes = 0;
	foreach ($plan['files'] as $f) {
		if (in_array($f['path'], array_merge($plan['add'], $plan['change']), true)) { $new_bytes += $f['size']; }
	}
	foreach (array_merge($plan['change'], $plan['remove']) as $rel) { $old_bytes += (int)@filesize($root . '/' . $rel); }
	$need = $new_bytes * 2 + $old_bytes + 4 * 1048576;
	foreach (array($root, $udir) as $where) {
		$free = @disk_free_space($where);
		if ($free !== false && $free < $need) { return gp_upd_fail('upd_err_disk', gp_bytes($need)); }
	}
	foreach (array('rollback' => 'update-rollback.tpl', 'verify' => 'update-verify.tpl') as $name => $tpl) {
		if (!is_file(__DIR__ . '/' . $tpl)) { return gp_upd_fail('upd_err_notemplate', $tpl); }
	}

	$stamp = date('Ymd-His');
	for ($n = 1; is_dir($udir . '/' . $stamp); $n++) { $stamp = date('Ymd-His') . '-' . $n; }
	$sd = $udir . '/' . $stamp;
	if (!@mkdir($sd . '/backup', 0700, true)) { return gp_upd_fail('upd_err_nowrite', $udir); }
	// Recovery scripts, from the code that runs NOW (the old version).
	foreach (array('rollback' => 'update-rollback.tpl', 'verify' => 'update-verify.tpl') as $name => $tpl) {
		$tmp = $udir . '/.' . $name . '.tmp' . bin2hex(random_bytes(3));
		if (@copy(__DIR__ . '/' . $tpl, $tmp) === false || !@rename($tmp, $udir . '/' . $name . '.php')) {
			@unlink($tmp); gp_upd_rmtree($sd); return gp_upd_fail('upd_err_nowrite', $udir);
		}
		gp_upd_opcache($udir . '/' . $name . '.php');
	}

	// Manifest and backups.
	$entries = array();
	$by_path = array();
	foreach ($plan['files'] as $f) { $by_path[$f['path']] = $f; }
	$todo = array();
	foreach ($plan['add'] as $rel) { $todo[] = array($rel, 'add'); }
	foreach ($plan['change'] as $rel) { $todo[] = array($rel, 'change'); }
	foreach ($plan['remove'] as $rel) { $todo[] = array($rel, 'remove'); }
	foreach ($todo as $t) {
		list($rel, $act) = $t;
		$cur = $root . '/' . $rel;
		$before = is_file($cur) ? hash_file('sha256', $cur) : null;
		if ($before !== null) {
			$b = $sd . '/backup/' . $rel;
			if (!is_dir(dirname($b)) && !@mkdir(dirname($b), 0700, true)) { gp_upd_rmtree($sd); return gp_upd_fail('upd_err_nowrite', $udir); }
			if (!@copy($cur, $b) || hash_file('sha256', $b) !== $before) { gp_upd_rmtree($sd); return gp_upd_fail('upd_err_backup', $rel); }
		}
		$entries[] = array('path' => $rel, 'action' => $act, 'before' => $before, 'after' => $act === 'remove' ? null : $by_path[$rel]['sha'],
			'mode_before' => $before !== null ? (int)(fileperms($cur) & 0777) : null, 'size' => $act === 'remove' ? 0 : $by_path[$rel]['size']);
	}
	$guard_off_created = !is_file($root . '/guard.off');
	$token = bin2hex(random_bytes(16));
	$key = bin2hex(random_bytes(16));
	$inst_prev = gp_upd_json_read($udir . '/installed.json');
	$manifest = array('format' => 1, 'stamp' => $stamp, 'status' => 'applying', 'created' => time(), 'actor' => (string)$actor,
		'from' => $plan['from'], 'to' => $plan['to'], 'zip_name' => $plan['zip_name'], 'keep' => GP_UPD_KEEP,
		'guard_off_created' => $guard_off_created, 'verify_key' => $key, 'installed_prev' => $inst_prev,
		'requirements_changed' => in_array('requirements_changed', $plan['warnings'], true),
		'cron_scripts_changed' => in_array('cron_scripts_changed', $plan['warnings'], true),
		'changelog' => $plan['changelog'], 'warnings' => $plan['warnings'], 'files' => $entries);
	if (!gp_upd_json_write($sd . '/manifest.json', $manifest)) { gp_upd_rmtree($sd); return gp_upd_fail('upd_err_nowrite', $udir); }
	// One-time recovery token: only its hash is kept in recovery.json; the plain value is shown once.
	gp_upd_json_write($udir . '/recovery.json', array('hash' => hash('sha256', $token), 'expires' => time() + GP_UPD_TOKEN_TTL, 'stamp' => $stamp));
	@file_put_contents($sd . '/token.once', $token);
	@chmod($sd . '/token.once', 0600);

	// The apply window: guard off (only when it was on), then swap the files.
	if ($guard_off_created && @file_put_contents($root . '/guard.off', "created by the updater " . $stamp . "\n") === false) {
		gp_upd_rmtree($sd); @unlink($udir . '/recovery.json'); return gp_upd_fail('upd_err_notwritable', 'guard.off');
	}
	$failed = '';
	foreach ($entries as $en) {
		$dest = $root . '/' . $en['path'];
		if ($en['action'] === 'remove') { if (is_file($dest) && !@unlink($dest)) { $failed = $en['path']; break; } continue; }
		if (!is_dir(dirname($dest)) && !@mkdir(dirname($dest), 0755, true)) { $failed = $en['path']; break; }
		$tmp = dirname($dest) . '/.' . basename($dest) . '.upd' . bin2hex(random_bytes(3));
		$mode = $en['mode_before'] !== null ? $en['mode_before'] : ($by_path[$en['path']]['exec'] ? 0755 : 0644);
		if (!@copy($sdir . '/' . $en['path'], $tmp) || !@chmod($tmp, $mode) || !@rename($tmp, $dest)) { @unlink($tmp); $failed = $en['path']; break; }
		if (preg_match('/\.(php|tpl)$/', $en['path'])) { gp_upd_opcache($dest); }
	}
	if ($failed !== '') {
		$rb = gp_upd_load_rollback() ? gprb_run($root, $stamp) : array(false, array());
		return gp_upd_fail($rb[0] ? 'upd_err_write_rolled' : 'upd_err_write_failed', $failed);
	}
	// What this ZIP installed: the base for "removed upstream" next time.
	$installed = array();
	foreach ($plan['files'] as $f) { $installed[$f['path']] = $f['sha']; }
	gp_upd_json_write($udir . '/installed.json', array('version' => $plan['to'], 'files' => $installed));
	$manifest['status'] = 'applied';
	$manifest['applied_at'] = time();
	gp_upd_json_write($sd . '/manifest.json', $manifest);
	gp_upd_plan_discard($plan['id']);
	return array('ok' => true, 'stamp' => $stamp, 'verify_key' => $key);
}

// --------------------------------------------------------------------------
// History, rollback, tokens
// --------------------------------------------------------------------------

// The recorded updates, newest first: array of array(stamp, from, to, status, created, actor, ...).
function gp_upd_history($limit = 10) {
	$out = array();
	$stamps = array();
	foreach ((array)@scandir(gp_upd_dir()) as $n) {
		if (preg_match('/^\d{8}-\d{6}(-\d+)?$/', $n) && is_file(gp_upd_dir() . '/' . $n . '/manifest.json')) { $stamps[] = $n; }
	}
	rsort($stamps, SORT_STRING);
	foreach (array_slice($stamps, 0, $limit) as $s) {
		$m = gp_upd_json_read(gp_upd_dir() . '/' . $s . '/manifest.json');
		if ($m === null) { continue; }
		$out[] = array('stamp' => $s, 'from' => (string)($m['from'] ?? ''), 'to' => (string)($m['to'] ?? ''), 'status' => (string)($m['status'] ?? ''),
			'created' => (int)($m['created'] ?? 0), 'actor' => (string)($m['actor'] ?? ''), 'files' => count((array)($m['files'] ?? array())),
			'verify_failed' => (string)($m['verify_failed'] ?? ''), 'verify_key' => (string)($m['verify_key'] ?? ''),
			'requirements_changed' => !empty($m['requirements_changed']), 'cron_scripts_changed' => !empty($m['cron_scripts_changed']),
			'pip_enqueued' => !empty($m['pip_enqueued']), 'changelog' => (array)($m['changelog'] ?? array()));
	}
	return $out;
}

// Roll back $stamp and every newer update. Returns array(ok, log).
function gp_upd_rollback($stamp) {
	if (!is_string($stamp) || !preg_match('/^\d{8}-\d{6}(-\d+)?$/', $stamp)) { return array(false, array('bad stamp')); }
	if (!gp_upd_load_rollback()) { return array(false, array('updates/rollback.php is missing')); }
	$r = gprb_run(gp_upd_root(), $stamp);
	if ($r[0]) { @unlink(gp_upd_dir() . '/recovery.json'); }
	return $r;
}

// The recovery token, shown once: reads and deletes the file the apply step left.
function gp_upd_token_take($stamp) {
	if (!is_string($stamp) || !preg_match('/^\d{8}-\d{6}(-\d+)?$/', $stamp)) { return ''; }
	$p = gp_upd_dir() . '/' . $stamp . '/token.once';
	if (!is_file($p)) { return ''; }
	$t = trim((string)@file_get_contents($p));
	@unlink($p);
	return preg_match('/^[a-f0-9]{32}$/', $t) ? $t : '';
}

function gp_upd_manifest_save($stamp, array $m) {
	return gp_upd_json_write(gp_upd_dir() . '/' . $stamp . '/manifest.json', $m);
}

// After a successful health check (called when the admin lands on the result page): enqueue pip_sync once when
// analyzer/requirements.txt changed. Returns the manifest summary, or null.
function gp_upd_post_verify($stamp, $actor) {
	if (!is_string($stamp) || !preg_match('/^\d{8}-\d{6}(-\d+)?$/', $stamp)) { return null; }
	$m = gp_upd_json_read(gp_upd_dir() . '/' . $stamp . '/manifest.json');
	if ($m === null || ($m['status'] ?? '') !== 'ok') { return null; }
	if (empty($m['audited'])) {
		$m['audited'] = true;
		gp_upd_manifest_save($stamp, $m);
		gp_upd_audit('update_verified', $actor, $stamp, array('version' => $m['from'] ?? ''), array('version' => $m['to'] ?? ''));
	}
	if (!empty($m['requirements_changed']) && empty($m['pip_enqueued'])) {
		$j = gp_job_enqueue('pip_sync', array(), $actor);
		$m['pip_enqueued'] = true;
		$m['pip_job'] = $j['ok'] ? (string)$j['id'] : '';
		$m['pip_error'] = $j['ok'] ? '' : (string)$j['error'];
		gp_upd_manifest_save($stamp, $m);
	}
	return $m;
}

// Dashboard alerts about updates: array of array(code, detail, level). Cheap: one manifest read, and the job list
// only when the newest update asked for a pip_sync.
function gp_upd_health($now = null) {
	$out = array();
	$h = gp_upd_history(1);
	if (!$h) { return $out; }
	$h = $h[0];
	if ($h['status'] === 'applied' || $h['status'] === 'applying') { $out[] = array('unverified', $h['stamp'], 'critical'); }
	elseif ($h['status'] === 'rollback_failed') { $out[] = array('rollback_failed', $h['stamp'], 'critical'); }
	if ($h['status'] === 'ok' && $h['pip_enqueued']) {
		foreach (gp_job_list(30) as $j) {
			if (($j['type'] ?? '') !== 'pip_sync') { continue; }
			if (($j['status'] ?? '') === 'failed') { $out[] = array('pip_failed', 'job ' . (string)($j['id'] ?? ''), 'warning'); }
			break;                                      // only the newest pip_sync counts
		}
	}
	return $out;
}

// What the Update page shows about this PHP: what the updater needs and whether the install is writable.
function gp_upd_environment() {
	$root = gp_upd_root();
	$free = @disk_free_space($root);
	return array('ziparchive' => class_exists('ZipArchive'), 'zlib' => function_exists('gzinflate'), 'backend' => gp_upd_backend_name(),
		'limit' => gp_upd_upload_limit(), 'uploads' => (bool)ini_get('file_uploads'), 'writable' => is_writable($root),
		'updates_writable' => is_dir(gp_upd_dir()) ? is_writable(gp_upd_dir()) : is_writable($root), 'free' => $free === false ? null : (int)$free,
		'git' => is_dir($root . '/.git'), 'opcache' => function_exists('opcache_invalidate'), 'php' => PHP_VERSION);
}

function gp_upd_backend_name() { return gp_upd_zip_backend(); }
