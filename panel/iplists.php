<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

require_once __DIR__ . '/data.php';
require_once __DIR__ . '/geo.php';
require_once __DIR__ . '/rules.php';

// IP lists: named allow / block lists kept as text, compiled into ONE range file
// per type that the guard binary-searches (guard/iplist.php, the format of
// guard/geo.php).
//
//   lists/lists.json      metadata, written only here (temp file + rename, under a lock)
//   lists/<id>.txt        the source text of a list, one address or CIDR per line
//   lists/allow.bin       compiled from every ENABLED allow list  (kind 3)
//   lists/block.bin       compiled from every ENABLED block list
//   lists/lists-status.json   what the last compile built (written by the compiler)
//
// Small lists are compiled in the panel request (gp_iplists_compile); big ones go
// to the worker as the `iplist_compile` job (analyzer/iplist.py, the same
// algorithm). Both skip lines that do not parse; the strict checks (invalid lines
// by line number, refused entries) run here when a list is saved.

define('GP_IPL_MAX_LISTS', 50);
define('GP_IPL_MAX_LINES', 300000);
define('GP_IPL_MAX_BYTES', 16777216);       // largest source text the panel accepts
define('GP_IPL_INLINE_BYTES', 524288);      // sources up to this size compile inside the request
define('GP_IPL_WIDE_V4', 8);                // a block entry wider than /8 (IPv4) ...
define('GP_IPL_WIDE_V6', 32);               // ... or /32 (IPv6) needs "I know what I'm doing"
define('GP_IPL_ALLOW_WIDE_V4', 16);         // an allow entry wider than /16 is warned about
define('GP_IPL_ALLOW_WIDE_V6', 32);
define('GP_IPL_SHOW_MAX', 200);
define('GP_IPL_SAMPLES', 10);              // dropped entries / invalid lines kept per list in lists-status.json

// ---------------------------------------------------------------- paths

function gp_ipl_dir() { return gv_iplist_dir(); }
function gp_ipl_source_path($id) { return gp_ipl_dir() . '/' . $id . '.txt'; }
function gp_ipl_status_path() { return gp_ipl_dir() . '/lists-status.json'; }

// ---------------------------------------------------------------- address arithmetic (binary strings)

// The string plus one (big endian), or null on overflow.
function gp_ipl_inc($s) {
	for ($i = strlen($s) - 1; $i >= 0; $i--) {
		$b = ord($s[$i]);
		if ($b < 255) { $s[$i] = chr($b + 1); return $s; }
		$s[$i] = "\0";
	}
	return null;
}

// The string minus one, or null on underflow.
function gp_ipl_dec($s) {
	for ($i = strlen($s) - 1; $i >= 0; $i--) {
		$b = ord($s[$i]);
		if ($b > 0) { $s[$i] = chr($b - 1); return $s; }
		$s[$i] = "\xff";
	}
	return null;
}

// One address or CIDR token. Returns array('v' => 4|6, 's' => bin, 'e' => bin, 'p' => prefix) or null.
// Host bits are masked; an IPv4-mapped IPv6 address is the IPv4 address it carries.
function gp_ipl_parse_entry($token) {
	if ($token === '' || strpbrk($token, "% \t") !== false) { return null; }
	$slash = strpos($token, '/');
	$addr = $slash === false ? $token : substr($token, 0, $slash);
	$tail = $slash === false ? null : substr($token, $slash + 1);
	if ($tail !== null && !preg_match('/^[0-9]{1,3}$/', $tail)) { return null; }
	if (filter_var($addr, FILTER_VALIDATE_IP) === false) { return null; }
	$bin = @inet_pton($addr);
	if ($bin === false) { return null; }
	$bits = strlen($bin) * 8;
	$prefix = $tail === null ? $bits : (int)$tail;
	if ($prefix > $bits) { return null; }
	if ($bits === 128 && strncmp($bin, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) === 0) {
		if ($prefix < 96) { return null; }
		$bin = substr($bin, 12);
		$bits = 32;
		$prefix -= 96;
	}
	$s = '';
	$e = '';
	for ($i = 0; $i < strlen($bin); $i++) {
		$keep = max(0, min(8, $prefix - $i * 8));
		$mask = $keep === 0 ? 0 : ((0xFF << (8 - $keep)) & 0xFF);
		$b = ord($bin[$i]);
		$s .= chr($b & $mask);
		$e .= chr(($b & $mask) | (~$mask & 0xFF));
	}
	return array('v' => $bits === 32 ? 4 : 6, 's' => $s, 'e' => $e, 'p' => $prefix);
}

// The canonical text of a parsed entry: "a.b.c.d" / "a.b.c.d/24" / "2001:db8::/32".
function gp_ipl_entry_text(array $en) {
	$full = $en['v'] === 4 ? 32 : 128;
	return inet_ntop($en['s']) . ($en['p'] === $full ? '' : '/' . $en['p']);
}

// The expiry an entry carries in its comment: `203.0.113.7  # expires=2026-11-30` (valid through the END of that day, UTC) or
// `# expires=2026-11-30T14:30` / `2026-11-30 14:30` (UTC, to the minute). Returns array(timestamp, ok): timestamp 0 = no expiry,
// ok = false for an `expires=` that is not a real date (the line is then refused: a typo must not make a temporary entry permanent).
function gp_ipl_expiry($comment) {
	if (!preg_match('/\bexpires\s*=\s*(\S*)(?:[ T](\d{2}:\d{2}))?/i', (string)$comment, $m)) { return array(0, true); }
	if (!preg_match('/^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}))?$/', $m[1], $d)) { return array(0, false); }
	if (!checkdate((int)$d[2], (int)$d[3], (int)$d[1])) { return array(0, false); }
	$hh = isset($d[4]) && $d[4] !== '' ? $d[4] : (isset($m[2]) && $m[2] !== '' ? substr($m[2], 0, 2) : '');
	$mm = isset($d[5]) && $d[5] !== '' ? $d[5] : (isset($m[2]) && $m[2] !== '' ? substr($m[2], 3, 2) : '');
	if ($hh === '') { return array(gmmktime(0, 0, 0, (int)$d[2], (int)$d[3], (int)$d[1]) + 86400, true); }
	if ((int)$hh > 23 || (int)$mm > 59) { return array(0, false); }
	return array(gmmktime((int)$hh, (int)$mm, 0, (int)$d[2], (int)$d[3], (int)$d[1]), true);
}

// A source text -> array(entries, bad). entries: parsed entries with 'line' (and 'exp', the expiry timestamp, when the comment has
// one); bad: array(array(line, text)). Handles a BOM, CRLF, # comments, blank lines and an optional CSV first column.
function gp_ipl_parse_text($text) {
	if (strncmp($text, "\xEF\xBB\xBF", 3) === 0) { $text = substr($text, 3); }
	$entries = array();
	$bad = array();
	$n = 0;
	foreach (preg_split('/\r\n|\n|\r/', $text) as $line) {
		$n++;
		$hash = strpos($line, '#');
		$comment = '';
		if ($hash !== false) { $comment = substr($line, $hash + 1); $line = substr($line, 0, $hash); }
		$line = trim($line);
		if ($line === '') { continue; }
		$comma = strpos($line, ',');
		$token = trim(trim($comma === false ? $line : substr($line, 0, $comma)), "\"' \t");
		$en = gp_ipl_parse_entry($token);
		$exp = gp_ipl_expiry($comment);
		if ($en === null || !$exp[1]) { $bad[] = array($n, substr($line, 0, 80)); }
		else { $en['line'] = $n; if ($exp[0] > 0) { $en['exp'] = $exp[0]; } $entries[] = $en; }
		if ($n >= GP_IPL_MAX_LINES) { break; }
	}
	return array($entries, $bad);
}

// Sorted, merged array(s, e) pairs (overlapping and adjacent ranges join).
function gp_ipl_union(array $pairs) {
	usort($pairs, function ($a, $b) { $c = strcmp($a[0], $b[0]); return $c !== 0 ? $c : strcmp($a[1], $b[1]); });
	$out = array();
	$last = -1;
	foreach ($pairs as $p) {
		if ($last >= 0) {
			$nx = gp_ipl_inc($out[$last][1]);
			if ($nx === null || strcmp($p[0], $nx) <= 0) {
				if (strcmp($p[1], $out[$last][1]) > 0) { $out[$last][1] = $p[1]; }
				continue;
			}
		}
		$out[] = $p;
		$last++;
	}
	return $out;
}

// Min-heap on the range value: the smaller value is at the top.
class GpIplHeap extends SplHeap {
	protected function compare($a, $b): int { return $b[0] <=> $a[0]; }
}

// Sorted, non-overlapping array(s, e, value) from possibly overlapping ones: at every
// address the SMALLEST value wins (enforced beats monitor, then the lower list index),
// whatever the widths. Same result as analyzer/iplist.py sweep().
function gp_ipl_sweep(array $ranges) {
	usort($ranges, function ($a, $b) {
		$c = strcmp($a[0], $b[0]);
		if ($c !== 0) { return $c; }
		return $a[2] !== $b[2] ? $a[2] <=> $b[2] : strcmp($a[1], $b[1]);
	});
	$out = array();
	$last = -1;
	$heap = new GpIplHeap();
	$i = 0;
	$n = count($ranges);
	$pos = '';
	while ($i < $n || !$heap->isEmpty()) {
		if ($heap->isEmpty()) { $pos = $ranges[$i][0]; }
		while ($i < $n && strcmp($ranges[$i][0], $pos) <= 0) { $heap->insert(array($ranges[$i][2], $ranges[$i][1])); $i++; }
		while (!$heap->isEmpty() && strcmp($heap->top()[1], $pos) < 0) { $heap->extract(); }
		if ($heap->isEmpty()) { continue; }
		$top = $heap->top();
		$end = $top[1];
		if ($i < $n) {
			$nx = gp_ipl_dec($ranges[$i][0]);
			if ($nx !== null && strcmp($nx, $end) < 0) { $end = $nx; }
		}
		if ($last >= 0 && $out[$last][2] === $top[0] && gp_ipl_inc($out[$last][1]) === $pos) { $out[$last][1] = $end; }
		else { $out[] = array($pos, $end, $top[0]); $last++; }
		$pos = gp_ipl_inc($end);
		if ($pos === null) { break; }                 // the top of the address space: nothing can follow
	}
	return $out;
}

// The bytes of a compiled IP list file (guard/geo.php layout, kind 3, uint16 values).
function gp_ipl_pack(array $v4, array $v6, $built, $source, $sha_hex) {
	$out = 'GVRG' . pack('nCCNNNN', 1, GV_GEO_IPLIST, 2, (int)$built, count($v4), count($v6), 0)
		. ($sha_hex !== '' ? hex2bin($sha_hex) : str_repeat("\0", 32)) . str_pad(substr($source, 0, 72), 72, "\0");
	$parts = array($out);
	foreach (array($v4, $v6) as $set) { foreach ($set as $r) { $parts[] = $r[0] . $r[1] . pack('n', $r[2]); } }
	return implode('', $parts);
}

// Atomic replace of a compiled file; the file it replaces becomes <path>.prev.
function gp_ipl_swap_in($path, $data) {
	$tmp = $path . '.tmp' . getmypid();
	if (@file_put_contents($tmp, $data, LOCK_EX) === false) { @unlink($tmp); return false; }
	@chmod($tmp, 0640);
	if (is_file($path)) {
		$ptmp = $path . '.prev.tmp' . getmypid();
		if (@copy($path, $ptmp)) { @rename($ptmp, $path . '.prev'); } else { @unlink($ptmp); }
	}
	if (!@rename($tmp, $path)) { @unlink($tmp); return false; }
	return true;
}

// Number of IPv4 addresses in a union.
function gp_ipl_count4(array $u) {
	$n = 0;
	foreach ($u as $r) { $n += unpack('N', $r[1])[1] - unpack('N', $r[0])[1] + 1; }
	return $n;
}

// Whether $key (4 or 16 bytes) lies in a union (binary search).
function gp_ipl_contains(array $u, $key) {
	$lo = 0;
	$hi = count($u) - 1;
	while ($lo <= $hi) {
		$mid = ($lo + $hi) >> 1;
		if (strcmp($key, $u[$mid][0]) < 0) { $hi = $mid - 1; }
		elseif (strcmp($key, $u[$mid][1]) > 0) { $lo = $mid + 1; }
		else { return true; }
	}
	return false;
}

// The overlaps of two unions: array(s, e) pairs. Linear merge.
function gp_ipl_intersect(array $a, array $b, $limit = 50) {
	$out = array();
	$i = $j = 0;
	while ($i < count($a) && $j < count($b) && count($out) < $limit) {
		$s = strcmp($a[$i][0], $b[$j][0]) >= 0 ? $a[$i][0] : $b[$j][0];
		$e = strcmp($a[$i][1], $b[$j][1]) <= 0 ? $a[$i][1] : $b[$j][1];
		if (strcmp($s, $e) <= 0) { $out[] = array($s, $e); }
		if (strcmp($a[$i][1], $b[$j][1]) < 0) { $i++; } else { $j++; }
	}
	return $out;
}

// ---------------------------------------------------------------- refusals

// Ranges a list entry must not cover without "I know what I'm doing": private, loopback,
// link-local and unspecified space, plus the server's own address and the operator's own.
function gp_ipl_protected($extra = array()) {
	$set = array('0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
		'::/128', '::1/128', 'fc00::/7', 'fe80::/10');
	foreach ((array)$extra as $ip) { if (is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) !== false) { $set[] = $ip; } }
	$out = array();
	foreach ($set as $c) { $en = gp_ipl_parse_entry($c); if ($en) { $out[] = $en; } }
	return $out;
}

// The server's own addresses as this request sees them (SERVER_ADDR / LOCAL_ADDR).
function gp_ipl_server_addresses() {
	$own = array();
	foreach (array('SERVER_ADDR', 'LOCAL_ADDR') as $k) {
		if (!empty($_SERVER[$k]) && is_string($_SERVER[$k]) && filter_var($_SERVER[$k], FILTER_VALIDATE_IP) !== false) { $own[] = gv_ip_canon($_SERVER[$k]); }
	}
	return $own;
}

// The server's own addresses kept in lists.json ("own"): the panel adds the ones it sees on every metadata
// write, so the compile step (here and the worker's) can protect them without a request. 16 at most.
function gp_ipl_merge_own(array $stored, array $seen) {
	$out = array();
	foreach (array_merge($stored, $seen) as $ip) {
		if (is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) !== false && !in_array($ip, $out, true)) { $out[] = $ip; }
	}
	return array_slice($out, 0, 16);
}

// The addresses to protect at save time: the stored server addresses and the operator's own.
function gp_ipl_own_addresses($client_ip = '', array $stored = array()) {
	$own = gp_ipl_merge_own($stored, gp_ipl_server_addresses());
	if ($client_ip !== '') { $own[] = $client_ip; }
	return $own;
}

// THE SAFETY CAPS: one function, used by the compile step (here and analyzer/iplist.py, which mirrors
// it exactly) and by the form's save check. Why an entry of a list of this type is dropped, or '' when
// it is kept. Pure.
//   'all'        0.0.0.0/0 or ::/0: ALWAYS dropped, even with "force" (an allow list with it would switch
//                the whole guard off, a block list would refuse everybody).
//   'allow_wide' an allow entry wider than /16 (IPv4) or /32 (IPv6)
//   'wide'       a block entry wider than /8 (IPv4) or /32 (IPv6)
//   'protected'  a block entry that covers private, loopback, link-local space or the server's own address
// The list's "force" flag (set only from the panel, audit-logged) keeps everything except 'all'.
function gp_ipl_refusal(array $en, $type, array $protected, $force = false) {
	if ($en['p'] === 0) { return 'all'; }
	if ($force) { return ''; }
	if ($type === 'allow') { return $en['p'] < ($en['v'] === 4 ? GP_IPL_ALLOW_WIDE_V4 : GP_IPL_ALLOW_WIDE_V6) ? 'allow_wide' : ''; }
	if ($en['p'] < ($en['v'] === 4 ? GP_IPL_WIDE_V4 : GP_IPL_WIDE_V6)) { return 'wide'; }
	foreach ($protected as $p) {
		if ($p['v'] !== $en['v']) { continue; }
		if (strcmp($en['s'], $p['e']) <= 0 && strcmp($en['e'], $p['s']) >= 0) { return 'protected'; }
	}
	return '';
}

// The reasons, in the order they are reported.
function gp_ipl_reasons() { return array('all', 'allow_wide', 'wide', 'protected'); }

// An allow entry wider than /8 would skip the guard for a huge part of the internet: the dashboard calls
// this one critical.
function gp_ipl_is_huge(array $en) { return $en['p'] < 8; }

// ---------------------------------------------------------------- metadata (lists.json)

function gp_ipl_slug($name) {
	$s = trim(preg_replace('/[^a-z0-9]+/', '-', strtolower((string)$name)), '-');
	$s = substr($s, 0, 24);
	$s = trim($s, '-');
	return $s === '' ? 'list' : $s;
}

// Characters in a UTF-8 text (mbstring is optional everywhere else in the panel, so it is here).
function gp_ipl_len($s) { return function_exists('mb_strlen') ? mb_strlen($s, 'UTF-8') : preg_match_all('/./us', $s); }

// Validate one list record. Returns array(true, clean) or array(false, code).
function gp_ipl_validate_meta($l) {
	if (!is_array($l)) { return array(false, 'bad_list'); }
	$id = isset($l['id']) && is_string($l['id']) ? $l['id'] : '';
	if (!preg_match('/^[a-z0-9][a-z0-9-]{0,23}$/', $id)) { return array(false, 'bad_id'); }
	$name = isset($l['name']) && is_string($l['name']) ? trim($l['name']) : '';
	if ($name === '' || gp_ipl_len($name) > 80 || !preg_match('//u', $name) || preg_match('/[\x00-\x1F\x7F]/', $name)) { return array(false, 'bad_name'); }
	if (!isset($l['type']) || !in_array($l['type'], gv_iplist_types(), true)) { return array(false, 'bad_type'); }
	if (!isset($l['mode']) || !in_array($l['mode'], array('enforce', 'monitor'), true)) { return array(false, 'bad_mode'); }
	$idx = isset($l['idx']) ? $l['idx'] : 0;
	if (!is_int($idx) || $idx < 1 || $idx > 0x7FFF) { return array(false, 'bad_idx'); }
	$note = isset($l['note']) && is_string($l['note']) ? trim($l['note']) : '';
	if (gp_ipl_len($note) > 200 || !preg_match('//u', $note) || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $note)) { return array(false, 'bad_note'); }
	return array(true, array('id' => $id, 'idx' => $idx, 'name' => $name, 'type' => $l['type'], 'enabled' => !empty($l['enabled']),
		'mode' => $l['mode'], 'force' => !empty($l['force']), 'note' => $note,
		'created_by' => isset($l['created_by']) && is_string($l['created_by']) ? substr($l['created_by'], 0, 64) : '',
		'created_at' => isset($l['created_at']) ? (int)$l['created_at'] : 0, 'updated_at' => isset($l['updated_at']) ? (int)$l['updated_at'] : 0));
}

// The metadata file as the panel sees it. state: missing | ok | invalid.
function gp_iplists_state() {
	$path = gv_iplist_meta_path();
	$out = array('state' => 'missing', 'lists' => array(), 'next_idx' => 1, 'own' => array(), 'path' => $path);
	if (!is_file($path)) { return $out; }
	$raw = @file_get_contents($path);
	if ($raw === false || trim($raw) === '') { $out['state'] = 'ok'; return $out; }
	$d = json_decode($raw, true);
	if (!is_array($d) || !isset($d['lists']) || !is_array($d['lists'])) { $out['state'] = 'invalid'; return $out; }
	$out['state'] = 'ok';
	foreach ($d['lists'] as $l) {
		$v = gp_ipl_validate_meta($l);
		if ($v[0]) { $out['lists'][] = $v[1]; } else { $out['state'] = 'invalid'; }
	}
	$out['next_idx'] = max(1, isset($d['next_idx']) ? (int)$d['next_idx'] : 1);
	$out['own'] = gp_ipl_merge_own(isset($d['own']) && is_array($d['own']) ? $d['own'] : array(), array());
	foreach ($out['lists'] as $l) { $out['next_idx'] = max($out['next_idx'], $l['idx'] + 1); }
	return $out;
}

function gp_ipl_ensure_dir() {
	$dir = gp_ipl_dir();
	if (!is_dir($dir)) { @mkdir($dir, 0750, true); }
	if (is_dir($dir) && !is_file($dir . '/.htaccess') && is_file(__DIR__ . '/../geo/.htaccess')) { @copy(__DIR__ . '/../geo/.htaccess', $dir . '/.htaccess'); }
	return is_dir($dir) && is_writable($dir);
}

// Write lists.json (temp + rename). Returns true or false.
function gp_iplists_write(array $lists, $next_idx, array $own = array()) {
	if (!gp_ipl_ensure_dir()) { return false; }
	$json = json_encode(array('v' => 1, 'next_idx' => (int)$next_idx, 'own' => array_values($own), 'lists' => array_values($lists)), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
	if ($json === false) { return false; }
	$path = gv_iplist_meta_path();
	$tmp = $path . '.tmp' . getmypid();
	if (@file_put_contents($tmp, $json, LOCK_EX) === false) { return false; }
	@chmod($tmp, 0640);
	if (!@rename($tmp, $path)) { @unlink($tmp); return false; }
	return true;
}

// Read-modify-write of the metadata under one lock. $fn(lists, next_idx) returns
// array(lists, next_idx) or a string error key. Returns array(ok, error key).
function gp_iplists_update($fn) {
	if (!gp_ipl_ensure_dir()) { return array(false, 'write_failed'); }
	$lock = @fopen(gp_ipl_dir() . '/.meta.lock', 'c');
	if ($lock) { @flock($lock, LOCK_EX); }
	try {
		$st = gp_iplists_state();
		if ($st['state'] === 'invalid') { return array(false, 'ipl_file_invalid'); }
		$new = $fn($st['lists'], $st['next_idx']);
		if (is_string($new)) { return array(false, $new); }
		// every metadata write also records the server's own addresses this request sees
		return gp_iplists_write($new[0], $new[1], gp_ipl_merge_own($st['own'], gp_ipl_server_addresses())) ? array(true, '') : array(false, 'write_failed');
	} finally {
		if ($lock) { @flock($lock, LOCK_UN); @fclose($lock); }
	}
}

function gp_ipl_audit($actor, $ip, $id, $old, $new) {
	gp_audit_append(array('event' => 'iplist', 'actor' => (string)$actor, 'ip' => (string)$ip, 'key' => $id, 'old' => $old, 'new' => $new));
}

function gp_ipl_find(array $lists, $id) {
	foreach ($lists as $l) { if ($l['id'] === $id) { return $l; } }
	return null;
}

// ---------------------------------------------------------------- compile (in the panel request)

// What the last compile wrote (lists-status.json), or null.
function gp_iplists_status() {
	$raw = @file_get_contents(gp_ipl_status_path());
	$d = is_string($raw) ? json_decode($raw, true) : null;
	return (is_array($d) && isset($d['types']) && is_array($d['types'])) ? $d : null;
}

// Build allow.bin and block.bin from the enabled lists. The same algorithm as
// analyzer/iplist.py. Returns the status array (also written to lists-status.json).
function gp_iplists_compile($now = null) {
	$now = $now === null ? time() : (int)$now;
	$status = array('v' => 1, 'time' => $now, 'by' => 'php', 'ok' => true, 'errors' => array(), 'types' => array('allow' => null, 'block' => null), 'lists' => array(), 'next_expiry' => 0);
	if (!gp_ipl_ensure_dir()) { $status['ok'] = false; $status['errors'][] = 'the lists directory is not writable: ' . gp_ipl_dir(); return $status; }
	$lock = @fopen(gp_ipl_dir() . '/.compile.lock', 'c');
	if ($lock) { @flock($lock, LOCK_EX); }
	try {
		$st = gp_iplists_state();
		$lists = $st['lists'];
		$protected = gp_ipl_protected($st['own']);          // private space + the server's own addresses (block lists)
		usort($lists, function ($a, $b) { return $a['idx'] <=> $b['idx']; });
		foreach (gv_iplist_types() as $type) {
			$mine = array_values(array_filter($lists, function ($l) use ($type) { return $l['type'] === $type && $l['enabled']; }));
			gp_ipl_compile_type($type, $mine, $now, $status, $protected);
		}
		$status['ok'] = !$status['errors'];
		$path = gp_ipl_status_path();
		$tmp = $path . '.tmp' . getmypid();
		if (@file_put_contents($tmp, json_encode($status, JSON_UNESCAPED_SLASHES), LOCK_EX) !== false && @rename($tmp, $path)) { @chmod($path, 0640); }
		else { @unlink($tmp); $status['ok'] = false; $status['errors'][] = 'cannot write lists-status.json'; }
	} finally {
		if ($lock) { @flock($lock, LOCK_UN); @fclose($lock); }
	}
	return $status;
}

function gp_ipl_compile_type($type, array $lists, $now, array &$status, array $protected = array()) {
	$path = gv_iplist_file($type);
	$r4 = array();
	$r6 = array();
	$digest = hash_init('sha256');
	$failed = false;
	foreach ($lists as $l) {
		$value = $l['idx'] | ($l['mode'] === 'monitor' ? GV_IPL_MONITOR : 0);
		$raw = @file_get_contents(gp_ipl_source_path($l['id']));
		if ($raw === false) { $status['errors'][] = $l['id'] . ': cannot read the source'; $failed = true; continue; }
		hash_update($digest, $l['idx'] . ':' . $l['mode'] . ':' . $raw);
		// The same checks as a panel upload, for a file that never went through the form (SFTP, the worker):
		// lines that do not parse are counted and shown, entries over a cap are dropped; nothing is fatal.
		list($entries, $bad) = gp_ipl_parse_text($raw);
		$dropped = array_fill_keys(gp_ipl_reasons(), 0);
		$samples = array();
		$huge = 0;
		$own4 = array();
		$own6 = array();
		$expired = 0;
		foreach ($entries as $k => $en) {
			// An entry past its `# expires=` time is ignored here, and its line is removed from the source below.
			if (isset($en['exp']) && $en['exp'] <= $now) { $expired++; unset($entries[$k]); continue; }
			// The earliest future expiry, stored in the status so the worker (every minute) knows when to recompile.
			if (isset($en['exp']) && ((int)($status['next_expiry'] ?? 0) === 0 || $en['exp'] < $status['next_expiry'])) { $status['next_expiry'] = (int)$en['exp']; }
			$why = gp_ipl_refusal($en, $type, $protected, $l['force']);
			if ($why !== '') {
				$dropped[$why]++;
				if ($type === 'allow' && gp_ipl_is_huge($en)) { $huge++; }
				if (count($samples) < GP_IPL_SAMPLES) { $samples[] = array(gp_ipl_entry_text($en), $why); }
				continue;
			}
			if ($en['v'] === 4) { $own4[] = array($en['s'], $en['e']); } else { $own6[] = array($en['s'], $en['e']); }
		}
		$u4 = gp_ipl_union($own4);
		$u6 = gp_ipl_union($own6);
		$status['lists'][$l['id']] = array('entries' => count($entries) - array_sum($dropped), 'v4' => count($u4), 'v6' => count($u6),
			'addresses' => gp_ipl_count4($u4), 'invalid' => count($bad), 'invalid_samples' => array_slice($bad, 0, GP_IPL_SAMPLES),
			'dropped' => $dropped, 'dropped_n' => array_sum($dropped), 'dropped_huge' => $huge, 'dropped_samples' => $samples, 'expired' => $expired);
		if ($expired > 0) { gp_ipl_prune_expired($l['id'], $raw, $now); }
		foreach ($u4 as $r) { $r4[] = array($r[0], $r[1], $value); }
		foreach ($u6 as $r) { $r6[] = array($r[0], $r[1], $value); }
	}
	if ($failed) { return; }                       // keep the file the guard has
	if (!$r4 && !$r6) { if (is_file($path)) { @unlink($path); } return; }
	$v4 = gp_ipl_sweep($r4);
	$v6 = gp_ipl_sweep($r6);
	$sha = hash_final($digest);
	if (!gp_ipl_swap_in($path, gp_ipl_pack($v4, $v6, $now, 'iplists-' . $type, $sha))) {
		$status['errors'][] = $type . ': cannot write ' . basename($path);
		return;
	}
	$status['types'][$type] = array('built' => $now, 'v4' => count($v4), 'v6' => count($v6), 'sha' => $sha, 'lists' => array_map(function ($l) { return $l['id']; }, $lists));
}

// Remove the lines whose `# expires=` time has passed from a list source (the compile ignored them already). $raw is what the compile
// read: if the file changed since (an editor saved meanwhile), nothing is rewritten and the next compile does it. Atomic replace,
// same mode. Returns the number of lines removed.
function gp_ipl_prune_expired($id, $raw, $now) {
	$path = gp_ipl_source_path($id);
	$keep = array();
	$gone = 0;
	foreach (preg_split('/(?<=\n)|(?<=\r)(?!\n)/', (string)$raw, -1, PREG_SPLIT_NO_EMPTY) as $line) {
		$hash = strpos($line, '#');
		if ($hash !== false) {
			$exp = gp_ipl_expiry(substr($line, $hash + 1));
			$body = trim(substr($line, 0, $hash));
			if ($body !== '' && $exp[1] && $exp[0] > 0 && $exp[0] <= $now) { $gone++; continue; }
		}
		$keep[] = $line;
	}
	if ($gone === 0 || @file_get_contents($path) !== $raw) { return 0; }
	$tmp = $path . '.tmp' . getmypid();
	$mode = @fileperms($path);
	if (@file_put_contents($tmp, implode('', $keep)) === false) { @unlink($tmp); return 0; }
	if ($mode !== false) { @chmod($tmp, $mode & 0777); }
	if (!@rename($tmp, $path)) { @unlink($tmp); return 0; }
	return $gone;
}

// Total size of the enabled sources: decides between an inline compile and the worker job.
function gp_ipl_enabled_bytes(array $lists) {
	$n = 0;
	foreach ($lists as $l) { if ($l['enabled']) { $n += (int)@filesize(gp_ipl_source_path($l['id'])); } }
	return $n;
}

// Where a compile runs: 'inline' (in the request) for small sources, 'job' (the worker) for big ones.
function gp_iplists_compile_mode(array $lists, $force_job = false) {
	return (!$force_job && gp_ipl_enabled_bytes($lists) <= GP_IPL_INLINE_BYTES) ? 'inline' : 'job';
}

// Record the server's own addresses (see gp_ipl_merge_own) when this request sees one that is not stored yet.
function gp_iplists_touch_own() {
	$st = gp_iplists_state();
	if ($st['state'] === 'ok' && $st['lists'] && gp_ipl_merge_own($st['own'], gp_ipl_server_addresses()) !== $st['own']) {
		gp_iplists_update(function ($lists, $next) { return array($lists, $next); });        // the update records the server addresses
	}
}

// Compile now (small) or queue the job (big). Returns array(ok, lang key, detail).
function gp_iplists_compile_auto($actor, $force_job = false) {
	gp_iplists_touch_own();                          // the worker compiles with the addresses stored in lists.json
	$st = gp_iplists_state();
	if (gp_iplists_compile_mode($st['lists'], $force_job) === 'inline') {
		$r = gp_iplists_compile();
		return $r['ok'] ? array(true, 'ipl_compiled', '') : array(false, 'ipl_compile_failed', implode('; ', array_slice($r['errors'], 0, 3)));
	}
	$j = gp_job_enqueue('iplist_compile', array(), $actor);
	return $j['ok'] ? array(true, 'ipl_compile_queued', $j['id']) : array(false, 'ipl_compile_failed', (string)$j['error']);
}

// ---------------------------------------------------------------- saving a list

function gp_ipl_pending_path($token) { return gp_ipl_dir() . '/.pending-' . $token . '.txt'; }

function gp_ipl_clean_pending() {
	foreach ((array)@glob(gp_ipl_dir() . '/.pending-*.txt') as $f) { if (is_file($f) && filemtime($f) < time() - 86400) { @unlink($f); } }
}

// The meta fields from a form post, validated. Returns array(clean or null, error code).
function gp_ipl_meta_from_post(array $p, ?array $existing, array $lists, $next_idx, $actor) {
	$now = time();
	$name = isset($p['name']) && is_string($p['name']) ? trim($p['name']) : '';
	$rec = array(
		'id' => $existing ? $existing['id'] : '', 'idx' => $existing ? $existing['idx'] : $next_idx,
		'name' => $name, 'type' => $existing ? $existing['type'] : (isset($p['type']) ? (string)$p['type'] : ''),
		'enabled' => !empty($p['enabled']), 'mode' => isset($p['mode']) ? (string)$p['mode'] : '',
		'force' => !empty($p['force']), 'note' => isset($p['note']) && is_string($p['note']) ? $p['note'] : '',
		'created_by' => $existing ? $existing['created_by'] : (string)$actor, 'created_at' => $existing ? $existing['created_at'] : $now, 'updated_at' => $now);
	if (!$existing) {
		$base = gp_ipl_slug($name);
		$id = $base;
		for ($i = 2; gp_ipl_find($lists, $id) !== null; $i++) { $id = substr($base, 0, 21) . '-' . $i; }
		$rec['id'] = $id;
	}
	$v = gp_ipl_validate_meta($rec);
	return $v[0] ? array($v[1], '') : array(null, $v[1]);
}

// Save a list (create or edit). $p: the POST fields; $file: an entry of $_FILES or null.
// Returns array('ok', 'msg' lang key, 'detail', 'errors' field => code, 'report' (invalid and refused lines),
// 'pending' token, 'draft').
function gp_iplists_save(array $p, $file, $actor, $client_ip) {
	$res = array('ok' => false, 'msg' => 'ipl_invalid', 'detail' => '', 'errors' => array(), 'report' => null, 'pending' => '', 'draft' => null);
	$st = gp_iplists_state();
	if ($st['state'] === 'invalid') { $res['msg'] = 'ipl_file_invalid'; return $res; }
	$id = isset($p['id']) && is_string($p['id']) ? $p['id'] : '';
	$existing = $id !== '' ? gp_ipl_find($st['lists'], $id) : null;
	if ($id !== '' && $existing === null) { $res['msg'] = 'ipl_not_found'; return $res; }
	if ($existing && function_exists('gp_feed_owner') && gp_feed_owner($existing['id']) !== null) { $res['msg'] = 'ipl_feed_owned'; return $res; }   // a feed's list is edited in the Feeds tab
	if (!$existing && count($st['lists']) >= GP_IPL_MAX_LISTS) { $res['msg'] = 'ipl_too_many'; return $res; }
	list($meta, $code) = gp_ipl_meta_from_post($p, $existing, $st['lists'], $st['next_idx'], $actor);
	$res['draft'] = array('id' => $id, 'name' => isset($p['name']) ? (string)$p['name'] : '', 'type' => $existing ? $existing['type'] : (string)($p['type'] ?? 'block'),
		'mode' => (string)($p['mode'] ?? 'monitor'), 'enabled' => !empty($p['enabled']), 'force' => !empty($p['force']), 'note' => (string)($p['note'] ?? ''), 'text' => '');
	if ($meta === null) {
		$res['errors'][preg_match('/^bad_(name|type|mode|note)$/', $code, $m) ? $m[1] : 'name'] = $code;
		return $res;
	}
	// The text: an uploaded file, a kept pending text, or the pasted box.
	$text = null;
	$token = isset($p['pending']) && is_string($p['pending']) && preg_match('/^[a-f0-9]{16}$/', $p['pending']) ? $p['pending'] : '';
	$up = is_array($file) && isset($file['error']) ? (int)$file['error'] : UPLOAD_ERR_NO_FILE;
	if ($up === UPLOAD_ERR_INI_SIZE || $up === UPLOAD_ERR_FORM_SIZE) { $res['msg'] = 'ipl_up_toobig'; $res['errors']['file'] = 'toobig'; return $res; }
	if ($up === UPLOAD_ERR_OK) {
		$tmp = (string)($file['tmp_name'] ?? '');
		if (!is_uploaded_file($tmp) && !(defined('GP_TEST_UPLOADS') && is_file($tmp))) { $res['msg'] = 'ipl_up_failed'; return $res; }
		if ((int)filesize($tmp) > GP_IPL_MAX_BYTES) { $res['msg'] = 'ipl_up_toobig'; $res['errors']['file'] = 'toobig'; return $res; }
		$text = (string)file_get_contents($tmp);
		$token = '';
	} elseif ($up !== UPLOAD_ERR_NO_FILE) { $res['msg'] = 'ipl_up_failed'; $res['detail'] = (string)$up; return $res; }
	elseif ($token !== '' && is_file(gp_ipl_pending_path($token))) { $text = (string)file_get_contents(gp_ipl_pending_path($token)); }
	elseif (isset($p['text']) && is_string($p['text']) && trim($p['text']) !== '') { $text = $p['text']; $token = ''; }
	if ($text !== null && strlen($text) > GP_IPL_MAX_BYTES) { $res['msg'] = 'ipl_up_toobig'; $res['errors']['text'] = 'toobig'; return $res; }
	if ($text !== null && !preg_match('//u', $text)) { $res['msg'] = 'ipl_not_text'; $res['errors']['text'] = 'not_utf8'; return $res; }

	$report = null;
	$clean = null;
	$sum = null;
	if ($text !== null) {
		list($entries, $bad) = gp_ipl_parse_text($text);
		$prot = gp_ipl_protected(gp_ipl_own_addresses($client_ip, $st['own']));
		$ok_entries = array();
		$refused = array();
		foreach ($entries as $en) {
			$why = gp_ipl_refusal($en, $meta['type'], $prot, $meta['force']);
			if ($why === '') { $ok_entries[] = $en; } else { $refused[] = array($en['line'], gp_ipl_entry_text($en), $why); }
		}
		$report = array('invalid' => array_slice($bad, 0, GP_IPL_SHOW_MAX), 'invalid_n' => count($bad), 'refused' => array_slice($refused, 0, GP_IPL_SHOW_MAX), 'refused_n' => count($refused));
		if ((count($bad) || count($refused)) && empty($p['accept'])) {
			// Nothing is saved until the operator confirms: keep the text for the next submit.
			if ($token === '') {
				$token = bin2hex(random_bytes(8));
				gp_ipl_ensure_dir();
				@file_put_contents(gp_ipl_pending_path($token), $text, LOCK_EX);
				@chmod(gp_ipl_pending_path($token), 0640);
			}
			$res['msg'] = 'ipl_confirm';
			$res['report'] = $report;
			$res['pending'] = $token;
			return $res;
		}
		$lines = array();
		$u4 = array();
		$u6 = array();
		foreach ($ok_entries as $en) {
			$lines[] = gp_ipl_entry_text($en);
			if ($en['v'] === 4) { $u4[] = array($en['s'], $en['e']); } else { $u6[] = array($en['s'], $en['e']); }
		}
		$u4 = gp_ipl_union($u4);
		$u6 = gp_ipl_union($u6);
		$clean = $lines ? implode("\n", $lines) . "\n" : '';
		$sum = array('entries' => count($ok_entries), 'ranges' => count($u4) + count($u6), 'addresses' => gp_ipl_count4($u4), 'v6' => count($u6),
			'skipped' => count($bad) + count($refused));
	} elseif (!$existing) {
		$clean = '';
		$sum = array('entries' => 0, 'ranges' => 0, 'addresses' => 0, 'v6' => 0, 'skipped' => 0);
	}

	if (!gp_ipl_ensure_dir()) { $res['msg'] = 'write_failed'; return $res; }
	if ($clean !== null) {
		$sp = gp_ipl_source_path($meta['id']);
		$tmp = $sp . '.tmp' . getmypid();
		if (@file_put_contents($tmp, $clean, LOCK_EX) === false || !@rename($tmp, $sp)) { @unlink($tmp); $res['msg'] = 'write_failed'; return $res; }
		@chmod($sp, 0640);
	}
	$r = gp_iplists_update(function ($lists, $next) use ($meta, $existing) {
		if ($existing) { foreach ($lists as $i => $l) { if ($l['id'] === $meta['id']) { $lists[$i] = $meta; } } }
		else { $lists[] = $meta; $next = max($next, $meta['idx'] + 1); }
		return array($lists, $next);
	});
	if (!$r[0]) { $res['msg'] = $r[1]; return $res; }
	if ($token !== '') { @unlink(gp_ipl_pending_path($token)); }
	gp_ipl_clean_pending();
	gp_ipl_audit($actor, $client_ip, $meta['id'], $existing, array_merge($meta, $sum !== null ? array('counts' => $sum) : array()));
	$c = gp_iplists_compile_auto($actor);
	$res['ok'] = true;
	$res['msg'] = $existing ? 'ipl_saved' : 'ipl_created';
	$res['detail'] = ($sum !== null ? $sum['entries'] . ' entries, ' . $sum['ranges'] . ' ranges, ' . $sum['addresses'] . ' IPv4 addresses' . ($sum['skipped'] ? ', ' . $sum['skipped'] . ' skipped' : '') . '. ' : '')
		. gp_t_safe($c[1]) . ($c[2] !== '' ? ': ' . $c[2] : '');
	$res['report'] = $report;
	$res['compile'] = $c;
	return $res;
}

// Delete a list: its source, its record, then recompile.
function gp_iplists_delete($id, $actor, $client_ip) {
	$st = gp_iplists_state();
	$l = gp_ipl_find($st['lists'], (string)$id);
	if ($l === null) { return array(false, 'ipl_not_found', ''); }
	if (function_exists('gp_feed_owner') && gp_feed_owner($l['id']) !== null) { return array(false, 'ipl_feed_owned', ''); }
	$r = gp_iplists_update(function ($lists, $next) use ($l) {
		return array(array_values(array_filter($lists, function ($x) use ($l) { return $x['id'] !== $l['id']; })), $next);
	});
	if (!$r[0]) { return array(false, $r[1], ''); }
	@unlink(gp_ipl_source_path($l['id']));
	gp_ipl_audit($actor, $client_ip, $l['id'], $l, null);
	$c = gp_iplists_compile_auto($actor);
	return array(true, 'ipl_deleted', gp_t_safe($c[1]));
}

// Switch a list on or off (or between modes), then recompile.
function gp_iplists_set(array $p, $actor, $client_ip) {
	$id = isset($p['id']) && is_string($p['id']) ? $p['id'] : '';
	$st = gp_iplists_state();
	$old = gp_ipl_find($st['lists'], $id);
	if ($old === null) { return array(false, 'ipl_not_found', ''); }
	if (function_exists('gp_feed_owner') && gp_feed_owner($old['id']) !== null) { return array(false, 'ipl_feed_owned', ''); }
	$new = $old;
	if (isset($p['enabled'])) { $new['enabled'] = ($p['enabled'] === '1'); }
	if (isset($p['mode']) && in_array($p['mode'], array('enforce', 'monitor'), true)) { $new['mode'] = $p['mode']; }
	if ($new === $old) { return array(true, 'ipl_saved', ''); }
	$new['updated_at'] = time();
	$r = gp_iplists_update(function ($lists, $next) use ($new) {
		foreach ($lists as $i => $l) { if ($l['id'] === $new['id']) { $lists[$i] = $new; } }
		return array($lists, $next);
	});
	if (!$r[0]) { return array(false, $r[1], ''); }
	gp_ipl_audit($actor, $client_ip, $id, $old, $new);
	$c = gp_iplists_compile_auto($actor);
	return array(true, 'ipl_saved', gp_t_safe($c[1]));
}

// Put the previous compiled file of a type back (copy .prev next to it, then rename over it).
function gp_iplists_rollback($type, $actor, $client_ip) {
	$type = $type === 'block' ? 'block' : 'allow';
	$path = gv_iplist_file($type);
	$prev = $path . '.prev';
	if (!is_file($prev)) { return array(false, 'geo_rb_none', ''); }
	$h = gv_geo_header_parse((string)@file_get_contents($prev, false, null, 0, GV_GEO_HEADER));
	if ($h === null || $h['kind'] !== GV_GEO_IPLIST) { return array(false, 'geo_rb_bad', ''); }
	$tmp = $path . '.rb' . getmypid();
	if (!@copy($prev, $tmp) || !@rename($tmp, $path)) { @unlink($tmp); return array(false, 'write_failed', ''); }
	gp_ipl_audit($actor, $client_ip, $type . '.bin', null, array('rollback' => true, 'built' => (int)$h['built']));
	return array(true, 'ipl_rb_done', basename($path));
}

// The source text of a list, for the export link. '' for an unknown list.
function gp_iplists_export($id) {
	$st = gp_iplists_state();
	$l = gp_ipl_find($st['lists'], (string)$id);
	if ($l === null) { return array(null, ''); }
	$raw = @file_get_contents(gp_ipl_source_path($l['id']));
	return array($l, $raw === false ? '' : $raw);
}

// ---------------------------------------------------------------- view data

// One list's state for the table: pending (changed since the last compile), file status.
function gp_iplists_pending($state, $status) {
	if (!$state['lists']) { return false; }
	$m = @filemtime($state['path']);
	if ($status === null) { return (bool)array_filter($state['lists'], function ($l) { return $l['enabled']; }); }
	return $m !== false && $m > (int)$status['time'];
}

// The list table rows: record + counts from the last compile + the hits from the snapshot.
function gp_iplists_rows(array $lists, $status, $snapshot) {
	$hits = (is_array($snapshot) && isset($snapshot['iplists']) && is_array($snapshot['iplists'])) ? $snapshot['iplists'] : array();
	$rows = array();
	foreach ($lists as $l) {
		$c = ($status && isset($status['lists'][$l['id']]) && is_array($status['lists'][$l['id']])) ? $status['lists'][$l['id']] : array();
		$key = $l['type'] . ':' . $l['id'];
		$rows[] = array_merge($l, array('stat' => $c, 'hit' => isset($hits[$key]) && is_array($hits[$key]) ? $hits[$key] : array()));
	}
	return $rows;
}

function gp_iplists_filter_spec() { return array('name' => 'text', 'type' => 'choice', 'mode' => 'choice', 'status' => 'choice'); }

// The status word a row filters on.
function gp_iplists_row_status(array $l) { return $l['enabled'] ? 'enabled' : 'disabled'; }

// The rows under the filter (include or exclude). Pure.
function gp_iplists_filter_rows(array $rows, array $f) {
	$out = array();
	foreach ($rows as $r) {
		if (isset($f['name']) && !gp_filter_test('text', $f['name'], $r['name'] . ' ' . $r['id'])) { continue; }
		if (isset($f['type']) && !gp_filter_test('choice', $f['type'], $r['type'])) { continue; }
		if (isset($f['mode']) && !gp_filter_test('choice', $f['mode'], $r['mode'])) { continue; }
		if (isset($f['status']) && !gp_filter_test('choice', $f['status'], gp_iplists_row_status($r))) { continue; }
		$out[] = $r;
	}
	return $out;
}

// Entries of one list for the Entries tab, under the entry text / family filter. Returns
// array(rows (capped), total matching, total entries, bad lines).
function gp_iplists_entries($id, array $f) {
	$st = gp_iplists_state();
	$l = gp_ipl_find($st['lists'], (string)$id);
	if ($l === null) { return array(array(), 0, 0, 0); }
	$raw = @file_get_contents(gp_ipl_source_path($l['id']));
	list($entries, $bad) = gp_ipl_parse_text($raw === false ? '' : $raw);
	$rows = array();
	$n = 0;
	foreach ($entries as $en) {
		$text = gp_ipl_entry_text($en);
		if (isset($f['entry']) && !gp_filter_test('text', $f['entry'], $text)) { continue; }
		if (isset($f['family']) && !gp_filter_test('choice', $f['family'], 'v' . $en['v'])) { continue; }
		$n++;
		if (count($rows) < GP_IPL_SHOW_MAX) { $rows[] = array('line' => $en['line'], 'text' => $text, 'v' => $en['v'], 'exp' => isset($en['exp']) ? (int)$en['exp'] : 0); }
	}
	return array($rows, $n, count($entries), count($bad));
}

// ---------------------------------------------------------------- tester

// Which lists hold an address: the live compiled files (what the guard does) and the
// source scan (which entry). Returns null for something that is not an address.
function gp_iplists_test($ip) {
	$ip = gp_geo_clean_ip($ip);
	if ($ip === '') { return null; }
	$st = gp_iplists_state();
	$res = array('ip' => $ip, 'live' => array(), 'matches' => array());
	$hit = gv_iplist_check($ip);
	foreach (gv_iplist_types() as $t) {
		if ($hit[$t] !== null) { $res['live'][$t] = array('id' => gv_iplist_id($hit[$t]['idx']), 'monitor' => $hit[$t]['monitor']); }
	}
	$key = gv_geo_key($ip);
	foreach ($st['lists'] as $l) {
		$raw = @file_get_contents(gp_ipl_source_path($l['id']));
		if ($raw === false) { continue; }
		list($entries) = gp_ipl_parse_text($raw);
		foreach ($entries as $en) {
			if (strlen($en['s']) === strlen($key) && strcmp($key, $en['s']) >= 0 && strcmp($key, $en['e']) <= 0) {
				$res['matches'][] = array('id' => $l['id'], 'name' => $l['name'], 'type' => $l['type'], 'enabled' => $l['enabled'], 'mode' => $l['mode'], 'entry' => gp_ipl_entry_text($en), 'line' => $en['line']);
				break;
			}
		}
	}
	// The effective decision, in the guard's order.
	$eff = '';
	if (isset($res['live']['allow']) && !$res['live']['allow']['monitor']) { $eff = 'allow'; }
	elseif (isset($res['live']['block']) && !$res['live']['block']['monitor']) { $eff = 'block'; }
	elseif ($res['live']) { $eff = 'monitor'; }
	$res['effective'] = $eff;
	return $res;
}

// ---------------------------------------------------------------- deny overrides under an allow list

// The id of the ENFORCED allow list that holds this address (the guard checks it before any override,
// so such an address is never denied), or ''. Reads the live compiled file, like the guard.
function gp_iplists_allow_cover($ip) {
	$ip = gp_geo_clean_ip($ip);
	if ($ip === '') { return ''; }
	$h = gv_iplist_check($ip);
	return ($h['allow'] !== null && !$h['allow']['monitor']) ? gv_iplist_id($h['allow']['idx']) : '';
}

// The addresses recent log rows show for these device ids (bounded by the log scan caps).
function gp_iplists_device_ips(array $devs, $max = 20) {
	$want = array_fill_keys($devs, true);
	$out = array();
	if (!$want) { return $out; }
	gp_log_scan(array_slice(gp_log_dates(), 0, 2), function ($row) use ($want, &$out, $max) {
		$d = isset($row['dev']) && is_string($row['dev']) ? $row['dev'] : '';
		if ($d === '' || !isset($want[$d]) || !isset($row['ip']) || !is_string($row['ip'])) { return; }
		if (!isset($out[$d])) { $out[$d] = array(); }
		if (count($out[$d]) < $max && !in_array($row['ip'], $out[$d], true)) { $out[$d][] = $row['ip']; }
	});
	return $out;
}

// Which of these identities (an address or a device id) a deny override can NOT touch because the address
// (for a device: an address it was seen on) is inside an enforced allow list. Returns identity => list id.
function gp_iplists_deny_shadow(array $identities) {
	// The answer depends on the identities, the enforced allow list and, for a device, on the addresses it was seen on in the last logs
	// (a scan of up to 8 MiB). It is cached for two minutes under a key made of the identities and the allow list's size and mtime, so
	// reloading the Overrides page does not rescan the logs each time.
	$ids = array_values(array_unique(array_filter($identities, 'is_string')));
	sort($ids);
	$allow = @stat(gv_iplist_file('allow'));
	$key = sha1(json_encode($ids) . '|' . ($allow ? $allow['mtime'] . ':' . $allow['size'] : '-') . '|' . @filemtime(gv_iplist_meta_path()));
	$file = gv_panel_data_dir() . '/.shadow-cache.json';
	$c = json_decode((string)@file_get_contents($file), true);
	if (is_array($c) && ($c['key'] ?? '') === $key && (time() - (int)($c['at'] ?? 0)) < 120 && is_array($c['out'] ?? null) && !defined('GP_SELFTEST')) { return $c['out']; }
	$out = gp_iplists_deny_shadow_scan($identities);
	if (is_dir(dirname($file)) && is_writable(dirname($file))) { @file_put_contents($file, json_encode(array('key' => $key, 'at' => time(), 'out' => $out)), LOCK_EX); }
	return $out;
}

function gp_iplists_deny_shadow_scan(array $identities) {
	$out = array();
	$devs = array();
	foreach ($identities as $id) {
		if (!is_string($id) || $id === '') { continue; }
		if (filter_var($id, FILTER_VALIDATE_IP) !== false) {
			$l = gp_iplists_allow_cover($id);
			if ($l !== '') { $out[$id] = $l; }
		} else { $devs[] = $id; }
	}
	foreach (gp_iplists_device_ips($devs) as $dev => $ips) {
		foreach ($ips as $ip) {
			$l = gp_iplists_allow_cover($ip);
			if ($l !== '') { $out[$dev] = $l; break; }
		}
	}
	return $out;
}

// ---------------------------------------------------------------- warnings

// ASNs of mobile operators whose addresses are shared by many subscribers (a partial, fixed list:
// the Iranian operators first, then a few large ones elsewhere). An allow entry inside one of them lets every subscriber bypass the guard.
function gp_ipl_mobile_asns() {
	return array(197207 => 'MCI', 44244 => 'Irancell', 57218 => 'Rightel',
		21928 => 'T-Mobile US', 22394 => 'Verizon Wireless', 20057 => 'AT&T Mobility', 12576 => 'EE', 55836 => 'Reliance Jio',
		45609 => 'Bharti Airtel', 38266 => 'Vodafone Idea', 16135 => 'Turkcell', 15897 => 'Vodafone Turkey');
}

// Warnings for the enabled lists: conflicts, wide allow entries, shared ranges, crawlers. Returns a
// list of array(code, text detail). $verified_ips: addresses of verified crawlers seen in the logs.
// Pure apart from reading the sources (and the ASN file for the mobile check).
function gp_iplists_warnings(array $lists, array $verified_ips = array(), $max_bytes = 8388608) {
	$w = array();
	$unions = array();                              // id => array('v4' => union, 'v6' => union)
	$total = 0;
	$wide_allow = array();
	$shared = array();
	$mobile = array();
	foreach ($lists as $l) {
		if (!$l['enabled']) { continue; }
		$sz = (int)@filesize(gp_ipl_source_path($l['id']));
		$total += $sz;
		if ($total > $max_bytes) { $w[] = array('too_big', ''); break; }
		$raw = @file_get_contents(gp_ipl_source_path($l['id']));
		list($entries) = gp_ipl_parse_text($raw === false ? '' : $raw);
		$u4 = array(); $u6 = array();
		$cg = gp_ipl_parse_entry('100.64.0.0/10');
		foreach ($entries as $en) {
			if ($en['v'] === 4) { $u4[] = array($en['s'], $en['e']); } else { $u6[] = array($en['s'], $en['e']); }
			if ($l['type'] !== 'allow') { continue; }
			if ($en['p'] < ($en['v'] === 4 ? GP_IPL_ALLOW_WIDE_V4 : GP_IPL_ALLOW_WIDE_V6) && count($wide_allow) < 5) { $wide_allow[] = $l['id'] . ': ' . gp_ipl_entry_text($en); }
			if ($en['v'] === 4 && strcmp($en['s'], $cg['e']) <= 0 && strcmp($en['e'], $cg['s']) >= 0 && count($shared) < 5) { $shared[] = $l['id'] . ': ' . gp_ipl_entry_text($en); }
		}
		if ($l['type'] === 'allow' && is_file(gv_geo_file(GV_GEO_ASN))) {
			$seen = 0;
			foreach ($entries as $en) {
				if (++$seen > 2000) { break; }
				$asn = gv_geo_asn(inet_ntop($en['s']), true);
				if ($asn > 0 && isset(gp_ipl_mobile_asns()[$asn]) && count($mobile) < 5) { $mobile[] = $l['id'] . ': ' . gp_ipl_entry_text($en) . ' (AS' . $asn . ' ' . gp_ipl_mobile_asns()[$asn] . ')'; }
			}
		}
		$unions[$l['id']] = array('v4' => gp_ipl_union($u4), 'v6' => gp_ipl_union($u6));
	}
	if ($wide_allow) { $w[] = array('allow_wide', implode('; ', $wide_allow)); }
	if ($shared) { $w[] = array('allow_shared', implode('; ', $shared)); }
	if ($mobile) { $w[] = array('allow_mobile', implode('; ', $mobile)); }
	// An address in both an allow and a block list: the allow list wins.
	$conf = array();
	foreach ($lists as $a) {
		if (!$a['enabled'] || $a['type'] !== 'allow' || !isset($unions[$a['id']])) { continue; }
		foreach ($lists as $b) {
			if (!$b['enabled'] || $b['type'] !== 'block' || !isset($unions[$b['id']])) { continue; }
			foreach (array('v4', 'v6') as $fam) {
				foreach (gp_ipl_intersect($unions[$a['id']][$fam], $unions[$b['id']][$fam], 5) as $o) {
					if (count($conf) < 10) { $conf[] = inet_ntop($o[0]) . ($o[0] === $o[1] ? '' : ' - ' . inet_ntop($o[1])) . ' (' . $a['id'] . ' / ' . $b['id'] . ')'; }
				}
			}
		}
	}
	if ($conf) { $w[] = array('conflict', implode('; ', $conf)); }
	// A block entry that covers a verified crawler address seen in the logs.
	$crawl = array();
	foreach ($lists as $b) {
		if (!$b['enabled'] || $b['type'] !== 'block' || !isset($unions[$b['id']])) { continue; }
		foreach ($verified_ips as $ip) {
			$k = gv_geo_key($ip);
			$u = $unions[$b['id']][strlen($k) === 4 ? 'v4' : 'v6'];
			if ($k !== '' && gp_ipl_contains($u, $k) && count($crawl) < 5) { $crawl[] = $ip . ' (' . $b['id'] . ')'; }
		}
	}
	if ($crawl) { $w[] = array('block_crawler', implode('; ', $crawl)); }
	return $w;
}

// Verified-crawler addresses seen in the most recent log rows (botv = ok). Bounded by the log scan caps.
function gp_iplists_verified_ips($max = 2000) {
	$ips = array();
	$dates = array_slice(gp_log_dates(), 0, 2);
	gp_log_scan($dates, function ($row) use (&$ips, $max) {
		if (count($ips) >= $max) { return; }
		if (isset($row['botv'], $row['ip']) && $row['botv'] === 'ok' && is_string($row['ip']) && $row['ip'] !== '') { $ips[$row['ip']] = true; }
	});
	return array_keys($ips);
}

// gp_iplists_warnings() for the IP lists page, cached per LIST VERSION: the warnings read every enabled source (up to 8 MiB), look up the ASN
// of up to 2000 entries per allow list and need the verified crawlers of the last two log days (a log scan). The key is made of every list's
// id, switches and the size / mtime of its source and of the ASN file, so editing any list, or the GeoIP data, recomputes it at once;
// the crawlers part ages out after five minutes. The page used to do all of it on every GET.
function gp_iplists_warnings_cached(array $lists) {
	$parts = array();
	foreach ($lists as $l) {
		$st = @stat(gp_ipl_source_path($l['id']));
		$parts[] = array($l['id'], !empty($l['enabled']), isset($l['type']) ? $l['type'] : '', isset($l['mode']) ? $l['mode'] : '', $st ? $st['size'] . ':' . $st['mtime'] : '-');
	}
	$asn = @stat(gv_geo_dir() . '/asn.bin');
	$key = sha1(json_encode($parts) . '|' . ($asn ? $asn['size'] . ':' . $asn['mtime'] : '-'));
	$file = gv_panel_data_dir() . '/.iplist-warnings.json';
	$c = json_decode((string)@file_get_contents($file), true);
	if (is_array($c) && ($c['key'] ?? '') === $key && (time() - (int)($c['at'] ?? 0)) < 300 && is_array($c['w'] ?? null) && !defined('GP_SELFTEST')) { return $c['w']; }
	$w = gp_iplists_warnings($lists, gp_iplists_verified_ips());
	if (is_dir(dirname($file)) && is_writable(dirname($file))) { @file_put_contents($file, json_encode(array('key' => $key, 'at' => time(), 'w' => $w)), LOCK_EX); }
	return $w;
}

// ---------------------------------------------------------------- health (dashboard)

// Enabled lists by type and mode for the dashboard's protection card: array(total, enabled, by 'type/mode' => n).
function gp_iplists_summary(array $lists) {
	$out = array('total' => count($lists), 'enabled' => 0, 'by' => array());
	foreach ($lists as $l) {
		if (empty($l['enabled'])) { continue; }
		$out['enabled']++;
		$k = $l['type'] . '/' . $l['mode'];
		$out['by'][$k] = isset($out['by'][$k]) ? $out['by'][$k] + 1 : 1;
	}
	return $out;
}


// Alert codes for the dashboard: file_missing / file_corrupt (an enabled list's compiled file is not
// usable), compile_failed (the last compile reported an error, or the last job failed), pending.
// Cheap: two header reads, a small JSON file. Empty when no list exists.
function gp_iplists_health($now = null, $jobs = null) {
	$now = $now === null ? time() : (int)$now;
	$st = gp_iplists_state();
	$out = array();
	if (!$st['lists']) { return $out; }
	$status = gp_iplists_status();
	$enabled = array_filter($st['lists'], function ($l) { return $l['enabled']; });
	if (!$enabled && $status === null) { return $out; }
	if ($status !== null) {
		foreach (gv_iplist_types() as $t) {
			if (!is_array($status['types'][$t] ?? null)) { continue; }          // nothing was built for this type
			$path = gv_iplist_file($t);
			if (!is_file($path)) { $out[] = array('file_missing', $t); continue; }
			$fh = @fopen($path, 'rb');
			$h = $fh ? gv_geo_header_parse((string)fread($fh, GV_GEO_HEADER)) : null;
			if ($fh) { fclose($fh); }
			if ($h === null || $h['kind'] !== GV_GEO_IPLIST) { $out[] = array('file_corrupt', $t); }
		}
		// Entries the compile dropped for a cap: a warning; an allow list that lost an entry wider than /8
		// (a would-be hole in the whole guard) is critical.
		$dn = 0; $dids = array(); $huge = array();
		foreach ((array)($status['lists'] ?? array()) as $id => $c) {
			if (!is_array($c)) { continue; }
			if ((int)($c['dropped_n'] ?? 0) > 0) { $dn += (int)$c['dropped_n']; $dids[] = (string)$id; }
			if ((int)($c['dropped_huge'] ?? 0) > 0) { $huge[] = (string)$id; }
		}
		if ($huge) { $out[] = array('allow_huge', implode(', ', $huge)); }
		if ($dn > 0) { $out[] = array('dropped', $dn . ' (' . implode(', ', $dids) . ')'); }
		if (empty($status['ok'])) { $out[] = array('compile_failed', implode('; ', array_slice((array)($status['errors'] ?? array()), 0, 2))); }
	}
	if ($jobs === null) { $jobs = $enabled ? gp_job_list(30) : array(); }
	foreach ($jobs as $j) {
		if (($j['type'] ?? '') !== 'iplist_compile') { continue; }
		if (($j['status'] ?? '') === 'failed' && (float)($j['requested_at'] ?? 0) >= (float)($status['time'] ?? 0)) { $out[] = array('compile_failed', 'job ' . (string)($j['id'] ?? '')); }
		break;                                      // only the newest compile job counts
	}
	if (gp_iplists_pending($st, $status) && $now - (int)@filemtime($st['path']) > 600) { $out[] = array('pending', ''); }
	return $out;
}
