<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

require_once __DIR__ . '/data.php';

// GeoIP page: the active compiled databases, uploading sources, compiling,
// rolling back, and the lookup tester.
//
// Sources (geo/*.mmdb, geo/geoip.dat) are compiled OFFLINE by the analyzer
// (analyzer/geo.py, job geo_compile) into geo/country.bin and geo/asn.bin, the
// files guard/geo.php searches. Nothing here parses a database: this page reads
// the 128-byte header of a compiled file and geo/geo-status.json, which the
// compile step writes.

define('GP_GEO_STALE_DAYS', 45);
define('GP_GEO_MAX_NAME', 64);

// The bytes in a php.ini size ("2M", "512K", "1G", "0" or ""). 0 = no limit.
function gp_ini_bytes($v) {
	$v = trim((string)$v);
	if ($v === '' || $v === '-1') { return 0; }
	$n = (float)$v;
	$u = strtolower(substr($v, -1));
	if ($u === 'g') { $n *= 1073741824; } elseif ($u === 'm') { $n *= 1048576; } elseif ($u === 'k') { $n *= 1024; }
	return (int)$n;
}

// The largest file the panel can receive: the smaller of the two PHP limits.
function gp_geo_upload_limit() {
	$a = gp_ini_bytes(ini_get('upload_max_filesize'));
	$b = gp_ini_bytes(ini_get('post_max_size'));
	if ($a === 0) { return $b; }
	if ($b === 0) { return $a; }
	return min($a, $b);
}

// One compiled file as the panel shows it, or null when it is missing.
function gp_geo_file_info($kind, $now) {
	$path = gv_geo_file($kind);
	if (!is_file($path)) { return null; }
	$fh = @fopen($path, 'rb');
	$h = $fh ? gv_geo_header_parse(fread($fh, GV_GEO_HEADER)) : null;
	if ($fh) { fclose($fh); }
	$out = array('path' => $path, 'valid' => ($h !== null && $h['kind'] === $kind), 'size' => (int)@filesize($path),
		'prev' => is_file($path . '.prev'), 'built' => 0, 'age_days' => null, 'v4' => 0, 'v6' => 0, 'source' => '', 'sha' => '');
	if ($out['valid']) {
		$out['built'] = (int)$h['built'];
		$out['age_days'] = (int)floor(max(0, $now - $h['built']) / 86400);
		$out['v4'] = (int)$h['v4'];
		$out['v6'] = (int)$h['v6'];
		$out['source'] = $h['source'];
		$out['sha'] = $h['sha'];
	}
	return $out;
}

// Everything the GeoIP page and the dashboard warning need.
function gp_geo_status($now = null) {
	$now = $now === null ? time() : $now;
	$dir = gv_geo_dir();
	$out = array('dir' => $dir, 'dir_ok' => is_dir($dir), 'dir_writable' => is_dir($dir) && is_writable($dir),
		'country' => gp_geo_file_info(GV_GEO_COUNTRY, $now), 'asn' => gp_geo_file_info(GV_GEO_ASN, $now),
		'compile' => null, 'sources' => array(), 'ignored_tags' => array(), 'countries' => array(), 'errors' => array(),
		'stale' => false, 'limit' => gp_geo_upload_limit());
	$raw = @file_get_contents($dir . '/geo-status.json');
	$st = is_string($raw) ? json_decode($raw, true) : null;
	if (is_array($st)) {
		$out['compile'] = array('time' => (int)($st['time'] ?? 0), 'ok' => !empty($st['ok']));
		$out['sources'] = (isset($st['sources']) && is_array($st['sources'])) ? $st['sources'] : array();
		$out['ignored_tags'] = (isset($st['ignored_tags']) && is_array($st['ignored_tags'])) ? $st['ignored_tags'] : array();
		$out['countries'] = (isset($st['countries']) && is_array($st['countries'])) ? $st['countries'] : array();
		$out['errors'] = (isset($st['errors']) && is_array($st['errors'])) ? $st['errors'] : array();
	}
	// Sources on disk that the last compile has not seen yet.
	$known = array();
	foreach ($out['sources'] as $s) { if (isset($s['name'])) { $known[$s['name']] = true; } }
	foreach ((array)@scandir($dir) as $n) {
		if (!is_string($n) || isset($known[$n]) || !preg_match('/\.(mmdb|dat)$/i', $n)) { continue; }
		$out['sources'][] = array('name' => $n, 'size' => (int)@filesize($dir . '/' . $n), 'mtime' => (int)@filemtime($dir . '/' . $n),
			'provides' => array(), 'used' => array(), 'new' => true);
	}
	$ages = array();
	foreach (array('country', 'asn') as $k) { if ($out[$k] && $out[$k]['valid']) { $ages[] = $out[$k]['age_days']; } }
	$out['stale'] = ($ages && max($ages) > GP_GEO_STALE_DAYS);
	return $out;
}

// Whether any ENABLED rule has a country or ASN condition (it needs the databases).
function gp_geo_rules_need($rules, $now = null) {
	$now = $now === null ? time() : $now;
	$n = 0;
	foreach ((array)$rules as $r) {
		if (!gv_rule_live($r, $now)) { continue; }
		if (!empty($r['country']) || !empty($r['asn'])) { $n++; }
	}
	return $n;
}

// Dashboard / GeoIP page warnings: list of codes (lang keys geo_w_<code>).
function gp_geo_warnings(array $status, $geo_rules, array $cfg) {
	$w = array();
	if ($status['stale']) { $w[] = 'stale'; }
	if ($geo_rules > 0 && !($status['country'] && $status['country']['valid']) && !($status['asn'] && $status['asn']['valid'])) { $w[] = 'missing'; }
	foreach (array('country', 'asn') as $k) {
		if ($status[$k] && !$status[$k]['valid']) { $w[] = 'corrupt'; break; }
	}
	if ($geo_rules > 0 && !$status['country'] && $status['asn']) { $w[] = 'no_country'; }
	if (!empty($cfg['geo']['log']) && !$status['country']) { $w[] = 'log_no_db'; }
	return array_values(array_unique($w));
}

// ---------------------------------------------------------------- actions

function gp_geo_audit($event, $actor, $ip, $key, $old, $new) {
	gp_audit_append(array('event' => $event, 'actor' => (string)$actor, 'ip' => (string)$ip, 'key' => $key, 'old' => $old, 'new' => $new));
}

// A source file name: letters, digits, dot, dash, underscore, ending in .mmdb or .dat.
function gp_geo_clean_name($name) {
	$name = basename(str_replace('\\', '/', (string)$name));
	$name = preg_replace('/[^A-Za-z0-9._-]/', '_', $name);
	$name = ltrim($name, '.');
	if ($name === '' || strlen($name) > GP_GEO_MAX_NAME || !preg_match('/\.(mmdb|dat)$/i', $name)) { return ''; }
	if (preg_match('/^(country|asn)\.bin/i', $name)) { return ''; }
	return $name;
}

// An .mmdb carries a metadata marker near its end; a .dat cannot be sniffed (the
// compile step reports a file that is not a geoip.dat).
function gp_geo_looks_ok($path, $name) {
	if (!preg_match('/\.mmdb$/i', $name)) { return filesize($path) > 0; }
	$size = (int)filesize($path);
	$fh = @fopen($path, 'rb');
	if (!$fh) { return false; }
	fseek($fh, max(0, $size - 131072));
	$tail = (string)fread($fh, 131072);
	fclose($fh);
	return strpos($tail, "\xAB\xCD\xEFMaxMind.com") !== false;
}

// Handle the uploaded source. $file is one entry of $_FILES. Returns array(ok, lang key, detail).
function gp_geo_upload(array $file, $actor, $ip) {
	$err = isset($file['error']) ? (int)$file['error'] : UPLOAD_ERR_NO_FILE;
	if ($err === UPLOAD_ERR_INI_SIZE || $err === UPLOAD_ERR_FORM_SIZE) { return array(false, 'geo_up_toobig', ''); }
	if ($err === UPLOAD_ERR_NO_FILE) { return array(false, 'geo_up_nofile', ''); }
	if ($err !== UPLOAD_ERR_OK) { return array(false, 'geo_up_failed', (string)$err); }
	$name = gp_geo_clean_name(isset($file['name']) ? $file['name'] : '');
	if ($name === '') { return array(false, 'geo_up_badname', ''); }
	$tmp = isset($file['tmp_name']) ? (string)$file['tmp_name'] : '';
	if (!is_uploaded_file($tmp) && !(defined('GP_TEST_UPLOADS') && is_file($tmp))) { return array(false, 'geo_up_failed', 'not an upload'); }
	if (!gp_geo_looks_ok($tmp, $name)) { return array(false, 'geo_up_badfile', ''); }
	$dir = gv_geo_dir();
	if (!is_dir($dir) || !is_writable($dir)) { return array(false, 'geo_up_nowrite', $dir); }
	$dest = $dir . '/' . $name;
	$partial = $dest . '.part' . getmypid();
	$ok = defined('GP_TEST_UPLOADS') ? @copy($tmp, $partial) : @move_uploaded_file($tmp, $partial);
	if (!$ok || !@rename($partial, $dest)) { @unlink($partial); return array(false, 'geo_up_nowrite', $dir); }
	@chmod($dest, 0640);
	gp_geo_audit('geo_upload', $actor, $ip, $name, null, array('size' => (int)@filesize($dest)));
	return array(true, 'geo_up_done', $name);
}

// Delete one uploaded source file (never a compiled file). Returns array(ok, lang key, detail).
function gp_geo_delete_source($name, $actor, $ip) {
	$clean = gp_geo_clean_name($name);
	$path = gv_geo_dir() . '/' . $clean;
	if ($clean === '' || $clean !== (string)$name || !is_file($path)) { return array(false, 'geo_del_none', ''); }
	$size = (int)@filesize($path);
	if (!@unlink($path)) { return array(false, 'geo_up_nowrite', ''); }
	gp_geo_audit('geo_delete', $actor, $ip, $clean, array('size' => $size), null);
	return array(true, 'geo_del_done', $clean);
}

// Queue the compile job. Returns array(ok, lang key, detail).
function gp_geo_compile($actor) {
	$r = gp_job_enqueue('geo_compile', array(), $actor);
	return $r['ok'] ? array(true, 'geo_compile_queued', $r['id']) : array(false, 'geo_compile_failed', (string)$r['error']);
}

// Put the previous compiled file back: copy .prev next to the live file, then rename over it.
function gp_geo_rollback($kind_name, $actor, $ip) {
	$kind = $kind_name === 'asn' ? GV_GEO_ASN : GV_GEO_COUNTRY;
	$path = gv_geo_file($kind);
	$prev = $path . '.prev';
	if (!is_file($prev)) { return array(false, 'geo_rb_none', ''); }
	$raw = @file_get_contents($prev, false, null, 0, GV_GEO_HEADER);
	$h = gv_geo_header_parse((string)$raw);
	if ($h === null || $h['kind'] !== $kind) { return array(false, 'geo_rb_bad', ''); }
	$tmp = $path . '.rb' . getmypid();
	if (!@copy($prev, $tmp) || !@rename($tmp, $path)) { @unlink($tmp); return array(false, 'geo_up_nowrite', ''); }
	gp_geo_audit('geo_rollback', $actor, $ip, basename($path), null, array('built' => (int)$h['built'], 'source' => $h['source']));
	return array(true, 'geo_rb_done', basename($path));
}

// ---------------------------------------------------------------- tester

// An address, validated. Returns the canonical form or ''.
function gp_geo_clean_ip($ip) {
	$ip = trim((string)$ip);
	if ($ip === '' || strlen($ip) > 45 || filter_var($ip, FILTER_VALIDATE_IP) === false) { return ''; }
	return gv_ip_canon($ip);
}

// The lookup tester: country, ASN and the rules that would match this client.
// Pure given the databases on disk. $verified: treat the client as a verified crawler.
function gp_geo_test($ip, $ua, $path, $verified, array $rules, array $cfg, $now) {
	$ip = gp_geo_clean_ip($ip);
	if ($ip === '') { return null; }
	$cc = gv_geo_country($ip, true);
	$asn = gv_geo_asn($ip, true);
	$res = gp_rules_test($rules, $ua, $path, $verified, $cfg, $now, $ip);
	$res['ip'] = $ip;
	$res['cc'] = $cc;
	$res['asn'] = $asn;
	return $res;
}

// The dashboard's GeoIP warnings (codes). Cheap: two 128-byte header reads and a
// scan of the rules file. Empty when GeoIP is not in use at all.
function gp_geo_dashboard_warnings() {
	$st = gp_geo_status();
	$rs = gp_rules_state();
	$n = gp_geo_rules_need($rs['rules']);
	if ($n === 0 && !$st['country'] && !$st['asn']) { return array(); }
	return gp_geo_warnings($st, $n, gv_cfg_load());
}
