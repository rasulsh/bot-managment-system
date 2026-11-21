<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }

// IP allow / block lists: the lookup the request path uses.
//
// Lists are managed in the panel (panel/iplists.php): the operator's source text
// lives in lists/<id>.txt, the metadata in lists/lists.json, and ONE compiled
// range file per list type is built from every enabled list of that type:
//
//   lists/allow.bin   lists/block.bin      (the range format of geo.php, kind 3)
//
// The value of a range is a uint16: bit 15 = the list is in monitor mode,
// bits 0-14 = the list index. Where lists overlap the smaller value wins, so an
// ENFORCED list beats a monitor list on the same address.
//
// A file exists only while an enabled list of that type has entries: the
// compile step deletes it otherwise. So "no enabled list" costs one failed
// fopen() per type and nothing else. No Redis, no DNS, no file write. A missing,
// short, wrong-magic or truncated file is "no match" plus one rate-limited line in
// guard-errors.log (geo.php's reader). The panel alerts when a file is missing or
// corrupt while its list is enabled.

define('GV_IPL_MONITOR', 0x8000);

function gv_iplist_dir() {
	// GV_LISTS_DIR lets the test harness swap the directory, like GV_GEO_DIR.
	$env = getenv('GV_LISTS_DIR');
	if (is_string($env) && $env !== '') { return rtrim($env, '/\\'); }
	return dirname(__DIR__) . '/lists';
}

function gv_iplist_types() { return array('allow', 'block'); }

function gv_iplist_file($type) {
	return gv_iplist_dir() . '/' . ($type === 'block' ? 'block' : 'allow') . '.bin';
}

function gv_iplist_meta_path() { return gv_iplist_dir() . '/lists.json'; }

// The value of the first range holding $ip in one compiled list file, or null.
// Quiet about a missing file: that is the normal "no enabled list" state.
function gv_iplist_find($type, $ip) {
	$path = gv_iplist_file($type);
	$g = gv_geo_open(GV_GEO_IPLIST, $path, true);
	if ($g === null) { return null; }          // missing = no list; a corrupt file was logged by gv_geo_open
	$v = gv_geo_find($g, $ip);
	return (is_string($v) && strlen($v) === 2) ? (int)unpack('n', $v)[1] : null;
}

// Both lookups for one client address. Returns array('allow' => hit, 'block' => hit)
// where a hit is null or array('idx' => list index, 'monitor' => bool). Never throws.
function gv_iplist_check($ip) {
	$out = array('allow' => null, 'block' => null);
	try {
		$ip = (string)$ip;
		if ($ip === '') { return $out; }
		foreach (gv_iplist_types() as $type) {
			$v = gv_iplist_find($type, $ip);
			if ($v !== null) { $out[$type] = array('idx' => $v & 0x7FFF, 'monitor' => (($v & GV_IPL_MONITOR) !== 0)); }
		}
	} catch (\Throwable $e) {
		gv_errlog('iplist_exception', get_class($e) . ': ' . $e->getMessage());
	}
	return $out;
}

// The id (log name) of a list index, read from lists.json. Called only when a
// hit has to be logged, never on a request that matched nothing.
function gv_iplist_id($idx) {
	try {
		$raw = @file_get_contents(gv_iplist_meta_path(), false, null, 0, 1048576);
		$data = is_string($raw) ? json_decode($raw, true) : null;
		if (is_array($data) && isset($data['lists']) && is_array($data['lists'])) {
			foreach ($data['lists'] as $l) {
				if (is_array($l) && isset($l['idx'], $l['id']) && (int)$l['idx'] === (int)$idx && is_string($l['id'])
					&& preg_match('/^[a-z0-9][a-z0-9-]{0,23}$/', $l['id'])) { return $l['id']; }
			}
		}
	} catch (\Throwable $e) {
	}
	return 'list' . (int)$idx;
}

// The log reason of a hit: IPL_ALLOW:<id> / IPL_BLOCK:<id>, SH_ prefixed for a monitor list.
function gv_iplist_reason($type, array $hit) {
	return ($hit['monitor'] ? 'SH_' : '') . 'IPL_' . ($type === 'block' ? 'BLOCK' : 'ALLOW') . ':' . gv_iplist_id($hit['idx']);
}
