<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }

// GeoIP lookup: country and ASN from compiled range files.
//
// The files in geo/ are written OFFLINE by the analyzer (analyzer/geo.py, job
// geo_compile). The request path only reads them: a binary search with
// fopen/fseek/fread, so the OS page cache does the work and nothing is loaded
// into memory. No .mmdb parsing, no extension, no network, no Redis.
//
// One format for every compiled range file (also used by the IP lists):
//
//   header, 128 bytes, big endian
//     0   4  magic "GVRG"
//     4   2  format version (1)
//     6   1  kind: 1 country, 2 asn, 3 ip list
//     7   1  value size in bytes (country 2, asn 4, ip list 2)
//     8   4  build time (unix)
//     12  4  IPv4 range count
//     16  4  IPv6 range count
//     20  4  reserved
//     24  32 sha256 of the source file(s), raw
//     56  72 source file name, NUL padded
//   IPv4 section: count records of  start 4 | end 4 | value      (sorted, non-overlapping)
//   IPv6 section: count records of  start 16 | end 16 | value
//
// Country value: two upper-case letters. ASN value: uint32. IP list value: uint16,
// bit 15 = the list is in monitor mode, bits 0-14 = the list index (see iplist.php). Anything wrong with
// the file (missing, short, wrong magic or version, truncated) means "unknown":
// no match, plus one rate-limited line in guard-errors.log. Never an exception.
//
// An UNKNOWN country or ASN matches neither an include nor an exclude condition
// (see gv_rule_geo_eval in rules.php): "block everything except IR" must not
// block a visitor whose country could not be determined.

define('GV_GEO_MAGIC', 'GVRG');
define('GV_GEO_VERSION', 1);
define('GV_GEO_HEADER', 128);
define('GV_GEO_COUNTRY', 1);
define('GV_GEO_ASN', 2);
define('GV_GEO_IPLIST', 3);

function gv_geo_dir() {
	// GV_GEO_DIR lets the test harness swap the directory, like GV_CONFIG.
	$env = getenv('GV_GEO_DIR');
	if (is_string($env) && $env !== '') { return rtrim($env, '/\\'); }
	return dirname(__DIR__) . '/geo';
}

function gv_geo_file($kind) {
	return gv_geo_dir() . '/' . ($kind === GV_GEO_ASN ? 'asn.bin' : 'country.bin');
}

// The header fields of a compiled file, or null when the 128 bytes are not one.
function gv_geo_header_parse($raw) {
	if (!is_string($raw) || strlen($raw) < GV_GEO_HEADER || strncmp($raw, GV_GEO_MAGIC, 4) !== 0) { return null; }
	$h = unpack('nver/Ckind/Cvsize/Nbuilt/Nv4/Nv6', substr($raw, 4, 16));
	if (!$h || $h['ver'] !== GV_GEO_VERSION) { return null; }
	$h['sha'] = bin2hex(substr($raw, 24, 32));
	$h['source'] = rtrim(substr($raw, 56, 72), "\0");
	return $h;
}

// Per-request state: open files, memoised lookups, which lookups ran. One place,
// so a test (or the benchmark, to model a fresh request) can reset it.
function &gv_geo_state($reset = false) {
	static $s = null;
	if ($s === null || $reset) {
		if ($s !== null) { foreach ($s['open'] as $g) { if ($g) { @fclose($g['fh']); } } }
		$s = array('open' => array(), 'cc' => array(), 'asn' => array(), 'ran' => array('cc' => false, 'asn' => false));
	}
	return $s;
}

// Open a compiled file once per request. Returns array(handle, header, offsets)
// or null; the failure is remembered, so a broken file costs one attempt.
// $kind is GV_GEO_COUNTRY, GV_GEO_ASN or GV_GEO_IPLIST (with $path).
function gv_geo_open($kind, $path = null, $quiet = false) {
	$s = &gv_geo_state();
	if ($path === null) { $path = gv_geo_file($kind); }
	if (array_key_exists($path, $s['open'])) { return $s['open'][$path]; }
	$s['open'][$path] = null;
	try {
		$fh = @fopen($path, 'rb');                // one failed open() is the whole cost of a missing file
		if (!$fh) {
			if (!$quiet) { gv_errlog('geo_missing', 'geo file missing or unreadable: ' . basename($path)); }
			return null;
		}
		stream_set_read_buffer($fh, 0);       // every read is one exact pread: no 8 KiB chunk per probe
		$h = gv_geo_header_parse(fread($fh, GV_GEO_HEADER));
		$st = fstat($fh);
		$vs = $h ? (int)$h['vsize'] : 0;
		$o6 = $h ? GV_GEO_HEADER + $h['v4'] * (8 + $vs) : 0;
		if (!$h || $h['kind'] !== $kind || !$st || $st['size'] < $o6 + $h['v6'] * (32 + $vs)
			|| ($kind === GV_GEO_COUNTRY && $vs !== 2) || ($kind === GV_GEO_ASN && $vs !== 4) || ($kind === GV_GEO_IPLIST && $vs !== 2)) {
			fclose($fh);
			gv_errlog('geo_corrupt', 'geo file is not a valid compiled range file: ' . basename($path));
			return null;
		}
		return $s['open'][$path] = array('fh' => $fh, 'h' => $h, 'o4' => GV_GEO_HEADER, 'o6' => $o6);
	} catch (\Throwable $e) {
		return null;
	}
}

// The 4 or 16 byte network-order key of an address (an IPv4-mapped IPv6 address
// is the IPv4 address it carries), or '' for anything that is not an address.
function gv_geo_key($ip) {
	$bin = @inet_pton((string)$ip);
	if ($bin === false) { return ''; }
	if (strlen($bin) === 16 && strncmp($bin, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) === 0) { $bin = substr($bin, 12); }
	return $bin;
}

// Binary search one section. Compares with strcmp(): a byte-wise comparison.
// (<=> would compare two digit-only binary strings as numbers.)
//
// Once 128 or fewer records are left they are read in ONE fread and searched in
// memory: a 100k table then needs about 10 seek+read pairs instead of 17.
function gv_geo_search($fh, $off, $count, $klen, $vsize, $key) {
	$rec = 2 * $klen + $vsize;
	$lo = 0;
	$hi = $count - 1;
	while ($lo <= $hi) {
		if ($hi - $lo < 128) {
			$n = $hi - $lo + 1;
			$base = $lo;
			if (fseek($fh, $off + $lo * $rec) !== 0) { return null; }
			$d = fread($fh, $n * $rec);
			if ($d === false || strlen($d) !== $n * $rec) { gv_errlog('geo_corrupt', 'geo file read failed'); return null; }
			while ($lo <= $hi) {
				$mid = ($lo + $hi) >> 1;
				$at = ($mid - $base) * $rec;
				if (strcmp($key, substr($d, $at, $klen)) < 0) { $hi = $mid - 1; }
				elseif (strcmp($key, substr($d, $at + $klen, $klen)) > 0) { $lo = $mid + 1; }
				else { return substr($d, $at + 2 * $klen, $vsize); }
			}
			return null;
		}
		$mid = ($lo + $hi) >> 1;
		if (fseek($fh, $off + $mid * $rec) !== 0) { return null; }
		$d = fread($fh, $rec);
		if ($d === false || strlen($d) !== $rec) { gv_errlog('geo_corrupt', 'geo file read failed'); return null; }
		if (strcmp($key, substr($d, 0, $klen)) < 0) { $hi = $mid - 1; }
		elseif (strcmp($key, substr($d, $klen, $klen)) > 0) { $lo = $mid + 1; }
		else { return substr($d, 2 * $klen); }
	}
	return null;
}

// The raw value of the range holding $ip in an open file: a string (empty for
// a file with no value, i.e. an IP list), or null when no range holds it.
function gv_geo_find($g, $ip) {
	if (!$g) { return null; }
	try {
		$key = gv_geo_key($ip);
		if (strlen($key) === 4) { return gv_geo_search($g['fh'], $g['o4'], $g['h']['v4'], 4, $g['h']['vsize'], $key); }
		if (strlen($key) === 16) { return gv_geo_search($g['fh'], $g['o6'], $g['h']['v6'], 16, $g['h']['vsize'], $key); }
	} catch (\Throwable $e) {
		gv_errlog('geo_exception', get_class($e) . ': ' . $e->getMessage());
	}
	return null;
}

// Which lookups ran in this request: the log row carries cc / asn only for those.
function gv_geo_ran($which = null) {
	$s = &gv_geo_state();
	if ($which !== null) { $s['ran'][$which] = true; }
	return $s['ran'];
}

// Country code of an address: 'IR', or '' when unknown. Memoised for the request.
function gv_geo_country($ip, $quiet = false) {
	$s = &gv_geo_state();
	$ip = (string)$ip;
	if (isset($s['cc'][$ip])) { return $s['cc'][$ip]; }
	if (count($s['cc']) > 5000) { $s['cc'] = array(); }
	if ($ip === '') { return ''; }
	gv_geo_ran('cc');
	$v = gv_geo_find(gv_geo_open(GV_GEO_COUNTRY, null, $quiet), $ip);
	return $s['cc'][$ip] = (is_string($v) && preg_match('/^[A-Z]{2}$/', $v)) ? $v : '';
}

// AS number of an address, or 0 when unknown.
function gv_geo_asn($ip, $quiet = false) {
	$s = &gv_geo_state();
	$ip = (string)$ip;
	if (isset($s['asn'][$ip])) { return $s['asn'][$ip]; }
	if (count($s['asn']) > 5000) { $s['asn'] = array(); }
	if ($ip === '') { return 0; }
	gv_geo_ran('asn');
	$v = gv_geo_find(gv_geo_open(GV_GEO_ASN, null, $quiet), $ip);
	return $s['asn'][$ip] = (is_string($v) && strlen($v) === 4) ? (int)unpack('N', $v)[1] : 0;
}
