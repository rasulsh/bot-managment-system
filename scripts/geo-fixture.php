<?php
// Test tooling: builds compiled GeoIP range files (the format in guard/geo.php)
// for the selftests, the benchmark and the web tests. Never loaded by the guard
// or the panel. The real compiler is analyzer/geo.py; the Python selftest checks
// that PHP reads what Python writes.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

// $v4: list of array(start_int, end_int, value), $v6: list of array(start_bin16, end_bin16, value).
// Both must already be sorted and non-overlapping. value: 2-letter string (kind 1) or int (kind 2).
function gf_pack($kind, array $v4, array $v6, $built = 1700000000, $source = 'fixture.dat') {
	$vs = $kind === 1 ? 2 : ($kind === 2 ? 4 : 0);
	$out = 'GVRG' . pack('nCCNNNN', 1, $kind, $vs, $built, count($v4), count($v6), 0)
		. str_repeat("\0", 32) . str_pad(substr($source, 0, 72), 72, "\0");
	$val = function ($v) use ($kind) { return $kind === 1 ? $v : ($kind === 2 ? pack('N', $v) : ''); };
	foreach ($v4 as $r) { $out .= pack('NN', $r[0], $r[1]) . $val($r[2]); }
	foreach ($v6 as $r) { $out .= $r[0] . $r[1] . $val($r[2]); }
	return $out;
}

// "a.b.c.d/n" -> array(start, end)
function gf_cidr4($cidr) {
	list($ip, $n) = explode('/', $cidr);
	$start = ip2long($ip) & 0xFFFFFFFF;
	$host = 32 - (int)$n;
	$start = ($start >> $host) << $host;
	return array($start, $start + (1 << $host) - 1);
}

// "2001:db8::/32" -> array(start_bin, end_bin)
function gf_cidr6($cidr) {
	list($ip, $n) = explode('/', $cidr);
	$bin = inet_pton($ip);
	$n = (int)$n;
	$start = ''; $end = '';
	for ($i = 0; $i < 16; $i++) {
		$bits = max(0, min(8, $n - $i * 8));
		$mask = $bits === 0 ? 0 : (0xFF << (8 - $bits)) & 0xFF;
		$b = ord($bin[$i]);
		$start .= chr($b & $mask);
		$end .= chr(($b & $mask) | (~$mask & 0xFF));
	}
	return array($start, $end);
}

// A realistic-size random table for benchmarks: $n4 IPv4 ranges and $n6 IPv6 ranges
// covering the space with gaps, country codes drawn from a fixed list.
function gf_random($kind, $n4, $n6, $seed = 7) {
	mt_srand($seed);
	$ccs = array('US', 'DE', 'FR', 'GB', 'IR', 'CN', 'RU', 'BR', 'IN', 'JP', 'NL', 'TR', 'AE', 'CA', 'AU');
	$val = function () use ($kind, $ccs) { return $kind === 1 ? $ccs[mt_rand(0, count($ccs) - 1)] : mt_rand(1, 400000); };
	$v4 = array(); $pos = 16777216; $step = (int)((4294967296 - 33554432) / max(1, $n4));
	for ($i = 0; $i < $n4; $i++) {
		$len = mt_rand(1, max(1, $step - 2));
		$v4[] = array($pos, $pos + $len - 1, $val());
		$pos += $step;
	}
	$v6 = array();
	for ($i = 0; $i < $n6; $i++) {
		$base = pack('N', 0x20000000 + $i * 3) . str_repeat("\0", 12);
		$end = substr($base, 0, 4) . str_repeat("\xff", 12);
		$v6[] = array($base, $end, $val());
	}
	return array($v4, $v6);
}
