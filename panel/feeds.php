<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

require_once __DIR__ . '/iplists.php';

// IP range feeds: a provider's list of IPv4 ranges, fetched from an HTTPS URL, kept in step with ONE destination.
//
//   destination "allow"  the feed owns one IP list (feed-<id>, type allow); an update replaces that list's entries
//   destination "cdn"    the ranges join the trusted CDN / proxy ranges: written to the overlay key cdn_ranges_feed, which the guard
//                        merges with the manually typed cdn_ranges (a feed never touches those)
//
//   lists/feeds.json        the feeds (settings + the state of the last run), written only here (temp file + rename, under a lock)
//   lists/feed-<id>.txt     a cdn feed's applied entries (an allow feed's entries are its list's source file)
//   lists/.feedhold-<id>.txt  a fetch that was HELD (it would remove more than half of the entries) until an admin confirms it
//
// Semantics (README Part 2, "IP feeds"): IPv4 only (IPv6 is dropped and counted); a failure keeps the last good entries; a fetch that
// removes more than 50 % is held; the compile caps of the IP lists apply (an allow entry wider than /16 is "held by the cap" until an
// admin accepts it for this feed); 0.0.0.0/0 is always dropped. Nothing here touches a manual list.

define('GP_FEED_MAX', 20);
define('GP_FEED_MAX_BYTES', 5242880);       // the largest body that is read
define('GP_FEED_MAX_REDIRECTS', 3);
define('GP_FEED_CONNECT_TIMEOUT', 8);
define('GP_FEED_TOTAL_TIMEOUT', 25);
define('GP_FEED_SHRINK', 0.5);              // a fetch that removes MORE than this share of the current entries is held
define('GP_FEED_CDN_MAX', 100);             // the cidrs4 limit of cdn_ranges_feed (guard/guard.php)
define('GP_FEED_FAIL_ALERT', 2);            // consecutive failures before the dashboard says so
define('GP_FEED_FORMATS', 'auto,text,google,json');

// ---------------------------------------------------------------- paths and the presets

function gp_feeds_path() { return gp_ipl_dir() . '/feeds.json'; }
function gp_feed_src_path($id) { return gp_ipl_dir() . '/feed-' . $id . '.txt'; }
function gp_feed_hold_path($id) { return gp_ipl_dir() . '/.feedhold-' . $id . '.txt'; }
function gp_feed_list_id($id) { return 'feed-' . $id; }

// The four example feeds with the destination that is right for each. CDN ranges belong in cdn_ranges, never in an allow list.
function gp_feed_presets() {
	return array(
		'google' => array('name' => 'Google common crawlers', 'url' => 'https://developers.google.com/static/search/apis/ipranges/common-crawlers.json', 'format' => 'google', 'dest' => 'allow'),
		'uptimerobot' => array('name' => 'UptimeRobot', 'url' => 'https://uptimerobot.com/inc/files/ips/IPv4.txt', 'format' => 'text', 'dest' => 'allow'),
		'arvancloud' => array('name' => 'ArvanCloud', 'url' => 'https://www.arvancloud.ir/en/ips.txt', 'format' => 'text', 'dest' => 'cdn'),
		'cloudflare' => array('name' => 'Cloudflare', 'url' => 'https://www.cloudflare.com/ips-v4', 'format' => 'text', 'dest' => 'cdn'),
	);
}

// Whether a feed's URL host looks like a CDN the site may sit behind (a warning on an ALLOW destination; never a refusal).
function gp_feed_cdn_host($url) {
	$h = strtolower((string)parse_url((string)$url, PHP_URL_HOST));
	foreach (array('cloudflare.com', 'arvancloud.ir', 'arvancloud.com', 'fastly.com', 'akamai', 'cloudfront', 'stackpath', 'bunny.net', 'imperva', 'incapsula', 'sucuri') as $n) {
		if ($h !== '' && strpos($h, $n) !== false) { return true; }
	}
	return false;
}

// ---------------------------------------------------------------- records (feeds.json)

function gp_feed_blank() {
	return array('id' => '', 'name' => '', 'url' => '', 'format' => 'auto', 'dest' => 'allow', 'mode' => 'monitor', 'enabled' => true, 'schedule' => 'daily',
		'note' => '', 'force' => false, 'created_by' => '', 'created_at' => 0, 'st' => gp_feed_blank_state());
}

function gp_feed_blank_state() {
	return array('last_run' => 0, 'last_ok' => 0, 'fail_streak' => 0, 'error' => '', 'http' => 0, 'bytes' => 0, 'ms' => 0, 'format' => '', 'found' => 0, 'v6' => 0,
		'invalid' => 0, 'dropped_all' => 0, 'added' => 0, 'removed' => 0, 'unchanged' => 0, 'applied' => 0, 'held' => '', 'held_n' => 0, 'held_removed' => 0, 'cap_held' => 0, 'cap_samples' => array(), 'redirects' => 0);
}

// The URL of a feed: https only, a host, no credentials, a sane length. Returns '' when fine, else an error code.
function gp_feed_url_check($url) {
	if (!is_string($url) || $url === '' || strlen($url) > 500 || preg_match('/[\s\x00-\x1F\x7F]/', $url)) { return 'url'; }
	$p = parse_url($url);
	if (!is_array($p) || !isset($p['scheme'], $p['host'])) { return 'url'; }
	if (strtolower($p['scheme']) !== 'https') { return 'scheme'; }
	if (isset($p['user']) || isset($p['pass'])) { return 'url'; }
	if (isset($p['port']) && ((int)$p['port'] < 1 || (int)$p['port'] > 65535)) { return 'url'; }
	return '';
}

// Validate one record. Returns array(true, clean) or array(false, field => code).
function gp_feed_validate($f) {
	$err = array();
	$id = isset($f['id']) && is_string($f['id']) ? $f['id'] : '';
	if (!preg_match('/^[a-z0-9][a-z0-9-]{0,18}$/', $id)) { return array(false, array('name' => 'bad_id')); }
	$name = isset($f['name']) && is_string($f['name']) ? trim($f['name']) : '';
	if ($name === '' || gp_ipl_len($name) > 60 || !preg_match('//u', $name) || preg_match('/[\x00-\x1F\x7F]/', $name)) { $err['name'] = 'bad_name'; }
	$url = isset($f['url']) && is_string($f['url']) ? trim($f['url']) : '';
	if (($c = gp_feed_url_check($url)) !== '') { $err['url'] = $c; }
	$format = isset($f['format']) && is_string($f['format']) ? $f['format'] : 'auto';
	if (!in_array($format, explode(',', GP_FEED_FORMATS), true)) { $err['format'] = 'bad_format'; }
	$dest = isset($f['dest']) && is_string($f['dest']) ? $f['dest'] : '';
	if (!in_array($dest, array('allow', 'cdn'), true)) { $err['dest'] = 'bad_dest'; }
	$mode = isset($f['mode']) && is_string($f['mode']) ? $f['mode'] : 'monitor';
	if (!in_array($mode, array('enforce', 'monitor'), true)) { $err['mode'] = 'bad_mode'; }
	$sched = isset($f['schedule']) && is_string($f['schedule']) ? $f['schedule'] : 'manual';
	if (!in_array($sched, array('manual', 'daily', 'weekly'), true)) { $err['schedule'] = 'bad_schedule'; }
	$note = isset($f['note']) && is_string($f['note']) ? trim($f['note']) : '';
	if (gp_ipl_len($note) > 200 || !preg_match('//u', $note) || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $note)) { $err['note'] = 'bad_note'; }
	if ($err) { return array(false, $err); }
	$st = gp_feed_blank_state();
	if (isset($f['st']) && is_array($f['st'])) {
		foreach ($st as $k => $def) {
			if (!array_key_exists($k, $f['st'])) { continue; }
			$v = $f['st'][$k];
			if (is_int($def)) { $st[$k] = max(0, (int)$v); }
			elseif (is_string($def)) { $st[$k] = substr((string)(is_scalar($v) ? $v : ''), 0, 300); }
			elseif (is_array($def)) { $st[$k] = is_array($v) ? array_slice(array_values($v), 0, GP_IPL_SAMPLES) : array(); }
		}
	}
	return array(true, array('id' => $id, 'name' => $name, 'url' => $url, 'format' => $format, 'dest' => $dest, 'mode' => $mode, 'enabled' => !empty($f['enabled']),
		'schedule' => $sched, 'note' => $note, 'force' => !empty($f['force']),
		'created_by' => isset($f['created_by']) && is_string($f['created_by']) ? substr($f['created_by'], 0, 64) : '',
		'created_at' => isset($f['created_at']) ? (int)$f['created_at'] : 0, 'st' => $st));
}

// The feeds file as the panel sees it. state: missing | ok | invalid.
function gp_feeds_state() {
	$out = array('state' => 'missing', 'feeds' => array());
	$path = gp_feeds_path();
	if (!is_file($path)) { return $out; }
	$raw = @file_get_contents($path);
	if ($raw === false || trim($raw) === '') { $out['state'] = 'ok'; return $out; }
	$d = json_decode($raw, true);
	if (!is_array($d) || !isset($d['feeds']) || !is_array($d['feeds'])) { $out['state'] = 'invalid'; return $out; }
	$out['state'] = 'ok';
	foreach ($d['feeds'] as $f) {
		$v = gp_feed_validate($f);
		if ($v[0]) { $out['feeds'][] = $v[1]; } else { $out['state'] = 'invalid'; }
	}
	return $out;
}

function gp_feed_find(array $feeds, $id) {
	foreach ($feeds as $f) { if ($f['id'] === $id) { return $f; } }
	return null;
}

// Read-modify-write of feeds.json under one lock. $fn(feeds) returns the new feeds or a string error key.
function gp_feeds_update($fn) {
	if (!gp_ipl_ensure_dir()) { return array(false, 'write_failed'); }
	$lock = @fopen(gp_ipl_dir() . '/.feeds.lock', 'c');
	if ($lock) { @flock($lock, LOCK_EX); }
	try {
		$st = gp_feeds_state();
		if ($st['state'] === 'invalid') { return array(false, 'feed_file_invalid'); }
		$new = $fn($st['feeds']);
		if (is_string($new)) { return array(false, $new); }
		$json = json_encode(array('v' => 1, 'feeds' => array_values($new)), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
		if ($json === false) { return array(false, 'write_failed'); }
		$path = gp_feeds_path();
		$tmp = $path . '.tmp' . getmypid();
		if (@file_put_contents($tmp, $json, LOCK_EX) === false) { return array(false, 'write_failed'); }
		@chmod($tmp, 0640);
		if (!@rename($tmp, $path)) { @unlink($tmp); return array(false, 'write_failed'); }
		return array(true, '');
	} finally {
		if ($lock) { @flock($lock, LOCK_UN); @fclose($lock); }
	}
}

// The feed that owns a list id (an allow feed's list), or null. Lists a feed owns are not edited from the lists table.
function gp_feed_owner($list_id) {
	foreach (gp_feeds_state()['feeds'] as $f) {
		if ($f['dest'] === 'allow' && gp_feed_list_id($f['id']) === $list_id) { return $f; }
	}
	return null;
}

function gp_feed_audit($actor, $ip, $id, $old, $new) { gp_ipl_audit($actor, $ip, 'feed:' . $id, $old, $new); }

// ---------------------------------------------------------------- fetching (HTTPS, SSRF-guarded)

// Whether an address is one a feed may be fetched from: a public unicast address. Private, loopback, link-local, carrier-grade NAT,
// documentation, benchmarking, multicast and reserved space are refused, for IPv4 and IPv6 (and IPv4-mapped IPv6).
function gp_feed_ip_public($ip) {
	$bin = @inet_pton((string)$ip);
	if ($bin === false) { return false; }
	if (strlen($bin) === 16) {
		if (strncmp($bin, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) === 0) { return gp_feed_ip_public(inet_ntop(substr($bin, 12))); }
		$b0 = ord($bin[0]); $b1 = ord($bin[1]);
		if ($bin === str_repeat("\0", 16) || $bin === str_repeat("\0", 15) . "\x01") { return false; }      // :: and ::1
		if (($b0 & 0xFE) === 0xFC || $b0 === 0xFF || ($b0 === 0xFE && ($b1 & 0xC0) === 0x80)) { return false; }   // fc00::/7, ff00::/8, fe80::/10
		if ($b0 === 0x20 && $b1 === 0x01 && ord($bin[2]) === 0x0D && ord($bin[3]) === 0xB8) { return false; }       // 2001:db8::/32
		if ($b0 === 0x20 && $b1 === 0x02) { return false; }                                                         // 6to4
		return ($b0 & 0xE0) === 0x20;                                                                               // 2000::/3 global unicast only
	}
	$a = ord($bin[0]); $b = ord($bin[1]); $c = ord($bin[2]);
	if ($a === 0 || $a === 10 || $a === 127 || $a >= 224) { return false; }
	if ($a === 100 && ($b & 0xC0) === 64) { return false; }                      // 100.64.0.0/10
	if ($a === 169 && $b === 254) { return false; }
	if ($a === 172 && ($b & 0xF0) === 16) { return false; }
	if ($a === 192 && $b === 168) { return false; }
	if ($a === 192 && $b === 0 && ($c === 0 || $c === 2)) { return false; }     // 192.0.0.0/24, 192.0.2.0/24
	if ($a === 198 && ($b === 18 || $b === 19)) { return false; }               // 198.18.0.0/15
	if (($a === 198 && $b === 51 && $c === 100) || ($a === 203 && $b === 0 && $c === 113)) { return false; }
	return true;
}

// The addresses of a host. A hook ($GLOBALS['gp_feed_resolver']) lets the tests run without a network.
function gp_feed_resolve($host) {
	if (isset($GLOBALS['gp_feed_resolver']) && is_callable($GLOBALS['gp_feed_resolver'])) { return (array)call_user_func($GLOBALS['gp_feed_resolver'], $host); }
	if (filter_var($host, FILTER_VALIDATE_IP) !== false) { return array($host); }
	$out = array();
	$a = @gethostbynamel($host);
	if (is_array($a)) { $out = $a; }
	if (function_exists('dns_get_record')) {
		$aaaa = @dns_get_record($host, DNS_AAAA);
		if (is_array($aaaa)) { foreach ($aaaa as $r) { if (isset($r['ipv6'])) { $out[] = $r['ipv6']; } } }
	}
	return array_values(array_unique($out));
}

// One HTTPS GET to a pinned address (the address that passed the check is the one connected to: no second DNS lookup to rebind),
// HTTP/1.0 so the body is never chunked, no compression, the body read up to $max bytes. Returns array(status, location, body, error).
function gp_feed_transport($ip, $port, $host, $path, $max, $deadline) {
	if (isset($GLOBALS['gp_feed_transport']) && is_callable($GLOBALS['gp_feed_transport'])) { return call_user_func($GLOBALS['gp_feed_transport'], $ip, $port, $host, $path, $max, $deadline); }
	$ctx = stream_context_create(array('ssl' => array('peer_name' => $host, 'SNI_enabled' => true, 'SNI_server_name' => $host, 'verify_peer' => true, 'verify_peer_name' => true, 'allow_self_signed' => false)));
	$target = (strpos($ip, ':') !== false ? '[' . $ip . ']' : $ip) . ':' . (int)$port;
	$errno = 0; $errstr = '';
	$fp = @stream_socket_client('ssl://' . $target, $errno, $errstr, GP_FEED_CONNECT_TIMEOUT, STREAM_CLIENT_CONNECT, $ctx);
	if (!$fp) { return array(0, '', '', (stripos($errstr, 'certificate') !== false || stripos($errstr, 'SSL') !== false) ? 'tls' : 'connect'); }
	stream_set_timeout($fp, GP_FEED_CONNECT_TIMEOUT);
	$ver = defined('GP_VERSION_STRING') ? GP_VERSION_STRING : (function_exists('gp_upd_version') ? gp_upd_version() : '');
	$req = "GET " . $path . " HTTP/1.0\r\nHost: " . $host . ($port != 443 ? ':' . (int)$port : '') . "\r\nUser-Agent: BotGuard-IP-feed/" . ($ver !== '' ? $ver : '1') . " (+admin panel; IPv4 range fetch)\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";
	if (@fwrite($fp, $req) === false) { fclose($fp); return array(0, '', '', 'connect'); }
	$raw = '';
	$timed_out = false;
	while (!feof($fp)) {
		$chunk = @fread($fp, 65536);
		if ($chunk === false || $chunk === '') {
			$meta = stream_get_meta_data($fp);
			if (!empty($meta['timed_out'])) { $timed_out = true; }
			break;
		}
		$raw .= $chunk;
		if (strlen($raw) > $max + 16384) { fclose($fp); return array(0, '', '', 'too_big'); }
		if (microtime(true) > $deadline) { $timed_out = true; break; }
	}
	fclose($fp);
	$cut = strpos($raw, "\r\n\r\n");
	if ($cut === false) { return array(0, '', '', $timed_out ? 'timeout' : 'connect'); }
	$head = substr($raw, 0, $cut);
	$body = substr($raw, $cut + 4);
	if (!preg_match('#^HTTP/\d\.\d\s+(\d{3})#', $head, $m)) { return array(0, '', '', 'connect'); }
	$loc = preg_match('/^Location:\s*(\S+)/mi', $head, $lm) ? $lm[1] : '';
	if ($timed_out) { return array((int)$m[1], $loc, $body, 'timeout'); }
	if (strlen($body) > $max) { return array((int)$m[1], $loc, '', 'too_big'); }
	return array((int)$m[1], $loc, $body, '');
}

// Resolve a Location against the URL it came from (absolute, scheme-relative, absolute path or relative). '' if it cannot be.
function gp_feed_redirect_url($base, $loc) {
	if (preg_match('#^https?://#i', $loc)) { return $loc; }
	$p = parse_url($base);
	if (!is_array($p) || !isset($p['host'])) { return ''; }
	$origin = 'https://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
	if (strncmp($loc, '//', 2) === 0) { return 'https:' . $loc; }
	if (isset($loc[0]) && $loc[0] === '/') { return $origin . $loc; }
	$dir = isset($p['path']) ? preg_replace('#/[^/]*$#', '/', $p['path']) : '/';
	return $origin . $dir . $loc;
}

// Fetch a feed. HTTPS only, at most GP_FEED_MAX_REDIRECTS redirects (each one HTTPS and checked again), a body cap, timeouts, and
// every resolved address of every hop must be public. Returns array(ok, error code, detail, http, bytes, ms, body, redirects).
function gp_feed_fetch($url) {
	$t0 = microtime(true);
	$res = array('ok' => false, 'error' => '', 'detail' => '', 'http' => 0, 'bytes' => 0, 'ms' => 0, 'body' => '', 'redirects' => 0);
	$deadline = $t0 + GP_FEED_TOTAL_TIMEOUT;
	$cur = $url;
	for ($hop = 0; $hop <= GP_FEED_MAX_REDIRECTS; $hop++) {
		if (($c = gp_feed_url_check($cur)) !== '') { $res['error'] = $c; $res['detail'] = $hop > 0 ? 'redirect target' : ''; break; }
		$p = parse_url($cur);
		$host = strtolower($p['host']);
		$port = isset($p['port']) ? (int)$p['port'] : 443;
		$path = (isset($p['path']) && $p['path'] !== '' ? $p['path'] : '/') . (isset($p['query']) ? '?' . $p['query'] : '');
		$ips = gp_feed_resolve(trim($host, '[]'));
		if (!$ips) { $res['error'] = 'dns'; $res['detail'] = $host; break; }
		$bad = '';
		foreach ($ips as $ip) { if (!gp_feed_ip_public($ip)) { $bad = $ip; break; } }
		if ($bad !== '') { $res['error'] = 'ssrf'; $res['detail'] = $host . ' -> ' . $bad; break; }
		list($st, $loc, $body, $err) = gp_feed_transport($ips[0], $port, trim($host, '[]'), $path, GP_FEED_MAX_BYTES, $deadline);
		$res['http'] = (int)$st;
		if ($err !== '') { $res['error'] = $err; break; }
		if ($st >= 300 && $st < 400 && $loc !== '') {
			if ($hop >= GP_FEED_MAX_REDIRECTS) { $res['error'] = 'redirects'; break; }
			$next = gp_feed_redirect_url($cur, $loc);
			if ($next === '') { $res['error'] = 'url'; $res['detail'] = 'redirect target'; break; }
			$cur = $next;
			$res['redirects']++;
			continue;
		}
		if ($st !== 200) { $res['error'] = 'http'; $res['detail'] = (string)$st; break; }
		if (strlen($body) > GP_FEED_MAX_BYTES) { $res['error'] = 'too_big'; break; }
		$res['body'] = $body;
		$res['bytes'] = strlen($body);
		$res['ok'] = true;
		break;
	}
	$res['ms'] = (int)round((microtime(true) - $t0) * 1000);
	return $res;
}

// ---------------------------------------------------------------- parsing (IPv4 only)

// Every string in a decoded JSON document (depth and count bounded).
function gp_feed_json_strings($v, array &$out, $depth = 0) {
	if ($depth > 12 || count($out) > 400000) { return; }
	if (is_string($v)) { $out[] = $v; return; }
	if (is_array($v)) { foreach ($v as $x) { gp_feed_json_strings($x, $out, $depth + 1); } }
}

// A body -> array(ok, format used, entries (canonical IPv4 text, sorted, unique), v6 dropped, invalid, dropped_all (0.0.0.0/0), error).
// $format: auto | text | google | json. Auto: a document starting with { or [ is JSON (Google's prefixes[] when present, else every
// string that is an IPv4 CIDR), anything else is plain text, one address or CIDR per line, # comments and blank lines ignored.
function gp_feed_parse($body, $format = 'auto') {
	$r = array('ok' => false, 'format' => '', 'entries' => array(), 'v6' => 0, 'invalid' => 0, 'dropped_all' => 0, 'error' => '');
	$body = (string)$body;
	if (strncmp($body, "\xEF\xBB\xBF", 3) === 0) { $body = substr($body, 3); }
	$lead = ltrim($body);
	$tokens = null;
	$used = $format;
	if ($format === 'auto') { $used = ($lead !== '' && ($lead[0] === '{' || $lead[0] === '[')) ? 'json' : 'text'; }
	if ($used === 'google' || $used === 'json') {
		$doc = json_decode($body, true);
		if (!is_array($doc)) { $r['error'] = 'parse'; $r['format'] = $used; return $r; }
		$tokens = array();
		if ($used === 'google' && isset($doc['prefixes']) && is_array($doc['prefixes'])) {
			foreach ($doc['prefixes'] as $pf) {
				if (!is_array($pf)) { continue; }
				if (isset($pf['ipv4Prefix']) && is_string($pf['ipv4Prefix'])) { $tokens[] = $pf['ipv4Prefix']; }
				if (isset($pf['ipv6Prefix']) && is_string($pf['ipv6Prefix'])) { $tokens[] = $pf['ipv6Prefix']; }
			}
		} else {
			// Generic fallback: every string that is an address range (a bare address is not enough in a free-form document).
			$all = array();
			gp_feed_json_strings($doc, $all);
			foreach ($all as $s) { if (strlen($s) <= 64 && strpos($s, '/') !== false && preg_match('/^[0-9a-fA-F:.]+\/\d{1,3}$/', $s)) { $tokens[] = $s; } }
		}
	}
	$seen = array();
	$consider = function ($en) use (&$r, &$seen) {
		if ($en['v'] === 6) { $r['v6']++; return; }
		if ($en['p'] === 0) { $r['dropped_all']++; return; }
		$t = gp_ipl_entry_text($en);
		if (!isset($seen[$t])) { $seen[$t] = $en['s']; }
	};
	if ($tokens === null) {
		list($entries, $bad) = gp_ipl_parse_text($body);
		foreach ($entries as $en) { $consider($en); }
		$r['invalid'] = count($bad);
	} else {
		foreach ($tokens as $t) {
			$en = gp_ipl_parse_entry(trim($t));
			if ($en === null) { $r['invalid']++; } else { $consider($en); }
		}
	}
	asort($seen, SORT_STRING);
	$r['entries'] = array_keys($seen);
	$r['format'] = $used;
	$r['ok'] = true;
	return $r;
}

// ---------------------------------------------------------------- the sync

// A source file's lines (canonical entries), or array().
function gp_feed_read_lines($path) {
	$raw = @file_get_contents($path);
	if (!is_string($raw) || $raw === '') { return array(); }
	return array_values(array_filter(array_map('trim', explode("\n", $raw)), 'strlen'));
}

function gp_feed_write_text($path, array $lines) {
	if (!gp_ipl_ensure_dir()) { return false; }
	$tmp = $path . '.tmp' . getmypid();
	if (@file_put_contents($tmp, $lines ? implode("\n", $lines) . "\n" : '', LOCK_EX) === false || !@rename($tmp, $path)) { @unlink($tmp); return false; }
	@chmod($path, 0640);
	return true;
}

// The cdn feeds' ranges as one list (the value of cdn_ranges_feed), $replace: feed id => lines to use instead of its file.
function gp_feed_cdn_union(array $feeds, array $replace = array()) {
	$u = array();
	foreach ($feeds as $f) {
		if ($f['dest'] !== 'cdn' || !$f['enabled']) { continue; }
		$lines = isset($replace[$f['id']]) ? $replace[$f['id']] : gp_feed_read_lines(gp_feed_src_path($f['id']));
		foreach ($lines as $l) { $u[$l] = true; }
	}
	$out = array_keys($u);
	sort($out, SORT_STRING);
	return $out;
}

// Entries a cdn destination cannot hold: cidrs4 allows /8 to /32 (a wider range would let clients choose their own address).
function gp_feed_cdn_ok($text) { return preg_match('/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/', $text, $m) ? (int)$m[2] >= 8 : true; }

// Write the merged cdn ranges to the overlay (cdn_ranges_feed). Returns array(ok, error).
function gp_feed_cdn_save(array $union, $actor, $ip) {
	$r = gp_config_save(array('cdn_ranges_feed' => $union), $actor, $ip);
	if (!$r['ok']) { return array(false, 'write_failed'); }
	return array(true, '');
}

// Make an allow feed's list match its record (enabled, mode, force) and compile; creates the list when it does not exist.
function gp_feed_sync_list(array $f, $actor, $ip, $compile = true) {
	$lid = gp_feed_list_id($f['id']);
	if (!is_file(gp_ipl_source_path($lid)) && !gp_feed_write_text(gp_ipl_source_path($lid), array())) { return array(false, 'write_failed'); }     // the compile reads it: an empty source until the first update
	$r = gp_iplists_update(function ($lists, $next) use ($f, $lid, $actor) {
		$found = false;
		foreach ($lists as $i => $l) {
			if ($l['id'] !== $lid) { continue; }
			$found = true;
			$lists[$i]['enabled'] = $f['enabled'];
			$lists[$i]['mode'] = $f['mode'];
			$lists[$i]['force'] = $f['force'];
			$lists[$i]['name'] = 'Feed: ' . $f['name'];
			$lists[$i]['updated_at'] = time();
		}
		if (!$found) {
			if (count($lists) >= GP_IPL_MAX_LISTS) { return 'ipl_too_many'; }
			$lists[] = array('id' => $lid, 'idx' => $next, 'name' => 'Feed: ' . $f['name'], 'type' => 'allow', 'enabled' => $f['enabled'], 'mode' => $f['mode'],
				'force' => $f['force'], 'note' => 'Managed by the IP feed "' . $f['id'] . '": its entries are replaced on every update (Feeds tab).',
				'created_by' => (string)$actor, 'created_at' => time(), 'updated_at' => time());
			$next++;
		}
		return array($lists, $next);
	});
	if (!$r[0]) { return $r; }
	if ($compile) { $c = gp_iplists_compile_auto($actor); return array($c[0], $c[0] ? '' : $c[1]); }
	return array(true, '');
}

// Fetch one feed and apply it (or hold / fail). $o: accept_hold (apply the held fetch without fetching again), now.
// Returns array(ok, status applied|nochange|held|failed, error, detail, added, removed, unchanged, ...). Never throws.
function gp_feed_sync($id, $actor, $ip, array $o = array()) {
	$now = isset($o['now']) ? (int)$o['now'] : time();
	$res = array('ok' => false, 'status' => 'failed', 'error' => '', 'detail' => '', 'added' => 0, 'removed' => 0, 'unchanged' => 0, 'found' => 0);
	$fs = gp_feeds_state();
	if ($fs['state'] === 'invalid') { $res['error'] = 'feed_file_invalid'; return $res; }
	$f = gp_feed_find($fs['feeds'], (string)$id);
	if ($f === null) { $res['error'] = 'not_found'; return $res; }
	if (!gp_ipl_ensure_dir()) { $res['error'] = 'write_failed'; return $res; }
	$lock = @fopen(gp_ipl_dir() . '/.feedsync-' . $f['id'] . '.lock', 'c');
	if ($lock && !@flock($lock, LOCK_EX | LOCK_NB)) { fclose($lock); $res['error'] = 'busy'; return $res; }
	try {
		$st = $f['st'];
		$st['last_run'] = $now;
		$fail = function ($code, $detail = '') use (&$st, &$res, $f, $actor, $ip) {
			$st['error'] = $code . ($detail !== '' ? ': ' . $detail : '');
			$st['fail_streak']++;
			$res['error'] = $code;
			$res['detail'] = $detail;
			gp_feeds_update(function ($feeds) use ($f, $st) { foreach ($feeds as $i => $x) { if ($x['id'] === $f['id']) { $feeds[$i]['st'] = $st; } } return $feeds; });
			gp_feed_audit($actor, $ip, $f['id'], null, array('failed' => $st['error'], 'streak' => $st['fail_streak']));
			return $res;
		};
		if (!empty($o['accept_hold'])) {
			if (!is_file(gp_feed_hold_path($f['id']))) { return $fail('no_hold'); }
			$entries = gp_feed_read_lines(gp_feed_hold_path($f['id']));
			$p = array('v6' => $st['v6'], 'invalid' => $st['invalid'], 'dropped_all' => $st['dropped_all'], 'format' => $st['format']);
		} else {
			$fe = gp_feed_fetch($f['url']);
			$st['http'] = $fe['http']; $st['bytes'] = $fe['bytes']; $st['ms'] = $fe['ms']; $st['redirects'] = $fe['redirects'];
			if (!$fe['ok']) { return $fail($fe['error'], $fe['detail']); }
			$pr = gp_feed_parse($fe['body'], $f['format']);
			if (!$pr['ok']) { return $fail($pr['error']); }
			$p = $pr;
			$entries = $pr['entries'];
			$st['format'] = $pr['format']; $st['v6'] = $pr['v6']; $st['invalid'] = $pr['invalid']; $st['dropped_all'] = $pr['dropped_all'];
			if (!$entries) { return $fail('zero'); }
		}
		$st['found'] = count($entries);
		$res['found'] = count($entries);
		// A cdn destination holds /8 to /32 only; anything wider is "held by the cap" and never applied (no force flag can widen it).
		$cap_samples = array();
		$cap_n = 0;
		$apply = array();
		if ($f['dest'] === 'cdn') {
			foreach ($entries as $e) { if (gp_feed_cdn_ok($e)) { $apply[] = $e; } else { $cap_n++; if (count($cap_samples) < GP_IPL_SAMPLES) { $cap_samples[] = $e; } } }
		} else {
			$prot = gp_ipl_protected(array());
			foreach ($entries as $e) {
				$en = gp_ipl_parse_entry($e);
				if ($en !== null && gp_ipl_refusal($en, 'allow', $prot, $f['force']) !== '') { $cap_n++; if (count($cap_samples) < GP_IPL_SAMPLES) { $cap_samples[] = $e; } }
			}
			$apply = $entries;                // all are written; the compile drops the capped ones (and says so) unless the feed is forced
		}
		$cur_path = $f['dest'] === 'cdn' ? gp_feed_src_path($f['id']) : gp_ipl_source_path(gp_feed_list_id($f['id']));
		$current = gp_feed_read_lines($cur_path);
		$new_set = array_flip($apply);
		$cur_set = array_flip($current);
		$added = count(array_diff_key($new_set, $cur_set));
		$removed = count(array_diff_key($cur_set, $new_set));
		$unchanged = count(array_intersect_key($new_set, $cur_set));
		$res['added'] = $added; $res['removed'] = $removed; $res['unchanged'] = $unchanged;
		$st['added'] = $added; $st['removed'] = $removed; $st['unchanged'] = $unchanged;
		$st['cap_held'] = $cap_n; $st['cap_samples'] = $cap_samples;
		// A fetch that would drop more than half of what is there waits for an admin (a provider outage returning a stub, a moved URL).
		if (empty($o['accept_hold']) && $current && $removed > count($current) * GP_FEED_SHRINK) {
			gp_feed_write_text(gp_feed_hold_path($f['id']), $apply);
			$st['held'] = 'shrink'; $st['held_n'] = count($apply); $st['held_removed'] = $removed;
			$st['error'] = '';
			gp_feeds_update(function ($feeds) use ($f, $st) { foreach ($feeds as $i => $x) { if ($x['id'] === $f['id']) { $feeds[$i]['st'] = $st; } } return $feeds; });
			gp_feed_audit($actor, $ip, $f['id'], null, array('held' => 'shrink', 'removed' => $removed, 'current' => count($current)));
			$res['ok'] = true; $res['status'] = 'held';
			return $res;
		}
		// Apply.
		if ($f['dest'] === 'cdn') {
			$union = gp_feed_cdn_union($fs['feeds'], array($f['id'] => $apply));
			if (count($union) > GP_FEED_CDN_MAX) { return $fail('cdn_too_many', (string)count($union)); }
			if (!gp_feed_write_text($cur_path, $apply)) { return $fail('write_failed'); }
			$sv = gp_feed_cdn_save($union, $actor, $ip);
			if (!$sv[0]) { gp_feed_write_text($cur_path, $current); return $fail($sv[1]); }
		} else {
			if (!gp_feed_write_text($cur_path, $apply)) { return $fail('write_failed'); }
			$sv = gp_feed_sync_list($f, $actor, $ip, true);
			if (!$sv[0]) { return $fail($sv[1]); }
		}
		@unlink(gp_feed_hold_path($f['id']));
		$st['held'] = ''; $st['held_n'] = 0; $st['held_removed'] = 0; $st['error'] = ''; $st['fail_streak'] = 0; $st['last_ok'] = $now; $st['applied'] = count($apply);
		gp_feeds_update(function ($feeds) use ($f, $st) { foreach ($feeds as $i => $x) { if ($x['id'] === $f['id']) { $feeds[$i]['st'] = $st; } } return $feeds; });
		gp_feed_audit($actor, $ip, $f['id'], null, array('applied' => count($apply), 'added' => $added, 'removed' => $removed, 'unchanged' => $unchanged, 'cap_held' => $cap_n,
			'v6_dropped' => $p['v6'], 'accepted_hold' => !empty($o['accept_hold'])));
		$res['ok'] = true;
		$res['status'] = ($added === 0 && $removed === 0) ? 'nochange' : 'applied';
		return $res;
	} finally {
		if ($lock) { @flock($lock, LOCK_UN); @fclose($lock); }
	}
}

// ---------------------------------------------------------------- managing feeds (the panel actions)

// Create or update a feed from a form post. Returns array(ok, lang key, detail, errors field => code, draft).
function gp_feed_save(array $p, $actor, $ip) {
	$res = array('ok' => false, 'msg' => 'feed_invalid', 'detail' => '', 'errors' => array(), 'draft' => null);
	$fs = gp_feeds_state();
	if ($fs['state'] === 'invalid') { $res['msg'] = 'feed_file_invalid'; return $res; }
	$id = isset($p['id']) && is_string($p['id']) ? $p['id'] : '';
	$old = $id !== '' ? gp_feed_find($fs['feeds'], $id) : null;
	if ($id !== '' && $old === null) { $res['msg'] = 'feed_not_found'; return $res; }
	if (!$old && count($fs['feeds']) >= GP_FEED_MAX) { $res['msg'] = 'feed_too_many'; return $res; }
	$rec = gp_feed_blank();
	foreach (array('name', 'url', 'format', 'schedule', 'note', 'mode') as $k) { if (isset($p[$k]) && is_string($p[$k])) { $rec[$k] = $p[$k]; } }
	$rec['enabled'] = !empty($p['enabled']);
	$rec['force'] = !empty($p['force']);
	$rec['dest'] = $old ? $old['dest'] : (isset($p['dest']) && is_string($p['dest']) ? $p['dest'] : '');     // the destination is fixed once a feed exists
	if ($old) { $rec['id'] = $old['id']; $rec['st'] = $old['st']; $rec['created_by'] = $old['created_by']; $rec['created_at'] = $old['created_at']; }
	else {
		$base = substr(gp_ipl_slug(isset($rec['name']) ? $rec['name'] : ''), 0, 19);
		$nid = $base;
		for ($i = 2; gp_feed_find($fs['feeds'], $nid) !== null; $i++) { $nid = substr($base, 0, 16) . '-' . $i; }
		$rec['id'] = $nid; $rec['created_by'] = (string)$actor; $rec['created_at'] = time();
	}
	$res['draft'] = $rec;
	if ($rec['dest'] === 'cdn') { $rec['force'] = false; }
	$v = gp_feed_validate($rec);
	if (!$v[0]) { $res['errors'] = $v[1]; return $res; }
	$new = $v[1];
	if (!$old && $new['dest'] === 'allow') {
		foreach (gp_iplists_state()['lists'] as $l) { if ($l['id'] === gp_feed_list_id($new['id'])) { $res['msg'] = 'feed_id_taken'; return $res; } }
	}
	$r = gp_feeds_update(function ($feeds) use ($new, $old) {
		if ($old) { foreach ($feeds as $i => $x) { if ($x['id'] === $new['id']) { $feeds[$i] = $new; } } }
		else { $feeds[] = $new; }
		return $feeds;
	});
	if (!$r[0]) { $res['msg'] = $r[1]; return $res; }
	gp_feed_audit($actor, $ip, $new['id'], $old ? array('url' => $old['url'], 'enabled' => $old['enabled'], 'schedule' => $old['schedule'], 'force' => $old['force']) : null,
		array('url' => $new['url'], 'dest' => $new['dest'], 'enabled' => $new['enabled'], 'schedule' => $new['schedule'], 'mode' => $new['mode'], 'force' => $new['force'], 'format' => $new['format']));
	// Keep the destination in step with the record (the list's enabled / mode / force, or the merged cdn ranges).
	if ($new['dest'] === 'allow') { $c = gp_feed_sync_list($new, $actor, $ip, true); }
	else { $all = gp_feeds_state()['feeds']; $c = gp_feed_cdn_save(gp_feed_cdn_union($all), $actor, $ip); }
	$res['ok'] = true;
	$res['msg'] = $old ? 'feed_saved' : 'feed_created';
	$res['detail'] = $c[0] ? '' : gp_t_safe('feed_dest_failed');
	return $res;
}

// Delete a feed with the entries it owns (its list, or its share of the cdn ranges). Manual lists and manual cdn_ranges stay.
function gp_feed_delete($id, $actor, $ip) {
	$fs = gp_feeds_state();
	$f = gp_feed_find($fs['feeds'], (string)$id);
	if ($f === null) { return array(false, 'feed_not_found', ''); }
	$r = gp_feeds_update(function ($feeds) use ($f) { return array_values(array_filter($feeds, function ($x) use ($f) { return $x['id'] !== $f['id']; })); });
	if (!$r[0]) { return array(false, $r[1], ''); }
	@unlink(gp_feed_hold_path($f['id']));
	if ($f['dest'] === 'allow') {
		$lid = gp_feed_list_id($f['id']);
		gp_iplists_update(function ($lists, $next) use ($lid) { return array(array_values(array_filter($lists, function ($x) use ($lid) { return $x['id'] !== $lid; })), $next); });
		@unlink(gp_ipl_source_path($lid));
		gp_iplists_compile_auto($actor);
	} else {
		@unlink(gp_feed_src_path($f['id']));
		gp_feed_cdn_save(gp_feed_cdn_union(gp_feeds_state()['feeds']), $actor, $ip);
	}
	gp_feed_audit($actor, $ip, $f['id'], array('url' => $f['url'], 'dest' => $f['dest']), null);
	return array(true, 'feed_deleted', '');
}

// Accept the entries held by the compile cap for THIS feed (the list's force flag, as for a manual list), audit-logged.
function gp_feed_accept_cap($id, $actor, $ip) {
	$fs = gp_feeds_state();
	$f = gp_feed_find($fs['feeds'], (string)$id);
	if ($f === null || $f['dest'] !== 'allow') { return array(false, 'feed_not_found', ''); }
	$f['force'] = true;
	$r = gp_feeds_update(function ($feeds) use ($f) { foreach ($feeds as $i => $x) { if ($x['id'] === $f['id']) { $feeds[$i]['force'] = true; $feeds[$i]['st']['cap_held'] = 0; $feeds[$i]['st']['cap_samples'] = array(); } } return $feeds; });
	if (!$r[0]) { return array(false, $r[1], ''); }
	gp_feed_sync_list($f, $actor, $ip, true);
	gp_feed_audit($actor, $ip, $f['id'], array('force' => false), array('force' => true, 'accepted_wide_entries' => true));
	return array(true, 'feed_cap_accepted', '');
}

// Drop a held fetch; the current entries stay as they are.
function gp_feed_discard_hold($id, $actor, $ip) {
	$fs = gp_feeds_state();
	$f = gp_feed_find($fs['feeds'], (string)$id);
	if ($f === null) { return array(false, 'feed_not_found', ''); }
	@unlink(gp_feed_hold_path($f['id']));
	gp_feeds_update(function ($feeds) use ($f) { foreach ($feeds as $i => $x) { if ($x['id'] === $f['id']) { $feeds[$i]['st']['held'] = ''; $feeds[$i]['st']['held_n'] = 0; $feeds[$i]['st']['held_removed'] = 0; } } return $feeds; });
	gp_feed_audit($actor, $ip, $f['id'], array('held' => 'shrink'), array('held' => ''));
	return array(true, 'feed_hold_discarded', '');
}

// ---------------------------------------------------------------- schedule, health, summary

// The feeds whose schedule is due. A held feed waits for its admin; manual feeds never run on their own.
function gp_feeds_due($now = null) {
	$now = $now === null ? time() : (int)$now;
	$out = array();
	foreach (gp_feeds_state()['feeds'] as $f) {
		if (!$f['enabled'] || $f['schedule'] === 'manual' || $f['st']['held'] !== '') { continue; }
		$every = $f['schedule'] === 'weekly' ? 6 * 86400 + 20 * 3600 : 20 * 3600;       // a little under the period: cron drifts
		if ($f['st']['last_run'] === 0 || $now - $f['st']['last_run'] >= $every) { $out[] = $f['id']; }
	}
	return $out;
}

// Run what is due (the cron job). Returns array(ran, failed, lines).
function gp_feeds_run_due($actor, $ip = '', $now = null) {
	$out = array('ran' => 0, 'failed' => 0, 'lines' => array());
	foreach (gp_feeds_due($now) as $id) {
		$r = gp_feed_sync($id, $actor, $ip, $now === null ? array() : array('now' => $now));
		$out['ran']++;
		if (!$r['ok']) { $out['failed']++; }
		$out['lines'][] = $id . ': ' . $r['status'] . ($r['ok'] ? ' (+' . $r['added'] . ' -' . $r['removed'] . ' =' . $r['unchanged'] . ')' : ' ' . $r['error'] . ($r['detail'] !== '' ? ' ' . $r['detail'] : ''));
	}
	return $out;
}

// For the dashboard: enabled feeds that failed GP_FEED_FAIL_ALERT times in a row, and held fetches. Pure on the state.
function gp_feeds_health(?array $feeds = null) {
	$feeds = $feeds === null ? gp_feeds_state()['feeds'] : $feeds;
	$out = array('failing' => array(), 'held' => array(), 'scheduled' => 0);
	foreach ($feeds as $f) {
		if ($f['enabled'] && $f['schedule'] !== 'manual') { $out['scheduled']++; }
		if ($f['enabled'] && $f['st']['fail_streak'] >= GP_FEED_FAIL_ALERT) { $out['failing'][] = array('id' => $f['id'], 'name' => $f['name'], 'n' => $f['st']['fail_streak'], 'error' => $f['st']['error']); }
		if ($f['st']['held'] !== '') { $out['held'][] = array('id' => $f['id'], 'name' => $f['name']); }
	}
	return $out;
}

// The error text of a feed's last failure: "code: detail" with the code translated.
function gp_feed_error_text($error) {
	$error = (string)$error;
	if ($error === '') { return ''; }
	$parts = explode(': ', $error, 2);
	$key = 'feed_err_' . $parts[0];
	$t = gp_t($key);
	return ($t === $key ? $parts[0] : $t) . (isset($parts[1]) ? ' (' . $parts[1] . ')' : '');
}
