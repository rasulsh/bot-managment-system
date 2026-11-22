<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// Authentication, session, CSRF and login rate limiting.
//
// Three deliberate choices worth knowing before changing anything here:
//
// 1. No setup wizard. If panel/panel.config.php is absent or malformed EVERY
//    route returns a bare 404 - no hint that a panel exists at all. A first-run
//    setup screen reachable by whoever finds the URL first is how admin panels
//    get taken over; one install-time CLI command is the correct trade.
//
// 2. The login rate limit is the one place in this entire system that does NOT
//    fail open. Everywhere else a broken Redis means "allow". Here it means
//    "fall back to a file counter", because a rate limiter that disappears when
//    Redis hiccups is not a rate limiter.
//
// 3. Wrong username and wrong password produce an identical message, an
//    identical status and a comparable response time, so the login form cannot
//    be used to enumerate the operator's username.

require_once __DIR__ . '/../guard/redis.php';
require_once __DIR__ . '/users.php';

define('GP_LOGIN_MAX_ATTEMPTS', 5);
define('GP_LOGIN_WINDOW', 900);          // 15 minutes
define('GP_LOGIN_LOCKOUT', 900);         // 15 minutes
define('GP_SESSION_COOKIE', 'gp_sess');
define('GP_KNOWN_COOKIE', 'gp_kd');         // the "known device" cookie (see below)
define('GP_KNOWN_TTL', 90 * 86400);
define('GP_FLASH_COOKIE', 'gp_flash');
define('GP_FLASH_MAX', 1024);            // cap on the stored flash JSON, in bytes

function gp_panel_config_path() {
	return __DIR__ . '/panel.config.php';
}

// Load the panel credentials, or null when the panel is not installed.
// Null is the signal for a bare 404: never a wizard, never an explanation.
function gp_panel_config() {
	// Test seam: panel-selftest (which defines GP_SELFTEST) injects a config so
	// the session, CSRF and renewal paths can be exercised without an installed
	// panel. Never reachable in production - index.php does not define
	// GP_SELFTEST - and it returns before the static cache, so a test that sets
	// and later unsets the global leaves the real resolution untouched.
	if (defined('GP_SELFTEST') && isset($GLOBALS['gp_test_panel_cfg'])) {
		return $GLOBALS['gp_test_panel_cfg'];
	}
	static $cache = false;
	if ($cache !== false) { return $cache; }
	$cache = null;
	try {
		$path = gp_panel_config_path();
		if (!is_file($path)) { return null; }
		$cfg = require $path;
		if (!is_array($cfg)) { return null; }
		foreach (array('username', 'password_hash', 'session_secret') as $key) {
			if (!isset($cfg[$key]) || !is_string($cfg[$key]) || $cfg[$key] === '') {
				return null;
			}
		}
		if (strlen($cfg['session_secret']) < 32) { return null; }
		if (!isset($cfg['session_ttl']) || !is_int($cfg['session_ttl'])
			|| $cfg['session_ttl'] < 300) {
			$cfg['session_ttl'] = 43200;
		}
		// The two address lists are normalised by gp_ip_list(): a single string
		// becomes a one-entry list, anything else that is not a list is kept as
		// an empty ('misconfigured') list so gp_ip_allowed() can fail closed.
		$cfg['ip_allowlist'] = isset($cfg['ip_allowlist']) ? gp_ip_list($cfg['ip_allowlist']) : array();
		$cfg['trusted_proxies'] = isset($cfg['trusted_proxies']) ? gp_ip_list($cfg['trusted_proxies']) : array();
		if ($cfg['trusted_proxies'] === null) { $cfg['trusted_proxies'] = array(); }
		$cache = $cfg;
	} catch (\Throwable $e) {
		$cache = null;
	}
	return $cache;
}

// --------------------------------------------------------------------------
// Client address and IP allowlist
// --------------------------------------------------------------------------

// Turn a configured value into a list of strings. null means "configured, but
// not a usable list" (the caller decides what that means); array() is a real,
// empty list.
function gp_ip_list($value) {
	if (is_string($value)) { return $value === '' ? array() : array($value); }
	if (!is_array($value)) { return null; }
	$out = array();
	foreach ($value as $entry) {
		if (!is_string($entry)) { return null; }
		$out[] = $entry;
	}
	return $out;
}

// Split "addr" or "addr/bits" into array(packed address, bits), or null when it
// is not a valid IPv4 or IPv6 address or prefix. An IPv4-mapped IPv6 address is
// treated as the IPv4 address it is, so 1.2.3.4 and ::ffff:1.2.3.4 are one
// thing. No zone ids, no hostnames, no ranges written with a dash.
function gp_ip_parse($text) {
	$text = trim((string)$text);
	if ($text === '' || strlen($text) > 64) { return null; }
	$pos = strpos($text, '/');
	$addr = $pos === false ? $text : substr($text, 0, $pos);
	$bits = null;
	if ($pos !== false) {
		$tail = substr($text, $pos + 1);
		if ($tail === '' || !ctype_digit($tail) || strlen($tail) > 3) { return null; }
		$bits = (int)$tail;
	}
	if (filter_var($addr, FILTER_VALIDATE_IP) === false) { return null; }
	$canon = gv_ip_canon($addr);
	$packed = @inet_pton($canon);
	if ($packed === false) { return null; }
	$max = strlen($packed) * 8;
	if ($bits === null) { return array($packed, $max); }
	// A prefix written against the IPv6 form of a mapped address ("::ffff:1.2.3.0/120")
	// would need shifting; it is refused rather than guessed at.
	if (strpos($addr, ':') !== false && strlen($packed) === 4) { return null; }
	if ($bits > $max) { return null; }
	return array($packed, $bits);
}

// True when $ip lies inside $cidr (single address or prefix, IPv4 or IPv6).
function gp_ip_in($ip, $cidr) {
	$a = gp_ip_parse($ip);
	$b = gp_ip_parse($cidr);
	if ($a === null || $b === null) { return false; }
	if (strpos((string)$ip, '/') !== false) { return false; }       // an address, not a range
	if (strlen($a[0]) !== strlen($b[0])) { return false; }          // v4 never matches v6
	$bits = $b[1];
	$whole = intdiv($bits, 8);
	if ($whole > 0 && substr($a[0], 0, $whole) !== substr($b[0], 0, $whole)) { return false; }
	$rest = $bits % 8;
	if ($rest === 0) { return true; }
	$mask = (0xFF << (8 - $rest)) & 0xFF;
	return ((ord($a[0][$whole]) & $mask) === (ord($b[0][$whole]) & $mask));
}

function gp_ip_in_any($ip, array $list) {
	foreach ($list as $cidr) {
		if (gp_ip_in($ip, (string)$cidr)) { return true; }
	}
	return false;
}

// The client address, decided from the connection and, only when that
// connection comes from a trusted proxy, from X-Forwarded-For.
//
// REMOTE_ADDR is the only thing a client cannot choose. X-Forwarded-For is a
// header anyone can send, so it is read ONLY when REMOTE_ADDR is inside
// $trusted. Then the list is walked from the right, skipping addresses that are
// themselves trusted proxies, and the first address that is not one is the
// client: entries further left were written by the client or by hops we have no
// reason to believe. A header that does not parse is ignored as a whole.
// Pure, so the self-test can exercise it without a web server.
function gp_resolve_client_ip(array $server, array $trusted) {
	$remote = isset($server['REMOTE_ADDR']) ? (string)$server['REMOTE_ADDR'] : '';
	if (gp_ip_parse($remote) === null || strpos($remote, '/') !== false) { return ''; }
	$remote = gv_ip_canon($remote);
	if (!$trusted || !gp_ip_in_any($remote, $trusted)) { return $remote; }
	$header = isset($server['HTTP_X_FORWARDED_FOR']) ? (string)$server['HTTP_X_FORWARDED_FOR'] : '';
	if ($header === '' || strlen($header) > 1024) { return $remote; }
	$hops = array_map('trim', explode(',', $header));
	if (count($hops) > 20) { return $remote; }
	foreach ($hops as $hop) {
		if (gp_ip_parse($hop) === null || strpos($hop, '/') !== false) { return $remote; }
	}
	for ($i = count($hops) - 1; $i >= 0; $i--) {
		$hop = gv_ip_canon($hops[$i]);
		if (!gp_ip_in_any($hop, $trusted)) { return $hop; }
	}
	return $remote;
}

// The panel's view of the client address (see gp_resolve_client_ip).
function gp_client_ip() {
	static $cache = null;
	if (defined('GP_SELFTEST')) { $cache = null; }                   // the test changes $_SERVER
	if ($cache !== null) { return $cache; }
	$cfg = gp_panel_config();
	$trusted = ($cfg !== null && isset($cfg['trusted_proxies'])) ? $cfg['trusted_proxies'] : array();
	$cache = gp_resolve_client_ip($_SERVER, $trusted);
	return $cache;
}

// The IP allowlist.
//
//   key absent, or an empty list   no restriction (login still required). This is
//                                  the documented default so an upgrade does not
//                                  lock anybody out.
//   non-empty list                 only a client inside one of the entries gets in.
//                                  Entries that do not parse are ignored; if NONE
//                                  parses, nobody gets in (a typo must never turn
//                                  the restriction off).
//   present but not a list         nobody gets in.
//   no usable client address       nobody gets in.
function gp_ip_allowed(array $cfg) {
	if (!array_key_exists('ip_allowlist', $cfg)) { return true; }
	$list = $cfg['ip_allowlist'];
	if ($list === null) { return false; }
	if (!$list) { return true; }
	$ip = gp_client_ip();
	if ($ip === '') { return false; }
	foreach ($list as $entry) {
		if (gp_ip_in($ip, (string)$entry)) { return true; }
	}
	return false;
}

// --------------------------------------------------------------------------
// Session cookie: user.issued_at.hmac
// --------------------------------------------------------------------------

// $ver is the user's session_version (panel/users.php). It is part of what the signature covers but not of the token: a
// bump (disable, role change, password reset) makes every older token of that user fail its signature. Version 0 signs
// exactly what the single-user panel signed, so sessions that exist at upgrade time stay valid.
function gp_session_sign($user, $issued, $secret, $ver = 0) {
	return hash_hmac('sha256', $user . '.' . $issued . ((int)$ver > 0 ? '.v' . (int)$ver : ''), $secret);
}

function gp_session_make($user, $secret, $issued = null, $ver = 0) {
	$issued = $issued === null ? time() : (int)$issued;
	return $user . '.' . $issued . '.' . gp_session_sign($user, $issued, $secret, $ver);
}

// The user name a token claims (NOT verified): the lookup that tells which session_version to verify against.
function gp_session_claimed_user($token) {
	$token = (string)$token;
	$last = strrpos($token, '.');
	if ($last === false) { return ''; }
	$mid = strrpos(substr($token, 0, $last), '.');
	return $mid === false ? '' : substr($token, 0, $mid);
}

// Verify a session token. Returns array(user, issued) or false.
// Pure, so the self-test can exercise tamper and expiry without a browser.
//
// The token has a fixed three-field shape user.issued.hmac, but user is the
// only field that can itself contain a dot (a username like "admin.site").
// Splitting on '.' and demanding exactly three parts turned such a username
// into a token that never verified, bouncing login with no error. Parse from
// the right instead: the last field is the hmac, the one before it the issued
// timestamp, and everything before that is the user. The security properties
// are unchanged - the hmac still covers user.issued.
function gp_session_check($token, $secret, $ttl, $now = null, $ver = 0) {
	$now = $now === null ? time() : (int)$now;
	$token = (string)$token;
	$last_dot = strrpos($token, '.');
	if ($last_dot === false) { return false; }
	$hmac = substr($token, $last_dot + 1);
	$head = substr($token, 0, $last_dot);
	$mid_dot = strrpos($head, '.');
	if ($mid_dot === false) { return false; }
	$user   = substr($head, 0, $mid_dot);
	$issued = substr($head, $mid_dot + 1);
	if ($user === '' || !ctype_digit($issued)) { return false; }
	$issued = (int)$issued;
	if (!hash_equals(gp_session_sign($user, $issued, $secret, $ver), $hmac)) { return false; }
	if ($issued > $now + 60) { return false; }          // clock skew, not a future session
	if (($now - $issued) >= (int)$ttl) { return false; }
	return array('user' => $user, 'issued' => $issued);
}

// True when the session is past half its life and should be renewed.
function gp_session_should_renew($issued, $ttl, $now = null) {
	$now = $now === null ? time() : (int)$now;
	return ($now - (int)$issued) >= ((int)$ttl / 2);
}

function gp_cookie_path() {
	$self = isset($_SERVER['SCRIPT_NAME']) ? (string)$_SERVER['SCRIPT_NAME'] : '/';
	$dir = rtrim(str_replace('\\', '/', dirname($self)), '/');
	return $dir === '' ? '/' : $dir . '/';
}

function gp_is_https() {
	if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') {
		return true;
	}
	return isset($_SERVER['HTTP_X_FORWARDED_PROTO'])
		&& strtolower((string)$_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https';
}

function gp_session_set_cookie($token, $ttl) {
	if (headers_sent()) { return; }
	setcookie(GP_SESSION_COOKIE, $token, array(
		'expires'  => time() + (int)$ttl,
		'path'     => gp_cookie_path(),
		'secure'   => gp_is_https(),
		'httponly' => true,
		'samesite' => 'Strict',
	));
}

function gp_session_clear() {
	if (headers_sent()) { return; }
	setcookie(GP_SESSION_COOKIE, '', array(
		'expires'  => time() - 3600,
		'path'     => gp_cookie_path(),
		'secure'   => gp_is_https(),
		'httponly' => true,
		'samesite' => 'Strict',
	));
}

// The session token this request should derive from: the freshly issued token
// when the session was renewed below, otherwise the raw cookie. Request-scoped.
//
// On the request that crosses half the TTL, gp_current_user() sets a new cookie
// (new issued-at) but gp_csrf_token() used to read the stale $_COOKIE value, so
// a form rendered in that response carried a token bound to the old cookie;
// once the browser adopted the new cookie the next submit failed err_csrf once.
// Remembering the renewed token here lets gp_csrf_token() bind the form to the
// cookie the browser is about to adopt.
function gp_effective_session_token($set = null) {
	static $tok = null;
	if ($set !== null) { $tok = (string)$set; }
	return $tok;
}

// The record of the user the current request belongs to (without the password hash), or null.
function gp_session_record($set = false) {
	static $rec = null;
	if ($set !== false) { $rec = $set; }
	return $rec;
}

// The current logged-in user name, or null. The session must verify against the user's CURRENT session_version, and the
// user must still exist and be enabled, so a disable, a role change or a password reset ends a session on its next
// request. A user store that cannot be read logs nobody in (fail closed). Renews a half-expired session in place.
function gp_current_user() {
	gp_session_record(null);
	$cfg = gp_panel_config();
	if ($cfg === null) { return null; }
	$token = isset($_COOKIE[GP_SESSION_COOKIE]) ? (string)$_COOKIE[GP_SESSION_COOKIE] : '';
	if ($token === '') { return null; }
	$claimed = gp_session_claimed_user($token);
	if ($claimed === '') { return null; }
	$u = gp_users_find($claimed);
	if ($u === null || !$u['enabled']) { return null; }
	$session = gp_session_check($token, $cfg['session_secret'], $cfg['session_ttl'], null, (int)$u['session_version']);
	if ($session === false) { return null; }
	if (gp_session_should_renew($session['issued'], $cfg['session_ttl'])) {
		// Build the renewed token once and use it for both the cookie and the
		// request-scoped holder, so CSRF tokens rendered this request match it.
		$new = gp_session_make($session['user'], $cfg['session_secret'], null, (int)$u['session_version']);
		gp_session_set_cookie($new, $cfg['session_ttl']);
		gp_effective_session_token($new);
	}
	unset($u['password_hash']);
	gp_session_record($u);
	return $session['user'];
}

// The role of the current request's user ('' when nobody is logged in).
function gp_current_role() {
	$r = gp_session_record();
	return $r === null ? '' : $r['role'];
}

// --------------------------------------------------------------------------
// Known device: a signed cookie that keeps the per-USERNAME sign-in limit from locking a person out
// --------------------------------------------------------------------------
//
// The per-username limit (10 wrong passwords per 15 minutes, from any address) lets anybody who knows a name keep that person out.
// A successful sign-in therefore sets a cookie, HMAC-signed with the panel's session secret, bound to the username and to the
// user's CURRENT session_version, valid 90 days (HttpOnly, SameSite=Strict, Secure on https). A sign-in attempt that presents a
// valid cookie for THAT username is neither blocked nor counted by the per-username limit. The per-address limit and the global
// limit still apply to it, and a wrong password from that device still counts against the address. Disabling the user, a role
// change and a password reset bump session_version, so every known-device cookie of that user stops working with them.
// A cookie made for another user, a forged or expired one, or one for a user that does not exist, is simply ignored.

function gp_known_sign($user, $issued, $ver, $secret) {
	return hash_hmac('sha256', 'kd.' . $user . '.' . (int)$issued . '.v' . (int)$ver, $secret);
}

// The cookie value for a user record (array with username and session_version).
function gp_known_make(array $rec, $secret, $issued = null) {
	$issued = $issued === null ? time() : (int)$issued;
	return $rec['username'] . '.' . $issued . '.' . gp_known_sign($rec['username'], $issued, (int)$rec['session_version'], $secret);
}

// Is $cookie a valid known-device cookie for $rec (the CURRENT record of an enabled user)? Pure.
function gp_known_check($cookie, $rec, $secret, $now = null) {
	$now = $now === null ? time() : (int)$now;
	if (!is_string($cookie) || !is_array($rec) || empty($rec['enabled']) || !isset($rec['username'], $rec['session_version'])) { return false; }
	$last = strrpos($cookie, '.');
	if ($last === false) { return false; }
	$mac = substr($cookie, $last + 1);
	$head = substr($cookie, 0, $last);
	$mid = strrpos($head, '.');
	if ($mid === false) { return false; }
	$user = substr($head, 0, $mid);
	$issued = substr($head, $mid + 1);
	if ($user !== $rec['username'] || !ctype_digit($issued)) { return false; }       // another user's cookie
	$issued = (int)$issued;
	if ($issued > $now + 60 || ($now - $issued) >= GP_KNOWN_TTL) { return false; }
	return hash_equals(gp_known_sign($user, $issued, (int)$rec['session_version'], $secret), $mac);
}

function gp_known_set_cookie(array $rec, $secret) {
	if (headers_sent()) { return; }
	setcookie(GP_KNOWN_COOKIE, gp_known_make($rec, $secret), array(
		'expires'  => time() + GP_KNOWN_TTL,
		'path'     => gp_cookie_path(),
		'secure'   => gp_is_https(),
		'httponly' => true,
		'samesite' => 'Strict',
	));
}

// Does this request carry a valid known-device cookie for $username (an existing, enabled user)?
function gp_known_device($username) {
	$cfg = gp_panel_config();
	$rec = gp_users_find($username);
	if ($cfg === null || $rec === null) { return false; }
	return gp_known_check(isset($_COOKIE[GP_KNOWN_COOKIE]) ? (string)$_COOKIE[GP_KNOWN_COOKIE] : '', $rec, $cfg['session_secret']);
}

// --------------------------------------------------------------------------
// CSRF
// --------------------------------------------------------------------------

// Per-session token, derived from the session cookie so it needs no storage.
function gp_csrf_token() {
	$cfg = gp_panel_config();
	if ($cfg === null) { return ''; }
	// Prefer the renewed token when this request renewed the session, so the
	// rendered form is bound to the cookie the browser is about to adopt; fall
	// back to the raw cookie otherwise.
	$token = gp_effective_session_token();
	if ($token === null || $token === '') {
		$token = isset($_COOKIE[GP_SESSION_COOKIE]) ? (string)$_COOKIE[GP_SESSION_COOKIE] : '';
	}
	return hash_hmac('sha256', 'csrf.' . $token, $cfg['session_secret']);
}

function gp_csrf_check($submitted) {
	$expected = gp_csrf_token();
	if ($expected === '' || !is_string($submitted) || $submitted === '') { return false; }
	return hash_equals($expected, $submitted);
}

// --------------------------------------------------------------------------
// Flash messages that survive a redirect
// --------------------------------------------------------------------------
//
// gp_flash() collects messages per request, but gp_redirect() 303s and exits,
// so "override added", "job enqueued" and "settings saved" were never shown.
// These two pure functions serialize the pending flashes into a short-lived
// signed cookie and read them back on the next request. Signed with the panel
// session_secret so the value cannot be forged; JSON only, never unserialize.
// The reader keeps only the known {kind, message} string shape, and the views
// re-escape every value through gp_e at render time.

// Encode flashes to the signed cookie value, or '' when there is nothing to
// store, no secret, or the payload would exceed the size cap.
function gp_flash_encode(array $flashes, $secret) {
	$secret = (string)$secret;
	if (!$flashes || $secret === '') { return ''; }
	$json = json_encode(array_values($flashes));
	if (!is_string($json) || strlen($json) > GP_FLASH_MAX) { return ''; }
	$payload = rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
	return $payload . '.' . hash_hmac('sha256', $json, $secret);
}

// Decode and verify a cookie value into a list of array(kind, message).
// Returns an empty array on any failure: missing/oversize, bad base64, a
// signature mismatch, malformed JSON, or an entry of the wrong shape.
function gp_flash_decode($raw, $secret) {
	$raw = (string)$raw;
	$secret = (string)$secret;
	if ($raw === '' || $secret === '' || strlen($raw) > GP_FLASH_MAX + 128) {
		return array();
	}
	$dot = strrpos($raw, '.');
	if ($dot === false) { return array(); }
	$payload = substr($raw, 0, $dot);
	$mac = substr($raw, $dot + 1);
	$json = base64_decode(strtr($payload, '-_', '+/'), true);
	if ($json === false) { return array(); }
	if (!hash_equals(hash_hmac('sha256', $json, $secret), $mac)) { return array(); }
	$data = json_decode($json, true);
	if (!is_array($data)) { return array(); }
	$out = array();
	foreach ($data as $entry) {
		if (!is_array($entry) || !isset($entry['kind'], $entry['message'])) { continue; }
		if (!is_string($entry['kind']) || !is_string($entry['message'])) { continue; }
		$e = array('kind' => $entry['kind'], 'message' => $entry['message']);
		if (isset($entry['section']) && is_string($entry['section']) && preg_match('/^[a-z0-9-]{1,40}$/', $entry['section'])) { $e['section'] = $entry['section']; }
		$out[] = $e;
	}
	return $out;
}

// --------------------------------------------------------------------------
// Login rate limiting - the one component here that does not fail open
// --------------------------------------------------------------------------

function gp_ratelimit_file_dir() {
	return __DIR__ . '/.ratelimit';
}

// Count and record one attempt against a bucket. Returns the new count.
// Uses Redis when reachable and a file counter when it is not.
function gp_attempts_bump($bucket, $window) {
	$cfg = gv_cfg_load();
	$conn = gv_redis_connect($cfg['redis'], (string)$cfg['log_dir'], false);
	if ($conn) {
		$key = gp_key('login:' . $bucket);        // after connect: the prefix is set there
		// One pipelined SET NX EX + INCR + TTL: the counter is created with its
		// TTL in the same write, so it can never lock the bucket out forever,
		// and a TTL-less leftover is repaired. gv_bump() folds any failure to 0,
		// which sends this down the file fallback below - the limiter never
		// fails open just because Redis is unreachable.
		$n = gv_bump($conn, $key, $window);
		gv_redis_close($conn);
		if ($n > 0) { return $n; }
	}
	return gp_attempts_bump_file($bucket, $window);
}

function gp_attempts_get($bucket, $window) {
	$cfg = gv_cfg_load();
	$conn = gv_redis_connect($cfg['redis'], (string)$cfg['log_dir'], false);
	if ($conn) {
		$v = gv_r_get($conn, gp_key('login:' . $bucket));
		gv_redis_close($conn);
		if (is_string($v) && ctype_digit($v)) { return (int)$v; }
		if ($v === null) { return 0; }
	}
	return gp_attempts_get_file($bucket, $window);
}

// File fallback. Not as precise as Redis, and that is fine: the requirement is
// that an attacker cannot remove the limit by taking Redis away.
function gp_attempts_file($bucket) {
	return gp_ratelimit_file_dir() . '/' . substr(hash('sha256', (string)$bucket), 0, 32);
}

function gp_attempts_bump_file($bucket, $window) {
	$dir = gp_ratelimit_file_dir();
	if (!is_dir($dir)) { @mkdir($dir, 0700, true); }
	if (!is_dir($dir)) { return GP_LOGIN_MAX_ATTEMPTS + 1; }   // cannot count: lock out
	$file = gp_attempts_file($bucket);
	$now = time();
	$state = array('n' => 0, 'start' => $now);
	// Read, increment and write under one lock on one handle. Reading without
	// the lock while another request truncated the file made a reader see an
	// empty counter and start again at 1: sixty parallel guesses all got through.
	$fh = @fopen($file, 'c+');
	if (!$fh) { return GP_LOGIN_MAX_ATTEMPTS + 1; }           // cannot count: lock out
	@chmod($file, 0600);
	if (!@flock($fh, LOCK_EX)) { @fclose($fh); return GP_LOGIN_MAX_ATTEMPTS + 1; }
	$raw = stream_get_contents($fh);
	$decoded = ($raw === false || $raw === '') ? null : json_decode($raw, true);
	if (is_array($decoded) && isset($decoded['n'], $decoded['start'])
		&& ($now - (int)$decoded['start']) < (int)$window) {
		$state = array('n' => (int)$decoded['n'], 'start' => (int)$decoded['start']);
	}
	$state['n']++;
	rewind($fh);
	ftruncate($fh, 0);
	fwrite($fh, json_encode($state));
	fflush($fh);
	@flock($fh, LOCK_UN);
	@fclose($fh);
	return $state['n'];
}

function gp_attempts_get_file($bucket, $window) {
	$file = gp_attempts_file($bucket);
	if (!is_file($file)) { return 0; }
	$raw = @file_get_contents($file);
	$decoded = $raw === false ? null : json_decode($raw, true);
	if (!is_array($decoded) || !isset($decoded['n'], $decoded['start'])) { return 0; }
	if ((time() - (int)$decoded['start']) >= (int)$window) { return 0; }
	return (int)$decoded['n'];
}

// True when this address or username is currently locked out.
// The lock is checked here and the counter bumped only after a failed attempt
// (gp_login_record_failure), so this is check-then-record, not atomic: a burst
// of concurrent attempts can each pass the check before any of them records,
// letting a few extra tries through per window. The impact is bounded - the
// window is short, the per-IP and single global 'user' counters both still
// trip, and password_verify runs on every attempt - so this is left as a
// documented bound rather than adding decrement/compare-and-set complexity.
function gp_login_user_bucket($username) {
	return 'u:' . substr(hash('sha256', gp_users_norm($username)), 0, 24);
}

// Locked when: this address has failed too often, this USERNAME has (any address, so a guess spread over many addresses against
// one account still stops), or the whole panel has (the global counter, four times the per-address limit). The bucket of a
// username that does not exist counts the same, so the lock reveals nothing about which accounts exist.
function gp_login_locked($username, $known = false) {
	$ip = gp_client_ip();
	if (gp_attempts_get($ip, GP_LOGIN_WINDOW) >= GP_LOGIN_MAX_ATTEMPTS) { return true; }
	if ($username !== '') {
		// A known device (a valid cookie for this user) is not subject to the per-username limit: see "Known device" above.
		if (!$known && gp_attempts_get(gp_login_user_bucket($username), GP_LOGIN_WINDOW) >= GP_LOGIN_MAX_ATTEMPTS * 2) { return true; }
		// A distributed attempt spread over many addresses and names still hits this - for everybody EXCEPT a known device: otherwise
		// 20 wrong passwords from 4 addresses would lock every user out of their own browser. The failures of a known device
		// still count (below), against its address and against this counter, so a stolen cookie guessed from many addresses is visible.
		if (!$known && gp_attempts_get('user', GP_LOGIN_WINDOW) >= GP_LOGIN_MAX_ATTEMPTS * 4) { return true; }
	}
	return false;
}

// What is locked right now, for the Users page and the dashboard. The global counter is exact. The per-username and per-address
// counters are counted from Redis (their keys are hashed, so names are not shown); with Redis down only the global one is known.
function gp_login_global_state() {
	$limit = GP_LOGIN_MAX_ATTEMPTS * 4;
	$n = gp_attempts_get('user', GP_LOGIN_WINDOW);
	return array('n' => $n, 'limit' => $limit, 'locked' => $n >= $limit, 'ttl' => $n >= $limit ? gp_attempts_ttl('user', GP_LOGIN_WINDOW) : 0);
}

function gp_login_lock_state() {
	$out = array('global' => gp_login_global_state(), 'users' => 0, 'ips' => 0, 'scanned' => false);
	$cfg = gv_cfg_load();
	$conn = gv_redis_connect($cfg['redis'], (string)$cfg['log_dir'], false);
	if (!$conn) { return $out; }
	$out['scanned'] = true;
	$prefix = gp_key('login:');
	$cursor = '0'; $guard = 0;
	do {
		$reply = gv_redis_cmd($conn, array('SCAN', $cursor, 'MATCH', $prefix . '*', 'COUNT', '200'));
		if (!is_array($reply) || count($reply) < 2) { break; }
		$cursor = (string)$reply[0];
		foreach ((array)$reply[1] as $k) {
			$bucket = substr((string)$k, strlen($prefix));
			if ($bucket === 'user') { continue; }
			$v = gv_r_get($conn, $k);
			if (!is_string($v) || !ctype_digit($v)) { continue; }
			if (strncmp($bucket, 'u:', 2) === 0) { if ((int)$v >= GP_LOGIN_MAX_ATTEMPTS * 2) { $out['users']++; } }
			elseif ((int)$v >= GP_LOGIN_MAX_ATTEMPTS) { $out['ips']++; }
		}
		$guard++;
	} while ($cursor !== '0' && $guard < 50);
	gv_redis_close($conn);
	return $out;
}

// Seconds until the counter of one bucket expires (0 when it is not running).
function gp_attempts_ttl($bucket, $window) {
	$cfg = gv_cfg_load();
	$conn = gv_redis_connect($cfg['redis'], (string)$cfg['log_dir'], false);
	if ($conn) {
		$ttl = gv_redis_cmd($conn, array('TTL', gp_key('login:' . $bucket)));
		gv_redis_close($conn);
		if (is_int($ttl) && $ttl > 0) { return $ttl; }
		if ($ttl === -2) { return 0; }
	}
	$raw = @file_get_contents(gp_attempts_file($bucket));
	$decoded = $raw === false ? null : json_decode($raw, true);
	if (!is_array($decoded) || !isset($decoded['start'])) { return 0; }
	return max(0, (int)$window - (time() - (int)$decoded['start']));
}

// How long a locked-out visitor should wait: the longest of the counters that
// are over their limit. The same buckets as gp_login_locked(), and the answer
// does not depend on whether the username exists.
function gp_login_retry_after($username, $known = false) {
	$wait = 0;
	if (gp_attempts_get(gp_client_ip(), GP_LOGIN_WINDOW) >= GP_LOGIN_MAX_ATTEMPTS) {
		$wait = max($wait, gp_attempts_ttl(gp_client_ip(), GP_LOGIN_WINDOW));
	}
	if ($username !== '') {
		$ub = gp_login_user_bucket($username);
		if (!$known && gp_attempts_get($ub, GP_LOGIN_WINDOW) >= GP_LOGIN_MAX_ATTEMPTS * 2) { $wait = max($wait, gp_attempts_ttl($ub, GP_LOGIN_WINDOW)); }
		if (!$known && gp_attempts_get('user', GP_LOGIN_WINDOW) >= GP_LOGIN_MAX_ATTEMPTS * 4) { $wait = max($wait, gp_attempts_ttl('user', GP_LOGIN_WINDOW)); }
	}
	return $wait > 0 ? $wait : GP_LOGIN_LOCKOUT;
}

function gp_login_record_failure($username = '', $known = false) {
	gp_attempts_bump(gp_client_ip(), GP_LOGIN_WINDOW);
	gp_attempts_bump('user', GP_LOGIN_WINDOW);
	if ($username !== '' && !$known) { gp_attempts_bump(gp_login_user_bucket($username), GP_LOGIN_WINDOW); }
}

// --------------------------------------------------------------------------
// Login
// --------------------------------------------------------------------------

// Attempt a login. Returns array(ok, message_key[, wait_seconds]).
// Wrong user, wrong password and a disabled account are indistinguishable by message, status and - because password_verify
// runs on a dummy hash for an unknown name - by timing. The one different answer is login_store: the user store cannot be
// read (fail closed), which says nothing about any account.
function gp_login_attempt($username, $password) {
	$cfg = gp_panel_config();
	if ($cfg === null) { return array(false, 'login_failed'); }
	// A form field can arrive as an array (username[]=x); that is not a login.
	$username = is_string($username) ? gp_users_norm(substr($username, 0, 200)) : '';
	$password = is_string($password) ? $password : '';

	$known = gp_known_device($username);
	if (gp_login_locked($username, $known)) {
		gp_audit_append(array('event' => 'login_locked', 'actor' => $username,
			'ip' => gp_client_ip()));
		return array(false, 'login_locked', gp_login_retry_after($username, $known));
	}

	$st = gp_users_state();
	if (!$st['ok']) {
		gp_audit_append(array('event' => 'login_store_error', 'actor' => $username, 'ip' => gp_client_ip(), 'key' => $st['error']));
		return array(false, 'login_store');
	}
	$u = isset($st['users'][$username]) ? $st['users'][$username] : null;
	// Always run the hash comparison, even for a wrong or disabled user, so the failures cost the same amount of time.
	$pass_ok = password_verify($password, $u !== null ? $u['password_hash'] : gp_users_dummy_hash());

	if ($u !== null && $u['enabled'] && $pass_ok) {
		gp_session_set_cookie(gp_session_make($u['username'], $cfg['session_secret'], null, (int)$u['session_version']),
			$cfg['session_ttl']);
		gp_users_record_login($u['username'], gp_client_ip());
		gp_known_set_cookie($u, $cfg['session_secret']);                 // this browser is now a known device of this user
		gp_audit_append(array('event' => 'login_ok', 'actor' => $u['username'], 'key' => $u['role'],
			'ip' => gp_client_ip()));
		return array(true, 'login_ok');
	}

	gp_login_record_failure($username, $known);
	gp_audit_append(array('event' => 'login_failed', 'actor' => $username,
		'ip' => gp_client_ip()));
	return array(false, 'login_failed');
}


// --------------------------------------------------------------------------
// Clearing a lockout (admin only in the panel, and `php panel/setpass.php --unlock ...` from the shell)
// --------------------------------------------------------------------------

function gp_attempts_clear($bucket) {
	$cfg = gv_cfg_load();
	$conn = gv_redis_connect($cfg['redis'], (string)$cfg['log_dir'], false);
	if ($conn) {
		gv_redis_cmd($conn, array('DEL', gp_key('login:' . $bucket)));
		gv_redis_close($conn);
	}
	@unlink(gp_attempts_file($bucket));
}

// Clear the sign-in counters of a user name and / or an address; with $all every counter (all names, all addresses, the global
// one). A name or address also clears the global counter when that is what holds the lock. Returns what was cleared.
function gp_login_unlock($username = '', $ip = '', $all = false) {
	$cleared = array();
	if ($all) {
		$cfg = gv_cfg_load();
		$conn = gv_redis_connect($cfg['redis'], (string)$cfg['log_dir'], false);
		if ($conn) {
			$cursor = '0'; $guard = 0;
			do {
				$reply = gv_redis_cmd($conn, array('SCAN', $cursor, 'MATCH', gp_key('login:*'), 'COUNT', '200'));
				if (!is_array($reply) || count($reply) < 2) { break; }
				$cursor = (string)$reply[0];
				foreach ((array)$reply[1] as $k) { gv_redis_cmd($conn, array('DEL', $k)); }
				$guard++;
			} while ($cursor !== '0' && $guard < 200);
			gv_redis_close($conn);
		}
		foreach ((array)glob(gp_ratelimit_file_dir() . '/*') as $f) { if (is_file($f)) { @unlink($f); } }
		return array('all');
	}
	if ($username !== '') { gp_attempts_clear(gp_login_user_bucket($username)); $cleared[] = 'user'; }
	if ($ip !== '') { gp_attempts_clear($ip); $cleared[] = 'ip'; }
	if (($username !== '' || $ip !== '') && gp_attempts_get('user', GP_LOGIN_WINDOW) >= GP_LOGIN_MAX_ATTEMPTS * 4) { gp_attempts_clear('user'); $cleared[] = 'global'; }
	return $cleared;
}

// Ask a logged-in user for their password again before a dangerous action. Returns 'ok', 'bad' or 'locked'.
// A wrong password counts against the same login limiter, so this cannot be used to guess the password
// from a stolen session.
function gp_reauth($user, $password) {
	$u = gp_users_find($user);
	if ($u === null || !$u['enabled'] || !is_string($password) || $password === '') { return 'bad'; }
	if (gp_login_locked((string)$user)) { return 'locked'; }
	if (password_verify($password, $u['password_hash'])) { return 'ok'; }
	gp_login_record_failure((string)$user);
	gp_audit_append(array('event' => 'reauth_failed', 'actor' => (string)$user, 'ip' => gp_client_ip()));
	return 'bad';
}

function gp_logout($user) {
	gp_session_clear();
	gp_audit_append(array('event' => 'logout', 'actor' => (string)$user,
		'ip' => gp_client_ip()));
}
