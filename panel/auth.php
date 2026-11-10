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

define('GP_LOGIN_MAX_ATTEMPTS', 5);
define('GP_LOGIN_WINDOW', 900);          // 15 minutes
define('GP_LOGIN_LOCKOUT', 900);         // 15 minutes
define('GP_SESSION_COOKIE', 'gp_sess');
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
		if (!isset($cfg['ip_allowlist']) || !is_array($cfg['ip_allowlist'])) {
			$cfg['ip_allowlist'] = array();
		}
		$cache = $cfg;
	} catch (\Throwable $e) {
		$cache = null;
	}
	return $cache;
}

// The panel's view of the client address. The panel is not behind the guard's
// CDN logic, so this stays deliberately simple: REMOTE_ADDR only.
function gp_client_ip() {
	return isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '';
}

// Optional CIDR allowlist. Empty means disabled.
function gp_ip_allowed(array $cfg) {
	$list = isset($cfg['ip_allowlist']) ? $cfg['ip_allowlist'] : array();
	if (!$list) { return true; }
	$ip = gp_client_ip();
	foreach ($list as $cidr) {
		if (gv_cidr_match($ip, (string)$cidr)) { return true; }
	}
	return false;
}

// --------------------------------------------------------------------------
// Session cookie: user.issued_at.hmac
// --------------------------------------------------------------------------

function gp_session_sign($user, $issued, $secret) {
	return hash_hmac('sha256', $user . '.' . $issued, $secret);
}

function gp_session_make($user, $secret, $issued = null) {
	$issued = $issued === null ? time() : (int)$issued;
	return $user . '.' . $issued . '.' . gp_session_sign($user, $issued, $secret);
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
function gp_session_check($token, $secret, $ttl, $now = null) {
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
	if (!hash_equals(gp_session_sign($user, $issued, $secret), $hmac)) { return false; }
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

// The current logged-in user, or null. Renews a half-expired session in place.
function gp_current_user() {
	$cfg = gp_panel_config();
	if ($cfg === null) { return null; }
	$token = isset($_COOKIE[GP_SESSION_COOKIE]) ? (string)$_COOKIE[GP_SESSION_COOKIE] : '';
	if ($token === '') { return null; }
	$session = gp_session_check($token, $cfg['session_secret'], $cfg['session_ttl']);
	if ($session === false) { return null; }
	if (!hash_equals($cfg['username'], $session['user'])) { return null; }
	if (gp_session_should_renew($session['issued'], $cfg['session_ttl'])) {
		// Build the renewed token once and use it for both the cookie and the
		// request-scoped holder, so CSRF tokens rendered this request match it.
		$new = gp_session_make($session['user'], $cfg['session_secret']);
		gp_session_set_cookie($new, $cfg['session_ttl']);
		gp_effective_session_token($new);
	}
	return $session['user'];
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
		$out[] = array('kind' => $entry['kind'], 'message' => $entry['message']);
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
	$key = 'gp:login:' . $bucket;
	$cfg = gv_cfg_load();
	$conn = gv_redis_connect($cfg['redis'], (string)$cfg['log_dir'], false);
	if ($conn) {
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
	$key = 'gp:login:' . $bucket;
	$cfg = gv_cfg_load();
	$conn = gv_redis_connect($cfg['redis'], (string)$cfg['log_dir'], false);
	if ($conn) {
		$v = gv_r_get($conn, $key);
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
	if (is_file($file)) {
		$raw = @file_get_contents($file);
		$decoded = $raw === false ? null : json_decode($raw, true);
		if (is_array($decoded) && isset($decoded['n'], $decoded['start'])
			&& ($now - (int)$decoded['start']) < (int)$window) {
			$state = array('n' => (int)$decoded['n'], 'start' => (int)$decoded['start']);
		}
	}
	$state['n']++;
	@file_put_contents($file, json_encode($state), LOCK_EX);
	@chmod($file, 0600);
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
function gp_login_locked($username) {
	$ip = gp_client_ip();
	if (gp_attempts_get($ip, GP_LOGIN_WINDOW) >= GP_LOGIN_MAX_ATTEMPTS) { return true; }
	if ($username !== ''
		&& gp_attempts_get('user', GP_LOGIN_WINDOW) >= GP_LOGIN_MAX_ATTEMPTS * 4) {
		// A distributed attempt spread over many addresses still hits this.
		return true;
	}
	return false;
}

function gp_login_record_failure() {
	gp_attempts_bump(gp_client_ip(), GP_LOGIN_WINDOW);
	gp_attempts_bump('user', GP_LOGIN_WINDOW);
}

// --------------------------------------------------------------------------
// Login
// --------------------------------------------------------------------------

// Attempt a login. Returns array(ok, message_key).
// Wrong user and wrong password are indistinguishable by message, status and
// - because password_verify runs either way - by timing.
function gp_login_attempt($username, $password) {
	$cfg = gp_panel_config();
	if ($cfg === null) { return array(false, 'login_failed'); }
	$username = (string)$username;
	$password = (string)$password;

	if (gp_login_locked($username)) {
		gp_audit_append(array('event' => 'login_locked', 'actor' => $username,
			'ip' => gp_client_ip()));
		return array(false, 'login_locked');
	}

	$user_ok = hash_equals($cfg['username'], $username);
	// Always run the hash comparison, even for a wrong username, so the two
	// failures cost the same amount of time.
	$pass_ok = password_verify($password, $cfg['password_hash']);

	if ($user_ok && $pass_ok) {
		gp_session_set_cookie(gp_session_make($cfg['username'], $cfg['session_secret']),
			$cfg['session_ttl']);
		gp_audit_append(array('event' => 'login_ok', 'actor' => $cfg['username'],
			'ip' => gp_client_ip()));
		return array(true, 'login_ok');
	}

	gp_login_record_failure();
	gp_audit_append(array('event' => 'login_failed', 'actor' => $username,
		'ip' => gp_client_ip()));
	return array(false, 'login_failed');
}

function gp_logout($user) {
	gp_session_clear();
	gp_audit_append(array('event' => 'logout', 'actor' => (string)$user,
		'ip' => gp_client_ip()));
}
