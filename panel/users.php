<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// Panel users and roles: the user store (panel/users.json).
//
//   admin     everything, including user management and the updater
//   operator  UI label "Monitoring operator": every report and page except secrets and user management; changes nothing
//   demo      UI label "Demo": only the aggregate metrics page; changes nothing
//
// The store is one JSON file, written atomically (temp file + rename) under an flock, mode 0600, never web-served
// (panel/.htaccess denies it, scripts/exposure-check.sh checks it). Record fields: username, role, enabled,
// password_hash (password_hash(), default algorithm), created_at, created_by, updated_at, last_login_at,
// last_login_ip, session_version.
//
// Migration: when users.json does not exist, the single user of panel/panel.config.php becomes an enabled admin
// with the same password hash (nobody has to change a password). panel.config.php keeps the install settings
// (IP allowlist, session secret) and its username / password_hash, so the previous code still works after a rollback.
//
// Fail closed: a users.json that exists but cannot be read as a valid store (bad JSON, unknown role, duplicate name)
// logs nobody in; the login page says so and panel/setpass.php (shell) is the recovery.
//
// session_version: part of what a session cookie signs. Disabling a user, changing the role or resetting the
// password bumps it, so every existing session of that user stops working on its next request.
//
// Everything here writes audit lines (actor, target, before / after) and NEVER a password hash.

define('GP_USERS_FORMAT', 1);
define('GP_USERS_MIN_PASSWORD', 12);
define('GP_USERS_MAX_PASSWORD', 256);

function gp_users_roles() { return array('admin', 'operator', 'demo'); }

function gp_users_path() {
	// GV_USERS lets the self-test keep the store out of the working tree, like GV_AUDIT.
	$env = getenv('GV_USERS');
	if (is_string($env) && $env !== '') { return $env; }
	return __DIR__ . '/users.json';
}

// A valid bcrypt hash of a random string. Verifying against it for an unknown or disabled user makes the failure cost
// the same as a wrong password, so the login form cannot be used to find usernames.
function gp_users_dummy_hash() {
	return '$2y$10$C2G2CMHQgySilaxm2ERiquMzI3TDrlRV/a.7dxkD7Qnb7GSWoUEde';
}

function gp_users_norm($name) {
	return strtolower(trim((string)$name));
}

// The rule for NEW names: lowercase letters, digits, dot, underscore, hyphen; 3 to 32 characters. Input is lowercased first
// (unique, case-insensitive). An older install may have a name outside the rule (migrated as is); it can still log in.
function gp_users_valid_name($name) {
	return preg_match('/^[a-z0-9._-]{3,32}$/', gp_users_norm($name)) === 1;
}

// Returns '' when fine, else a lang key.
function gp_users_check_password($password, $username) {
	if (!is_string($password) || strlen($password) < GP_USERS_MIN_PASSWORD) { return 'usr_err_pw_short'; }
	if (strlen($password) > GP_USERS_MAX_PASSWORD) { return 'usr_err_pw_long'; }
	if (strtolower($password) === gp_users_norm($username)) { return 'usr_err_pw_same'; }
	return '';
}

// One record as stored, with defaults for missing fields. $hash is a password hash, not a password.
function gp_users_record($username, $role, $hash, $by, $now = null) {
	$now = $now === null ? time() : (int)$now;
	return array('username' => gp_users_norm($username), 'role' => $role, 'enabled' => true, 'password_hash' => (string)$hash,
		'created_at' => $now, 'created_by' => (string)$by, 'updated_at' => $now, 'last_login_at' => 0, 'last_login_ip' => '', 'session_version' => 0);
}

// Validate a decoded store. Returns array(true, users by name) or array(false, reason).
function gp_users_validate($data) {
	if (!is_array($data) || !isset($data['users']) || !is_array($data['users'])) { return array(false, 'not a user store'); }
	$out = array();
	foreach ($data['users'] as $u) {
		if (!is_array($u)) { return array(false, 'bad record'); }
		$name = isset($u['username']) && is_string($u['username']) ? $u['username'] : '';
		if (preg_match('/^[a-z0-9._-]{1,64}$/', $name) !== 1) { return array(false, 'bad username'); }
		if (isset($out[$name])) { return array(false, 'duplicate username'); }
		if (!isset($u['role']) || !in_array($u['role'], gp_users_roles(), true)) { return array(false, 'unknown role'); }
		if (!isset($u['password_hash']) || !is_string($u['password_hash']) || $u['password_hash'] === '') { return array(false, 'bad password hash'); }
		$out[$name] = array('username' => $name, 'role' => $u['role'], 'enabled' => !empty($u['enabled']), 'password_hash' => $u['password_hash'],
			'created_at' => (int)($u['created_at'] ?? 0), 'created_by' => is_string($u['created_by'] ?? null) ? $u['created_by'] : '',
			'updated_at' => (int)($u['updated_at'] ?? 0), 'last_login_at' => (int)($u['last_login_at'] ?? 0),
			'last_login_ip' => is_string($u['last_login_ip'] ?? null) ? $u['last_login_ip'] : '', 'session_version' => max(0, (int)($u['session_version'] ?? 0)));
	}
	return array(true, $out);
}

// The user of panel.config.php as an admin record, or null when that file has no usable user.
function gp_users_from_config() {
	$cfg = gp_panel_config();
	if ($cfg === null || !isset($cfg['username'], $cfg['password_hash'])) { return null; }
	$name = gp_users_norm($cfg['username']);
	if (preg_match('/^[a-z0-9._-]{1,64}$/', $name) !== 1) { return null; }
	$path = gp_panel_config_path();
	$when = is_file($path) ? (int)@filemtime($path) : time();
	return gp_users_record($name, 'admin', $cfg['password_hash'], 'migration', $when);
}

// Read the store. array('ok' => bool, 'users' => name => record, 'error' => '', 'migrated' => bool, 'readonly' => bool).
// $migrate false never creates the file (used under the lock, which does it itself). The result is cached per request
// and per file state; any write clears it.
function gp_users_state($fresh = false) {
	static $cache = null;
	$path = gp_users_path();
	if (!$fresh && $cache !== null && $cache['path'] === $path) {
		clearstatcache(true, $path);
		$sig = is_file($path) ? @filemtime($path) . ':' . @filesize($path) : 'missing';
		if ($cache['sig'] === $sig) { return $cache['state']; }
	}
	$state = gp_users_read($path);
	clearstatcache(true, $path);
	$cache = array('path' => $path, 'sig' => is_file($path) ? @filemtime($path) . ':' . @filesize($path) : 'missing', 'state' => $state);
	return $state;
}

function gp_users_read($path) {
	$fail = function ($why) { return array('ok' => false, 'users' => array(), 'error' => $why, 'migrated' => false, 'readonly' => false); };
	if (!is_file($path)) {
		$rec = gp_users_from_config();
		if ($rec === null) { return $fail('missing'); }
		$state = array('ok' => true, 'users' => array($rec['username'] => $rec), 'error' => '', 'migrated' => true, 'readonly' => false);
		// First load: write users.json so the store is real from now on. When the directory is not writable the migrated user
		// still works from memory (read-only: the Users page says so).
		$w = gp_users_write_locked(function ($users) use ($rec) {
			if ($users) { return null; }                     // somebody else created it meanwhile
			return array('users' => array($rec['username'] => $rec));
		});
		if ($w === false) { $state['readonly'] = true; }
		elseif (is_array($w) && !$w['ok']) { return $fail($w['error']); }
		elseif (is_array($w) && $w['wrote'] === false && is_file($path)) { return gp_users_read_file($path); }
		return $state;
	}
	return gp_users_read_file($path);
}

function gp_users_read_file($path) {
	$raw = @file_get_contents($path);
	if (!is_string($raw)) { return array('ok' => false, 'users' => array(), 'error' => 'unreadable', 'migrated' => false, 'readonly' => false); }
	$data = json_decode($raw, true);
	$v = gp_users_validate($data);
	if (!$v[0]) { return array('ok' => false, 'users' => array(), 'error' => 'corrupt', 'migrated' => false, 'readonly' => false); }
	return array('ok' => true, 'users' => $v[1], 'error' => '', 'migrated' => false, 'readonly' => false);
}

function gp_users_find($name) {
	$st = gp_users_state();
	$n = gp_users_norm($name);
	return ($st['ok'] && isset($st['users'][$n])) ? $st['users'][$n] : null;
}

function gp_users_enabled_admins(array $users) {
	$n = 0;
	foreach ($users as $u) { if ($u['role'] === 'admin' && $u['enabled']) { $n++; } }
	return $n;
}

// The lowest-level write: lock, read the current file (a missing or empty file is an empty store), let $fn decide.
// $fn(array $users) returns null (nothing to do), array('users' => new users) or array('error' => lang key).
// Returns false when the lock or the file cannot be written, array('ok' => true, 'wrote' => bool, 'users' => ...) or
// array('ok' => false, 'error' => key). A corrupt existing file is refused (nothing overwrites it).
function gp_users_write_locked(callable $fn) {
	$path = gp_users_path();
	$dir = dirname($path);
	if (!is_dir($dir) || !is_writable($dir)) { return false; }
	$lock = @fopen($path . '.lock', 'c');
	if (!$lock) { return false; }
	@chmod($path . '.lock', 0600);
	if (!@flock($lock, LOCK_EX)) { @fclose($lock); return false; }
	try {
		$users = array();
		if (is_file($path)) {
			$cur = gp_users_read_file($path);
			if (!$cur['ok']) { return array('ok' => false, 'error' => 'usr_err_store'); }
			$users = $cur['users'];
		}
		$res = $fn($users);
		if ($res === null) { return array('ok' => true, 'wrote' => false, 'users' => $users); }
		if (isset($res['error'])) { return array('ok' => false, 'error' => $res['error']); }
		$list = array_values($res['users']);
		$json = json_encode(array('v' => GP_USERS_FORMAT, 'users' => $list), JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
		$tmp = $path . '.tmp' . bin2hex(random_bytes(4));
		if ($json === false || @file_put_contents($tmp, $json) === false) { @unlink($tmp); return false; }
		@chmod($tmp, 0600);
		if (!@rename($tmp, $path)) { @unlink($tmp); return false; }
		@chmod($path, 0600);
		return array('ok' => true, 'wrote' => true, 'users' => $res['users']);
	} finally {
		@flock($lock, LOCK_UN);
		@fclose($lock);
	}
}

// Run a change under the lock, then audit. $fn(array $users) as above but may also return 'audit' => list of audit rows.
// Returns array(ok, error key).
function gp_users_mutate(callable $fn) {
	$st = gp_users_state();
	if (!$st['ok']) { return array(false, 'usr_err_store'); }
	if ($st['readonly']) { return array(false, 'usr_err_readonly'); }
	$audit = array();
	$r = gp_users_write_locked(function ($users) use ($fn, &$audit) {
		$res = $fn($users);
		if (is_array($res) && isset($res['audit'])) { $audit = $res['audit']; unset($res['audit']); }
		return $res;
	});
	if ($r === false) { return array(false, 'usr_err_write'); }
	if (!$r['ok']) { return array(false, $r['error']); }
	gp_users_state(true);                         // drop the per-request cache
	foreach ($audit as $row) { gp_audit_append($row); }
	return array(true, '');
}

function gp_users_audit_row($event, $actor, $target, $old, $new) {
	return array('event' => $event, 'actor' => (string)$actor, 'ip' => function_exists('gp_client_ip') ? gp_client_ip() : '', 'key' => (string)$target, 'old' => $old, 'new' => $new);
}

// What an audit row may say about a user: never the hash.
function gp_users_public($u) {
	return $u === null ? null : array('role' => $u['role'], 'enabled' => $u['enabled']);
}

// ---------------------------------------------------------------- management (admin only; the router enforces that)

function gp_users_create($actor, $name, $role, $password) {
	$n = gp_users_norm($name);
	if (!gp_users_valid_name($n)) { return array(false, 'usr_err_name'); }
	if (!in_array($role, gp_users_roles(), true)) { return array(false, 'usr_err_role'); }
	$pw = gp_users_check_password($password, $n);
	if ($pw !== '') { return array(false, $pw); }
	$hash = password_hash($password, PASSWORD_DEFAULT);
	return gp_users_mutate(function ($users) use ($actor, $n, $role, $hash) {
		if (isset($users[$n])) { return array('error' => 'usr_err_exists'); }
		$users[$n] = gp_users_record($n, $role, $hash, $actor);
		return array('users' => $users, 'audit' => array(gp_users_audit_row('user_create', $actor, $n, null, array('role' => $role, 'enabled' => true))));
	});
}

function gp_users_set_role($actor, $name, $role) {
	$n = gp_users_norm($name);
	if (!in_array($role, gp_users_roles(), true)) { return array(false, 'usr_err_role'); }
	return gp_users_mutate(function ($users) use ($actor, $n, $role) {
		if (!isset($users[$n])) { return array('error' => 'usr_err_unknown'); }
		$u = $users[$n];
		if ($u['role'] === $role) { return null; }
		if ($n === gp_users_norm($actor)) { return array('error' => 'usr_err_self'); }
		$old = gp_users_public($u);
		$users[$n]['role'] = $role;
		$users[$n]['updated_at'] = time();
		$users[$n]['session_version']++;               // ends the sessions that were issued under the old role
		if (gp_users_enabled_admins($users) < 1) { return array('error' => 'usr_err_last_admin'); }
		return array('users' => $users, 'audit' => array(gp_users_audit_row('user_role', $actor, $n, $old, gp_users_public($users[$n]))));
	});
}

function gp_users_set_enabled($actor, $name, $enabled) {
	$n = gp_users_norm($name);
	return gp_users_mutate(function ($users) use ($actor, $n, $enabled) {
		if (!isset($users[$n])) { return array('error' => 'usr_err_unknown'); }
		if ($users[$n]['enabled'] === (bool)$enabled) { return null; }
		if (!$enabled && $n === gp_users_norm($actor)) { return array('error' => 'usr_err_self'); }
		$old = gp_users_public($users[$n]);
		$users[$n]['enabled'] = (bool)$enabled;
		$users[$n]['updated_at'] = time();
		$users[$n]['session_version']++;
		if (gp_users_enabled_admins($users) < 1) { return array('error' => 'usr_err_last_admin'); }
		return array('users' => $users, 'audit' => array(gp_users_audit_row($enabled ? 'user_enable' : 'user_disable', $actor, $n, $old, gp_users_public($users[$n]))));
	});
}

function gp_users_reset_password($actor, $name, $password) {
	$n = gp_users_norm($name);
	$pw = gp_users_check_password($password, $n);
	if ($pw !== '') { return array(false, $pw); }
	$hash = password_hash($password, PASSWORD_DEFAULT);
	return gp_users_mutate(function ($users) use ($actor, $n, $hash) {
		if (!isset($users[$n])) { return array('error' => 'usr_err_unknown'); }
		$users[$n]['password_hash'] = $hash;
		$users[$n]['updated_at'] = time();
		$users[$n]['session_version']++;
		return array('users' => $users, 'audit' => array(gp_users_audit_row('user_password_reset', $actor, $n, null, array('password' => 'changed'))));
	});
}

function gp_users_delete($actor, $name) {
	$n = gp_users_norm($name);
	return gp_users_mutate(function ($users) use ($actor, $n) {
		if (!isset($users[$n])) { return array('error' => 'usr_err_unknown'); }
		if ($n === gp_users_norm($actor)) { return array('error' => 'usr_err_self'); }
		$old = gp_users_public($users[$n]);
		unset($users[$n]);
		if (gp_users_enabled_admins($users) < 1) { return array('error' => 'usr_err_last_admin'); }
		return array('users' => $users, 'audit' => array(gp_users_audit_row('user_delete', $actor, $n, $old, null)));
	});
}

// A user changes their OWN password (current password required). Returns array(ok, error key, new session_version).
// Other sessions of the user end (the version moves); the caller reissues the cookie for the current one.
function gp_users_change_own_password($name, $current, $new) {
	$n = gp_users_norm($name);
	$u = gp_users_find($n);
	if ($u === null) { return array(false, 'usr_err_unknown', 0); }
	if (!is_string($current) || !password_verify($current, $u['password_hash'])) { return array(false, 'usr_err_current', 0); }
	$pw = gp_users_check_password($new, $n);
	if ($pw !== '') { return array(false, $pw, 0); }
	$hash = password_hash($new, PASSWORD_DEFAULT);
	$ver = 0;
	$r = gp_users_mutate(function ($users) use ($n, $hash, &$ver) {
		if (!isset($users[$n])) { return array('error' => 'usr_err_unknown'); }
		$users[$n]['password_hash'] = $hash;
		$users[$n]['updated_at'] = time();
		$users[$n]['session_version']++;
		$ver = $users[$n]['session_version'];
		return array('users' => $users, 'audit' => array(gp_users_audit_row('user_password_change', $n, $n, null, array('password' => 'changed'))));
	});
	return array($r[0], $r[1], $ver);
}

// Last login time and address (best effort: a failed write never blocks a login).
function gp_users_record_login($name, $ip) {
	$n = gp_users_norm($name);
	$st = gp_users_state();
	if (!$st['ok'] || $st['readonly']) { return; }
	gp_users_write_locked(function ($users) use ($n, $ip) {
		if (!isset($users[$n])) { return null; }
		$users[$n]['last_login_at'] = time();
		$users[$n]['last_login_ip'] = substr((string)$ip, 0, 64);
		return array('users' => $users);
	});
	gp_users_state(true);
}

// Shell recovery (panel/setpass.php): create an ADMIN or reset an existing account, enable it, make it an admin and end its
// sessions. Works when nobody can log in, also when users.json is missing; refuses a corrupt store (the file is left alone).
// Returns array(ok, 'created' | 'reset' | error key).
function gp_users_cli_admin($name, $password, $by = 'setpass') {
	$n = gp_users_norm($name);
	if (!gp_users_valid_name($n)) { return array(false, 'usr_err_name'); }
	$pw = gp_users_check_password($password, $n);
	if ($pw !== '') { return array(false, $pw); }
	$hash = password_hash($password, PASSWORD_DEFAULT);
	$what = 'created';
	$r = gp_users_write_locked(function ($users) use ($n, $hash, $by, &$what) {
		if (isset($users[$n])) {
			$what = 'reset';
			$users[$n]['password_hash'] = $hash;
			$users[$n]['role'] = 'admin';
			$users[$n]['enabled'] = true;
			$users[$n]['updated_at'] = time();
			$users[$n]['session_version']++;
		} else {
			$users[$n] = gp_users_record($n, 'admin', $hash, $by);
		}
		return array('users' => $users);
	});
	if ($r === false) { return array(false, 'usr_err_write'); }
	if (!$r['ok']) { return array(false, $r['error']); }
	gp_users_state(true);
	gp_audit_append(gp_users_audit_row('user_cli_admin', $by, $n, null, array('result' => $what)));
	return array(true, $what);
}

function gp_users_role_label($role) {
	$key = 'role_' . $role;
	$t = function_exists('gp_t') ? gp_t($key) : $key;
	return $t === $key ? $role : $t;
}
