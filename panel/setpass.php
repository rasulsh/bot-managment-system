<?php
// Credential setup and admin recovery for the admin panel (shell only).
//
//   php panel/setpass.php
//
// First run: creates panel/panel.config.php (install settings: session secret, IP allowlist, trusted proxies) and the first
// ADMINISTRATOR account in panel/users.json.
//
// Later runs (recovery, also when nobody can sign in): create a new administrator, or reset an existing account - set a new
// password, make it an administrator, re-enable it and end its sessions. Other accounts and their sessions are not touched.
// Optionally every session is logged out (a new session secret). A damaged users.json can be moved aside and replaced.
//
// There is no web-based setup wizard on purpose: a first-run screen reachable by whoever finds the URL first is how admin
// panels get taken over. Until panel.config.php exists, every panel route returns a bare 404.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
if (PHP_VERSION_ID < 80000) { fwrite(STDERR, 'Bot Guard requires PHP 8.0 or newer (found ' . PHP_VERSION . ").\n"); exit(1); }

define('GP_BOOT', 1);
define('GP_MIN_PASSWORD', 12);
require_once __DIR__ . '/config_io.php';
require_once __DIR__ . '/auth.php';          // loads users.php: the user store

$gp_target = __DIR__ . '/panel.config.php';

function gp_prompt($label) {
	fwrite(STDOUT, $label);
	$line = fgets(STDIN);
	return $line === false ? '' : trim($line);
}

// Read without echoing where the SAPI allows it.
//
// Turning terminal echo off normally means running `stty`, and no file under
// panel/ is permitted to execute a shell command - so this uses the readline
// extension when it is present and otherwise warns that the password will be
// visible. Warning is better than either shelling out or refusing to install.
function gp_prompt_hidden($label) {
	if (function_exists('readline_callback_handler_install')
		&& function_exists('readline_callback_handler_remove')) {
		fwrite(STDOUT, $label);
		$value = '';
		readline_callback_handler_install('', function () {});
		while (true) {
			// KNOWN FRAGILITY (#22): mixing readline_callback_handler_install with
			// raw stream_get_contents(STDIN, 1) reads is build-dependent and may
			// misbehave on some readline builds. It is left as is because this is
			// interactive one-time setup with a working visible fallback below;
			// the robust alternative, if it ever needs hardening, is to read with
			// readline_callback_read_char() here - but only after verifying it on
			// the target readline-enabled build.
			$char = stream_get_contents(STDIN, 1);
			if ($char === "\n" || $char === "\r" || $char === '' || $char === false) { break; }
			if ($char === chr(127) || $char === chr(8)) {
				$value = substr($value, 0, -1);
				continue;
			}
			$value .= $char;
		}
		readline_callback_handler_remove();
		fwrite(STDOUT, "\n");
		return $value;
	}
	fwrite(STDOUT, "NOTE: the readline extension is not available, so what you type\n"
		. "      below will be visible. Clear your shell history afterwards.\n");
	fwrite(STDOUT, $label);
	return trim((string)fgets(STDIN));
}

fwrite(STDOUT, "Bot Guard admin panel - administrator setup and recovery\n");
fwrite(STDOUT, "---------------------------------------------------------\n");

$gp_exists = is_file($gp_target);
if ($gp_exists) {
	fwrite(STDOUT, "A panel configuration already exists at:\n  " . $gp_target . "\n");
	$answer = gp_prompt("Create an administrator, or reset an existing account? [y/N]: ");
	if (strtolower($answer) !== 'y') {
		fwrite(STDOUT, "Cancelled. Nothing was written.\n");
		exit(0);
	}
	// A store that does not exist yet is created from panel.config.php first, so a reset never drops the migrated user.
	$st = gp_users_state(true);
	if (!$st['ok'] && $st['error'] !== 'missing') {
		fwrite(STDOUT, "panel/users.json exists but cannot be read as a user store (" . $st['error'] . ").\n");
		$answer = gp_prompt("Move it aside and start a new store with the administrator you enter now? [y/N]: ");
		if (strtolower($answer) !== 'y') {
			fwrite(STDERR, "Nothing was changed. Repair or move panel/users.json yourself, then run this again.\n");
			exit(2);
		}
		$aside = gp_users_path() . '.bad-' . date('Ymd-His');
		if (!@rename(gp_users_path(), $aside)) { fwrite(STDERR, "ERROR: could not move " . gp_users_path() . " aside.\n"); exit(2); }
		fwrite(STDOUT, "Moved to " . $aside . "\n");
	}
}

$username = strtolower(gp_prompt("Username (3-32 characters: a-z, 0-9, '.', '_', '-'): "));
if (!gp_users_valid_name($username)) {
	fwrite(STDERR, "ERROR: the username must be 3 to 32 characters: lowercase letters, digits, '.', '_' or '-'.\n");
	exit(2);
}
$password = gp_prompt_hidden("Password (at least " . GP_MIN_PASSWORD . " characters): ");
$why = gp_users_check_password($password, $username);
if ($why !== '') {
	fwrite(STDERR, "ERROR: the password must be at least " . GP_MIN_PASSWORD
		. " characters and not the username. This panel can change enforcement for the whole site. Nothing was written.\n");
	exit(2);
}
$confirm = gp_prompt_hidden("Repeat the password: ");
if (!hash_equals($password, $confirm)) {
	fwrite(STDERR, "ERROR: the two passwords do not match. Nothing was written.\n");
	exit(2);
}
$rotate = false;
if ($gp_exists) {
	$rotate = (strtolower(gp_prompt("Also log out EVERY session, all users (new session secret)? [y/N]: ")) === 'y');
}

// panel.config.php holds the install settings. On the first run it is created; later it is kept (the address lists are settings
// the operator wrote by hand), and the session secret changes only when asked. Its username and password_hash are kept in step
// with the account of the same name, so the previous panel code (a rollback) still signs that account in.
$gp_old = array();
if ($gp_exists) {
	$gp_old = @include $gp_target;
	if (!is_array($gp_old)) { $gp_old = array(); }
}
$config = array(
	'username'       => $gp_exists && isset($gp_old['username']) && $gp_old['username'] !== $username ? $gp_old['username'] : $username,
	'password_hash'  => $gp_exists && isset($gp_old['username']) && $gp_old['username'] !== $username && isset($gp_old['password_hash']) ? $gp_old['password_hash'] : password_hash($password, PASSWORD_DEFAULT),
	// Distinct from the guard's secret on purpose: a panel session forgery must
	// not become a guard token forgery, and rotating one must not touch the other.
	'session_secret' => ($gp_exists && !$rotate && isset($gp_old['session_secret']) && is_string($gp_old['session_secret']) && strlen($gp_old['session_secret']) >= 32) ? $gp_old['session_secret'] : bin2hex(random_bytes(32)),
	'session_ttl'    => isset($gp_old['session_ttl']) && is_int($gp_old['session_ttl']) ? $gp_old['session_ttl'] : 43200,
	'ip_allowlist'   => isset($gp_old['ip_allowlist']) ? $gp_old['ip_allowlist'] : array(),
	'trusted_proxies' => isset($gp_old['trusted_proxies']) ? $gp_old['trusted_proxies'] : array(),
);

$r = gp_users_cli_admin($username, $password, 'setpass');
if (!$r[0]) {
	fwrite(STDERR, "ERROR: the account could not be written (" . $r[1] . "). Is panel/ writable by you? Nothing else was changed.\n");
	exit(2);
}

// The emitted file carries the same direct-access guard every other file under
// panel/ has: it holds the session secret, so if a server ever serves .php as text
// - a broken handler, a stray editor backup - it needs a second line of defence
// behind .htaccess and mode 0600. index.php defines GP_BOOT before gp_panel_config()
// requires this, and the panel self-test defines it too.
$body = "<?php\n"
	. "// Bot Guard admin panel install settings. Written by panel/setpass.php.\n"
	. "// NEVER commit this file. The accounts live in panel/users.json (Users page); username and\n"
	. "// password_hash here are only kept so that an older panel version still signs the first account in.\n"
	. "// ip_allowlist: who may open the panel. Single IPv4/IPv6 addresses or CIDR ranges,\n"
	. "//   e.g. array('203.0.113.7', '198.51.100.0/24', '2001:db8::/32').\n"
	. "//   Empty = no IP restriction (the login still applies). If the list is not\n"
	. "//   empty but nothing in it is valid, nobody can open the panel.\n"
	. "// trusted_proxies: addresses of your own reverse proxy / load balancer / CDN. Only a\n"
	. "//   request that arrives FROM one of these may name the client in X-Forwarded-For.\n"
	. "//   Leave empty unless the panel really is behind a proxy.\n"
	. "if (!defined('GP_BOOT')) { http_response_code(404); exit; }\n"
	. "return " . var_export($config, true) . ";\n";

$tmp = $gp_target . '.tmp' . bin2hex(random_bytes(4));
if (@file_put_contents($tmp, $body, LOCK_EX) === false) {
	fwrite(STDERR, "ERROR: could not write to " . dirname($gp_target) . "\n");
	@unlink($tmp);
	exit(2);
}
@chmod($tmp, 0600);
if (!@rename($tmp, $gp_target)) {
	fwrite(STDERR, "ERROR: could not move the new configuration into place.\n");
	@unlink($tmp);
	exit(2);
}
@chmod($gp_target, 0600);

fwrite(STDOUT, "\nAdministrator '" . $username . "' " . ($r[1] === 'created' ? 'created' : 'reset (enabled, role administrator, sessions ended)') . " in " . gp_users_path() . ".\n");
fwrite(STDOUT, "Wrote " . $gp_target . " (mode 0600)" . ($rotate ? '; every session was logged out' : '') . ".\n");
if (!$gp_exists) {
	fwrite(STDOUT, "Next steps:\n");
	fwrite(STDOUT, "  1. Add the panel path to exempt_paths in guard/config.php, so your own\n");
	fwrite(STDOUT, "     bot guard cannot challenge you out of your own admin panel.\n");
	fwrite(STDOUT, "  2. Add the snapshot and worker cron modes (see README).\n");
	fwrite(STDOUT, "  3. Open panel/index.php in a browser and sign in. More people: page Users.\n");
	if (!$config['ip_allowlist']) {
		fwrite(STDOUT, "  4. RECOMMENDED: the panel is open to every IP address. Add your own address\n"
			. "     to 'ip_allowlist' in " . $gp_target . " (IPv4, IPv6 or CIDR).\n");
	}
}
exit(0);
