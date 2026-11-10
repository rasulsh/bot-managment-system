<?php
// One-time credential setup for the admin panel.
//
//   php panel/setpass.php
//
// This is the only terminal command the panel requires, and only at install.
// Re-running it rotates the credentials and invalidates every existing session,
// because the session secret is regenerated too.
//
// There is no web-based setup wizard on purpose: a first-run screen reachable by
// whoever finds the URL first is how admin panels get taken over. Until this
// command has been run, every panel route returns a bare 404.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
if (PHP_VERSION_ID < 80000) { fwrite(STDERR, 'Bot Guard requires PHP 8.0 or newer (found ' . PHP_VERSION . ").\n"); exit(1); }

define('GP_MIN_PASSWORD', 12);

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

fwrite(STDOUT, "Bot Guard admin panel - credential setup\n");
fwrite(STDOUT, "----------------------------------------\n");

if (is_file($gp_target)) {
	fwrite(STDOUT, "A panel configuration already exists at:\n  " . $gp_target . "\n");
	$answer = gp_prompt("Rotate the credentials? Every session will be logged out. [y/N]: ");
	if (strtolower($answer) !== 'y') {
		fwrite(STDOUT, "Cancelled. Nothing was written.\n");
		exit(0);
	}
}

$username = gp_prompt("Username: ");
if ($username === '' || strlen($username) > 64) {
	fwrite(STDERR, "ERROR: the username must be between 1 and 64 characters.\n");
	exit(2);
}
// The session token is user.issued.hmac; a dot or whitespace in the username
// would break parsing and lock the account out. Restrict to a delimiter-safe
// charset at creation. (gp_session_check also parses defensively, but the
// cleaner guarantee is to never write a username that can collide.)
if (!preg_match('/^[A-Za-z0-9_-]+$/', $username)) {
	fwrite(STDERR, "ERROR: the username may contain only letters, digits, "
		. "'-' and '_' (no dots, spaces or other punctuation).\n");
	exit(2);
}

$password = gp_prompt_hidden("Password (at least " . GP_MIN_PASSWORD . " characters): ");
if (strlen($password) < GP_MIN_PASSWORD) {
	fwrite(STDERR, "ERROR: the password must be at least " . GP_MIN_PASSWORD
		. " characters. This panel can change enforcement for the whole site.\n");
	exit(2);
}
$confirm = gp_prompt_hidden("Repeat the password: ");
if (!hash_equals($password, $confirm)) {
	fwrite(STDERR, "ERROR: the two passwords do not match. Nothing was written.\n");
	exit(2);
}

$config = array(
	'username'       => $username,
	'password_hash'  => password_hash($password, PASSWORD_DEFAULT),
	// Distinct from the guard's secret on purpose: a panel session forgery must
	// not become a guard token forgery, and rotating one must not touch the other.
	'session_secret' => bin2hex(random_bytes(32)),
	'session_ttl'    => 43200,
	'ip_allowlist'   => array(),
);

// The emitted file carries the same direct-access guard every other file under
// panel/ has. It was the one that did not, and it is the one that matters most:
// it holds the password hash and the session secret, so if a server ever serves
// .php as text - a broken handler, a stray editor backup - this file had no
// second line of defence behind .htaccess and mode 0600. index.php defines
// GP_BOOT at line 8, before gp_panel_config() ever requires this, and the panel
// self-test defines it too, so nothing legitimate is locked out.
$body = "<?php\n"
	. "// Bot Guard admin panel credentials. Written by panel/setpass.php.\n"
	. "// NEVER commit this file. Re-run setpass.php to rotate.\n"
	. "// ip_allowlist takes IPv4 CIDRs, e.g. array('203.0.113.0/24'); empty disables it.\n"
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

fwrite(STDOUT, "\nWrote " . $gp_target . " (mode 0600).\n");
fwrite(STDOUT, "Next steps:\n");
fwrite(STDOUT, "  1. Add the panel path to exempt_paths in guard/config.php, so your own\n");
fwrite(STDOUT, "     bot guard cannot challenge you out of your own admin panel.\n");
fwrite(STDOUT, "  2. Add the snapshot and worker cron modes (see README).\n");
fwrite(STDOUT, "  3. Open panel/index.php in a browser and sign in.\n");
exit(0);
