<?php
// Prints the secret values of this install, one per line, for scripts/lib-jobstatus.sh to redact
// from job error text before it is written to logs/jobs-errors.log or the job status.
// Values only (secret, holdout_salt, Redis password, the panel's password hash and session
// secret). Never run it by hand into a terminal log; it is read through a pipe by the wrapper.
if (!(PHP_SAPI === 'cli' || (strncmp(PHP_SAPI, 'cgi', 3) === 0 && !isset($_SERVER['REQUEST_METHOD']) && !isset($_SERVER['REMOTE_ADDR'])))) { exit; }   // the CLI, or a CGI php run from a shell
define('GV_BOOT', 1);
define('GV_NO_AUTORUN', 1);
$out = array();
try {
	require __DIR__ . '/../guard/guard.php';
	$cfg = gv_cfg_load();
	foreach (array(isset($cfg['secret']) ? $cfg['secret'] : '', isset($cfg['holdout_salt']) ? $cfg['holdout_salt'] : '',
		isset($cfg['redis']['password']) ? $cfg['redis']['password'] : '') as $v) {
		if (is_string($v)) { $out[] = $v; }
	}
} catch (\Throwable $e) {
}
try {
	$p = __DIR__ . '/../panel/panel.config.php';
	if (is_file($p)) {
		define('GP_BOOT', 1);
		$pc = require $p;
		if (is_array($pc)) {
			foreach (array('password_hash', 'session_secret', 'password') as $k) { if (isset($pc[$k]) && is_string($pc[$k])) { $out[] = $pc[$k]; } }
		}
	}
} catch (\Throwable $e) {
}
try {
	// The panel's user store: every account's password hash is a secret too.
	$up = getenv('GV_USERS');
	$up = (is_string($up) && $up !== '') ? $up : gv_panel_data_path('users.json');
	if (is_file($up)) {
		$ud = json_decode((string)file_get_contents($up), true);
		foreach ((is_array($ud) && isset($ud['users']) && is_array($ud['users'])) ? $ud['users'] : array() as $uu) {
			if (is_array($uu) && isset($uu['password_hash']) && is_string($uu['password_hash'])) { $out[] = $uu['password_hash']; }
		}
	}
} catch (\Throwable $e) {
}
foreach (array_unique($out) as $v) {
	if (strlen($v) >= 6 && $v !== 'CHANGE_ME' && $v !== 'CHANGE_ME_TOO' && strpos($v, "\n") === false) { echo $v, "\n"; }
}
