<?php
// Print the guard's EFFECTIVE configuration as JSON, for the Python analyzer.
//
//   php scripts/config-dump.php
//   php scripts/config-dump.php --config /full/path/to/config.php
//   php scripts/config-dump.php --redis-credentials     (analyzer bridge only)
//
// The config is loaded through the guard's own gv_cfg_load()/gv_cfg_defaults(),
// so the dump reflects the shipped defaults and the forced-monitor rule exactly
// as the guard sees them. This is what lets the analyzer tune against the
// thresholds actually in force instead of a copy that drifted.
//
// secret and holdout_salt are removed unconditionally. There is no flag to
// print them: this output is meant to be piped, logged and pasted into issues.
// redis.password and redis.username are removed by default for the same reason.
// The ONE exception is --redis-credentials, which prints nothing but the redis
// block (credentials included) for analyzer/bridge.py to read over a pipe so
// the analyzer connects with the same settings as the guard. It is not meant
// to be run by hand, logged or captured.
if (PHP_SAPI !== 'cli') { exit; }
if (PHP_VERSION_ID < 80000) { fwrite(STDERR, 'Bot Guard requires PHP 8.0 or newer (found ' . PHP_VERSION . ").\n"); exit(1); }

define('GV_BOOT', 1);

$gv_argv   = isset($argv) && is_array($argv) ? $argv : array();
$gv_config = '';
$gv_creds  = false;
for ($i = 1; $i < count($gv_argv); $i++) {
	if ($gv_argv[$i] === '--config' && isset($gv_argv[$i + 1])) {
		$gv_config = (string)$gv_argv[$i + 1];
		$i++;
	} elseif (strncmp($gv_argv[$i], '--config=', 9) === 0) {
		$gv_config = substr($gv_argv[$i], 9);
	} elseif ($gv_argv[$i] === '--redis-credentials') {
		$gv_creds = true;
	} elseif ($gv_argv[$i] === '--help' || $gv_argv[$i] === '-h') {
		fwrite(STDERR, "Usage: php scripts/config-dump.php [--config /path/to/config.php] [--redis-credentials]\n");
		exit(0);
	}
}

if ($gv_config !== '') {
	if (!is_file($gv_config)) {
		fwrite(STDERR, 'ERROR: config file not found: ' . $gv_config . "\n");
		exit(2);
	}
	putenv('GV_CONFIG=' . $gv_config);
}

require __DIR__ . '/../guard/guard.php';

$gv_cfg = gv_cfg_load();

// Strip the secrets. unset() rather than masking: a masked value still leaks
// its length, and nothing downstream has any use for any of these keys.
// panel_* is stripped defensively - the panel keeps its credentials in
// panel/panel.config.php and they can never reach the guard config, but an
// operator who pastes something into the wrong file should not publish a hash.
if ($gv_creds) {
	$gv_cfg = array('redis' => isset($gv_cfg['redis']) && is_array($gv_cfg['redis']) ? $gv_cfg['redis'] : array());
} else {
	if (isset($gv_cfg['redis']) && is_array($gv_cfg['redis'])) {
		unset($gv_cfg['redis']['password'], $gv_cfg['redis']['username']);
	}
}
unset($gv_cfg['secret'], $gv_cfg['holdout_salt'],
	$gv_cfg['panel'], $gv_cfg['panel_password_hash'], $gv_cfg['panel_session_secret'],
	$gv_cfg['password_hash'], $gv_cfg['session_secret']);

$gv_flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
if (defined('JSON_PRETTY_PRINT')) { $gv_flags |= JSON_PRETTY_PRINT; }
$gv_json = json_encode($gv_cfg, $gv_flags);
if ($gv_json === false) {
	fwrite(STDERR, "ERROR: could not encode the configuration as JSON\n");
	exit(2);
}
echo $gv_json . "\n";
