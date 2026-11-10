<?php
// Test helper for scripts/guard-test.sh. Prints "<device_id> <token>" for an
// identity that is inside the holdout under scripts/config.dev.php, or with
// --outside for one that is not.
//
// This only works because config.dev.php publishes its secret, which is the
// whole reason that file must never be deployed. There is no way to mint a
// token for a chosen device id against a real configuration.
if (PHP_SAPI !== 'cli') { exit; }
if (PHP_VERSION_ID < 80000) { fwrite(STDERR, 'Bot Guard requires PHP 8.0 or newer (found ' . PHP_VERSION . ").\n"); exit(1); }

define('GV_BOOT', 1);
putenv('GV_CONFIG=' . __DIR__ . '/config.dev.php');
require __DIR__ . '/../guard/guard.php';

$gv_want_inside = true;
if (isset($argv) && is_array($argv)) {
	foreach ($argv as $gv_a) {
		if ($gv_a === '--outside') { $gv_want_inside = false; }
	}
}

$gv_cfg = gv_cfg_load();
if ((int)$gv_cfg['holdout_pct'] <= 0) {
	fwrite(STDERR, "holdout_pct is 0 in the dev config; nothing to probe\n");
	exit(1);
}

for ($gv_i = 0; $gv_i < 200000; $gv_i++) {
	$gv_dev = substr(md5('holdout-probe-' . $gv_i), 0, 24);
	$gv_in = gv_is_holdout($gv_dev, $gv_cfg['holdout_salt'], $gv_cfg['holdout_pct']);
	if ($gv_in !== $gv_want_inside) { continue; }
	$gv_payload = $gv_dev . '.' . time();
	$gv_token = $gv_payload . '.' . hash_hmac('sha256', $gv_payload, $gv_cfg['secret']);
	echo $gv_dev . ' ' . $gv_token . "\n";
	exit(0);
}

fwrite(STDERR, "could not find a matching identity\n");
exit(1);
