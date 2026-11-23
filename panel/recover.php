<?php
// Bot Guard updater - web recovery entry (kept tiny on purpose).
//
// The only job of this file is to hand a request to the recovery scripts the updater
// wrote into updates/ BEFORE the last update (updates/rollback.php, updates/verify.php).
// Those scripts need a one-time token; without a valid one this file answers a bare,
// empty 404 and reveals nothing. It does not load the panel, the guard or any other
// file of the new version, so it still works when the new code is broken.
if (PHP_SAPI === 'cli') { exit; }
$gp_rc_dir = dirname(__DIR__) . '/updates';
$gp_rc_script = ((isset($_GET['a']) && $_GET['a'] === 'verify') ? 'verify' : 'rollback') . '.php';
if (!is_file($gp_rc_dir . '/' . $gp_rc_script)) {
	http_response_code(404);
	header('Content-Type: text/plain; charset=utf-8');
	header('Cache-Control: no-store');
	header('X-LiteSpeed-Cache-Control: no-cache');
	exit;
}
define('GP_RECOVER_WEB', 1);
require $gp_rc_dir . '/' . $gp_rc_script;
