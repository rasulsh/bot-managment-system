<?php
// Bot Guard universal entry — safe to prepend to any PHP application.
if (defined('GV_BOOT')) { return; }
if (PHP_SAPI === 'cli') { return; }
// Bot Guard needs PHP 8.0+. On anything older the host application simply runs
// unguarded (fail-open); leave one throttled note where the operator will look.
if (PHP_VERSION_ID < 80000) {
	$gv_marker = __DIR__ . '/logs/.err-php_too_old';
	if (!is_file($gv_marker) || (time() - (int)@filemtime($gv_marker)) > 3600) {
		@touch($gv_marker);
		@file_put_contents(__DIR__ . '/logs/guard-errors.log',
			date('c') . ' php_too_old Bot Guard needs PHP 8.0+, found ' . PHP_VERSION . "; the guard is not running\n",
			FILE_APPEND);
	}
	return;
}
if (is_file(__DIR__ . '/guard.off')) { return; }
define('GV_BOOT', 1);
try {
	require __DIR__ . '/guard/guard.php';
} catch (\Throwable $e) {
	// fail-open: never break the host application, but leave a trace when the
	// error logger itself was loaded.
	if (function_exists('gv_errlog')) {
		gv_errlog('prepend_exception', get_class($e) . ': ' . $e->getMessage()
			. ' @ ' . basename($e->getFile()) . ':' . $e->getLine());
	}
}
