<?php
// Bot Guard universal entry — safe to prepend to any PHP application.
if (defined('GV_BOOT')) { return; }
if (PHP_SAPI === 'cli') { return; }
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
