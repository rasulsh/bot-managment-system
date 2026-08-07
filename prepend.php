<?php
// Bot Guard universal entry — safe to prepend to any PHP application.
if (defined('GV_BOOT')) { return; }
if (PHP_SAPI === 'cli') { return; }
if (is_file(__DIR__ . '/guard.off')) { return; }
define('GV_BOOT', 1);
try {
	require __DIR__ . '/guard/guard.php';
} catch (\Throwable $e) {
	// fail-open: never break the host application
}
