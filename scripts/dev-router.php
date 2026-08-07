<?php
// Development router for the PHP built-in server:
//
//   php -S 127.0.0.1:8080 scripts/dev-router.php
//
// Every request passes through the full guard first, so the whole flow can be
// exercised without any host platform. Test use only.
putenv('GV_CONFIG=' . __DIR__ . '/config.dev.php');
require __DIR__ . '/../prepend.php';

// Reached only when the guard allowed the request.
if (!headers_sent()) {
	header('Content-Type: text/html; charset=utf-8');
	header('Cache-Control: no-store');
}
echo "<!doctype html>\n";
echo "<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Bot Guard dev server</title></head>\n";
echo "<body>OK</body></html>\n";
