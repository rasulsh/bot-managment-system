<?php
// Development router for the PHP built-in server:
//
//   php -S 127.0.0.1:8080 scripts/dev-router.php
//
// Every request passes through the full guard first, so the whole flow can be
// exercised without any host platform. Test use only.
putenv('GV_CONFIG=' . __DIR__ . '/config.dev.php');
require __DIR__ . '/../prepend.php';

// Reached only when the guard allowed the request. Everything below stands in
// for the host application, and the outcome-capture tests compare its bytes and
// headers with capture on and off - so nothing here may depend on the guard.
$gv_path = parse_url(isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/', PHP_URL_PATH);
if (!is_string($gv_path)) { $gv_path = '/'; }

switch ($gv_path) {
	case '/t/404':
		// A real application 404: the status the guard never sees today.
		http_response_code(404);
		header('Content-Type: text/html; charset=utf-8');
		echo "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
			. "<title>Not Found</title></head><body>Not Found</body></html>\n";
		return;

	case '/t/500':
		http_response_code(500);
		header('Content-Type: text/html; charset=utf-8');
		echo "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
			. "<title>Server Error</title></head><body>Server Error</body></html>\n";
		return;

	case '/t/big':
		// A body large enough that any accidental buffering would show up, with
		// a declared Content-Length so gv_declared_length has something to read.
		$gv_body = str_repeat("0123456789abcdef", 8192);   // 128 KiB
		header('Content-Type: text/plain; charset=utf-8');
		header('Content-Length: ' . strlen($gv_body));
		echo $gv_body;
		return;

	case '/t/headers':
		// Custom headers the capture must leave exactly as the application set
		// them, including one the guard itself also uses.
		header('Content-Type: application/json; charset=utf-8');
		header('X-App-Header: application-value');
		header('X-Another: second-value');
		header('Cache-Control: private, max-age=17');
		echo "{\"ok\":true}\n";
		return;

	case '/t/fatal':
		// A fatal error. register_shutdown_function still runs, which is the
		// point: a request that fataled is itself a signal.
		header('Content-Type: text/plain; charset=utf-8');
		echo "before fatal\n";
		gv_this_function_does_not_exist();
		return;

	case '/t/nolength':
		// No declared Content-Length: 'by' must come back null, never guessed.
		header('Content-Type: text/plain; charset=utf-8');
		echo "no declared length\n";
		return;
}

if (!headers_sent()) {
	header('Content-Type: text/html; charset=utf-8');
	header('Cache-Control: no-store');
}
echo "<!doctype html>\n";
echo "<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Bot Guard dev server</title></head>\n";
echo "<body>OK</body></html>\n";
