<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }

// Response outcome capture.
//
// This is the only guard code that runs AFTER the host application, so it is
// held to a stricter rule than anything else here: it may never alter the
// response. The shutdown callback emits no bytes, sends no header, sets no
// cookie, starts no buffer, never exits, and swallows every Throwable. It does
// exactly one thing - append one short line to a file.
//
// Three traps worth knowing about, each of which is a documented limitation
// rather than something to chase:
//
// 1. register_shutdown_function runs on fatal errors too, which is precisely
//    what makes it the right hook: a request that fataled is itself a signal.
//    It does NOT run on SIGKILL, an OOM kill, or a hard server timeout. Those
//    requests simply have no outcome line, and the analyzer treats a missing
//    outcome as unknown rather than as an error.
//
// 2. If the application calls fastcgi_finish_request(), the callback runs after
//    the client already holds the complete response. That is ideal: the capture
//    then costs the visitor nothing at all.
//
// 3. http_response_code() returns what PHP knows. A status the web server
//    substitutes afterwards - a 304 from its own cache validation, an error
//    page it generates itself - is invisible here.
//
// Response bytes are read from the DECLARED Content-Length header and are null
// when the application did not declare one. Buffering the response to measure
// it would break streaming and downloads, double the memory of large pages, and
// collide with the host application's own buffering. Partial coverage of a safe
// signal beats full coverage of a dangerous one, which is why outcome_cov
// exists as a feature: the model learns how much to trust the rest.

require_once __DIR__ . '/log.php';

// Correlation id shared by the decision line and the outcome line.
function gv_rid() {
	return bin2hex(random_bytes(6));
}

// Declared response size, or null. Never guesses: an absent, malformed or
// duplicated Content-Length yields null rather than an invented number.
function gv_declared_length() {
	if (!function_exists('headers_list')) { return null; }
	$headers = @headers_list();
	if (!is_array($headers)) { return null; }
	$found = null;
	foreach ($headers as $header) {
		$pos = strpos($header, ':');
		if ($pos === false) { continue; }
		if (strcasecmp(trim(substr($header, 0, $pos)), 'Content-Length') !== 0) { continue; }
		$value = trim(substr($header, $pos + 1));
		if ($value === '' || !ctype_digit($value)) { return null; }
		$found = (int)$value;
	}
	return $found;
}

// Total request duration in milliseconds, or null when the SAPI did not record
// a start time.
function gv_request_ms() {
	if (!isset($_SERVER['REQUEST_TIME_FLOAT'])) { return null; }
	$start = (float)$_SERVER['REQUEST_TIME_FLOAT'];
	if ($start <= 0) { return null; }
	return round((microtime(true) - $start) * 1000, 1);
}

// Register the shutdown callback. Values are captured BY VALUE so the closure
// cannot observe or alter anything the application changed after this point.
function gv_capture_outcome($rid, $log_dir) {
	$rid = (string)$rid;
	$log_dir = (string)$log_dir;
	if ($rid === '' || $log_dir === '') { return; }
	register_shutdown_function(function () use ($rid, $log_dir) {
		try {
			$row = array(
				'o'   => 1,
				'rid' => $rid,
				'st'  => (int)http_response_code(),
				'by'  => gv_declared_length(),
				'dur' => gv_request_ms(),
				'ts'  => round(microtime(true), 3),
			);
			gv_log_outcome($row, $log_dir);
		} catch (\Throwable $e) {
			// the guard may fail, the response may not
		}
	});
}
