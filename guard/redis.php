<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }

// Minimal Redis client: raw TCP socket, RESP protocol, no extension required.
// Every failure path returns false. A false connection means degraded mode
// (counters disabled) and never a bypass of the guard.

// Serialize one command as a RESP array of bulk strings. Pure function.
function gv_resp_encode(array $args) {
	$out = '*' . count($args) . "\r\n";
	foreach ($args as $a) {
		$a = (string)$a;
		$out .= '$' . strlen($a) . "\r\n" . $a . "\r\n";
	}
	return $out;
}

// Open a socket to Redis. Returns a stream resource or false. Never throws.
function gv_redis_connect($cfg) {
	if (!is_array($cfg)) { return false; }
	$host = isset($cfg['host']) ? (string)$cfg['host'] : '127.0.0.1';
	$port = isset($cfg['port']) ? (int)$cfg['port'] : 6379;
	$to   = isset($cfg['timeout']) ? (float)$cfg['timeout'] : 0.05;
	if ($to <= 0) { $to = 0.05; }
	$errno  = 0;
	$errstr = '';
	$conn = @stream_socket_client('tcp://' . $host . ':' . $port, $errno, $errstr, $to, STREAM_CLIENT_CONNECT);
	if (!$conn) { return false; }
	$sec  = (int)$to;
	$usec = (int)round(($to - $sec) * 1000000);
	@stream_set_timeout($conn, $sec, $usec);
	return $conn;
}

// Send one command and read exactly one reply.
// Returns string (simple/bulk), int (integer), null (null bulk) or false (error).
function gv_redis_cmd($conn, array $args) {
	if (!$conn || !is_resource($conn)) { return false; }
	$payload = gv_resp_encode($args);
	$written = @fwrite($conn, $payload);
	if ($written === false || $written < strlen($payload)) { return false; }
	$line = @fgets($conn);
	if ($line === false || $line === '') { return false; }
	$line = rtrim($line, "\r\n");
	if ($line === '') { return false; }
	$type = substr($line, 0, 1);
	$body = substr($line, 1);
	if ($type === '+') { return $body; }
	if ($type === '-') { return false; }
	if ($type === ':') { return (int)$body; }
	if ($type === '$') {
		$len = (int)$body;
		if ($len < 0) { return null; }
		$need = $len + 2;                     // payload plus trailing CRLF
		$data = '';
		while (strlen($data) < $need) {
			$chunk = @fread($conn, $need - strlen($data));
			if ($chunk === false || $chunk === '') { return false; }
			$data .= $chunk;
		}
		return substr($data, 0, $len);
	}
	return false;
}

// Close a connection opened by gv_redis_connect(). Safe with false.
function gv_redis_close($conn) {
	if ($conn && is_resource($conn)) { @fclose($conn); }
}

function gv_r_get($conn, $key) {
	return gv_redis_cmd($conn, array('GET', $key));
}

function gv_r_setex($conn, $key, $ttl, $value) {
	return gv_redis_cmd($conn, array('SETEX', $key, (string)(int)$ttl, (string)$value));
}

function gv_r_incr($conn, $key) {
	return gv_redis_cmd($conn, array('INCR', $key));
}

function gv_r_expire($conn, $key, $ttl) {
	return gv_redis_cmd($conn, array('EXPIRE', $key, (string)(int)$ttl));
}

// SET key value EX ttl NX. Sets value and expiry in one atomic command, so the
// key can never exist without a TTL. Returns 'OK' when the key was created,
// null when it already existed, false on error.
function gv_r_set_nx_ex($conn, $key, $ttl, $value) {
	return gv_redis_cmd($conn, array('SET', $key, (string)$value,
		'EX', (string)(int)$ttl, 'NX'));
}
