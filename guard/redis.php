<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }

// Minimal Redis client: raw socket, RESP protocol, no extension required.
//
// Failure model (the whole point of this file):
//   * Every failure returns false. A false connection means degraded mode
//     (counters disabled) and never a bypass of the guard.
//   * Fail-fast. The first transport failure (connect error, write error, read
//     timeout, malformed reply, authentication refused) CLOSES the connection.
//     Every later call in the request sees a dead connection and is a no-op.
//     That bounds the worst case to ONE timeout per request, and it removes the
//     reply-desync hazard: a late reply to a timed-out command can never be
//     read as the answer to the next command, because the socket is gone.
//   * Circuit breaker. After a transport failure a marker file is touched; for
//     breaker_ttl seconds later requests skip Redis entirely instead of each
//     paying one timeout while Redis is down.
//   * An application error reply ("-ERR ...") to one command is NOT a transport
//     failure: the stream is still in sync, so it only fails that command.
//     -NOAUTH / -WRONGPASS / -NOPERM mean this connection cannot be used.

class GvRedisFail extends RuntimeException {}

// A "-ERR ..." reply kept apart from real values until the caller decides.
class GvRedisErr {
	public $msg;
	public function __construct($msg) { $this->msg = (string)$msg; }
}

// Serialize one command as a RESP array of bulk strings. Pure function.
function gv_resp_encode(array $args) {
	$out = '*' . count($args) . "\r\n";
	foreach ($args as $a) {
		$a = (string)$a;
		$out .= '$' . strlen($a) . "\r\n" . $a . "\r\n";
	}
	return $out;
}

// --------------------------------------------------------------------------
// Per-request context
// --------------------------------------------------------------------------

// log_dir/breaker_ttl: where the breaker marker and the error log live.
// rt: number of socket writes (= round trips) this request made. It is the
// test seam for "no path performs more than two round trips".
// probe: this request is the one probing a Redis the breaker had marked down.
function gv_redis_ctx($set = null) {
	static $ctx = array('log_dir' => '', 'breaker' => false, 'breaker_ttl' => 0,
		'rt' => 0, 'probe' => false);
	if (is_array($set)) { $ctx = array_merge($ctx, $set); }
	return $ctx;
}

// Round trips made so far; pass true to reset the counter (tests).
function gv_redis_rt($reset = false) {
	$n = gv_redis_ctx();
	if ($reset) { gv_redis_ctx(array('rt' => 0)); }
	return (int)$n['rt'];
}

function gv_redis_alive($conn) {
	return ($conn && is_resource($conn));
}

// --------------------------------------------------------------------------
// Key namespace
// --------------------------------------------------------------------------

// The prefix of the connection opened last (set by gv_redis_connect, validated
// there). EVERY Redis key in the project is built by gv_key() or gp_key(); a
// self-test scans the source and fails on any other 'gv:' / 'gp:' literal. With
// the default empty prefix the key names are exactly the legacy ones.
function gv_redis_prefix($set = null) {
	static $prefix = '';
	if (is_string($set)) { $prefix = $set; }
	return $prefix;
}

// Allowed prefix: letters, digits and _ . : - up to 32 characters. No glob
// characters (it goes into SCAN MATCH patterns) and no whitespace.
function gv_redis_prefix_valid($p) {
	return is_string($p) && preg_match('/^[A-Za-z0-9_.:-]{0,32}$/', $p) === 1;
}

// Verdict, counter and override keys: gv:{name}, namespaced.
function gv_key($name) {
	return gv_redis_prefix() . 'gv:' . $name;
}

// Panel keys (login limiter, job queue): gp:{name}, namespaced.
function gp_key($name) {
	return gv_redis_prefix() . 'gp:' . $name;
}

// --------------------------------------------------------------------------
// Error log and circuit breaker (best effort, silent on every failure)
// --------------------------------------------------------------------------

// Append one line to {log_dir}/guard-errors.log, at most once a minute per
// error code. The throttle is the mtime of a tiny marker file, so no APCu and
// no shared memory are needed. Messages must never contain a secret.
function gv_errlog($code, $msg = '', $log_dir = null) {
	try {
		if ($log_dir === null) {
			$c = gv_redis_ctx();
			$log_dir = $c['log_dir'];
		}
		$log_dir = rtrim((string)$log_dir, '/\\');
		// Before the config is loaded (a syntax error in it is exactly such a case) no
		// log_dir is known yet: fall back to the shipped default, next to the code.
		if ($log_dir === '') { $log_dir = dirname(__DIR__) . '/logs'; }
		if (!is_dir($log_dir)) {
			@mkdir($log_dir, 0775, true);
			if (!is_dir($log_dir)) { return; }
		}
		$code = preg_replace('/[^a-z0-9_]/', '', strtolower((string)$code));
		if ($code === '') { $code = 'unknown'; }
		$marker = $log_dir . '/.err-' . $code;
		clearstatcache(true, $marker);
		$t = @filemtime($marker);
		if ($t !== false && (time() - $t) < 60) { return; }
		@touch($marker);
		$msg = preg_replace('/[\x00-\x1f\x7f]+/', ' ', (string)$msg);
		if (strlen($msg) > 200) { $msg = substr($msg, 0, 200); }
		@file_put_contents($log_dir . '/guard-errors.log',
			date('c') . ' ' . $code . ' ' . $msg . "\n", FILE_APPEND | LOCK_EX);
	} catch (\Throwable $e) {
		// silent: the error log may fail, the site may not
	}
}

function gv_breaker_path() {
	$c = gv_redis_ctx();
	$d = rtrim((string)$c['log_dir'], '/\\');
	return $d === '' ? '' : $d . '/.redis-down';
}

// True when this request must skip Redis. One stat per healthy request.
//
// After the window expires exactly one request probes: it takes a
// non-blocking lock, re-checks the marker and refreshes its mtime BEFORE
// probing, so every concurrent request still sees a fresh marker and keeps
// skipping. No thundering herd against a Redis that may still be down. The
// marker is removed only after a command really succeeded (see
// gv_redis_pipeline), because a black-hole server accepts the connection.
function gv_breaker_skip() {
	$c = gv_redis_ctx();
	if (empty($c['breaker']) || (int)$c['breaker_ttl'] <= 0) { return false; }
	$m = gv_breaker_path();
	if ($m === '') { return false; }
	clearstatcache(true, $m);                        // the stat cache would hide a fresh marker
	$t = @filemtime($m);
	if ($t === false) { return false; }
	$ttl = (int)$c['breaker_ttl'];
	if ((time() - $t) < $ttl) { return true; }
	$fh = @fopen($m, 'c');
	if (!$fh) { return false; }                      // cannot coordinate: just probe
	$skip = true;
	if (@flock($fh, LOCK_EX | LOCK_NB)) {
		clearstatcache(true, $m);
		$t2 = @filemtime($m);
		if ($t2 === false || (time() - $t2) >= $ttl) {
			@touch($m);
			gv_redis_ctx(array('probe' => true));
			$skip = false;
		}
		@flock($fh, LOCK_UN);
	}
	@fclose($fh);
	return $skip;
}

function gv_breaker_arm() {
	$c = gv_redis_ctx();
	if (empty($c['breaker']) || (int)$c['breaker_ttl'] <= 0) { return; }
	$m = gv_breaker_path();
	if ($m === '') { return; }
	$d = dirname($m);
	if (!is_dir($d)) { @mkdir($d, 0775, true); }
	@touch($m);
}

// Close the connection and record why. $e is a GvRedisFail whose message is
// the error code, or any other Throwable (reported as redis_error).
function gv_redis_fail($conn, $e, $detail = '') {
	if ($conn && is_resource($conn)) { @fclose($conn); }
	$code = ($e instanceof GvRedisFail) ? $e->getMessage() : 'redis_error';
	gv_breaker_arm();
	gv_errlog($code, $detail);
	gv_redis_ctx(array('probe' => false));
}

// --------------------------------------------------------------------------
// Connection
// --------------------------------------------------------------------------

// Open a connection and run the AUTH/SELECT handshake. Returns a stream
// resource or false. Never throws. $log_dir locates the breaker marker and the
// error log; $breaker = false makes the call ignore the breaker (the panel
// wants the truth, not a cached "down").
function gv_redis_connect($cfg, $log_dir = '', $breaker = true) {
	try {
		return gv_redis_connect_do($cfg, $log_dir, $breaker);
	} catch (\Throwable $e) {
		return false;
	}
}

function gv_redis_connect_do($cfg, $log_dir, $breaker) {
	if (!is_array($cfg)) { return false; }
	$ttl = isset($cfg['breaker_ttl']) ? (int)$cfg['breaker_ttl'] : 5;
	$prefix = isset($cfg['prefix']) ? $cfg['prefix'] : '';
	if (!gv_redis_prefix_valid($prefix)) {
		// A configuration error, never silently altered: Redis is treated as
		// unavailable (degraded mode) and the mistake is reported.
		gv_redis_prefix('');
		gv_redis_ctx(array('log_dir' => (string)$log_dir, 'breaker' => false));
		gv_errlog('redis_prefix', 'redis.prefix is invalid (allowed: [A-Za-z0-9_.:-], max 32)');
		return false;
	}
	gv_redis_prefix($prefix);
	gv_redis_ctx(array('log_dir' => (string)$log_dir, 'breaker' => (bool)$breaker,
		'breaker_ttl' => $ttl, 'probe' => false));

	if (gv_breaker_skip()) { return false; }

	$to = isset($cfg['timeout']) ? (float)$cfg['timeout'] : 0.05;
	if ($to <= 0) { $to = 0.05; }
	$socket = isset($cfg['socket']) ? trim((string)$cfg['socket']) : '';
	if ($socket !== '') {
		$target = 'unix://' . $socket;
	} else {
		$host = isset($cfg['host']) ? (string)$cfg['host'] : '127.0.0.1';
		$port = isset($cfg['port']) ? (int)$cfg['port'] : 6379;
		$target = 'tcp://' . $host . ':' . $port;
	}
	$errno  = 0;
	$errstr = '';
	$conn = @stream_socket_client($target, $errno, $errstr, $to, STREAM_CLIENT_CONNECT);
	if (!$conn) {
		gv_redis_fail(false, new GvRedisFail('redis_connect'), $errstr . ' (' . $errno . ')');
		return false;
	}
	$sec  = (int)$to;
	$usec = (int)round(($to - $sec) * 1000000);
	@stream_set_timeout($conn, $sec, $usec);

	// Handshake: AUTH and SELECT in ONE write, so it costs at most one extra
	// round trip, and none at all with the default config (no password, db 0).
	$hand = array();
	$user = isset($cfg['username']) ? (string)$cfg['username'] : '';
	$pass = isset($cfg['password']) ? (string)$cfg['password'] : '';
	$db   = isset($cfg['db']) ? (int)$cfg['db'] : 0;
	if ($pass !== '') {
		$hand[] = ($user !== '') ? array('AUTH', $user, $pass) : array('AUTH', $pass);
	}
	if ($db > 0) { $hand[] = array('SELECT', (string)$db); }
	if ($hand) {
		try {
			$r = gv_redis_pipeline_raw($conn, $hand);
		} catch (\Throwable $e) {
			gv_redis_fail($conn, $e, 'during handshake');
			return false;
		}
		$i = 0;
		if ($pass !== '') {
			$a = $r[$i++];
			if ($a instanceof GvRedisErr) {
				// A password sent to a server that has none is harmless: keep
				// going and say so once. The wording differs by version:
				//   Redis <= 5: "ERR Client sent AUTH, but no password is set"
				//   Redis >= 6: "ERR AUTH <password> called without any password
				//                configured for the default user ..."
				if (preg_match('/no password is set|without any password/i', $a->msg)) {
					gv_errlog('redis_auth_unneeded', 'a password is configured but the server has none');
				} else {
					gv_redis_fail($conn, new GvRedisFail('redis_auth'), 'AUTH refused');
					return false;
				}
			}
		}
		if ($db > 0) {
			$s = $r[$i++];
			if ($s instanceof GvRedisErr) {
				gv_redis_fail($conn, new GvRedisFail('redis_select'), 'SELECT refused');
				return false;
			}
		}
	}
	return $conn;
}

// Close a connection. Safe with false.
function gv_redis_close($conn) {
	if ($conn && is_resource($conn)) { @fclose($conn); }
}

// --------------------------------------------------------------------------
// Protocol
// --------------------------------------------------------------------------

function gv_redis_timed_out($conn) {
	$m = @stream_get_meta_data($conn);
	return is_array($m) && !empty($m['timed_out']);
}

// Read one reply. Returns string, int, null, array or GvRedisErr; throws
// GvRedisFail on any transport problem or malformed data.
function gv_redis_read($conn, $depth = 0) {
	$line = @fgets($conn);
	if ($line === false || $line === '') {
		throw new GvRedisFail(gv_redis_timed_out($conn) ? 'redis_timeout' : 'redis_io');
	}
	$line = rtrim($line, "\r\n");
	if ($line === '') { throw new GvRedisFail('redis_proto'); }
	$type = $line[0];
	$body = substr($line, 1);
	if ($type === '+') { return $body; }
	if ($type === '-') {
		if (preg_match('/^(NOAUTH|WRONGPASS|NOPERM)\b/', $body)) {
			throw new GvRedisFail('redis_auth');
		}
		return new GvRedisErr($body);
	}
	if ($type === ':') { return (int)$body; }
	if ($type === '$') {
		$len = (int)$body;
		if ($len < 0) { return null; }
		if ($len > 16777216) { throw new GvRedisFail('redis_proto'); }
		$need = $len + 2;                     // payload plus trailing CRLF
		$data = '';
		while (strlen($data) < $need) {
			$chunk = @fread($conn, $need - strlen($data));
			if ($chunk === false || $chunk === '') {
				throw new GvRedisFail(gv_redis_timed_out($conn) ? 'redis_timeout' : 'redis_io');
			}
			$data .= $chunk;
		}
		return substr($data, 0, $len);
	}
	if ($type === '*') {
		$n = (int)$body;
		if ($n < 0) { return null; }
		if ($n > 100000 || $depth > 3) { throw new GvRedisFail('redis_proto'); }
		$out = array();
		for ($i = 0; $i < $n; $i++) { $out[] = gv_redis_read($conn, $depth + 1); }
		return $out;
	}
	throw new GvRedisFail('redis_proto');
}

// Write every command in one go, then read exactly one reply per command, in
// order. Throws GvRedisFail; error replies stay GvRedisErr values.
function gv_redis_pipeline_raw($conn, array $cmds) {
	if (!$conn || !is_resource($conn)) { throw new GvRedisFail('redis_closed'); }
	$payload = '';
	foreach ($cmds as $c) { $payload .= gv_resp_encode($c); }
	$c = gv_redis_ctx();
	gv_redis_ctx(array('rt' => (int)$c['rt'] + 1));
	$total = strlen($payload);
	$sent  = 0;
	while ($sent < $total) {
		$w = @fwrite($conn, substr($payload, $sent));
		if ($w === false || $w === 0) { throw new GvRedisFail('redis_write'); }
		$sent += $w;
	}
	$out = array();
	foreach ($cmds as $_c) { $out[] = gv_redis_read($conn); }
	return $out;
}

// Run a batch. Returns the list of replies (string/int/null/array, or false for
// a command that got an error reply), or false for the WHOLE batch when the
// transport failed - in which case the connection is already closed.
function gv_redis_pipeline($conn, array $cmds) {
	if (!$conn || !is_resource($conn)) { return false; }
	if (!$cmds) { return array(); }
	try {
		$replies = gv_redis_pipeline_raw($conn, $cmds);
	} catch (\Throwable $e) {
		gv_redis_fail($conn, $e);
		return false;
	}
	foreach ($replies as $i => $r) {
		if ($r instanceof GvRedisErr) { $replies[$i] = false; }
	}
	$c = gv_redis_ctx();
	if (!empty($c['probe'])) {
		// The breaker had marked Redis down and this request proved it is back.
		$m = gv_breaker_path();
		if ($m !== '') { @unlink($m); }
		gv_redis_ctx(array('probe' => false));
	}
	return $replies;
}

// Send one command and read exactly one reply.
// Returns string (simple/bulk), int, null (null bulk), array (multi-bulk) or
// false (error reply, or a dead connection).
function gv_redis_cmd($conn, array $args) {
	$r = gv_redis_pipeline($conn, array($args));
	if ($r === false) { return false; }
	return $r[0];
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

// The three commands that make up one fixed-window counter. Pipelined with
// others by the caller; read the result with gv_bump_result().
//   SET key 0 EX window NX   creates the key WITH its TTL, only if absent
//   INCR key                 the count (1 on the first hit, then 2, 3, ...)
//   TTL key                  -1 here means a TTL-less key (see gv_bump_result)
function gv_bump_cmds($key, $window) {
	return array(
		array('SET', $key, '0', 'EX', (string)(int)$window, 'NX'),
		array('INCR', $key),
		array('TTL', $key),
	);
}

// Interpret the three replies of gv_bump_cmds(). Returns array(count, repair)
// where repair is true when the key has no TTL and needs an EXPIRE. That can
// only happen when the key expired between SET NX and INCR: INCR then
// re-creates it with no TTL, and a counter without a TTL would 429 the
// identity forever once it crossed the limit. A failed read folds to 0.
function gv_bump_result($incr, $ttl) {
	if (!is_int($incr)) { return array(0, false); }
	return array($incr, $ttl === -1);
}
