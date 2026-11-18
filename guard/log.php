<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }

// JSONL logger: one line per handled request, one file per day.
// Every failure is silent - logging must never affect the host application.

// Truncate to a character count without breaking multi-byte sequences.
function gv_cut($s, $max) {
	$s = (string)$s;
	if (function_exists('mb_substr')) {
		return mb_substr($s, 0, $max, 'UTF-8');
	}
	return substr($s, 0, $max);
}

// Per-request write policy, set once by gv_run():
//   skip      the request path is in log_skip_paths: write nothing for it
//   min_free  MiB that must stay free on the log disk (0 = no check)
// Outside a request (tests, panel, CLI) the default writes everything.
function gv_log_policy($set = null) {
	static $policy = array('skip' => false, 'min_free' => 0);
	if (is_array($set)) { $policy = array_merge($policy, $set); }
	return $policy;
}

// May a line be written to $log_dir now? False for a skipped path, and while
// the disk is below the free-space floor. Below the floor the guard keeps
// deciding and the site keeps answering; only logging pauses, with a throttled
// note in guard-errors.log. disk_free_space() is one statfs() call.
function gv_log_allowed($log_dir) {
	$p = gv_log_policy();
	if (!empty($p['skip'])) { return false; }
	if ((int)$p['min_free'] > 0) {
		$free = @disk_free_space($log_dir);
		if ($free !== false && $free < (int)$p['min_free'] * 1048576) {
			if (function_exists('gv_errlog')) {
				gv_errlog('disk_low', 'free space ' . (int)($free / 1048576) . ' MiB is below log_min_free_mb '
					. (int)$p['min_free'] . '; request logging is paused', $log_dir);
			}
			return false;
		}
	}
	return true;
}

// Append one row to {log_dir}/guard-YYYYMMDD.jsonl.
// The directory is passed explicitly so the logger stays free of global state
// and can be unit-tested against a temporary directory.
function gv_log(array $row, $log_dir) {
	try {
		$log_dir = (string)$log_dir;
		if ($log_dir === '') { return; }
		if (!is_dir($log_dir)) {
			@mkdir($log_dir, 0775, true);
			if (!is_dir($log_dir)) { return; }
		}
		if (!gv_log_allowed($log_dir)) { return; }
		$flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
		// Keep the line even when a header carries invalid UTF-8 bytes.
		if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) { $flags |= JSON_INVALID_UTF8_SUBSTITUTE; }
		$line = json_encode($row, $flags);
		if ($line === false) { return; }
		$file = rtrim($log_dir, '/\\') . '/guard-' . date('Ymd') . '.jsonl';
		$n = @file_put_contents($file, $line . "\n", FILE_APPEND | LOCK_EX);
		// A log that cannot be written is otherwise invisible: the guard keeps
		// deciding and nothing records it. gv_errlog throttles itself.
		if ($n === false && function_exists('gv_errlog')) {
			gv_errlog('log_write_failed', 'cannot append to ' . basename($file), $log_dir);
		}
	} catch (\Throwable $e) {
		// silent: the guard may fail, the site may not
	}
}

// Append one outcome row to the same daily file.
//
// This deliberately mirrors gv_log() rather than adding a flag to it. The two
// writers cannot then drift, and this one - the only logging that happens after
// the host application has finished - stays short enough to audit at a glance.
function gv_log_outcome(array $row, $log_dir) {
	try {
		$log_dir = (string)$log_dir;
		if ($log_dir === '') { return; }
		if (!is_dir($log_dir)) {
			@mkdir($log_dir, 0775, true);
			if (!is_dir($log_dir)) { return; }
		}
		if (!gv_log_allowed($log_dir)) { return; }
		$flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
		if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) { $flags |= JSON_INVALID_UTF8_SUBSTITUTE; }
		$line = json_encode($row, $flags);
		if ($line === false) { return; }
		$file = rtrim($log_dir, '/\\') . '/guard-' . date('Ymd') . '.jsonl';
		$n = @file_put_contents($file, $line . "\n", FILE_APPEND | LOCK_EX);
		// A log that cannot be written is otherwise invisible: the guard keeps
		// deciding and nothing records it. gv_errlog throttles itself.
		if ($n === false && function_exists('gv_errlog')) {
			gv_errlog('log_write_failed', 'cannot append to ' . basename($file), $log_dir);
		}
	} catch (\Throwable $e) {
		// silent: the response is already on its way to the client
	}
}
