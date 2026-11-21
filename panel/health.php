<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

require_once __DIR__ . '/data.php';
require_once __DIR__ . '/rules.php';
require_once __DIR__ . '/iplists.php';

// Job health and the dashboard's critical alerts.
//
// Everything that decides an alert is read LIVE (a small file read or stat, one cheap Redis
// command): the snapshot can be the very thing that died, so it never vouches for itself.
// Heavy numbers (KPIs, top lists) still come from the snapshot.
//
// A job's state comes from analyzer/.jobstatus-<mode>.json, written by the cron wrapper
// (scripts/lib-jobstatus.sh) on every run: last start / end / success / failure, exit code,
// duration, skip count, the last error lines, warnings, a result. Until the new wrapper has
// run, the old .lastrun-<name> marker gives a last-success time.
//
// States: never (no record) | ok | warning (ran, but said it did nothing useful) |
//         late (no success for more than twice the expected interval) | failing (the last run failed).

define('GP_JOB_LATE_FACTOR', 2);
define('GP_QUEUE_STUCK_S', 300);

// The jobs: name => array(label key, marker for the old heartbeat, required, interval setting key).
function gp_job_defs() {
	return array(
		'verify'    => array('label' => 'job_n_verify', 'marker' => 'run_verify', 'required' => true),
		'worker'    => array('label' => 'job_n_worker', 'marker' => 'worker', 'required' => true),
		'snapshot'  => array('label' => 'job_n_snapshot', 'marker' => 'snapshot', 'required' => true),
		'nightly'   => array('label' => 'job_n_nightly', 'marker' => 'run_nightly', 'required' => true),
		'logrotate' => array('label' => 'job_n_logrotate', 'marker' => '', 'required' => true),
		'train'     => array('label' => 'job_n_train', 'marker' => '', 'required' => false),
		'train-clf' => array('label' => 'job_n_train_clf', 'marker' => '', 'required' => false),
		'geo'       => array('label' => 'job_n_geo', 'marker' => '', 'required' => false),
		'report'    => array('label' => 'job_n_report', 'marker' => '', 'required' => false),
	);
}

// Expected interval in seconds per job (Settings -> Analyzer, minutes; defaults = the documented crontab).
function gp_job_intervals(?array $cfg = null) {
	$cfg = $cfg === null ? gp_effective_config() : $cfg;
	$def = gp_analyzer_defaults();
	$out = array();
	foreach (array_keys(gp_job_defs()) as $job) {
		$k = 'interval_' . str_replace('-', '_', $job);
		$v = isset($cfg['analyzer'][$k]) ? $cfg['analyzer'][$k] : $def[$k];
		$out[$job] = max(60, (int)$v * 60);
	}
	return $out;
}

function gp_status_dir() {
	$env = getenv('GV_JOBSTATUS_DIR');
	return (is_string($env) && $env !== '') ? rtrim($env, '/') : dirname(__DIR__) . '/analyzer';
}

// One job's status file: array, null (no file) or false (unreadable / not valid).
function gp_job_status_read($job, $dir = null) {
	$dir = $dir === null ? gp_status_dir() : $dir;
	$p = $dir . '/.jobstatus-' . $job . '.json';
	if (!is_file($p)) { return null; }
	$raw = @file_get_contents($p);
	$d = is_string($raw) ? json_decode($raw, true) : null;
	return (is_array($d) && isset($d['mode'])) ? $d : false;
}

// The old heartbeat marker (.lastrun-<name>): a unix time, 0 when absent.
function gp_job_marker($marker, $dir = null) {
	if ($marker === '') { return 0; }
	$dir = $dir === null ? gp_status_dir() : $dir;
	$raw = @file_get_contents($dir . '/.lastrun-' . $marker);
	return (is_string($raw) && is_numeric(trim($raw))) ? (int)$raw : 0;
}

// The health of one job. Pure given the status record, the marker time and "now".
// $st: the decoded status file, null (none) or false (corrupt).
function gp_job_health_one($job, array $def, $st, $marker_ts, $interval, $now, $seen = 0) {
	$h = array('job' => $job, 'label' => $def['label'], 'required' => $def['required'], 'interval' => (int)$interval,
		'state' => 'never', 'source' => 'none', 'status' => '', 'last_start' => 0, 'last_end' => 0, 'last_success' => 0, 'last_failure' => 0,
		'last_exit' => 0, 'duration' => 0, 'skipped' => 0, 'runs' => 0, 'failures' => 0, 'last_error' => '', 'first_line' => '',
		'warnings' => array(), 'result' => null, 'next_expected' => 0, 'overdue' => 0, 'skew' => false, 'seen' => false, 'corrupt' => ($st === false));
	if (is_array($st)) {
		$h['source'] = 'status';
		$h['status'] = (string)($st['status'] ?? '');
		foreach (array('last_start', 'last_end', 'last_success', 'last_failure', 'last_exit', 'duration', 'skipped', 'runs', 'failures') as $k) {
			$h[$k] = isset($st[$k]) && is_numeric($st[$k]) ? (int)$st[$k] : 0;
		}
		$h['last_error'] = (string)($st['last_error'] ?? '');
		$h['first_line'] = strtok($h['last_error'], "\n") ?: '';
		$h['warnings'] = (isset($st['warnings']) && is_array($st['warnings'])) ? array_values(array_filter($st['warnings'], 'is_string')) : array();
		if (isset($st['result_json']) && is_string($st['result_json']) && $st['result_json'] !== '') {
			$r = json_decode($st['result_json'], true);
			if (is_array($r)) { $h['result'] = $r; }
		}
	} elseif ($marker_ts > 0) {
		$h['source'] = 'marker';
		$h['last_success'] = $marker_ts;
		$h['last_end'] = $marker_ts;
		$h['status'] = 'ok';
	}
	if ($h['source'] === 'none') { return $h; }
	// A clock that is ahead (the host moved back, or two machines disagree): never negative ages, flagged.
	foreach (array('last_end', 'last_success', 'last_start', 'last_failure') as $k) {
		if ($h[$k] > $now + 300) { $h['skew'] = true; $h[$k] = $now; }
	}
	$ref = $h['last_success'];
	$h['next_expected'] = $ref > 0 ? $ref + $interval : 0;
	$age = $ref > 0 ? max(0, $now - $ref) : null;
	// Failing = the last real run failed: a failure newer than the last success. (A later firing that was
	// only skipped by the lock does not clear it.)
	if ($h['source'] === 'status' && $h['last_failure'] > 0 && $h['last_failure'] >= $h['last_success']) {
		$h['state'] = 'failing';
	} elseif ($age === null) {
		$h['state'] = 'never';                 // only skips / failures so far, never a success
	} elseif ($age > GP_JOB_LATE_FACTOR * $interval) {
		$h['state'] = 'late';
		$h['overdue'] = $age - GP_JOB_LATE_FACTOR * $interval;
	} elseif ($h['status'] === 'warning') {
		$h['state'] = 'warning';
	} else {
		$h['state'] = 'ok';
	}
	$h['seen'] = ($h['state'] === 'failing' && $h['last_failure'] > 0 && $h['last_failure'] <= (int)$seen);
	return $h;
}

// Every job's health. $now / $dir / $intervals are injectable for tests.
function gp_job_health($now = null, $dir = null, ?array $intervals = null, ?array $seen = null) {
	$now = $now === null ? time() : (int)$now;
	$intervals = $intervals === null ? gp_job_intervals() : $intervals;
	$seen = $seen === null ? gp_jobs_seen() : $seen;
	$out = array();
	foreach (gp_job_defs() as $job => $def) {
		$out[$job] = gp_job_health_one($job, $def, gp_job_status_read($job, $dir), gp_job_marker($def['marker'], $dir),
			$intervals[$job], $now, isset($seen[$job]) ? (int)$seen[$job] : 0);
	}
	return $out;
}

// ---------------------------------------------------------------- "seen" errors

function gp_jobs_seen_path() {
	$env = getenv('GP_JOBS_SEEN');
	return (is_string($env) && $env !== '') ? $env : __DIR__ . '/jobs-seen.json';
}

function gp_jobs_seen() {
	$raw = @file_get_contents(gp_jobs_seen_path());
	$d = is_string($raw) ? json_decode($raw, true) : null;
	$out = array();
	if (is_array($d)) { foreach ($d as $k => $v) { if (is_string($k) && is_numeric($v)) { $out[$k] = (int)$v; } } }
	return $out;
}

// Mark the current failure of a job as seen: the alert goes quiet until a NEWER failure.
// Audit-logged. Returns array(ok, key).
function gp_jobs_mark_seen($job, $actor, $ip) {
	$defs = gp_job_defs();
	if (!isset($defs[$job])) { return array(false, 'job_unknown'); }
	$h = gp_job_health_one($job, $defs[$job], gp_job_status_read($job), 0, 60, time());
	if ($h['last_failure'] <= 0) { return array(false, 'job_no_failure'); }
	$seen = gp_jobs_seen();
	$old = isset($seen[$job]) ? $seen[$job] : 0;
	$seen[$job] = $h['last_failure'];
	$p = gp_jobs_seen_path();
	$tmp = $p . '.tmp' . getmypid();
	if (@file_put_contents($tmp, json_encode($seen), LOCK_EX) === false || !@rename($tmp, $p)) { @unlink($tmp); return array(false, 'write_failed'); }
	@chmod($p, 0640);
	gp_audit_append(array('event' => 'job_error_seen', 'actor' => (string)$actor, 'ip' => (string)$ip, 'key' => $job, 'old' => $old, 'new' => $h['last_failure']));
	return array(true, 'job_seen_done');
}

// ---------------------------------------------------------------- the queue

// Length and age of the oldest queued panel job. The worker pops from the tail (RPOP), so the oldest is the last element.
function gp_queue_health($now = null) {
	$now = $now === null ? time() : (int)$now;
	$out = array('redis' => false, 'length' => 0, 'oldest_age' => null, 'stuck' => false);
	$conn = gp_redis();
	if (!$conn) { return $out; }
	$out['redis'] = true;
	$len = gv_redis_cmd($conn, array('LLEN', gp_key('jobs')));
	$out['length'] = is_numeric($len) ? (int)$len : 0;
	if ($out['length'] > 0) {
		$raw = gv_redis_cmd($conn, array('LINDEX', gp_key('jobs'), '-1'));
		$env = is_string($raw) ? json_decode($raw, true) : null;
		if (is_array($env) && isset($env['requested_at']) && is_numeric($env['requested_at'])) {
			$out['oldest_age'] = max(0, $now - (int)$env['requested_at']);
			$out['stuck'] = $out['oldest_age'] > GP_QUEUE_STUCK_S;
		}
	}
	return $out;
}

// ---------------------------------------------------------------- crontab check

function gp_cron_check_file() { return gp_status_dir() . '/.cron-check.json'; }
function gp_cron_check_live_file() { return gp_status_dir() . '/.cron-check-live.json'; }
define('GP_CRON_CACHE_TTL', 300);        // the live result is reused for 5 minutes
define('GP_CRON_REFRESH_GAP', 30);       // "Check again" at most once per 30 seconds

// The crontab check, first source that works: (1) the live check (scripts/cron-check.sh run through proc_open with an
// argv array: no shell, no operator input, fixed binary, 3 s timeout), whose result is CACHED in
// analyzer/.cron-check-live.json for 5 minutes so the dashboard and the Jobs page do not spawn a process per view;
// (2) the copy the cron wrapper leaves in analyzer/.cron-check.json; (3) nothing. $force skips a fresh cache (the
// "Check again" button). Returns array(mode live|cache|file|none, report|null, age|null).
function gp_cron_check($now = null, $allow_exec = true, $force = false) {
	$now = $now === null ? time() : (int)$now;
	if ($allow_exec && !defined('GP_NO_EXEC')) {
		$cf = gp_cron_check_live_file();
		clearstatcache(true, $cf);
		if (!$force && is_file($cf)) {
			$age = max(0, $now - (int)@filemtime($cf));
			$d = json_decode((string)@file_get_contents($cf), true);
			if ($age < GP_CRON_CACHE_TTL && is_array($d) && isset($d['jobs'])) { return array('mode' => 'cache', 'report' => $d, 'age' => $age); }
		}
		$r = gp_cron_check_exec();
		if ($r !== null) {
			$tmp = $cf . '.tmp' . getmypid();
			if (@file_put_contents($tmp, json_encode($r), LOCK_EX) !== false) { @chmod($tmp, 0640); if (!@rename($tmp, $cf)) { @unlink($tmp); } }
			return array('mode' => 'live', 'report' => $r, 'age' => 0);
		}
	}
	$f = gp_cron_check_file();
	if (is_file($f)) {
		$d = json_decode((string)@file_get_contents($f), true);
		if (is_array($d) && isset($d['jobs'])) { return array('mode' => 'file', 'report' => $d, 'age' => max(0, $now - (int)@filemtime($f))); }
	}
	return array('mode' => 'none', 'report' => null, 'age' => null);
}

// "Check again": refresh the live cache now. Rate-limited to once per 30 s (by the cache file's own time, so it holds for
// every operator), audit-logged. Returns array(ok, lang key).
function gp_cron_check_refresh($actor, $ip, $now = null) {
	$now = $now === null ? time() : (int)$now;
	$cf = gp_cron_check_live_file();
	$lock = gp_status_dir() . '/.cron-check-refresh';
	clearstatcache(true, $lock);
	$last = max((int)@filemtime($lock), 0);
	if ($now - $last < GP_CRON_REFRESH_GAP) { return array(false, 'cron_refresh_wait'); }
	@touch($lock, $now);
	$c = gp_cron_check($now, true, true);
	gp_audit_append(array('event' => 'cron_check_refresh', 'actor' => (string)$actor, 'ip' => (string)$ip, 'key' => 'cron-check', 'old' => null, 'new' => $c['mode']));
	return array(true, $c['mode'] === 'live' ? 'cron_refresh_done' : 'cron_refresh_nolive');
}

// Run scripts/cron-check.sh. Never blocks the page: stderr goes to /dev/null (an unread pipe could fill and stall the
// child), reading stops at 3 s, and a child that is still alive is terminated and, if it does not exit within 1 s,
// killed with SIGKILL before proc_close (which would otherwise wait for it for ever). $script / $bash are test seams.
function gp_cron_check_exec($script = null, $bash = null, $timeout = 3.0) {
	if (!function_exists('proc_open')) { return null; }
	$disabled = array_map('trim', explode(',', (string)ini_get('disable_functions')));
	if (in_array('proc_open', $disabled, true)) { return null; }
	if ($bash === null) { $bash = is_executable('/bin/bash') ? '/bin/bash' : (is_executable('/usr/bin/bash') ? '/usr/bin/bash' : ''); }
	if ($script === null) {
		$script = dirname(__DIR__) . '/scripts/cron-check.sh';
		// Test seam: only the self-test (which defines GP_SELFTEST) can point this at another script.
		if (defined('GP_SELFTEST') && isset($GLOBALS['gp_test_cron_script'])) { $script = (string)$GLOBALS['gp_test_cron_script']; }
	}
	if ($bash === '' || !is_file($script)) { return null; }
	$proc = @proc_open(array($bash, $script, '--json'), array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('file', '/dev/null', 'w')), $pipes);
	if (!is_resource($proc)) { return null; }
	fclose($pipes[0]);
	stream_set_blocking($pipes[1], false);
	$out = '';
	$deadline = microtime(true) + $timeout;
	$done = false;
	while (microtime(true) < $deadline) {
		$r = array($pipes[1]); $w = null; $e = null;
		if (@stream_select($r, $w, $e, 0, 100000) > 0) {
			$chunk = fread($pipes[1], 65536);
			if ($chunk === '' || $chunk === false) { if (feof($pipes[1])) { $done = true; break; } } else { $out .= $chunk; }
		}
		if (strlen($out) > 262144) { break; }
	}
	fclose($pipes[1]);
	$st = proc_get_status($proc);
	if ($st['running']) {
		proc_terminate($proc);
		$kill_at = microtime(true) + 1.0;
		while (microtime(true) < $kill_at) { $st = proc_get_status($proc); if (!$st['running']) { break; } usleep(50000); }
		if ($st['running']) { proc_terminate($proc, 9); }
	}
	proc_close($proc);
	if (!$done && $out === '') { return null; }
	$d = json_decode($out, true);
	return (is_array($d) && isset($d['jobs']) && empty($d['unreadable'])) ? $d : null;
}

// ---------------------------------------------------------------- the alerts

// Whether the Redis eviction policy is noeviction: true / false / null (unknown: CONFIG not allowed).
function gp_redis_noeviction() {
	$conn = gp_redis();
	if (!$conn) { return null; }
	$r = gv_redis_cmd($conn, array('CONFIG', 'GET', 'maxmemory-policy'));
	if (is_array($r) && count($r) >= 2 && is_string($r[1])) { return $r[1] === 'noeviction'; }
	return null;
}

// Rows of the last $window seconds that were written in degraded mode (rd=1): array(rows, degraded).
function gp_degraded_recent($window = 900, $now = null) {
	$now = $now === null ? time() : (int)$now;
	$f = gp_log_file(null);
	$rows = 0; $deg = 0;
	if (is_file($f)) {
		foreach (gp_tail_lines($f, 4000, 1048576) as $line) {
			$r = json_decode($line, true);
			if (!is_array($r) || !isset($r['ts']) || isset($r['o']) || (float)$r['ts'] < $now - $window) { continue; }
			$rows++;
			if (!empty($r['rd'])) { $deg++; }
		}
	}
	return array($rows, $deg);
}

// New guard errors: guard-errors.log lines from the last $window seconds, as array(code => count).
function gp_recent_guard_errors($window = 3600, $now = null) {
	$now = $now === null ? time() : (int)$now;
	$f = rtrim(gp_log_dir(), '/\\') . '/guard-errors.log';
	$out = array();
	if (!is_file($f)) { return $out; }
	foreach (gp_tail_lines($f, 200, 65536) as $line) {
		if (!preg_match('/^(\S+)\s+([a-z0-9_]+)\s/', $line, $m)) { continue; }
		$t = strtotime($m[1]);
		if ($t === false || $t < $now - $window) { continue; }
		$out[$m[2]] = isset($out[$m[2]]) ? $out[$m[2]] + 1 : 1;
	}
	return $out;
}

// Whether guard/rules.cache.php is older than guard/rules.json while a rule is enabled (the guard then reads the JSON on every request).
function gp_rules_cache_stale() {
	$json = gv_rules_path();
	$jm = @filemtime($json);
	if ($jm === false) { return false; }
	$cm = @filemtime(gv_rules_cache_path($json));
	return ($cm === false || $cm < $jm);
}

// Gather every input the alerts need. Live reads only; each is small.
function gp_health_inputs($now = null) {
	$now = $now === null ? time() : (int)$now;
	$cfg = gv_cfg_load();
	$rs = gp_rules_state();
	$snap = gp_snapshot();
	$def = gp_degraded_recent(900, $now);
	return array(
		'now' => $now, 'exposed' => gp_exposure_warning(), 'redis_up' => gp_redis_up(), 'degraded' => $def,
		'guard_errors' => gp_recent_guard_errors(3600, $now), 'jobs' => gp_job_health($now), 'queue' => gp_queue_health($now),
		'storage' => gp_log_storage($now), 'snapshot' => $snap, 'geo_warn' => gp_geo_dashboard_warnings(), 'geo_rules' => gp_geo_rules_need($rs['rules']),
		'rules_state' => $rs['state'], 'rules_enabled' => count(array_filter($rs['rules'], function ($r) { return !empty($r['enabled']); })), 'rules_cache_stale' => gp_rules_cache_stale(),
		'secret_default' => (!isset($cfg['secret']) || $cfg['secret'] === 'CHANGE_ME'), 'salt_default' => (!isset($cfg['holdout_salt']) || $cfg['holdout_salt'] === 'CHANGE_ME_TOO'),
		'noeviction' => gp_redis_noeviction(), 'cron' => gp_cron_check($now), 'tz_offset' => (int)date('Z', $now),
		'geo_used' => gp_geo_status($now)['country'] !== null || gp_geo_status($now)['asn'] !== null,
		'iplist_warn' => gp_iplists_health($now),
	);
}

// The critical-alert list from gathered inputs. PURE: every decision is here, so every case is testable.
// Each alert: array(id, level critical|warning, key (lang), detail, link (route or '')).
function gp_health_alerts(array $in) {
	$a = array();
	$add = function ($id, $level, $key, $detail = '', $link = '') use (&$a) { $a[] = array('id' => $id, 'level' => $level, 'key' => $key, 'detail' => $detail, 'link' => $link); };
	if (!empty($in['exposed'])) { $add('exposed', 'critical', 'al_exposed', implode(' ', array_slice((array)$in['exposed'], 0, 3)), 'dashboard'); }
	if (empty($in['redis_up'])) { $add('redis_down', 'critical', 'al_redis_down', '', ''); }
	$d = isset($in['degraded']) ? $in['degraded'] : array(0, 0);
	if ($d[1] > 0) { $add('degraded', ($d[0] > 0 && $d[1] * 2 >= $d[0]) ? 'critical' : 'warning', 'al_degraded', $d[1] . '/' . $d[0], 'logs'); }
	if (!empty($in['guard_errors'])) {
		$parts = array(); foreach ($in['guard_errors'] as $c => $n) { $parts[] = $c . ' x' . $n; }
		$add('guard_errors', 'warning', 'al_guard_errors', implode(', ', array_slice($parts, 0, 4)), '');
	}
	foreach ((array)($in['jobs'] ?? array()) as $job => $h) {
		if ($h['state'] === 'failing' && !$h['seen']) { $add('job_failing_' . $job, $h['required'] ? 'critical' : 'warning', 'al_job_failing', $job . ': ' . $h['first_line'], 'jobs&job=' . $job); }
		elseif ($h['state'] === 'late') { $add('job_late_' . $job, $h['required'] ? 'critical' : 'warning', 'al_job_late', $job, 'jobs&job=' . $job); }
		elseif ($h['state'] === 'warning') { $add('job_warning_' . $job, 'warning', 'al_job_warning', $job . ': ' . $h['first_line'], 'jobs&job=' . $job); }
		elseif ($h['state'] === 'never' && $h['required']) { $add('job_never_' . $job, 'warning', 'al_job_never', $job, 'jobs&job=' . $job); }
	}
	$q = isset($in['queue']) ? $in['queue'] : array('stuck' => false);
	if (!empty($q['stuck'])) { $add('queue_stuck', 'critical', 'al_queue_stuck', (int)floor($q['oldest_age'] / 60) . ' min, ' . $q['length'] . ' job(s)', 'jobs'); }
	$s = isset($in['storage']) ? $in['storage'] : array('warnings' => array());
	foreach ((array)$s['warnings'] as $w) {
		if ($w === 'disk_low') { $add('disk_low', 'critical', 'al_disk_low', '', 'dashboard'); }
		elseif ($w === 'over_cap') { $add('over_cap', 'warning', 'al_over_cap', '', 'dashboard'); }
	}
	$snap = isset($in['snapshot']) ? $in['snapshot'] : null;
	$snap_int = isset($in['jobs']['snapshot']) ? $in['jobs']['snapshot']['interval'] : 900;
	if (!is_array($snap)) { $add('snapshot_missing', 'warning', 'al_snapshot_missing', '', ''); }
	elseif (!empty($snap['generated_at']) && ($in['now'] - (float)$snap['generated_at']) > GP_JOB_LATE_FACTOR * $snap_int) { $add('snapshot_stale', 'warning', 'al_snapshot_stale', gp_age($snap['generated_at']), ''); }
	if (is_array($snap) && isset($snap['tz']['offset']) && abs((int)$snap['tz']['offset'] - (int)$in['tz_offset']) >= 60) {
		$add('tz_mismatch', 'warning', 'al_tz_mismatch', 'analyzer UTC' . sprintf('%+d', (int)$snap['tz']['offset'] / 3600) . ' / panel UTC' . sprintf('%+d', (int)$in['tz_offset'] / 3600), '');
	}
	foreach ((array)($in['geo_warn'] ?? array()) as $g) {
		$crit = in_array($g, array('missing', 'corrupt'), true) && !empty($in['geo_rules']);
		$add('geo_' . $g, $crit ? 'critical' : 'warning', 'geo_w_' . $g, '', 'geo');
	}
	foreach ((array)($in['iplist_warn'] ?? array()) as $w) {
		// A list file that is missing or corrupt while its list is enabled, or a failed compile: the guard
		// silently treats the list as empty (fail-open), so these are critical. A pending compile is a warning.
		$add('iplist_' . $w[0] . ($w[0] === 'file_missing' || $w[0] === 'file_corrupt' ? '_' . $w[1] : ''), $w[0] === 'pending' ? 'warning' : 'critical',
			'al_iplist_' . $w[0], $w[1], 'iplists');
	}
	if (($in['rules_state'] ?? '') === 'invalid') { $add('rules_invalid', 'critical', 'al_rules_invalid', '', 'rules'); }
	if (!empty($in['rules_enabled']) && !empty($in['rules_cache_stale'])) { $add('rules_cache_stale', 'warning', 'al_rules_cache_stale', '', 'rules'); }
	if (!empty($in['secret_default'])) { $add('secret_default', 'warning', 'al_secret_default', '', 'config_file'); }
	elseif (!empty($in['salt_default'])) { $add('salt_default', 'warning', 'al_salt_default', '', 'config_file'); }
	if (array_key_exists('noeviction', $in) && $in['noeviction'] === false) { $add('evictable', 'warning', 'al_evictable', '', ''); }
	$c = isset($in['cron']) ? $in['cron'] : array('mode' => 'none');
	if ($c['mode'] === 'none') { $add('cron_unknown', 'warning', 'al_cron_unknown', '', 'jobs'); }
	elseif (is_array($c['report'])) {
		$miss = array(); $other = array();
		foreach ($c['report']['jobs'] as $j) {
			if ($j['state'] === 'missing' && $j['severity'] === 'critical') { $miss[] = $j['job']; }
			elseif (in_array($j['state'], array('disabled', 'wrong_path', 'wrong_schedule'), true) && $j['required']) { $other[] = $j['job'] . ' (' . $j['state'] . ')'; }
		}
		if ($miss) { $add('cron_missing', 'critical', 'al_cron_missing', implode(', ', $miss), 'jobs'); }
		if ($other) { $add('cron_wrong', 'warning', 'al_cron_wrong', implode(', ', $other), 'jobs'); }
		$py = $c['report']['gv_python'] ?? array('set' => true, 'ok' => true);
		if (!empty($py['set']) && empty($py['ok'])) { $add('gv_python_bad', 'warning', 'al_gv_python_bad', (string)$py['value'], 'jobs'); }
		elseif (empty($py['set'])) { $add('gv_python_missing', 'warning', 'al_gv_python_missing', '', 'jobs'); }
	}
	usort($a, function ($x, $y) { return ($x['level'] === 'critical' ? 0 : 1) <=> ($y['level'] === 'critical' ? 0 : 1); });
	return $a;
}

// Whether the "Cron setup" help card shows: some job has never run, or the crontab check found a missing entry.
function gp_cron_card_needed(array $jobs, array $cron) {
	foreach ($jobs as $h) { if ($h['state'] === 'never' && $h['required']) { return true; } }
	if (is_array($cron['report'] ?? null)) {
		foreach ($cron['report']['jobs'] as $j) { if ($j['state'] !== 'ok' && $j['state'] !== 'duplicate' && ($j['required'] || $j['state'] !== 'missing')) { return true; } }
	}
	return false;
}

// The global protection summary: "monitor" | "partial" | "enforcing", from the enforce toggles and enforced rules.
function gp_protection_mode(array $cfg, array $rules) {
	$forced = ($cfg['secret'] ?? 'CHANGE_ME') === 'CHANGE_ME';
	$tog = 0;
	foreach (array('block', 'challenge', 'ratelimit') as $k) { if (!empty($cfg['enforce'][$k])) { $tog++; } }
	$enforced_rules = 0;
	foreach ($rules as $r) { if (!empty($r['enabled']) && $r['mode'] === 'enforce' && $r['action'] !== 'log') { $enforced_rules++; } }
	if ($forced) { return array('mode' => 'monitor', 'forced' => true, 'toggles' => $tog, 'enforced_rules' => $enforced_rules); }
	$mode = ($tog === 3) ? 'enforcing' : (($tog > 0 || $enforced_rules > 0) ? 'partial' : 'monitor');
	return array('mode' => $mode, 'forced' => false, 'toggles' => $tog, 'enforced_rules' => $enforced_rules);
}

// Rule counts by mode and action (enabled rules only).
function gp_rules_summary(array $rules) {
	$out = array('total' => count($rules), 'enabled' => 0, 'by' => array());
	foreach ($rules as $r) {
		if (empty($r['enabled'])) { continue; }
		$out['enabled']++;
		$k = $r['mode'] . '/' . $r['action'];
		$out['by'][$k] = isset($out['by'][$k]) ? $out['by'][$k] + 1 : 1;
	}
	return $out;
}

// "+12 %" / "-3 %" / "new" / "" for a KPI against the previous window.
function gp_kpi_change($cur, $prev) {
	if ($prev === null || $cur === null) { return ''; }
	if ((float)$prev == 0.0) { return (float)$cur == 0.0 ? '0 %' : 'new'; }
	return sprintf('%+d %%', (int)round(100.0 * ((float)$cur - (float)$prev) / (float)$prev));
}

function gp_job_badge($state) {
	return array('ok' => 'gp-badge-on', 'warning' => 'gp-badge-warn', 'late' => 'gp-badge-bad', 'failing' => 'gp-badge-bad', 'never' => 'gp-badge-off')[$state] ?? 'gp-badge-off';
}

// The documented crontab: job => array(schedule, mode argument, script). Mirrors scripts/cron_check.py.
function gp_cron_defaults() {
	return array(
		'verify' => array('*/10 * * * *', 'analyzer-cron.sh', 'verify'), 'worker' => array('* * * * *', 'analyzer-cron.sh', 'worker'),
		'snapshot' => array('*/15 * * * *', 'analyzer-cron.sh', 'snapshot'), 'nightly' => array('17 4 * * *', 'analyzer-cron.sh', 'nightly'),
		'logrotate' => array('10 3 * * *', 'guard-logrotate.sh', ''), 'train' => array('41 5 * * 0', 'analyzer-cron.sh', 'train'),
		'train-clf' => array('11 6 * * 0', 'analyzer-cron.sh', 'train-clf'), 'geo' => array('23 3 1 * *', 'analyzer-cron.sh', 'geo'),
	);
}

// The exact lines to add for what is missing (or all of them when the crontab could not be read), built from
// the REAL install directory, starting with the GV_PYTHON= line. Pure apart from the directory it is given.
function gp_cron_setup_lines(array $jobs, array $cron, $root = null) {
	$root = $root === null ? dirname(__DIR__) : rtrim($root, '/');
	$lines = array();
	$venv = $root . '/.venv/bin/python';
	$py = is_array($cron['report'] ?? null) ? $cron['report']['gv_python'] : array('set' => false, 'ok' => false);
	if (empty($py['set']) || empty($py['ok'])) { $lines[] = 'GV_PYTHON=' . (is_file($venv) ? $venv : '/path/to/virtualenv/bin/python'); }
	$missing = null;
	if (is_array($cron['report'] ?? null)) {
		$missing = array();
		foreach ($cron['report']['jobs'] as $j) { if ($j['state'] !== 'ok' && $j['state'] !== 'duplicate' && ($j['required'] || $j['state'] !== 'missing')) { $missing[$j['job']] = true; } }
	}
	foreach (gp_cron_defaults() as $job => $d) {
		$need = ($missing === null)
			? (isset($jobs[$job]) && $jobs[$job]['required'] ? true : false)
			: isset($missing[$job]);
		if (!$need) { continue; }
		$lines[] = $d[0] . ' ' . $root . '/scripts/' . $d[1] . ($d[2] !== '' ? ' ' . $d[2] : '') . ' >/dev/null 2>&1';
	}
	return $lines;
}

// The last runs of one job from logs/jobs.log (newest first), at most $n.
function gp_job_runs($mode, $n = 10) {
	$f = rtrim(gp_log_dir(), '/\\') . '/jobs.log';
	$out = array();
	if (!is_file($f)) { return $out; }
	foreach (array_reverse(gp_tail_lines($f, 400, 262144)) as $line) {
		$r = json_decode($line, true);
		if (is_array($r) && ($r['mode'] ?? '') === $mode) { $out[] = $r; if (count($out) >= $n) { break; } }
	}
	return $out;
}

// The captured stderr of the most recent FAILED runs of a job from logs/jobs-errors.log (newest first). Already redacted
// when it was written; shown escaped. At most $n blocks of 8 KiB each.
function gp_job_error_blocks($mode, $n = 2) {
	$f = rtrim(gp_log_dir(), '/\\') . '/jobs-errors.log';
	if (!is_file($f)) { return array(); }
	$size = (int)@filesize($f);
	$fh = @fopen($f, 'rb');
	if (!$fh) { return array(); }
	if ($size > 196608) { fseek($fh, -196608, SEEK_END); }
	$raw = (string)stream_get_contents($fh);
	fclose($fh);
	$blocks = preg_split('/^(?==== )/m', $raw, -1, PREG_SPLIT_NO_EMPTY);
	$out = array();
	foreach (array_reverse($blocks) as $b) {
		if (preg_match('/^=== \S+ ' . preg_quote($mode, '/') . ' exit /', $b)) { $out[] = substr($b, 0, 8192); if (count($out) >= $n) { break; } }
	}
	return $out;
}
