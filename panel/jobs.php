<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// Job queue producer, and model status reading.
//
// Analyzer actions are dispatched as typed JSON envelopes on a Redis list,
// drained by a Python worker that calls the corresponding function in-process.
// Nothing here builds a command string, and nothing here executes one:
// shell_exec and friends are frequently disabled on shared hosting anyway, and
// passing operator input into a command line inside a security tool is exactly
// the class of bug this project exists to stop.
//
// The allowed type list is closed. The worker checks it again independently,
// so a queue entry written by anything other than this file is still refused.

require_once __DIR__ . '/../guard/guard.php';
require_once __DIR__ . '/data.php';

define('GP_JOB_TTL', 86400);

function gp_job_types() {
	return array('verify', 'nightly', 'train', 'train_clf', 'replay_full',
		'promote_ml', 'promote_clf', 'snapshot', 'geo_compile', 'iplist_compile', 'pip_sync');
}

// Validate a job's parameters. Returns array(ok, params_or_error).
// Every value is typed and bounded; replay overrides are restricted to the same
// whitelist the config overlay uses, so the queue can never carry a key the
// guard would not accept anyway.
function gp_job_params($type, array $params) {
	$out = array();
	if (isset($params['days'])) {
		$days = (int)$params['days'];
		if ($days < 1 || $days > 90) { return array(false, 'bad_days'); }
		$out['days'] = $days;
	}
	if ($type === 'replay_full') {
		$set = isset($params['set']) && is_array($params['set']) ? $params['set'] : array();
		$clean = array();
		foreach ($set as $key => $value) {
			$check = gv_overlay_validate($key, $value);
			if (!$check[0]) { return array(false, 'bad_override'); }
			$clean[$key] = $check[1];
		}
		if (count($clean) > 20) { return array(false, 'too_many'); }
		$out['set'] = $clean;
	}
	return array(true, $out);
}

// Enqueue one job. Returns array(ok, id, error).
function gp_job_enqueue($type, array $params, $actor) {
	$type = (string)$type;
	if (!in_array($type, gp_job_types(), true)) {
		return array('ok' => false, 'id' => null, 'error' => 'unknown job type');
	}
	$checked = gp_job_params($type, $params);
	if (!$checked[0]) {
		return array('ok' => false, 'id' => null, 'error' => $checked[1]);
	}
	$conn = gp_redis();
	if (!$conn) {
		return array('ok' => false, 'id' => null, 'error' => gp_t_safe('job_needs_redis'));
	}

	$id = bin2hex(random_bytes(8));
	$envelope = array(
		'id'           => $id,
		'type'         => $type,
		'params'       => $checked[1],
		'requested_by' => (string)$actor,
		'requested_at' => round(microtime(true), 3),
	);
	$json = json_encode($envelope, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	if ($json === false) {
		return array('ok' => false, 'id' => null, 'error' => 'encode_failed');
	}

	$status = json_encode(array_merge($envelope, array('status' => 'queued')),
		JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	gv_r_setex($conn, gp_key('job:' . $id), GP_JOB_TTL, $status);
	$pushed = gv_redis_cmd($conn, array('LPUSH', gp_key('jobs'), $json));
	if ($pushed === false) {
		return array('ok' => false, 'id' => null, 'error' => 'queue_failed');
	}
	// Refresh the whole list's TTL on every enqueue. This is intentional (#14):
	// the list expires 24h after the LAST enqueue, which bounds growth if the
	// worker is permanently down. The worker normally drains it every minute, so
	// in practice the TTL is never reached; removing it risks unbounded growth.
	gv_redis_cmd($conn, array('EXPIRE', gp_key('jobs'), (string)GP_JOB_TTL));

	gp_audit_append(array('event' => 'job', 'actor' => (string)$actor,
		'ip' => gp_client_ip(), 'key' => $type, 'old' => null,
		'new' => array('id' => $id, 'params' => $checked[1])));

	return array('ok' => true, 'id' => $id, 'error' => null);
}

// gp_t() lives in the front controller; jobs.php is also loaded by the
// self-test, where it is not defined.
function gp_t_safe($key) {
	return function_exists('gp_t') ? gp_t($key) : $key;
}

// Recent jobs, newest first, bounded.
function gp_job_list($limit = 50) {
	$out = array();
	$conn = gp_redis();
	if (!$conn) { return $out; }
	$cursor = '0';
	$guard = 0;
	do {
		// The glob job:* requires the trailing colon, so it matches the per-job
		// status keys (job:<id>) but NOT the list key (jobs, no colon). A GET on
		// the list key would fail and be skipped anyway, so this is doubly safe
		// (#21d: the reviewer's collision claim is incorrect).
		$reply = gp_scan($conn, $cursor, gp_key('job:*'));
		if ($reply === null) { break; }
		list($cursor, $keys) = $reply;
		foreach ($keys as $key) {
			$raw = gv_r_get($conn, $key);
			if (!is_string($raw)) { continue; }
			$row = json_decode($raw, true);
			if (is_array($row)) { $out[] = $row; }
			if (count($out) >= $limit) { break 2; }
		}
		$guard++;
	} while ($cursor !== '0' && $guard < 32);

	usort($out, function ($a, $b) {
		return ($b['requested_at'] ?? 0) <=> ($a['requested_at'] ?? 0);
	});
	return $out;
}

// --------------------------------------------------------------------------
// Model status
// --------------------------------------------------------------------------

// Read what the analyzer knows about each model from the snapshot, which is
// where the Python side records it. The panel does not open joblib bundles
// itself - that would mean reading a pickle in the web tier.
// Where the supervised classifier stands on its labels (written by every nightly run, copied into the snapshot): array(positives, humans,
// needed, sources => honeypot / refuted_claim / ground_truth) or null before the first nightly run that records it. Whole numbers only.
function gp_clf_labels(?array $snapshot = null) {
	$snapshot = $snapshot === null ? gp_snapshot() : $snapshot;
	$l = isset($snapshot['clf_labels']) && is_array($snapshot['clf_labels']) ? $snapshot['clf_labels'] : null;
	if ($l === null || !isset($l['positives'], $l['needed'])) { return null; }
	$src = isset($l['sources']) && is_array($l['sources']) ? $l['sources'] : array();
	return array('positives' => max(0, (int)$l['positives']), 'humans' => max(0, (int)($l['humans'] ?? 0)), 'needed' => max(1, (int)$l['needed']),
		'sources' => array('honeypot' => max(0, (int)($src['honeypot'] ?? 0)), 'refuted_claim' => max(0, (int)($src['refuted_claim'] ?? 0)), 'ground_truth' => max(0, (int)($src['ground_truth'] ?? 0))));
}

function gp_model_status() {
	$snapshot = gp_snapshot();
	$models = isset($snapshot['models']) && is_array($snapshot['models'])
		? $snapshot['models'] : array();
	$out = array();
	foreach (array('ml', 'clf') as $kind) {
		$out[$kind] = isset($models[$kind]) && is_array($models[$kind])
			? $models[$kind]
			: array('live' => null, 'candidate' => null);
	}
	return $out;
}
