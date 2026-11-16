<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// Threshold replay, computed natively in PHP.
//
// gv_effective_score() and gv_decide() are pure and already parity-tested case
// by case against the Python mirror in Phase 3, so PHP reproduces the candidate
// decision exactly. That means interactive tuning needs no queue, no worker and
// no Python round trip - the operator moves a slider and sees the answer.
//
// Full-mode replay, which re-derives reputation and anomaly levels, still goes
// to the analyzer as a job: that one genuinely needs the model.

require_once __DIR__ . '/../guard/guard.php';
require_once __DIR__ . '/data.php';

// Rows whose action the decision engine never produced. They short-circuit
// before the decision step, exactly as in analyzer/replay.py.
function gp_replay_non_decision() {
	return array('exempt', 'allow_bot', '404_hp', 'token_issued', 'nonce_bad',
		'nonce_replay', 'pow_bad', 'mint_limited', 'allow_override', 'allow_preview');
}

function gp_replay_actions() {
	return array('allow', 'challenge', '403', '429');
}

// Most permissive to most restrictive, so "did this get stricter?" is one
// comparison. Mirrors _SEVERITY in analyzer/replay.py.
function gp_replay_severity($action) {
	$map = array('allow' => 0, 'challenge' => 1, '429' => 2, '403' => 3);
	return isset($map[$action]) ? $map[$action] : 0;
}

// Read the slider values out of the request, typed and bounded.
function gp_replay_params_from_request() {
	$src = $_SERVER['REQUEST_METHOD'] === 'POST' ? $_POST : $_GET;
	$cfg = gv_cfg_load();
	$out = array(
		'hard_block_score' => isset($src['hard_block_score'])
			? max(10, min(200, (int)$src['hard_block_score']))
			: (int)$cfg['hard_block_score'],
		'ml_weight' => isset($src['ml_weight'])
			? max(0.0, min(2.0, (float)$src['ml_weight']))
			: (float)$cfg['ml_weight'],
		'clf_weight' => isset($src['clf_weight'])
			? max(0.0, min(2.0, (float)$src['clf_weight']))
			: (float)$cfg['clf_weight'],
		'days' => isset($src['days']) ? max(1, min(14, (int)$src['days'])) : 1,
	);
	foreach (array('reputation', 'ml', 'clf') as $signal) {
		$key = 'signals_' . $signal;
		$out[$key] = isset($src['run']) || $_SERVER['REQUEST_METHOD'] === 'POST'
			? !empty($src[$key])
			: !empty($cfg['signals'][$signal]);
	}
	return $out;
}

// Turn slider values into a validated overlay set, for "apply these values".
function gp_replay_overlay_from_params(array $params) {
	return array(
		'hard_block_score'   => (int)$params['hard_block_score'],
		'ml_weight'          => (float)$params['ml_weight'],
		'clf_weight'         => (float)$params['clf_weight'],
		'signals.reputation' => (bool)$params['signals_reputation'],
		'signals.ml'         => (bool)$params['signals_ml'],
		'signals.clf'        => (bool)$params['signals_clf'],
	);
}

// The decision-function config shape gv_effective_score expects.
function gp_replay_cfg(array $params) {
	return array(
		'signals' => array(
			'reputation' => (bool)$params['signals_reputation'],
			'ml'         => (bool)$params['signals_ml'],
			'clf'        => (bool)$params['signals_clf'],
		),
		'ml_weight'  => (float)$params['ml_weight'],
		'clf_weight' => (float)$params['clf_weight'],
	);
}

// Recompute decisions over a bounded recent window.
//
// Labelling is deliberately simpler than the Python side: the panel labels an
// identity a bot from evidence already present in the row - a honeypot hit or
// a reverse-DNS refutation - and human from a completed handshake. It never
// uses challenge_unsolved, for the same reason analyzer/labels.py does not:
// that is the guard's own decision fed back as ground truth.
function gp_replay_run(array $params) {
	$base_cfg = gv_cfg_load();
	$baseline = array(
		'signals' => array(
			'reputation' => !empty($base_cfg['signals']['reputation']),
			'ml'         => !empty($base_cfg['signals']['ml']),
			'clf'        => !empty($base_cfg['signals']['clf']),
		),
		'ml_weight'  => (float)$base_cfg['ml_weight'],
		'clf_weight' => (float)$base_cfg['clf_weight'],
	);
	$candidate = gp_replay_cfg($params);
	$base_hard = (int)$base_cfg['hard_block_score'];
	$cand_hard = (int)$params['hard_block_score'];

	$result = array(
		'considered' => 0, 'skipped' => 0, 'esc_changed' => 0,
		'baseline' => array(), 'candidate' => array(), 'movement' => array(),
		'bot_rows' => 0, 'bot_newly' => 0,
		'human_rows' => 0, 'human_newly' => 0,
		'holdout_rows' => 0, 'holdout_newly' => 0,
		'capped' => false, 'scanned_lines' => 0, 'days' => (int)$params['days'],
	);
	foreach (gp_replay_actions() as $action) {
		$result['baseline'][$action] = 0;
		$result['candidate'][$action] = 0;
	}

	$labels = array();
	$dates = array_slice(gp_log_dates(14), 0, (int)$params['days']);
	foreach ($dates as $date) {
		gp_replay_scan_day($date, $baseline, $candidate, $base_hard, $cand_hard,
			$result, $labels);
		if ($result['capped']) { break; }
	}
	return $result;
}

// One day's file, reverse-streamed under the same caps as the log explorer.
function gp_replay_scan_day($date, array $baseline, array $candidate, $base_hard,
		$cand_hard, array &$result, array &$labels) {
	$file = gp_log_file($date);
	if (!is_file($file)) { return; }
	$fh = @fopen($file, 'rb');
	if (!$fh) { return; }
	$size = filesize($file);
	if ($size === false) { fclose($fh); return; }

	$pos = $size;
	$buffer = '';
	$scanned = 0;
	$rows = array();

	while ($pos > 0 && $scanned < GP_MAX_SCAN_BYTES
		&& $result['scanned_lines'] < GP_MAX_SCAN_LINES) {
		$read = (int)min(65536, $pos, GP_MAX_SCAN_BYTES - $scanned);
		if ($read <= 0) { break; }
		$pos -= $read;
		if (fseek($fh, $pos, SEEK_SET) !== 0) { break; }
		$data = fread($fh, $read);
		if ($data === false) { break; }
		$scanned += strlen($data);
		$buffer = $data . $buffer;
		$parts = explode("\n", $buffer);
		$buffer = array_shift($parts);
		foreach ($parts as $line) {
			$line = trim($line);
			if ($line === '') { continue; }
			$result['scanned_lines']++;
			if ($result['scanned_lines'] >= GP_MAX_SCAN_LINES) { break; }
			$row = json_decode($line, true);
			if (!is_array($row) || (isset($row['o']) && $row['o'] === 1)) { continue; }
			$rows[] = $row;
		}
	}
	fclose($fh);
	// The loop above keeps the oldest, possibly partial, line in $buffer. Once the
	// whole file has been read ($pos reached 0) that line is complete - the file's
	// first row - and used to be dropped, so the panel's replay saw one row fewer
	// per day than analyzer/replay.py (found by the replay parity test).
	if ($pos <= 0 && trim($buffer) !== '' && $result['scanned_lines'] < GP_MAX_SCAN_LINES) {
		$result['scanned_lines']++;
		$row = json_decode(trim($buffer), true);
		if (is_array($row) && !(isset($row['o']) && $row['o'] === 1)) { $rows[] = $row; }
	}
	if ($scanned >= GP_MAX_SCAN_BYTES || $result['scanned_lines'] >= GP_MAX_SCAN_LINES) {
		$result['capped'] = true;
	}

	// First pass: label identities from evidence independent of the gate.
	foreach ($rows as $row) {
		$key = gp_identity_key($row);
		if ($key === '') { continue; }
		if ((int)($row['hp'] ?? 0) === 1 || (string)($row['botv'] ?? '') === 'bad') {
			$labels[$key] = 1;
		} elseif ((string)($row['act'] ?? '') === 'token_issued'     // not the shadowed handshake acts
			&& !isset($labels[$key])) {
			$labels[$key] = 0;
		}
	}

	// Second pass: replay the decision.
	$non_decision = gp_replay_non_decision();
	$actions = gp_replay_actions();
	foreach ($rows as $row) {
		$act = (string)($row['act'] ?? '');
		if (in_array($act, $non_decision, true) || !in_array($act, $actions, true)) {
			$result['skipped']++;
			continue;
		}
		$sc  = (int)($row['sc'] ?? 0);
		$rep = (int)($row['rep'] ?? 0);
		$ml  = isset($row['ml']) ? (int)$row['ml'] : -1;
		$clf = isset($row['clf']) ? (int)$row['clf'] : -1;
		$over = $act === '429';
		// Schema 5 logs the gate the guard decided on; older rows have only nav.
		$nav = (int)($row['gate'] ?? $row['nav'] ?? 0) === 1;
		$tok = (string)($row['tok'] ?? 'm');
		$ovr = (string)($row['ovr'] ?? '');

		$base_esc = gv_effective_score($sc, $rep, $ml, $clf, $baseline);
		$cand_esc = gv_effective_score($sc, $rep, $ml, $clf, $candidate);
		$base_act = gv_decide($base_esc, $over, $nav, $tok, $base_hard, $ovr);
		$cand_act = gv_decide($cand_esc, $over, $nav, $tok, $cand_hard, $ovr);

		$result['considered']++;
		$result['baseline'][$base_act] = ($result['baseline'][$base_act] ?? 0) + 1;
		$result['candidate'][$cand_act] = ($result['candidate'][$cand_act] ?? 0) + 1;
		if ($base_esc !== $cand_esc) { $result['esc_changed']++; }
		if ($base_act !== $cand_act) {
			$move = $base_act . '->' . $cand_act;
			$result['movement'][$move] = ($result['movement'][$move] ?? 0) + 1;
		}

		$stricter = gp_replay_severity($cand_act) > gp_replay_severity($base_act);
		$key = gp_identity_key($row);
		$label = isset($labels[$key]) ? $labels[$key] : null;
		if ($label === 1) {
			$result['bot_rows']++;
			if ($stricter) { $result['bot_newly']++; }
		} elseif ($label === 0) {
			$result['human_rows']++;
			if ($stricter) { $result['human_newly']++; }
		}
		if ((int)($row['hold'] ?? 0) === 1) {
			$result['holdout_rows']++;
			if ($stricter) { $result['holdout_newly']++; }
		}
	}
}

// Session key: the device id when present, else ip|uah. Mirrors
// analyzer/logs.py session_key().
function gp_identity_key(array $row) {
	$dev = (string)($row['dev'] ?? '');
	if ($dev !== '') { return $dev; }
	$ip = (string)($row['ip'] ?? '');
	$uah = (string)($row['uah'] ?? '');
	if ($ip === '' && $uah === '') { return ''; }
	return $ip . '|' . $uah;
}
