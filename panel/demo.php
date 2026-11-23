<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// The Demo role's dashboard: a SEPARATE, data-minimised view model built on the server.
//
// The page for the demo role is rendered from the array this function returns, and nothing else: numbers and a few fixed
// enum words. The snapshot, the log rows, the rules, the lists and the job status are read here and reduced to counts; the
// request handler never hands them to the demo view, so the sensitive fields do not reach the response at all (not hidden
// with CSS, not in HTML comments, not in JSON). No IP address, device id, User-Agent, path, query string, country or ASN of a
// client, rule pattern, list entry, log row, error text, job output, file path, host name, setting value, audit entry or the
// name of another user can be in it, because no function below ever reads such a value into the result.

// The only KPI keys the demo page shows: counts and rates, never a name.
function gp_demo_kpi_keys() {
	return array('requests', 'allowed', 'blocked', 'limited', 'challenged', 'challenge_success', 'rule_hits', 'honeypot', 'degraded',
		'captcha_shown', 'captcha_solved', 'captcha_failed', 'captcha_expired', 'captcha_solve_rate', 'would_act');
}

// $in (all optional, for tests): snapshot, cfg, rules, lists, jobs, now. Defaults read the live data.
function gp_demo_model(array $in = array()) {
	$now = isset($in['now']) ? (int)$in['now'] : time();
	$snap = array_key_exists('snapshot', $in) ? $in['snapshot'] : gp_snapshot();
	$snap = is_array($snap) ? $snap : array();
	$cfg = isset($in['cfg']) ? $in['cfg'] : gv_cfg_load();
	$rules = isset($in['rules']) ? $in['rules'] : gp_rules_state()['rules'];
	$lists = isset($in['lists']) ? $in['lists'] : gp_iplists_state()['lists'];
	$jobs = isset($in['jobs']) ? $in['jobs'] : gp_job_health($now);

	$kpi = isset($snap['kpi']) && is_array($snap['kpi']) ? $snap['kpi'] : array();
	$cur = isset($kpi['cur']) && is_array($kpi['cur']) ? $kpi['cur'] : array();
	$prev = isset($kpi['prev']) && is_array($kpi['prev']) ? $kpi['prev'] : array();
	$tiles = array();
	foreach (gp_demo_kpi_keys() as $k) {
		$c = (isset($cur[$k]) && is_numeric($cur[$k])) ? (float)$cur[$k] : null;
		$p = (isset($prev[$k]) && is_numeric($prev[$k])) ? (float)$prev[$k] : null;
		$tiles[$k] = array('cur' => $c, 'prev' => $p, 'change' => gp_demo_change($c, $p));
	}
	$gen = isset($snap['generated_at']) && is_numeric($snap['generated_at']) ? (float)$snap['generated_at'] : 0.0;

	$mode = gp_protection_mode(is_array($cfg) ? $cfg : array(), is_array($rules) ? $rules : array());
	$protection = in_array($mode['mode'], array('monitor', 'partial', 'enforcing'), true) ? $mode['mode'] : 'monitor';

	$rn = 0; $re = 0;
	foreach ((array)$rules as $r) { $rn++; if (!empty($r['enabled'])) { $re++; } }
	$ln = 0; $le = 0;
	foreach ((array)$lists as $l) { $ln++; if (!empty($l['enabled'])) { $le++; } }
	$ok = 0; $bad = 0;
	foreach ((array)$jobs as $h) {
		$state = isset($h['state']) ? $h['state'] : '';
		if ($state === 'ok') { $ok++; }
		elseif (in_array($state, array('failing', 'late', 'warning'), true) || ($state === 'skipped' && !empty($h['required'])) || ($state === 'never' && !empty($h['required']))) { $bad++; }
	}
	// The main chart: hourly COUNTS only (an hour, five outcome counts, a distinct-address count). Nothing else from the dash block is read.
	$chart = array('h24' => array(), 'd7' => array());
	$dash = gp_dash_block($snap);
	foreach (array('h24' => 'hours', 'd7' => 'days7') as $ck => $dk) {
		foreach ((isset($dash[$dk]) && is_array($dash[$dk])) ? $dash[$dk] : array() as $b) {
			if (!is_array($b)) { continue; }
			$row = array();
			foreach (array('t', 'n', 'a', 'c', 'p', 'b', 'r', 'm', 'ips') as $f) { $row[$f] = isset($b[$f]) && is_numeric($b[$f]) ? (int)$b[$f] : 0; }
			$chart[$ck][] = $row;
		}
	}
	return array('generated' => (int)$gen, 'chart' => $chart, 'stale' => ($gen > 0 && ($now - $gen) > 3600), 'has_data' => ($cur !== array()),
		'kpi' => $tiles, 'protection' => $protection,
		'counts' => array('rules_total' => $rn, 'rules_enabled' => $re, 'lists_total' => $ln, 'lists_enabled' => $le,
			'jobs_healthy' => $ok, 'jobs_unhealthy' => $bad));
}

// "+12.0 %" / "-3.0 %" / "new" / "" for a count against the previous period; a rate shows in points. Numbers only.
function gp_demo_change($cur, $prev) {
	if ($cur === null || $prev === null) { return ''; }
	if ($prev == 0.0) { return $cur == 0.0 ? '0 %' : 'new'; }
	return sprintf('%+.1f %%', ($cur - $prev) / abs($prev) * 100);
}
