<?php
// Emit the guard's decision matrix as JSON so the Python mirror can be checked
// against it case by case.
//
//   php scripts/decision-parity.php --emit
//
// The decision logic exists in two languages: gv_effective_score/gv_decide in
// PHP, and analyzer/decision.py in Python. That duplication is a maintenance
// hazard, and this harness is the whole reason it is acceptable - the Python
// self-test runs this command and asserts an exact match on every case, so the
// two can never drift silently.
if (PHP_SAPI !== 'cli') { exit; }
if (PHP_VERSION_ID < 80000) { fwrite(STDERR, 'Bot Guard requires PHP 8.0 or newer (found ' . PHP_VERSION . ").\n"); exit(1); }

define('GV_BOOT', 1);
require __DIR__ . '/../guard/guard.php';

$gv_emit = false;
if (isset($argv) && is_array($argv)) {
	foreach ($argv as $gv_a) {
		if ($gv_a === '--emit') { $gv_emit = true; }
		if ($gv_a === '--help' || $gv_a === '-h') {
			fwrite(STDERR, "Usage: php scripts/decision-parity.php --emit\n");
			exit(0);
		}
	}
}
if (!$gv_emit) {
	fwrite(STDERR, "Usage: php scripts/decision-parity.php --emit\n");
	exit(2);
}

// Build a config carrying only the keys the two mirrored functions read.
function gvp_cfg($reputation, $ml, $clf, $ml_weight = 0.4, $clf_weight = 0.5) {
	return array(
		'signals'    => array('reputation' => $reputation, 'ml' => $ml, 'clf' => $clf),
		'ml_weight'  => $ml_weight,
		'clf_weight' => $clf_weight,
	);
}

$gv_cases = array();

// Add one case: the inputs, plus the two values PHP computes from them.
function gvp_add(&$cases, $sc, $rep, $ml, $clf, array $cfg, $over, $nav, $tok, $ovr, $hard) {
	$esc = gv_effective_score($sc, $rep, $ml, $clf, $cfg);
	$cases[] = array(
		'sc'   => (int)$sc,
		'rep'  => (int)$rep,
		'ml'   => (int)$ml,
		'clf'  => (int)$clf,
		'cfg'  => $cfg,
		'over' => (bool)$over,
		'nav'  => (bool)$nav,
		'tok'  => (string)$tok,
		'ovr'  => (string)$ovr,
		'hard_block_score' => (int)$hard,
		'esc'      => (int)$esc,
		'decision' => gv_decide($esc, $over, $nav, $tok, $hard, $ovr),
	);
}

// 1. Every combination of the three signal toggles, against a request that
//    carries all three verdicts. 8 cases.
foreach (array(false, true) as $s_rep) {
	foreach (array(false, true) as $s_ml) {
		foreach (array(false, true) as $s_clf) {
			gvp_add($gv_cases, 20, 30, 60, 40, gvp_cfg($s_rep, $s_ml, $s_clf),
				false, true, 'v', '', 60);
		}
	}
}

// 2. Verdict-absent sentinels: rep 0, ml -1, clf -1 must contribute nothing
//    even with every toggle on. Level 0 is a real verdict worth zero. 6 cases.
$gv_all = gvp_cfg(true, true, true);
gvp_add($gv_cases, 25, 0, -1, -1, $gv_all, false, true, 'v', '', 60);
gvp_add($gv_cases, 25, 0, 0, -1, $gv_all, false, true, 'v', '', 60);
gvp_add($gv_cases, 25, 0, -1, 0, $gv_all, false, true, 'v', '', 60);
gvp_add($gv_cases, 25, 0, 0, 0, $gv_all, false, true, 'v', '', 60);
gvp_add($gv_cases, 25, -20, -1, -1, $gv_all, false, true, 'v', '', 60);
gvp_add($gv_cases, 0, -50, -1, -1, $gv_all, false, true, 'v', '', 60);

// 3. Both sides of hard_block_score, including the exact boundary. 6 cases.
foreach (array(58, 59, 60, 61, 0, 200) as $gv_sc) {
	gvp_add($gv_cases, $gv_sc, 0, -1, -1, $gv_all, false, true, 'v', '', 60);
}

// 4. Every decision branch, and rule precedence between them. 8 cases.
gvp_add($gv_cases, 0, 0, -1, -1, $gv_all, false, true, 'v', '', 60);    // allow
gvp_add($gv_cases, 90, 0, -1, -1, $gv_all, false, true, 'v', '', 60);   // 403
gvp_add($gv_cases, 90, 0, -1, -1, $gv_all, false, false, 'v', '', 60);  // nav gate on 403
gvp_add($gv_cases, 0, 0, -1, -1, $gv_all, true, true, 'v', '', 60);     // 429
gvp_add($gv_cases, 0, 0, -1, -1, $gv_all, false, true, 'm', '', 60);    // challenge
gvp_add($gv_cases, 0, 0, -1, -1, $gv_all, false, true, 'b', '', 60);    // bad token
gvp_add($gv_cases, 0, 0, -1, -1, $gv_all, false, false, 'm', '', 60);   // never challenged
gvp_add($gv_cases, 90, 0, -1, -1, $gv_all, true, true, 'm', '', 60);    // 403 beats 429

// 5. Both override values, against every branch they can pre-empt. 8 cases.
foreach (array('allow', 'deny') as $gv_ovr) {
	gvp_add($gv_cases, 0, 0, -1, -1, $gv_all, false, true, 'v', $gv_ovr, 60);
	gvp_add($gv_cases, 0, 0, -1, -1, $gv_all, true, true, 'v', $gv_ovr, 60);
	gvp_add($gv_cases, 0, 0, -1, -1, $gv_all, false, true, 'm', $gv_ovr, 60);
	gvp_add($gv_cases, 90, 0, -1, -1, $gv_all, false, false, 'v', $gv_ovr, 60);
}

// 6. The holdout-relevant boundary: the two actions a holdout suppresses
//    (403 and challenge) and the one it never does (429), at the threshold.
//    Membership itself is not part of these two functions - the decision is
//    computed first and the holdout is applied at the gate. 6 cases.
gvp_add($gv_cases, 60, 0, -1, -1, $gv_all, false, true, 'v', '', 60);
gvp_add($gv_cases, 59, 0, -1, -1, $gv_all, false, true, 'm', '', 60);
gvp_add($gv_cases, 0, 0, -1, -1, $gv_all, true, true, 'm', '', 60);
gvp_add($gv_cases, 30, 30, -1, -1, $gv_all, false, true, 'v', '', 60);
gvp_add($gv_cases, 30, 0, 75, -1, $gv_all, false, true, 'v', '', 60);
gvp_add($gv_cases, 30, 0, -1, 60, $gv_all, false, true, 'v', '', 60);

// 7. Rounding and non-default weights, where a mirror is most likely to drift.
//    PHP rounds half away from zero; Python's round() is banker's rounding, so
//    these cases are the ones that catch a naive port. 8 cases.
gvp_add($gv_cases, 0, 0, 5, -1, gvp_cfg(false, true, false, 0.1), false, true, 'v', '', 60);
gvp_add($gv_cases, 0, 0, 15, -1, gvp_cfg(false, true, false, 0.1), false, true, 'v', '', 60);
gvp_add($gv_cases, 0, 0, 25, -1, gvp_cfg(false, true, false, 0.1), false, true, 'v', '', 60);
gvp_add($gv_cases, 0, 0, -1, 5, gvp_cfg(false, false, true, 0.4, 0.1), false, true, 'v', '', 60);
gvp_add($gv_cases, 0, 0, -1, 15, gvp_cfg(false, false, true, 0.4, 0.1), false, true, 'v', '', 60);
gvp_add($gv_cases, 0, 0, 3, -1, gvp_cfg(false, true, false, 0.5), false, true, 'v', '', 60);
gvp_add($gv_cases, 0, 0, -1, 7, gvp_cfg(false, false, true, 0.4, 0.5), false, true, 'v', '', 60);
gvp_add($gv_cases, 0, 0, 100, 100, gvp_cfg(false, true, true, 0.37, 0.63), false, true, 'v', '', 60);

// 8. Negative reputation rescuing a scored request, and a non-default
//    hard_block_score. 4 cases.
gvp_add($gv_cases, 70, -20, -1, -1, $gv_all, false, true, 'v', '', 60);
gvp_add($gv_cases, 70, -50, -1, -1, $gv_all, false, true, 'v', '', 60);
gvp_add($gv_cases, 45, 0, -1, -1, $gv_all, false, true, 'v', '', 40);
gvp_add($gv_cases, 35, 0, -1, -1, $gv_all, false, true, 'v', '', 40);

$gv_flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
$gv_out = json_encode($gv_cases, $gv_flags);
if ($gv_out === false) {
	fwrite(STDERR, "ERROR: could not encode the parity matrix as JSON\n");
	exit(2);
}
echo $gv_out . "\n";
