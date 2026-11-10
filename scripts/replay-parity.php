<?php
// Test helper: run the PANEL's replay over a log directory and print its totals
// as JSON, so analyzer/selftest.py can compare them with analyzer/replay.py on
// the very same rows.
//
//   php scripts/replay-parity.php <log_dir> <hard_block_score> <signals csv: reputation,ml,clf>
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
if (PHP_VERSION_ID < 80000) { fwrite(STDERR, 'Bot Guard requires PHP 8.0 or newer (found ' . PHP_VERSION . ").\n"); exit(1); }
define('GV_BOOT', 1);
define('GP_BOOT', 1);
define('GP_SELFTEST', 1);
if ($argc < 4) { fwrite(STDERR, "usage: replay-parity.php <log_dir> <hard_block_score> <signals>\n"); exit(2); }

$cfgfile = sys_get_temp_dir() . '/gv-replay-parity-' . getmypid() . '.php';
file_put_contents($cfgfile, '<?php if (!defined("GV_BOOT")) { exit; } return ' . var_export(array(
	'secret' => 'x', 'log_dir' => $argv[1], 'hard_block_score' => 60,
	'signals' => array('reputation' => false, 'ml' => false, 'clf' => false),
), true) . ';');
putenv('GV_CONFIG=' . $cfgfile);
require __DIR__ . '/../guard/guard.php';
require __DIR__ . '/../panel/config_io.php';
require __DIR__ . '/../panel/replay.php';

$signals = array_filter(explode(',', $argv[3]));
$params = array(
	'hard_block_score'   => (int)$argv[2],
	'ml_weight'          => 0.4,
	'clf_weight'         => 0.5,
	'days'               => 14,
	'signals_reputation' => in_array('reputation', $signals, true),
	'signals_ml'         => in_array('ml', $signals, true),
	'signals_clf'        => in_array('clf', $signals, true),
);
$r = gp_replay_run($params);
@unlink($cfgfile);
echo json_encode(array('considered' => $r['considered'], 'skipped' => $r['skipped'],
	'esc_changed' => $r['esc_changed'], 'baseline' => $r['baseline'], 'candidate' => $r['candidate'])) . "\n";
