<?php
// Verifier for scripts/e2e-pipeline.sh. Not meant to be run by hand.
//
//   php scripts/e2e-verify.php <log_dir> <expect.tsv> <snapshot.json>
//
// Reads what the guard wrote and what the panel would show, and compares them
// with what the driver script actually sent.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
if ($argc < 4) { fwrite(STDERR, "usage: e2e-verify.php <log_dir> <expect.tsv> <snapshot.json>\n"); exit(2); }

define('GV_BOOT', 1);
define('GP_BOOT', 1);
define('GV_NO_AUTORUN', 1);
require __DIR__ . '/../guard/guard.php';
require __DIR__ . '/../panel/config_io.php';
require __DIR__ . '/../panel/data.php';

$pass = 0; $fail = 0;
function chk($name, $cond, $detail = '') {
	global $pass, $fail;
	if ($cond) { $pass++; echo "PASS  $name\n"; }
	else { $fail++; echo "FAIL  $name" . ($detail !== '' ? "  [$detail]" : '') . "\n"; }
}

list(, $dir, $expect_file, $snap_file) = $argv;

// --- The file itself ------------------------------------------------------
$files = glob($dir . '/guard-*.jsonl');
chk('exactly one daily log file exists', count($files) === 1, implode(',', array_map('basename', $files)));
$file = $files ? $files[0] : '';
$lines = $file ? file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : array();
$bad = 0; $rows = array(); $outs = array();
foreach ($lines as $l) {
	$r = json_decode($l, true);
	if (!is_array($r)) { $bad++; continue; }
	if (isset($r['o']) && $r['o'] === 1) { $outs[] = $r; } else { $rows[] = $r; }
}
chk('every line is complete JSON (no torn or interleaved writes under concurrency)', $bad === 0, "$bad bad of " . count($lines));
$rids = array_column($rows, 'rid');
chk('every decision row has a unique request id', count($rids) === count(array_unique($rids)) && !in_array('', $rids, true));
foreach ($outs as $o) {
	if (!isset($o['rid'])) { $bad++; }
}
$known = array_flip($rids);
$orphans = 0;
foreach ($outs as $o) { if (!isset($known[$o['rid'] ?? ''])) { $orphans++; } }
chk('every outcome line belongs to a decision row', $orphans === 0, "$orphans orphans");

// --- Per scenario ---------------------------------------------------------
$by = array();
foreach ($rows as $r) {
	if (preg_match('/(?:^|&)t=([a-z0-9]+)/', (string)($r['q'] ?? ''), $m)) { $by[$m[1]][] = $r; }
}
foreach (file($expect_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
	list($label, $want_rows, $want_ips, $want_devs) = explode("\t", $line);
	$got = isset($by[$label]) ? $by[$label] : array();
	chk("[$label] $want_rows requests were captured (got " . count($got) . ')', count($got) === (int)$want_rows);
	$ips = array_unique(array_column($got, 'ip'));
	chk("[$label] $want_ips distinct client addresses were recorded (got " . count($ips) . ')', count($ips) === (int)$want_ips, implode(',', $ips));
}

// IPv4 addresses are recorded exactly as the client connected from.
$ips_scn = array_unique(array_column(isset($by['ips']) ? $by['ips'] : array(), 'ip'));
sort($ips_scn);
chk('[ips] the recorded addresses are the ones used', $ips_scn === array('127.0.0.11', '127.0.0.12', '127.0.0.13', '127.0.0.14', '127.0.0.15'), implode(',', $ips_scn));

// Sessions: the tabs of one browser share ONE device id, another browser has its own.
$dev1 = array_unique(array_filter(array_column(array_filter(isset($by['tabs']) ? $by['tabs'] : array(), function ($r) { return $r['tok'] === 'v'; }), 'dev')));
$dev2 = array_unique(array_filter(array_column(array_filter(isset($by['tabs2']) ? $by['tabs2'] : array(), function ($r) { return $r['tok'] === 'v'; }), 'dev')));
chk('[tabs] all tabs of one browser share one device id', count($dev1) === 1, implode(',', $dev1));
chk('[tabs2] a second browser has its own device id', count($dev2) === 1 && $dev1 && $dev2 && current($dev1) !== current($dev2));
$tab_v = count(array_filter(isset($by['tabs']) ? $by['tabs'] : array(), function ($r) { return $r['tok'] === 'v'; }));
chk('[tabs] all six parallel tabs carried a valid token', $tab_v >= 6, "tok=v rows: $tab_v");
$issued = count(array_filter(isset($by['tabs']) ? $by['tabs'] : array(), function ($r) { return $r['act'] === 'token_issued'; }));
chk('[tabs] exactly one token was issued for the first browser', $issued === 1, "issued: $issued");

$acts_exempt = isset($by['exempt']) ? array_column($by['exempt'], 'act') : array();
chk('[exempt] an exempt path is still logged, as act=exempt', $acts_exempt === array('exempt'), implode(',', $acts_exempt));
$hm = isset($by['head']) ? array_column($by['head'], 'm') : array();
chk('[head] the HTTP method is recorded', $hm === array('HEAD'), implode(',', $hm));

// --- The panel's own readers ---------------------------------------------
$all = array(); $cursor = 0; $pages = 0;
do {
	list($page, $meta) = gp_log_query(array(), $cursor, 50);
	foreach ($page as $r) { $all[] = $r; }
	$cursor = $meta['next_cursor'];
	$pages++;
} while ($cursor !== null && $pages < 100);
$all_rids = array_column($all, 'rid');
chk('panel: paging through the log returns every decision row, once (' . count($all) . ' of ' . count($rows) . ')',
	count($all) === count($rows) && count($all_rids) === count(array_unique($all_rids)));
list($p1) = gp_log_query(array('ip' => '127.0.0.11'), 0, 200);
chk('panel: the address filter returns that address\'s 3 requests', count($p1) === 3, 'got ' . count($p1));
list($p2) = gp_log_query(array('path' => '/t/404'), 0, 50);
$st404 = $p2 ? ((isset($p2[0]['_out']['st'])) ? $p2[0]['_out']['st'] : null) : null;
chk('panel: the application 404 is shown with its outcome status', count($p2) === 1 && $st404 === 404, 'status ' . var_export($st404, true));
list($p3) = gp_log_query(array('status' => '404'), 0, 50);
chk('panel: the status filter finds the 404', count($p3) === 1, 'got ' . count($p3));
list($p4) = gp_log_query(array('act' => 'challenge'), 0, 200);
chk('panel: the action filter finds challenge rows', count($p4) > 0);

// --- The snapshot the dashboard reads ------------------------------------
$snap = json_decode((string)@file_get_contents($snap_file), true);
chk('snapshot file was written and parses', is_array($snap));
if (is_array($snap)) {
	$t = isset($snap['traffic']) ? $snap['traffic'] : array();
	chk('snapshot: request count equals the decision rows in the log (' . (isset($t['requests']) ? $t['requests'] : '?') . ' of ' . count($rows) . ')',
		isset($t['requests']) && (int)$t['requests'] === count($rows));
	$want_addr = count(array_unique(array_column($rows, 'ip')));
	chk('snapshot: unique addresses equals the distinct addresses in the log (' . (isset($t['addresses']) ? $t['addresses'] : '?') . ' of ' . $want_addr . ')',
		isset($t['addresses']) && (int)$t['addresses'] === $want_addr);
	$want_dev = count(array_unique(array_filter(array_column($rows, 'dev'))));
	chk('snapshot: unique devices equals the distinct devices in the log (' . (isset($t['devices']) ? $t['devices'] : '?') . ' of ' . $want_dev . ')',
		isset($t['devices']) && (int)$t['devices'] === $want_dev);
	chk('snapshot: has a generated_at timestamp', !empty($snap['generated_at']));
}

echo "\nPASS $pass  FAIL $fail\n";
exit($fail === 0 ? 0 : 1);
