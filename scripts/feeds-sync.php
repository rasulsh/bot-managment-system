<?php
// Fetch the IP range feeds that are due (the cron job behind `analyzer-cron.sh feeds`).
//
//   php scripts/feeds-sync.php               every enabled feed whose schedule (daily / weekly) is due
//   php scripts/feeds-sync.php --id <feed>   that feed now, whatever its schedule
//   php scripts/feeds-sync.php --list        one line per feed: destination, schedule, last run, state
//
// Prints one line per feed and exits 1 when a feed failed (the job-health page then shows the run as failed; the last good entries stay in
// force). The panel's Feeds tab does the same with its Update button; the logic is panel/feeds.php.
// The CLI, or a CGI build of php run from a shell (see scripts/config-dump.php).
if (!(PHP_SAPI === 'cli' || (strncmp(PHP_SAPI, 'cgi', 3) === 0 && !isset($_SERVER['REQUEST_METHOD']) && !isset($_SERVER['REMOTE_ADDR'])))) { exit; }
if (PHP_VERSION_ID < 80000) { fwrite(STDERR, 'Bot Guard requires PHP 8.0 or newer (found ' . PHP_VERSION . ").\n"); exit(1); }

define('GV_BOOT', 1);
define('GV_NO_AUTORUN', 1);
define('GP_BOOT', 1);
$root = dirname(__DIR__);
require_once $root . '/guard/guard.php';
foreach (array('config_io', 'auth', 'data', 'jobs', 'health', 'filters', 'ui', 'rules', 'geo', 'iplists', 'feeds') as $lib) { require_once $root . '/panel/' . $lib . '.php'; }
$GP_LANG = require $root . '/panel/lang.php';
if (!function_exists('gp_t')) {
	function gp_t($key) { global $GP_LANG; return isset($GP_LANG[$key]) ? $GP_LANG[$key] : $key; }
}

$args = isset($argv) && is_array($argv) ? array_slice($argv, 1) : array();
$fs = gp_feeds_state();
if ($fs['state'] === 'invalid') { fwrite(STDERR, "lists/feeds.json is not valid: nothing was fetched.\n"); exit(1); }

if (in_array('--list', $args, true)) {
	foreach ($fs['feeds'] as $f) {
		echo $f['id'] . '  ' . $f['dest'] . '  ' . ($f['enabled'] ? 'on' : 'off') . '  ' . $f['schedule'] . '  last run '
			. ($f['st']['last_run'] ? gmdate('Y-m-d H:i', $f['st']['last_run']) . ' UTC' : 'never') . '  ' . ($f['st']['error'] !== '' ? 'ERROR ' . $f['st']['error'] : ($f['st']['held'] !== '' ? 'HELD' : 'ok')) . "\n";
	}
	exit(0);
}

$one = '';
foreach ($args as $i => $a) { if ($a === '--id' && isset($args[$i + 1])) { $one = (string)$args[$i + 1]; } }
if ($one !== '') {
	$r = gp_feed_sync($one, 'feeds-cron', '');
	echo $one . ': ' . $r['status'] . ($r['ok'] ? ' (+' . $r['added'] . ' -' . $r['removed'] . ' =' . $r['unchanged'] . ')' : ' ' . $r['error'] . ($r['detail'] !== '' ? ' ' . $r['detail'] : '')) . "\n";
	exit($r['ok'] ? 0 : 1);
}

$run = gp_feeds_run_due('feeds-cron');
foreach ($run['lines'] as $l) { echo $l . "\n"; }
if ($run['ran'] === 0) { echo "No feed is due.\n"; }
exit($run['failed'] > 0 ? 1 : 0);
