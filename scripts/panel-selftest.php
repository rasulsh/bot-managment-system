<?php
// Bot Guard admin panel self-test. Run: php scripts/panel-selftest.php
// Exit code 0 when every non-SKIP assertion passes, 1 otherwise.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

define('GV_BOOT', 1);
define('GP_BOOT', 1);
define('GP_SELFTEST', 1);

require __DIR__ . '/../guard/guard.php';
require __DIR__ . '/../panel/config_io.php';

$GP_PASS = 0;
$GP_FAIL = 0;
$GP_SKIP = 0;

function t_ok($name, $cond) {
	global $GP_PASS, $GP_FAIL;
	if ($cond) { $GP_PASS++; echo "PASS  " . $name . "\n"; }
	else { $GP_FAIL++; echo "FAIL  " . $name . "\n"; }
}

function t_skip($name, $why) {
	global $GP_SKIP;
	$GP_SKIP++;
	echo "SKIP  " . $name . " (" . $why . ")\n";
}

function t_section($name) { echo "\n-- " . $name . "\n"; }

// The overlay lives at a fixed path next to guard/config.php. The tests below
// write and remove it, so refuse to run if the operator already has one.
$overlay = gv_overlay_path();
$overlay_backup = null;
if (is_file($overlay)) {
	$overlay_backup = file_get_contents($overlay);
}

function t_write_overlay($raw) {
	file_put_contents(gv_overlay_path(), $raw);
}

function t_clear_overlay() {
	if (is_file(gv_overlay_path())) { @unlink(gv_overlay_path()); }
}

t_clear_overlay();

// --------------------------------------------------------------------------
t_section('Overlay merge precedence');

$base = gv_cfg_load();
t_ok('a missing overlay is ignored silently', is_array($base) && isset($base['hard_block_score']));
$php_score = $base['hard_block_score'];

t_write_overlay(json_encode(array('hard_block_score' => 55)));
$merged = gv_cfg_load();
t_ok('the overlay overrides the PHP config', $merged['hard_block_score'] === 55);
t_ok('unrelated keys keep their PHP values',
	$merged['cookie_name'] === $base['cookie_name']);

t_write_overlay(json_encode(array('enforce.block' => true, 'signals.clf' => true,
	'limits.window' => 120)));
$merged = gv_cfg_load();
t_ok('dotted keys resolve into nested config',
	$merged['signals']['clf'] === true && $merged['limits']['window'] === 120);
t_ok('sibling nested keys are untouched',
	$merged['signals']['ml'] === false
	&& $merged['limits']['device'] === $base['limits']['device']);

// The CHANGE_ME safety rule must still win over an overlay that enables things:
// the overlay is applied BEFORE that check, so an operator cannot turn on
// enforcement from the panel while the guard is still unconfigured.
t_ok('an unconfigured secret still forces monitor mode even from the overlay',
	((string)$merged['secret'] === 'CHANGE_ME')
		? $merged['enforce']['block'] === false
		: $merged['enforce']['block'] === true);

t_clear_overlay();
t_ok('removing the overlay restores the PHP value',
	gv_cfg_load()['hard_block_score'] === $php_score);

// --------------------------------------------------------------------------
t_section('Overlay is never fatal');

foreach (array(
	'not json at all'          => 'this is not json {',
	'a JSON list'              => '[1,2,3]',
	'a bare scalar'            => '"hello"',
	'a JSON null'              => 'null',
	'an empty file'            => '',
	'a truncated object'       => '{"hard_block_score": 5',
) as $label => $raw) {
	t_write_overlay($raw);
	$cfg = gv_cfg_load();
	t_ok('the guard still loads with ' . $label,
		is_array($cfg) && $cfg['hard_block_score'] === $php_score);
}

t_write_overlay(json_encode(array('hard_block_score' => 77, 'garbage_key' => 'x',
	'ml_weight' => 'not a number', 'limits.device' => 900)));
$cfg = gv_cfg_load();
t_ok('a valid key is kept alongside invalid ones', $cfg['hard_block_score'] === 77);
t_ok('an unknown key is discarded', !isset($cfg['garbage_key']));
t_ok('a wrong-typed key is discarded individually, not the whole file',
	$cfg['ml_weight'] === $base['ml_weight'] && $cfg['limits']['device'] === 900);

t_clear_overlay();

// --------------------------------------------------------------------------
t_section('Secrets are unreachable through the overlay');

$secret_before = $base['secret'];
$salt_before = $base['holdout_salt'];
t_write_overlay(json_encode(array(
	'secret' => 'attacker-chosen-secret',
	'holdout_salt' => 'attacker-chosen-salt',
	'panel.password_hash' => 'x',
	'session_secret' => 'x',
)));
$cfg = gv_cfg_load();
t_ok('secret cannot be set through the overlay', $cfg['secret'] === $secret_before);
t_ok('holdout_salt cannot be set through the overlay', $cfg['holdout_salt'] === $salt_before);
t_ok('no panel credential key leaks into the guard config',
	!isset($cfg['session_secret']) && !isset($cfg['panel']));
t_ok('secret is not on the whitelist',
	!isset(gv_overlay_whitelist()['secret']));
t_ok('holdout_salt is not on the whitelist',
	!isset(gv_overlay_whitelist()['holdout_salt']));
t_ok('gv_overlay_validate refuses secret outright',
	gv_overlay_validate('secret', 'x') === array(false, 'unknown_key'));
t_clear_overlay();

// --------------------------------------------------------------------------
t_section('Whitelist bounds');

$cases = array(
	// key, value, expected_ok
	array('hard_block_score', 10, true),
	array('hard_block_score', 200, true),
	array('hard_block_score', 9, false),
	array('hard_block_score', 201, false),
	array('hard_block_score', 60.5, false),
	array('hard_block_score', '60', false),
	array('hard_block_score', true, false),
	array('ml_weight', 0.0, true),
	array('ml_weight', 2.0, true),
	array('ml_weight', 1, true),
	array('ml_weight', -0.1, false),
	array('ml_weight', 2.1, false),
	array('clf_weight', 0.5, true),
	array('limits.window', 30, true),
	array('limits.window', 3600, true),
	array('limits.window', 29, false),
	array('limits.window', 3601, false),
	array('limits.device', 1, true),
	array('limits.device', 100000, true),
	array('limits.device', 0, false),
	array('limits.device', 100001, false),
	array('limits.ip_ua', 500, true),
	array('limits.ip', 1200, true),
	array('limits.bot', 600, true),
	array('holdout_pct', 0, true),
	array('holdout_pct', 5, true),
	array('holdout_pct', 6, false),
	array('holdout_pct', -1, false),
	array('capture_outcomes', true, true),
	array('capture_outcomes', 1, false),
	array('enforce.block', false, true),
	array('enforce.challenge', 'yes', false),
	array('signals.reputation', true, true),
	array('signals.ml', true, true),
	array('signals.clf', false, true),
	array('honeypot_path', '/old-archive', true),
	array('honeypot_path', 'old-archive', false),
	array('honeypot_path', '/' . str_repeat('a', 100), false),
	array('honeypot_path', '', false),
	array('exempt_paths', array('/wp-cron.php', '/api/'), true),
	array('exempt_paths', array('no-slash'), false),
	array('exempt_paths', array('/' . str_repeat('a', 200)), false),
	array('exempt_paths', array_fill(0, 51, '/x'), false),
	array('exempt_paths', array('a' => '/x'), false),
	array('exempt_paths', 'not-a-list', false),
	array('known_bots', array('googlebot', 'bingbot'), true),
	array('known_bots', array('Googlebot'), false),
	array('known_bots', array('bad bot'), false),
	array('known_bots', array_fill(0, 21, 'x'), false),
	array('exempt_params', array('route' => array('payment/', 'api/')), true),
	array('exempt_params', array('route' => 'not-a-list'), false),
	array('exempt_params', array('route' => array_fill(0, 51, 'x')), false),
	array('unknown_key_entirely', 1, false),
);
$bad = array();
foreach ($cases as $case) {
	$got = gv_overlay_validate($case[0], $case[1]);
	if ($got[0] !== $case[2]) {
		$bad[] = $case[0] . '=' . json_encode($case[1]);
	}
}
t_ok('every whitelist bound behaves as documented (' . count($cases) . ' cases)'
	. ($bad ? ' - failed: ' . implode(', ', array_slice($bad, 0, 4)) : ''), !$bad);
t_ok('out-of-range values are rejected, never clamped',
	gv_overlay_validate('hard_block_score', 500) === array(false, 'out_of_range'));

// --------------------------------------------------------------------------
t_section('Atomic write and audit trail');

$audit_backup = is_file(gp_audit_path()) ? file_get_contents(gp_audit_path()) : null;
if (is_file(gp_audit_path())) { @unlink(gp_audit_path()); }

$res = gp_config_save(array('hard_block_score' => 45, 'signals.ml' => true),
	'tester', '203.0.113.9');
t_ok('a valid save succeeds', $res['ok'] === true);
t_ok('the overlay file now exists', is_file(gv_overlay_path()));
t_ok('the saved values are in force',
	gv_cfg_load()['hard_block_score'] === 45 && gv_cfg_load()['signals']['ml'] === true);
t_ok('the overlay file is valid JSON object',
	is_array(json_decode(file_get_contents(gv_overlay_path()), true)));
$perms = substr(sprintf('%o', fileperms(gv_overlay_path())), -4);
t_ok('the overlay is written 0640 (got ' . $perms . ')', $perms === '0640');
t_ok('no temporary file is left behind',
	count(glob(dirname(gv_overlay_path()) . '/config.local.json.tmp*')) === 0);

$bad_save = gp_config_save(array('hard_block_score' => 9999), 'tester', '203.0.113.9');
t_ok('an out-of-range save is refused', $bad_save['ok'] === false);
t_ok('the refusal names the offending key and reason',
	($bad_save['errors']['hard_block_score'] ?? '') === 'out_of_range');
t_ok('a refused save changes nothing', gv_cfg_load()['hard_block_score'] === 45);

$mixed = gp_config_save(array('holdout_pct' => 2, 'ml_weight' => 99.0),
	'tester', '203.0.113.9');
t_ok('one bad key rejects the whole form rather than half-applying it',
	$mixed['ok'] === false && gv_cfg_load()['holdout_pct'] === 0);

$audit = gp_audit_read(50);
t_ok('the audit trail recorded the accepted change', count($audit) >= 2);
$first = $audit ? $audit[0] : array();
t_ok('an audit line carries ts, actor, key, old, new and ip',
	isset($first['ts'], $first['actor'], $first['key'], $first['ip'])
	&& array_key_exists('old', $first) && array_key_exists('new', $first));
t_ok('the audit line records the actor and client ip',
	$first['actor'] === 'tester' && $first['ip'] === '203.0.113.9');
t_ok('a refused change is not audited',
	count(array_filter($audit, function ($r) { return ($r['new'] ?? null) === 9999; })) === 0);

t_ok('resetting a key removes it from the overlay',
	gp_config_reset('hard_block_score', 'tester', '203.0.113.9')
	&& !array_key_exists('hard_block_score', gp_overlay_current()));
t_ok('a reset is audited',
	count(array_filter(gp_audit_read(50),
		function ($r) { return ($r['event'] ?? '') === 'config_reset'; })) === 1);

$diff = gp_overlay_diff(array('holdout_pct' => 3));
t_ok('the diff reports the pending change',
	count($diff) === 1 && $diff[0]['key'] === 'holdout_pct' && $diff[0]['new'] === 3);
t_ok('the diff is empty when nothing would change',
	gp_overlay_diff(array('signals.ml' => true)) === array());

t_clear_overlay();
if (is_file(gp_audit_path())) { @unlink(gp_audit_path()); }
if ($audit_backup !== null) { file_put_contents(gp_audit_path(), $audit_backup); }

// --------------------------------------------------------------------------
t_section('Bounded tail reader');

$tmp = sys_get_temp_dir() . '/gp-tail-' . getmypid() . '.txt';
$fh = fopen($tmp, 'w');
for ($i = 0; $i < 5000; $i++) { fwrite($fh, 'line-' . $i . "\n"); }
fclose($fh);
$tail = gp_tail_lines($tmp, 10, 1048576);
t_ok('the tail reader returns the requested number of lines', count($tail) >= 10);
t_ok('the tail reader returns the newest lines',
	in_array('line-4999', $tail, true));
$capped = gp_tail_lines($tmp, 100000, 4096);
t_ok('the tail reader honours its byte cap', count($capped) < 5000);
t_ok('a missing file yields nothing', gp_tail_lines($tmp . '.absent', 10, 1000) === array());
@unlink($tmp);

// --------------------------------------------------------------------------
t_section('No shell execution anywhere under panel/');

$forbidden = array('exec', 'shell_exec', 'system', 'passthru', 'proc_open',
	'popen', 'pcntl_exec', 'assert', 'create_function');
$panel_dir = __DIR__ . '/../panel';
$hits = array();
$backticks = array();
$files = array();
if (is_dir($panel_dir)) {
	$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($panel_dir));
	foreach ($it as $file) {
		if (!$file->isFile()) { continue; }
		if (substr($file->getFilename(), -4) !== '.php') { continue; }
		$files[] = $file->getPathname();
	}
}
foreach ($files as $file) {
	foreach (token_get_all(file_get_contents($file)) as $tk) {
		if (is_array($tk)) {
			if ($tk[0] === T_STRING && in_array(strtolower($tk[1]), $forbidden, true)) {
				$hits[] = basename($file) . ':' . $tk[1];
			}
			if (defined('T_SHELL_EXEC') && $tk[0] === T_SHELL_EXEC) {
				$backticks[] = basename($file);
			}
		} elseif ($tk === '`') {
			$backticks[] = basename($file);
		}
	}
}
t_ok('panel/ contains PHP files to scan (' . count($files) . ')', count($files) > 0);
t_ok('no shell-execution function appears under panel/'
	. ($hits ? ' - found: ' . implode(', ', array_slice($hits, 0, 5)) : ''), !$hits);
t_ok('no backtick operator appears under panel/', !$backticks);

$evals = array();
foreach ($files as $file) {
	foreach (token_get_all(file_get_contents($file)) as $tk) {
		if (is_array($tk) && $tk[0] === T_EVAL) { $evals[] = basename($file); }
	}
}
t_ok('no eval appears under panel/', !$evals);

// --------------------------------------------------------------------------
// Restore whatever the operator had before this ran.
t_clear_overlay();
if ($overlay_backup !== null) { file_put_contents($overlay, $overlay_backup); }

echo "\n";
echo "PASS " . $GP_PASS . "  FAIL " . $GP_FAIL . "  SKIP " . $GP_SKIP . "\n";
exit($GP_FAIL === 0 ? 0 : 1);
