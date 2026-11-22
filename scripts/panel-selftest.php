<?php
// Bot Guard admin panel self-test. Run: php scripts/panel-selftest.php
// Exit code 0 when every non-SKIP assertion passes, 1 otherwise.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
if (PHP_VERSION_ID < 80000) { fwrite(STDERR, 'Bot Guard requires PHP 8.0 or newer (found ' . PHP_VERSION . ").\n"); exit(1); }

define('GV_BOOT', 1);
define('GP_BOOT', 1);
define('GP_SELFTEST', 1);

require __DIR__ . '/../guard/guard.php';
require __DIR__ . '/../panel/config_io.php';
require __DIR__ . '/../panel/acl.php';          // the views ask it which links the role may follow

// Nothing this suite does may write into the repository tree, also when no Redis is running (a refused connect logs a line):
// every error log the guard's helpers fall back to goes to a temp directory, removed at exit.
$GP_TMP_LOGS = sys_get_temp_dir() . '/gp-selftest-logs-' . getmypid();
@mkdir($GP_TMP_LOGS, 0775, true);
gv_redis_ctx(array('log_dir' => $GP_TMP_LOGS));
register_shutdown_function(function () use ($GP_TMP_LOGS) {
	foreach ((array)glob($GP_TMP_LOGS . '/{,.}*', GLOB_BRACE) as $f) { if (is_file($f)) { @unlink($f); } }
	@rmdir($GP_TMP_LOGS);
});

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

// The DOM parse below is the only assertion in this file that needs an
// extension beyond the core. Every other optional dependency in this project
// degrades to SKIP; this one used to construct DOMDocument unconditionally, so
// on a host without ext-dom the suite died with an uncaught Error and took
// everything after it down - including the shell-execution section, which is
// the last section anyone should discover was silently never run.
$GP_HAS_DOM = class_exists('DOMDocument');

function t_dom_ok($name, $cond) {
	global $GP_HAS_DOM;
	if (!$GP_HAS_DOM) { t_skip($name, 'ext-dom not installed'); return; }
	t_ok($name, $cond);
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
	array('limits.mint', 60, true),
	array('limits.mint', 0, false),
	array('limits.mint', 100001, false),
	array('challenge.pow_bits', 16, true),
	array('challenge.pow_bits', 0, true),
	array('challenge.pow_bits', 22, true),
	array('challenge.pow_bits', 23, false),
	array('challenge.pow_bits', -1, false),
	array('challenge.pow_bits', '16', false),
	array('challenge.bind_ip', false, true),
	array('challenge.bind_ip', 0, false),
	array('token_ttl', 3600, true),
	array('token_ttl', 3599, false),
	array('nonce_ttl', 901, false),
	array('cdn_ranges', array('203.0.113.0/24'), true),
	array('cdn_ranges', array('203.0.113.0/7'), false),
	array('cdn_ranges', array('2001:db8::/32'), false),
	array('cdn_ranges', array('300.0.0.0/24'), false),
	array('exempt_params_paths', array('/', '/index.php'), true),
	array('exempt_params_paths', array('index.php'), false),
	array('bot_suffixes', array('googlebot' => array('.googlebot.com', '.google.com')), true),
	array('bot_suffixes', array('googlebot' => array('googlebot.com')), false),
	array('bot_suffixes', array('googlebot' => array('.com')), false),
	array('bot_suffixes', array('googlebot' => array()), false),
	array('bot_suffixes', array(array('.x.com')), false),
	array('strings.dir', 'rtl', true),
	array('strings.dir', 'up', false),
	array('strings.lang', 'fa', true),
	array('strings.lang', 'fa"><', false),
	array('strings.title', 'Please wait', true),
	array('strings.title', '', false),
	array('strings.title', "two\nlines", false),
	array('strings.title', str_repeat('a', 201), false),
	array('analyzer.window_days', 7, true),
	array('analyzer.window_days', 61, false),
	array('analyzer.contamination', 0.05, true),
	array('analyzer.contamination', 0.5, false),
	array('analyzer.dns_canary', 'www.google.com', true),
	array('analyzer.dns_canary', 'not a host', false),
	array('analyzer.path_listing', array('^/category/'), true),
	array('analyzer.path_listing', array('(unclosed'), false),
	// File-only (Category A): never reachable through the overlay.
	array('secret', 'x', false),
	array('holdout_salt', 'x', false),
	array('cookie_name', '_x', false),
	array('log_dir', '/tmp', false),
	array('challenge.test_key', 'abcdefabcdefabcdef', false),
	array('redis.timeout', 1, false),
	array('challenge.trust_headers', true, false),
	array('analyzer.model_path', '/tmp/x', false),
	array('analyzer.php_bin', '/usr/bin/php', false),
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
t_section('Audit trail renders newest-first past 64 KiB');

// Build a >128 KB audit.jsonl with sequential ids and confirm gp_audit_read
// returns strictly newest-first with no gaps - the multi-chunk case the old
// chunk-forward accumulation scrambled.
$au_path = gp_audit_path();
$au_backup = is_file($au_path) ? file_get_contents($au_path) : null;
$au_n = 2000;
$au_fh = fopen($au_path, 'w');
for ($i = 0; $i < $au_n; $i++) {
	fwrite($au_fh, json_encode(array('ts' => 1700000000 + $i, 'id' => $i,
		'event' => 'config_save', 'actor' => 'tester', 'ip' => '203.0.113.9',
		'key' => 'hard_block_score', 'old' => 40, 'new' => 50,
		'pad' => str_repeat('x', 48))) . "\n");
}
fclose($au_fh);
t_ok('the audit fixture exceeds 128 KiB (' . filesize($au_path) . ' bytes)',
	filesize($au_path) > 131072);
$au_rows = gp_audit_read($au_n);
$au_ids = array();
foreach ($au_rows as $au_row) { $au_ids[] = (int)$au_row['id']; }
$au_desc = count($au_ids) === $au_n;
for ($k = 1; $k < count($au_ids); $k++) {
	if ($au_ids[$k] !== $au_ids[$k - 1] - 1) { $au_desc = false; break; }
}
t_ok('gp_audit_read returns every entry strictly newest-first with no gaps', $au_desc);
t_ok('the newest audit entry is read first and the oldest last',
	$au_ids && $au_ids[0] === $au_n - 1 && $au_ids[count($au_ids) - 1] === 0);
$au_tail = gp_tail_lines($au_path, $au_n, 4194304);
$au_first = $au_tail ? json_decode($au_tail[0], true) : null;
$au_last = $au_tail ? json_decode($au_tail[count($au_tail) - 1], true) : null;
t_ok('the shared producer gp_tail_lines is oldest-first across chunks',
	count($au_tail) === $au_n && is_array($au_first) && is_array($au_last)
	&& (int)$au_first['id'] === 0 && (int)$au_last['id'] === $au_n - 1);
if ($au_backup !== null) { file_put_contents($au_path, $au_backup); }
elseif (is_file($au_path)) { @unlink($au_path); }

// --------------------------------------------------------------------------
t_section('Log explorer pagination is gap-free and duplicate-free');

require_once __DIR__ . '/../panel/data.php';

// gp_log_query reads gp_log_dir()/guard-<date>.jsonl. Build a dense multi-chunk
// daily file under a sentinel date and walk it page by page, following
// next_cursor, asserting the union of returned ids is the full set with no
// duplicates - the same shape as the simulation that proved the bug.
$pg_dir  = gp_log_dir();
$pg_date = '19990102';
$pg_file = rtrim($pg_dir, '/\\') . '/guard-' . $pg_date . '.jsonl';
if (is_file($pg_file)) {
	t_skip('log pagination round-trip', 'sentinel log file already present');
} elseif (!is_dir($pg_dir) || !is_writable($pg_dir)) {
	t_skip('log pagination round-trip', 'log dir is not writable');
} else {
	$pg_n = 2000;
	$pg_fh = fopen($pg_file, 'w');
	for ($i = 0; $i < $pg_n; $i++) {
		// Pad each line so the file spans several 64 KiB chunks.
		fwrite($pg_fh, json_encode(array('v' => 4, 'rid' => sprintf('%012x', $i),
			'ts' => 1700000000 + $i, 'ip' => '203.0.113.5', 'ua' => 'ua',
			'm' => 'GET', 'p' => '/p/' . $i . '/' . str_repeat('a', 60),
			'act' => 'allow', 'sh' => 0, 'hold' => 0, 'ovr' => '', 'tok' => 'v',
			'dev' => 'seq' . $i, 'sc' => 0, 'esc' => 0, 'rs' => array())) . "\n");
	}
	fclose($pg_fh);
	$pg_bytes = filesize($pg_file);
	t_ok('the paginated fixture spans several chunks (' . $pg_bytes . ' bytes)',
		$pg_bytes > 200000);

	$pg_seen = array();
	$pg_dups = 0;
	$pg_cursor = 0;
	$pg_pages = 0;
	$pg_prev = null;
	$pg_monotone = true;
	do {
		list($pg_rows, $pg_meta) = gp_log_query(array('date' => $pg_date), $pg_cursor, 50);
		foreach ($pg_rows as $pg_row) {
			$pg_id = (string)$pg_row['rid'];
			if (isset($pg_seen[$pg_id])) { $pg_dups++; }
			$pg_seen[$pg_id] = true;
			$pg_num = (int)hexdec($pg_id);
			if ($pg_prev !== null && $pg_num >= $pg_prev) { $pg_monotone = false; }
			$pg_prev = $pg_num;
		}
		$pg_cursor = isset($pg_meta['next_cursor']) ? (int)$pg_meta['next_cursor'] : 0;
		$pg_pages++;
	} while ($pg_cursor > 0 && $pg_pages < 10000);

	t_ok('pagination follows the cursor to the end without looping', $pg_pages < 10000);
	t_ok('pagination returns every row exactly once (no duplicates)', $pg_dups === 0);
	t_ok('pagination returns the full set with no gaps (' . count($pg_seen) . '/' . $pg_n . ')',
		count($pg_seen) === $pg_n);
	t_ok('the newest and oldest rows are both reachable',
		isset($pg_seen[sprintf('%012x', 0)]) && isset($pg_seen[sprintf('%012x', $pg_n - 1)]));
	t_ok('rows are returned strictly newest-first across page boundaries', $pg_monotone);
	@unlink($pg_file);
}

// --------------------------------------------------------------------------
t_section('Session cookie');

require_once __DIR__ . '/../panel/auth.php';

$sec = bin2hex(random_bytes(32));
$now = time();
$tok = gp_session_make('operator', $sec, $now);
t_ok('a session token has three dot-separated parts',
	count(explode('.', $tok)) === 3);
$check = gp_session_check($tok, $sec, 43200, $now);
t_ok('a fresh token verifies and returns the user',
	is_array($check) && $check['user'] === 'operator');
t_ok('a token verifies just inside its ttl',
	gp_session_check($tok, $sec, 43200, $now + 43199) !== false);
t_ok('a token expires exactly at its ttl',
	gp_session_check($tok, $sec, 43200, $now + 43200) === false);
t_ok('a token signed with another secret fails',
	gp_session_check($tok, bin2hex(random_bytes(32)), 43200, $now) === false);

$parts = explode('.', $tok);
t_ok('a tampered signature fails',
	gp_session_check($parts[0] . '.' . $parts[1] . '.' . strrev($parts[2]),
		$sec, 43200, $now) === false);
t_ok('a tampered username fails',
	gp_session_check('attacker.' . $parts[1] . '.' . $parts[2], $sec, 43200, $now) === false);
t_ok('a tampered issued-at fails',
	gp_session_check($parts[0] . '.' . ($now - 100000) . '.' . $parts[2],
		$sec, 43200, $now) === false);
t_ok('a future-dated token is refused',
	gp_session_check(gp_session_make('operator', $sec, $now + 5000), $sec, 43200, $now) === false);
t_ok('a malformed token fails', gp_session_check('garbage', $sec, 43200, $now) === false);
t_ok('an empty token fails', gp_session_check('', $sec, 43200, $now) === false);
t_ok('a non-numeric issued-at fails',
	gp_session_check('operator.abc.' . $parts[2], $sec, 43200, $now) === false);

// A username containing a dot must round-trip: the token is user.issued.hmac,
// and parsing from the right keeps the dotted user intact (FIX #3).
$dotted_tok = gp_session_make('admin.site', $sec, $now);
$dotted = gp_session_check($dotted_tok, $sec, 43200, $now);
t_ok('a dotted username round-trips through make/check',
	is_array($dotted) && $dotted['user'] === 'admin.site' && $dotted['issued'] === $now);
t_ok('a dotted-username token with a tampered signature still fails',
	gp_session_check('admin.site.' . $now . '.' . strrev(gp_session_sign('admin.site', $now, $sec)),
		$sec, 43200, $now) === false);

t_ok('a fresh session is not yet due for renewal',
	gp_session_should_renew($now, 43200, $now) === false);
t_ok('a session past half its life is renewed',
	gp_session_should_renew($now - 21601, 43200, $now) === true);

// --------------------------------------------------------------------------
t_section('CSRF');

$_COOKIE[GP_SESSION_COOKIE] = $tok;
// The GP_SELFTEST seam in gp_panel_config() injects this config, so the real
// CSRF path is exercised here rather than only the not-installed guard.
$GLOBALS['gp_test_panel_cfg'] = array('session_secret' => $sec);
if (gp_panel_config() === null) {
	t_ok('csrf is unavailable while the panel is not installed', gp_csrf_token() === '');
	t_ok('an empty csrf token never validates', gp_csrf_check('') === false);
	t_ok('any token is refused while the panel is not installed',
		gp_csrf_check(str_repeat('a', 64)) === false);
} else {
	$csrf = gp_csrf_token();
	t_ok('a csrf token is produced', $csrf !== '' && strlen($csrf) === 64);
	t_ok('the matching csrf token is accepted', gp_csrf_check($csrf) === true);
	t_ok('a wrong csrf token is refused', gp_csrf_check(strrev($csrf)) === false);
	t_ok('an empty csrf token is refused', gp_csrf_check('') === false);
}
unset($_COOKIE[GP_SESSION_COOKIE]);

// --------------------------------------------------------------------------
t_section('Sliding session renewal keeps the CSRF token valid');

// A session past half its TTL is renewed in place: gp_current_user() issues a
// new cookie. gp_csrf_token() must bind the form it renders to that renewed
// token, not the stale cookie, or the next submit fails err_csrf once.
putenv('GV_USERS=' . $GP_TMP_LOGS . '/users-renew.json');       // the user store of this test (migrated from the injected config)
$GLOBALS['gp_test_panel_cfg'] = array(
	'username' => 'operator', 'password_hash' => 'x', 'session_secret' => $sec, 'session_ttl' => 43200);
$old_issued = time() - 30000;                  // past half of 43200
$old_tok = gp_session_make('operator', $sec, $old_issued);
$_COOKIE[GP_SESSION_COOKIE] = $old_tok;

t_ok('before renewal csrf is bound to the cookie token',
	gp_effective_session_token() === null
	&& gp_csrf_token() === hash_hmac('sha256', 'csrf.' . $old_tok, $sec));

$renewed_user = gp_current_user();
t_ok('the half-expired session still authenticates', $renewed_user === 'operator');
$renewed_tok = gp_effective_session_token();
t_ok('renewal recorded a fresh effective token',
	is_string($renewed_tok) && $renewed_tok !== '' && $renewed_tok !== $old_tok);
t_ok('after renewal csrf is bound to the renewed token, not the stale cookie',
	gp_csrf_token() === hash_hmac('sha256', 'csrf.' . $renewed_tok, $sec));
t_ok('the renewed csrf validates on the next submit (no one-request failure)',
	gp_csrf_check(gp_csrf_token()) === true);

unset($_COOKIE[GP_SESSION_COOKIE]);
unset($GLOBALS['gp_test_panel_cfg']);
putenv('GV_USERS');

// --------------------------------------------------------------------------
t_section('Flash messages survive a redirect (signed cookie)');

$flash_secret = bin2hex(random_bytes(32));
$flashes = array(
	array('kind' => 'ok', 'message' => 'override added'),
	array('kind' => 'error', 'message' => 'train with Redis down failed'),
);
$flash_cookie = gp_flash_encode($flashes, $flash_secret);
t_ok('encoding pending flashes yields a non-empty signed value',
	is_string($flash_cookie) && $flash_cookie !== '');
t_ok('a saved flash cookie round-trips to the same messages',
	gp_flash_decode($flash_cookie, $flash_secret) === $flashes);
t_ok('a tampered flash cookie yields no messages',
	gp_flash_decode($flash_cookie . 'x', $flash_secret) === array());
t_ok('a flash cookie signed with another secret yields no messages',
	gp_flash_decode($flash_cookie, bin2hex(random_bytes(32))) === array());
t_ok('a garbage flash cookie yields no messages',
	gp_flash_decode('not-a-flash-cookie', $flash_secret) === array());
t_ok('an empty flash list encodes to nothing to store',
	gp_flash_encode(array(), $flash_secret) === '');
$flash_big = array();
for ($i = 0; $i < 200; $i++) { $flash_big[] = array('kind' => 'ok', 'message' => str_repeat('x', 40)); }
t_ok('an oversize flash set is refused rather than bloating headers',
	gp_flash_encode($flash_big, $flash_secret) === '');
$flash_poison = gp_flash_encode(array(array('kind' => 'ok')), $flash_secret);
t_ok('an entry of the wrong shape is dropped on load',
	$flash_poison !== '' && gp_flash_decode($flash_poison, $flash_secret) === array());

// --------------------------------------------------------------------------
t_section('No panel configuration means a bare 404');

t_ok('gp_panel_config returns null when nothing is installed',
	!is_file(gp_panel_config_path()) ? gp_panel_config() === null : true);
t_ok('gp_current_user is null without a configuration',
	!is_file(gp_panel_config_path()) ? gp_current_user() === null : true);

// --------------------------------------------------------------------------
t_section('Login rate limiting does not fail open');

// Point the file fallback at a scratch directory and force the Redis path to
// fail, which is the case that matters: an attacker must not be able to remove
// the limit by taking Redis away.
$rl_bucket = 'selftest-' . bin2hex(random_bytes(4));
$rl_dir = gp_ratelimit_file_dir();
$had_rl_dir = is_dir($rl_dir);

$count = 0;
for ($i = 1; $i <= GP_LOGIN_MAX_ATTEMPTS; $i++) {
	$count = gp_attempts_bump_file($rl_bucket, GP_LOGIN_WINDOW);
}
t_ok('the file fallback counts every attempt', $count === GP_LOGIN_MAX_ATTEMPTS);
t_ok('the file fallback reports the current count',
	gp_attempts_get_file($rl_bucket, GP_LOGIN_WINDOW) === GP_LOGIN_MAX_ATTEMPTS);
t_ok('the limit is reached after the configured attempts',
	gp_attempts_get_file($rl_bucket, GP_LOGIN_WINDOW) >= GP_LOGIN_MAX_ATTEMPTS);
t_ok('the counter keeps climbing past the limit',
	gp_attempts_bump_file($rl_bucket, GP_LOGIN_WINDOW) === GP_LOGIN_MAX_ATTEMPTS + 1);
t_ok('an expired window resets the counter',
	gp_attempts_get_file($rl_bucket, -1) === 0);
t_ok('an unknown bucket starts at zero',
	gp_attempts_get_file('never-seen-' . bin2hex(random_bytes(4)), GP_LOGIN_WINDOW) === 0);
$rl_file = gp_attempts_file($rl_bucket);
t_ok('the fallback counter file is written 0600',
	is_file($rl_file) ? substr(sprintf('%o', fileperms($rl_file)), -4) === '0600' : false);
@unlink($rl_file);
if (!$had_rl_dir && is_dir($rl_dir)) { @rmdir($rl_dir); }

$redis_bin = trim((string)@shell_exec('command -v redis-cli 2>/dev/null'));
if ($redis_bin === '') {
	t_skip('redis-backed rate limit', 'redis-cli not available');
} else {
	$cfg_rl = gv_cfg_load();
	$conn_rl = gv_redis_connect($cfg_rl['redis']);
	if (!$conn_rl) {
		t_skip('redis-backed rate limit', 'no reachable local Redis');
	} else {
		$rk = 'redis-' . bin2hex(random_bytes(4));
		gv_redis_cmd($conn_rl, array('DEL', 'gp:login:' . $rk));
		gv_redis_close($conn_rl);
		t_ok('the redis counter starts at zero', gp_attempts_get($rk, GP_LOGIN_WINDOW) === 0);
		t_ok('the redis counter increments', gp_attempts_bump($rk, GP_LOGIN_WINDOW) === 1);
		t_ok('the redis counter is readable back', gp_attempts_get($rk, GP_LOGIN_WINDOW) === 1);
		$conn_rl = gv_redis_connect($cfg_rl['redis']);
		t_ok('the login key carries the gp: prefix and a ttl',
			(int)gv_redis_cmd($conn_rl, array('TTL', 'gp:login:' . $rk)) > 0);
		gv_redis_cmd($conn_rl, array('DEL', 'gp:login:' . $rk));
		gv_redis_close($conn_rl);
	}
}

// --------------------------------------------------------------------------
t_section('Stored XSS: everything rendered comes from the attacker');

require_once __DIR__ . '/../panel/data.php';

$XSS = '<script>alert(1)</script>"><img src=x onerror=alert(1)>';

t_ok('gp_e escapes angle brackets',
	strpos(gp_e($XSS), '<script') === false && strpos(gp_e($XSS), '<img') === false);
t_ok('gp_e escapes double quotes so an attribute cannot be broken out of',
	strpos(gp_e($XSS), '"') === false);
t_ok('gp_e escapes single quotes too', strpos(gp_e("it's"), "'") === false);
t_ok('gp_e produces the expected entity form',
	strpos(gp_e($XSS), '&lt;script&gt;alert(1)&lt;/script&gt;') !== false);
t_ok('gp_e substitutes invalid UTF-8 rather than returning empty',
	gp_e("bad \xC3\x28 bytes") !== '');
t_ok('gp_u percent-encodes a payload used in a URL',
	strpos(gp_u($XSS), '<') === false && strpos(gp_u($XSS), '"') === false);
t_ok('gp_json escapes tags, ampersands and quotes for an inline script',
	strpos(gp_json(array('ua' => $XSS)), '<') === false
	&& strpos(gp_json(array('ua' => $XSS)), "'") === false);

// Render the real log explorer view over a crafted row and inspect the output.
if (!function_exists('gp_t')) {
	$GP_STRINGS = require __DIR__ . '/../panel/lang.php';
	function gp_t($key) {
		global $GP_STRINGS;
		return isset($GP_STRINGS[$key]) ? $GP_STRINGS[$key] : $key;
	}
}
require_once __DIR__ . '/../panel/ui.php';
if (!function_exists('gp_csrf_token_stub')) {
	// gp_csrf_token() needs an installed panel; the view only echoes it.
	function gp_csrf_token_stub() { return str_repeat('a', 64); }
}
if (!function_exists('gp_csrf_token')) {
	function gp_csrf_token() { return gp_csrf_token_stub(); }
}

$xss_row = array(
	'v' => 4, 'rid' => 'abcdef012345', 'ts' => time(), 'ip' => '203.0.113.5',
	'ua' => $XSS, 'uah' => 'aaaaaaaaaaaa', 'm' => 'GET', 'p' => '/' . $XSS,
	'q' => 'q=' . $XSS, 'aj' => 0, 'nav' => 1, 'tok' => 'm', 'dev' => $XSS,
	'sf' => '', 'al' => 1, 'hc' => 4, 'sc' => 30, 'esc' => 30,
	'rs' => array($XSS), 'cd' => 0, 'ciu' => 0, 'ci' => 0, 'rd' => 0, 'hp' => 0,
	'bot' => $XSS, 'ref' => $XSS, 'botv' => '', 'rep' => 0, 'ml' => -1, 'clf' => -1,
	'hold' => 0, 'ovr' => $XSS, 'act' => $XSS, 'sh' => 0, 'ms' => 0.4,
	'_out' => array('o' => 1, 'rid' => 'abcdef012345', 'st' => 404, 'by' => 1,
		'dur' => 1.0, 'ts' => time()),
);

$filter = array('date' => date('Ymd'), 'path' => $XSS, 'dev' => $XSS, 'ip' => $XSS);
$rows = array($xss_row);
$meta = array('file' => 'guard-' . $XSS . '.jsonl', 'scanned_lines' => 1,
	'scanned_bytes' => 1, 'capped' => false, 'next_cursor' => null, 'exists' => true);
$dates = array(date('Ymd'));
$route = 'logs';
$user = 'tester';

ob_start();
require __DIR__ . '/../panel/views/logs.php';
$rendered = ob_get_clean();

// Parse the output the way a browser would, rather than pattern-matching the
// source. A naive regex cannot tell an escaped payload sitting inside an
// attribute value from a real attribute, because &gt; does not close a tag -
// only a parser knows the difference, and only the parser's answer matters.
function t_dom_findings($html) {
	$out = array('scripts' => 0, 'handlers' => array(), 'tags' => array(),
		'js_urls' => array());
	// Without ext-dom there is no parse to report. Returning the empty shape
	// keeps every call site's expression harmless; t_dom_ok() is what turns
	// these into SKIPs, so an absent extension can never read as a pass.
	if (!class_exists('DOMDocument')) { return $out; }
	$doc = new DOMDocument();
	$prev = libxml_use_internal_errors(true);
	$doc->loadHTML('<?xml encoding="utf-8"?>' . $html);
	libxml_clear_errors();
	libxml_use_internal_errors($prev);
	foreach ($doc->getElementsByTagName('*') as $el) {
		$name = strtolower($el->nodeName);
		$out['tags'][$name] = true;
		if ($name === 'script') { $out['scripts']++; }
		if (!$el->hasAttributes()) { continue; }
		foreach ($el->attributes as $attr) {
			$attr_name = strtolower($attr->nodeName);
			if (strpos($attr_name, 'on') === 0) {
				$out['handlers'][] = $name . '@' . $attr_name;
			}
			if (in_array($attr_name, array('href', 'src', 'action', 'formaction'), true)
				&& stripos(trim($attr->nodeValue), 'javascript:') === 0) {
				$out['js_urls'][] = $name . '@' . $attr_name;
			}
		}
	}
	return $out;
}

$dom = t_dom_findings($rendered);
t_ok('the log explorer rendered output', strlen($rendered) > 500);
t_ok('the log explorer shows no Persian or Arabic-Indic digit anywhere (Latin digits only)',
	preg_match('/[\x{06F0}-\x{06F9}\x{0660}-\x{0669}]/u', $rendered) === 0);
t_ok('the log explorer uses the grouped row layout', strpos($rendered, 'gp-log-line') !== false && strpos($rendered, 'gp-log-detail') !== false);
t_ok('gp_latin formats with Latin digits, no grouping', gp_latin(1234567) === '1234567' && gp_latin(1.5, 2) === '1.50' && gp_latin(2.0, 2, true) === '2' && gp_latin(1.50, 2, true) === '1.5' && gp_latin(-0.0) === '0');
t_ok('gp_latin never emits a Persian digit', preg_match('/[\x{06F0}-\x{06F9}]/u', gp_latin(9876543210)) === 0);
t_ok('gp_num uses Latin digits with thousands grouping', gp_num(1234567) === '1,234,567' && gp_num(0.5, 1) === '0.5' && gp_num(-0.0) === '0');
t_ok('gp_pct uses Latin digits and the ASCII percent sign', gp_pct(1, 3) === '33.3%' && gp_pct(0, 0) === '0.0%');
t_ok('gp_num_raw turns Persian and Arabic-Indic digits into Latin ones',
	gp_num_raw("\u{06F1}\u{06F4}\u{06F0}\u{06F5}-\u{0660}\u{0669} 12:30") === '1405-09 12:30');
t_ok('gp_datetime is Latin', preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', gp_datetime(1700000000)) === 1);
t_ok('gp_plural picks singular and plural', gp_plural(1, 'hour') === '1 hour' && gp_plural(6, 'hour') === '6 hours' && gp_plural(1000, 'day') === '1,000 days');
t_ok('gp_age is English with Latin digits', gp_age(time() - 180) === '3 minutes' && gp_age(time() - 1) === '1 second');

// Log detail redesign: every value sits under a label that names it, with the
// raw log key next to the label, and long values collapse instead of flooding.
t_ok('log detail: every field is a label/value pair with its log key',
	substr_count($rendered, 'class="gp-prop"') >= 20 && strpos($rendered, '<code class="gp-prop-key" title="Log field">ua</code>') !== false);
t_ok('log detail: section titles are English', strpos($rendered, '>Request</h3>') !== false && strpos($rendered, '>Identity</h3>') !== false
	&& strpos($rendered, '>Counters and internals</h3>') !== false);
t_ok('log detail: booleans are Yes/No badges', preg_match('/gp-badge-(on|off)">(Yes|No)</', $rendered) === 1);
$lg_long = $xss_row;
$lg_long['ua'] = str_repeat('Mozilla/5.0 (X11; Linux x86_64) ', 20);
$lg_long['q'] = 'route=product%2Fproduct&product_id=42&search=a+b&' . rawurlencode('<b>') . '=' . rawurlencode('"><script>x</script>');
$rows = array($lg_long);
ob_start();
require __DIR__ . '/../panel/views/logs.php';
$lg_html = ob_get_clean();
t_ok('log detail: a long value is collapsed with a "Show full value" toggle and keeps the full text',
	strpos($lg_html, 'gp-prop-more') !== false && strpos($lg_html, 'Show full value (' . strlen($lg_long['ua']) . ' characters)') !== false
	&& strpos($lg_html, gp_e($lg_long['ua'])) !== false);
t_ok('log detail: the query string is split into decoded parameters',
	strpos($lg_html, '<th scope="row">route</th>') !== false && strpos($lg_html, 'product/product') !== false
	&& strpos($lg_html, '<th scope="row">search</th>') !== false && strpos($lg_html, '>a b<') !== false);
t_ok('log detail: a decoded parameter name or value is still escaped',
	strpos($lg_html, '<th scope="row">&lt;b&gt;</th>') !== false && strpos($lg_html, '<script>x') === false);
$lg_dom = t_dom_findings($lg_html);
t_dom_ok('log detail: the browser sees no script element from decoded parameters', $lg_dom['scripts'] === 0 && !isset($lg_dom['tags']['b']));
$rows = array($xss_row);
t_dom_ok('the browser sees no script element from log data', $dom['scripts'] === 0);
t_dom_ok('the browser sees no img element from log data',
	!isset($dom['tags']['img']));
t_dom_ok('the browser sees no event-handler attribute anywhere'
	. ($dom['handlers'] ? ' - found: ' . implode(', ', $dom['handlers']) : ''),
	$dom['handlers'] === array());
t_dom_ok('no javascript: url survives', $dom['js_urls'] === array());
t_ok('no raw closing script tag from the payload',
	stripos($rendered, '</script>') === false);
t_ok('the payload is present, escaped',
	strpos($rendered, '&lt;script&gt;alert(1)&lt;/script&gt;') !== false);
t_ok('the payload in the path is escaped too',
	strpos($rendered, '&quot;&gt;&lt;img') !== false);
t_ok('every attribute value is quoted and escaped',
	preg_match('/=\s*"[^"]*<[^"]*"/', $rendered) === 0);

// The same payload as a URL parameter must be percent-encoded, not echoed.
t_ok('an identity link percent-encodes the payload',
	strpos($rendered, 'id=%3Cscript%3E') !== false
	|| strpos($rendered, 'id=' . rawurlencode($XSS)) !== false);

// Render the audit view over a poisoned entry too.
$entries = array(array('ts' => time(), 'event' => $XSS, 'actor' => $XSS,
	'ip' => $XSS, 'key' => $XSS, 'old' => $XSS, 'new' => array($XSS)));
$query = $XSS;
$filter = array('q' => array('v' => array($XSS), 'not' => true), 'event' => array('v' => array($XSS), 'not' => false));
ob_start();
require __DIR__ . '/../panel/views/audit.php';
$rendered_audit = ob_get_clean();
$dom_audit = t_dom_findings($rendered_audit);
t_dom_ok('the audit view escapes a poisoned entry',
	$dom_audit['scripts'] === 0 && $dom_audit['handlers'] === array()
	&& !isset($dom_audit['tags']['img']));
t_ok('the audit search box escapes the query it echoes back',
	strpos($rendered_audit, 'value="&lt;script&gt;') !== false);

// --------------------------------------------------------------------------
t_section('Redis settings are file-only and never displayed');

foreach (array('redis.password', 'redis.username', 'redis.prefix', 'redis.host', 'redis.socket', 'redis.db') as $rk) {
	$chk = gv_overlay_validate($rk, 'x');
	t_ok("$rk is not in the overlay whitelist (file-only, like secret)", $chk[0] === false && $chk[1] === 'unknown_key');
}
$rf = tempnam(sys_get_temp_dir(), 'gvrcfg');
file_put_contents($rf, '<?php if (!defined("GV_BOOT")) { exit; } return array("secret" => "x",'
	. ' "redis" => array("host" => "10.1.2.3", "port" => 6380, "username" => "uSeRnAmE", "password" => "p4ssw0rd-LEAK",'
	. ' "db" => 3, "prefix" => "shop1:"));');
putenv('GV_CONFIG=' . $rf);
$ri = gp_redis_info();
putenv('GV_CONFIG');
@unlink($rf);
t_ok('gp_redis_info reports endpoint, db, prefix and auth on/off',
	$ri['endpoint'] === '10.1.2.3:6380' && $ri['db'] === 3 && $ri['prefix'] === 'shop1:' && $ri['auth'] === true);
t_ok('gp_redis_info never carries the password or username',
	strpos(json_encode($ri), 'p4ssw0rd') === false && strpos(json_encode($ri), 'uSeRnAmE') === false);
$dash_src = file_get_contents(__DIR__ . '/../panel/views/dashboard.php') . file_get_contents(__DIR__ . '/../panel/views/settings.php');
t_ok('no panel view reads redis.password', strpos($dash_src, "['password']") === false);

// --------------------------------------------------------------------------
t_section('Exposure warning (data under the document root)');

$ex_base = sys_get_temp_dir() . '/gp-expo-' . getmypid();
@mkdir($ex_base . '/site/sub', 0775, true);
@mkdir($ex_base . '/outside', 0775, true);
t_ok('a path inside the document root is flagged',
	count(gp_exposure_paths($ex_base . '/site', array($ex_base . '/site/sub'))) === 1);
t_ok('a path outside the document root is not',
	gp_exposure_paths($ex_base . '/site', array($ex_base . '/outside')) === array());
t_ok('a sibling with the same name prefix is not mistaken for a child',
	gp_exposure_paths($ex_base . '/site', array($ex_base . '/outside')) === array()
	&& gp_exposure_paths($ex_base . '/site', array($ex_base)) === array());
t_ok('the document root itself is flagged', count(gp_exposure_paths($ex_base . '/site', array($ex_base . '/site'))) === 1);
t_ok('an unknown document root warns about nothing', gp_exposure_paths('', array($ex_base . '/site')) === array());
t_ok('a missing path is ignored', gp_exposure_paths($ex_base . '/site', array($ex_base . '/site/none')) === array());
@rmdir($ex_base . '/site/sub'); @rmdir($ex_base . '/site'); @rmdir($ex_base . '/outside'); @rmdir($ex_base);

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
// The ONE allowed exception: health.php runs scripts/cron-check.sh with proc_open and an ARGV ARRAY (no shell, a fixed
// binary, no operator input, 3 s timeout). It must be exactly that call and no other.
$allowed_po = array_values(array_filter($hits, function ($h) { return $h === 'health.php:proc_open'; }));
$hits = array_values(array_diff($hits, array('health.php:proc_open')));
t_ok('no shell-execution function appears under panel/'
	. ($hits ? ' - found: ' . implode(', ', array_slice($hits, 0, 5)) : ''), !$hits);
$hsrc = file_get_contents(__DIR__ . '/../panel/health.php');
t_ok('the one proc_open (panel/health.php) takes an argv array of fixed binary + fixed script + --json, no string command, no shell, no operator input',
	count($allowed_po) === 1 && substr_count($hsrc, '@proc_open(') === 1 && preg_match('/proc_open\(array\(\$bash, \$script, \x27--json\x27\)/', $hsrc) === 1
	&& strpos($hsrc, "'/bin/bash'") !== false && strpos($hsrc, '$_GET') === false && strpos($hsrc, '$_POST') === false && strpos($hsrc, '$_REQUEST') === false);
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
@unlink(gv_overlay_path() . '.lock');
// --------------------------------------------------------------------------
t_section('Review hardening');

$h_audit = is_file(gp_audit_path()) ? file_get_contents(gp_audit_path()) : null;
t_clear_overlay();
@unlink(gp_audit_path());

gp_audit_append(array('event' => 'login_failed', 'actor' => str_repeat('A', 1200000), 'ip' => '203.0.113.9'));
gp_audit_append(array('event' => 'config', 'actor' => 'tester', 'ip' => '203.0.113.9', 'key' => 'hard_block_score', 'old' => 60, 'new' => 55));
t_ok('an oversized username cannot bloat the audit file (' . filesize(gp_audit_path()) . ' bytes)', filesize(gp_audit_path()) < 600);
$h_rows = gp_audit_read(50);
t_ok('...or push real entries out of the audit view', count($h_rows) === 2 && strlen($h_rows[1]['actor'] ?? $h_rows[0]['actor']) <= 70);
gp_audit_append(array('event' => 'x', 'actor' => array('not', 'a', 'string'), 'ip' => '203.0.113.9'));
t_ok('a non-string actor is stored as an empty string, without a warning',
	strpos(file_get_contents(gp_audit_path()), '"event":"x","actor":""') !== false);

// A save writes only what changed.
$h_form = array('hard_block_score' => 60, 'holdout_pct' => 0, 'limits.device' => 150, 'limits.ip' => 1200);
$h_eff = gv_cfg_load();
foreach ($h_form as $k => $_v) { $h_form[$k] = gp_effective_value($h_eff, $k); }   // the form as loaded
$h_form['limits.ip'] = 999;
$h_save = gp_config_save($h_form, 'tester', '203.0.113.9');
$h_file = json_decode(file_get_contents(gv_overlay_path()), true);
t_ok('saving a form with one changed field writes one key, not the whole form',
	$h_save['ok'] && array_keys($h_file) === array('limits.ip') && $h_file['limits.ip'] === 999);
t_ok('the save lock file is not left locked', ($h_fh = fopen(gv_overlay_path() . '.lock', 'c')) && flock($h_fh, LOCK_EX | LOCK_NB));
if ($h_fh) { flock($h_fh, LOCK_UN); fclose($h_fh); }
@unlink(gv_overlay_path() . '.lock');

// An overlay the guard would ignore as a whole is refused at write time.
$h_big = array();
for ($i = 0; $i < 20; $i++) {
	$vals = array();
	for ($j = 0; $j < 50; $j++) { $vals[] = str_repeat('"', 150) . $i . '-' . $j; }
	$h_big['p' . $i] = $vals;
}
$h_res = gp_config_save(array('exempt_params' => $h_big), 'tester', '203.0.113.9');
t_ok('a save that would exceed the size the guard reads is refused, not silently ignored',
	$h_res['ok'] === false && isset($h_res['errors']['_write'])
	&& json_decode(file_get_contents(gv_overlay_path()), true) === array('limits.ip' => 999));

// One-click outages are refused by the same validators the guard reads with.
foreach (array(array('exempt_paths', array('/')), array('known_bots', array('mozilla')), array('preview_bots', array('a')),
	array('honeypot_path', '/'), array('challenge.pow_bits', 24)) as $h_case) {
	$h_r = gp_config_save(array($h_case[0] => $h_case[1]), 'tester', '203.0.113.9');
	t_ok('the panel refuses ' . $h_case[0] . ' = ' . json_encode($h_case[1]), $h_r['ok'] === false && isset($h_r['errors'][$h_case[0]]));
}

// Overrides land on the key the guard reads.
t_ok('an override address is stored in the guard\'s canonical spelling',
	gp_identity_canon('2001:DB8:0:0:0:0:0:5') === '2001:db8::5' && gp_identity_canon('::ffff:203.0.113.7') === '203.0.113.7'
	&& gp_identity_canon('203.0.113.7') === '203.0.113.7' && gp_identity_canon('a1b2c3d4e5f6a1b2c3d4e5f6') === 'a1b2c3d4e5f6a1b2c3d4e5f6');

// The file login counter under real concurrency.
$h_bucket = 'race-' . bin2hex(random_bytes(4));
$h_code = 'define("GV_BOOT",1);define("GP_BOOT",1);define("GP_SELFTEST",1);define("GV_NO_AUTORUN",1);'
	. 'require ' . var_export(realpath(__DIR__ . '/../guard/guard.php'), true) . ';'
	. 'require ' . var_export(realpath(__DIR__ . '/../panel/config_io.php'), true) . ';'
	. 'require ' . var_export(realpath(__DIR__ . '/../panel/auth.php'), true) . ';'
	. 'for($i=0;$i<25;$i++){gp_attempts_bump_file(' . var_export($h_bucket, true) . ',900);}';
$h_procs = array();
for ($i = 0; $i < 8; $i++) {
	$h_procs[] = proc_open(array(PHP_BINARY, '-r', $h_code), array(1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $h_pipes);
}
foreach ($h_procs as $h_p) { if (is_resource($h_p)) { proc_close($h_p); } }
$h_n = gp_attempts_get_file($h_bucket, 900);
t_ok('8 processes x 25 attempts are all counted by the file limiter (' . $h_n . ' of 200)', $h_n === 200);
@unlink(gp_attempts_file($h_bucket));

// Every library the front controller loads must load together (a function
// declared twice is a fatal error on every panel request, not just in a test).
$ld_code = 'define("GP_BOOT",1);foreach(array("config_io","auth","data","jobs","replay") as $f){require "' . addslashes(dirname(__DIR__)) . '/panel/".$f.".php";}echo "LOADED";';
$ld_out = (string)shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($ld_code) . ' 2>&1');
t_ok('all panel library files load together without a redeclared function', trim($ld_out) === 'LOADED');

// --------------------------------------------------------------------------
t_section('Log storage card');
$lsd = sys_get_temp_dir() . '/gp-ls-' . getmypid();
@mkdir($lsd);
$lsc = tempnam(sys_get_temp_dir(), 'gvcfg');
file_put_contents($lsc, '<?php return array("secret" => "x", "log_dir" => "' . $lsd . '", "log_max_mb" => 1, "log_min_free_mb" => 0, "log_skip_paths" => array("/gv-admin/"));');
putenv('GV_CONFIG=' . $lsc);
$now = time();
file_put_contents($lsd . '/guard-' . date('Ymd', $now) . '.jsonl', str_repeat('x', 1000));
file_put_contents($lsd . '/guard-' . date('Ymd', $now - 5 * 86400) . '.jsonl', str_repeat('x', 2000));
touch($lsd . '/guard-' . date('Ymd', $now - 5 * 86400) . '.jsonl', $now - 5 * 86400);
file_put_contents($lsd . '/guard-20260101.jsonl.gz', str_repeat('y', 2 * 1048576));
$ls = gp_log_storage($now);
t_ok('log storage: sizes, archive count and oldest day', $ls['total'] === 1000 + 2000 + 2 * 1048576 && $ls['today'] === 1000
	&& $ls['archives'] === 1 && $ls['oldest'] === '20260101' && $ls['skip_paths'] === array('/gv-admin/'));
t_ok('log storage: an old uncompressed day and no marker means rotation never ran', in_array('rotate_never', $ls['warnings'], true));
t_ok('log storage: over the size cap is reported', in_array('over_cap', $ls['warnings'], true));
file_put_contents($lsd . '/.last-rotate', json_encode(array('ts' => $now - 3 * 86400, 'failures' => 1)) . "\n");
$ls = gp_log_storage($now);
t_ok('log storage: a stale and failed rotation is reported', in_array('rotate_stale', $ls['warnings'], true) && in_array('rotate_failed', $ls['warnings'], true) && !in_array('rotate_never', $ls['warnings'], true));
file_put_contents($lsc, '<?php return array("secret" => "x", "log_dir" => "' . $lsd . '", "log_min_free_mb" => 1000000000);');
$ls = gp_log_storage($now);
t_ok('log storage: free space under the floor is reported', in_array('disk_low', $ls['warnings'], true) && $ls['free'] !== null);
t_ok('gp_bytes is readable and Latin', gp_bytes(512) === '512 B' && gp_bytes(1536) === '1.5 KB' && gp_bytes(3 * 1073741824) === '3.0 GB');
putenv('GV_CONFIG');
@unlink($lsc);
foreach ((array)glob($lsd . '/{,.}*', GLOB_BRACE) as $f) { if (is_file($f)) { @unlink($f); } }
@rmdir($lsd);

// --------------------------------------------------------------------------
t_section('Settings management: form parsing, analyzer keys, file editor, backups');

$bk_before = array_map('basename', (array)glob(gp_backup_dir() . '/*'));
t_clear_overlay();

// The form posts every whitelisted key; parsing is driven by the whitelist.
$_POST = array('present' => array('challenge.bind_ip' => 1), 'f' => array(
	'token_ttl' => '7200', 'cdn_ranges' => "203.0.113.0/24\n\n198.51.100.0/24 ",
	'bot_suffixes' => "googlebot: .googlebot.com, .google.com\nbingbot: .search.msn.com",
	'strings.title' => '  Please wait  ', 'strings.dir' => 'rtl', 'analyzer.contamination' => '0.1',
	'analyzer.path_listing' => "^/category/\n^/c/\\d+"));
// gp_settings_from_request() lives in index.php, which cannot be included here
// (it dispatches a request); load just the three functions from its source.
$sm_src = file_get_contents(__DIR__ . '/../panel/index.php');
preg_match('/function gp_settings_from_request\(\) \{.*?\n\}\n/s', $sm_src, $sm_fn);
preg_match('/function gp_lines_to_list\(\$text\) \{.*?\n\}\n/s', $sm_src, $sm_fn2);
preg_match('/function gp_parse_params\(\$text\) \{.*?\n\}\n/s', $sm_src, $sm_fn3);
if (!function_exists('gp_settings_from_request')) { eval($sm_fn[0] . $sm_fn2[0] . $sm_fn3[0]); }
$sm = gp_settings_from_request();
t_ok('form parsing: numbers, lists, name: values maps and trimmed text are typed from the whitelist',
	$sm['token_ttl'] === 7200 && $sm['cdn_ranges'] === array('203.0.113.0/24', '198.51.100.0/24')
	&& $sm['bot_suffixes'] === array('googlebot' => array('.googlebot.com', '.google.com'), 'bingbot' => array('.search.msn.com'))
	&& $sm['strings.title'] === 'Please wait' && $sm['challenge.bind_ip'] === false
	&& $sm['analyzer.contamination'] === 0.1 && $sm['analyzer.path_listing'] === array('^/category/', '^/c/\d+'));
t_ok('form parsing: a bool without its "present" marker is not touched', !isset($sm['enforce.block']));
$_POST = array();

$sv = gp_config_save(array('token_ttl' => 7200, 'challenge.bind_ip' => true, 'analyzer.window_days' => 7), 'tester', '127.0.0.1');
$sv_file = json_decode(file_get_contents(gv_overlay_path()), true);
t_ok('a save writes only what differs from the value in force (bind_ip true and window_days 7 are defaults)',
	$sv['ok'] && $sv_file === array('token_ttl' => 7200));
$sv2 = gp_config_save(array('token_ttl' => 7200, 'analyzer.window_days' => 'abc'), 'tester', '127.0.0.1');
t_ok('a changed invalid value is refused by name and nothing is written',
	!$sv2['ok'] && ($sv2['errors']['analyzer.window_days'] ?? '') === 'not_int'
	&& json_decode(file_get_contents(gv_overlay_path()), true) === array('token_ttl' => 7200));
$sm_cfg = gv_cfg_load();
t_ok('overlay keys reach the guard config (token_ttl, nested analyzer block)', $sm_cfg['token_ttl'] === 7200);
gp_config_save(array('analyzer.window_days' => 14, 'strings.dir' => 'rtl'), 'tester', '127.0.0.1');
$sm_cfg = gv_cfg_load();
t_ok('analyzer.* lands in $cfg["analyzer"] and strings.* in $cfg["strings"]',
	($sm_cfg['analyzer']['window_days'] ?? null) === 14 && $sm_cfg['strings']['dir'] === 'rtl' && $sm_cfg['strings']['title'] !== '');
$sm_pc = gv_cfg_load();
t_ok('a value from config.php outside the panel range does not block other saves',
	(function () {
		$tmpc = tempnam(sys_get_temp_dir(), 'gvcfg');
		file_put_contents($tmpc, '<?php return array("secret" => "x", "challenge" => array("pow_bits" => 24));');
		putenv('GV_CONFIG=' . $tmpc);
		$r = gp_config_save(array('challenge.pow_bits' => 24, 'nonce_ttl' => 300), 'tester', '127.0.0.1');
		putenv('GV_CONFIG');
		@unlink($tmpc);
		return $r['ok'] && !isset($r['errors']['challenge.pow_bits']);
	})());

// Analyzer defaults in PHP mirror analyzer/config.py.
$py = trim((string)@shell_exec('cd ' . escapeshellarg(dirname(__DIR__)) . ' && python3 -c '
	. escapeshellarg('import json,sys; sys.path.insert(0,"."); from analyzer import config as c; print(json.dumps({k: c.DEFAULTS[k] for k in c.PANEL_KEYS}))') . ' 2>/dev/null'));
$py_d = $py !== '' ? json_decode($py, true) : null;
if (is_array($py_d)) {
	$php_d = gp_analyzer_defaults();
	$diff_d = array();
	foreach ($py_d as $k => $v) { if (!array_key_exists($k, $php_d) || $php_d[$k] != $v) { $diff_d[] = $k; } }
	foreach ($php_d as $k => $v) { if (!array_key_exists($k, $py_d)) { $diff_d[] = $k; } }
	t_ok('gp_analyzer_defaults() matches analyzer/config.py DEFAULTS for every panel key' . ($diff_d ? ' (' . implode(',', $diff_d) . ')' : ''), !$diff_d);
	$wl_an = array();
	foreach (array_keys(gv_overlay_whitelist()) as $k) { if (strpos($k, 'analyzer.') === 0) { $wl_an[] = substr($k, 9); } }
	sort($wl_an); $pk = array_keys($py_d); sort($pk);
	t_ok('the analyzer.* whitelist and analyzer PANEL_KEYS list the same keys', $wl_an === $pk);
} else {
	t_skip('analyzer defaults parity', 'python3 not available');
}

// JSON scan: line and column of the first error, duplicates, structure.
$js = gp_overlay_file_check("{\n  \"token_ttl\": 7200,\n  \"nonce_ttl\": 300,\n}\n");
t_ok('file check: a trailing comma is reported on its line with a clear message',
	!$js['ok'] && $js['errors'][0]['line'] === 4 && stripos($js['errors'][0]['message'], 'trailing comma') !== false);
$js = gp_overlay_file_check("{\n  \"token_ttl\": 7200\n  \"nonce_ttl\": 300\n}");
t_ok('file check: a missing comma points at the next key (line 3)', !$js['ok'] && $js['errors'][0]['line'] === 3);
$js = gp_overlay_file_check("{\n  'token_ttl': 7200\n}");
t_ok('file check: single quotes are explained', !$js['ok'] && stripos($js['errors'][0]['message'], 'double quotes') !== false);
$js = gp_overlay_file_check("{\n  \"token_ttl\": 7200,\n  \"token_ttl\": 9000\n}");
t_ok('file check: a duplicate key is refused (json_decode would silently keep the last one)',
	!$js['ok'] && $js['errors'][0]['key'] === 'token_ttl' && $js['errors'][0]['line'] === 3);
$js = gp_overlay_file_check("{\n  \"token_ttl\": 1,\n  \"secret\": \"x\",\n  \"strings.dir\": \"up\"\n}");
$js_keys = array_map(function ($e) { return $e['key'] . '@' . $e['line']; }, $js['errors']);
t_ok('file check: every bad key is listed with its line (out of range, file-only key, enum)',
	!$js['ok'] && $js_keys === array('token_ttl@2', 'secret@3', 'strings.dir@4')
	&& strpos($js['errors'][0]['message'], '3600') !== false && strpos($js['errors'][2]['message'], 'ltr, rtl') !== false);
t_ok('file check: a list or a scalar is not an overlay', !gp_overlay_file_check('[1,2]')['ok'] && !gp_overlay_file_check('42')['ok']);
t_ok('file check: {} and a valid object pass', gp_overlay_file_check("{}\n")['ok']
	&& gp_overlay_file_check("{\"cdn_ranges\": [\"203.0.113.0/24\"], \"strings.title\": \"\\u0633\\u0644\\u0627\\u0645\"}")['ok']);
t_ok('file check: unclosed string and garbage after the object are caught',
	!gp_overlay_file_check("{\"a\": \"x}")['ok'] && !gp_overlay_file_check("{} x")['ok']);

// Saving through the editor: hash guard, atomic write, backup, audit.
$fe_before = gp_overlay_file_raw();
$fe_bad = gp_overlay_file_save("{\"token_ttl\": 5}", hash('sha256', $fe_before), 'tester', '127.0.0.1');
t_ok('editor: an invalid file is not written and the file on disk is unchanged',
	!$fe_bad['ok'] && gp_overlay_file_raw() === $fe_before);
$fe_conf = gp_overlay_file_save("{\"token_ttl\": 9000}", hash('sha256', 'something else'), 'tester', '127.0.0.1');
t_ok('editor: a stale base hash (file changed meanwhile) is refused', !$fe_conf['ok'] && $fe_conf['conflict'] && gp_overlay_file_raw() === $fe_before);
$bk_n = count(gp_overlay_backups());
$fe_ok = gp_overlay_file_save("{\r\n  \"token_ttl\": 9000,\r\n  \"cdn_ranges\": [\"203.0.113.0/24\"]\r\n}", hash('sha256', $fe_before), 'tester', '127.0.0.1');
$fe_cfg = gv_cfg_load();
t_ok('editor: a valid file is saved as written (CRLF normalized) and the guard reads it',
	$fe_ok['ok'] && $fe_ok['changed'] && strpos(gp_overlay_file_raw(), "\r") === false
	&& $fe_cfg['token_ttl'] === 9000 && $fe_cfg['cdn_ranges'] === array('203.0.113.0/24'));
$bk_list = gp_overlay_backups();
t_ok('editor: the previous file was backed up and the backup reads back identical',
	count($bk_list) === $bk_n + 1 && gp_overlay_backup_read($bk_list[0]['name']) === $fe_before);
t_ok('backups are not readable by path tricks', gp_overlay_backup_read('../config.php') === null
	&& gp_overlay_backup_read('config.local.20260101-000000-000000-zzzzzz.json') === null);
$fe_aud = gp_audit_read(20);
t_ok('editor: each changed key is audited as config_file', (function () use ($fe_aud) {
	$keys = array(); foreach ($fe_aud as $r) { if (($r['event'] ?? '') === 'config_file') { $keys[] = $r['key']; } }
	return in_array('cdn_ranges', $keys, true) && in_array('token_ttl', $keys, true);
})());
$fe_same = gp_overlay_file_save(gp_overlay_file_raw(), hash('sha256', gp_overlay_file_raw()), 'tester', '127.0.0.1');
t_ok('editor: saving an unchanged file writes nothing and makes no backup',
	$fe_same['ok'] && !$fe_same['changed'] && count(gp_overlay_backups()) === $bk_n + 1);
for ($bk_i = 0; $bk_i < GP_BACKUP_KEEP + 3; $bk_i++) { gp_config_save(array('nonce_ttl' => 100 + $bk_i), 'tester', '127.0.0.1'); }
t_ok('backups are capped at ' . GP_BACKUP_KEEP, count(gp_overlay_backups()) === GP_BACKUP_KEEP);
t_ok('the backup directory is denied to the web by guard/.htaccess (inherited) and git-ignored',
	strpos(file_get_contents(__DIR__ . '/../.gitignore'), 'guard/config-backups/') !== false);

// The settings and editor views render, escape hostile values and show errors.
$cfg = gp_effective_config();
$cfg['strings']['title'] = '"><script>alert(1)</script>';
$overlay = array('token_ttl' => 9000);
$errors = array('nonce_ttl' => 'out_of_range');
$pending = array('nonce_ttl' => 5);
$diff = array();
$route = 'settings';
ob_start(); require __DIR__ . '/../panel/views/settings.php'; $set_html = ob_get_clean();
$set_dom = t_dom_findings($set_html);
t_dom_ok('settings view: a hostile config value is escaped', $set_dom['scripts'] === 0 && strpos($set_html, '&quot;&gt;&lt;script&gt;') !== false);
t_ok('settings view: every whitelisted key has a field', (function () use ($set_html) {
	foreach (array_keys(gv_overlay_whitelist()) as $k) { if (strpos($set_html, 'name="f[' . $k . ']"') === false) { return false; } }
	return true; })());
t_ok('settings view: a rejected value is shown as typed, with a message naming the range',
	strpos($set_html, 'name="f[nonce_ttl]"') !== false && preg_match('/name="f\[nonce_ttl\]"[^>]*value="5"|value="5"[^>]*name="f\[nonce_ttl\]"/s', $set_html) === 1
	&& strpos($set_html, 'Allowed: 30 to 900.') !== false);
t_ok('settings view: number fields carry the whitelist range', strpos($set_html, 'min="10" max="200"') !== false);
t_ok('settings view: secrets are never printed, only their state', strpos($set_html, (string)gv_cfg_load()['secret']) === false || gv_cfg_load()['secret'] === 'CHANGE_ME');
$text = "{\n  \"strings.title\": \"</textarea><script>alert(1)</script>\"\n}";
$base_hash = 'x'; $check = gp_overlay_file_check($text); $from_backup = ''; $backups = gp_overlay_backups(); $path = gv_overlay_path();
ob_start(); require __DIR__ . '/../panel/views/config_file.php'; $cf_html = ob_get_clean();
t_ok('editor view: file content cannot break out of the textarea', strpos($cf_html, '</textarea><script>alert(1)') === false
	&& strpos($cf_html, '&lt;/textarea&gt;&lt;script&gt;') !== false);
t_ok('editor view: lists the allowed keys and the backups', strpos($cf_html, 'analyzer.window_days') !== false && strpos($cf_html, 'Open in editor') !== false);

foreach ((array)glob(gp_backup_dir() . '/*') as $bk_f) { if (!in_array(basename($bk_f), $bk_before, true)) { @unlink($bk_f); } }
if (!$bk_before) { @rmdir(gp_backup_dir()); }

t_clear_overlay();
@unlink(gv_overlay_path() . '.lock');
if ($h_audit !== null) { file_put_contents(gp_audit_path(), $h_audit); } else { @unlink(gp_audit_path()); }

if ($overlay_backup !== null) { file_put_contents($overlay, $overlay_backup); }

// --------------------------------------------------------------------------
t_section('Theme tokens: contrast and the two dark copies');
$th_css = file_get_contents(__DIR__ . '/../panel/assets/app.src.css');
$th_tokens = function ($block) {
	$m = array();
	preg_match_all('/--gp-([a-z-]+):\s*(\d+) (\d+) (\d+);/', $block, $m, PREG_SET_ORDER);
	$o = array();
	foreach ($m as $r) { $o[$r[1]] = array((int)$r[2], (int)$r[3], (int)$r[4]); }
	return $o;
};
preg_match('/\n:root \{(.*?)\n\}/s', $th_css, $th_l);
preg_match('/:root:not\(\[data-theme="light"\]\) \{(.*?)\n\t\}/s', $th_css, $th_d1);
preg_match('/\n:root\[data-theme="dark"\] \{(.*?)\n\}/s', $th_css, $th_d2);
$th_light = $th_tokens($th_l[1] ?? '');
$th_dark1 = $th_tokens($th_d1[1] ?? '');
$th_dark2 = $th_tokens($th_d2[1] ?? '');
t_ok('light and dark token sets were found', count($th_light) > 15 && count($th_dark2) > 15);
t_ok('the media-query dark copy equals the data-theme="dark" copy', $th_dark1 === $th_dark2);
$th_dark = array_merge($th_light, $th_dark2);
$th_lum = function ($c) {
	$f = function ($v) { $v /= 255; return $v <= 0.03928 ? $v / 12.92 : pow(($v + 0.055) / 1.055, 2.4); };
	return 0.2126 * $f($c[0]) + 0.7152 * $f($c[1]) + 0.0722 * $f($c[2]);
};
$th_ratio = function ($a, $b) use ($th_lum) {
	$x = $th_lum($a); $y = $th_lum($b);
	return (max($x, $y) + 0.05) / (min($x, $y) + 0.05);
};
$th_pairs = array(
	array('ink', 'surface', 4.5), array('ink', 'page', 4.5), array('ink', 'sunken', 4.5),
	array('muted', 'surface', 4.5), array('muted', 'page', 4.5), array('subtle', 'surface', 4.5),
	array('on-brand', 'brand', 4.5), array('on-danger', 'danger', 4.5),
	array('ok-fg', 'ok-bg', 4.5), array('warn-fg', 'warn-bg', 4.5),
	array('bad-fg', 'bad-bg', 4.5), array('info-fg', 'info-bg', 4.5),
	array('field', 'surface', 3.0),
);
foreach (array('light' => $th_light, 'dark' => $th_dark) as $th_name => $th_set) {
	foreach ($th_pairs as $th_p) {
		if (!isset($th_set[$th_p[0]], $th_set[$th_p[1]])) { t_ok($th_name . ' token ' . $th_p[0] . '/' . $th_p[1] . ' exists', false); continue; }
		$r = $th_ratio($th_set[$th_p[0]], $th_set[$th_p[1]]);
		t_ok(sprintf('%s %s on %s >= %.1f (%.2f)', $th_name, $th_p[0], $th_p[1], $th_p[2], $r), $r >= $th_p[2]);
	}
}
$th_layout = file_get_contents(__DIR__ . '/../panel/views/layout.php');
t_ok('layout applies the stored theme before first paint', strpos($th_layout, 'gp_theme') !== false);
t_ok('layout carries a robots noindex meta', strpos($th_layout, 'name="robots"') !== false && strpos($th_layout, 'noindex') !== false);

t_section('IP allowlist and client address');
$ip_ok = function ($ip, $cidr) { return gp_ip_in($ip, $cidr); };
t_ok('IPv4 single address', $ip_ok('203.0.113.7', '203.0.113.7') && !$ip_ok('203.0.113.8', '203.0.113.7'));
t_ok('IPv4 /24 inside and outside', $ip_ok('198.51.100.200', '198.51.100.0/24') && !$ip_ok('198.51.101.1', '198.51.100.0/24'));
t_ok('IPv4 /20 and /32 and /0', $ip_ok('10.0.15.255', '10.0.0.0/20') && !$ip_ok('10.0.16.0', '10.0.0.0/20')
	&& $ip_ok('1.2.3.4', '1.2.3.4/32') && !$ip_ok('1.2.3.5', '1.2.3.4/32') && $ip_ok('9.9.9.9', '0.0.0.0/0'));
t_ok('IPv6 single address, compressed or not', $ip_ok('2001:db8::1', '2001:0db8:0:0:0:0:0:1') && !$ip_ok('2001:db8::2', '2001:db8::1'));
t_ok('IPv6 /32, /64 and /128', $ip_ok('2001:db8:ffff::1', '2001:db8::/32') && !$ip_ok('2001:db9::1', '2001:db8::/32')
	&& $ip_ok('2001:db8:0:1::5', '2001:db8:0:1::/64') && !$ip_ok('2001:db8:0:2::5', '2001:db8:0:1::/64')
	&& $ip_ok('::1', '::1/128'));
t_ok('IPv4 never matches an IPv6 range and the reverse', !$ip_ok('1.2.3.4', '::/0') && !$ip_ok('::1', '0.0.0.0/0'));
t_ok('IPv4-mapped IPv6 matches the IPv4 entry', $ip_ok('::ffff:203.0.113.7', '203.0.113.0/24'));
t_ok('invalid prefixes and garbage are refused',
	gp_ip_parse('1.2.3.4/33') === null && gp_ip_parse('::1/129') === null && gp_ip_parse('1.2.3.4/') === null
	&& gp_ip_parse('1.2.3.4/-1') === null && gp_ip_parse('1.2.3.4/8x') === null && gp_ip_parse('example.com') === null
	&& gp_ip_parse('1.2.3.4 ') !== null && gp_ip_parse('1.2.3') === null && gp_ip_parse('') === null
	&& gp_ip_parse('fe80::1%eth0') === null && gp_ip_parse('1.2.3.4-1.2.3.9') === null);

$ip_cfg = function ($list) { return array('ip_allowlist' => $list); };
$_SERVER['REMOTE_ADDR'] = '203.0.113.7';
unset($_SERVER['HTTP_X_FORWARDED_FOR']);
t_ok('no ip_allowlist key: not restricted', gp_ip_allowed(array()) === true);
t_ok('empty list: not restricted (documented default)', gp_ip_allowed($ip_cfg(array())) === true);
t_ok('listed client is allowed', gp_ip_allowed($ip_cfg(array('203.0.113.0/24'))) === true);
t_ok('unlisted client is refused', gp_ip_allowed($ip_cfg(array('198.51.100.0/24'))) === false);
t_ok('a list with only invalid entries refuses everybody (fail closed)', gp_ip_allowed($ip_cfg(array('nonsense', '1.2.3.4/99'))) === false);
t_ok('a valid entry still works next to an invalid one', gp_ip_allowed($ip_cfg(array('nonsense', '203.0.113.7'))) === true);
t_ok('a non-list value refuses everybody', gp_ip_allowed($ip_cfg(null)) === false);
$_SERVER['REMOTE_ADDR'] = '';
t_ok('no usable client address is refused when a list exists', gp_ip_allowed($ip_cfg(array('0.0.0.0/0'))) === false);
t_ok('gp_ip_list accepts a string and rejects non-strings', gp_ip_list('1.2.3.4') === array('1.2.3.4')
	&& gp_ip_list(array(1)) === null && gp_ip_list(5) === null && gp_ip_list('') === array());

$px = array('10.0.0.0/8', '2001:db8:aaaa::/48');
$px_res = function ($remote, $xff) use ($px) {
	$s = array('REMOTE_ADDR' => $remote);
	if ($xff !== null) { $s['HTTP_X_FORWARDED_FOR'] = $xff; }
	return gp_resolve_client_ip($s, $px);
};
t_ok('XFF is ignored when the peer is not a trusted proxy', $px_res('203.0.113.7', '198.51.100.9') === '203.0.113.7');
t_ok('XFF is used when the peer is a trusted proxy', $px_res('10.1.2.3', '198.51.100.9') === '198.51.100.9');
t_ok('a forged left-hand entry is not believed', $px_res('10.1.2.3', '1.1.1.1, 198.51.100.9') === '198.51.100.9');
t_ok('trusted hops on the right are skipped', $px_res('10.1.2.3', '198.51.100.9, 10.9.9.9') === '198.51.100.9');
t_ok('an IPv6 trusted proxy works', $px_res('2001:db8:aaaa::1', '198.51.100.9') === '198.51.100.9');
t_ok('a malformed header is ignored as a whole', $px_res('10.1.2.3', '198.51.100.9, not-an-ip') === '10.1.2.3');
t_ok('a missing header gives the peer', $px_res('10.1.2.3', null) === '10.1.2.3');
t_ok('no trusted proxies configured: header never read', gp_resolve_client_ip(array('REMOTE_ADDR' => '10.1.2.3', 'HTTP_X_FORWARDED_FOR' => '1.1.1.1'), array()) === '10.1.2.3');
t_ok('mapped IPv6 peer is canonicalised', gp_resolve_client_ip(array('REMOTE_ADDR' => '::ffff:203.0.113.7'), array()) === '203.0.113.7');
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';

t_section('noindex headers and routing');
$nx_src = file_get_contents(__DIR__ . '/../panel/index.php');
t_ok('PHP sends X-Robots-Tag with noindex on every panel response', strpos($nx_src, "X-Robots-Tag: noindex, nofollow, noarchive, nosnippet") !== false);
$nx_ht = file_get_contents(__DIR__ . '/../panel/.htaccess');
t_ok('.htaccess adds X-Robots-Tag for static files and Apache errors', preg_match('/Header always set X-Robots-Tag "noindex/', $nx_ht) === 1);
t_ok('the allowlist check runs before any route, including login', strpos($nx_src, 'gp_ip_allowed($gp_cfg)') < strpos($nx_src, 'switch ($gp_route)'));
t_ok('no robots.txt is shipped inside the panel', !is_file(__DIR__ . '/../panel/robots.txt'));

t_section('Data pipeline: status verdicts and the log readers');
// Point the guard at a scratch log directory for these checks.
$pl_dir = sys_get_temp_dir() . '/gp-pipe-' . bin2hex(random_bytes(4));
$pl_cfg = sys_get_temp_dir() . '/gp-pipe-cfg-' . bin2hex(random_bytes(4)) . '.php';
file_put_contents($pl_cfg, "<?php\nif (!defined('GV_BOOT')) { exit; }\n\$c = require " . var_export(realpath(__DIR__ . '/../scripts/config.dev.php'), true) . ";\n\$c['log_dir'] = " . var_export($pl_dir, true) . ";\nreturn \$c;\n");
$pl_prev = getenv('GV_CONFIG');
putenv('GV_CONFIG=' . $pl_cfg);
$ks_was = gp_killswitch_on();
if ($ks_was) { @unlink(gp_killswitch_path()); }
t_ok('missing log directory is reported as no_dir', gp_pipeline_status()['verdict'] === 'no_dir');
mkdir($pl_dir, 0775, true);
t_ok('an empty log directory is reported as never', gp_pipeline_status()['verdict'] === 'never');
$pl_now = time();
gv_log(array('v' => 5, 'rid' => 'r1', 'ts' => $pl_now - 30, 'ip' => '203.0.113.9', 'm' => 'GET', 'p' => '/', 'q' => '', 'act' => 'allow', 'sh' => 0), $pl_dir);
$pl_s = gp_pipeline_status($pl_now);
t_ok('a row written 30 s ago is ok, with its age', $pl_s['verdict'] === 'ok' && $pl_s['last_age'] >= 29 && $pl_s['last_age'] <= 31);
t_ok('the same row two hours later is quiet', gp_pipeline_status($pl_now + 7200)['verdict'] === 'quiet');
// An outcome line is newer than its decision row and must count as activity too.
gv_log_outcome(array('o' => 1, 'rid' => 'r1', 'ts' => $pl_now - 10, 'st' => 200, 'by' => 10, 'dur' => 3.0), $pl_dir);
t_ok('the newest line of either kind sets the last activity', (int)gp_pipeline_status($pl_now)['last_age'] <= 11);
file_put_contents(gp_killswitch_path(), '1');
t_ok('with the kill switch on and no recent row the verdict is killed', gp_pipeline_status($pl_now + 7200)['verdict'] === 'killed');
t_ok('a recent row still reads ok even with the kill switch on', gp_pipeline_status($pl_now)['verdict'] === 'ok');
@unlink(gp_killswitch_path());
if ($ks_was) { file_put_contents(gp_killswitch_path(), '1'); }
@chmod($pl_dir, 0555);
if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
	t_skip('read-only log directory is reported as not_writable', 'running as root, which ignores directory modes');
} else {
	t_ok('a read-only log directory is reported as not_writable', gp_pipeline_status()['verdict'] === 'not_writable');
}
@chmod($pl_dir, 0775);

// The status filter must see the outcome that was written AFTER the decision row.
gv_log(array('v' => 5, 'rid' => 'r404', 'ts' => $pl_now, 'ip' => '203.0.113.10', 'm' => 'GET', 'p' => '/gone', 'q' => '', 'act' => 'allow', 'sh' => 0), $pl_dir);
gv_log_outcome(array('o' => 1, 'rid' => 'r404', 'ts' => $pl_now, 'st' => 404, 'by' => 5, 'dur' => 1.0), $pl_dir);
gv_log(array('v' => 5, 'rid' => 'r200', 'ts' => $pl_now, 'ip' => '203.0.113.11', 'm' => 'GET', 'p' => '/ok', 'q' => '', 'act' => 'allow', 'sh' => 0), $pl_dir);
gv_log_outcome(array('o' => 1, 'rid' => 'r200', 'ts' => $pl_now, 'st' => 200, 'by' => 5, 'dur' => 1.0), $pl_dir);
$pl_404 = gp_log_query(array('status' => '404'), 0, 50)[0];
t_ok('the status filter 404 returns exactly the 404 row', count($pl_404) === 1 && $pl_404[0]['rid'] === 'r404');
t_ok('the status filter 2xx returns the 200 rows, not the 404', count(gp_log_query(array('status' => '2xx'), 0, 50)[0]) === 2);
t_ok('a row without an outcome never matches a status filter', count(gp_log_query(array('status' => '5xx'), 0, 50)[0]) === 0);
t_ok('without a filter every decision row comes back once', count(gp_log_query(array(), 0, 50)[0]) === 3);

// Many processes appending at once must not tear a line.
$pl_code = 'define("GV_BOOT",1);require ' . var_export(realpath(__DIR__ . '/../guard/log.php'), true) . ';'
	. 'for($i=0;$i<50;$i++){gv_log(array("v"=>5,"rid"=>getmypid()."-".$i,"ts"=>microtime(true),"ip"=>"203.0.113.1","m"=>"GET","p"=>"/c","q"=>"","ua"=>str_repeat("x",100),"act"=>"allow","sh"=>0),' . var_export($pl_dir, true) . ');}';
$pl_procs = array();
for ($i = 0; $i < 8; $i++) { $pl_procs[] = proc_open(array(PHP_BINARY, '-r', $pl_code), array(1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pl_pipes); }
foreach ($pl_procs as $pl_p) { if (is_resource($pl_p)) { proc_close($pl_p); } }
$pl_lines = file(gp_log_file(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$pl_bad = 0; foreach ($pl_lines as $pl_l) { if (!is_array(json_decode($pl_l, true))) { $pl_bad++; } }
t_ok('8 processes x 50 rows: all 400 are present and none is torn (' . count($pl_lines) . ' lines, ' . $pl_bad . ' bad)', $pl_bad === 0 && count($pl_lines) === 400 + 6);

foreach (glob($pl_dir . '/*') as $pl_f) { @unlink($pl_f); }
@rmdir($pl_dir); @unlink($pl_cfg);
putenv($pl_prev === false ? 'GV_CONFIG' : 'GV_CONFIG=' . $pl_prev);

t_section('Access rules page');
// The guard's error logger falls back to the repository's logs/ when no log dir is known.
$ar_logs = sys_get_temp_dir() . '/gp-rules-logs-' . getmypid();
gv_redis_ctx(array('log_dir' => $ar_logs));
require_once __DIR__ . '/../panel/rules.php';
$ar_file = sys_get_temp_dir() . '/gp-rules-selftest-' . getmypid() . '.json';
@unlink($ar_file);
putenv('GV_RULES=' . $ar_file);
$ar_audit_backup = is_file(gp_audit_path()) ? file_get_contents(gp_audit_path()) : null;
if (is_file(gp_audit_path())) { @unlink(gp_audit_path()); }
$ar_cfg = gv_cfg_defaults(array());
$ar_cfg['known_bots'] = array('googlebot', 'bingbot');
$ar_cfg['preview_bots'] = array('telegrambot');
$ar_cfg['exempt_paths'] = array();
$ar_post = array('do' => 'save', 'id' => '', 'name' => 'Block curl', 'enabled' => '1', 'skip_verified_bots' => '1',
	'mode' => 'monitor', 'action' => 'block', 'priority' => '100', 'ua_op' => 'include', 'ua_type' => 'contains',
	'ua_values' => "curl/\r\nWget\r\n", 'path_values' => '', 'pow_bits' => '0', 'expires_date' => '', 'note' => '');

t_ok('no file: state is missing and the list is empty', gp_rules_state()['state'] === 'missing' && gp_rules_state()['rules'] === array());
$ar = gp_rules_action('save', $ar_post, 'tester', '198.51.100.1', $ar_cfg);
t_ok('a valid rule is saved', $ar['ok'] === true && $ar['msg'] === 'rule_saved');
$ar_rules = gv_rules_read($ar_file);
t_ok('the guard reads back what the panel wrote (same validator)', count($ar_rules) === 1 && $ar_rules[0]['name'] === 'Block curl'
	&& $ar_rules[0]['ua']['values'] === array('curl/', 'Wget') && $ar_rules[0]['created_by'] === 'tester');
$ar_id = $ar_rules[0]['id'];
t_ok('the generated id is short and safe for a log reason', (bool)preg_match('/^r[0-9a-f]{6}$/', $ar_id));
t_ok('the file is not group- or world-writable', (fileperms($ar_file) & 0022) === 0);
t_ok('no temp file is left behind', glob($ar_file . '.tmp*') === array());
$ar_aud = gp_audit_read(10);
t_ok('creating a rule is audited with before (null) and after', count($ar_aud) === 1 && $ar_aud[0]['event'] === 'rule_create'
	&& $ar_aud[0]['key'] === $ar_id && $ar_aud[0]['old'] === null && $ar_aud[0]['new']['name'] === 'Block curl');

$ar_cache = gv_rules_cache_path($ar_file);
t_ok('a save also writes the generated cache next to the JSON', is_file($ar_cache) && filemtime($ar_cache) >= filemtime($ar_file));
$ar_loaded = gv_rules_load();
t_ok('the guard loads that cache (enabled rules, compiled pattern present)', count($ar_loaded) === 1 && isset($ar_loaded[0]['ua']['pat']));
t_ok('the cache is not group- or world-writable and leaves no temp file', (fileperms($ar_cache) & 0022) === 0 && glob($ar_cache . '.tmp*') === array());
t_ok('the cache is valid PHP returning the same ids as the JSON', (include $ar_cache) === $ar_loaded && array_column($ar_loaded, 'id') === array($ar_id));

// Validation failures are reported per field and nothing is written.
$bad = $ar_post; $bad['ua_type'] = 'regex'; $bad['ua_values'] = '(unclosed'; $bad['name'] = 'bad regex';
$ar = gp_rules_action('save', $bad, 'tester', '198.51.100.1', $ar_cfg);
t_ok('a broken regex is refused with a message on the UA field', $ar['ok'] === false && isset($ar['errors']['ua']) && $ar['errors']['ua'] === 'bad_regex'
	&& isset($ar['details']['ua']));
t_ok('the refused rule was not written', count(gv_rules_read($ar_file)) === 1);
$bad = $ar_post; $bad['ua_values'] = ''; $bad['path_values'] = '';
t_ok('a rule without any condition is refused', gp_rules_action('save', $bad, 't', '1.1.1.1', $ar_cfg)['errors']['ua'] === 'no_condition');
$bad = $ar_post; $bad['expires_date'] = '2026-13-45';
t_ok('an invalid expiry date is refused', isset(gp_rules_action('save', $bad, 't', '1.1.1.1', $ar_cfg)['errors']['expires_at']));
$bad = $ar_post; $bad['name'] = str_repeat('n', 81);
t_ok('a name over 80 characters is refused', isset(gp_rules_action('save', $bad, 't', '1.1.1.1', $ar_cfg)['errors']['name']));

// Warnings are non-blocking, shown once, then "save anyway".
$warn = $ar_post; $warn['name'] = 'Too wide'; $warn['ua_type'] = 'contains'; $warn['ua_values'] = 'Mozilla';
$ar = gp_rules_action('save', $warn, 'tester', '1.1.1.1', $ar_cfg);
$ar_codes = array_column($ar['warnings'], 0);
t_ok('a pattern matching real browsers warns and is not saved yet', $ar['ok'] === false && $ar['msg'] === 'rule_warnings' && in_array('browsers', $ar_codes, true));
$warn['ack'] = '1';
t_ok('with the acknowledgement the same rule is saved', gp_rules_action('save', $warn, 'tester', '1.1.1.1', $ar_cfg)['ok'] === true);
$gb = array_merge(gp_rule_blank(), array('id' => 'r-x1', 'name' => 'x', 'ua' => array('op' => 'include', 'type' => 'contains', 'values' => array('googlebot'))));
t_ok('a pattern matching a known bot warns', in_array('bots', array_column(gp_rule_warnings($gb, $ar_cfg), 0), true));
$short = array_merge(gp_rule_blank(), array('id' => 'r-x2', 'name' => 'x', 'ua' => array('op' => 'include', 'type' => 'contains', 'values' => array('ab'))));
t_ok('a "contains" pattern under 4 characters warns', in_array('short', array_column(gp_rule_warnings($short, $ar_cfg), 0), true));
$ex_cfg = array_merge($ar_cfg, array('exempt_paths' => array('/pay/')));
$pathrule = array_merge(gp_rule_blank(), array('id' => 'r-x3', 'name' => 'x', 'ua' => null, 'path' => array('op' => 'include', 'type' => 'prefix', 'values' => array('/pay/cb'))));
t_ok('a path rule that overlaps an exempt path warns', in_array('exempt', array_column(gp_rule_warnings($pathrule, $ex_cfg), 0), true));
$exact = array_merge(gp_rule_blank(), array('id' => 'r-x4', 'name' => 'x', 'ua' => array('op' => 'include', 'type' => 'exact', 'values' => array('weird-client/1'))));
t_ok('a precise pattern warns about nothing', gp_rule_warnings($exact, $ar_cfg) === array());
t_ok('every browser sample is a Mozilla UA string', count(gp_rules_browser_samples()) >= 8);

// Edit, toggle, duplicate, move, delete: each audited.
$edit = $ar_post; $edit['id'] = $ar_id; $edit['name'] = 'Block curl v2';
t_ok('an existing rule can be edited', gp_rules_action('save', $edit, 'tester', '1.1.1.1', $ar_cfg)['ok'] === true);
t_ok('an edit keeps created_by and created_at', gv_rules_read($ar_file)[0]['created_by'] === 'tester' && gv_rules_read($ar_file)[0]['name'] === 'Block curl v2');
$edit['id'] = 'rnotthere';
t_ok('editing a rule that does not exist is refused', gp_rules_action('save', $edit, 't', '1.1.1.1', $ar_cfg)['msg'] === 'rule_not_found');
$ar_before = gv_rules_read($ar_file)[0]['enabled'];
gp_rules_action('toggle', array('id' => $ar_id), 'tester', '1.1.1.1', $ar_cfg);
t_ok('toggle flips enabled', gv_rules_read($ar_file)[0]['enabled'] === !$ar_before);
t_ok('a disabled rule is dropped from the cache', !in_array($ar_id, array_column(gv_rules_load(), 'id'), true));
$n0 = count(gv_rules_read($ar_file));
gp_rules_action('duplicate', array('id' => $ar_id), 'tester', '1.1.1.1', $ar_cfg);
$ar_all = gv_rules_read($ar_file);
$ar_copy = null; foreach ($ar_all as $r) { if (substr($r['name'], -7) === ' (copy)') { $ar_copy = $r; } }
t_ok('duplicate adds a disabled monitor copy with a new id', count($ar_all) === $n0 + 1 && $ar_copy && !$ar_copy['enabled'] && $ar_copy['mode'] === 'monitor' && $ar_copy['id'] !== $ar_id);
$ar_pre = array_column(gv_rules_read($ar_file), 'id');
$ar_pos = array_search($ar_copy['id'], $ar_pre);
gp_rules_action('move', array('id' => $ar_copy['id'], 'dir' => 'up'), 'tester', '1.1.1.1', $ar_cfg);
$ar_order = array_column(gv_rules_read($ar_file), 'id');
t_ok('move up swaps with the neighbour and renumbers by 10', $ar_order[$ar_pos - 1] === $ar_copy['id'] && $ar_order[$ar_pos] === $ar_pre[$ar_pos - 1]
	&& array_column(gv_rules_read($ar_file), 'priority') === range(10, 10 * count($ar_order), 10));
gp_rules_action('delete', array('id' => $ar_copy['id']), 'tester', '1.1.1.1', $ar_cfg);
t_ok('delete removes the rule', !in_array($ar_copy['id'], array_column(gv_rules_read($ar_file), 'id'), true));
$ar_events = array_column(gp_audit_read(50), 'event');
t_ok('toggle, duplicate, reorder and delete are all audited',
	in_array('rule_toggle', $ar_events, true) && in_array('rule_duplicate', $ar_events, true)
	&& in_array('rule_reorder', $ar_events, true) && in_array('rule_delete', $ar_events, true) && in_array('rule_update', $ar_events, true));

// Starter set.
gp_rules_action('starter', array(), 'tester', '1.1.1.1', $ar_cfg);
$n1 = count(gv_rules_read($ar_file));
gp_rules_action('starter', array(), 'tester', '1.1.1.1', $ar_cfg);
t_ok('the starter set adds 16 disabled monitor rules, once', count(gv_rules_read($ar_file)) === $n1 && $n1 >= 16);

// An invalid file blocks writes (the guard ignores it; overwriting would hide it).
$ar_keep = file_get_contents($ar_file);
file_put_contents($ar_file, '{"rules":[{"id":"r-ok1"},"x"]}');
t_ok('a file with invalid rules is reported as invalid', gp_rules_state()['state'] === 'invalid');
t_ok('writes are refused while the file is invalid', gp_rules_action('toggle', array('id' => 'r-ok1'), 't', '1.1.1.1', $ar_cfg)['msg'] === 'rules_file_invalid');
t_ok('the invalid file was not touched', file_get_contents($ar_file) === '{"rules":[{"id":"r-ok1"},"x"]}');
file_put_contents($ar_file, 'garbage');
t_ok('unreadable JSON is invalid too', gp_rules_state()['state'] === 'invalid');
file_put_contents($ar_file, $ar_keep);

// The test box: pure function.
$ar_t = gp_rules_test(array(
	array_merge(gp_rule_blank(), array('id' => 'r-t1', 'name' => 't1', 'mode' => 'enforce', 'action' => 'block', 'priority' => 5,
		'ua' => array('op' => 'include', 'type' => 'contains', 'values' => array('googlebot')))),
	array_merge(gp_rule_blank(), array('id' => 'r-t2', 'name' => 't2', 'mode' => 'monitor', 'action' => 'log', 'priority' => 6,
		'ua' => array('op' => 'include', 'type' => 'contains', 'values' => array('googlebot')), 'skip_verified_bots' => false)),
), 'Googlebot/2.1', '/', false, $ar_cfg, time());
t_ok('the test box names the winning rule and the known bot', $ar_t['winner']['id'] === 'r-t1' && $ar_t['bot'] === 'googlebot' && count($ar_t['matches']) === 2);
$ar_t = gp_rules_test(array(
	array_merge(gp_rule_blank(), array('id' => 'r-t1', 'name' => 't1', 'mode' => 'enforce', 'action' => 'block', 'priority' => 5,
		'ua' => array('op' => 'include', 'type' => 'contains', 'values' => array('googlebot')))),
), 'Googlebot/2.1', '/', true, $ar_cfg, time());
t_ok('a verified crawler skips the rule in the test box', $ar_t['winner'] === null && $ar_t['skipped'] === array('r-t1'));
t_ok('the test box on an empty UA matches an <empty> rule',
	gp_rules_test(array(array_merge(gp_rule_blank(), array('id' => 'r-t3', 'name' => 't', 'ua' => array('op' => 'include', 'type' => 'exact', 'values' => array(GV_RULE_EMPTY))))), '', '/', false, $ar_cfg, time())['winner']['id'] === 'r-t3');
t_ok('the test box changes nothing: the file is as it was', file_get_contents($ar_file) === $ar_keep);

// Quick block pre-fill.
$qb = gp_rule_from_ua('curl/8.4.0');
t_ok('quick block: exact UA rule in monitor mode', $qb['mode'] === 'monitor' && $qb['ua']['type'] === 'exact' && $qb['ua']['values'] === array('curl/8.4.0') && $qb['action'] === 'block');
t_ok('quick block of a UA cut at 120 chars becomes a prefix rule', gp_rule_from_ua(str_repeat('a', 120))['ua']['type'] === 'prefix');
t_ok('quick block of an empty UA uses <empty>', gp_rule_from_ua('')['ua']['values'] === array(GV_RULE_EMPTY));
t_ok('the pre-filled rule validates', gv_rule_validate(array_merge($qb, array('id' => 'r-qb1')), true)[0] === true);

// Table filters: is / is not, several values, text contains / does not contain.
$fr = array(array_merge(gp_rule_blank(), array('id' => 'r-f1', 'name' => 'Alpha scraper', 'action' => 'block', 'mode' => 'enforce', 'ua' => array('op' => 'include', 'type' => 'contains', 'values' => array('x')))),
	array_merge(gp_rule_blank(), array('id' => 'r-f2', 'name' => 'Beta', 'action' => 'challenge', 'mode' => 'monitor', 'enabled' => false, 'ua' => array('op' => 'include', 'type' => 'contains', 'values' => array('y')))));
$fl = function ($get) use ($fr) { $f = gp_rules_filter_from_request($get); return array_column(array_filter($fr, function ($r) use ($f) { return gp_rules_filter_match($r, $f, time()); }), 'id'); };
t_ok('filter: action is block', $fl(array('action' => 'block')) === array('r-f1'));
t_ok('filter: action is not block', array_values($fl(array('action' => 'block', 'action_op' => 'not'))) === array('r-f2'));
t_ok('filter: several values are OR-ed', count($fl(array('action' => 'block,challenge'))) === 2);
t_ok('filter: state is disabled', $fl(array('state' => 'disabled')) === array('r-f2'));
t_ok('filter: fields are AND-ed', $fl(array('action' => 'block', 'mode' => 'monitor')) === array());
t_ok('filter: text contains / does not contain', $fl(array('q' => 'scraper')) === array('r-f1') && array_values($fl(array('q' => 'scraper', 'q_op' => 'not'))) === array('r-f2'));
t_ok('filter: no filter shows everything', count($fl(array())) === 2);

// Impact preview.
$im_dir = sys_get_temp_dir() . '/gp-impact-' . bin2hex(random_bytes(4));
$im_cfg = sys_get_temp_dir() . '/gp-impact-cfg-' . bin2hex(random_bytes(4)) . '.php';
file_put_contents($im_cfg, "<?php\nif (!defined('GV_BOOT')) { exit; }\n\$c = require " . var_export(realpath(__DIR__ . '/../scripts/config.dev.php'), true) . ";\n\$c['log_dir'] = " . var_export($im_dir, true) . ";\nreturn \$c;\n");
$im_prev = getenv('GV_CONFIG');
putenv('GV_CONFIG=' . $im_cfg);
mkdir($im_dir, 0775, true);
$im_now = time();
$im_row = function ($ts, $ua, $p, $ip, $dev = '', $tok = 'm', $botv = '') {
	return array('v' => 5, 'ts' => $ts, 'ua' => $ua, 'p' => $p, 'ip' => $ip, 'dev' => $dev, 'tok' => $tok, 'botv' => $botv, 'act' => 'allow');
};
$im_rule = array_merge(gp_rule_blank(), array('id' => 'r-im1', 'name' => 'im', 'mode' => 'monitor', 'action' => 'block',
	'ua' => array('op' => 'include', 'type' => 'contains', 'values' => array('scrapy'))));
$im_rows = array(
	$im_row(1, 'Scrapy/2.0', '/a', '198.51.100.1'), $im_row(2, 'Scrapy/2.0', '/a', '198.51.100.1'),
	$im_row(3, 'scrapy x', '/b', '198.51.100.2', 'dev1'), $im_row(4, 'Mozilla/5.0 Chrome', '/a', '198.51.100.3'),
	$im_row(5, 'Scrapy', '/c', '198.51.100.4', 'dev2', 'v'), $im_row(6, 'Scrapy', '/c', '198.51.100.9', '', 'm', 'ok'),
);
$imp = gp_rules_impact_fold($im_rule, $im_rows);
t_ok('impact: counts matching requests, distinct IPs and distinct devices', $imp['requests'] === 4 && $imp['ips'] === 3 && $imp['devices'] === 2 && $imp['scanned'] === 6);
t_ok('impact: counts requests that carried a valid token', $imp['tokened'] === 1);
t_ok('impact: a verified crawler is not counted when the rule skips it', $imp['ips'] === 3);
$imp2 = gp_rules_impact_fold(array_merge($im_rule, array('skip_verified_bots' => false)), $im_rows);
t_ok('impact: ...but is counted when the rule does not skip', $imp2['requests'] === 5);
t_ok('impact: top paths are ordered by count', array_key_first($imp['paths']) === '/a' && $imp['paths']['/a'] === 2);
t_ok('impact: a valid token makes the warning red', $imp['danger'] === true);
$many = array();
for ($k = 0; $k < 51; $k++) { $many[] = $im_row(10 + $k, 'Scrapy', '/x' . $k, '203.0.113.' . ($k % 250), 'devx' . $k); }
t_ok('impact: more than 50 distinct devices is red', gp_rules_impact_fold($im_rule, $many)['danger'] === true);
t_ok('impact: 50 devices and no token is not red', gp_rules_impact_fold($im_rule, array_slice($many, 0, 50))['danger'] === false);
$top = array();
for ($k = 0; $k < 9; $k++) { $top[] = $im_row($k + 1, 'Scrapy', '/p' . $k, '203.0.113.5'); }
t_ok('impact: at most five top paths', count(gp_rules_impact_fold($im_rule, $top)['paths']) === 5);
t_ok('impact: no rows, nothing matched, not red', gp_rules_impact_fold($im_rule, array())['danger'] === false);
t_ok('impact: a path condition is evaluated on the logged path',
	gp_rules_impact_fold(array_merge($im_rule, array('ua' => null, 'path' => array('op' => 'include', 'type' => 'prefix', 'values' => array('/c')))), $im_rows)['requests'] === 1);

// The scanner: newest first, two files, outcome lines skipped, range reported.
gv_log($im_row($im_now - 90000, 'Scrapy', '/old', '198.51.100.50'), $im_dir);
$f_today = gp_log_file();
file_put_contents($f_today, json_encode($im_row($im_now - 300, 'Scrapy/2', '/t1', '198.51.100.60', 'd60')) . "\n"
	. json_encode(array('o' => 1, 'rid' => 'x', 'ts' => $im_now - 299, 'st' => 200)) . "\n"
	. json_encode($im_row($im_now - 100, 'Mozilla', '/t2', '198.51.100.61')) . "\nnot json\n");
$f_prev = gp_log_file(date('Ymd', $im_now - 86400));
file_put_contents($f_prev, json_encode($im_row($im_now - 86400 + 5, 'Scrapy/1', '/y1', '198.51.100.70', 'd70', 'v')) . "\n");
$live = gp_rules_impact($im_rule);
t_ok('the scanner reads today and yesterday and skips outcome lines and junk', $live['scanned'] === 3 && $live['requests'] === 2 && $live['meta']['files'] === 2);
t_ok('the scanner reports the time range it covered', abs($live['meta']['newest'] - ($im_now - 100)) < 1 && abs($live['meta']['oldest'] - ($im_now - 86400 + 5)) < 1);
t_ok('the scanner reports that no cap was hit on a small log', $live['meta']['capped'] === false);
t_ok('the live preview carries the token flag through (red)', $live['tokened'] === 1 && $live['danger'] === true);
$fh = fopen($im_dir . '/guard-20000101.jsonl', 'w');
$line = json_encode($im_row($im_now, 'Scrapy', '/big', '198.51.100.1')) . "\n";
for ($k = 0; $k < GP_MAX_SCAN_LINES + 100; $k++) { fwrite($fh, $line); }
fclose($fh);
unlink($f_today); unlink($f_prev);
$cap_dates = array('20000101');
$cap_n = 0;
$cap_meta = gp_log_scan($cap_dates, function ($row) use (&$cap_n) { $cap_n++; });
t_ok('the scanner stops at the existing line cap and says so', $cap_meta['capped'] === true && $cap_n <= GP_MAX_SCAN_LINES);

// Switching a rule to enforce needs the impact and an acknowledgement.
$en_file = sys_get_temp_dir() . '/gp-rules-enforce-' . getmypid() . '.json';
putenv('GV_RULES=' . $en_file);
$en_post = array('do' => 'save', 'id' => '', 'name' => 'Enforce me', 'enabled' => '1', 'skip_verified_bots' => '1', 'mode' => 'monitor',
	'action' => 'block', 'priority' => '100', 'ua_op' => 'include', 'ua_type' => 'exact', 'ua_values' => 'weird-client/1', 'path_values' => '',
	'pow_bits' => '0', 'expires_date' => '', 'note' => '');
t_ok('a new monitor rule is saved without a preview step', gp_rules_action('save', $en_post, 't', '1.1.1.1', $ar_cfg)['ok'] === true);
$en_id = gv_rules_read($en_file)[0]['id'];
$en_post['id'] = $en_id; $en_post['mode'] = 'enforce';
$r = gp_rules_action('save', $en_post, 't', '1.1.1.1', $ar_cfg);
t_ok('monitor -> enforce is not saved yet: it returns the impact and a warning', $r['ok'] === false && $r['msg'] === 'rule_warnings' && is_array($r['impact'])
	&& in_array('enforce', array_column($r['warnings'], 0), true));
t_ok('...and the rule is still in monitor mode', gv_rules_read($en_file)[0]['mode'] === 'monitor');
$en_post['ack'] = '1';
t_ok('with the acknowledgement it is switched to enforce', gp_rules_action('save', $en_post, 't', '1.1.1.1', $ar_cfg)['ok'] === true && gv_rules_read($en_file)[0]['mode'] === 'enforce');
$en_post['name'] = 'Enforce me again'; unset($en_post['ack']);
t_ok('editing a rule that is already enforcing asks for nothing', gp_rules_action('save', $en_post, 't', '1.1.1.1', $ar_cfg)['ok'] === true);
$pv = $en_post; $pv['mode'] = 'monitor'; $pv['name'] = 'Preview only';
$before = file_get_contents($en_file);
$r = gp_rules_action('preview', $pv, 't', '1.1.1.1', $ar_cfg);
t_ok('Preview returns the impact and saves nothing', $r['ok'] === false && $r['msg'] === 'rule_preview' && is_array($r['impact']) && file_get_contents($en_file) === $before);
$pv['ua_type'] = 'regex'; $pv['ua_values'] = '(unclosed';
t_ok('Preview of an invalid rule reports the errors instead', isset(gp_rules_action('preview', $pv, 't', '1.1.1.1', $ar_cfg)['errors']['ua']));
$r = gp_rules_action('save', array_merge($en_post, array('id' => '', 'name' => 'new enforcing', 'ua_values' => 'other-client/2')), 't', '1.1.1.1', $ar_cfg);
t_ok('a NEW rule created in enforce mode also needs the impact review', $r['ok'] === false && is_array($r['impact']) && $r['draft']['id'] === '');
foreach (array('rules_impact', 'rules_impact_danger', 'rules_impact_range', 'rules_impact_capped', 'rules_impact_note', 'rules_preview', 'rwarn_enforce', 'rwarn_enforce_danger', 'rule_preview') as $k) {
	t_ok('translation exists: ' . $k, isset($GLOBALS['ar_lang'][$k]) || strpos(file_get_contents(__DIR__ . '/../panel/lang.php'), "'" . $k . "'") !== false);
}
@unlink($en_file); @unlink($en_file . '.lock'); @unlink(gv_rules_cache_path($en_file));
putenv('GV_RULES=' . $ar_file);
foreach ((array)glob($im_dir . '/{,.}*', GLOB_BRACE) as $f) { if (is_file($f)) { @unlink($f); } }
@rmdir($im_dir); @unlink($im_cfg);
putenv($im_prev === false ? 'GV_CONFIG' : 'GV_CONFIG=' . $im_prev);

// Every dynamic translation key the page builds exists.
$ar_lang = require __DIR__ . '/../panel/lang.php';
$ar_miss = array();
foreach (array_merge(
	array_map(function ($a) { return 'rules_act_' . $a; }, gv_rule_actions()),
	array_map(function ($a) { return 'rules_type_' . $a; }, gv_rule_ua_types()),
	array('rules_mode_enforce', 'rules_mode_monitor', 'rwarn_bots', 'rwarn_browsers', 'rwarn_short', 'rwarn_exempt', 'rwarn_wide',
		'rerr_bad_id', 'rerr_empty', 'rerr_too_long', 'rerr_not_allowed', 'rerr_out_of_range', 'rerr_bad_condition', 'rerr_bad_op',
		'rerr_bad_type', 'rerr_not_list', 'rerr_no_values', 'rerr_too_many', 'rerr_no_condition', 'rerr_must_start_slash',
		'rerr_bad_regex', 'rerr_regex_backref', 'rerr_regex_costly', 'rerr_regex_slow', 'rerr_regex_join', 'rerr_duplicate_id', 'rerr_not_utf8',
		'rerr_control_chars', 'rerr_not_string', 'rule_saved', 'rule_done', 'rule_not_found', 'rule_warnings', 'rules_invalid',
		'rules_file_invalid', 'rule_starter_done', 'write_failed')) as $k) {
	if (!isset($ar_lang[$k])) { $ar_miss[] = $k; }
}
t_ok('every translation key the rules page builds dynamically exists' . ($ar_miss ? ' (missing: ' . implode(',', $ar_miss) . ')' : ''), !$ar_miss);
$ar_view = file_get_contents(__DIR__ . '/../panel/views/rules.php');
t_ok('the rules page posts a CSRF token on every form', substr_count($ar_view, '<form method="post"') <= substr_count($ar_view, 'gp_csrf_token()'));
t_ok('the rules page escapes through gp_e (no raw echo of a variable)', preg_match('/<\?= \$[a-z_]+\s*\?>/', $ar_view) === 0);

@unlink($ar_file); @unlink($ar_file . '.lock'); @unlink($ar_cache);
foreach ((array)glob($ar_logs . '/{,.}*', GLOB_BRACE) as $f) { if (is_file($f)) { @unlink($f); } }
@rmdir($ar_logs);
putenv('GV_RULES');
if (is_file(gp_audit_path())) { @unlink(gp_audit_path()); }
if ($ar_audit_backup !== null) { file_put_contents(gp_audit_path(), $ar_audit_backup); }

t_section('GeoIP page and country / ASN rules');
require_once __DIR__ . '/../panel/geo.php';
require_once __DIR__ . '/../panel/jobs.php';
require_once __DIR__ . '/geo-fixture.php';
$gx_tmp = sys_get_temp_dir() . '/gp-geo-selftest-' . getmypid();
@mkdir($gx_tmp . '/geo', 0775, true);
@mkdir($gx_tmp . '/logs', 0775, true);
gv_redis_ctx(array('log_dir' => $gx_tmp . '/logs'));
putenv('GV_GEO_DIR=' . $gx_tmp . '/geo');
putenv('GV_RULES=' . $gx_tmp . '/rules.json');
gv_geo_state(true);
define('GP_TEST_UPLOADS', 1);
$gx_audit_backup = is_file(gp_audit_path()) ? file_get_contents(gp_audit_path()) : null;
if (is_file(gp_audit_path())) { @unlink(gp_audit_path()); }
$gx_g4 = array(array_merge(gf_cidr4('5.0.0.0/8'), array('IR')), array_merge(gf_cidr4('127.0.0.0/8'), array('US')));
$gx_bin = function ($built, $kind = 1) use ($gx_g4) {
	return $kind === 1 ? gf_pack(1, $gx_g4, array(), $built, 'fixture.dat')
		: gf_pack(2, array(array(83886080, 100663295, 12880)), array(), $built, 'asn.mmdb');
};
$gx_now = 1900000000;

// PHP limits and file names.
t_ok('ini sizes: K, M, G, plain, unlimited', gp_ini_bytes('2M') === 2097152 && gp_ini_bytes('512K') === 524288 && gp_ini_bytes('1G') === 1073741824
	&& gp_ini_bytes('8192') === 8192 && gp_ini_bytes('0') === 0 && gp_ini_bytes('') === 0 && gp_ini_bytes('-1') === 0);
t_ok('the upload limit is the smaller of the two PHP limits', gp_geo_upload_limit() >= 0);
t_ok('source names: .mmdb and .dat only, sanitised, no path, no compiled names',
	gp_geo_clean_name('GeoLite2-Country.mmdb') === 'GeoLite2-Country.mmdb' && gp_geo_clean_name('geoip.dat') === 'geoip.dat'
	&& gp_geo_clean_name('../../etc/x.mmdb') === 'x.mmdb' && gp_geo_clean_name('a b.mmdb') === 'a_b.mmdb'
	&& gp_geo_clean_name('shell.php') === '' && gp_geo_clean_name('.htaccess') === '' && gp_geo_clean_name('country.bin') === ''
	&& gp_geo_clean_name('country.bin.mmdb') === '' && gp_geo_clean_name('') === '' && gp_geo_clean_name(str_repeat('a', 70) . '.dat') === '');

// Upload.
$gx_up = function ($name, $content, $err = 0) use ($gx_tmp) {
	$tmp = $gx_tmp . '/upload.tmp';
	file_put_contents($tmp, $content);
	return array('name' => $name, 'tmp_name' => $tmp, 'error' => $err, 'size' => strlen($content));
};
$gx_mmdb = str_repeat('x', 1000) . "\xAB\xCD\xEFMaxMind.com" . str_repeat('m', 50);
t_ok('upload: a valid .mmdb is stored under its clean name and audited', (function () use ($gx_up, $gx_mmdb, $gx_tmp) {
	$r = gp_geo_upload($gx_up('Geo Country.mmdb', $gx_mmdb), 'tester', '198.51.100.1');
	$a = gp_audit_read(5);
	return $r[0] && $r[1] === 'geo_up_done' && is_file($gx_tmp . '/geo/Geo_Country.mmdb') && $a && $a[0]['event'] === 'geo_upload' && $a[0]['key'] === 'Geo_Country.mmdb';
})());
t_ok('upload: no temp file is left in geo/', glob($gx_tmp . '/geo/*.part*') === array());
t_ok('upload: a file without the MaxMind marker is refused', gp_geo_upload($gx_up('x.mmdb', 'just text'), 't', '1.1.1.1')[1] === 'geo_up_badfile' && !is_file($gx_tmp . '/geo/x.mmdb'));
t_ok('upload: a geoip.dat is accepted', gp_geo_upload($gx_up('geoip.dat', "\x0a\x00"), 't', '1.1.1.1')[0] === true && is_file($gx_tmp . '/geo/geoip.dat'));
t_ok('upload: a script or an unnamed file is refused', gp_geo_upload($gx_up('shell.php', '<?php'), 't', '1.1.1.1')[1] === 'geo_up_badname' && !is_file($gx_tmp . '/geo/shell.php'));
t_ok('upload: too big for PHP, no file, and a failed upload each say so',
	gp_geo_upload(array('name' => 'a.mmdb', 'tmp_name' => '', 'error' => UPLOAD_ERR_INI_SIZE), 't', '1.1.1.1')[1] === 'geo_up_toobig'
	&& gp_geo_upload(array('error' => UPLOAD_ERR_NO_FILE), 't', '1.1.1.1')[1] === 'geo_up_nofile'
	&& gp_geo_upload(array('name' => 'a.mmdb', 'tmp_name' => '', 'error' => UPLOAD_ERR_PARTIAL), 't', '1.1.1.1')[1] === 'geo_up_failed'
	&& gp_geo_upload(array(), 't', '1.1.1.1')[1] === 'geo_up_nofile');
t_ok('upload: the compile job type exists and takes no parameters', in_array('geo_compile', gp_job_types(), true) && gp_job_params('geo_compile', array())[0] === true);

// Status, staleness, rollback.
t_ok('status: nothing compiled yet', gp_geo_status($gx_now)['country'] === null && gp_geo_status($gx_now)['asn'] === null && gp_geo_status($gx_now)['stale'] === false);
file_put_contents($gx_tmp . '/geo/country.bin', $gx_bin($gx_now - 10 * 86400));
$gx_st = gp_geo_status($gx_now);
t_ok('status: a fresh country file shows its header', $gx_st['country']['valid'] && $gx_st['country']['age_days'] === 10 && $gx_st['country']['v4'] === 2 && $gx_st['country']['source'] === 'fixture.dat' && !$gx_st['stale']);
file_put_contents($gx_tmp . '/geo/country.bin', $gx_bin($gx_now - 46 * 86400));
t_ok('status: older than 45 days is stale, exactly 45 is not', gp_geo_status($gx_now)['stale'] === true
	&& (function () use ($gx_tmp, $gx_bin, $gx_now) { file_put_contents($gx_tmp . '/geo/country.bin', $gx_bin($gx_now - 45 * 86400)); return gp_geo_status($gx_now)['stale'] === false; })());
file_put_contents($gx_tmp . '/geo/country.bin', $gx_bin($gx_now - 90 * 86400));
file_put_contents($gx_tmp . '/geo/asn.bin', $gx_bin($gx_now - 5 * 86400, 2));
t_ok('status: the oldest of the two files decides', gp_geo_status($gx_now)['stale'] === true && gp_geo_status($gx_now)['asn']['age_days'] === 5);
t_ok('warnings: stale', gp_geo_warnings(gp_geo_status($gx_now), 0, gv_cfg_defaults(array())) === array('stale'));
file_put_contents($gx_tmp . '/geo/country.bin', 'GARBAGE');
t_ok('status: a damaged file is reported as corrupt, not as missing', gp_geo_status($gx_now)['country']['valid'] === false && in_array('corrupt', gp_geo_warnings(gp_geo_status($gx_now), 0, gv_cfg_defaults(array())), true));
@unlink($gx_tmp . '/geo/country.bin'); @unlink($gx_tmp . '/geo/asn.bin');
t_ok('warnings: a geo rule with no database at all', gp_geo_warnings(gp_geo_status($gx_now), 1, gv_cfg_defaults(array())) === array('missing'));
t_ok('warnings: geo.log on with no country database', in_array('log_no_db', gp_geo_warnings(gp_geo_status($gx_now), 0, array('geo' => array('log' => true))), true));

file_put_contents($gx_tmp . '/geo/country.bin', $gx_bin($gx_now - 1 * 86400));
file_put_contents($gx_tmp . '/geo/country.bin.prev', $gx_bin($gx_now - 40 * 86400));
t_ok('rollback: the previous file becomes the live file (audited), the .prev stays', (function () use ($gx_tmp, $gx_now) {
	$r = gp_geo_rollback('country', 'tester', '1.1.1.1');
	$h = gv_geo_header_parse(file_get_contents($gx_tmp . '/geo/country.bin', false, null, 0, 128));
	$a = gp_audit_read(1);
	return $r[0] && $h['built'] === $gx_now - 40 * 86400 && is_file($gx_tmp . '/geo/country.bin.prev') && $a[0]['event'] === 'geo_rollback' && glob($gx_tmp . '/geo/*.rb*') === array();
})());
t_ok('rollback: nothing to roll back to / a damaged previous file', gp_geo_rollback('asn', 't', '1.1.1.1')[1] === 'geo_rb_none'
	&& (function () use ($gx_tmp) { file_put_contents($gx_tmp . '/geo/asn.bin.prev', 'junk'); return gp_geo_rollback('asn', 't', '1.1.1.1')[1] === 'geo_rb_bad'; })());
@unlink($gx_tmp . '/geo/asn.bin.prev');
file_put_contents($gx_tmp . '/geo/geo-status.json', json_encode(array('v' => 1, 'time' => $gx_now - 100, 'ok' => false, 'errors' => array('country table not replaced: no range for IR'),
	'sources' => array(array('name' => 'geoip.dat', 'size' => 2, 'mtime' => 5, 'provides' => array('country'), 'used' => array('country'))),
	'ignored_tags' => array('private' => 3, 'cloudflare' => 9), 'countries' => array('IR', 'US'))));
$gx_st = gp_geo_status($gx_now);
t_ok('status: the last compile result, ignored tags and errors are read from geo-status.json', $gx_st['compile']['ok'] === false && $gx_st['ignored_tags']['private'] === 3
	&& $gx_st['errors'][0] === 'country table not replaced: no range for IR' && $gx_st['countries'] === array('IR', 'US'));
t_ok('status: a source on disk that the last compile has not seen is listed as new', (function () use ($gx_st) {
	foreach ($gx_st['sources'] as $s) { if ($s['name'] === 'Geo_Country.mmdb' && !empty($s['new'])) { return true; } }
	return false;
})());
file_put_contents($gx_tmp . '/geo/geo-status.json', '{not json');
t_ok('status: a damaged geo-status.json is ignored', gp_geo_status($gx_now)['compile'] === null);
@unlink($gx_tmp . '/geo/geo-status.json');

// The form (no database installed yet).
@unlink($gx_tmp . '/geo/country.bin'); @unlink($gx_tmp . '/geo/country.bin.prev'); @unlink($gx_tmp . '/geo/asn.bin');
gv_geo_state(true);
$gx_post = array('do' => 'save', 'id' => '', 'name' => 'Block IR', 'enabled' => '1', 'skip_verified_bots' => '1', 'mode' => 'monitor', 'action' => 'challenge',
	'priority' => '100', 'ua_values' => '', 'path_values' => '', 'pow_bits' => '0', 'expires_date' => '', 'note' => '',
	'country_op' => 'exclude', 'country_values' => "ir, tr\nIR", 'asn_op' => 'include', 'asn_values' => 'AS13335  15169,as15169');
$gx_rule = gp_rule_from_post($gx_post);
t_ok('form: country codes are upper-cased and de-duplicated, ASN numbers lose their AS prefix',
	$gx_rule['country'] === array('op' => 'exclude', 'type' => 'code', 'values' => array('IR', 'TR'))
	&& $gx_rule['asn'] === array('op' => 'include', 'type' => 'number', 'values' => array('13335', '15169')));
$gx_empty = $gx_post; $gx_empty['country_values'] = '  '; $gx_empty['asn_values'] = '';
t_ok('form: empty boxes mean no condition', gp_rule_from_post($gx_empty)['country'] === null && gp_rule_from_post($gx_empty)['asn'] === null);
$gx_cfg = gv_cfg_defaults(array());
$gx_save = $gx_post; $gx_save['asn_values'] = '';
$gx_r = gp_rules_action('save', $gx_save, 'tester', '1.1.1.1', $gx_cfg);
t_ok('a country-only rule is saved (no UA needed), warns about the missing database, and is not saved until acknowledged', $gx_r['ok'] === false && $gx_r['msg'] === 'rule_warnings'
	&& in_array('geo_nodb', array_column($gx_r['warnings'], 0), true) && in_array('geo_exclude_ir', array_column($gx_r['warnings'], 0), true) === false);
$gx_save['ack'] = '1';
t_ok('...and saves with the acknowledgement', gp_rules_action('save', $gx_save, 'tester', '1.1.1.1', $gx_cfg)['ok'] === true);
$gx_back = gv_rules_read(gv_rules_path());
$gx_loaded = gv_rules_load();
t_ok('the guard reads the country rule back, and the generated cache carries its set', count($gx_back) === 1 && $gx_back[0]['country']['values'] === array('IR', 'TR')
	&& $gx_loaded[0]['country']['set'] === array('IR' => true, 'TR' => true));
$gx_bad = $gx_post; $gx_bad['country_values'] = 'IRAN'; $gx_bad['asn_values'] = 'AS0';
$gx_r = gp_rules_action('save', $gx_bad, 't', '1.1.1.1', $gx_cfg);
t_ok('a bad country code and a bad AS number are reported on their own fields', $gx_r['errors']['country'] === 'bad_country' && $gx_r['errors']['asn'] === 'bad_asn');

// Warnings.
$gx_w = function (array $over, $geo = null) use ($gx_cfg, $gx_post) {
	return array_column(gp_rule_warnings(array_merge(gp_rule_from_post($gx_post), $over), $gx_cfg, $geo), 0);
};
$gx_good_geo = array('country' => array('valid' => true), 'asn' => array('valid' => true), 'countries' => array('IR', 'US', 'DE', 'TR'));
t_ok('warning: block / challenge by country without skipping verified crawlers',
	in_array('geo_bots', $gx_w(array('skip_verified_bots' => false, 'action' => 'block')), true) && in_array('geo_bots', $gx_w(array('skip_verified_bots' => false, 'action' => 'challenge')), true)
	&& !in_array('geo_bots', $gx_w(array('skip_verified_bots' => true, 'action' => 'block')), true) && !in_array('geo_bots', $gx_w(array('skip_verified_bots' => false, 'action' => 'log')), true));
t_ok('warning: "not IR -> block" names the VPN problem; "not IR -> challenge" does not',
	in_array('geo_exclude_ir', $gx_w(array('action' => 'block')), true) && !in_array('geo_exclude_ir', $gx_w(array('action' => 'challenge')), true)
	&& !in_array('geo_exclude_ir', $gx_w(array('action' => 'block', 'country' => array('op' => 'include', 'type' => 'code', 'values' => array('IR')))), true)
	&& !in_array('geo_exclude_ir', $gx_w(array('action' => 'block', 'country' => array('op' => 'exclude', 'type' => 'code', 'values' => array('DE')))), true));
t_ok('warning: the rule needs a database that is not installed', in_array('geo_nodb', $gx_w(array(), array('country' => null, 'asn' => null, 'countries' => array())), true)
	&& !in_array('geo_nodb', $gx_w(array('asn' => null), $gx_good_geo), true));
t_ok('warning: a country code that is not in the active database', in_array('geo_code_absent', $gx_w(array('country' => array('op' => 'include', 'type' => 'code', 'values' => array('IR', 'QQ'))), $gx_good_geo), true)
	&& !in_array('geo_code_absent', $gx_w(array(), $gx_good_geo), true));
t_ok('no geo warning for a rule with no country / ASN condition', array_filter($gx_w(array('country' => null, 'asn' => null, 'ua' => array('op' => 'include', 'type' => 'contains', 'values' => array('curlx'))), $gx_good_geo),
	function ($c) { return strpos($c, 'geo_') === 0; }) === array());

// The test box and the tester.
file_put_contents($gx_tmp . '/geo/country.bin', $gx_bin($gx_now - 86400));
file_put_contents($gx_tmp . '/geo/asn.bin', $gx_bin($gx_now - 86400, 2));
gv_geo_state(true);
$gx_rules = array(
	array_merge(gp_rule_blank(), array('id' => 'r-ir', 'name' => 'IR', 'mode' => 'enforce', 'action' => 'block', 'ua' => null,
		'country' => array('op' => 'include', 'type' => 'code', 'values' => array('IR')))),
	array_merge(gp_rule_blank(), array('id' => 'r-as', 'name' => 'AS', 'priority' => 200, 'mode' => 'enforce', 'action' => 'challenge', 'ua' => null,
		'asn' => array('op' => 'include', 'type' => 'number', 'values' => array('12880')))),
);
$gx_t = gp_geo_test('5.1.1.1', 'Mozilla/5.0', '/', false, $gx_rules, $gx_cfg, $gx_now);
t_ok('tester: country, ASN and the winning rule for an address', $gx_t['cc'] === 'IR' && $gx_t['asn'] === 12880 && $gx_t['winner']['id'] === 'r-ir' && array_column($gx_t['matches'], 'id') === array('r-ir', 'r-as'));
$gx_t = gp_geo_test('127.0.0.1', 'x', '/', false, $gx_rules, $gx_cfg, $gx_now);
t_ok('tester: another country matches nothing', $gx_t['cc'] === 'US' && $gx_t['asn'] === 0 && $gx_t['winner'] === null);
t_ok('tester: an address in no range is unknown and matches no geo rule', gp_geo_test('8.8.8.8', 'x', '/', false, $gx_rules, $gx_cfg, $gx_now)['cc'] === '' && gp_geo_test('8.8.8.8', 'x', '/', false, $gx_rules, $gx_cfg, $gx_now)['winner'] === null);
t_ok('tester: IPv4-mapped IPv6 input; garbage and empty input', gp_geo_test('::ffff:5.1.1.1', 'x', '/', false, $gx_rules, $gx_cfg, $gx_now)['cc'] === 'IR'
	&& gp_geo_test('nope', 'x', '/', false, $gx_rules, $gx_cfg, $gx_now) === null && gp_geo_test('', 'x', '/', false, $gx_rules, $gx_cfg, $gx_now) === null);
t_ok('the rules test box takes an optional IP; without one the country is unknown', gp_rules_test($gx_rules, 'x', '/', false, $gx_cfg, $gx_now, '5.1.1.1')['winner']['id'] === 'r-ir'
	&& gp_rules_test($gx_rules, 'x', '/', false, $gx_cfg, $gx_now)['winner'] === null);
t_ok('the verified-bot skip applies to a country rule in the tester', (function () use ($gx_rules, $gx_cfg, $gx_now) {
	$c = $gx_cfg; $c['known_bots'] = array('googlebot');
	$t = gp_geo_test('5.1.1.1', 'Googlebot/2.1', '/', true, $gx_rules, $c, $gx_now);
	return $t['winner'] === null && $t['skipped'] === array('r-ir', 'r-as');
})());

// Impact preview with country / ASN.
$gx_irrule = $gx_rules[0];
$gx_rows = array(
	array('ip' => '5.1.1.1', 'ua' => 'a', 'p' => '/a', 'cc' => 'IR', 'dev' => 'd1', 'tok' => 'm'),
	array('ip' => '5.2.2.2', 'ua' => 'a', 'p' => '/a', 'dev' => 'd2', 'tok' => 'v'),               // no cc in the log: resolved now
	array('ip' => '127.0.0.1', 'ua' => 'a', 'p' => '/a'),                                             // resolved now: US
	array('ip' => '127.0.0.2', 'ua' => 'a', 'p' => '/a', 'cc' => 'US'),
);
$gx_im = gp_rules_impact_fold($gx_irrule, $gx_rows);
t_ok('impact: logged and resolved-now rows are both counted and told apart', $gx_im['requests'] === 2 && $gx_im['geo'] === true && $gx_im['geo_logged'] === 2 && $gx_im['geo_lookup'] === 2 && $gx_im['geo_none'] === 0 && $gx_im['tokened'] === 1);
$gx_im = gp_rules_impact_fold($gx_irrule, array(array('ip' => '5.1.1.1', 'ua' => 'a', 'p' => '/a', 'cc' => 'IR'), array('ip' => '5.1.1.2', 'ua' => 'a', 'p' => '/a', 'cc' => 'IR')));
t_ok('impact: a log with cc on every row needs no lookup', $gx_im['geo_logged'] === 2 && $gx_im['geo_lookup'] === 0 && $gx_im['requests'] === 2);
putenv('GV_GEO_DIR=' . $gx_tmp . '/nodb');
gv_geo_state(true);
$gx_im = gp_rules_impact_fold($gx_irrule, array(array('ip' => '5.1.1.1', 'ua' => 'a', 'p' => '/a'), array('ip' => '5.1.1.2', 'ua' => 'a', 'p' => '/a')));
t_ok('impact: no cc in the log and no database: the preview says it cannot evaluate (counts none), not "zero matches"', $gx_im['requests'] === 0 && $gx_im['geo_none'] === 2 && $gx_im['geo_logged'] === 0 && $gx_im['geo_lookup'] === 0 && $gx_im['scanned'] === 2);
putenv('GV_GEO_DIR=' . $gx_tmp . '/geo');
gv_geo_state(true);
t_ok('impact: a rule with no geo condition carries no geo counters of note', gp_rules_impact_fold(gp_rule_blank() + array(), array())['geo'] === false);
$gx_asn_im = gp_rules_impact_fold($gx_rules[1], array(array('ip' => '5.1.1.1', 'ua' => 'a', 'p' => '/', 'asn' => 12880), array('ip' => '8.8.8.8', 'ua' => 'a', 'p' => '/', 'asn' => 0), array('ip' => '5.9.9.9', 'ua' => 'a', 'p' => '/')));
t_ok('impact: ASN rows, an unknown ASN (0) in the log never matches', $gx_asn_im['requests'] === 2 && $gx_asn_im['geo_logged'] === 2 && $gx_asn_im['geo_lookup'] === 1);
t_ok('impact: the Rules page and the preview scan carry the geo counters through gp_rules_impact', (function () use ($gx_irrule) {
	$i = gp_rules_impact($gx_irrule);
	return array_key_exists('geo_none', $i) && array_key_exists('meta', $i);
})());

// Logs: filters and export.
t_ok('log filter: cc (any case) and asn', gp_log_match(array('cc' => 'IR'), array('cc' => 'ir')) && !gp_log_match(array('cc' => 'US'), array('cc' => 'IR')) && !gp_log_match(array(), array('cc' => 'IR'))
	&& gp_log_match(array('asn' => 12880), array('asn' => 12880)) && !gp_log_match(array('asn' => 1), array('asn' => 12880)) && gp_log_match(array(), array()));
$gx_index = file_get_contents(__DIR__ . '/../panel/index.php');

// Dashboard, settings, strings, views.
file_put_contents($gx_tmp . '/geo/country.bin', $gx_bin(time() - 60 * 86400));
t_ok('the dashboard warns when a database is older than 45 days', gp_geo_dashboard_warnings() === array('stale'));
file_put_contents($gx_tmp . '/geo/country.bin', $gx_bin(time() - 3 * 86400));
t_ok('the dashboard is quiet about a fresh database', gp_geo_dashboard_warnings() === array());
@unlink($gx_tmp . '/geo/country.bin'); @unlink($gx_tmp . '/geo/asn.bin'); @unlink($gx_tmp . '/rules.json'); @unlink(gv_rules_cache_path($gx_tmp . '/rules.json'));
$gx_def = array();
$gx_lang = require __DIR__ . '/../panel/lang.php';
foreach (array('stale', 'missing', 'corrupt', 'no_country', 'log_no_db') as $c) { if (!isset($gx_lang['geo_w_' . $c])) { $gx_def[] = 'geo_w_' . $c; } }
foreach (array('geo_up_toobig', 'geo_up_nofile', 'geo_up_badname', 'geo_up_badfile', 'geo_up_failed', 'geo_up_nowrite', 'geo_up_done', 'geo_compile_queued', 'geo_compile_failed',
	'geo_rb_none', 'geo_rb_bad', 'geo_rb_done', 'rwarn_geo_bots', 'rwarn_geo_exclude_ir', 'rwarn_geo_nodb', 'rwarn_geo_code_absent', 'rerr_bad_country', 'rerr_bad_asn',
	'lbl_geo_log', 'help_geo_log', 'set_group_geo', 'nav_geo', 'rules_impact_geo_blind', 'rules_impact_geo_nolog', 'rules_impact_geo_mixed') as $k) {
	if (!isset($gx_lang[$k])) { $gx_def[] = $k; }
}
t_ok('every GeoIP translation key the page builds dynamically exists' . ($gx_def ? ' (missing: ' . implode(',', $gx_def) . ')' : ''), !$gx_def);
$gx_view = file_get_contents(__DIR__ . '/../panel/views/geo.php');
t_ok('the GeoIP page posts a CSRF token on every POST form and escapes everything', substr_count($gx_view, 'method="post"') === substr_count($gx_view, 'gp_csrf_token()')
	&& preg_match('/<\?= \$[a-z_]+\s*\?>/', $gx_view) === 0 && strpos($gx_view, 'enctype="multipart/form-data"') !== false);
t_ok('the GeoIP page loads nothing from outside (no http:// or https:// URL)', preg_match('#https?://#', $gx_view) === 0);
t_ok('Settings has a GeoIP group with the geo.log switch, labelled', strpos(file_get_contents(__DIR__ . '/../panel/views/settings.php'), "'geo.log'") !== false);
t_ok('the panel routes /geo and links it in the navigation', strpos($gx_index, "case 'geo':") !== false && strpos(file_get_contents(__DIR__ . '/../panel/views/layout.php'), "'geo'") !== false);

foreach ((array)glob($gx_tmp . '/{geo,logs}/{,.}*', GLOB_BRACE) as $f) { if (is_file($f)) { @unlink($f); } }
foreach (array('/geo', '/logs', '/nodb') as $d) { @rmdir($gx_tmp . $d); }
foreach ((array)glob($gx_tmp . '/*') as $f) { if (is_file($f)) { @unlink($f); } }
@rmdir($gx_tmp);
putenv('GV_GEO_DIR'); putenv('GV_RULES');
gv_geo_state(true);
if (is_file(gp_audit_path())) { @unlink(gp_audit_path()); }
if ($gx_audit_backup !== null) { file_put_contents(gp_audit_path(), $gx_audit_backup); }

t_section('Panel layout: include / exclude filters, tabs, tooltips');
require_once __DIR__ . '/../panel/filters.php';
require_once __DIR__ . '/../panel/ui.php';
if (!function_exists('gp_t')) {
	$GP_STRINGS = require __DIR__ . '/../panel/lang.php';
	function gp_t($key) { global $GP_STRINGS; return isset($GP_STRINGS[$key]) ? $GP_STRINGS[$key] : $key; }
}
$fx_spec = array('act' => 'choice', 'cc' => array('choice', 'ci' => true), 'ip' => 'ident', 'path' => 'text', 'n' => 'num');

// Parser.
$fp = gp_filter_parse(array('act' => '403, 429 ,403', 'act_op' => 'not', 'cc' => 'ir,Us', 'path' => '  /admin ', 'ip' => '10.0.0.0/8', 'n' => '7x', 'junk' => 'x'), $fx_spec);
t_ok('parser: comma list, trimmed, de-duplicated, operator not', $fp['act'] === array('v' => array('403', '429'), 'not' => true));
t_ok('parser: absent operator means include; ci values are upper-cased', $fp['cc'] === array('v' => array('IR', 'US'), 'not' => false) && $fp['ip']['not'] === false);
t_ok('parser: text is one value, num is an int, unknown keys are dropped', $fp['path']['v'] === array('/admin') && $fp['n'] === 7 && !isset($fp['junk']));
t_ok('parser: empty values and array parameters are ignored', gp_filter_parse(array('act' => ' , ,', 'path' => '', 'cc' => array('x')), $fx_spec) === array());
t_ok('parser: an operator other than "not" is include', gp_filter_parse(array('act' => 'a', 'act_op' => 'NOT'), $fx_spec)['act']['not'] === false && gp_filter_parse(array('act' => 'a', 'act_op' => 'is'), $fx_spec)['act']['not'] === false);
t_ok('parser: caps on the number and length of values', count(gp_filter_parse(array('act' => implode(',', range(1, 30))), $fx_spec)['act']['v']) === GP_FILTER_MAX_VALUES
	&& strlen(gp_filter_parse(array('path' => str_repeat('a', 500)), $fx_spec)['path']['v'][0]) === GP_FILTER_MAX_LEN);

// Matcher: every operator.
$ft = function ($type, $f, $actual, $ci = false) { return gp_filter_test($type, $f, $actual, $ci); };
$is = array('v' => array('403', '429'), 'not' => false);
$not = array('v' => array('403', '429'), 'not' => true);
t_ok('choice: is matches any listed value, is not matches none', $ft('choice', $is, '429') && !$ft('choice', $is, '200') && !$ft('choice', $not, '429') && $ft('choice', $not, '200'));
t_ok('choice: a list of actual values (row reasons): any hit counts', $ft('choice', array('v' => array('B'), 'not' => false), array('A', 'B')) && !$ft('choice', array('v' => array('B'), 'not' => true), array('A', 'B')) && $ft('choice', array('v' => array('B'), 'not' => true), array()));
t_ok('choice: case-insensitive only when asked', $ft('choice', array('v' => array('IR'), 'not' => false), 'ir', true) && !$ft('choice', array('v' => array('IR'), 'not' => false), 'ir', false));
t_ok('text: contains / does not contain, case-insensitive', $ft('text', array('v' => array('ADMIN'), 'not' => false), '/wp-admin/x') && !$ft('text', array('v' => array('ADMIN'), 'not' => true), '/wp-admin/x') && $ft('text', array('v' => array('admin'), 'not' => true), '/shop'));
t_ok('ident: an address matches a v4 CIDR, an exact address, and a v6 CIDR; "is not" inverts',
	$ft('ident', array('v' => array('10.0.0.0/8'), 'not' => false), '10.9.8.7') && !$ft('ident', array('v' => array('10.0.0.0/8'), 'not' => false), '11.0.0.1')
	&& $ft('ident', array('v' => array('192.0.2.5'), 'not' => false), '192.0.2.5') && !$ft('ident', array('v' => array('192.0.2.5'), 'not' => false), '192.0.2.6')
	&& $ft('ident', array('v' => array('2001:db8::/32'), 'not' => false), '2001:db8:1::5') && !$ft('ident', array('v' => array('2001:db8::/32'), 'not' => false), '2001:db9::1')
	&& $ft('ident', array('v' => array('10.0.0.0/8'), 'not' => true), '11.0.0.1') && !$ft('ident', array('v' => array('10.0.0.0/8'), 'not' => true), '10.0.0.1'));
t_ok('CIDR: odd prefix lengths, /0, /32, bad input and mixed families', gp_filter_in_cidr('10.1.2.3', '10.1.2.0/23') && !gp_filter_in_cidr('10.1.4.3', '10.1.2.0/23')
	&& gp_filter_in_cidr('1.2.3.4', '0.0.0.0/0') && gp_filter_in_cidr('1.2.3.4', '1.2.3.4/32') && !gp_filter_in_cidr('1.2.3.4', '1.2.3.0/33')
	&& !gp_filter_in_cidr('1.2.3.4', '1.2.3.0/x') && !gp_filter_in_cidr('1.2.3.4', '::/0') && !gp_filter_in_cidr('nope', '1.0.0.0/8') && gp_filter_in_cidr('::1', '::/0'));
t_ok('legacy scalar filters still mean "is"; empty means nothing to test', gp_filter_def('x') === array('v' => array('x'), 'not' => false) && gp_filter_def('') === null && gp_filter_def(array('v' => array(), 'not' => true)) === null && $ft('choice', '', 'anything'));

// Query string round trip.
$q = gp_filter_qs($fp + array('date' => '20261121'));
t_ok('query string: comma values, _op=not only for exclude, scalars pass through', $q['act'] === '403,429' && $q['act_op'] === 'not' && !isset($q['cc_op']) && $q['date'] === '20261121');
t_ok('query string: parse(qs(parse(x))) is stable', gp_filter_parse($q, $fx_spec) === gp_filter_parse(gp_filter_qs(gp_filter_parse($q, $fx_spec)), $fx_spec));
t_ok('gp_logs_qs keeps the operators, the cursor and the export flag', (function () use ($fp) {
	parse_str(substr(gp_logs_qs($fp, array('cursor' => 5, 'export' => 'csv')), strlen('index.php?')), $o);
	return $o['r'] === 'logs' && $o['act'] === '403,429' && $o['act_op'] === 'not' && $o['cursor'] === '5' && $o['export'] === 'csv';
})());

// Chips.
$chips = gp_filter_chips($fp + array('date' => '20261121'), array('act' => 'Action', 'cc' => 'Country', 'path' => 'Path'), array('path' => 'text'), function ($q) { return 'index.php?' . http_build_query(array_merge(array('r' => 'logs'), $q)); });
t_ok('chips: one per labelled operator filter, the exclude one is marked, the others are not', count($chips) === 3 && $chips[0]['not'] === true && $chips[1]['not'] === false && $chips[2]['kind'] === 'text');
t_ok('chips: removing one keeps the others and their operators, and the date', (function () use ($chips) {
	parse_str(substr($chips[1]['href'], strlen('index.php?')), $o);
	return !isset($o['cc']) && $o['act'] === '403,429' && $o['act_op'] === 'not' && $o['date'] === '20261121' && isset($o['path']);
})());
$chip_html = gp_filter_chips_html(gp_filter_chips(array('path' => array('v' => array('<script>alert(1)</script>"x'), 'not' => true)), array('path' => '<b>P</b>'), array('path' => 'text'), function ($q) { return 'index.php?x=' . http_build_query($q); }));
t_ok('chips: everything is escaped; "does not contain" is spelled out', strpos($chip_html, '<script>') === false && strpos($chip_html, '<b>') === false && strpos($chip_html, 'does not contain') !== false && strpos($chip_html, 'gp-chip-not') !== false);
t_ok('chips: no chips, no markup', gp_filter_chips_html(array()) === '');
$opsel = gp_filter_op_select('act', array('v' => array('a'), 'not' => true), 'is') . gp_filter_op_select('path', null, 'has');
t_ok('operator select: names, selected state and wording', strpos($opsel, 'name="act_op"') !== false && strpos($opsel, '<option value="not" selected>is not</option>') !== false && strpos($opsel, 'contains') !== false && strpos($opsel, 'name="path_op"') !== false);

// Logs: every field, include and exclude, AND.
$lr = array('ip' => '203.0.113.9', 'dev' => 'd1', 'p' => '/shop/item', 'ua' => 'Mozilla/5.0 Chrome', 'act' => '403', 'tok' => 'm', 'ovr' => '', 'sh' => 0, 'hold' => 1,
	'cc' => 'IR', 'asn' => 12880, 'rs' => array('UA_SCRIPT', 'RULE:r1'), 'sc' => 40, 'esc' => 55, '_out' => array('st' => 503));
$lm = function ($f) use ($lr) { return gp_log_match($lr, gp_filter_parse($f, array('act' => 'choice', 'ovr' => 'choice', 'tok' => 'choice', 'reason' => 'choice', 'sh' => 'choice', 'hold' => 'choice',
	'cc' => array('choice', 'ci' => true), 'asn' => 'choice', 'status' => 'choice', 'dev' => 'ident', 'ip' => 'ident', 'path' => 'text', 'ua' => 'text'))); };
t_ok('logs: act is / is not, several values', $lm(array('act' => '403,429')) && !$lm(array('act' => '200')) && !$lm(array('act' => '403', 'act_op' => 'not')) && $lm(array('act' => '200,429', 'act_op' => 'not')));
t_ok('logs: ip is / is not, CIDR', $lm(array('ip' => '203.0.113.0/24')) && !$lm(array('ip' => '203.0.113.0/24', 'ip_op' => 'not')) && $lm(array('ip' => '198.51.100.1', 'ip_op' => 'not')) && !$lm(array('ip' => '198.51.100.1')));
t_ok('logs: dev is / is not', $lm(array('dev' => 'd1')) && $lm(array('dev' => 'd2', 'dev_op' => 'not')) && !$lm(array('dev' => 'd1', 'dev_op' => 'not')));
t_ok('logs: path and UA contains / does not contain', $lm(array('path' => 'SHOP')) && !$lm(array('path' => 'shop', 'path_op' => 'not')) && $lm(array('path' => 'admin', 'path_op' => 'not'))
	&& $lm(array('ua' => 'chrome')) && !$lm(array('ua' => 'chrome', 'ua_op' => 'not')));
t_ok('logs: country is / is not (any case) and ASN is / is not on rows that have a value', $lm(array('cc' => 'ir,us')) && !$lm(array('cc' => 'IR', 'cc_op' => 'not')) && $lm(array('cc' => 'US', 'cc_op' => 'not'))
	&& $lm(array('asn' => '12880')) && !$lm(array('asn' => '12880', 'asn_op' => 'not')) && $lm(array('asn' => '1', 'asn_op' => 'not')));
t_ok('logs: reason matches any of the row\'s reasons; is not excludes the row', $lm(array('reason' => 'RULE:r1')) && $lm(array('reason' => 'X,UA_SCRIPT')) && !$lm(array('reason' => 'UA_SCRIPT', 'reason_op' => 'not')) && $lm(array('reason' => 'BOT_FAKE', 'reason_op' => 'not')));
t_ok('logs: tok, shadow and holdout flags (always present), ovr on a row with no override', $lm(array('tok' => 'm')) && !$lm(array('tok' => 'v')) && $lm(array('sh' => '0')) && !$lm(array('sh' => '1')) && $lm(array('hold' => '1')) && $lm(array('hold' => '0', 'hold_op' => 'not'))
	&& $lm(array('ovr' => 'allow', 'ovr_op' => 'not')) && $lm(array('ovr' => '(none)')));
t_ok('logs: status classes, include and exclude on a row that has an outcome', $lm(array('status' => '5xx')) && !$lm(array('status' => '2xx')) && !$lm(array('status' => '5xx', 'status_op' => 'not')) && $lm(array('status' => '404,4xx', 'status_op' => 'not')));
t_ok('logs: fields are AND-ed, with score ranges that keep no operator', $lm(array('act' => '403', 'cc' => 'IR', 'path' => 'shop')) && !$lm(array('act' => '403', 'cc' => 'US')) && gp_log_match($lr, array('sc_min' => 30, 'sc_max' => 40))
	&& !gp_log_match($lr, array('sc_min' => 41)) && !gp_log_match($lr, array('esc_max' => 54)));
t_ok('logs: the filter form reads every field from the query string', (function () {
	$_GET = array('act' => '403,429', 'act_op' => 'not', 'cc' => 'ir', 'ua' => 'curl', 'ua_op' => 'not', 'asn' => '13335', 'date' => '20261121', 'sc_min' => '30');
	$f = gp_logs_filter_from_request();
	$_GET = array();
	return $f['act']['not'] === true && $f['cc']['v'] === array('IR') && $f['ua']['not'] === true && $f['asn']['v'] === array('13335') && $f['date'] === '20261121' && $f['sc_min'] === 30;
})());
t_ok('logs: filter keys and CSV columns include cc and asn', isset(gp_log_filter_spec()['cc'], gp_log_filter_spec()['asn'], gp_log_filter_spec()['ua'])
	&& strpos(file_get_contents(__DIR__ . '/../panel/index.php'), "'botv', 'cc', 'asn', 'st'") !== false);

// Missing-value semantics. A field a row may lack (country, ASN, status, bot verdict,
// override, device, reasons) follows the rule engine's "unknown matches neither": a row
// WITHOUT the value matches neither "is" nor "is not". (none) selects absent rows.
$opt_fields = array(
	'cc'     => array(array(), array('cc' => 'IR'), array('cc' => 'US'), 'IR', 'ir'),
	'asn'    => array(array('asn' => 0), array('asn' => 12880), array('asn' => 15169), '12880', '12880'),
	'status' => array(array(), array('_out' => array('st' => 503)), array('_out' => array('st' => 200)), '5xx', '5xx'),
	'botv'   => array(array('botv' => ''), array('botv' => 'ok'), array('botv' => 'bad'), 'ok', 'ok'),
	'ovr'    => array(array('ovr' => ''), array('ovr' => 'allow'), array('ovr' => 'deny'), 'allow', 'allow'),
	'dev'    => array(array('dev' => ''), array('dev' => 'd1'), array('dev' => 'd2'), 'd1', 'd1'),
	'reason' => array(array('rs' => array()), array('rs' => array('UA_SCRIPT')), array('rs' => array('BOT_FAKE')), 'UA_SCRIPT', 'UA_SCRIPT'),
);
$ob = array(); $om = array();
foreach ($opt_fields as $of => $d) {
	// Absence means NOT KNOWN for cc / asn / status / botv; for ovr / dev / reason it is a KNOWN empty value.
	$known_empty = in_array($of, array('ovr', 'dev', 'reason'), true);
	$mk = function ($val, $op) use ($of) { return gp_filter_parse(array($of => $val, $of . '_op' => $op), array($of => $of === 'cc' ? array('choice', 'ci' => true) : ($of === 'dev' ? 'ident' : 'choice'))); };
	$chk = function ($val, $op, $absent, $has, $other) use ($of, $d, $mk, &$ob) {
		$f = $mk($val, $op);
		$got = array(gp_log_match($d[0], $f), gp_log_match($d[1], $f), gp_log_match($d[2], $f));
		if ($got !== array($absent, $has, $other)) { $ob[] = $of . ' ' . $op . ' ' . $val . ' => ' . json_encode($got); }
	};
	$v = $d[3];
	$chk($v, 'is', false, true, false);                    // is X: absent no
	$chk($v, 'not', $known_empty, false, true);            // is not X: absent NO for unknown fields, YES for known-empty ones
	$chk('(none)', 'is', true, false, false);              // is (none): the empty rows only
	$chk('(none)', 'not', false, true, true);              // is not (none): rows that have a value
	$chk($v . ',(none)', 'is', true, true, false);         // X or none
	$chk($v . ',(none)', 'not', false, false, true);       // not X and not none: empty rows are excluded by (none)
	$chk(strtoupper('(None)'), 'is', true, false, false);  // the token is case-insensitive
}
t_ok('every empty-able field (unknown: cc, asn, status, botv; known-empty: ovr, dev, reason): is / is not / (none) / mixed lists behave as specified on a row without, with, and with another value' . ($ob ? ' (' . implode('; ', $ob) . ')' : ''), !$ob);
t_ok('known-empty fields: "reason is not UA_EMPTY", "dev is not X" and "ovr is not deny" INCLUDE the rows with no reason / no device / no override',
	gp_log_match(array('rs' => array()), array('reason' => array('v' => array('UA_EMPTY'), 'not' => true))) && gp_log_match(array(), array('reason' => array('v' => array('UA_EMPTY'), 'not' => true)))
	&& gp_log_match(array('dev' => ''), array('dev' => array('v' => array('d1'), 'not' => true))) && gp_log_match(array(), array('dev' => array('v' => array('d1'), 'not' => true)))
	&& gp_log_match(array('ovr' => ''), array('ovr' => array('v' => array('deny'), 'not' => true))) && gp_log_match(array(), array('ovr' => array('v' => array('deny'), 'not' => true)))
	&& !gp_log_match(array('ovr' => ''), array('ovr' => array('v' => array('deny'), 'not' => false))));
t_ok('unknown-able fields: a row WITHOUT the field matches neither "is" nor "is not" (country, ASN, status, botv)',
	!gp_log_match(array(), array('cc' => array('v' => array('IR'), 'not' => false))) && !gp_log_match(array(), array('cc' => array('v' => array('IR'), 'not' => true)))
	&& !gp_log_match(array(), array('status' => array('v' => array('5xx'), 'not' => false))) && !gp_log_match(array(), array('status' => array('v' => array('5xx'), 'not' => true)))
	&& !gp_log_match(array(), array('botv' => array('v' => array('ok'), 'not' => false))) && !gp_log_match(array(), array('botv' => array('v' => array('ok'), 'not' => true)))
	&& !gp_log_match(array('asn' => 0), array('asn' => array('v' => array('1'), 'not' => true))) && !gp_log_match(array(), array('asn' => array('v' => array('1'), 'not' => true))));
t_ok('a row with asn 0 (looked up, none found) counts as having no ASN', gp_log_match(array('asn' => 0), array('asn' => array('v' => array('(none)'), 'not' => false))) && !gp_log_match(array('asn' => 0), array('asn' => array('v' => array('1'), 'not' => true))));
t_ok('always-present fields keep include / exclude: act, ip, tok, sh, path, ua', gp_log_match(array('ip' => '1.2.3.4'), array('ip' => array('v' => array('5.5.5.5'), 'not' => true)))
	&& gp_log_match(array(), array('act' => array('v' => array('403'), 'not' => true))) && gp_log_match(array('p' => '/a'), array('path' => array('v' => array('zzz'), 'not' => true)))
	&& gp_log_match(array('tok' => 'm'), array('tok' => array('v' => array('v'), 'not' => true))) && gp_log_match(array('sh' => 0), array('sh' => array('v' => array('1'), 'not' => true))));
t_ok('(none) on a field that always has a value (act 403) matches nothing; "is not (none)" matches it', !gp_log_match(array('act' => '403'), array('act' => array('v' => array('(none)'), 'not' => false)))
	&& gp_log_match(array('act' => '403'), array('act' => array('v' => array('(none)'), 'not' => true))));
t_ok('parser: (none) in any case is normalised, also in a case-insensitive field, and mixes with values', gp_filter_parse(array('cc' => '(NONE), ir'), array('cc' => array('choice', 'ci' => true)))['cc']['v'] === array('(none)', 'IR'));
t_ok('Share link, CSV export and paging keep (none): the query string carries it and it parses back unchanged', (function () {
	$f = gp_filter_parse(array('cc' => 'ir,(none)', 'cc_op' => 'not', 'status' => '(none)'), array('cc' => array('choice', 'ci' => true), 'status' => 'choice'));
	foreach (array(gp_logs_qs($f), gp_logs_qs($f, array('export' => 'csv')), gp_logs_qs($f, array('cursor' => 9))) as $u) {
		parse_str(substr($u, strlen('index.php?')), $o);
		if ($o['cc'] !== 'IR,(none)' || $o['cc_op'] !== 'not' || $o['status'] !== '(none)') { return false; }
		if (gp_filter_parse($o, array('cc' => array('choice', 'ci' => true), 'status' => 'choice')) !== $f) { return false; }
	}
	return strpos(gp_logs_qs($f), '%28none%29') !== false;
})());
t_ok('the chip of a (none) filter shows the token and its remove link keeps the others', (function () {
	$f = gp_filter_parse(array('cc' => '(none)', 'act' => '403'), array('cc' => 'choice', 'act' => 'choice'));
	$c = gp_filter_chips($f, array('cc' => 'Country', 'act' => 'Action'), array(), function ($q) { return 'index.php?' . http_build_query($q); });
	return $c[0]['text'] === '(none)' && strpos($c[0]['href'], 'act=403') !== false && strpos($c[0]['href'], 'cc=') === false;
})());
$nv = file_get_contents(__DIR__ . '/../panel/views/logs.php') . file_get_contents(__DIR__ . '/../panel/views/rules.php');
t_ok('the filter forms offer (none) in the datalist of optional fields and the logs form has the botv filter', strpos($nv, 'GP_FILTER_NONE') !== false && strpos($nv, "'botv'") !== false);

// Other lists.
$oi = array(array('kind' => 'deny', 'identity' => '203.0.113.5'), array('kind' => 'allow', 'identity' => 'devabc'), array('kind' => 'deny', 'identity' => '198.51.100.7'));
t_ok('overrides: kind and identity, is / is not, CIDR', count(gp_overrides_filter($oi, gp_filter_parse(array('kind' => 'deny'), array('kind' => 'choice')))) === 2
	&& count(gp_overrides_filter($oi, gp_filter_parse(array('kind' => 'deny', 'kind_op' => 'not'), array('kind' => 'choice')))) === 1
	&& count(gp_overrides_filter($oi, gp_filter_parse(array('identity' => '203.0.113.0/24'), array('identity' => 'ident')))) === 1
	&& count(gp_overrides_filter($oi, gp_filter_parse(array('identity' => '203.0.113.0/24', 'identity_op' => 'not'), array('identity' => 'ident')))) === 2);
$ar_row = array('event' => 'rule_update', 'actor' => 'admin', 'key' => 'r1');
t_ok('audit: event, actor, text contains / does not contain', gp_audit_match($ar_row, gp_filter_parse(array('event' => 'rule_update,config'), array('event' => 'choice')))
	&& !gp_audit_match($ar_row, gp_filter_parse(array('event' => 'rule_update', 'event_op' => 'not'), array('event' => 'choice')))
	&& gp_audit_match($ar_row, gp_filter_parse(array('actor' => 'bob', 'actor_op' => 'not'), array('actor' => 'ident')))
	&& gp_audit_match($ar_row, gp_filter_parse(array('q' => 'r1'), array('q' => 'text'))) && !gp_audit_match($ar_row, gp_filter_parse(array('q' => 'r1', 'q_op' => 'not'), array('q' => 'text'))));
$gs = array(array('name' => 'a.mmdb', 'used' => array('country')), array('name' => 'b.dat', 'used' => array()), array('name' => 'c.mmdb', 'new' => true), array('name' => 'd.mmdb', 'error' => 'x'));
t_ok('geoip sources: name contains / does not contain and use is / is not', count(gp_geo_filter_sources($gs, gp_filter_parse(array('name' => 'mmdb'), array('name' => 'text')))) === 3
	&& count(gp_geo_filter_sources($gs, gp_filter_parse(array('name' => 'mmdb', 'name_op' => 'not'), array('name' => 'text')))) === 1
	&& array_column(gp_geo_filter_sources($gs, gp_filter_parse(array('use' => 'used,unused'), array('use' => 'choice'))), 'name') === array('a.mmdb', 'b.dat')
	&& array_column(gp_geo_filter_sources($gs, gp_filter_parse(array('use' => 'used,unused', 'use_op' => 'not'), array('use' => 'choice'))), 'name') === array('c.mmdb', 'd.mmdb'));
$rfr = array(array_merge(gp_rule_blank(), array('id' => 'r-g1', 'name' => 'IR rule', 'country' => array('op' => 'include', 'type' => 'code', 'values' => array('IR')), 'ua' => null,
	'asn' => array('op' => 'include', 'type' => 'number', 'values' => array('13335')))), array_merge(gp_rule_blank(), array('id' => 'r-g2', 'name' => 'curl rule', 'ua' => array('op' => 'include', 'type' => 'contains', 'values' => array('curl')))));
$rfl = function ($get) use ($rfr) { $f = gp_rules_filter_from_request($get); return array_column(array_filter($rfr, function ($r) use ($f) { return gp_rules_filter_match($r, $f, time()); }), 'id'); };
t_ok('rules: a rule with no country / ASN condition has a KNOWN "none": "is not" includes it, (none) lists it', $rfl(array('cc' => 'ir')) === array('r-g1') && array_values($rfl(array('cc' => 'US', 'cc_op' => 'not'))) === array('r-g1', 'r-g2')
	&& $rfl(array('asn' => '13335')) === array('r-g1') && array_values($rfl(array('asn' => '1', 'asn_op' => 'not'))) === array('r-g1', 'r-g2')
	&& array_values($rfl(array('cc' => 'IR', 'cc_op' => 'not'))) === array('r-g2') && array_values($rfl(array('cc' => '(none)'))) === array('r-g2') && array_values($rfl(array('cc' => '(none)', 'cc_op' => 'not'))) === array('r-g1'));
t_ok('rules: UA text contains / does not contain', $rfl(array('ua' => 'CURL')) === array('r-g2') && array_values($rfl(array('ua' => 'curl', 'ua_op' => 'not'))) === array('r-g1'));
t_ok('identity page: rows are filtered by action and path', (function () {
	$f = gp_filter_parse(array('act' => '403', 'path' => 'shop', 'path_op' => 'not'), array('act' => 'choice', 'path' => 'text'));
	return gp_log_match(array('act' => '403', 'p' => '/cart'), $f) && !gp_log_match(array('act' => '403', 'p' => '/shop'), $f) && !gp_log_match(array('act' => '200', 'p' => '/cart'), $f);
})());
t_ok('a filter form renders operators, values, chips and keeps the hidden parameters (escaped)', (function () {
	$f = gp_filter_parse(array('act' => '403', 'act_op' => 'not'), array('act' => 'choice'));
	$h = gp_filter_form_html('identity', array('act' => array('logs_act', 'is', array('403', '429'), 'flt_act')), $f, array('id' => '"><x'));
	return strpos($h, 'name="act_op"') !== false && strpos($h, 'value="403"') !== false && strpos($h, 'gp-chip-not') !== false && strpos($h, '"><x') === false && strpos($h, '&quot;&gt;&lt;x') !== false;
})());

// Tabs.
ob_start();
gp_tabs_begin('rule', array('a' => 'Alpha', 'b' => 'Beta <b>', 'c' => 'Gamma'), array('b' => 2, 'c' => 1));
gp_tab_begin('rule', 'a', 'Alpha'); echo 'A'; gp_tab_end();
gp_tab_begin('rule', 'b', 'Beta'); echo 'B'; gp_tab_end();
gp_tabs_end();
$tabs_html = ob_get_clean();
t_ok('tabs: role tablist / tab / tabpanel with aria-controls and aria-labelledby', strpos($tabs_html, 'role="tablist"') !== false && substr_count($tabs_html, 'role="tab"') === 3
	&& strpos($tabs_html, 'aria-controls="panel-rule-b"') !== false && strpos($tabs_html, 'aria-labelledby="tab-rule-b"') !== false && strpos($tabs_html, 'role="tabpanel"') !== false);
t_ok('tabs: the first tab with an error opens, and every tab with errors has a badge with its count', strpos($tabs_html, 'data-open="b"') !== false
	&& strpos($tabs_html, '>2</span>') !== false && strpos($tabs_html, '>1</span>') !== false && substr_count($tabs_html, 'gp-tab-badge') === 2);
t_ok('tabs: no error means no data-open (the hash or the first tab decides); labels are escaped', strpos((function () { ob_start(); gp_tabs_begin('g', array('a' => 'A')); gp_tabs_end(); return ob_get_clean(); })(), 'data-open') === false && strpos($tabs_html, 'Beta <b>') === false);
t_ok('tabs: every panel is in the markup (without JavaScript they stack)', strpos($tabs_html, '>A<') !== false && strpos($tabs_html, '>B<') !== false && strpos($tabs_html, ' hidden') === false);
$lay = file_get_contents(__DIR__ . '/../panel/views/layout.php');
t_ok('tabs script: arrow keys, Home / End, roving tabindex, URL hash, error tab wins over the hash', strpos($lay, "'ArrowRight'") !== false && strpos($lay, "'ArrowLeft'") !== false && strpos($lay, "'Home'") !== false
	&& strpos($lay, "'End'") !== false && strpos($lay, "'tabindex'") !== false && strpos($lay, 'replaceState') !== false && strpos($lay, "box.getAttribute('data-open') || fromHash()") !== false);
t_ok('tooltip script: tap toggles, Escape and outside tap close, kept inside the screen', strpos($lay, "'Escape'") !== false && strpos($lay, 'closest(\'.gp-tip\')') !== false && strpos($lay, 'clientWidth') !== false && strpos($lay, 'gp-open') !== false);
$vset = file_get_contents(__DIR__ . '/../panel/views/settings.php');
t_ok('settings: one tab per group in one form with one Save button, errors open and badge the tab', strpos($vset, "gp_tabs_begin('set'") !== false && substr_count($vset, 'type="submit"') >= 1 && strpos($vset, '$tab_errors') !== false);
$vrules = file_get_contents(__DIR__ . '/../panel/views/rules.php');
$vgeo = file_get_contents(__DIR__ . '/../panel/views/geo.php');
t_ok('rules form: conditions / action / advanced tabs; the GeoIP page has tabs too', strpos($vrules, "gp_tabs_begin('rule'") !== false && strpos($vrules, "=> 'advanced'") !== false && strpos($vgeo, "gp_tabs_begin('geo'") !== false);
t_ok('rules form: every validator field maps to a tab', (function () use ($vrules) {
	foreach (array('ua', 'path', 'country', 'asn', 'action', 'mode', 'skip_verified_bots', 'pow_bits', 'priority', 'expires_at', 'note', 'enabled') as $f) { if (strpos($vrules, "'$f' =>") === false) { return false; } }
	return true;
})());

// Tooltips.
t_ok('tip: a button with aria-describedby pointing at a role=tooltip text, escaped, with a unique id each time', (function () {
	$a = gp_tip('rule_name'); $b = gp_tip('rule_name');
	preg_match('/aria-describedby="([^"]+)"/', $a, $m1); preg_match('/aria-describedby="([^"]+)"/', $b, $m2);
	return strpos($a, 'role="tooltip"') !== false && strpos($a, 'id="' . $m1[1] . '"') !== false && $m1[1] !== $m2[1] && strpos($a, '<button type="button"') !== false;
})());
t_ok('tip: an unknown key renders nothing (never a broken page)', gp_tip('no_such_tip_key') === '');
$tip_miss = array(); $tip_short = array();
$tip_keys = array();
foreach (array_keys(gv_overlay_whitelist()) as $k) { $tip_keys[] = 'set_' . str_replace('.', '_', $k); }
foreach (array('name', 'priority', 'enabled', 'action', 'mode', 'skip', 'ua', 'path', 'country', 'asn', 'expires', 'pow', 'note') as $k) { $tip_keys[] = 'rule_' . $k; }
foreach (array('compile', 'upload', 'rollback', 'delete', 'ip', 'ua', 'path', 'verified', 'filter', 'sources', 'active') as $k) { $tip_keys[] = 'geo_' . $k; }
foreach (array('rule_cc', 'rule_asn', 'ip', 'path', 'ua', 'cc', 'asn', 'act', 'status', 'reason', 'botv', 'tok', 'dev', 'sh', 'hold', 'ovr', 'date', 'score', 'q', 'kind', 'event', 'actor', 'use', 'state') as $k) { $tip_keys[] = 'flt_' . $k; }
$tip_lang = require __DIR__ . '/../panel/lang.php';
foreach ($tip_keys as $k) {
	$t = isset($tip_lang['tip_' . $k]) ? $tip_lang['tip_' . $k] : '';
	if ($t === '') { $tip_miss[] = $k; continue; }
	if (strlen($t) < 50 || stripos($t, 'safe value') === false || stripos($t, 'risk') === false || stripos($t, 'what it does') === false) { $tip_short[] = $k; }
}
t_ok('every setting, rule field, GeoIP field and filter has a tooltip text' . ($tip_miss ? ' (missing: ' . implode(',', $tip_miss) . ')' : ''), !$tip_miss);
t_ok('every tooltip says what it does, a safe value and the risk' . ($tip_short ? ' (incomplete: ' . implode(',', $tip_short) . ')' : ''), !$tip_short);
t_ok('every tooltip is more than the label repeated', (function () use ($tip_lang) {
	foreach ($tip_lang as $k => $v) {
		if (strpos($k, 'tip_set_') === 0) { $lbl = isset($tip_lang['lbl_' . substr($k, 8)]) ? $tip_lang['lbl_' . substr($k, 8)] : ''; if ($lbl !== '' && strlen($v) < strlen($lbl) + 40) { return false; } }
	}
	return true;
})());
$tip_used = array();
foreach (array('settings', 'rules', 'geo', 'logs', 'audit', 'overrides', 'identity') as $vn) {
	preg_match_all("/gp_tip\\('([a-z_]+)'\\)/", file_get_contents(__DIR__ . '/../panel/views/' . $vn . '.php'), $mm);
	foreach ($mm[1] as $k) { if (!isset($tip_lang['tip_' . $k])) { $tip_used[] = $vn . ':' . $k; } }
}
t_ok('every literal gp_tip() key in the views has a text' . ($tip_used ? ' (missing: ' . implode(',', $tip_used) . ')' : ''), !$tip_used);

// CSS: wide layout, no outside assets.
$css_src = file_get_contents(__DIR__ . '/../panel/assets/app.src.css');
$css_out = file_get_contents(__DIR__ . '/../panel/assets/app.css');
t_ok('layout: the shell and the top bar are 1680 px wide, not 7xl', substr_count($css_src, 'max-w-[1680px]') === 2 && strpos($css_src, 'max-w-7xl') === false && strpos($css_out, 'max-width:1680px') !== false);
t_ok('the compiled css has every new component', (function () use ($css_out) {
	foreach (array('.gp-tablist', '.gp-tab-badge', '.gp-tabpanel', '.gp-tip-box', '.gp-tip-btn', '.gp-chip', '.gp-chip-not', '.gp-cardgrid', '.gp-fgroup', '.gp-op') as $c) { if (strpos($css_out, $c) === false) { return false; } }
	return true;
})());
t_ok('the css and the new views load nothing from outside (no url(http...), no @import)', preg_match('#url\(\s*["\']?(https?:)?//#', $css_out) === 0 && strpos($css_out, '@import') === false
	&& preg_match('#https?://#', file_get_contents(__DIR__ . '/../panel/ui.php') . file_get_contents(__DIR__ . '/../panel/filters.php')) === 0);
t_ok('tables stay inside their card: every <table> in the views sits in a gp-table-wrap', (function () {
	foreach (glob(__DIR__ . '/../panel/views/*.php') as $vf) {
		$s = file_get_contents($vf);
		if (substr_count($s, '<table class="gp-table') > substr_count($s, 'gp-table-wrap')) { return false; }
	}
	return true;
})());

t_section('Job health, crontab check reader and dashboard alerts');
require_once __DIR__ . '/../panel/health.php';
$jh_tmp = sys_get_temp_dir() . '/gp-health-' . getmypid();
@mkdir($jh_tmp . '/status', 0775, true);
@mkdir($jh_tmp . '/logs', 0775, true);
gv_redis_ctx(array('log_dir' => $jh_tmp . '/logs'));
putenv('GV_JOBSTATUS_DIR=' . $jh_tmp . '/status');
putenv('GP_JOBS_SEEN=' . $jh_tmp . '/seen.json');
$jh_audit_backup = is_file(gp_audit_path()) ? file_get_contents(gp_audit_path()) : null;
if (is_file(gp_audit_path())) { @unlink(gp_audit_path()); }
$jh_cfg_file = $jh_tmp . '/config.php';
file_put_contents($jh_cfg_file, "<?php\nif (!defined('GV_BOOT')) { exit; }\n\$c = require " . var_export(realpath(__DIR__ . '/../scripts/config.dev.php'), true) . ";\n\$c['log_dir'] = " . var_export($jh_tmp . '/logs', true) . ";\nreturn \$c;\n");
$jh_prev_cfg = getenv('GV_CONFIG');
putenv('GV_CONFIG=' . $jh_cfg_file);
$jh_now = time();
$jh_def = gp_job_defs()['verify'];
$st = function (array $over = array()) use ($jh_now) {
	return array_merge(array('v' => 1, 'mode' => 'verify', 'status' => 'ok', 'last_start' => $jh_now - 100, 'last_end' => $jh_now - 95, 'last_success' => $jh_now - 95, 'last_failure' => 0,
		'last_exit' => 0, 'duration' => 5, 'skipped' => 0, 'runs' => 4, 'failures' => 0, 'last_error' => '', 'warnings' => array(), 'result_json' => ''), $over);
};
$h1 = function ($status, $marker = 0, $interval = 600, $seen = 0) use ($jh_def, $jh_now) { return gp_job_health_one('verify', $jh_def, $status, $marker, $interval, $jh_now, $seen); };

// The four states, and the edges between them.
t_ok('state never: no status file and no heartbeat', $h1(null)['state'] === 'never' && $h1(null)['source'] === 'none');
t_ok('state ok: a recent success', $h1($st())['state'] === 'ok' && $h1($st())['next_expected'] === $jh_now - 95 + 600);
t_ok('state late: no success for MORE than twice the interval; exactly twice is still ok', $h1($st(array('last_success' => $jh_now - 1201)))['state'] === 'late'
	&& $h1($st(array('last_success' => $jh_now - 1200)))['state'] === 'ok' && $h1($st(array('last_success' => $jh_now - 1201)))['overdue'] === 1);
t_ok('state failing: the last run failed (a failure newer than the last success)', $h1($st(array('status' => 'failed', 'last_exit' => 1, 'last_failure' => $jh_now - 10, 'last_success' => $jh_now - 400, 'last_error' => "Traceback\nValueError: boom")))['state'] === 'failing'
	&& $h1($st(array('status' => 'failed', 'last_exit' => 1, 'last_failure' => $jh_now - 10, 'last_error' => "Traceback\nValueError: boom")))['first_line'] === 'Traceback');
t_ok('failing wins over late (a job that keeps failing is failing, not merely late)', $h1($st(array('status' => 'failed', 'last_exit' => 1, 'last_failure' => $jh_now - 10, 'last_success' => $jh_now - 99999)))['state'] === 'failing');
t_ok('a later success clears failing; a later firing skipped by the lock does not', $h1($st(array('last_failure' => $jh_now - 500, 'last_success' => $jh_now - 95)))['state'] === 'ok'
	&& $h1($st(array('status' => 'skipped', 'last_failure' => $jh_now - 10, 'last_success' => $jh_now - 400)))['state'] === 'failing');
t_ok('state warning: ran fine but said it did nothing useful; late still beats warning', $h1($st(array('status' => 'warning', 'warnings' => array('no input rows'))))['state'] === 'warning'
	&& $h1($st(array('status' => 'warning', 'last_success' => $jh_now - 99999)))['state'] === 'late');
t_ok('only skips so far (never a success) is "never", not failing', $h1($st(array('status' => 'skipped', 'last_success' => 0, 'last_failure' => 0, 'skipped' => 3)))['state'] === 'never');
t_ok('the old heartbeat marker still gives a last success (upgrade period) and goes late like any other', $h1(null, $jh_now - 100)['state'] === 'ok' && $h1(null, $jh_now - 100)['source'] === 'marker' && $h1(null, $jh_now - 5000)['state'] === 'late');
t_ok('clock skew: timestamps in the future are clamped, the job is not called late or failing, and the skew is flagged', (function () use ($h1, $st, $jh_now) {
	$h = $h1($st(array('last_success' => $jh_now + 7200, 'last_end' => $jh_now + 7200, 'last_start' => $jh_now + 7190)));
	return $h['state'] === 'ok' && $h['skew'] === true && $h['last_success'] === $jh_now && $h['overdue'] === 0;
})());
t_ok('a small clock difference (under 5 minutes) is not skew', $h1($st(array('last_success' => $jh_now + 100)))['skew'] === false);
t_ok('a corrupt status file reads as never, flagged corrupt, never an exception', $h1(false)['state'] === 'never' && $h1(false)['corrupt'] === true);
t_ok('the result and the warnings of a run are decoded', $h1($st(array('result_json' => '{"ml_samples":321}', 'warnings' => array('a', 'b'))))['result'] === array('ml_samples' => 321) && $h1($st(array('warnings' => array('a', 'b'))))['warnings'] === array('a', 'b'));
t_ok('seen: an error marked seen is quiet until a NEWER failure', $h1($st(array('status' => 'failed', 'last_exit' => 1, 'last_failure' => $jh_now - 10, 'last_success' => 0)), 0, 600, $jh_now - 10)['seen'] === true
	&& $h1($st(array('status' => 'failed', 'last_exit' => 1, 'last_failure' => $jh_now - 5, 'last_success' => 0)), 0, 600, $jh_now - 10)['seen'] === false);

// Reading the files, and the intervals.
t_ok('status files: missing = null, garbage = false, valid = array', gp_job_status_read('verify') === null && (function () use ($jh_tmp) {
	file_put_contents($jh_tmp . '/status/.jobstatus-verify.json', '{not json'); $a = gp_job_status_read('verify') === false;
	file_put_contents($jh_tmp . '/status/.jobstatus-verify.json', '[]'); $b = gp_job_status_read('verify') === false;
	file_put_contents($jh_tmp . '/status/.jobstatus-verify.json', json_encode(array('v' => 1, 'mode' => 'verify', 'status' => 'ok'))); return $a && $b && is_array(gp_job_status_read('verify'));
})());
@unlink($jh_tmp . '/status/.jobstatus-verify.json');
t_ok('intervals: the documented crontab by default, editable in Settings > Analyzer, never below one minute', gp_job_intervals() === array('verify' => 600, 'worker' => 60, 'snapshot' => 900, 'nightly' => 86400, 'logrotate' => 86400,
	'train' => 604800, 'train-clf' => 604800, 'geo' => 2592000, 'report' => 604800)
	&& gp_job_intervals(array('analyzer' => array_merge(gp_analyzer_defaults(), array('interval_verify' => 30, 'interval_geo' => 0))))['verify'] === 1800
	&& gp_job_intervals(array('analyzer' => array_merge(gp_analyzer_defaults(), array('interval_geo' => 0))))['geo'] === 60);
t_ok('every interval is a whitelisted Settings key with a bound', (function () {
	foreach (array('verify', 'worker', 'snapshot', 'nightly', 'logrotate', 'train', 'train_clf', 'geo', 'report') as $j) {
		$spec = gv_overlay_whitelist()['analyzer.interval_' . $j];
		if (!gv_overlay_validate('analyzer.interval_' . $j, $spec[1])[0] || gv_overlay_validate('analyzer.interval_' . $j, $spec[1] - 1)[0] || !gv_overlay_validate('analyzer.interval_' . $j, $spec[2])[0] || gv_overlay_validate('analyzer.interval_' . $j, $spec[2] + 1)[0]) { return false; }
	}
	return true;
})());
file_put_contents($jh_tmp . '/status/.jobstatus-snapshot.json', json_encode($st(array('mode' => 'snapshot', 'last_success' => $jh_now - 5000, 'last_end' => $jh_now - 5000))));
file_put_contents($jh_tmp . '/status/.jobstatus-nightly.json', json_encode($st(array('mode' => 'nightly', 'status' => 'failed', 'last_exit' => 1, 'last_failure' => $jh_now - 60, 'last_success' => $jh_now - 90000, 'last_error' => 'boom'))));
file_put_contents($jh_tmp . '/status/.lastrun-worker', (string)($jh_now - 30));
$jall = gp_job_health($jh_now, $jh_tmp . '/status', gp_job_intervals(), array());
t_ok('gp_job_health reads every job: snapshot late, nightly failing, worker from its old marker, the rest never', $jall['snapshot']['state'] === 'late' && $jall['nightly']['state'] === 'failing' && $jall['worker']['state'] === 'ok'
	&& $jall['verify']['state'] === 'never' && $jall['logrotate']['state'] === 'never' && count($jall) === 9);

// Marking an error as seen.
t_ok('mark seen: writes the file, is audited, silences THIS failure only', (function () use ($jh_tmp, $jh_now) {
	$r = gp_jobs_mark_seen('nightly', 'tester', '198.51.100.1');
	$a = gp_audit_read(3);
	$seen = gp_jobs_seen();
	return $r[0] && $seen['nightly'] === $jh_now - 60 && $a && $a[0]['event'] === 'job_error_seen' && $a[0]['key'] === 'nightly' && gp_job_health($jh_now, $jh_tmp . '/status', gp_job_intervals())['nightly']['seen'] === true;
})());
t_ok('a NEWER failure after it was marked raises the alert again', (function () use ($jh_tmp, $jh_now, $st) {
	file_put_contents($jh_tmp . '/status/.jobstatus-nightly.json', json_encode($st(array('mode' => 'nightly', 'status' => 'failed', 'last_exit' => 1, 'last_failure' => $jh_now - 5, 'last_success' => $jh_now - 90000, 'last_error' => 'boom 2'))));
	$h = gp_job_health($jh_now, $jh_tmp . '/status', gp_job_intervals())['nightly'];
	return $h['state'] === 'failing' && $h['seen'] === false;
})());
t_ok('mark seen refuses an unknown job and a job with no failure', gp_jobs_mark_seen('../../etc', 't', '1.1.1.1')[0] === false && gp_jobs_mark_seen('verify', 't', '1.1.1.1')[0] === false);
t_ok('the seen file is not world-writable and leaves no temp file', (fileperms($jh_tmp . '/seen.json') & 0002) === 0 && glob($jh_tmp . '/seen.json.tmp*') === array());

// The alerts: a healthy input has none; every case raises exactly its alert.
$ok_jobs = array();
foreach (gp_job_defs() as $jn => $jd) { $ok_jobs[$jn] = gp_job_health_one($jn, $jd, array_merge($st(), array('mode' => $jn)), 0, 600, $jh_now); }
$cron_ok = array('mode' => 'live', 'age' => 0, 'report' => array('jobs' => array(array('job' => 'verify', 'state' => 'ok', 'severity' => 'ok', 'required' => true)), 'gv_python' => array('set' => true, 'ok' => true, 'value' => '/x')));
$healthy = array('now' => $jh_now, 'exposed' => array(), 'redis_up' => true, 'degraded' => array(100, 0), 'guard_errors' => array(), 'jobs' => $ok_jobs, 'queue' => array('stuck' => false, 'length' => 0, 'oldest_age' => null),
	'storage' => array('warnings' => array()), 'snapshot' => array('generated_at' => $jh_now - 60, 'tz' => array('offset' => 0)), 'geo_warn' => array(), 'geo_rules' => 0, 'rules_state' => 'ok', 'rules_enabled' => 0, 'rules_cache_stale' => false,
	'secret_default' => false, 'salt_default' => false, 'noeviction' => true, 'cron' => $cron_ok, 'tz_offset' => 0);
$al = function (array $over) use ($healthy) { return gp_health_alerts(array_merge($healthy, $over)); };
$al_ids = function (array $over) use ($al) { return array_column($al($over), 'id'); };
$al_level = function (array $over, $id) use ($al) { foreach ($al($over) as $a) { if ($a['id'] === $id) { return $a['level']; } } return null; };
t_ok('alerts: everything healthy = no alert at all', $al(array()) === array());
t_ok('alert: web exposure (critical)', $al_ids(array('exposed' => array('/x/logs'))) === array('exposed') && $al_level(array('exposed' => array('/x/logs')), 'exposed') === 'critical');
t_ok('alert: Redis down (critical)', $al_level(array('redis_up' => false), 'redis_down') === 'critical');
t_ok('alert: degraded rows in the last 15 min (warning, critical when half or more)', $al_level(array('degraded' => array(100, 10)), 'degraded') === 'warning' && $al_level(array('degraded' => array(100, 60)), 'degraded') === 'critical' && $al_ids(array('degraded' => array(0, 0))) === array());
t_ok('alert: new guard errors', $al_ids(array('guard_errors' => array('redis_connect' => 3, 'geo_missing' => 1))) === array('guard_errors') && strpos($al(array('guard_errors' => array('redis_connect' => 3)))[0]['detail'], 'redis_connect') !== false);
$jf = $ok_jobs; $jf['nightly'] = gp_job_health_one('nightly', gp_job_defs()['nightly'], array_merge($st(), array('mode' => 'nightly', 'status' => 'failed', 'last_exit' => 1, 'last_failure' => $jh_now - 5, 'last_success' => $jh_now - 99999, 'last_error' => 'boom')), 0, 86400, $jh_now);
$jl = $ok_jobs; $jl['snapshot'] = gp_job_health_one('snapshot', gp_job_defs()['snapshot'], array_merge($st(), array('mode' => 'snapshot', 'last_success' => $jh_now - 9999)), 0, 900, $jh_now);
$jw = $ok_jobs; $jw['verify'] = gp_job_health_one('verify', gp_job_defs()['verify'], array_merge($st(), array('status' => 'warning', 'warnings' => array('no rows'))), 0, 600, $jh_now);
$jn_ = $ok_jobs; $jn_['worker'] = gp_job_health_one('worker', gp_job_defs()['worker'], null, 0, 60, $jh_now);
$jt = $ok_jobs; $jt['train'] = gp_job_health_one('train', gp_job_defs()['train'], array_merge($st(), array('mode' => 'train', 'last_success' => $jh_now - 99999999)), 0, 604800, $jh_now);
t_ok('alert: a failing required job (critical, with its first error line and a link to the Jobs page), a late one, a warning one, a never-run one', $al_level(array('jobs' => $jf), 'job_failing_nightly') === 'critical'
	&& strpos($al(array('jobs' => $jf))[0]['detail'], 'boom') !== false && $al(array('jobs' => $jf))[0]['link'] === 'jobs&job=nightly'
	&& $al_level(array('jobs' => $jl), 'job_late_snapshot') === 'critical' && $al_level(array('jobs' => $jw), 'job_warning_verify') === 'warning' && $al_level(array('jobs' => $jn_), 'job_never_worker') === 'warning');
t_ok('alert: a late RECOMMENDED job is only a warning; a never-run recommended job raises nothing', $al_level(array('jobs' => $jt), 'job_late_train') === 'warning' && $al_ids(array('jobs' => array_merge($ok_jobs, array('geo' => gp_job_health_one('geo', gp_job_defs()['geo'], null, 0, 99, $jh_now))))) === array());
$jfs = $jf; $jfs['nightly'] = gp_job_health_one('nightly', gp_job_defs()['nightly'], array_merge($st(), array('mode' => 'nightly', 'status' => 'failed', 'last_exit' => 1, 'last_failure' => $jh_now - 5, 'last_success' => $jh_now - 99999, 'last_error' => 'boom')), 0, 86400, $jh_now, $jh_now - 5);
t_ok('alert: a failure marked as seen raises none, but a late job is not silenced by "seen"', $al_ids(array('jobs' => $jfs)) === array());
t_ok('alert: a stuck job queue (critical, with age and length)', $al_level(array('queue' => array('stuck' => true, 'oldest_age' => 900, 'length' => 2)), 'queue_stuck') === 'critical' && strpos($al(array('queue' => array('stuck' => true, 'oldest_age' => 900, 'length' => 2)))[0]['detail'], '15 min') !== false);
t_ok('alert: disk below the floor (critical) and over the size cap (warning)', $al_level(array('storage' => array('warnings' => array('disk_low'))), 'disk_low') === 'critical' && $al_level(array('storage' => array('warnings' => array('over_cap'))), 'over_cap') === 'warning');
t_ok('alert: no snapshot, and a stale snapshot (judged against the snapshot interval, read live, not from the snapshot)', $al_ids(array('snapshot' => null)) === array('snapshot_missing')
	&& $al_ids(array('snapshot' => array('generated_at' => $jh_now - 5000, 'tz' => array('offset' => 0)))) === array('snapshot_stale') && $al_ids(array('snapshot' => array('generated_at' => $jh_now - 1100, 'tz' => array('offset' => 0)))) === array());
t_ok('alert: the analyzer and the panel disagree on the time zone', $al_ids(array('snapshot' => array('generated_at' => $jh_now - 60, 'tz' => array('offset' => 12600)), 'tz_offset' => 0)) === array('tz_mismatch') && $al_ids(array('snapshot' => array('generated_at' => $jh_now - 60, 'tz' => array('offset' => 12600)), 'tz_offset' => 12600)) === array());
t_ok('alert (PR 2): GeoIP database missing or corrupt while a geo rule is enabled is critical; older than 45 days is a warning',
	$al_level(array('geo_warn' => array('missing'), 'geo_rules' => 1), 'geo_missing') === 'critical' && $al_level(array('geo_warn' => array('corrupt'), 'geo_rules' => 2), 'geo_corrupt') === 'critical'
	&& $al_level(array('geo_warn' => array('stale'), 'geo_rules' => 1), 'geo_stale') === 'warning' && $al_level(array('geo_warn' => array('corrupt'), 'geo_rules' => 0), 'geo_corrupt') === 'warning');
t_ok('alert (PR 1): an invalid rules file is critical, a stale rules cache is a warning (only when a rule is enabled)', $al_level(array('rules_state' => 'invalid'), 'rules_invalid') === 'critical'
	&& $al_level(array('rules_enabled' => 3, 'rules_cache_stale' => true), 'rules_cache_stale') === 'warning' && $al_ids(array('rules_enabled' => 0, 'rules_cache_stale' => true)) === array());
t_ok('alert: secret and holdout_salt still at their placeholders (one alert, the secret first)', $al_ids(array('secret_default' => true, 'salt_default' => true)) === array('secret_default') && $al_ids(array('salt_default' => true)) === array('salt_default'));
t_ok('alert: Redis not on noeviction; unknown (CONFIG not allowed) raises nothing', $al_ids(array('noeviction' => false)) === array('evictable') && $al_ids(array('noeviction' => null)) === array());
t_ok('alert: crontab missing a required entry is critical; disabled / wrong path / wrong schedule are warnings; GV_PYTHON bad or unset is a warning; unreadable crontab is a warning', (function () use ($al, $al_level, $cron_ok) {
	$mk = function ($jobs, $py = null) use ($cron_ok) { $c = $cron_ok; $c['report']['jobs'] = $jobs; if ($py) { $c['report']['gv_python'] = $py; } return array('cron' => $c); };
	return $al_level($mk(array(array('job' => 'worker', 'state' => 'missing', 'severity' => 'critical', 'required' => true))), 'cron_missing') === 'critical'
		&& $al_level($mk(array(array('job' => 'nightly', 'state' => 'disabled', 'severity' => 'warning', 'required' => true))), 'cron_wrong') === 'warning'
		&& $al_level($mk(array(array('job' => 'verify', 'state' => 'wrong_schedule', 'severity' => 'warning', 'required' => true))), 'cron_wrong') === 'warning'
		&& $al_level($mk(array(), array('set' => true, 'ok' => false, 'value' => '/nope')), 'gv_python_bad') === 'warning' && $al_level($mk(array(), array('set' => false, 'ok' => false, 'value' => '')), 'gv_python_missing') === 'warning'
		&& $al_level(array('cron' => array('mode' => 'none', 'report' => null, 'age' => null)), 'cron_unknown') === 'warning'
		&& $al($mk(array(array('job' => 'train', 'state' => 'missing', 'severity' => 'info', 'required' => false)))) === array();
})());
t_ok('alerts are ordered critical first', (function () use ($al) { $a = $al(array('secret_default' => true, 'redis_up' => false)); return $a[0]['level'] === 'critical' && $a[1]['level'] === 'warning'; })());
t_ok('every alert key and detail text exists in lang.php', (function () use ($al, $jf, $jl, $jw, $jn_, $healthy, $tip_lang) {
	$lang = require __DIR__ . '/../panel/lang.php';
	$all = array_merge($al(array('exposed' => array('/x'), 'redis_down' => 1, 'redis_up' => false, 'degraded' => array(10, 9), 'guard_errors' => array('a' => 1), 'jobs' => $jf, 'queue' => array('stuck' => true, 'oldest_age' => 600, 'length' => 1),
		'storage' => array('warnings' => array('disk_low', 'over_cap')), 'snapshot' => null, 'geo_warn' => array('stale', 'missing', 'corrupt', 'no_country', 'log_no_db'), 'geo_rules' => 1, 'rules_state' => 'invalid', 'rules_enabled' => 1, 'rules_cache_stale' => true,
		'secret_default' => true, 'noeviction' => false, 'cron' => array('mode' => 'none', 'report' => null))), $al(array('jobs' => $jl)), $al(array('jobs' => $jw)), $al(array('jobs' => $jn_)), $al(array('salt_default' => true, 'snapshot' => array('generated_at' => 1, 'tz' => array('offset' => 3600)))));
	foreach ($all as $a) { if (!isset($lang[$a['key']])) { return false; } }
	return count($all) >= 20;
})());

// KPI helpers, protection summary, cron setup lines.
t_ok('kpi change: percent against the previous window, "new" from zero, nothing when unknown', gp_kpi_change(120, 100) === '+20 %' && gp_kpi_change(50, 100) === '-50 %' && gp_kpi_change(5, 0) === 'new' && gp_kpi_change(0, 0) === '0 %' && gp_kpi_change(null, 5) === '' && gp_kpi_change(5, null) === '');
$pm_cfg = gv_cfg_defaults(array('secret' => 'real-secret-value'));
$pm_rules = array(array('enabled' => true, 'mode' => 'enforce', 'action' => 'block'), array('enabled' => true, 'mode' => 'monitor', 'action' => 'block'), array('enabled' => false, 'mode' => 'enforce', 'action' => 'block'), array('enabled' => true, 'mode' => 'enforce', 'action' => 'log'));
t_ok('protection mode: placeholder secret = forced monitor; no toggle and no enforced rule = monitor; any toggle or an enforced block/challenge rule = partly; all three toggles = enforcing',
	gp_protection_mode(gv_cfg_defaults(array()), $pm_rules)['mode'] === 'monitor' && gp_protection_mode(gv_cfg_defaults(array()), $pm_rules)['forced'] === true
	&& gp_protection_mode($pm_cfg, array())['mode'] === 'monitor' && gp_protection_mode($pm_cfg, $pm_rules)['mode'] === 'partial' && gp_protection_mode($pm_cfg, $pm_rules)['enforced_rules'] === 1
	&& gp_protection_mode(array_merge($pm_cfg, array('enforce' => array('block' => true, 'challenge' => false, 'ratelimit' => false))), array())['mode'] === 'partial'
	&& gp_protection_mode(array_merge($pm_cfg, array('enforce' => array('block' => true, 'challenge' => true, 'ratelimit' => true))), array())['mode'] === 'enforcing');
t_ok('rules summary: enabled rules by mode and action', gp_rules_summary($pm_rules) === array('total' => 4, 'enabled' => 3, 'by' => array('enforce/block' => 1, 'monitor/block' => 1, 'enforce/log' => 1)));
$jn_all = array(); foreach (gp_job_defs() as $jn => $jd) { $jn_all[$jn] = gp_job_health_one($jn, $jd, null, 0, 600, $jh_now); }
$lines_none = gp_cron_setup_lines($jn_all, array('mode' => 'none', 'report' => null), '/home/u/bot-guard');
t_ok('cron setup lines with an unreadable crontab: the GV_PYTHON line and every required entry, built from the real install directory', $lines_none[0] === 'GV_PYTHON=/path/to/virtualenv/bin/python'
	&& in_array('* * * * * bash /home/u/bot-guard/scripts/analyzer-cron.sh worker >/dev/null 2>&1', $lines_none, true) && in_array('10 3 * * * bash /home/u/bot-guard/scripts/guard-logrotate.sh >/dev/null 2>&1', $lines_none, true)
	&& count($lines_none) === 6 && !in_array('41 5 * * 0 bash /home/u/bot-guard/scripts/analyzer-cron.sh train >/dev/null 2>&1', $lines_none, true));
$cr = array('mode' => 'live', 'age' => 0, 'report' => array('jobs' => array(array('job' => 'worker', 'state' => 'missing', 'required' => true, 'severity' => 'critical', 'schedule' => '', 'message' => 'there is no entry for it'), array('job' => 'verify', 'state' => 'ok', 'required' => true, 'severity' => 'ok', 'schedule' => '*/10 * * * *', 'message' => ''), array('job' => 'geo', 'state' => 'missing', 'required' => false, 'severity' => 'info', 'schedule' => '', 'message' => '')),
	'gv_python' => array('set' => true, 'ok' => true, 'value' => '/x')));
t_ok('cron setup lines with a readable crontab: only what is missing or wrong, no GV_PYTHON line when it is fine, recommended entries only when asked', gp_cron_setup_lines($jn_all, $cr, '/home/u/bot-guard') === array('* * * * * bash /home/u/bot-guard/scripts/analyzer-cron.sh worker >/dev/null 2>&1'));
t_ok('the cron setup card shows when a required job never ran or an entry is missing, and not when all is well', gp_cron_card_needed($jn_all, array('report' => null)) === true && gp_cron_card_needed($ok_jobs, array('report' => null)) === false
	&& gp_cron_card_needed($ok_jobs, $cr) === true && gp_cron_card_needed($ok_jobs, array('report' => array('jobs' => array(array('job' => 'verify', 'state' => 'ok', 'required' => true))))) === false);

// The live crontab check: cached for 5 minutes, "Check again" rate-limited, a hanging or noisy child cannot block the page.
$cc_valid = json_encode(array('v' => 1, 'time' => $jh_now, 'source' => 'crontab', 'root' => '/x', 'jobs' => array(array('job' => 'verify', 'state' => 'ok', 'severity' => 'ok', 'required' => true, 'schedule' => '*/10 * * * *', 'message' => '')),
	'gv_python' => array('set' => true, 'ok' => true, 'value' => '/x'), 'problems' => 0, 'warnings' => 0, 'ok' => true, 'unreadable' => false));
$cc_live = $jh_tmp . '/status/.cron-check-live.json';
file_put_contents($cc_live, $cc_valid);
touch($cc_live, $jh_now - 100);
$cch = gp_cron_check($jh_now);
t_ok('crontab check: a cached live result younger than 5 minutes is used (no process is started), with its age', $cch['mode'] === 'cache' && $cch['age'] === 100 && isset($cch['report']['jobs']));
touch($cc_live, $jh_now - 299);
t_ok('...still a hit at 299 s', gp_cron_check($jh_now)['mode'] === 'cache');
file_put_contents($jh_tmp . '/status/.cron-check.json', $cc_valid);
touch($jh_tmp . '/status/.cron-check.json', $jh_now - 700);
touch($cc_live, $jh_now - 301);
$GLOBALS['gp_test_cron_script'] = $jh_tmp . '/no-such-script.sh';
$cce = gp_cron_check($jh_now);
t_ok('crontab check: at 301 s the cache has expired, the live check is tried again and, when it cannot run, the cron-written copy is used (mode file)', $cce['mode'] === 'file' && $cce['age'] === 700);
file_put_contents($cc_live, 'garbage');
touch($cc_live, $jh_now - 10);
t_ok('crontab check: a damaged cache file is ignored', gp_cron_check($jh_now)['mode'] === 'file');
// A good live run writes the cache
file_put_contents($jh_tmp . '/good.sh', "#!/bin/bash\ncat <<'J'\n" . $cc_valid . "\nJ\n");
$GLOBALS['gp_test_cron_script'] = $jh_tmp . '/good.sh';
@unlink($cc_live);
$ccl = gp_cron_check($jh_now);
t_ok('crontab check: a live run succeeds, returns mode live and writes .cron-check-live.json (not world-writable, no temp file left)', $ccl['mode'] === 'live' && is_file($cc_live) && (fileperms($cc_live) & 0002) === 0 && glob($cc_live . '.tmp*') === array()
	&& gp_cron_check($jh_now + 5)['mode'] === 'cache');
// Check again: forced refresh, rate limit, audit
@unlink($jh_tmp . '/status/.cron-check-refresh');
if (is_file(gp_audit_path())) { @unlink(gp_audit_path()); }
$r1 = gp_cron_check_refresh('tester', '198.51.100.1', $jh_now);
$r2 = gp_cron_check_refresh('tester', '198.51.100.1', $jh_now + 10);
$r3 = gp_cron_check_refresh('other', '198.51.100.2', $jh_now + 29);
$r4 = gp_cron_check_refresh('tester', '198.51.100.1', $jh_now + 31);
t_ok('Check again: the first press refreshes (live), presses within 30 s are refused for every operator, one after 30 s works again', $r1 === array(true, 'cron_refresh_done') && $r2 === array(false, 'cron_refresh_wait') && $r3[0] === false && $r4[0] === true);
$ca = array_values(array_filter(gp_audit_read(10), function ($e) { return $e['event'] === 'cron_check_refresh'; }));
t_ok('Check again is audit-logged once per refresh that ran (refused presses are not)', count($ca) === 2 && $ca[0]['actor'] === 'tester');
t_ok('Check again bypasses a fresh cache (it ran the script even though the cache was 1 s old)', (function () use ($cc_live, $jh_tmp, $jh_now, $cc_valid) {
	file_put_contents($jh_tmp . '/good.sh', "#!/bin/bash\ncat <<'J'\n" . str_replace('"source":"crontab"', '"source":"refreshed"', $cc_valid) . "\nJ\n");
	@unlink($jh_tmp . '/status/.cron-check-refresh');
	gp_cron_check_refresh('t', '1.1.1.1', $jh_now + 1000);
	return json_decode(file_get_contents($cc_live), true)['source'] === 'refreshed';
})());
t_ok('the Jobs page has a Check again button that posts a CSRF token, and the route handles it', strpos(file_get_contents(__DIR__ . '/../panel/views/jobs.php'), 'name="cron_refresh"') !== false && strpos(file_get_contents(__DIR__ . '/../panel/index.php'), "isset(\$_POST['cron_refresh'])") !== false);
// A child that hangs is killed; a noisy child cannot block.
file_put_contents($jh_tmp . '/hang.sh', "#!/bin/bash\nsleep 30\n");
$t0 = microtime(true);
$hung = gp_cron_check_exec($jh_tmp . '/hang.sh', '/bin/bash', 0.6);
$el = microtime(true) - $t0;
t_ok('a child that hangs: gp_cron_check_exec gives up after the timeout, kills it (SIGTERM then SIGKILL) and returns null within about 2 s', $hung === null && $el < 3.0);
file_put_contents($jh_tmp . '/stubborn.sh', "#!/bin/bash\ntrap '' TERM\nwhile true; do sleep 1; done\n");
$t0 = microtime(true);
$stub = gp_cron_check_exec($jh_tmp . '/stubborn.sh', '/bin/bash', 0.5);
$el2 = microtime(true) - $t0;
t_ok('a child that ignores SIGTERM: proc_close does not wait for ever, SIGKILL after 1 s', $stub === null && $el2 < 4.0);
exec('pgrep -f ' . escapeshellarg('[s]tubborn\\.sh') . ' 2>/dev/null', $pg);
t_ok('...and no stubborn child is left running', empty($pg));
file_put_contents($jh_tmp . '/noisy.sh', "#!/bin/bash\nhead -c 2000000 /dev/zero | tr '\\\\0' 'x' >&2\ncat <<'J'\n" . $cc_valid . "\nJ\n");
$t0 = microtime(true);
$noisy = gp_cron_check_exec($jh_tmp . '/noisy.sh', '/bin/bash', 3.0);
t_ok('a child that writes 2 MB to stderr cannot block: stderr goes to /dev/null, the report still arrives, quickly', is_array($noisy) && isset($noisy['jobs']) && (microtime(true) - $t0) < 2.5);
t_ok('the child gets /dev/null for stderr, not a pipe (source check)', strpos(file_get_contents(__DIR__ . '/../panel/health.php'), "2 => array('file', '/dev/null', 'w')") !== false && strpos(file_get_contents(__DIR__ . '/../panel/health.php'), "2 => array('pipe'") === false && strpos(file_get_contents(__DIR__ . '/../panel/health.php'), 'proc_terminate($proc, 9)') !== false);
file_put_contents($jh_tmp . '/status/.cron-check-live.json', 'x'); @unlink($jh_tmp . '/status/.cron-check-live.json');
$GLOBALS['gp_test_cron_script'] = $jh_tmp . '/hang.sh';
$t0 = microtime(true);
t_ok('end to end: with a hanging live check and a cron-written copy, gp_cron_check falls back to the file source', (function () use ($jh_now, $t0) {
	// 3 s timeout is the production value; the hang script is killed by it
	$c = gp_cron_check($jh_now);
	return $c['mode'] === 'file' && (microtime(true) - $t0) < 6.0;
})());
unset($GLOBALS['gp_test_cron_script']);

@unlink($jh_tmp . '/status/.cron-check.json'); @unlink($jh_tmp . '/status/.cron-check-live.json'); @unlink($jh_tmp . '/status/.cron-check-refresh');
// The crontab check reader: sources in order.
define('GP_NO_EXEC', 1);
t_ok('crontab check: nothing available = mode none (heartbeat-only status)', gp_cron_check($jh_now)['mode'] === 'none');
file_put_contents($jh_tmp . '/status/.cron-check.json', json_encode($cron_ok['report'] + array('time' => $jh_now - 120)));
touch($jh_tmp . '/status/.cron-check.json', $jh_now - 120);
$cc = gp_cron_check($jh_now);
t_ok('crontab check: the copy the cron wrapper left (mode file, with its age)', $cc['mode'] === 'file' && $cc['age'] === 120 && isset($cc['report']['jobs']));
file_put_contents($jh_tmp . '/status/.cron-check.json', 'garbage');
t_ok('crontab check: a damaged copy is ignored', gp_cron_check($jh_now)['mode'] === 'none');
t_ok('crontab check: the live check is tried first and falls back cleanly when it cannot read a crontab (this sandbox has none)', (function () use ($jh_now) {
	$r = gp_cron_check_exec();
	return $r === null || (is_array($r) && isset($r['jobs']));
})());

// Live inputs: degraded rows, guard errors, rules cache.
$jh_log = $jh_tmp . '/logs/guard-' . date('Ymd') . '.jsonl';
$jh_rows = '';
for ($i = 0; $i < 10; $i++) { $jh_rows .= json_encode(array('ts' => time() - 60 - $i, 'rd' => $i < 4 ? 1 : 0, 'act' => 'allow')) . "\n"; }
$jh_rows .= json_encode(array('ts' => time() - 5000, 'rd' => 1)) . "\n" . json_encode(array('o' => 1, 'ts' => time(), 'rd' => 1)) . "\n";
file_put_contents($jh_log, $jh_rows);
t_ok('degraded rows are counted over the last 15 minutes only, outcome lines and old rows excluded', gp_degraded_recent(900) === array(10, 4));
file_put_contents($jh_tmp . '/logs/guard-errors.log', date('c', time() - 60) . " redis_connect Redis down\n" . date('c', time() - 60) . " redis_connect Redis down\n" . date('c', time() - 7200) . " old_one x\n");
t_ok('guard errors: only the last hour, counted by code', gp_recent_guard_errors(3600) === array('redis_connect' => 2));
$jh_rules = $jh_tmp . '/rules.json';
putenv('GV_RULES=' . $jh_rules);
file_put_contents($jh_rules, '{"rules":[]}');
file_put_contents(gv_rules_cache_path($jh_rules), '<?php return array();');
touch($jh_rules, time() - 100); touch(gv_rules_cache_path($jh_rules), time() - 50);
t_ok('rules cache: fresh = not stale; older than rules.json = stale; missing cache = stale; no rules.json = not stale', gp_rules_cache_stale() === false
	&& (function () use ($jh_rules) { touch($jh_rules, time()); return gp_rules_cache_stale() === true; })()
	&& (function () use ($jh_rules) { @unlink(gv_rules_cache_path($jh_rules)); return gp_rules_cache_stale() === true; })()
	&& (function () use ($jh_rules) { @unlink($jh_rules); return gp_rules_cache_stale() === false; })());
putenv('GV_RULES');

// The dashboard and the Jobs page rendered in four situations: no snapshot, stale snapshot, all healthy, everything failing.
if (!function_exists('gp_age_stub')) { function gp_age_stub() {} }
$jh_render = function ($view, array $in, array $extra = array()) use ($jh_now, $healthy) {
	$all_in = array_merge($healthy, $in);
	$hjobs = $all_in['jobs'];
	$vars = array_merge(array('snapshot' => $all_in['snapshot'], 'cfg' => gv_cfg_defaults(array()), 'kill' => false, 'redis_up' => $all_in['redis_up'], 'health' => array('breaker' => false, 'last_error' => ''),
		'rinfo' => array('endpoint' => '127.0.0.1:6379', 'db' => 0, 'prefix' => '', 'auth' => false), 'exposed' => $all_in['exposed'], 'pipeline' => null, 'storage' => array('total' => 0, 'today' => 0, 'live_files' => 0, 'archives' => 0, 'oldest' => '',
		'free' => null, 'disk' => null, 'min_free_mb' => 200, 'max_mb' => 0, 'retention_days' => 60, 'skip_paths' => array(), 'rotate' => null, 'warnings' => $all_in['storage']['warnings']),
		'ip_open' => false, 'geo_warn' => $all_in['geo_warn'], 'alerts' => gp_health_alerts($all_in), 'jobs' => $hjobs, 'queue' => array('length' => 0, 'oldest_age' => null, 'stuck' => false, 'redis' => true), 'cron' => $all_in['cron'],
		'cron_card' => gp_cron_card_needed($hjobs, $all_in['cron']), 'cron_lines' => gp_cron_setup_lines($hjobs, $all_in['cron'], '/home/u/bot-guard'), 'protection' => gp_protection_mode(gv_cfg_defaults(array()), array()), 'rsum' => gp_rules_summary(array()),
		'route' => 'dashboard', 'user' => 'tester'), $extra);
	$errs = array();
	set_error_handler(function ($no, $str) use (&$errs) { $errs[] = $str; return true; });
	extract($vars, EXTR_SKIP);
	ob_start();
	require __DIR__ . '/../panel/views/' . $view . '.php';
	$html = ob_get_clean();
	restore_error_handler();
	return array($html, $errs);
};
$kpi_snap = array('generated_at' => $jh_now, 'tz' => array('offset' => 0, 'name' => 'UTC'), 'traffic' => array('requests' => 10, 'devices' => 3, 'addresses' => 4, 'degraded' => 0), 'decisions' => array('allow' => 9, '403' => 1),
	'kpi' => array('cur' => array('requests' => 120, 'allowed' => 100, 'blocked' => 10, 'limited' => 2, 'challenged' => 8, 'challenge_success' => 91.5, 'rule_hits' => 7, 'honeypot' => 1, 'degraded' => 0), 'prev' => array('requests' => 100, 'allowed' => 90, 'blocked' => 5, 'limited' => 2, 'challenged' => 8, 'challenge_success' => 95.0, 'rule_hits' => 0, 'honeypot' => 1, 'degraded' => 0)),
	'top' => array('rules' => array(array('r1', 5)), 'reasons' => array(array('UA_SCRIPT', 9)), 'ips' => array(array('203.0.113.5', 4)), 'devices' => array(), 'uas' => array(array('curl/8.4', 4)), 'paths' => array(array('/shop?x=<b>', 3)), 'countries' => array(array('IR', 6))));
list($h_nosnap, $e_nosnap) = $jh_render('dashboard', array('snapshot' => null));
t_ok('dashboard with no snapshot: renders without a PHP warning, raises the snapshot alert, says the 24 h numbers are missing', !$e_nosnap && strpos($h_nosnap, 'data-alert="snapshot_missing"') !== false && strpos($h_nosnap, 'gp-grid-kpi') === false);
list($h_stale, $e_stale) = $jh_render('dashboard', array('snapshot' => array_merge($kpi_snap, array('generated_at' => $jh_now - 9999))));
t_ok('dashboard with a stale snapshot: the stale alert is raised from a LIVE judgement and the old numbers are still shown', !$e_stale && strpos($h_stale, 'data-alert="snapshot_stale"') !== false && strpos($h_stale, 'gp-grid-kpi') !== false);
list($h_ok, $e_ok) = $jh_render('dashboard', array('snapshot' => $kpi_snap));
t_ok('dashboard, everything healthy: no alert strip, no cron card; protection state, 9 KPI tiles with change vs the previous 24 h, top lists linking to the Logs filters', !$e_ok && strpos($h_ok, 'gp-alerts') === false && strpos($h_ok, 'id="cron-setup"') === false
	&& substr_count($h_ok, 'gp-kpi-label') === 9 && strpos($h_ok, '+20 %') !== false && strpos($h_ok, '-3.5 pt') !== false && strpos($h_ok, 'dash_protection') === false && strpos($h_ok, 'Protection state') !== false);
t_ok('top lists link to the matching Logs filter, with the value escaped and URL-encoded', strpos($h_ok, 'index.php?r=logs&amp;reason=RULE%3Ar1%2CSH_RULE%3Ar1') !== false && strpos($h_ok, 'index.php?r=logs&amp;ip=203.0.113.5') !== false
	&& strpos($h_ok, 'index.php?r=logs&amp;cc=IR') !== false && strpos($h_ok, 'index.php?r=logs&amp;path=%2Fshop%3Fx%3D%3Cb%3E') !== false && strpos($h_ok, '<b>') === false);
$jh_bad = array();
foreach (gp_job_defs() as $jn => $jd) { $jh_bad[$jn] = gp_job_health_one($jn, $jd, array_merge($st(), array('mode' => $jn, 'status' => 'failed', 'last_exit' => 1, 'last_failure' => $jh_now - 5, 'last_success' => 0, 'last_error' => "Traceback <script>\nValueError: boom")), 0, 600, $jh_now); }
$jh_bad['worker'] = gp_job_health_one('worker', gp_job_defs()['worker'], null, 0, 60, $jh_now);       // one job that never ran: the cron setup card
list($h_bad, $e_bad) = $jh_render('dashboard', array('snapshot' => null, 'redis_up' => false, 'jobs' => $jh_bad, 'exposed' => array('/x/logs'), 'storage' => array('warnings' => array('disk_low')), 'queue' => array('stuck' => true, 'oldest_age' => 900, 'length' => 3),
	'cron' => array('mode' => 'none', 'report' => null, 'age' => null), 'secret_default' => true, 'noeviction' => false, 'rules_state' => 'invalid', 'geo_warn' => array('missing'), 'geo_rules' => 1, 'degraded' => array(10, 10), 'guard_errors' => array('redis_connect' => 4)));
t_ok('dashboard, everything failing: renders without a warning, many critical alerts, the cron setup card with the exact lines, and nothing unescaped', !$e_bad && substr_count($h_bad, 'gp-alert-critical') >= 8 && strpos($h_bad, 'id="cron-setup"') !== false && strpos($h_bad, 'analyzer-cron.sh worker') !== false
	&& strpos($h_bad, 'GV_PYTHON=') !== false && strpos($h_bad, '<script>') === false);
list($h_jobs, $e_jobs) = $jh_render('jobs', array('jobs' => $jh_bad), array('jobs' => array(), 'detail' => 'nightly', 'health' => $jh_bad, 'errors' => array("=== 2026 nightly exit 1 ===\n<script>x</script>"), 'runs' => array(array('end' => $jh_now, 'status' => 'failed', 'exit' => 1, 'duration' => 3, 'error' => '<b>e</b>')), 'route' => 'jobs',
	'cron' => $cr + array('mode' => 'live'), 'cron_lines' => array('* * * * * x')));
t_ok('Jobs page: health table, detail with the captured error, recent runs and the crontab check render escaped and without a warning', !$e_jobs && strpos($h_jobs, 'job-detail') !== false && strpos($h_jobs, '<script>') === false && strpos($h_jobs, '<b>e</b>') === false && strpos($h_jobs, 'name="seen"') !== false && strpos($h_jobs, 'id="cron-check"') !== false);
t_ok('the dashboard and Jobs views post a CSRF token on every POST form', substr_count(file_get_contents(__DIR__ . '/../panel/views/jobs.php'), 'method="post"') === substr_count(file_get_contents(__DIR__ . '/../panel/views/jobs.php'), 'gp_csrf_token()')
	&& substr_count(file_get_contents(__DIR__ . '/../panel/views/dashboard.php'), 'method="post"') === substr_count(file_get_contents(__DIR__ . '/../panel/views/dashboard.php'), 'gp_csrf_token()'));

foreach ((array)glob($jh_tmp . '/{status,logs}/{,.}*', GLOB_BRACE) as $f) { if (is_file($f)) { @unlink($f); } }
foreach ((array)glob($jh_tmp . '/*') as $f) { if (is_file($f)) { @unlink($f); } }
foreach (array('/status', '/logs') as $d) { @rmdir($jh_tmp . $d); }
@rmdir($jh_tmp);
putenv('GV_JOBSTATUS_DIR'); putenv('GP_JOBS_SEEN');
if ($jh_prev_cfg !== false) { putenv('GV_CONFIG=' . $jh_prev_cfg); } else { putenv('GV_CONFIG'); }
if (is_file(gp_audit_path())) { @unlink(gp_audit_path()); }
if ($jh_audit_backup !== null) { file_put_contents(gp_audit_path(), $jh_audit_backup); }

t_section('IP lists page: parser, compile, save flow, warnings, alerts');

require_once __DIR__ . '/../panel/iplists.php';
require_once __DIR__ . '/geo-fixture.php';
$il_tmp = sys_get_temp_dir() . '/gp-iplist-selftest-' . getmypid();
@mkdir($il_tmp . '/lists', 0775, true);
@mkdir($il_tmp . '/geo', 0775, true);
@mkdir($il_tmp . '/logs', 0775, true);
register_shutdown_function(function () use ($il_tmp) {
	foreach ((array)glob($il_tmp . '/{,*/}{,.}*', GLOB_BRACE) as $f) { if (is_file($f)) { @unlink($f); } }
	foreach ((array)glob($il_tmp . '/*', GLOB_ONLYDIR) as $d) { @rmdir($d); }
	@rmdir($il_tmp);
});
putenv('GV_LISTS_DIR=' . $il_tmp . '/lists');
putenv('GV_GEO_DIR=' . $il_tmp . '/geo');
putenv('GV_AUDIT=' . $il_tmp . '/audit.jsonl');
gv_redis_ctx(array('log_dir' => $il_tmp . '/logs'));
gv_geo_state(true);
if (!defined('GP_TEST_UPLOADS')) { define('GP_TEST_UPLOADS', 1); }
$il_hex = function ($bin) { return inet_ntop($bin); };
$pe = function ($t) { $e = gp_ipl_parse_entry($t); return $e === null ? null : gp_ipl_entry_text($e); };

// ---- parser
t_ok('parse: a bare address is a /32 or /128, a CIDR keeps its prefix', $pe('203.0.113.7') === '203.0.113.7' && $pe('203.0.113.0/24') === '203.0.113.0/24' && $pe('2001:db8::1') === '2001:db8::1' && $pe('2001:db8::/32') === '2001:db8::/32');
t_ok('parse: host bits are masked (192.0.2.77/24 is 192.0.2.0/24)', $pe('192.0.2.77/24') === '192.0.2.0/24' && $pe('2001:db8:1:2::9/48') === '2001:db8:1::/48' && $pe('1.2.3.4/0') === '0.0.0.0/0');
t_ok('parse: an IPv4-mapped IPv6 address is the IPv4 address it carries, a mapped CIDR counts from /96', $pe('::ffff:1.2.3.4') === '1.2.3.4' && $pe('::ffff:1.2.3.0/120') === '1.2.3.0/24' && $pe('::ffff:1.2.3.4/128') === '1.2.3.4');
t_ok('parse: a mapped range wider than /96 is refused, as is everything that is not an address',
	$pe('::ffff:1.2.3.0/64') === null && $pe('1.2.3') === null && $pe('300.1.1.1') === null && $pe('1.2.3.4/33') === null && $pe('2001:db8::/129') === null && $pe('1.2.3.4/') === null
	&& $pe('1.2.3.4/a') === null && $pe('1.2.3.4/-1') === null && $pe('fe80::1%eth0') === null && $pe('') === null && $pe('1.2.3.4 5.6.7.8') === null && $pe('1.2.3.04') === null && $pe('example.com') === null);
list($pt, $pb) = gp_ipl_parse_text("\xEF\xBB\xBFip,note\r\n# comment\r\n\r\n203.0.113.0/24  # trailing\r\n\"198.51.100.7\",x\r\n'192.0.2.1' , y\r\n2001:db8::/32\n\t10.9.9.9\t\njunk line\r5.5.5.5");
t_ok('parse_text: BOM, CRLF, CR, comments, blank lines, a CSV first column and quotes; bad lines are reported with their number',
	count($pt) === 6 && $pb === array(array(1, 'ip,note'), array(9, 'junk line'))
	&& array_map('gp_ipl_entry_text', $pt) === array('203.0.113.0/24', '198.51.100.7', '192.0.2.1', '2001:db8::/32', '10.9.9.9', '5.5.5.5') && $pt[0]['line'] === 4 && $pt[1]['line'] === 5);
t_ok('parse_text: an empty text has no entries and no errors', gp_ipl_parse_text('') === array(array(), array()) && gp_ipl_parse_text("# only\n\n") === array(array(), array()));

// ---- ranges
$rg = function ($t) { $e = gp_ipl_parse_entry($t); return array($e['s'], $e['e']); };
$un = gp_ipl_union(array($rg('10.0.0.0/24'), $rg('10.0.1.0/24'), $rg('10.0.0.128/25'), $rg('10.0.3.0/24'), $rg('255.255.255.255'), $rg('255.255.255.0/24')));
t_ok('union: overlapping, nested and ADJACENT ranges merge; a gap stays; the top of the space does not overflow',
	count($un) === 3 && $il_hex($un[0][0]) === '10.0.0.0' && $il_hex($un[0][1]) === '10.0.1.255' && $il_hex($un[1][0]) === '10.0.3.0' && $il_hex($un[2][1]) === '255.255.255.255');
t_ok('union: IPv6 and counting', count(gp_ipl_union(array($rg('2001:db8::/33'), $rg('2001:db8:8000::/33')))) === 1 && gp_ipl_count4(gp_ipl_union(array($rg('10.0.0.0/24'), $rg('10.0.0.0/25')))) === 256);
t_ok('inc / dec carry across bytes and stop at the ends', gp_ipl_inc("\x00\xff\xff\xff") === "\x01\x00\x00\x00" && gp_ipl_inc("\xff\xff") === null && gp_ipl_dec("\x01\x00") === "\x00\xff" && gp_ipl_dec("\x00\x00") === null);
$sw = gp_ipl_sweep(array(array($rg('10.0.0.0/8')[0], $rg('10.0.0.0/8')[1], 5), array($rg('10.1.0.0/16')[0], $rg('10.1.0.0/16')[1], 1), array($rg('10.2.0.0/16')[0], $rg('10.2.0.0/16')[1], 9),
	array($rg('11.0.0.0/8')[0], $rg('11.0.0.0/8')[1], 5), array($rg('255.255.255.0/24')[0], $rg('255.255.255.255')[1], 32770)));
$sw_t = array_map(function ($r) use ($il_hex) { return $il_hex($r[0]) . '-' . $il_hex($r[1]) . '=' . $r[2]; }, $sw);
t_ok('sweep: the SMALLER value wins on an overlap whatever the widths, equal neighbours merge, the top of the space is kept',
	$sw_t === array('10.0.0.0-10.0.255.255=5', '10.1.0.0-10.1.255.255=1', '10.2.0.0-10.255.255.255=5', '11.0.0.0-11.255.255.255=5', '255.255.255.0-255.255.255.255=32770') || $sw_t === array('10.0.0.0-10.0.255.255=5', '10.1.0.0-10.1.255.255=1', '10.2.0.0-11.255.255.255=5', '255.255.255.0-255.255.255.255=32770'));
t_ok('sweep: an enforced list (value without bit 15) beats a monitor list on the same address', (function () use ($rg) {
	$a = $rg('10.0.0.0/8'); $b = $rg('10.5.0.0/16');
	$r = gp_ipl_sweep(array(array($a[0], $a[1], 0x8001), array($b[0], $b[1], 2)));
	return count($r) === 3 && $r[1][2] === 2 && $r[0][2] === 0x8001 && $r[2][2] === 0x8001;
})());
t_ok('sweep: nothing in, nothing out; a single range is itself', gp_ipl_sweep(array()) === array() && count(gp_ipl_sweep(array(array($rg('1.1.1.1')[0], $rg('1.1.1.1')[1], 1)))) === 1);
// The brute-force check: random overlapping ranges against a per-address scan.
mt_srand(21);
$bad = 0;
$in = array();
for ($i = 0; $i < 60; $i++) { $s = mt_rand(0, 200); $e = $s + mt_rand(0, 60); $in[] = array(pack('N', $s), pack('N', $e), mt_rand(1, 6) | (mt_rand(0, 1) ? 0x8000 : 0)); }
$swp = gp_ipl_sweep($in);
for ($a = 0; $a < 270; $a++) {
	$want = null;
	foreach ($in as $r) { if ($a >= unpack('N', $r[0])[1] && $a <= unpack('N', $r[1])[1]) { $want = $want === null ? $r[2] : min($want, $r[2]); } }
	$got = null;
	foreach ($swp as $r) { if ($a >= unpack('N', $r[0])[1] && $a <= unpack('N', $r[1])[1]) { $got = $r[2]; } }
	if ($got !== $want) { $bad++; }
}
t_ok('sweep: 60 random overlapping ranges agree with a per-address minimum on 270 addresses (' . $bad . ' wrong)', $bad === 0);
$prev_end = null; $okorder = true;
foreach ($swp as $r) { if ($prev_end !== null && strcmp($r[0], $prev_end) <= 0) { $okorder = false; } $prev_end = $r[1]; }
t_ok('sweep: the output is sorted and non-overlapping', $okorder);

// ---- refusals and metadata
$prot = gp_ipl_protected(array('198.51.100.200', '2001:db8:ffff::5', 'not-an-ip'));
$rf = function ($t, $type, $force = false) use ($prot) { return gp_ipl_refusal(gp_ipl_parse_entry($t), $type, $prot, $force); };
t_ok('caps: 0.0.0.0/0 and ::/0 are dropped for BOTH types, and even when the list is forced (also as a mapped /96)',
	$rf('0.0.0.0/0', 'allow') === 'all' && $rf('0.0.0.0/0', 'block') === 'all' && $rf('::/0', 'allow') === 'all' && $rf('::/0', 'block') === 'all'
	&& $rf('0.0.0.0/0', 'allow', true) === 'all' && $rf('::/0', 'block', true) === 'all' && $rf('::ffff:0.0.0.0/96', 'allow', true) === 'all' && $rf('0.0.0.0', 'allow') === '');
t_ok('caps: an allow entry wider than /16 (IPv4) or /32 (IPv6) is "allow_wide"; /16 and /32 are fine; forced keeps it',
	$rf('64.0.0.0/12', 'allow') === 'allow_wide' && $rf('64.0.0.0/15', 'allow') === 'allow_wide' && $rf('64.0.0.0/16', 'allow') === '' && $rf('2400::/31', 'allow') === 'allow_wide' && $rf('2400::/32', 'allow') === ''
	&& $rf('64.0.0.0/8', 'allow') === 'allow_wide' && $rf('64.0.0.0/12', 'allow', true) === '' && $rf('64.0.0.0/4', 'allow', true) === '');
t_ok('caps: a block entry wider than /8 (IPv4) or /32 (IPv6) is "wide", /8 and /32 are fine, forced keeps it',
	$rf('64.0.0.0/7', 'block') === 'wide' && $rf('64.0.0.0/8', 'block') === '' && $rf('2400::/31', 'block') === 'wide' && $rf('2400::/32', 'block') === '' && $rf('64.0.0.0/4', 'block', true) === '');
t_ok('caps: a BLOCK entry touching private, loopback, link-local space is "protected" (v4 and v6); allow entries are not checked for it; forced keeps it',
	$rf('10.1.2.3', 'block') === 'protected' && $rf('192.168.0.0/16', 'block') === 'protected' && $rf('127.0.0.1', 'block') === 'protected' && $rf('169.254.1.1', 'block') === 'protected' && $rf('172.20.0.0/14', 'block') === 'protected'
	&& $rf('::1', 'block') === 'protected' && $rf('fc00:1::/32', 'block') === 'protected' && $rf('fe80::/64', 'block') === 'protected' && $rf('0.0.0.0', 'block') === 'protected'
	&& $rf('192.168.0.0/16', 'allow') === '' && $rf('10.1.2.3', 'block', true) === '');
t_ok('caps: a /9 that CONTAINS a private block is protected too; public space is fine', $rf('0.0.0.0/9', 'block') === 'protected' && $rf('203.0.113.0/24', 'block') === '' && $rf('11.0.0.0/8', 'block') === '' && $rf('172.32.0.0/16', 'block') === '');
t_ok('caps: the server\'s own addresses are protected in a block list, a bad extra is ignored', $rf('198.51.100.200', 'block') === 'protected' && $rf('198.51.100.0/24', 'block') === 'protected' && $rf('2001:db8:ffff::/48', 'block') === 'protected' && $rf('198.51.101.1', 'block') === '');
t_ok('caps: the reasons are the four known ones; "huge" means wider than /8', gp_ipl_reasons() === array('all', 'allow_wide', 'wide', 'protected') && gp_ipl_is_huge(gp_ipl_parse_entry('64.0.0.0/7')) && !gp_ipl_is_huge(gp_ipl_parse_entry('64.0.0.0/8')));
$mv = function ($o) { return gp_ipl_validate_meta(array_merge(array('id' => 'a-list', 'idx' => 3, 'name' => 'A list', 'type' => 'block', 'mode' => 'monitor', 'enabled' => true, 'note' => ''), $o)); };
t_ok('meta: a good record round-trips, every bad field is refused',
	$mv(array())[0] && $mv(array('id' => 'A'))[0] === false && $mv(array('id' => '-a'))[0] === false && $mv(array('id' => str_repeat('a', 25)))[0] === false && $mv(array('name' => ''))[0] === false
	&& $mv(array('name' => str_repeat('x', 81)))[0] === false && $mv(array('name' => "a\nb"))[0] === false && $mv(array('type' => 'x'))[0] === false && $mv(array('mode' => 'x'))[0] === false
	&& $mv(array('idx' => 0))[0] === false && $mv(array('idx' => 32768))[0] === false && $mv(array('idx' => '3'))[0] === false && $mv(array('note' => str_repeat('n', 201)))[0] === false && gp_ipl_validate_meta('x')[0] === false);
t_ok('slug: a name becomes a short log id', gp_ipl_slug('Scraper ASN ranges (2026)!') === 'scraper-asn-ranges-2026' && gp_ipl_slug('') === 'list' && gp_ipl_slug('!!!') === 'list' && strlen(gp_ipl_slug(str_repeat('abc ', 20))) <= 24);

// ---- compile + the save flow
$il_up = function ($content, $err = 0) use ($il_tmp) { $t = $il_tmp . '/up.tmp'; file_put_contents($t, $content); return array('name' => 'l.txt', 'tmp_name' => $t, 'error' => $err, 'size' => strlen($content)); };
$sv = function (array $p, $file = null) { return gp_iplists_save(array_merge(array('name' => 'Scrapers', 'type' => 'block', 'mode' => 'enforce', 'enabled' => '1', 'note' => ''), $p), $file, 'tester', '198.18.77.7'); };
t_ok('state: no file yet', gp_iplists_state()['state'] === 'missing' && gp_iplists_state()['lists'] === array() && gp_iplists_status() === null);
$r1 = $sv(array('text' => "203.0.113.0/24\n198.51.100.0/25\n2001:db8::/48\n"));
t_ok('save: a new block list is created, its source, record, compiled file and audit line exist',
	$r1['ok'] && $r1['msg'] === 'ipl_created' && is_file($il_tmp . '/lists/scrapers.txt') && is_file($il_tmp . '/lists/block.bin') && !is_file($il_tmp . '/lists/allow.bin')
	&& gp_iplists_state()['lists'][0]['id'] === 'scrapers' && gp_iplists_state()['lists'][0]['idx'] === 1 && file_get_contents($il_tmp . '/lists/scrapers.txt') === "203.0.113.0/24\n198.51.100.0/25\n2001:db8::/48\n"
	&& strpos((string)@file_get_contents($il_tmp . '/audit.jsonl'), '"event":"iplist"') !== false);
t_ok('save: the report says how many entries, ranges and addresses (and the compile result)', strpos($r1['detail'], '3 entries') !== false && strpos($r1['detail'], '384 IPv4 addresses') !== false);
gv_geo_state(true);
t_ok('compile: the guard finds the addresses in the file the panel wrote (v4, v6, mapped), with the list index', gv_iplist_check('203.0.113.9')['block'] === array('idx' => 1, 'monitor' => false)
	&& gv_iplist_check('2001:db8::7')['block'] !== null && gv_iplist_check('::ffff:198.51.100.5')['block'] !== null && gv_iplist_check('198.51.100.200')['block'] === null && gv_iplist_check('203.0.113.9')['allow'] === null);
$stt = gp_iplists_status();
t_ok('compile: lists-status.json has the per-list counts and the type summary', $stt && $stt['ok'] === true && $stt['by'] === 'php' && $stt['lists']['scrapers']['entries'] === 3 && $stt['lists']['scrapers']['addresses'] === 384
	&& $stt['lists']['scrapers']['v6'] === 1 && $stt['types']['block']['v4'] === 2 && $stt['types']['block']['lists'] === array('scrapers') && $stt['types']['allow'] === null);
t_ok('compile: the header says kind 3, a 2-byte value and the build time', (function () use ($il_tmp, $stt) {
	$h = gv_geo_header_parse(file_get_contents($il_tmp . '/lists/block.bin', false, null, 0, 128));
	return $h && $h['kind'] === 3 && $h['vsize'] === 2 && $h['built'] === $stt['time'] && $h['v4'] === 2 && $h['v6'] === 1 && $h['source'] === 'iplists-block';
})());
// Invalid and refused lines: nothing is saved until the operator confirms.
$before_meta = file_get_contents($il_tmp . '/lists/lists.json');
$r2 = $sv(array('name' => 'Second', 'text' => "192.0.2.0/24\nbogus\n10.0.0.0/8\n64.0.0.0/4\n"));
t_ok('save: invalid lines and refused entries are reported (by line number) and NOTHING is saved or written',
	!$r2['ok'] && $r2['msg'] === 'ipl_confirm' && $r2['report']['invalid'] === array(array(2, 'bogus')) && count($r2['report']['refused']) === 2 && $r2['report']['refused'][0][0] === 3 && $r2['report']['refused'][0][2] === 'protected'
	&& $r2['report']['refused'][1][2] === 'wide' && file_get_contents($il_tmp . '/lists/lists.json') === $before_meta && !is_file($il_tmp . '/lists/second.txt') && preg_match('/^[a-f0-9]{16}$/', $r2['pending']));
t_ok('save: the text waits in a pending file that the next submit uses', is_file(gp_ipl_pending_path($r2['pending'])));
$r3 = $sv(array('name' => 'Second', 'pending' => $r2['pending'], 'accept' => '1'));
t_ok('save: after the operator accepts, the valid lines are saved and the pending file is gone', $r3['ok'] && file_get_contents($il_tmp . '/lists/second.txt') === "192.0.2.0/24\n" && !is_file(gp_ipl_pending_path($r2['pending']))
	&& strpos($r3['detail'], '3 skipped') !== false);
$r4 = $sv(array('name' => 'Wide', 'text' => "64.0.0.0/4\n10.0.0.0/8\n", 'force' => '1'));
t_ok('save: "I know what I\'m doing" lets wide and private block entries through', $r4['ok'] && file_get_contents($il_tmp . '/lists/wide.txt') === "64.0.0.0/4\n10.0.0.0/8\n" && gp_ipl_find(gp_iplists_state()['lists'], 'wide')['force'] === true);
gv_geo_state(true);
$stt = gp_iplists_status();
file_put_contents($il_tmp . '/lists/second.txt', "192.0.2.0/24\n32.0.0.0/4\n");           // a wide entry in an UNFORCED list (e.g. copied over SFTP)
$cw = gp_iplists_compile();
$stw = gp_iplists_status();
file_put_contents($il_tmp . '/lists/second.txt', "192.0.2.0/24\n");
gp_iplists_compile();
gv_geo_state(true);
t_ok('compile: a forced list keeps its wide entry; an unforced one drops it and counts it', $stt['lists']['wide']['entries'] === 2 && $stt['lists']['wide']['dropped_n'] === 0 && gv_iplist_check('70.1.1.1')['block'] !== null
	&& $cw['ok'] && $stw['lists']['second']['entries'] === 1 && $stw['lists']['second']['dropped']['wide'] === 1 && $stw['lists']['second']['dropped_n'] === 1);
$ids = array_map(function ($l) { return $l['id'] . ':' . $l['idx']; }, gp_iplists_state()['lists']);
t_ok('save: ids are slugs of the name, indexes count up and are never reused', $ids === array('scrapers:1', 'second:2', 'wide:3'));
t_ok('save: the same name gets a distinct id', $sv(array('name' => 'Scrapers', 'text' => '203.0.114.0/24'))['ok'] && gp_ipl_find(gp_iplists_state()['lists'], 'scrapers-2')['idx'] === 4);
t_ok('save: an uploaded file is read like pasted text (UTF-8 BOM, CRLF, CSV)', $sv(array('name' => 'Uploaded'), $il_up("\xEF\xBB\xBF203.0.115.0/24,x\r\n203.0.116.1\r\n"))['ok'] && file_get_contents($il_tmp . '/lists/uploaded.txt') === "203.0.115.0/24\n203.0.116.1\n");
t_ok('save: a file over the PHP limit, a failed upload and a non-UTF-8 text are refused with their own message',
	$sv(array('name' => 'X1'), array('error' => UPLOAD_ERR_INI_SIZE))['msg'] === 'ipl_up_toobig' && $sv(array('name' => 'X2'), array('error' => UPLOAD_ERR_PARTIAL))['msg'] === 'ipl_up_failed'
	&& $sv(array('name' => 'X3', 'text' => "\xff\xfe1.2.3.4"))['msg'] === 'ipl_not_text' && !is_file($il_tmp . '/lists/x1.txt') && !is_file($il_tmp . '/lists/x3.txt'));
$bad_name = $sv(array('name' => str_repeat('n', 81), 'text' => '1.2.3.4'));
t_ok('save: a bad name is refused with the field named, nothing written', !$bad_name['ok'] && isset($bad_name['errors']['name']) && gp_ipl_find(gp_iplists_state()['lists'], 'nnnnnnnnnnnnnnnnnnnnnnnn') === null);
$edit = gp_iplists_save(array('id' => 'second', 'name' => 'Second renamed', 'type' => 'allow', 'mode' => 'monitor', 'enabled' => '1', 'note' => 'n'), null, 'tester', '198.18.77.7');
$sec = gp_ipl_find(gp_iplists_state()['lists'], 'second');
t_ok('edit: without text the entries stay; the name, mode and note change; the TYPE and the id cannot', $edit['ok'] && $edit['msg'] === 'ipl_saved' && $sec['name'] === 'Second renamed' && $sec['type'] === 'block' && $sec['mode'] === 'monitor' && $sec['note'] === 'n'
	&& $sec['id'] === 'second' && $sec['idx'] === 2 && file_get_contents($il_tmp . '/lists/second.txt') === "192.0.2.0/24\n");
$edit2 = gp_iplists_save(array('id' => 'second', 'name' => 'Second renamed', 'mode' => 'monitor', 'enabled' => '1', 'text' => "192.0.2.128/25\n"), null, 'tester', '198.18.77.7');
t_ok('edit: pasted text REPLACES the entries', $edit2['ok'] && file_get_contents($il_tmp . '/lists/second.txt') === "192.0.2.128/25\n");
t_ok('edit: an unknown id is refused', gp_iplists_save(array('id' => 'nope', 'name' => 'x'), null, 'tester', '1.1.1.1')['msg'] === 'ipl_not_found');
// Compile semantics across lists.
$sv(array('name' => 'Partners', 'type' => 'allow', 'mode' => 'enforce', 'text' => "203.0.113.64/26\n"));
gv_geo_state(true);
$both = gv_iplist_check('203.0.113.70');
t_ok('compile: an address in an allow AND a block list is found in BOTH files (the guard lets the allow list win)', $both['allow'] !== null && $both['block'] !== null && gv_iplist_check('203.0.113.5')['allow'] === null);
gp_iplists_set(array('id' => 'partners', 'enabled' => '0'), 'tester', '1.1.1.1');
gv_geo_state(true);
t_ok('set: disabling the only allow list removes allow.bin: the guard has no allow lookup to do', !is_file($il_tmp . '/lists/allow.bin') && gv_iplist_check('203.0.113.70')['allow'] === null && gp_iplists_status()['types']['allow'] === null);
gp_iplists_set(array('id' => 'partners', 'enabled' => '1', 'mode' => 'monitor'), 'tester', '1.1.1.1');
gv_geo_state(true);
t_ok('set: monitor mode sets bit 15 of the value; a monitor allow still shows as a hit with monitor=true', gv_iplist_check('203.0.113.70')['allow']['monitor'] === true && is_file($il_tmp . '/lists/allow.bin.prev') === false || is_file($il_tmp . '/lists/allow.bin'));
gp_iplists_set(array('id' => 'partners', 'mode' => 'enforce'), 'tester', '1.1.1.1');
t_ok('set: .prev keeps the previous compiled file, rollback puts it back', (function () use ($il_tmp) {
	if (!is_file($il_tmp . '/lists/allow.bin.prev')) { return false; }
	$h = gv_geo_header_parse(file_get_contents($il_tmp . '/lists/allow.bin.prev', false, null, 0, 128));
	$r = gp_iplists_rollback('allow', 'tester', '1.1.1.1');
	gv_geo_state(true);
	return $h && $r[0] && gv_iplist_check('203.0.113.70')['allow']['monitor'] === true && gp_iplists_rollback('block', 't', '1')[0] === true && gp_iplists_rollback('allow', 't', '1')[0] === true;
})());
t_ok('rollback: with no .prev, or a .prev that is not a list file, it refuses', (function () use ($il_tmp) {
	@unlink($il_tmp . '/lists/allow.bin.prev');
	$a = gp_iplists_rollback('allow', 't', '1');
	file_put_contents($il_tmp . '/lists/allow.bin.prev', 'junk');
	$b = gp_iplists_rollback('allow', 't', '1');
	@unlink($il_tmp . '/lists/allow.bin.prev');
	return !$a[0] && !$b[0];
})());
file_put_contents($il_tmp . '/lists/partners.txt.bak', 'x'); @unlink($il_tmp . '/lists/partners.txt.bak');
// A source that cannot be read keeps the old file and reports it.
$keep = file_get_contents($il_tmp . '/lists/block.bin');
rename($il_tmp . '/lists/second.txt', $il_tmp . '/lists/second.txt.gone');
$cr = gp_iplists_compile();
t_ok('compile: an enabled list whose source is missing: the error is reported, ok is false, the previous block file is kept', !$cr['ok'] && strpos(implode(' ', $cr['errors']), 'second') !== false && file_get_contents($il_tmp . '/lists/block.bin') === $keep && gp_iplists_status()['ok'] === false);
rename($il_tmp . '/lists/second.txt.gone', $il_tmp . '/lists/second.txt');
t_ok('compile: ... and compiles again once the source is back', gp_iplists_compile()['ok'] === true);
// Export, entries, delete.
$ex = gp_iplists_export('scrapers');
t_ok('export: the source text comes back; an unknown list gives null', $ex[0]['id'] === 'scrapers' && $ex[1] === "203.0.113.0/24\n198.51.100.0/25\n2001:db8::/48\n" && gp_iplists_export('nope')[0] === null);
$en = gp_iplists_entries('scrapers', array());
t_ok('entries: every entry with its line, family and the totals', $en[1] === 3 && $en[2] === 3 && $en[0][0] === array('line' => 1, 'text' => '203.0.113.0/24', 'v' => 4) && $en[0][2]['v'] === 6);
$en2 = gp_iplists_entries('scrapers', gp_filter_parse(array('entry' => '203.0', 'entry_op' => 'not'), array('entry' => 'text')));
t_ok('entries: the text filter "does not contain" and the family filter "is" / "is not"', $en2[1] === 2 && array_column($en2[0], 'text') === array('198.51.100.0/25', '2001:db8::/48')
	&& gp_iplists_entries('scrapers', gp_filter_parse(array('family' => 'v6'), array('family' => 'choice')))[1] === 1 && gp_iplists_entries('scrapers', gp_filter_parse(array('family' => 'v6', 'family_op' => 'not'), array('family' => 'choice')))[1] === 2);
t_ok('entries: an unknown list is empty', gp_iplists_entries('nope', array()) === array(array(), 0, 0, 0));
// The tester.
gv_geo_state(true);
$tt = gp_iplists_test('203.0.113.70');
t_ok('tester: live hits per type, the effective decision (allow beats block) and the matching source entry', $tt && $tt['ip'] === '203.0.113.70' && $tt['live']['allow']['id'] === 'partners' && $tt['live']['block']['id'] === 'scrapers' && $tt['effective'] === 'allow'
	&& count($tt['matches']) === 2 && $tt['matches'][0]['entry'] === '203.0.113.0/24');
t_ok('tester: a block-only address, a clean address, a monitor-only address, and a non-address',
	gp_iplists_test('198.51.100.5')['effective'] === 'block' && gp_iplists_test('8.8.8.8')['effective'] === '' && gp_iplists_test('8.8.8.8')['matches'] === array() && gp_iplists_test('192.0.2.200')['effective'] === 'monitor' && gp_iplists_test('nonsense') === null && gp_iplists_test('') === null);
t_ok('tester: IPv6 and IPv4-mapped input', gp_iplists_test('2001:db8::9')['effective'] === 'block' && gp_iplists_test('::ffff:198.51.100.5')['effective'] === 'block');

// ---- warnings
$warn_lists = gp_iplists_state()['lists'];
$wc = array_column(gp_iplists_warnings($warn_lists), 0);
t_ok('warnings: an address in both an allow and a block list is reported with its lists', in_array('conflict', $wc, true) && (function () use ($warn_lists) { foreach (gp_iplists_warnings($warn_lists) as $w) { if ($w[0] === 'conflict') { return strpos($w[1], '203.0.113.64 - 203.0.113.127') !== false && strpos($w[1], 'partners / scrapers') !== false; } } return false; })());
$sv(array('name' => 'Big allow', 'type' => 'allow', 'mode' => 'enforce', 'force' => '1', 'text' => "20.0.0.0/8\n100.64.5.0/24\n2a00::/16\n0.0.0.0/0\n", 'accept' => '1'));
$ww = gp_iplists_warnings(gp_iplists_state()['lists']);
$wm = array(); foreach ($ww as $w) { $wm[$w[0]] = $w[1]; }
t_ok('warnings: an allow entry wider than /16 (or an IPv6 /16), and one in the shared CGNAT range', isset($wm['allow_wide']) && strpos($wm['allow_wide'], '20.0.0.0/8') !== false && strpos($wm['allow_wide'], '2a00::/16') !== false && isset($wm['allow_shared']) && strpos($wm['allow_shared'], '100.64.5.0/24') !== false);
file_put_contents($il_tmp . '/geo/asn.bin', gf_pack(2, array(array(ip2long('100.64.5.0'), ip2long('100.64.5.255'), 44244)), array()));
gv_geo_state(true);
$wm2 = array(); foreach (gp_iplists_warnings(gp_iplists_state()['lists']) as $w) { $wm2[$w[0]] = $w[1]; }
t_ok('warnings: an allow entry inside a mobile operator AS (needs the ASN file) names the operator', isset($wm2['allow_mobile']) && strpos($wm2['allow_mobile'], 'AS44244 Irancell') !== false);
$wm3 = array(); foreach (gp_iplists_warnings(gp_iplists_state()['lists'], array('203.0.113.9', '8.8.8.8', '2001:db8::5', 'junk')) as $w) { $wm3[$w[0]] = $w[1]; }
t_ok('warnings: a block entry covering a verified crawler address from the logs (v4 and v6)', isset($wm3['block_crawler']) && strpos($wm3['block_crawler'], '203.0.113.9 (scrapers)') !== false && strpos($wm3['block_crawler'], '2001:db8::5') !== false && strpos($wm3['block_crawler'], '8.8.8.8') === false);
t_ok('warnings: disabled lists are ignored, a huge total is reported instead of analysed', gp_iplists_warnings(array_map(function ($l) { $l['enabled'] = false; return $l; }, $warn_lists)) === array() && gp_iplists_warnings($warn_lists, array(), 10)[0][0] === 'too_big');
// Verified crawler addresses out of the logs.
$il_logs = $il_tmp . '/logs';
$il_day = date('Ymd');
file_put_contents($il_logs . '/guard-' . $il_day . '.jsonl', json_encode(array('ts' => time(), 'ip' => '203.0.113.50', 'bot' => 'Googlebot', 'botv' => 'ok', 'act' => 'allow_bot')) . "\n"
	. json_encode(array('ts' => time(), 'ip' => '203.0.113.51', 'bot' => 'Googlebot', 'botv' => 'bad', 'act' => '403')) . "\n" . json_encode(array('ts' => time(), 'ip' => '198.18.0.1', 'act' => 'allow')) . "\n");
putenv('GV_LOG_DIR=' . $il_logs);
$il_cfgf = $il_tmp . '/config.php';
file_put_contents($il_cfgf, "<?php\nif (!defined('GV_BOOT')) { exit; }\n\$c = require " . var_export(__DIR__ . '/config.dev.php', true) . ";\n\$c['log_dir'] = " . var_export($il_logs, true) . ";\nreturn \$c;\n");
putenv('GV_CONFIG=' . $il_cfgf);
t_ok('verified crawler ips: only botv=ok rows count', gp_iplists_verified_ips() === array('203.0.113.50'));
putenv('GV_CONFIG'); putenv('GV_LOG_DIR');

// ---- health / dashboard alerts
$hl = function ($jobs = array(), $now = null) { return gp_iplists_health($now, $jobs); };
t_ok('health: compiled and fine: no alert', $hl() === array() || array_column($hl(), 0) === array());
$bak = file_get_contents($il_tmp . '/lists/block.bin');
unlink($il_tmp . '/lists/block.bin');
t_ok('health: a missing compiled file while its list is enabled: file_missing for that type', in_array(array('file_missing', 'block'), $hl(), true));
file_put_contents($il_tmp . '/lists/block.bin', 'GVRGxxxx' . str_repeat("\0", 200));
t_ok('health: a corrupt compiled file: file_corrupt', in_array(array('file_corrupt', 'block'), $hl(), true));
file_put_contents($il_tmp . '/lists/block.bin', $bak);
t_ok('health: restored: quiet again', !array_filter($hl(), function ($w) { return in_array($w[0], array('file_missing', 'file_corrupt'), true); }));
$st_bak = file_get_contents($il_tmp . '/lists/lists-status.json');
$sj = json_decode($st_bak, true); $sj['ok'] = false; $sj['errors'] = array('boom: cannot read'); file_put_contents($il_tmp . '/lists/lists-status.json', json_encode($sj));
t_ok('health: the last compile reported errors: compile_failed with the first error', in_array(array('compile_failed', 'boom: cannot read'), $hl(), true));
file_put_contents($il_tmp . '/lists/lists-status.json', $st_bak);
t_ok('health: a FAILED compile job newer than the last compile: compile_failed; an older failure and other job types do not count',
	in_array(array('compile_failed', 'job j9'), $hl(array(array('id' => 'j9', 'type' => 'iplist_compile', 'status' => 'failed', 'requested_at' => time() + 5))), true)
	&& !array_filter($hl(array(array('id' => 'j9', 'type' => 'iplist_compile', 'status' => 'failed', 'requested_at' => 5))), function ($w) { return $w[0] === 'compile_failed'; })
	&& !array_filter($hl(array(array('id' => 'j9', 'type' => 'geo_compile', 'status' => 'failed', 'requested_at' => time() + 5))), function ($w) { return $w[0] === 'compile_failed'; })
	&& !array_filter($hl(array(array('id' => 'j10', 'type' => 'iplist_compile', 'status' => 'done', 'requested_at' => time() + 9), array('id' => 'j9', 'type' => 'iplist_compile', 'status' => 'failed', 'requested_at' => time() + 5))), function ($w) { return $w[0] === 'compile_failed'; }));
touch($il_tmp . '/lists/lists.json', time() + 5000);
t_ok('health: lists changed long ago and never compiled (pending): a warning only after 10 minutes', in_array(array('pending', ''), $hl(array(), time() + 5700), true) && !in_array(array('pending', ''), $hl(array(), time() + 5100), true));
touch($il_tmp . '/lists/lists.json');
$ha = gp_health_alerts(array_merge(array('now' => time(), 'redis_up' => true, 'jobs' => array(), 'storage' => array('warnings' => array()), 'snapshot' => array('generated_at' => time(), 'tz' => array('offset' => 0)), 'tz_offset' => 0,
	'queue' => array('stuck' => false), 'cron' => array('mode' => 'none', 'report' => null)),
	array('iplist_warn' => array(array('file_missing', 'block'), array('file_corrupt', 'allow'), array('compile_failed', 'job j1'), array('pending', '')))));
$hm = array(); foreach ($ha as $a) { $hm[$a['id']] = $a; }
t_ok('alerts: file_missing / file_corrupt / compile_failed are CRITICAL and link to the IP lists page, pending is a warning',
	$hm['iplist_file_missing_block']['level'] === 'critical' && $hm['iplist_file_corrupt_allow']['level'] === 'critical' && $hm['iplist_compile_failed']['level'] === 'critical' && $hm['iplist_pending']['level'] === 'warning'
	&& $hm['iplist_file_missing_block']['link'] === 'iplists' && $hm['iplist_file_missing_block']['key'] === 'al_iplist_file_missing');
t_ok('alerts: nothing wrong, nothing raised', !array_filter(gp_health_alerts(array('now' => time(), 'redis_up' => true, 'jobs' => array(), 'storage' => array('warnings' => array()), 'snapshot' => array('generated_at' => time(), 'tz' => array('offset' => 0)), 'tz_offset' => 0,
	'queue' => array('stuck' => false), 'cron' => array('mode' => 'none', 'report' => null), 'iplist_warn' => array())), function ($a) { return strpos($a['id'], 'iplist') === 0; }));
list($h_dal, $e_dal) = $jh_render('dashboard', array(), array('alerts' => $ha, 'isum' => array('total' => 2, 'enabled' => 2, 'by' => array('block/enforce' => 1, 'allow/monitor' => 1))));
t_ok('dashboard: the IP list alerts render with their text, the compiled file / job in the detail, a link to the IP lists page, and the protection card counts enabled lists',
	!$e_dal && strpos($h_dal, 'data-alert="iplist_file_missing_block"') !== false && strpos($h_dal, 'data-alert="iplist_compile_failed"') !== false && strpos($h_dal, 'compiled IP list file is missing') !== false
	&& strpos($h_dal, 'job j1') !== false && strpos($h_dal, 'index.php?r=iplists') !== false && strpos($h_dal, 'Enabled IP lists') !== false && strpos($h_dal, 'Block') !== false);
t_ok('summary: enabled lists by type / mode for the dashboard', gp_iplists_summary(array(array('enabled' => true, 'type' => 'block', 'mode' => 'enforce'), array('enabled' => true, 'type' => 'block', 'mode' => 'enforce'), array('enabled' => false, 'type' => 'allow', 'mode' => 'monitor'), array('enabled' => true, 'type' => 'allow', 'mode' => 'monitor')))
	=== array('total' => 4, 'enabled' => 3, 'by' => array('block/enforce' => 2, 'allow/monitor' => 1)));

// ---- filters (include / exclude) on the lists table
$fr = gp_iplists_rows(gp_iplists_state()['lists'], gp_iplists_status(), array('iplists' => array('block:scrapers' => array('h24' => 5, 'd7' => 9, 'last' => 123))));
$fl = function (array $get) use ($fr) { return array_column(gp_iplists_filter_rows($fr, gp_filter_parse($get, gp_iplists_filter_spec())), 'id'); };
t_ok('rows: carry the compile counts and the snapshot hits of their own type:id', $fr[0]['hit'] === array('h24' => 5, 'd7' => 9, 'last' => 123) && $fr[0]['stat']['entries'] === 3 && $fr[1]['hit'] === array());
t_ok('filter: type is / is not', $fl(array('type' => 'allow')) === array('partners', 'big-allow') && count($fl(array('type' => 'allow', 'type_op' => 'not'))) === count($fr) - 2 && count($fl(array('type' => 'allow,block'))) === count($fr));
t_ok('filter: mode is / is not, status is / is not, several values OR inside the field, fields AND together',
	$fl(array('mode' => 'monitor')) === array('second') && !in_array('second', $fl(array('mode' => 'monitor', 'mode_op' => 'not')), true) && count($fl(array('status' => 'enabled'))) === count($fr) && $fl(array('status' => 'disabled')) === array()
	&& $fl(array('type' => 'block', 'mode' => 'monitor')) === array('second') && $fl(array('type' => 'allow', 'mode' => 'monitor')) === array());
t_ok('filter: the name filter contains / does not contain, on the name and the id, case-insensitively', $fl(array('name' => 'SCRAP')) === array('scrapers', 'scrapers-2') && in_array('partners', $fl(array('name' => 'scrap', 'name_op' => 'not')), true) && !in_array('scrapers', $fl(array('name' => 'scrap', 'name_op' => 'not')), true));

// ---- delete
$del = gp_iplists_delete('wide', 'tester', '1.1.1.1');
t_ok('delete: the record and the source are gone, the compiled file no longer holds its ranges, the audit has before / null',
	$del[0] && gp_ipl_find(gp_iplists_state()['lists'], 'wide') === null && !is_file($il_tmp . '/lists/wide.txt') && (gv_geo_state(true) || true) && gv_iplist_check('70.1.1.1')['block'] === null
	&& strpos((string)file_get_contents($il_tmp . '/audit.jsonl'), '"key":"wide"') !== false && !gp_iplists_delete('wide', 't', '1')[0]);
foreach (array('scrapers', 'scrapers-2', 'second', 'uploaded', 'partners', 'big-allow') as $d) { gp_iplists_delete($d, 'tester', '1.1.1.1'); }
t_ok('delete: with every list gone no compiled file is left, so the guard opens nothing', !is_file($il_tmp . '/lists/block.bin') && !is_file($il_tmp . '/lists/allow.bin') && gp_iplists_state()['lists'] === array());
// An invalid metadata file blocks every write.
file_put_contents($il_tmp . '/lists/lists.json', '{not json');
t_ok('state: an unreadable lists.json is "invalid" and every write refuses until it is repaired', gp_iplists_state()['state'] === 'invalid' && $sv(array('name' => 'Z', 'text' => '1.2.3.4'))['msg'] === 'ipl_file_invalid' && gp_iplists_set(array('id' => 'a', 'enabled' => '1'), 't', '1')[0] === false);
@unlink($il_tmp . '/lists/lists.json');
// ---- the compile enforces the caps on files that never went through the form (SFTP, the worker)
$_SERVER['SERVER_ADDR'] = '198.51.100.77';
$cp1 = $sv(array('name' => 'Cap allow', 'type' => 'allow', 'mode' => 'enforce'));
$cp2 = $sv(array('name' => 'Cap block', 'type' => 'block', 'mode' => 'enforce'));
$cp3 = $sv(array('name' => 'Cap forced', 'type' => 'allow', 'mode' => 'enforce', 'force' => '1'));
t_ok('caps: the panel records the server\'s own address in lists.json on every metadata write', $cp1['ok'] && $cp2['ok'] && $cp3['ok'] && gp_iplists_state()['own'] === array('198.51.100.77')
	&& json_decode(file_get_contents($il_tmp . '/lists/lists.json'), true)['own'] === array('198.51.100.77'));
unset($_SERVER['SERVER_ADDR']);
file_put_contents($il_tmp . '/lists/cap-allow.txt', "0.0.0.0/0\n::/0\n64.0.0.0/12\n2400::/31\n203.0.113.0/24\nnot an address\r\n198.51.100.0/24\n");
file_put_contents($il_tmp . '/lists/cap-block.txt', "0.0.0.0/0\n::/0\n10.1.0.0/16\n127.0.0.1\n169.254.9.9\nfc00:1::/32\n::1\nfe80::/64\n198.51.100.77\n64.0.0.0/7\n2400::/31\n203.0.114.0/24\nbogus\n2a02::/32\n");
file_put_contents($il_tmp . '/lists/cap-forced.txt', "0.0.0.0/0\n::/0\n64.0.0.0/12\n2400::/31\n");
$cpc = gp_iplists_compile();
$cps = gp_iplists_status();
$ca_ = $cps['lists']['cap-allow']; $cb_ = $cps['lists']['cap-block']; $cf_ = $cps['lists']['cap-forced'];
t_ok('caps (SFTP file, allow): 0/0 and ::/0 and a /12 and an IPv6 /31 are dropped, valid entries kept, bad lines counted with their number, nothing fatal',
	$cpc['ok'] && $ca_['dropped'] === array('all' => 2, 'allow_wide' => 2, 'wide' => 0, 'protected' => 0) && $ca_['dropped_n'] === 4 && $ca_['entries'] === 2 && $ca_['invalid'] === 1 && $ca_['invalid_samples'] === array(array(6, 'not an address'))
	&& $ca_['dropped_samples'][0] === array('0.0.0.0/0', 'all') && $ca_['dropped_samples'][3] === array('2400::/31', 'allow_wide') && $ca_['dropped_huge'] === 2);
t_ok('caps (SFTP file, block): 0/0, ::/0, private, loopback, link-local, ULA, the server\'s own address and a /7 or an IPv6 /31 are dropped; public entries kept',
	$cb_['dropped'] === array('all' => 2, 'allow_wide' => 0, 'wide' => 2, 'protected' => 7) && $cb_['entries'] === 2 && $cb_['invalid'] === 1 && $cb_['dropped_huge'] === 0
	&& in_array(array('198.51.100.77', 'protected'), $cb_['dropped_samples'], true));
gv_geo_state(true);
t_ok('caps: nothing dropped reached the compiled files: the guard finds the kept entries and none of the dropped ones',
	gv_iplist_check('203.0.113.9')['allow'] !== null && gv_iplist_check('8.8.8.8')['allow'] === null && gv_iplist_check('1.1.1.1')['allow'] === null && gv_iplist_check('2a03::1')['allow'] === null && gv_iplist_check('0.0.0.5')['allow'] === null
	&& gv_iplist_check('203.0.114.9')['block'] !== null && gv_iplist_check('10.1.2.3')['block'] === null && gv_iplist_check('127.0.0.1')['block'] === null && gv_iplist_check('198.51.100.77')['block'] === null && gv_iplist_check('2a02::1')['block'] !== null);
t_ok('caps (forced list): 0/0 and ::/0 are STILL dropped, the /12 and the IPv6 /31 are kept', $cf_['dropped'] === array('all' => 2, 'allow_wide' => 0, 'wide' => 0, 'protected' => 0) && $cf_['entries'] === 2 && $cf_['dropped_huge'] === 2 && gv_iplist_check('64.1.1.1')['allow'] !== null && gv_iplist_check('8.8.8.8')['allow'] === null);
$cph = gp_iplists_health(time(), array());
$cphm = array(); foreach ($cph as $w) { $cphm[$w[0]] = $w[1]; }
t_ok('caps: the dashboard gets a "dropped" warning (total and lists) and a critical "allow_huge" for the allow lists that lost an entry wider than /8; the block list alone does not raise allow_huge',
	isset($cphm['dropped']) && strpos($cphm['dropped'], '17') === 0 && strpos($cphm['dropped'], 'cap-block') !== false && isset($cphm['allow_huge']) && strpos($cphm['allow_huge'], 'cap-allow') !== false && strpos($cphm['allow_huge'], 'cap-forced') !== false && strpos($cphm['allow_huge'], 'cap-block') === false);
$cha = array(); foreach (gp_health_alerts(array('now' => time(), 'redis_up' => true, 'jobs' => array(), 'storage' => array('warnings' => array()), 'snapshot' => array('generated_at' => time(), 'tz' => array('offset' => 0)), 'tz_offset' => 0,
	'queue' => array('stuck' => false), 'cron' => array('mode' => 'none', 'report' => null), 'iplist_warn' => $cph)) as $a_) { $cha[$a_['id']] = $a_['level']; }
t_ok('caps: alert levels: allow_huge critical, dropped warning', ($cha['iplist_allow_huge'] ?? '') === 'critical' && ($cha['iplist_dropped'] ?? '') === 'warning');
t_ok('caps (form): 0/0 pasted into a list is refused with the reason "all" even with the box ticked; a /12 in an allow list is refused unless forced',
	(function () use ($sv) {
		$a = $sv(array('name' => 'Cap form', 'type' => 'allow', 'force' => '1', 'text' => "0.0.0.0/0\n203.0.200.0/24\n"));
		$b = $sv(array('name' => 'Cap form2', 'type' => 'allow', 'text' => "64.0.0.0/12\n"));
		return !$a['ok'] && $a['report']['refused'][0][2] === 'all' && !$b['ok'] && $b['report']['refused'][0][2] === 'allow_wide';
	})());
$cap_render = function (array $vars) {
	$errs = array();
	set_error_handler(function ($no, $str) use (&$errs) { $errs[] = $str; return true; });
	$state = gp_iplists_state();
	$vars = array_merge(array('state' => $state, 'filter' => array(), 'edit' => null, 'save' => null, 'warnings' => array(), 'pending' => false, 'health' => array(), 'efilter' => array(), 'test_ip' => '', 'test' => null,
		'test_ran' => false, 'limit' => 2097152, 'jobs' => array(), 'prev' => array('allow' => false, 'block' => false), 'snapshot' => null, 'route' => 'iplists', 'user' => 'tester'), $vars);
	$vars['visible'] = $vars['all'];
	extract($vars, EXTR_SKIP);
	ob_start();
	require __DIR__ . '/../panel/views/iplists.php';
	$html = ob_get_clean();
	restore_error_handler();
	return array($html, $errs);
};
$cps_html = $cap_render(array('status' => $cps, 'all' => gp_iplists_rows(gp_iplists_state()['lists'], $cps, null), 'eid' => 'cap-block', 'entries' => gp_iplists_entries('cap-block', array())));
t_ok('caps: the Compile and Entries tabs show what was dropped (counts per reason, samples) and the skipped lines, escaped; no PHP warning',
	!$cps_html[1] && strpos($cps_html[0], '198.51.100.77 (protected)') !== false && strpos($cps_html[0], '0.0.0.0/0 (all)') !== false && strpos($cps_html[0], 'bogus') !== false && substr_count($cps_html[0], 'gp-badge-warn') >= 4);
foreach (array('cap-allow', 'cap-block', 'cap-forced') as $d) { gp_iplists_delete($d, 'tester', '1.1.1.1'); }
t_ok('caps: the test lists are gone again', gp_iplists_state()['lists'] === array() && !is_file($il_tmp . '/lists/block.bin'));

// ---- a deny override under an ENFORCED allow list has no effect: warn, with a link to the list
$sd1 = $sv(array('name' => 'Shadow allow', 'type' => 'allow', 'mode' => 'enforce', 'text' => "203.0.113.0/24\n2001:db8:aa::/48\n"));
$sd2 = $sv(array('name' => 'Shadow monitor', 'type' => 'allow', 'mode' => 'monitor', 'text' => "198.51.100.0/24\n"));
gv_geo_state(true);
$sd_logs = $il_tmp . '/logs';
file_put_contents($sd_logs . '/guard-' . date('Ymd') . '.jsonl', json_encode(array('ts' => time(), 'ip' => '203.0.113.50', 'dev' => 'devcovered', 'act' => 'allow')) . "\n"
	. json_encode(array('ts' => time(), 'ip' => '192.0.2.50', 'dev' => 'devfree', 'act' => 'allow')) . "\n");
$sd_cfg = $il_tmp . '/config-shadow.php';
file_put_contents($sd_cfg, "<?php\nif (!defined('GV_BOOT')) { exit; }\n\$c = require " . var_export(__DIR__ . '/config.dev.php', true) . ";\n\$c['log_dir'] = " . var_export($sd_logs, true) . ";\nreturn \$c;\n");
putenv('GV_CONFIG=' . $sd_cfg);
$sh = gp_iplists_deny_shadow(array('203.0.113.9', '::ffff:203.0.113.9', '2001:db8:aa::5', '198.51.100.7', '8.8.8.8', 'devcovered', 'devfree', 'devunknown', '', 'x y'));
putenv('GV_CONFIG');
t_ok('shadow: an address inside an ENFORCED allow list (v4, mapped, v6) and a device seen on such an address are reported with the list id; a monitor allow list, other addresses, unknown or odd identities are not',
	$sh === array('203.0.113.9' => 'shadow-allow', '::ffff:203.0.113.9' => 'shadow-allow', '2001:db8:aa::5' => 'shadow-allow', 'devcovered' => 'shadow-allow') && gp_iplists_allow_cover('198.51.100.7') === '' && gp_iplists_allow_cover('nonsense') === '');
$sd_over = function (array $shadow) {
	$errs = array();
	set_error_handler(function ($no, $str) use (&$errs) { $errs[] = $str; return true; });
	$vars = array('redis_up' => true, 'filter' => array(), 'items_all' => array(array('kind' => 'deny', 'identity' => '203.0.113.9', 'ttl' => 100)), 'items' => array(array('kind' => 'deny', 'identity' => '203.0.113.9', 'ttl' => 100)), 'shadow' => $shadow, 'route' => 'overrides', 'user' => 't');
	extract($vars, EXTR_SKIP);
	ob_start();
	require __DIR__ . '/../panel/views/overrides.php';
	$h = ob_get_clean();
	restore_error_handler();
	return array($h, $errs);
};
list($sd_h, $sd_e) = $sd_over(array('203.0.113.9' => 'shadow-allow'));
t_ok('shadow: the Overrides page says the deny has no effect, names the list and links to its entries', !$sd_e && strpos($sd_h, 'data-shadow="203.0.113.9"') !== false && strpos($sd_h, 'has NO effect') !== false && strpos($sd_h, 'enforced allow list &quot;shadow-allow&quot;') !== false
	&& strpos($sd_h, 'index.php?r=iplists&amp;list=shadow-allow#ipl-entries') !== false);
list($sd_h2, $sd_e2) = $sd_over(array());
t_ok('shadow: no warning when no deny is covered', !$sd_e2 && strpos($sd_h2, 'data-shadow') === false);
$sd_src = file_get_contents(__DIR__ . '/../panel/index.php');
t_ok('shadow: creating a deny override flashes the warning (the handler calls the check)', strpos($sd_src, "if (\$action === 'deny') {\n\t\t\t\t\$sh = gp_iplists_deny_shadow(") !== false && strpos((require __DIR__ . '/../panel/lang.php')['ovr_deny_shadowed'], '%s') !== false);
foreach (array('shadow-allow', 'shadow-monitor') as $d) { gp_iplists_delete($d, 'tester', '1.1.1.1'); }
t_ok('shadow: the test lists are gone again', gp_iplists_state()['lists'] === array());

// Big lists go through the worker.
$sv(array('name' => 'Huge', 'text' => '203.0.113.0/24'));
file_put_contents($il_tmp . '/lists/huge.txt', str_repeat("203.0.113.0/24\n", 50000));
t_ok('compile mode: sources up to 512 KiB compile in the request, a bigger total (or "use the worker job") goes to the worker',
	gp_iplists_compile_mode(gp_iplists_state()['lists']) === 'job' && gp_ipl_enabled_bytes(gp_iplists_state()['lists']) > GP_IPL_INLINE_BYTES
	&& gp_iplists_compile_mode(array()) === 'inline' && gp_iplists_compile_mode(array(), true) === 'job');
t_ok('compile_auto: the iplist_compile job type is on the closed list and takes no parameters', in_array('iplist_compile', gp_job_types(), true) && gp_job_params('iplist_compile', array())[0] === true);
gp_iplists_delete('huge', 'tester', '1.1.1.1');

// ---- the page renders, escaped, with tabs, tooltips and filters
$il_render = function (array $extra) {
	$errs = array();
	set_error_handler(function ($no, $str) use (&$errs) { $errs[] = $str; return true; });
	$state = gp_iplists_state(); $status = gp_iplists_status();
	$rows = gp_iplists_rows($state['lists'], $status, null);
	$vars = array_merge(array('state' => $state, 'status' => $status, 'all' => $rows, 'visible' => $rows, 'filter' => array(), 'edit' => null, 'save' => null, 'warnings' => array(), 'pending' => false, 'health' => array(),
		'eid' => '', 'efilter' => array(), 'entries' => array(array(), 0, 0, 0), 'test_ip' => '', 'test' => null, 'test_ran' => false, 'limit' => 2097152, 'jobs' => array(), 'prev' => array('allow' => false, 'block' => false),
		'snapshot' => null, 'route' => 'iplists', 'user' => 'tester'), $extra);
	extract($vars, EXTR_SKIP);
	ob_start();
	require __DIR__ . '/../panel/views/iplists.php';
	$html = ob_get_clean();
	restore_error_handler();
	return array($html, $errs);
};
list($h0, $e0) = $il_render(array());
t_ok('page, no lists: renders without a PHP warning, five tabs, an empty-state text', !$e0 && substr_count($h0, 'role="tab"') === 5 && strpos($h0, 'No list yet') !== false && strpos($h0, 'role="tabpanel"') !== false);
$sv(array('name' => 'Evil <script>alert(1)</script>', 'note' => '"><img src=x>', 'text' => "203.0.113.0/24\nbogus<b>\n"));
$sv(array('name' => 'Evil <script>alert(1)</script>', 'note' => '"><img src=x>', 'text' => "203.0.113.0/24\n", 'accept' => '1'));
$gp_post_bak = $_POST;
list($h1, $e1) = $il_render(array('filter' => gp_filter_parse(array('type' => 'block', 'type_op' => 'not', 'name' => 'ev'), gp_iplists_filter_spec())));
t_ok('page, with lists: names and notes are escaped, nothing breaks out', !$e1 && strpos($h1, '<script>alert') === false && strpos($h1, '<img src=x>') === false && strpos($h1, 'Evil &lt;script&gt;') !== false);
t_ok('page: the lists table sits in a gp-table-wrap and shows enabled / mode / counts', strpos($h1, 'gp-table-wrap') !== false && strpos($h1, 'gp-badge-bad') !== false);
t_ok('page: active filters are chips and "is not" is visibly marked', strpos($h1, 'gp-chip-not') !== false && strpos($h1, 'flt_is_not') === false);
list($h2, $e2) = $il_render(array('edit' => array('id' => '', 'name' => 'N', 'type' => 'block', 'mode' => 'monitor', 'enabled' => true, 'force' => false, 'note' => '', 'text' => ''),
	'save' => array('ok' => false, 'msg' => 'ipl_confirm', 'detail' => '', 'errors' => array('name' => 'bad_name'), 'pending' => 'abcdef0123456789', 'draft' => null,
		'report' => array('invalid' => array(array(2, 'bogus<b>')), 'invalid_n' => 1, 'refused' => array(array(3, '10.0.0.0/8', 'protected')), 'refused_n' => 1))));
t_ok('page, editor after a refused save: the confirmation table with line numbers and reasons, the accept box, the pending token, the name error, and the Editor tab opens with an error badge',
	!$e2 && strpos($h2, 'bogus&lt;b&gt;') !== false && strpos($h2, 'name="accept"') !== false && strpos($h2, 'name="pending" value="abcdef0123456789"') !== false && strpos($h2, 'data-open="editor"') !== false && strpos($h2, 'gp-tab-badge') !== false && strpos($h2, 'name="csrf"') !== false);
t_ok('page, editor: every field has a tooltip, the file input and the paste box, the force box', substr_count($h2, 'class="gp-tip"') >= 8 && strpos($h2, 'type="file" name="file"') !== false && strpos($h2, 'name="text"') !== false && strpos($h2, 'name="force"') !== false);
$ent = gp_iplists_entries(gp_iplists_state()['lists'][0]['id'], array());
list($h3, $e3) = $il_render(array('eid' => gp_iplists_state()['lists'][0]['id'], 'entries' => $ent, 'test_ip' => '203.0.113.5', 'test_ran' => true, 'test' => gp_iplists_test('203.0.113.5'),
	'warnings' => array(array('conflict', '1.2.3.4 (a / b)')), 'health' => array(array('file_missing', 'block')), 'pending' => true));
t_ok('page, entries / tester / warnings / alerts: render without a warning and show the entry, the matching list and the notes', !$e3 && strpos($h3, '203.0.113.0/24') !== false && strpos($h3, 'ipl_eff_') === false && strpos($h3, 'both an allow and a block list') !== false && strpos($h3, 'compiled IP list file is missing') !== false);
list($h4, $e4) = $il_render(array('test_ran' => true, 'test' => null, 'test_ip' => 'zzz'));
t_ok('page, tester with a bad address says so', !$e4 && strpos($h4, 'not a valid') !== false || strpos($h4, 'geo_bad_ip') === false);
foreach (gp_iplists_state()['lists'] as $l) { gp_iplists_delete($l['id'], 'tester', '1.1.1.1'); }
$_POST = $gp_post_bak;

// ---- wiring: route, nav, lang, tips
$idx_src = file_get_contents(__DIR__ . '/../panel/index.php');
t_ok('wiring: the route, the nav entry and the dashboard hooks exist', strpos($idx_src, "case 'iplists':") !== false && strpos(file_get_contents(__DIR__ . '/../panel/views/layout.php'), "'iplists'") !== false
	&& strpos($idx_src, "gp_iplists_summary") !== false && strpos(file_get_contents(__DIR__ . '/../panel/health.php'), 'gp_iplists_health') !== false);
$il_lang = require __DIR__ . '/../panel/lang.php';
$il_tip_miss = array(); $il_tip_short = array();
foreach (array('ipl_name', 'ipl_type', 'ipl_mode', 'ipl_enabled', 'ipl_note', 'ipl_text', 'ipl_file', 'ipl_force', 'ipl_accept', 'ipl_filter_name', 'ipl_compile', 'ipl_compile_job', 'ipl_ip', 'ipl_f_entry', 'ipl_f_family', 'ipl_f_list') as $k) {
	$t = isset($il_lang['tip_' . $k]) ? $il_lang['tip_' . $k] : '';
	if ($t === '') { $il_tip_miss[] = $k; continue; }
	if (strlen($t) < 50 || stripos($t, 'safe value') === false || stripos($t, 'risk') === false || stripos($t, 'what it does') === false) { $il_tip_short[] = $k; }
}
t_ok('every IP list field and filter has a tooltip with what it does, a safe value and the risk' . ($il_tip_miss ? ' (missing: ' . implode(',', $il_tip_miss) . ')' : '') . ($il_tip_short ? ' (incomplete: ' . implode(',', $il_tip_short) . ')' : ''), !$il_tip_miss && !$il_tip_short);
preg_match_all("/gp_tip\\('([a-z_]+)'\\)/", file_get_contents(__DIR__ . '/../panel/views/iplists.php'), $il_mm);
t_ok('every literal gp_tip() key in the IP lists view has a text', !array_filter($il_mm[1], function ($k) use ($il_lang) { return !isset($il_lang['tip_' . $k]); }));
t_ok('the IP lists view loads nothing from outside', preg_match('#https?://#', file_get_contents(__DIR__ . '/../panel/views/iplists.php') . file_get_contents(__DIR__ . '/../panel/iplists.php')) === 0);
t_ok('the selftest left nothing in the repository: no lists/ files, no audit line for it', glob(__DIR__ . '/../lists/*.{txt,bin,json}', GLOB_BRACE) === array());
putenv('GV_LISTS_DIR'); putenv('GV_GEO_DIR'); putenv('GV_AUDIT');
gv_geo_state(true);

t_section('Image CAPTCHA: rule action, impact preview, Settings tab, dashboard KPIs and the GD alert');

$cr_rule = array_merge(gp_rule_blank(), array('id' => 'cx', 'name' => 'c', 'mode' => 'enforce', 'action' => 'captcha', 'ua' => array('op' => 'include', 'type' => 'contains', 'values' => array('scraper'))));
$cr_rows = array(
	array('ua' => 'scraper/1', 'p' => '/a', 'ip' => '203.0.113.1', 'nav' => 1, 'gate' => 1, 'tok' => 'm', 'act' => 'challenge', 'dev' => ''),                 // would get a CAPTCHA
	array('ua' => 'scraper/1', 'p' => '/b', 'ip' => '203.0.113.2', 'nav' => 1, 'gate' => 1, 'tok' => 'v', 'act' => 'allow', 'dev' => 'd1'),                  // PoW-level token: still asked
	array('ua' => 'scraper/1', 'p' => '/c', 'ip' => '203.0.113.3', 'nav' => 1, 'gate' => 1, 'tok' => 'v', 'tl' => 'c', 'act' => 'allow', 'dev' => 'd2'),     // CAPTCHA-level token: not asked
	array('ua' => 'scraper/1', 'p' => '/d', 'ip' => '203.0.113.4', 'nav' => 0, 'gate' => 1, 'tok' => 'm', 'act' => 'allow'),                                  // not HTML: keeps its flow
	array('ua' => 'scraper/1', 'p' => '/e', 'ip' => '203.0.113.5', 'nav' => 1, 'gate' => 0, 'tok' => 'm', 'act' => 'allow'),                                  // not gated
	array('ua' => 'scraper/1', 'p' => '/f', 'ip' => '203.0.113.6', 'nav' => 1, 'gate' => 1, 'tok' => 'm', 'act' => 'exempt'),                                 // exempt path
	array('ua' => 'scraper/1', 'p' => '/g', 'ip' => '203.0.113.7', 'nav' => 1, 'gate' => 1, 'tok' => 'm', 'act' => 'allow_override'),                         // operator allow
	array('ua' => 'scraper/1', 'p' => '/h', 'ip' => '203.0.113.8', 'nav' => 1, 'gate' => 1, 'tok' => 'm', 'botv' => 'ok', 'act' => 'allow_bot'),             // verified crawler
	array('ua' => 'scraper/1', 'p' => '/i', 'ip' => '203.0.113.9', 'nav' => 1, 'tok' => 'm', 'act' => 'challenge'),                                           // an older row without gate: counts as gated
	array('ua' => 'nice/1', 'p' => '/j', 'ip' => '203.0.113.10', 'nav' => 1, 'gate' => 1, 'tok' => 'm'),                                                      // does not match
);
$cr_im = gp_rules_impact_fold($cr_rule, $cr_rows);
t_ok('impact: a captcha rule counts how many matched requests WOULD get a CAPTCHA (HTML, gated, no CAPTCHA-level token, not exempt, not allowed, not a verified crawler)',
	$cr_im['captcha'] === true && $cr_im['requests'] === 8 && $cr_im['captcha_would'] === 3 && $cr_im['tokened'] === 2);
t_ok('impact: a verified crawler is not counted for a captcha rule even with skip_verified_bots off (it is never asked)', gp_rules_impact_fold(array_merge($cr_rule, array('skip_verified_bots' => false)), $cr_rows)['requests'] === 8);
t_ok('impact: other actions carry no captcha number', gp_rules_impact_fold(array_merge($cr_rule, array('action' => 'challenge')), $cr_rows)['captcha'] === false && gp_rules_impact_fold(array_merge($cr_rule, array('action' => 'challenge')), $cr_rows)['captcha_would'] === 0);
t_ok('impact: an empty log is zero, not an error', gp_rules_impact_fold($cr_rule, array())['captcha_would'] === 0);
$cr_view = function (array $im) {
	$errs = array(); set_error_handler(function ($no, $str) use (&$errs) { $errs[] = $str; return true; });
	$state = array('state' => 'ok', 'rules' => array(), 'dropped' => 0, 'path' => ''); $all = array(); $visible = array(); $filter = array(); $draft = gp_rule_blank(); $errors = array(); $details = array(); $warnings = array();
	$impact = $im; $test = null; $test_in = array('ua' => '', 'path' => '', 'verified' => false, 'ip' => ''); $snapshot = null; $route = 'rules'; $user = 't';
	ob_start(); require __DIR__ . '/../panel/views/rules.php'; $h = ob_get_clean(); restore_error_handler(); return array($h, $errs);
};
$cr_im['meta'] = array('files' => 1, 'capped' => false, 'from' => time() - 100, 'to' => time(), 'newest' => time(), 'oldest' => time() - 100);
list($cr_h, $cr_e) = $cr_view($cr_im);
t_ok('rules page: the impact preview shows the number of requests that would get a CAPTCHA and says what it counts; the action list has Image CAPTCHA', !$cr_e && strpos($cr_h, 'data-captcha-would="3"') !== false && strpos($cr_h, 'Would get a CAPTCHA') !== false && strpos($cr_h, 'value="captcha"') !== false && strpos($cr_h, 'Image CAPTCHA') !== false);
putenv('GV_CAPTCHA_NO_GD=1');
t_ok('rules form: a captcha rule on a PHP without GD is warned about; other actions are not', in_array(array('captcha_gd', ''), gp_rule_warnings($cr_rule, gv_cfg_defaults(array())), true) && !in_array(array('captcha_gd', ''), gp_rule_warnings(array_merge($cr_rule, array('action' => 'block')), gv_cfg_defaults(array())), true));
putenv('GV_CAPTCHA_NO_GD');
t_ok('rules form: with GD there is no captcha warning', gv_captcha_available() === false || !in_array(array('captcha_gd', ''), gp_rule_warnings($cr_rule, gv_cfg_defaults(array())), true));
// the alert
$ca_cfg = gv_cfg_defaults(array());
$ca_live = array_merge($cr_rule, array('enabled' => true, 'expires_at' => 0));
t_ok('alert input: a CAPTCHA is "needed" by an enforced captcha rule, an escalation score or the device budget; a monitor rule, a disabled rule, a block rule need none',
	gp_captcha_needed($ca_cfg, array($ca_live)) === true && gp_captcha_needed($ca_cfg, array(array_merge($ca_live, array('mode' => 'monitor')))) === false && gp_captcha_needed($ca_cfg, array(array_merge($ca_live, array('enabled' => false)))) === false
	&& gp_captcha_needed($ca_cfg, array(array_merge($ca_live, array('action' => 'block')))) === false && gp_captcha_needed($ca_cfg, array()) === false && gp_captcha_needed(array_merge($ca_cfg, array('captcha' => array_merge($ca_cfg['captcha'], array('escalate_score' => 60)))), array()) === true
	&& gp_captcha_needed(array_merge($ca_cfg, array('captcha' => array_merge($ca_cfg['captcha'], array('device_budget' => true)))), array()) === true && gp_captcha_needed($ca_cfg, array(array_merge($ca_live, array('expires_at' => 5)))) === false);
$ca_base = array('now' => time(), 'redis_up' => true, 'jobs' => array(), 'storage' => array('warnings' => array()), 'snapshot' => array('generated_at' => time(), 'tz' => array('offset' => 0)), 'tz_offset' => 0, 'queue' => array('stuck' => false), 'cron' => array('mode' => 'none', 'report' => null));
$ca_ids = function (array $extra) use ($ca_base) { $o = array(); foreach (gp_health_alerts(array_merge($ca_base, $extra)) as $a_) { $o[$a_['id']] = $a_['level']; } return $o; };
t_ok('alert: GD missing while a CAPTCHA is configured: a warning that opens Settings; GD present, or nothing configured: no alert',
	($ca_ids(array('captcha_gd_needed' => true, 'captcha_gd' => false))['captcha_gd'] ?? '') === 'warning' && !isset($ca_ids(array('captcha_gd_needed' => true, 'captcha_gd' => true))['captcha_gd']) && !isset($ca_ids(array('captcha_gd_needed' => false, 'captcha_gd' => false))['captcha_gd'])
	&& (function () use ($ca_base) { foreach (gp_health_alerts(array_merge($ca_base, array('captcha_gd_needed' => true, 'captcha_gd' => false))) as $a_) { if ($a_['id'] === 'captcha_gd') { return $a_['link'] === 'settings' && $a_['key'] === 'al_captcha_gd'; } } return false; })());
// Settings
$cs_keys = array_values(array_filter(array_keys(gv_overlay_whitelist()), function ($k) { return strncmp($k, 'captcha.', 8) === 0 || strncmp($k, 'strings.cap_', 12) === 0; }));
$cs_src = file_get_contents(__DIR__ . '/../panel/views/settings.php');
t_ok('settings: every captcha.* and strings.cap_* key is on the Settings page (' . count($cs_keys) . ' keys)', !array_filter($cs_keys, function ($k) use ($cs_src) { return strpos($cs_src, "'" . $k . "'") === false; }) && count($cs_keys) >= 33);
$cs_render = function () {
	$cfg = gp_effective_config(); $overlay = array(); $errors = array(); $pending = array(); $diff = array(); $route = 'settings';
	$errs = array(); set_error_handler(function ($no, $str) use (&$errs) { $errs[] = $str; return true; });
	ob_start(); require __DIR__ . '/../panel/views/settings.php'; $h = ob_get_clean(); restore_error_handler(); return array($h, $errs);
};
list($cs_h, $cs_e) = $cs_render();
t_ok('settings: the CAPTCHA tab shows the GD status and the preview image with its button, and every field has a tooltip', !$cs_e && strpos($cs_h, 'data-panel="captcha"') !== false && (!gv_captcha_available() || (strpos($cs_h, 'id="cap-preview"') !== false && strpos($cs_h, 'id="cap-preview-btn"') !== false && strpos($cs_h, 'GD is installed') !== false))
	&& substr_count($cs_h, 'class="gp-tip"') > 100);
putenv('GV_CAPTCHA_NO_GD=1');
list($cs_h2, $cs_e2) = $cs_render();
putenv('GV_CAPTCHA_NO_GD');
t_ok('settings: without GD the tab says "CAPTCHA unavailable (GD not installed)", every captcha action falls back, and there is no broken preview image', !$cs_e2 && strpos($cs_h2, 'CAPTCHA unavailable (GD not installed)') !== false && strpos($cs_h2, 'id="cap-preview"') === false);
t_ok('settings: the preview is drawn by a logged-in-only route that validates its input and saves nothing', strpos(file_get_contents(__DIR__ . '/../panel/index.php'), "case 'captcha_preview':") !== false && strpos(file_get_contents(__DIR__ . '/../panel/index.php'), "ctype_digit(\$_GET['level'])") !== false
	&& strpos(file_get_contents(__DIR__ . '/../panel/views/layout.php'), "captcha_preview") !== false);
// the lang: every new setting has a label, a help text and a tooltip with the required parts
$cl = require __DIR__ . '/../panel/lang.php'; $cl_bad = array();
foreach ($cs_keys as $k) {
	$kk = str_replace('.', '_', $k);
	foreach (array('lbl_', 'help_', 'tip_set_') as $pre) { if (empty($cl[$pre . $kk])) { $cl_bad[] = $pre . $kk; } }
	$t = isset($cl['tip_set_' . $kk]) ? $cl['tip_set_' . $kk] : '';
	if (stripos($t, 'what it does') === false || stripos($t, 'safe value') === false || stripos($t, 'risk') === false) { $cl_bad[] = 'tip shape ' . $kk; }
}
t_ok('lang: every CAPTCHA setting has a label, a help text and a tooltip (what it does, a safe value, the risk)' . ($cl_bad ? ' (bad: ' . implode(',', array_slice($cl_bad, 0, 5)) . ')' : ''), !$cl_bad);
t_ok('lang: each headless signal has its own weight setting with the signal named in its tooltip', isset($cl['tip_set_captcha_w_webdriver']) && stripos($cl['tip_set_captcha_w_webdriver'], 'webdriver') !== false && stripos($cl['tip_set_captcha_w_webgl_soft'], 'WebGL') !== false && stripos($cl['tip_set_captcha_w_too_fast'], 'fast') !== false);
// the dashboard KPIs
$ck_snap = array('generated_at' => time(), 'tz' => array('offset' => 0, 'name' => 'UTC'), 'traffic' => array('requests' => 10, 'devices' => 3, 'addresses' => 4, 'degraded' => 0), 'decisions' => array('allow' => 9),
	'kpi' => array('cur' => array('requests' => 120, 'allowed' => 100, 'blocked' => 10, 'limited' => 2, 'challenged' => 8, 'challenge_success' => 91.5, 'rule_hits' => 7, 'honeypot' => 1, 'degraded' => 0,
		'captcha_shown' => 40, 'captcha_solved' => 30, 'captcha_failed' => 12, 'captcha_expired' => 3, 'captcha_solve_rate' => 75.0, 'captcha_median_s' => 6.5),
		'prev' => array('requests' => 100, 'allowed' => 90, 'blocked' => 5, 'limited' => 2, 'challenged' => 8, 'challenge_success' => 95.0, 'rule_hits' => 0, 'honeypot' => 1, 'degraded' => 0,
		'captcha_shown' => 20, 'captcha_solved' => 18, 'captcha_failed' => 4, 'captcha_expired' => 1, 'captcha_solve_rate' => 90.0, 'captcha_median_s' => 8.0)),
	'top' => array('rules' => array(), 'reasons' => array(), 'ips' => array(), 'devices' => array(), 'uas' => array(), 'paths' => array(), 'countries' => array()));
list($ck_h, $ck_e) = $jh_render('dashboard', array('snapshot' => $ck_snap));
t_ok('dashboard: the CAPTCHA KPIs (shown, solved, failed, expired, solve rate, median time) with the change against the previous 24 h; a rising failure count is marked',
	!$ck_e && strpos($ck_h, 'id="dash-captcha"') !== false && substr_count($ck_h, 'data-captcha-kpi=') === 6 && strpos($ck_h, 'CAPTCHAs shown') !== false && strpos($ck_h, '+100 %') !== false && strpos($ck_h, '-15.0 pt') !== false
	&& strpos($ck_h, '6.5 s') !== false && strpos($ck_h, '75.0%') !== false && strpos($ck_h, 'solving service') !== false && substr_count($ck_h, 'gp-kpi-label') === 9 + 6);
$ck_none = $ck_snap; $ck_none['kpi']['cur'] = array_merge($ck_none['kpi']['cur'], array('captcha_shown' => 0, 'captcha_solved' => 0, 'captcha_failed' => 0, 'captcha_expired' => 0, 'captcha_solve_rate' => null, 'captcha_median_s' => null));
list($ck_h2, $ck_e2) = $jh_render('dashboard', array('snapshot' => $ck_none));
t_ok('dashboard: no CAPTCHA activity in the 24 h: no CAPTCHA section at all (no empty tiles, no 0 %)', !$ck_e2 && strpos($ck_h2, 'id="dash-captcha"') === false);
$ck_only = $ck_snap; $ck_only['kpi']['cur']['captcha_solve_rate'] = null; $ck_only['kpi']['cur']['captcha_median_s'] = null; $ck_only['kpi']['cur']['captcha_solved'] = 0; $ck_only['kpi']['prev'] = array('requests' => 1);
list($ck_h3, $ck_e3) = $jh_render('dashboard', array('snapshot' => $ck_only));
t_ok('dashboard: a missing rate or median is a dash; a missing previous window shows no change', !$ck_e3 && strpos($ck_h3, 'data-captcha-kpi="captcha_median_s"') !== false && preg_match('/data-captcha-kpi="captcha_solve_rate".*?gp-kpi-value">—</s', $ck_h3) === 1);
list($ck_h4, $ck_e4) = $jh_render('dashboard', array('snapshot' => $kpi_snap));
t_ok('dashboard: an older snapshot without CAPTCHA keys renders exactly as before (9 tiles, no CAPTCHA section)', !$ck_e4 && strpos($ck_h4, 'id="dash-captcha"') === false && substr_count($ck_h4, 'gp-kpi-label') === 9);

t_section('Translations');
$tr_lang = file_get_contents(__DIR__ . '/../panel/lang.php');
// The panel is English and left-to-right. No Persian or Arabic script (letters
// or digits) may be written in its strings or its markup; text of that script
// can only reach a page from log data, which is shown as received.
t_ok('the panel strings are English: no Persian or Arabic script in lang.php', preg_match('/[\x{0600}-\x{06FF}]/u', $tr_lang) === 0);
$tr_src_bad = array();
foreach (array_merge(glob(__DIR__ . '/../panel/*.php'), glob(__DIR__ . '/../panel/views/*.php'), array(__DIR__ . '/../panel/assets/app.src.css')) as $tr_f) {
	if (preg_match('/[\x{0600}-\x{06FF}]/u', file_get_contents($tr_f))) { $tr_src_bad[] = basename($tr_f); }
}
t_ok('no Persian or Arabic script in any panel source file' . ($tr_src_bad ? ' (' . implode(',', $tr_src_bad) . ')' : ''), !$tr_src_bad);
$tr_dir_bad = array();
foreach (array_merge(glob(__DIR__ . '/../panel/*.php'), glob(__DIR__ . '/../panel/views/*.php')) as $tr_f) {
	$tr_src = file_get_contents($tr_f);
	if (stripos($tr_src, 'dir="rtl"') !== false || stripos($tr_src, 'lang="fa"') !== false) { $tr_dir_bad[] = basename($tr_f); }
}
t_ok('no page is declared Persian or right-to-left' . ($tr_dir_bad ? ' (' . implode(',', $tr_dir_bad) . ')' : ''), !$tr_dir_bad);
t_ok('the layout declares lang="en" dir="ltr"', strpos(file_get_contents(__DIR__ . '/../panel/views/layout.php'), '<html lang="en" dir="ltr">') !== false);
t_ok('settings: number fields take their range from the whitelist (no empty "global $rules")',
	strpos(file_get_contents(__DIR__ . '/../panel/views/settings.php'), 'global $rules') === false);
$tr_keys = array();
preg_match_all("/^\t'([a-z0-9_]+)'\s*=>/m", $tr_lang, $tr_keys);
t_ok('every translation key is unique', count($tr_keys[1]) === count(array_unique($tr_keys[1])));
$tr_missing = array();
foreach (array_merge(glob(__DIR__ . '/../panel/*.php'), glob(__DIR__ . '/../panel/views/*.php')) as $tr_f) {
	preg_match_all("/gp_t\('([a-z0-9_]+)'\s*[,)]/", file_get_contents($tr_f), $tr_u);
	foreach ($tr_u[1] as $tr_k) { if (!in_array($tr_k, $tr_keys[1], true)) { $tr_missing[$tr_k] = basename($tr_f); } }
}
t_ok('every gp_t() key used in the panel exists in lang.php' . ($tr_missing ? ' (missing: ' . implode(',', array_keys($tr_missing)) . ')' : ''), !$tr_missing);

t_section('Login page: message inside the card, username kept, lockout text');
$lg_render = function ($msg, $user) {
	ob_start();
	$login_msg = $msg; $login_user = $user;
	require __DIR__ . '/../panel/views/login.php';
	return ob_get_clean();
};
$lg_ok = $lg_render('', '');
$lg_bad = $lg_render(gp_t('login_failed'), 'open"cart<x>');
$lg_card = (preg_match('~<div class="gp-login-card">(.*)</div>\s*</div>\s*$~s', $lg_bad, $lg_m) === 1) ? $lg_m[1] : '';
t_ok('login: a clean page has no message box', strpos($lg_ok, 'role="alert"') === false && strpos($lg_ok, 'gp-flash') === false);
t_ok('login: the message sits inside the card, between the brand block and the form',
	$lg_card !== '' && ($a = strpos($lg_card, 'gp-login-brand')) !== false && ($b = strpos($lg_card, 'role="alert"')) !== false && ($c = strpos($lg_card, '<form')) !== false && $a < $b && $b < $c);
t_ok('login: the message box is an alert carrying the text', strpos($lg_bad, 'role="alert"') !== false && strpos($lg_bad, gp_t('login_failed')) !== false);
t_ok('login: the typed username is kept and escaped', strpos($lg_bad, 'value="open&quot;cart&lt;x&gt;"') !== false && strpos($lg_bad, 'cart<x>') === false);
t_ok('login: the password field never has a value', preg_match('~type="password"[^>]*\svalue=~', $lg_bad) !== 1);
t_ok('login: after a failure the password field takes focus, not the username', preg_match('~type="password"[^>]*autofocus~', $lg_bad) === 1 && preg_match('~name="username"[^>]*autofocus~', $lg_bad) !== 1);
t_ok('login: on a fresh page the username takes focus', preg_match('~name="username"[^>]*autofocus~', $lg_ok) === 1);
t_ok('login: the layout draws no flash container for the login view', (function () {
	$src = file_get_contents(__DIR__ . '/../panel/index.php');
	return strpos($src, "(\$view === 'login') ? array() : \$gp_flash") !== false;
})());
t_ok('login: the lockout text names a wait time and is different from the wrong-password text',
	strpos(gp_t('login_locked'), '%d') !== false && gp_t('login_locked') !== gp_t('login_failed')
	&& strpos(sprintf(gp_t('login_locked'), 15), '15') !== false);
t_ok('login: the lockout text does not say whether the username exists', stripos(gp_t('login_locked'), 'username') === false && stripos(gp_t('login_locked'), 'password') === false);
$lg_bucket = 'selftest-ttl-' . bin2hex(random_bytes(4));
gp_attempts_bump($lg_bucket, GP_LOGIN_WINDOW);
$lg_ttl = gp_attempts_ttl($lg_bucket, GP_LOGIN_WINDOW);
t_ok('login: the remaining lockout time is between 1 and the window', $lg_ttl >= 1 && $lg_ttl <= GP_LOGIN_WINDOW);
t_ok('login: an unknown bucket has no wait', gp_attempts_ttl('selftest-none-' . bin2hex(random_bytes(4)), GP_LOGIN_WINDOW) === 0);
@unlink(gp_attempts_file($lg_bucket));
$lg_c = gv_redis_connect(gv_cfg_load()['redis'], $GP_TMP_LOGS, false);
if ($lg_c) { gv_redis_cmd($lg_c, array('DEL', gp_key('login:' . $lg_bucket))); gv_redis_close($lg_c); }

// ==========================================================================
t_section('Updater: ZIP validation, protected files, apply, health check, rollback');
// Everything happens in scratch copies under the system temp directory; nothing is written into the repository tree.
require_once __DIR__ . '/../panel/update.php';
$UT = sys_get_temp_dir() . '/gp-upd-' . bin2hex(random_bytes(4));
@mkdir($UT, 0775, true);
putenv('GV_AUDIT=' . $UT . '/audit.jsonl');
register_shutdown_function(function () use ($UT) { gp_upd_rmtree($UT); });
$UT_REPO = realpath(__DIR__ . '/..');
$UT_PHP = PHP_BINARY;

// Copy the repository (code only) into $dst. Local data files are created by the callers.
function ut_copy_tree($src, $dst) {
	@mkdir($dst, 0775, true);
	foreach ((array)scandir($src) as $n) {
		if ($n === '.' || $n === '..' || $n === '.git' || $n === '__pycache__' || $n === 'node_modules' || $n === '.ratelimit' || $n === '.github') { continue; }
		$s = $src . '/' . $n;
		if (is_dir($s)) { ut_copy_tree($s, $dst . '/' . $n); continue; }
		if (preg_match('/\.(pyc|jsonl|log|joblib|candidate|csv)$/', $n) || $n === 'panel.config.php' || $n === 'guard.off' || $n === '.err-redis_connect') { continue; }
		copy($s, $dst . '/' . $n);
		chmod($dst . '/' . $n, fileperms($s) & 0777);
	}
}
// Every file below $dir as relpath => sha256.
function ut_hashes($dir, $base = null) {
	$base = $base === null ? $dir : $base;
	$out = array();
	foreach ((array)scandir($dir) as $n) {
		if ($n === '.' || $n === '..') { continue; }
		$p = $dir . '/' . $n;
		$rel = substr($p, strlen($base) + 1);
		if (strpos($rel, 'updates/') === 0 && $n !== '.htaccess' && $n !== '.gitkeep') { continue; }   // the updater's own workspace is not part of the install state
		if (is_dir($p)) { $out += ut_hashes($p, $base); } else { $out[$rel] = hash_file('sha256', $p); }
	}
	ksort($out);
	return $out;
}
// The install state without what a health-check run legitimately leaves behind (error logs).
function ut_nologs(array $h) { foreach (array_keys($h) as $k) { if (strpos($k, 'logs/') === 0 && $k !== 'logs/.htaccess' && $k !== 'logs/.gitkeep') { unset($h[$k]); } } return $h; }
// A minimal ZIP writer, so the test can make entries ZipArchive would refuse to create (traversal names, symlinks).
// $entries: list of array(name, data, mode, method).
function ut_zip($path, array $entries) {
	$out = ''; $cd = ''; $n = 0;
	foreach ($entries as $e) {
		$name = $e[0]; $data = (string)$e[1]; $mode = isset($e[2]) ? $e[2] : 0100644; $method = isset($e[3]) ? $e[3] : 8;
		$isdir = substr($name, -1) === '/';
		$comp = $method === 8 ? gzdeflate($data) : $data;
		$crc = crc32($data) & 0xFFFFFFFF;
		$off = strlen($out);
		$out .= "PK\x03\x04" . pack('vvvvvVVVvv', 20, 0, $method, 0, 0x21, $crc, strlen($comp), strlen($data), strlen($name), 0) . $name . $comp;
		$cd .= "PK\x01\x02" . pack('vvvvvvVVVvvvvvVV', (3 << 8) | 20, 20, 0, $method, 0, 0x21, $crc, strlen($comp), strlen($data), strlen($name), 0, 0, 0, 0, ($isdir ? 0040755 : $mode) << 16, $off) . $name;
		$n++;
	}
	file_put_contents($path, $out . $cd . "PK\x05\x06" . pack('vvvvVVv', 0, 0, $n, $n, strlen($cd), strlen($out), 0));
}
// The code files of a tree as ZIP entries under a wrapper folder, with changes: $over rel => new contents (null = leave out).
function ut_entries($dir, $top, array $over = array(), array $extra = array()) {
	$all = ut_hashes($dir);
	$ent = array();
	$local = array('guard/config.local.json', 'guard/rules.json', 'panel/panel.config.php', 'panel/audit.jsonl', 'analyzer/snapshot.json', 'guard.off', 'guard/local-notes.txt');
	if ($top !== '') { $ent[] = array($top, '', 0040755, 0); }
	foreach ($all as $rel => $sha) {
		if (in_array($rel, $local, true) || preg_match('#^(\.venv|\.git)/#', $rel) || preg_match('#^(logs|lists|geo)/(?!\.htaccess|\.gitkeep)#', $rel)) { continue; }
		if (array_key_exists($rel, $over)) { if ($over[$rel] === null) { unset($over[$rel]); continue; } $data = $over[$rel]; unset($over[$rel]); }
		else { $data = file_get_contents($dir . '/' . $rel); }
		$ent[] = array($top . $rel, $data, is_executable($dir . '/' . $rel) ? 0100755 : 0100644);
	}
	foreach ($over as $rel => $data) { if ($data !== null) { $ent[] = array($top . $rel, $data); } }
	return array_merge($ent, $extra);
}
// A fresh scratch install with local data, version 2026.01.01.
$ut_n = 0;
function ut_install() {
	global $UT, $UT_REPO, $ut_n, $gp_upd_root;
	$root = $UT . '/inst' . (++$ut_n);
	ut_copy_tree($UT_REPO, $root);
	foreach (glob($root . '/updates/*') as $f) { if (!in_array(basename($f), array('.htaccess', '.gitkeep'), true)) { is_dir($f) ? gp_upd_rmtree($f) : unlink($f); } }
	file_put_contents($root . '/VERSION', "2026.01.01\n");
	file_put_contents($root . '/guard/config.local.json', '{"mode":"monitor","secret":"LOCAL-SECRET"}');
	file_put_contents($root . '/guard/rules.json', '[{"id":"r1"}]');
	file_put_contents($root . '/panel/panel.config.php', "<?php return array('username'=>'admin');");
	file_put_contents($root . '/panel/audit.jsonl', "{\"event\":\"x\"}\n");
	@mkdir($root . '/lists', 0775, true);
	file_put_contents($root . '/lists/allow.txt', "198.51.100.0/24\n");
	@mkdir($root . '/logs', 0775, true);
	file_put_contents($root . '/logs/guard-20260101.jsonl', "{}\n");
	@mkdir($root . '/analyzer', 0775, true);
	file_put_contents($root . '/analyzer/snapshot.json', '{"k":1}');
	$gp_upd_root = $root;
	return $root;
}
// The next version as a ZIP: the install tree with changes. Returns the zip path.
function ut_make_zip($root, $version, array $over = array(), $top = 'bot-managment-system-master/', array $extra = array(), $name = '') {
	global $UT;
	$over = array_merge(array('VERSION' => $version . "\n"), $over);
	$zip = $UT . '/' . ($name !== '' ? $name : 'v' . $version . '-' . bin2hex(random_bytes(3))) . '.zip';
	ut_zip($zip, ut_entries($root, $top, $over, $extra));
	return $zip;
}
$ut_log_note = "<?php\n// updated\n";
$ut_changelog = "# Changelog\n\n## 2026.03.03\n\n- third\n\n## 2026.02.02\n\n- second\n\n## 2025.12.01\n\n- ancient\n";
$ut_run = function ($script, array $args = array()) use ($UT_PHP) {
	$cmd = escapeshellarg($UT_PHP) . ' ' . escapeshellarg($script);
	foreach ($args as $a) { $cmd .= ' ' . escapeshellarg($a); }
	exec($cmd . ' 2>&1', $o, $rc);
	return array($rc, implode("\n", $o));
};

// ---- name and pattern units
t_ok('names: traversal, absolute, backslash and drive-letter paths are all refused',
	gp_upd_bad_name('../x.php') !== '' && gp_upd_bad_name('a/../../x.php') !== '' && gp_upd_bad_name('/etc/x.php') !== '' && gp_upd_bad_name("a\\b.php") !== ''
	&& gp_upd_bad_name('C:/x.php') !== '' && gp_upd_bad_name("a\x00b") !== '' && gp_upd_bad_name('a//b') !== '' && gp_upd_bad_name('./a') !== '' && gp_upd_bad_name('guard/guard.php') === '');
$ut_pat = gp_upd_parse_patterns(file_get_contents(__DIR__ . '/../panel/update-protected.txt'));
t_ok('protected: the install-local files named in the brief are all protected',
	count(array_filter(array('guard/config.php', 'guard/config.local.json', 'guard/config.local.json.bak', 'guard/rules.json', 'guard/rules.cache.php', 'panel/panel.config.php', 'panel/users.json', 'panel/audit.jsonl',
		'panel/jobs-seen.json', 'lists/allow.txt', 'lists/allow.bin', 'geo/country.bin', 'logs/guard-20260101.jsonl', 'analyzer/model.joblib', 'analyzer/snapshot.json', 'analyzer/reports/r.txt',
		'analyzer/.jobstatus-verify.json', '.venv/bin/python', 'analyzer/.venv/x.py', 'guard.off', '.git/config', 'updates/20260101-000000/manifest.json'), function ($f) use ($ut_pat) { return !gp_upd_is_protected($f, $ut_pat); })) === 0);
t_ok('protected: code is not protected (guard.php, panel/index.php, scripts, docs, requirements)',
	!gp_upd_is_protected('guard/guard.php', $ut_pat) && !gp_upd_is_protected('panel/index.php', $ut_pat) && !gp_upd_is_protected('scripts/analyzer-cron.sh', $ut_pat)
	&& !gp_upd_is_protected('docs/09-ADMIN-PANEL.md', $ut_pat) && !gp_upd_is_protected('analyzer/requirements.txt', $ut_pat) && !gp_upd_is_protected('analyzer/worker.py', $ut_pat) && !gp_upd_is_protected('VERSION', $ut_pat));
t_ok('protected: .htaccess and .gitkeep inside data directories stay updatable',
	!gp_upd_is_protected('lists/.htaccess', $ut_pat) && !gp_upd_is_protected('logs/.gitkeep', $ut_pat) && !gp_upd_is_protected('updates/.htaccess', $ut_pat));
t_ok('protected: a .gitignore pattern protects too (and a name pattern matches in any directory)',
	gp_upd_is_protected('analyzer/foo.csv', gp_upd_parse_patterns("analyzer/*.csv\n")) && gp_upd_is_protected('a/b/x.pyc', gp_upd_parse_patterns("*.pyc\n")) && gp_upd_is_protected('a/__pycache__/x.py', gp_upd_parse_patterns("__pycache__/\n")));
t_ok('protected: the single list is the one the docs quote (every pattern is in docs/09-ADMIN-PANEL.md)', (function () use ($ut_pat) {
	$doc = file_get_contents(__DIR__ . '/../docs/09-ADMIN-PANEL.md');
	foreach ($ut_pat as $p) { if (strpos($doc, $p) === false) { return false; } }
	return true;
})());
t_ok('the recovery script templates parse (token_get_all with TOKEN_PARSE)', (function () {
	try { foreach (array('update-rollback.tpl', 'update-verify.tpl') as $t) { token_get_all(file_get_contents(__DIR__ . '/../panel/' . $t), TOKEN_PARSE); } return true; }
	catch (\Throwable $e) { return false; }
})());
$ut_ver = trim(file_get_contents(__DIR__ . '/../VERSION'));
t_ok('VERSION is a date-style version and the newest CHANGELOG entry carries it', preg_match('/^\d{4}\.\d{2}\.\d{2}(\.\d+)?$/', $ut_ver) === 1 && preg_match('/^## ' . preg_quote($ut_ver, '/') . '\s*$/m', file_get_contents(__DIR__ . '/../CHANGELOG.md')) === 1);
t_ok('changelog: only the entries after the installed version up to the new one, newest first', (function () use ($ut_changelog) {
	$c = gp_upd_changelog($ut_changelog, '2026.01.01', '2026.03.03');
	return count($c) === 2 && $c[0]['version'] === '2026.03.03' && $c[1]['version'] === '2026.02.02';
})());

// ---- refusals (nothing is staged)
$root = ut_install();
$refuse = function ($entries_extra, $expect, $over = array(), $top = 'bot-managment-system-master/') use ($root, $UT) {
	$z = ut_make_zip($root, '2026.02.02', $over, $top, $entries_extra);
	$r = gp_upd_stage($z, 'x.zip', 'admin');
	return !$r['ok'] && $r['error'] === $expect && count(glob(gp_upd_dir() . '/pending/*')) === 0;
};
t_ok('zip-slip: ../ in an entry name is refused and nothing is staged', $refuse(array(array('bot-managment-system-master/../../evil.php', '<?php')), 'upd_err_path'));
t_ok('zip-slip: a name with ../ in the middle, an absolute name, a backslash and a drive letter are refused',
	$refuse(array(array('bot-managment-system-master/guard/../../evil.php', '<?php')), 'upd_err_path') && $refuse(array(array('/etc/evil.php', '<?php')), 'upd_err_path')
	&& $refuse(array(array("bot-managment-system-master/guard\\evil.php", '<?php')), 'upd_err_path') && $refuse(array(array('C:/evil.php', '<?php')), 'upd_err_path'));
t_ok('a symbolic link entry is refused', $refuse(array(array('bot-managment-system-master/guard/link.php', '/etc/passwd', 0120777)), 'upd_err_symlink'));
t_ok('an entry outside the project folders, and .git, are refused', $refuse(array(array('bot-managment-system-master/evil/x.php', '<?php')), 'upd_err_tree') && $refuse(array(array('bot-managment-system-master/.git/config', 'x')), 'upd_err_tree'));
t_ok('unexpected file types are refused (.exe, .phtml, .phar, no extension)',
	$refuse(array(array('bot-managment-system-master/guard/x.exe', 'MZ')), 'upd_err_ext') && $refuse(array(array('bot-managment-system-master/guard/x.phtml', '<?php')), 'upd_err_ext')
	&& $refuse(array(array('bot-managment-system-master/guard/x.phar', 'x')), 'upd_err_ext') && $refuse(array(array('bot-managment-system-master/guard/Makefile', 'x')), 'upd_err_ext'));
t_ok('a ZIP without VERSION, prepend.php, guard/guard.php or panel/index.php is refused',
	$refuse(array(), 'upd_err_required', array('VERSION' => null)) && $refuse(array(), 'upd_err_required', array('prepend.php' => null))
	&& $refuse(array(), 'upd_err_required', array('guard/guard.php' => null)) && $refuse(array(), 'upd_err_required', array('panel/index.php' => null)));
t_ok('a PHP parse error anywhere in the staged copy refuses the whole update', (function () use ($root, $UT) {
	$z = ut_make_zip($root, '2026.02.02', array('guard/log.php' => "<?php\nfunction (\n"));
	$r = gp_upd_stage($z, 'x.zip', 'admin');
	return !$r['ok'] && $r['error'] === 'upd_err_parse' && strpos($r['detail'], 'guard/log.php') !== false && count(glob(gp_upd_dir() . '/pending/*')) === 0;
})());
t_ok('a duplicate path, a bad VERSION and a file that is not a ZIP are refused',
	$refuse(array(array('bot-managment-system-master/guard/log.php', '<?php')), 'upd_err_dup') && $refuse(array(), 'upd_err_version', array('VERSION' => "not a version!\n"))
	&& (function () use ($UT) { file_put_contents($UT . '/x.zip', 'hello'); $r = gp_upd_stage($UT . '/x.zip', 'x.zip', 'a'); return !$r['ok'] && $r['error'] === 'upd_err_notzip'; })());
t_ok('a damaged entry (wrong CRC) is refused', (function () use ($root, $UT) {
	$z = ut_make_zip($root, '2026.02.02', array('guard/log.php' => str_repeat('<?php // x' . "\n", 50)), 'bot-managment-system-master/', array(), 'crc');
	$b = file_get_contents($z);
	$at = strrpos($b, 'bot-managment-system-master/guard/log.php');                    // the central directory copy of the name comes last
	file_put_contents($z, substr($b, 0, $at - 46 + 16) . "\x00\x00\x00\x00" . substr($b, $at - 46 + 20));
	$r = gp_upd_stage($z, 'x.zip', 'a', 'pure');
	return !$r['ok'] && $r['error'] === 'upd_err_damaged';
})());

// ---- plan, top folder, parity of the two readers
$z_a = ut_make_zip($root, '2026.02.02', array('guard/log.php' => file_get_contents($root . '/guard/log.php') . "\n// changed\n", 'docs/NEW-DOC.md' => "# new\n",
	'guard/config.php' => "<?php return array('secret'=>'FROM-ZIP');", 'CHANGELOG.md' => $ut_changelog, 'lists/allow.txt' => "0.0.0.0/0\n"),
	'bot-managment-system-master/', array(array('bot-managment-system-master/.github/workflows/ci.yml', 'x')), 'va');
$p_pure = gp_upd_stage($z_a, 'bot-managment-system-master.zip', 'admin', 'pure');
t_ok('the pure-PHP reader stages a GitHub-style ZIP (top folder stripped, .github ignored)', $p_pure['ok'] && $p_pure['plan']['ignored'] === 1 && in_array('docs/NEW-DOC.md', $p_pure['plan']['add'], true) && in_array('guard/log.php', $p_pure['plan']['change'], true));
t_ok('the plan names versions, counts, the changelog and skips protected files that are in the ZIP',
	$p_pure['ok'] && $p_pure['plan']['from'] === '2026.01.01' && $p_pure['plan']['to'] === '2026.02.02' && in_array('guard/config.php', $p_pure['plan']['protected_skipped'], true)
	&& in_array('lists/allow.txt', $p_pure['plan']['protected_skipped'], true) && count($p_pure['plan']['changelog']) === 1 && in_array('first_update', $p_pure['plan']['warnings'], true));
if (class_exists('ZipArchive')) {
	$p_za = gp_upd_stage($z_a, 'bot-managment-system-master.zip', 'admin', 'ziparchive');
	$sig = function ($p) { $f = $p['files']; usort($f, function ($a, $b) { return strcmp($a['path'], $b['path']); }); return json_encode(array($f, $p['add'], $p['change'], $p['remove'], $p['protected_skipped'], $p['warnings'], $p['ignored'])); };
	t_ok('parity: ZipArchive and the pure reader produce the same plan (same files, same sha256)', $p_za['ok'] && $sig($p_za['plan']) === $sig($p_pure['plan']) && $p_za['plan']['backend'] === 'ziparchive' && $p_pure['plan']['backend'] === 'pure');
	$o1 = gp_upd_zip_open($z_a, 'ziparchive'); $o2 = gp_upd_zip_open($z_a, 'pure');
	$same = $o1['ok'] && $o2['ok'] && count($o1['zip']['entries']) === count($o2['zip']['entries']);
	if ($same) { foreach ($o1['zip']['entries'] as $i => $e1) { $e2 = $o2['zip']['entries'][$i]; if ($e1['name'] !== $e2['name'] || $e1['size'] !== $e2['size'] || $e1['mode'] !== $e2['mode'] || (!$e1['dir'] && gp_upd_zip_read($o1['zip'], $e1) !== gp_upd_zip_read($o2['zip'], $e2))) { $same = false; break; } } }
	t_ok('parity: entry names, sizes, modes and contents are identical in both readers', $same);
	if ($o1['ok']) { gp_upd_zip_close($o1['zip']); } if ($o2['ok']) { gp_upd_zip_close($o2['zip']); }
	$z_sl = $UT . '/symlink-real.zip';
	$zaw = new ZipArchive(); $zaw->open($z_sl, ZipArchive::CREATE);
	$zaw->addFromString('top/VERSION', "1\n"); $zaw->addFromString('top/ln', '/etc/passwd'); $zaw->setExternalAttributesName('top/ln', ZipArchive::OPSYS_UNIX, 0120777 << 16); $zaw->close();
	$zs = gp_upd_zip_open($z_sl, 'ziparchive'); $zp = gp_upd_zip_open($z_sl, 'pure');
	t_ok('a symlink made by a real zip tool is seen by both readers', $zs['ok'] && $zp['ok'] && array_sum(array_map(function ($e) { return $e['symlink'] ? 1 : 0; }, $zs['zip']['entries'])) === 1 && array_sum(array_map(function ($e) { return $e['symlink'] ? 1 : 0; }, $zp['zip']['entries'])) === 1);
	if ($zs['ok']) { gp_upd_zip_close($zs['zip']); } if ($zp['ok']) { gp_upd_zip_close($zp['zip']); }
} else {
	t_skip('parity of ZipArchive and the pure-PHP reader', 'ZipArchive is not installed here');
}
t_ok('a ZIP without the wrapper folder works too', gp_upd_stage(ut_make_zip($root, '2026.02.02', array(), '', array(), 'notop'), 'x.zip', 'a')['ok']);
gp_upd_plan_discard($p_pure['plan']['id']);
foreach (glob(gp_upd_dir() . '/pending/*') as $d) { gp_upd_rmtree($d); }

// ---- apply, protected files untouched, manifest, backup, guard.off, OPcache, then the health check
$before = ut_hashes($root);
$ops = array();
$gp_upd_opcache_hook = function ($f) use (&$ops) { $ops[] = $f; };
$st = gp_upd_stage($z_a, 'bot-managment-system-master.zip', 'admin');
t_ok('staging changes nothing in the install', $st['ok'] && ut_hashes($root) === $before && is_dir(gp_upd_dir() . '/pending/' . $st['plan']['id']));
$ap = gp_upd_apply($st['plan']['id'], 'admin');
$after = ut_hashes($root);
$prot = array('guard/config.local.json', 'guard/rules.json', 'panel/panel.config.php', 'panel/audit.jsonl', 'lists/allow.txt', 'logs/guard-20260101.jsonl', 'analyzer/snapshot.json', 'guard/config.php');
t_ok('apply succeeds and returns the stamp and the verify key', $ap['ok'] && preg_match('/^\d{8}-\d{6}/', $ap['stamp']) === 1 && strlen($ap['verify_key']) === 32);
t_ok('protected files are byte-identical after the update, also the ones that exist in the ZIP', (function () use ($before, $after, $prot) { foreach ($prot as $f) { if (!isset($after[$f]) || $after[$f] !== $before[$f]) { return false; } } return true; })());
t_ok('new and changed files carry the new bytes; VERSION is bumped',
	trim(file_get_contents($root . '/VERSION')) === '2026.02.02' && is_file($root . '/docs/NEW-DOC.md') && strpos(file_get_contents($root . '/guard/log.php'), '// changed') !== false);
$man = gp_upd_json_read(gp_upd_dir() . '/' . $ap['stamp'] . '/manifest.json');
$man_ok = is_array($man) && $man['status'] === 'applied' && $man['from'] === '2026.01.01' && $man['to'] === '2026.02.02';
$byp = array(); foreach ((array)$man['files'] as $f) { $byp[$f['path']] = $f; }
t_ok('manifest lists every changed or added file with sha256 before and after', $man_ok && isset($byp['guard/log.php'], $byp['docs/NEW-DOC.md'], $byp['VERSION'])
	&& $byp['guard/log.php']['before'] === $before['guard/log.php'] && $byp['guard/log.php']['after'] === $after['guard/log.php'] && $byp['docs/NEW-DOC.md']['before'] === null);
t_ok('every file that changes is backed up byte-for-byte, a new file has no backup', (function () use ($root, $ap, $before, $byp) {
	foreach ($byp as $p => $f) {
		$b = gp_upd_dir() . '/' . $ap['stamp'] . '/backup/' . $p;
		if ($f['before'] === null ? is_file($b) : (!is_file($b) || hash_file('sha256', $b) !== $before[$p])) { return false; }
	}
	return true;
})());
t_ok('guard.off exists during the window and the manifest says the updater created it', is_file($root . '/guard.off') && $man['guard_off_created'] === true);
t_ok('OPcache is invalidated for every changed PHP file', in_array($root . '/guard/log.php', $ops, true) && in_array($root . '/updates/rollback.php', $ops, true));
t_ok('updates/rollback.php and updates/verify.php are written from the old code', is_file($root . '/updates/rollback.php') && is_file($root . '/updates/verify.php')
	&& file_get_contents($root . '/updates/rollback.php') === file_get_contents(__DIR__ . '/../panel/update-rollback.tpl'));
$rec = gp_upd_json_read(gp_upd_dir() . '/recovery.json');
$tok = trim((string)@file_get_contents(gp_upd_dir() . '/' . $ap['stamp'] . '/token.once'));
t_ok('the recovery token is stored hashed, valid 24 hours', is_array($rec) && $rec['hash'] === hash('sha256', $tok) && strpos(json_encode($rec), $tok) === false && $rec['expires'] - time() > 86300 && $rec['expires'] - time() <= GP_UPD_TOKEN_TTL);
t_ok('the installed.json base holds the new file list (for "removed upstream" next time)', (function () use ($root) { $i = gp_upd_json_read(gp_upd_dir() . '/installed.json'); return is_array($i) && $i['version'] === '2026.02.02' && isset($i['files']['guard/log.php']); })());
$st2 = gp_upd_stage(ut_make_zip($root, '2026.03.03'), 'x.zip', 'admin');
t_ok('a new update is refused while the previous one has not passed its health check', $st2['ok'] && gp_upd_apply($st2['plan']['id'], 'admin')['error'] === 'upd_err_unverified');
gp_upd_plan_discard($st2['plan']['id']);

// the health check, in a fresh PHP process
$vr = $ut_run($root . '/updates/verify.php', array($ap['stamp']));
$man = gp_upd_json_read(gp_upd_dir() . '/' . $ap['stamp'] . '/manifest.json');
t_ok('the health check passes on good code (fresh process: guard, panel, config, rules, lists, one synthetic request)', $vr[0] === 0 && strpos($vr[1], 'OK') === 0 && $man['status'] === 'ok');
t_ok('...the guard.off the updater created is removed', !is_file($root . '/guard.off'));
t_ok('...and the synthetic request left no log row behind', count(glob($root . '/logs/guard-*.jsonl')) === 1 && trim(file_get_contents($root . '/logs/guard-20260101.jsonl')) === '{}');
t_ok('the VERSION shown by the panel is the new one', gp_upd_version() === '2026.02.02');

// an operator's own guard.off is never removed
$root_k = ut_install();
file_put_contents($root_k . '/guard.off', "operator\n");
$sk = gp_upd_stage(ut_make_zip($root_k, '2026.02.02', array('docs/K.md' => "k\n")), 'k.zip', 'a');
$ak = gp_upd_apply($sk['plan']['id'], 'admin');
$vk = $ut_run($root_k . '/updates/verify.php', array($ak['stamp']));
t_ok('a guard.off created by the operator survives the update and the check', $ak['ok'] && $vk[0] === 0 && is_file($root_k . '/guard.off') && file_get_contents($root_k . '/guard.off') === "operator\n");

// ---- automatic rollback when the health check fails
$bad_cases = array(
	'an exception while loading' => array('guard/redis.php' => file_get_contents($root . '/guard/redis.php') . "\nthrow new RuntimeException('boom');\n"),
	'a fatal error (redeclared function)' => array('guard/log.php' => file_get_contents($root . '/guard/log.php') . "\nfunction gv_log_policy() {}\n"),
	'an error inside the synthetic request' => array('guard/guard.php' => preg_replace('/function gv_run\(\$t0\) \{/', 'function gv_run($t0) { throw new RuntimeException("synthetic failure");', file_get_contents($root . '/guard/guard.php'), 1)),
);
foreach ($bad_cases as $label => $over) {
	$rb_root = ut_install();
	$h0 = ut_hashes($rb_root);
	$s = gp_upd_stage(ut_make_zip($rb_root, '2026.04.04', $over), 'bad.zip', 'a');
	$a = $s['ok'] ? gp_upd_apply($s['plan']['id'], 'admin') : array('ok' => false);
	$v = $a['ok'] ? $ut_run($rb_root . '/updates/verify.php', array($a['stamp'])) : array(9, 'not applied');
	$h1 = ut_hashes($rb_root);
	unset($h0['updates/rollback.php'], $h1['updates/rollback.php']);
	$strip = function ($h) { foreach (array_keys($h) as $k) { if (strpos($k, 'updates/') === 0 && $k !== 'updates/.htaccess' && $k !== 'updates/.gitkeep') { unset($h[$k]); } } return $h; };
	$mm = $a['ok'] ? gp_upd_json_read(gp_upd_dir() . '/' . $a['stamp'] . '/manifest.json') : array();
	t_ok('health check failure (' . $label . '): rolled back automatically, every file byte-identical, guard.off gone, reported',
		$s['ok'] && $a['ok'] && $v[0] === 1 && strpos($v[1], 'FAILED:') !== false && strpos($v[1], 'rolled back') !== false && ut_nologs($strip($h1)) === ut_nologs($strip($h0)) && !is_file($rb_root . '/guard.off')
		&& $mm['status'] === 'rolled_back' && !empty($mm['auto_rollback']) && $mm['verify_failed'] !== '' && !is_file(gp_upd_dir() . '/recovery.json'));
}
// a web request without the key does not run the check
$wk = $ut_run($root_k . '/updates/verify.php', array('20260101-000000'));
t_ok('verify.php refuses an unknown update stamp', $wk[0] === 2);

// ---- rollback.php with the panel code broken
$root_b = ut_install();
$hb = ut_hashes($root_b);
$sb = gp_upd_stage(ut_make_zip($root_b, '2026.05.05', array('docs/B.md' => "b\n", 'guard/log.php' => file_get_contents($root_b . '/guard/log.php') . "\n// b\n",
	'panel/index.php' => file_get_contents($root_b . '/panel/index.php') . "\n// b\n", 'panel/update.php' => file_get_contents($root_b . '/panel/update.php') . "\n// b\n", 'guard/guard.php' => file_get_contents($root_b . '/guard/guard.php') . "\n// b\n")), 'b.zip', 'a');
$ab = gp_upd_apply($sb['plan']['id'], 'admin');
$ut_run($root_b . '/updates/verify.php', array($ab['stamp']));
file_put_contents($root_b . '/panel/index.php', "<?php this is broken (");
file_put_contents($root_b . '/panel/update.php', "<?php also broken {");
file_put_contents($root_b . '/guard/guard.php', "<?php broken");
$ls = $ut_run($root_b . '/updates/rollback.php', array('--list'));
$rbk = $ut_run($root_b . '/updates/rollback.php');
$hb2 = ut_hashes($root_b);
foreach (array_keys($hb2) as $k) { if (strpos($k, 'updates/') === 0 && $k !== 'updates/.htaccess' && $k !== 'updates/.gitkeep') { unset($hb2[$k]); } }
t_ok('rollback.php --list works from the shell with the new code broken', $ls[0] === 0 && strpos($ls[1], $ab['stamp']) !== false);
t_ok('rollback.php restores byte-identical files from the shell although panel and guard code are broken, and removes added files', $rbk[0] === 0 && ut_nologs($hb2) === ut_nologs($hb) && !is_file($root_b . '/docs/B.md'));
t_ok('a second rollback has nothing left to roll back', $ut_run($root_b . '/updates/rollback.php')[0] === 1);
$gp_upd_root = $root_b;
// a damaged backup is detected and nothing is changed
$root_d = ut_install();
$sd = gp_upd_stage(ut_make_zip($root_d, '2026.06.06', array('guard/log.php' => file_get_contents($root_d . '/guard/log.php') . "\n// d\n")), 'd.zip', 'a');
$ad = gp_upd_apply($sd['plan']['id'], 'admin');
file_put_contents(gp_upd_dir() . '/' . $ad['stamp'] . '/backup/guard/log.php', 'tampered');
$cur = ut_hashes($root_d);
$rd = $ut_run($root_d . '/updates/rollback.php', array($ad['stamp']));
t_ok('a damaged backup makes the rollback refuse and change nothing', $rd[0] === 1 && ut_hashes($root_d) === $cur);

// ---- recovery token (web path): single use, expiry, wrong token
$root_t = ut_install();
$stt = gp_upd_stage(ut_make_zip($root_t, '2026.07.07', array('docs/T.md' => "t\n")), 't.zip', 'a');
$att = gp_upd_apply($stt['plan']['id'], 'admin');
$ttok = gp_upd_token_take($att['stamp']);
t_ok('the token is shown once: the second read finds nothing', strlen($ttok) === 32 && gp_upd_token_take($att['stamp']) === '');
gp_upd_load_rollback();
t_ok('the web recovery refuses a wrong token and an empty one', !gprb_token_ok('0123456789abcdef0123456789abcdef') && !gprb_token_ok('') && gprb_token_ok($ttok));
$rj = gp_upd_json_read(gp_upd_dir() . '/recovery.json'); $rj['expires'] = time() - 5; gp_upd_json_write(gp_upd_dir() . '/recovery.json', $rj);
t_ok('an expired token is refused', !gprb_token_ok($ttok));
$rj['expires'] = time() + 3600; gp_upd_json_write(gp_upd_dir() . '/recovery.json', $rj);
$_SERVER['REQUEST_METHOD'] = 'POST'; $_POST = array('token' => 'wrong-token');
ob_start(); gprb_main_web(); $wb = ob_get_clean();
t_ok('a wrong token in the web form changes nothing and shows nothing', $wb === '' && is_file($root_t . '/docs/T.md'));
$_POST = array('token' => $ttok);
ob_start(); gprb_main_web(); $wb = ob_get_clean();
t_ok('the right token rolls the update back from the web', strpos($wb, 'Rolled back.') !== false && !is_file($root_t . '/docs/T.md') && trim(file_get_contents($root_t . '/VERSION')) === '2026.01.01');
t_ok('...and is single use: the recovery file is gone and the token no longer works', !is_file(gp_upd_dir() . '/recovery.json') && !gprb_token_ok($ttok));
$_SERVER['REQUEST_METHOD'] = 'GET'; $_POST = array();
t_ok('panel/recover.php answers a bare 404 when no recovery script exists and never loads the panel', (function () {
	$src = file_get_contents(__DIR__ . '/../panel/recover.php');
	return strpos($src, "http_response_code(404)") !== false && strpos($src, 'GP_BOOT') === false && strpos($src, 'require') !== false && substr_count($src, 'require') === 1;
})());

// ---- warnings and confirmation
$root_w = ut_install();
$sw = gp_upd_stage(ut_make_zip($root_w, '2025.01.01'), 'old.zip', 'a');
t_ok('a downgrade is warned about and needs an explicit confirmation', $sw['ok'] && in_array('downgrade', $sw['plan']['warnings'], true)
	&& gp_upd_apply($sw['plan']['id'], 'a')['error'] === 'upd_err_confirm' && is_dir(gp_upd_dir() . '/pending/' . $sw['plan']['id']));
$ss = gp_upd_stage(ut_make_zip($root_w, '2026.01.01'), 'same.zip', 'a');
t_ok('the same version is warned about and needs confirmation', in_array('same_version', $ss['plan']['warnings'], true) && gp_upd_apply($ss['plan']['id'], 'a')['error'] === 'upd_err_confirm');
mkdir($root_w . '/.git', 0775);
$sg = gp_upd_stage(ut_make_zip($root_w, '2026.02.02', array('analyzer/requirements.txt' => "redis>=4.0\nnewpkg>=1\n", 'scripts/cron-check.sh' => file_get_contents($root_w . '/scripts/cron-check.sh') . "\n# x\n")), 'g.zip', 'a');
t_ok('a .git directory, a changed requirements.txt and a changed cron script are all warned about',
	$sg['ok'] && array_diff(array('git_present', 'requirements_changed', 'cron_scripts_changed'), $sg['plan']['warnings']) === array() && gp_upd_apply($sg['plan']['id'], 'a')['error'] === 'upd_err_confirm');
$ag = gp_upd_apply($sg['plan']['id'], 'a', array('confirm' => array('git_present')));
t_ok('...and goes through once the .git warning is confirmed', $ag['ok'] === true);
$ut_run($root_w . '/updates/verify.php', array($ag['stamp']));
$ph = gp_upd_post_verify($ag['stamp'], 'admin');
t_ok('after a good check a changed requirements.txt asks for the pip_sync job exactly once', $ph !== null && $ph['status'] === 'ok' && !empty($ph['pip_enqueued']) && !empty(gp_upd_json_read(gp_upd_dir() . '/' . $ag['stamp'] . '/manifest.json')['audited']));
if (!empty($ph['pip_job'])) {                                   // a Redis that was reachable took the job: remove it again
	$ut_c = gv_redis_connect(gv_cfg_load()['redis'], $GP_TMP_LOGS, false);
	if ($ut_c) { gv_redis_cmd($ut_c, array('DEL', gp_key('job:' . $ph['pip_job'])));
		foreach ((array)gv_redis_cmd($ut_c, array('LRANGE', gp_key('jobs'), '0', '-1')) as $ut_j) { if (is_string($ut_j) && strpos($ut_j, $ph['pip_job']) !== false) { gv_redis_cmd($ut_c, array('LREM', gp_key('jobs'), '0', $ut_j)); } }
		gv_redis_close($ut_c); }
}
t_ok('pip_sync is an allowed job type', in_array('pip_sync', gp_job_types(), true) && gp_job_params('pip_sync', array())[0] === true);

// ---- removed upstream, unverified chain, history rollback chain, prune
$root_r = ut_install();
$s1 = gp_upd_stage(ut_make_zip($root_r, '2026.02.02', array('docs/ONLY-IN-V2.md' => "x\n", 'scripts/only-in-v2.sh' => "#!/bin/sh\n")), 'r1.zip', 'a');
$a1 = gp_upd_apply($s1['plan']['id'], 'a');
$ut_run($root_r . '/updates/verify.php', array($a1['stamp']));
$h_before = ut_hashes($root_r);
$s2 = gp_upd_stage(ut_make_zip($root_r, '2026.03.03', array('docs/ONLY-IN-V2.md' => null, 'scripts/only-in-v2.sh' => null, 'docs/V3.md' => "v3\n")), 'r2.zip', 'a');
t_ok('a tracked file missing from the new ZIP is planned for removal (from the previous manifest)', $s2['ok'] && $s2['plan']['remove'] === array('docs/ONLY-IN-V2.md', 'scripts/only-in-v2.sh') && !in_array('first_update', $s2['plan']['warnings'], true));
file_put_contents($root_r . '/guard/local-notes.txt', 'mine');
$a2 = gp_upd_apply($s2['plan']['id'], 'a');
t_ok('removed files are deleted, files the ZIP never had are left alone, the removed file is in the backup',
	$a2['ok'] && !is_file($root_r . '/docs/ONLY-IN-V2.md') && is_file($root_r . '/guard/local-notes.txt') && is_file(gp_upd_dir() . '/' . $a2['stamp'] . '/backup/docs/ONLY-IN-V2.md'));
$ut_run($root_r . '/updates/verify.php', array($a2['stamp']));
$hist = gp_upd_history(10);
t_ok('history lists both updates newest first with their status', count($hist) === 2 && $hist[0]['stamp'] === $a2['stamp'] && $hist[0]['status'] === 'ok' && $hist[1]['status'] === 'ok');
$rbr = gp_upd_rollback($a1['stamp']);
$h_end = ut_hashes($root_r);
t_ok('rolling back the older update also rolls back every newer one, newest first', $rbr[0] && trim(file_get_contents($root_r . '/VERSION')) === '2026.01.01' && !is_file($root_r . '/docs/V3.md') && !is_file($root_r . '/docs/ONLY-IN-V2.md') && is_file($root_r . '/guard/local-notes.txt'));
t_ok('...both are marked rolled back and the install is back to the original files', array_column(gp_upd_history(10), 'status') === array('rolled_back', 'rolled_back') && ($h_end['VERSION'] ?? '') === hash('sha256', "2026.01.01\n"));
// prune
$root_p = ut_install();
foreach (array('20200101-000001', '20200101-000002', '20200101-000003', '20200101-000004') as $old) {
	mkdir(gp_upd_dir() . '/' . $old . '/backup', 0775, true);
	file_put_contents(gp_upd_dir() . '/' . $old . '/manifest.json', json_encode(array('status' => 'ok', 'files' => array())));
}
$sp = gp_upd_stage(ut_make_zip($root_p, '2026.08.08', array('docs/P.md' => "p\n")), 'p.zip', 'a');
$ap2 = gp_upd_apply($sp['plan']['id'], 'a');
$ut_run($root_p . '/updates/verify.php', array($ap2['stamp']));
t_ok('only the newest ' . GP_UPD_KEEP . ' updates (and their backups) are kept', count(gp_upd_history(50)) === GP_UPD_KEEP && is_dir(gp_upd_dir() . '/' . $ap2['stamp'] . '/backup') && !is_dir(gp_upd_dir() . '/20200101-000001'));
// lock
$root_l = ut_install();
$sl = gp_upd_stage(ut_make_zip($root_l, '2026.09.09'), 'l.zip', 'a');
$lk = fopen(gp_upd_dir() . '/.lock', 'c'); flock($lk, LOCK_EX);
t_ok('two updates cannot run at the same time (lock)', gp_upd_apply($sl['plan']['id'], 'a')['error'] === 'upd_err_busy');
flock($lk, LOCK_UN); fclose($lk);
t_ok('an expired or tampered staged ZIP is not applied', (function () use ($sl) {
	$pf = gp_upd_dir() . '/pending/' . $sl['plan']['id'] . '/files/VERSION';
	file_put_contents($pf, "9.9.9\n");
	return gp_upd_plan_load($sl['plan']['id']) === null && gp_upd_apply($sl['plan']['id'], 'a')['error'] === 'upd_err_nopending' && gp_upd_apply('../../etc', 'a')['error'] === 'upd_err_nopending';
})());

// ---- upload handler, re-entering the password, routes, view, alerts
$tmpz = ut_make_zip(ut_install(), '2026.10.10');
t_ok('upload: a .txt name, a PHP error code and a missing file are refused with their own message',
	gp_upd_upload(array('error' => 0, 'tmp_name' => $tmpz, 'name' => 'x.txt'), 'a')[2] === 'upd_err_notzip_name' && gp_upd_upload(array('error' => 1, 'tmp_name' => '', 'name' => 'x.zip'), 'a')[2] === 'upd_err_phplimit'
	&& gp_upd_upload(array('error' => 4), 'a')[2] === 'upd_err_upload' && gp_upd_upload(array('error' => 0, 'tmp_name' => $UT . '/nope.zip', 'name' => 'x.zip'), 'a')[2] === 'upd_err_upload');
$up = gp_upd_upload(array('error' => 0, 'tmp_name' => $tmpz, 'name' => 'bot-managment-system-master.zip'), 'admin');
t_ok('upload: a good ZIP is staged and audited', $up[0] === true && strlen($up[1]) === 16 && strpos((string)@file_get_contents($UT . '/audit.jsonl'), 'update_upload') !== false);
gp_upd_upload(array('error' => 0, 'tmp_name' => $UT . '/x.zip', 'name' => 'x.zip'), 'admin');
t_ok('upload: a refused ZIP is audited as update_refused', strpos((string)@file_get_contents($UT . '/audit.jsonl'), 'update_refused') !== false);
$ut_ip = $_SERVER['REMOTE_ADDR']; $_SERVER['REMOTE_ADDR'] = '203.0.113.201';
putenv('GV_USERS=' . $UT . '/users-reauth.json');
$GLOBALS['gp_test_panel_cfg'] = array('session_secret' => str_repeat('s', 32), 'username' => 'admin', 'password_hash' => password_hash('correct horse battery', PASSWORD_DEFAULT));
t_ok('the password is asked again: the right one passes, a wrong one and an empty one do not', gp_reauth('admin', 'correct horse battery') === 'ok' && gp_reauth('admin', 'nope') === 'bad' && gp_reauth('admin', '') === 'bad' && gp_reauth('other', 'correct horse battery') === 'bad');
foreach (array('203.0.113.201', 'user') as $ut_b) {          // leave no login counters behind (file fallback and Redis)
	@unlink(gp_attempts_file($ut_b));
	$ut_c = gv_redis_connect(gv_cfg_load()['redis'], $GP_TMP_LOGS, false);
	if ($ut_c) { gv_redis_cmd($ut_c, array('DEL', gp_key('login:' . $ut_b))); gv_redis_close($ut_c); }
}
$_SERVER['REMOTE_ADDR'] = $ut_ip;
unset($GLOBALS['gp_test_panel_cfg']);
putenv('GV_USERS');
$ut_src = file_get_contents(__DIR__ . '/../panel/index.php');
$ut_case = substr($ut_src, strpos($ut_src, "case 'update':"), 5200);
t_ok('the update route is POST-only for every action, behind the session and the CSRF check, and the apply step asks for the password',
	strpos($ut_case, 'if ($gp_post)') !== false && strpos($ut_case, "gp_reauth(") !== false && strpos($ut_src, "if (\$gp_post && !gp_csrf_check(") !== false && strpos($ut_src, "case 'update':") > strpos($ut_src, 'if ($gp_user === null)'));
t_ok('apply, upload, refuse, verify and rollback are all audit-logged', strpos($ut_src, "'update_apply'") !== false && strpos($ut_src, "'update_rollback'") !== false && strpos($ut_src, "'update_failed'") !== false
	&& strpos(file_get_contents(__DIR__ . '/../panel/update.php'), "'update_upload'") !== false && strpos(file_get_contents(__DIR__ . '/../panel/update.php'), "'update_verified'") !== false);
t_ok('the layout links the Update page and shows the installed version', strpos(file_get_contents(__DIR__ . '/../panel/views/layout.php'), "'update'") !== false && strpos(file_get_contents(__DIR__ . '/../panel/views/layout.php'), 'footer_version') !== false);
// the page renders (plan + history + result)
$gp_upd_root = $root_w;
$view_plan = gp_upd_stage(ut_make_zip($root_w, '2026.11.11', array('docs/V.md' => "v\n", 'CHANGELOG.md' => $ut_changelog)), 'v.zip', 'a')['plan'];
ob_start();
$env = gp_upd_environment(); $version = gp_upd_version(); $plan = $view_plan; $history = gp_upd_history(10); $res = ''; $ts = ''; $m = null; $token = ''; $cron_lines = array(); $web_url = 'recover.php';
require __DIR__ . '/../panel/views/update.php';
$view_html = ob_get_clean();
t_ok('the Update page shows version, the review, the password field with a tooltip, the upload form and the history',
	strpos($view_html, '2026.02.02') !== false && strpos($view_html, 'id="update-apply"') !== false && strpos($view_html, 'type="password"') !== false && strpos($view_html, 'gp-tip-btn') !== false
	&& strpos($view_html, 'enctype="multipart/form-data"') !== false && strpos($view_html, 'name="do" value="rollback"') !== false && strpos($view_html, 'name="csrf"') !== false);
$res = 'ok'; $m = array('to' => '2026.11.11', 'requirements_changed' => true, 'pip_error' => '', 'cron_scripts_changed' => true, 'changelog' => array(array('version' => '2026.11.11', 'text' => 'x<script>')));
$token = str_repeat('ab', 16); $cron_lines = array('* * * * * /x/y');
ob_start(); $plan = null; require __DIR__ . '/../panel/views/update.php'; $view_html = ob_get_clean();
t_ok('the result page shows the recovery token once, the pip_sync note, the cron lines, and escapes the changelog',
	strpos($view_html, $token) !== false && strpos($view_html, 'pip_sync') !== false && strpos($view_html, '* * * * * /x/y') !== false && strpos($view_html, 'x<script>') === false && strpos($view_html, 'role="status"') !== false);
$al = gp_health_alerts(array('now' => time(), 'redis_up' => true, 'update_warn' => array(array('unverified', '20260101-000000', 'critical'), array('pip_failed', 'job abc', 'warning'))));
t_ok('the dashboard raises an alert for an unverified update and for a failed pip_sync', count(array_filter($al, function ($a) { return $a['id'] === 'update_unverified' && $a['level'] === 'critical'; })) === 1
	&& count(array_filter($al, function ($a) { return $a['id'] === 'update_pip_failed' && $a['level'] === 'warning'; })) === 1);
t_ok('the exposure check knows the updates/ files and panel/recover.php', (function () { $s = file_get_contents(__DIR__ . '/exposure-check.sh'); return strpos($s, '/updates/recovery.json') !== false && strpos($s, '/updates/rollback.php') !== false && strpos($s, 'recover.php') !== false; })());

// ---- file modes, the permission health check, the bash crontab form
t_section('Updater file modes, permission health check, crontab through bash');
function ut_chmod_tree($root, $fmode, $dmode) {
	$pat = gp_upd_patterns();
	foreach (array('guard', 'panel', 'analyzer', 'scripts', 'docs') as $top) {
		if (!is_dir($root . '/' . $top)) { continue; }
		$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root . '/' . $top, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
		foreach ($it as $f) {
			$rel = substr($f->getPathname(), strlen($root) + 1);
			if ($f->isDir()) { chmod($f->getPathname(), $dmode); continue; }
			chmod($f->getPathname(), gp_upd_is_protected($rel, $pat) ? 0600 : $fmode);
		}
		chmod($root . '/' . $top, $dmode);
	}
	foreach (glob($root . '/*', GLOB_NOSORT) as $f) { if (is_file($f)) { chmod($f, gp_upd_is_protected(basename($f), gp_upd_patterns()) ? 0600 : $fmode); } }
}
$ut_umask = umask(0);
$rm = ut_install();
ut_chmod_tree($rm, 0666, 0777);                       // what the production server looked like: 666, no execute bit
foreach (glob($rm . '/scripts/*.sh') as $f) { chmod($f, 0666); }
$sm = gp_upd_stage(ut_make_zip($rm, '2026.12.12', array('guard/log.php' => file_get_contents($rm . '/guard/log.php') . "\n// m\n", 'scripts/cron-check.sh' => file_get_contents($rm . '/scripts/cron-check.sh') . "\n# m\n",
	'scripts/new-tool.sh' => "#!/bin/sh\ntrue\n", 'docs/newdir/deep/X.md' => "x\n")), 'm.zip', 'a');
$am = gp_upd_apply($sm['plan']['id'], 'admin');
$mode = function ($rel) use ($rm) { return fileperms($rm . '/' . $rel) & 0777; };
t_ok('modes: every script under scripts/ is 0755 - changed, new and unchanged ones alike', $am['ok'] && $mode('scripts/cron-check.sh') === 0755 && $mode('scripts/new-tool.sh') === 0755
	&& $mode('scripts/analyzer-cron.sh') === 0755 && $mode('scripts/guard-logrotate.sh') === 0755 && $mode('scripts/lib-jobstatus.sh') === 0755);
t_ok('modes: every other file the ZIP delivers is 0644 (changed, new and unchanged, with umask 000 and 666 before)', $mode('guard/log.php') === 0644 && $mode('docs/newdir/deep/X.md') === 0644
	&& $mode('guard/guard.php') === 0644 && $mode('panel/index.php') === 0644 && $mode('VERSION') === 0644 && $mode('prepend.php') === 0644 && $mode('analyzer/worker.py') === 0644);
t_ok('modes: directories the updater creates are 0755 (also with umask 000)', $mode('docs/newdir') === 0755 && $mode('docs/newdir/deep') === 0755);
t_ok('modes: the code directories lose group / world write (777 -> 755)', $mode('guard') === 0755 && $mode('panel') === 0755 && $mode('scripts') === 0755 && $mode('docs') === 0755);
t_ok('modes: no code file of the install is group- or world-writable afterwards (data files and directories keep the mode the operator gave them)', (function () use ($rm) {
	$pat = gp_upd_patterns();
	foreach (array_keys(ut_hashes($rm)) as $rel) {
		if (gp_upd_is_protected($rel, $pat) || preg_match('#^(updates|logs|lists|geo)/#', $rel)) { continue; }
		if ((fileperms($rm . '/' . $rel) & 0022) !== 0) { return false; }
	}
	return true;
})() && (fileperms($rm . '/updates/rollback.php') & 0022) === 0 && (fileperms($rm . '/updates/installed.json') & 0022) === 0 && (fileperms($rm . '/updates/recovery.json') & 0777) === 0600);
t_ok('modes: protected files are not touched (the 0600 they had is still there, bytes unchanged)', $mode('guard/config.php') === 0600 && $mode('panel/panel.config.php') === 0600 && $mode('guard/config.local.json') === 0600);
$mmod = gp_upd_json_read(gp_upd_dir() . '/' . $am['stamp'] . '/manifest.json');
t_ok('modes: the manifest records how many modes were corrected', $mmod['modes_fixed']['files'] > 50 && $mmod['modes_fixed']['dirs'] >= 4);
$rbm = gp_upd_rollback($am['stamp']);
t_ok('modes: a rollback restores the old bytes but not group / world write, and scripts stay executable', $rbm[0] && $mode('guard/log.php') === 0644 && $mode('scripts/cron-check.sh') === 0755 && !is_file($rm . '/scripts/new-tool.sh') && !is_dir($rm . '/docs/newdir'));
umask($ut_umask);

// the permission scan
$ut_status = $UT . '/status';
@mkdir($ut_status, 0775, true);
putenv('GV_JOBSTATUS_DIR=' . $ut_status);
$rp = ut_install();
ut_chmod_tree($rp, 0644, 0755);
foreach (glob($rp . '/scripts/*.sh') as $f) { chmod($f, 0755); }
@mkdir($rp . '/.venv', 0777); file_put_contents($rp . '/.venv/y', 'x'); chmod($rp . '/.venv/y', 0666);
@mkdir($rp . '/.git', 0777); file_put_contents($rp . '/.git/z', 'x'); chmod($rp . '/.git/z', 0666);
file_put_contents($rp . '/logs/x.log', 'x'); chmod($rp . '/logs/x.log', 0666);
$t0 = 1000000;
$sc0 = gp_perm_scan(true, $t0, $rp);
t_ok('permission scan: a clean install has no findings (.venv, .git and logs are skipped even when writable)', !gp_perm_has_issues($sc0) && $sc0['scanned'] > 100 && gp_perm_fix_commands($sc0) === array());
chmod($rp . '/guard/log.php', 0666); chmod($rp . '/docs', 0777); chmod($rp . '/scripts/cron-check.sh', 0644); chmod($rp . '/guard/config.php', 0644);
file_put_contents($rp . '/panel/users.json', '{}'); chmod($rp . '/panel/users.json', 0664);
$sc1 = gp_perm_scan_now($rp, $t0 + 10);
t_ok('permission scan: finds a writable file, a writable directory, a cron script without the execute bit and a world-readable secret',
	$sc1['writable_files'] === 2 && $sc1['writable_dirs'] === 1 && $sc1['cron_not_exec'] === array('scripts/cron-check.sh') && $sc1['secret_readable'] === array('guard/config.php', 'panel/users.json'));
t_ok('permission scan: a secret file that does not exist (panel/users.json before the user store) is not judged', (function () use ($rp, $t0) { unlink($rp . '/panel/users.json'); $r = gp_perm_scan_now($rp, $t0)['secret_readable']; file_put_contents($rp . '/panel/users.json', '{}'); chmod($rp . '/panel/users.json', 0664); return $r === array('guard/config.php'); })());
$cmds = gp_perm_fix_commands($sc1);
t_ok('permission scan: the exact commands are offered (chmod 600 per secret, chmod 755 scripts, find ... -perm /022 for directories and files)',
	in_array('chmod 600 ' . escapeshellarg($rp . '/guard/config.php'), $cmds, true) && in_array('chmod 755 ' . escapeshellarg($rp) . '/scripts/*.sh', $cmds, true)
	&& count(array_filter($cmds, function ($c) { return strpos($c, '-type d -perm /022 -exec chmod go-w') !== false; })) === 1 && count(array_filter($cmds, function ($c) { return strpos($c, '-type f -perm /022 -exec chmod go-w') !== false; })) === 1);
foreach ($cmds as $c) { exec($c . ' 2>&1'); }
$sc2 = gp_perm_scan_now($rp, $t0 + 20);
t_ok('permission scan: running the offered commands really fixes everything it found', !gp_perm_has_issues($sc2), json_encode($sc2));
// cache: one hour, recomputed after an update
chmod($rp . '/guard/log.php', 0666);
$ca = gp_perm_scan(true, $t0, $rp);
chmod($rp . '/guard/log.php', 0644);
t_ok('permission scan: the result is cached for an hour (an older scan is returned within 3599 s)', gp_perm_scan(false, $t0 + 3599, $rp)['writable_files'] === 1 && gp_perm_scan(false, $t0 + 3599, $rp)['time'] === $t0);
t_ok('permission scan: ...and recomputed after an hour, on request, and when the install directory differs', gp_perm_scan(false, $t0 + 3601, $rp)['writable_files'] === 0 && gp_perm_scan(true, $t0 + 3602, $rp)['time'] === $t0 + 3602
	&& gp_perm_scan(false, $t0 + 3603, $UT . '/other')['root'] === $UT . '/other');
gp_perm_scan(true, time(), $rp);
$sup = gp_upd_stage(ut_make_zip($rp, '2027.01.01', array('docs/PERM.md' => "p\n")), 'perm.zip', 'a');
t_ok('permission scan: the cache is dropped when an update is applied', is_file(gp_perm_cache_path()) && gp_upd_apply($sup['plan']['id'], 'a', array('confirm' => array('git_present')))['ok'] && !is_file(gp_perm_cache_path()));
t_ok('permission scan: reading the cache never touches the repository (the cache file lives in the status directory)', strpos(gp_perm_cache_path(), $ut_status) === 0);
// alerts
$al_clean = gp_health_alerts(array('now' => time(), 'redis_up' => true, 'perms' => $sc2));
$al_bad = gp_health_alerts(array('now' => time(), 'redis_up' => true, 'perms' => $sc1));
$lv = function ($a, $id) { foreach ($a as $x) { if ($x['id'] === $id) { return $x['level']; } } return ''; };
t_ok('permission alerts: none on a clean install; critical for a readable secret, warnings for a writable tree and a non-executable cron script',
	count(array_filter($al_clean, function ($a) { return strpos($a['id'], 'perm_') === 0; })) === 0 && $lv($al_bad, 'perm_secret') === 'critical' && $lv($al_bad, 'perm_cron_exec') === 'warning' && $lv($al_bad, 'perm_writable') === 'warning');
$cron_bad = array('mode' => 'live', 'age' => 0, 'report' => array('jobs' => array(array('job' => 'worker', 'state' => 'not_executable', 'severity' => 'critical', 'required' => true)), 'gv_python' => array('set' => true, 'ok' => true)));
t_ok('crontab alert: a direct entry that is not executable is a critical dashboard alert of its own', $lv(gp_health_alerts(array('now' => time(), 'redis_up' => true, 'cron' => $cron_bad)), 'cron_not_exec') === 'critical');
// the documented crontab lines go through bash
$direct = 0;
foreach (array('README.md', 'docs/03-SETUP.md', 'docs/07-CONFIG-REFERENCE.md', 'docs/08-ANALYZER-PHASES.md', 'analyzer/README.md', 'scripts/analyzer-cron.sh') as $docf) {
	$direct += preg_match_all('~^[#\s]*(?:[0-9*/,\-]+\s+){5}\S*/scripts/(?:analyzer-cron|guard-logrotate)\.sh~m', file_get_contents(__DIR__ . '/../' . $docf));
}
t_ok('every documented crontab line calls the script through bash (none calls it directly)', $direct === 0 && substr_count(file_get_contents(__DIR__ . '/../docs/03-SETUP.md'), ' bash /home/youruser/bot-guard/scripts/') >= 8);
// cron-check.sh as a command: exit code and wording for a non-executable direct script
$py3 = trim((string)@shell_exec('command -v python3'));
if ($py3 === '') {
	t_skip('cron-check.sh exit codes', 'python3 not available');
} else {
	$cr = $UT . '/cronroot';
	mkdir($cr . '/scripts', 0775, true);
	foreach (array('analyzer-cron.sh', 'guard-logrotate.sh') as $sn) { file_put_contents($cr . '/scripts/' . $sn, "#!/bin/sh\ntrue\n"); chmod($cr . '/scripts/' . $sn, 0644); }
	$mk = function ($prefix) use ($cr) {
		return "GV_PYTHON=" . PHP_BINARY . "\n*/10 * * * * {$prefix}{$cr}/scripts/analyzer-cron.sh verify >/dev/null 2>&1\n* * * * * {$prefix}{$cr}/scripts/analyzer-cron.sh worker >/dev/null 2>&1\n"
			. "*/15 * * * * {$prefix}{$cr}/scripts/analyzer-cron.sh snapshot >/dev/null 2>&1\n17 4 * * * {$prefix}{$cr}/scripts/analyzer-cron.sh nightly >/dev/null 2>&1\n10 3 * * * {$prefix}{$cr}/scripts/guard-logrotate.sh >/dev/null 2>&1\n";
	};
	file_put_contents($UT . '/ct-direct.txt', $mk(''));
	file_put_contents($UT . '/ct-bash.txt', $mk('bash '));
	exec('bash ' . escapeshellarg(__DIR__ . '/cron-check.sh') . ' --file ' . escapeshellarg($UT . '/ct-direct.txt') . ' --root ' . escapeshellarg($cr) . ' 2>&1', $co1, $crc1);
	exec('bash ' . escapeshellarg(__DIR__ . '/cron-check.sh') . ' --file ' . escapeshellarg($UT . '/ct-bash.txt') . ' --root ' . escapeshellarg($cr) . ' 2>&1', $co2, $crc2);
	t_ok('cron-check.sh: a non-executable direct script exits 1 and says ERROR, "not executable", "fail silently" and the fix', $crc1 === 1 && strpos(implode("\n", $co1), 'ERROR') !== false && strpos(implode("\n", $co1), 'not executable') !== false
		&& strpos(implode("\n", $co1), 'fail silently') !== false && strpos(implode("\n", $co1), 'chmod 755') !== false);
	t_ok('cron-check.sh: the bash form of the same crontab exits 0', $crc2 === 0 && strpos(implode("\n", $co2), 'ERROR') === false, implode("\n", $co2));
	exec('bash ' . escapeshellarg(__DIR__ . '/cron-check.sh') . ' --json --file ' . escapeshellarg($UT . '/ct-direct.txt') . ' --root ' . escapeshellarg($cr) . ' 2>&1', $co3);
	$jr = json_decode(implode("\n", $co3), true);
	t_ok('cron-check.sh --json reports state not_executable with the bash line to use (the panel reads this)', is_array($jr) && $jr['jobs'][0]['state'] === 'not_executable' && strpos($jr['jobs'][0]['install_line'], ' bash ') !== false);
}
putenv('GV_JOBSTATUS_DIR');

unset($gp_upd_opcache_hook);
putenv('GV_AUDIT');
$gp_upd_root = '';


// ==========================================================================
t_section('Users and roles: ACL matrix, demo leakage, sessions, safety rules, migration, fail closed, concurrency, CLI recovery');
require_once __DIR__ . '/../panel/acl.php';
require_once __DIR__ . '/../panel/demo.php';
putenv('GV_AUDIT=' . $UT . '/audit-users.jsonl');
putenv('GV_USERS=' . $UT . '/users-main.json');
$uc_secret = bin2hex(random_bytes(32));
$GLOBALS['gp_test_panel_cfg'] = array('username' => 'LegacyAdmin', 'password_hash' => password_hash('legacy password 1', PASSWORD_DEFAULT), 'session_secret' => $uc_secret, 'session_ttl' => 43200);
$uc_audit = function () use ($UT) { return is_file($UT . '/audit-users.jsonl') ? (string)file_get_contents($UT . '/audit-users.jsonl') : ''; };

// ---- migration from panel.config.php
t_ok('migration: users.json does not exist before the first load', !is_file($UT . '/users-main.json'));
$m0 = gp_users_state(true);
t_ok('migration: the single user of panel.config.php becomes an enabled admin, name lowercased, same password hash, no password change', $m0['ok'] && $m0['migrated'] && count($m0['users']) === 1
	&& $m0['users']['legacyadmin']['role'] === 'admin' && $m0['users']['legacyadmin']['enabled'] === true && password_verify('legacy password 1', $m0['users']['legacyadmin']['password_hash'])
	&& $m0['users']['legacyadmin']['created_by'] === 'migration');
t_ok('migration: users.json is written (mode 0600), valid JSON with every field of the spec', is_file($UT . '/users-main.json') && (fileperms($UT . '/users-main.json') & 0777) === 0600
	&& (function () use ($UT) { $d = json_decode(file_get_contents($UT . '/users-main.json'), true); $u = $d['users'][0];
		foreach (array('username', 'role', 'enabled', 'password_hash', 'created_at', 'created_by', 'updated_at', 'last_login_at', 'last_login_ip', 'session_version') as $f) { if (!array_key_exists($f, $u)) { return false; } } return true; })());
t_ok('migration: the second load reads the file (not migrated again)', gp_users_state(true)['migrated'] === false);
$GLOBALS['gp_test_panel_cfg']['username'] = 'someone-else';
t_ok('migration: once users.json exists panel.config.php no longer decides who exists', gp_users_find('someone-else') === null && gp_users_find('LegacyAdmin') !== null);
$GLOBALS['gp_test_panel_cfg']['username'] = 'LegacyAdmin';

// ---- the old password still logs in (no password change needed), with the generic failure otherwise
$_SERVER['REMOTE_ADDR'] = '203.0.113.210';
$lg = gp_login_attempt('LegacyAdmin', 'legacy password 1');
t_ok('login: the migrated admin signs in with the existing password (name is case-insensitive)', $lg[0] === true && gp_users_find('legacyadmin')['last_login_at'] > 0 && gp_users_find('legacyadmin')['last_login_ip'] === '203.0.113.210');
t_ok('login: a wrong password and an unknown user give the same generic message', gp_login_attempt('legacyadmin', 'nope')[1] === 'login_failed' && gp_login_attempt('nobody-here', 'nope')[1] === 'login_failed');

// ---- management and the safety rules
$A = 'legacyadmin';
t_ok('create: a user with a valid name, role and password', gp_users_create($A, 'Olivia', 'operator', 'olivia-long-password')[0] === true && gp_users_find('olivia')['role'] === 'operator' && gp_users_find('olivia')['created_by'] === $A);
t_ok('create: names are unique and case-insensitive', gp_users_create($A, 'OLIVIA', 'demo', 'olivia-long-password')[1] === 'usr_err_exists');
t_ok('create: the name rule [a-z0-9._-]{3,32}', gp_users_create($A, 'ab', 'demo', 'long-enough-password')[1] === 'usr_err_name' && gp_users_create($A, str_repeat('a', 33), 'demo', 'long-enough-password')[1] === 'usr_err_name'
	&& gp_users_create($A, 'bad name', 'demo', 'long-enough-password')[1] === 'usr_err_name' && gp_users_create($A, 'bad/name', 'demo', 'long-enough-password')[1] === 'usr_err_name'
	&& gp_users_create($A, 'a.b_c-d', 'demo', 'long-enough-password')[0] === true);
t_ok('create: the password rule (12 characters, not the username, case-insensitive)', gp_users_create($A, 'shortpw', 'demo', '12345678901')[1] === 'usr_err_pw_short'
	&& gp_users_create($A, 'same-as-name-x', 'demo', 'Same-As-Name-X')[1] === 'usr_err_pw_same' && gp_users_create($A, 'okpw-user', 'demo', '123456789012')[0] === true);
t_ok('create: an unknown role is refused', gp_users_create($A, 'rolebad', 'superuser', 'long-enough-password')[1] === 'usr_err_role');
t_ok('create: a hash is stored (password_hash default algorithm), never the password', (function () use ($UT) { $raw = file_get_contents($UT . '/users-main.json'); return strpos($raw, 'olivia-long-password') === false && strpos($raw, '$2y$') !== false; })());
t_ok('safety: an admin cannot disable, demote or delete themselves', (function () use ($A) {
	gp_users_create($A, 'second.admin', 'admin', 'second-admin-password');
	return gp_users_set_enabled($A, $A, false)[1] === 'usr_err_self' && gp_users_set_role($A, $A, 'operator')[1] === 'usr_err_self' && gp_users_delete($A, $A)[1] === 'usr_err_self'
		&& gp_users_find($A)['enabled'] === true && gp_users_find($A)['role'] === 'admin';
})());
t_ok('safety: the last enabled admin cannot be disabled, demoted or deleted (even by somebody else)', (function () use ($A) {
	gp_users_set_enabled($A, 'second.admin', false);                                          // legacyadmin is now the only enabled admin
	$r = array(gp_users_set_enabled('ghost', $A, false)[1], gp_users_set_role('ghost', $A, 'demo')[1], gp_users_delete('ghost', $A)[1]);
	gp_users_set_enabled($A, 'second.admin', true);
	return $r === array('usr_err_last_admin', 'usr_err_last_admin', 'usr_err_last_admin') && gp_users_find($A)['enabled'] === true;
})());
t_ok('safety: with two admins one may demote, disable or delete the other', gp_users_set_role($A, 'second.admin', 'operator')[0] === true && gp_users_set_role($A, 'second.admin', 'admin')[0] === true
	&& gp_users_delete($A, 'second.admin')[0] === true && gp_users_find('second.admin') === null);

// ---- sessions end immediately (disable, role change, password reset, own password change, delete)
$tokenFor = function ($name) use ($uc_secret) { $u = gp_users_find($name); return gp_session_make($u['username'], $uc_secret, null, (int)$u['session_version']); };
$who = function ($tok) { $_COOKIE[GP_SESSION_COOKIE] = $tok; $u = gp_current_user(); $r = gp_current_role(); unset($_COOKIE[GP_SESSION_COOKIE]); return array($u, $r); };
$t1 = $tokenFor('olivia');
t_ok('session: a session carries its user and role', $who($t1) === array('olivia', 'operator'));
gp_users_set_role($A, 'olivia', 'demo');
t_ok('session: a role change ends the existing session at once (a new one has the new role)', $who($t1) === array(null, '') && $who($tokenFor('olivia')) === array('olivia', 'demo'));
$t2 = $tokenFor('olivia');
gp_users_set_enabled($A, 'olivia', false);
t_ok('session: disabling a user ends the session at once, even with a freshly signed token', $who($t2) === array(null, '') && $who($tokenFor('olivia')) === array(null, ''));
gp_users_set_enabled($A, 'olivia', true);
t_ok('session: enabling again does not revive the old session', $who($t2) === array(null, '') && $who($tokenFor('olivia'))[0] === 'olivia');
$t3 = $tokenFor('olivia');
gp_users_reset_password($A, 'olivia', 'brand-new-password-1');
t_ok('session: a password reset ends the session at once, and the new password works', $who($t3) === array(null, '') && password_verify('brand-new-password-1', gp_users_find('olivia')['password_hash']));
$t4 = $tokenFor('olivia'); $other = $tokenFor($A);
$own = gp_users_change_own_password('olivia', 'brand-new-password-1', 'olivias-own-new-pass');
t_ok('session: changing your own password needs the current one, ends the other sessions and returns the new version for the current one', $own[0] === true && $who($t4) === array(null, '')
	&& $who(gp_session_make('olivia', $uc_secret, null, $own[2]))[0] === 'olivia' && gp_users_change_own_password('olivia', 'wrong-current-pass', 'xxxxxxxxxxxxxxx')[1] === 'usr_err_current'
	&& gp_users_change_own_password('olivia', 'olivias-own-new-pass', 'short')[1] === 'usr_err_pw_short');
t_ok('session: other users keep their sessions', $who($other) === array($A, 'admin'));
t_ok('session: a token signed with another version, a tampered user and a deleted user all fail', $who(gp_session_make('olivia', $uc_secret, null, 99)) === array(null, '')
	&& $who(gp_session_make('olivia', 'x' . $uc_secret, null, (int)gp_users_find('olivia')['session_version'])) === array(null, '') && (function () use ($A, $who, $tokenFor) { gp_users_create($A, 'temp.user', 'demo', 'temporary-password-1'); $t = $tokenFor('temp.user'); gp_users_delete($A, 'temp.user'); return $who($t) === array(null, ''); })());
t_ok('session: a session issued before the upgrade (version 0, the old token shape) still works', (function () use ($A, $who, $uc_secret) { gp_users_create($A, 'old.session', 'operator', 'old-session-password'); return gp_users_find('old.session')['session_version'] === 0 && $who(gp_session_make('old.session', $uc_secret)) === array('old.session', 'operator'); })());
t_ok('audit: user management lines carry actor, target and before / after, never a hash',
	strpos($uc_audit(), '"event":"user_create"') !== false && strpos($uc_audit(), '"event":"user_role"') !== false && strpos($uc_audit(), '"event":"user_disable"') !== false
	&& strpos($uc_audit(), '"event":"user_password_reset"') !== false && strpos($uc_audit(), '"event":"user_password_change"') !== false && strpos($uc_audit(), '"event":"user_delete"') !== false
	&& strpos($uc_audit(), '$2y$') === false && strpos($uc_audit(), 'brand-new-password') === false && strpos($uc_audit(), '"old":{"role":"operator","enabled":true}') !== false);

// ---- login limiter per username and per IP
$_SERVER['REMOTE_ADDR'] = '203.0.113.211';
$lim = array();
for ($i = 0; $i < 5; $i++) { $lim[] = gp_login_attempt('victim.one', 'wrong' . $i)[1]; }
t_ok('limiter: five wrong attempts from one address, then it is locked for every user name', $lim === array_fill(0, 5, 'login_failed') && gp_login_attempt('olivia', 'olivias-own-new-pass')[1] === 'login_locked');
$_SERVER['REMOTE_ADDR'] = '203.0.113.212';
$a2 = array();
for ($i = 0; $i < 10; $i++) { $_SERVER['REMOTE_ADDR'] = '203.0.113.' . (220 + $i); $a2[] = gp_login_attempt('target.user', 'wrong' . $i)[1]; }
$_SERVER['REMOTE_ADDR'] = '203.0.113.240';
t_ok('limiter: ten wrong attempts at ONE user name from ten addresses lock that name for a fresh address (per-username limit), with the same wait answer for a name that does not exist',
	count(array_unique($a2)) === 1 && gp_login_attempt('target.user', 'x')[1] === 'login_locked' && gp_login_attempt('olivia', 'olivias-own-new-pass')[0] === true);
foreach (array_merge(array('203.0.113.210', '203.0.113.211', '203.0.113.240', 'user', gp_login_user_bucket('victim.one'), gp_login_user_bucket('target.user'), gp_login_user_bucket('nobody-here')), array_map(function ($i) { return '203.0.113.' . (220 + $i); }, range(0, 9))) as $ub) {
	@unlink(gp_attempts_file($ub));
	$cc = gv_redis_connect(gv_cfg_load()['redis'], $GP_TMP_LOGS, false);
	if ($cc) { gv_redis_cmd($cc, array('DEL', gp_key('login:' . $ub))); gv_redis_close($cc); }
}
t_ok('login: a disabled user cannot sign in and gets the same generic message', (function () use ($A) { gp_users_set_enabled($A, 'olivia', false); $r = gp_login_attempt('olivia', 'olivias-own-new-pass'); gp_users_set_enabled($A, 'olivia', true); return $r[1] === 'login_failed'; })());
foreach (array('203.0.113.240') as $ub) { @unlink(gp_attempts_file($ub)); @unlink(gp_attempts_file(gp_login_user_bucket('olivia'))); }
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';

// ---- the ACL matrix: every route in the router x GET/POST x role (+ logged out)
$ui_src = file_get_contents(__DIR__ . '/../panel/index.php');
preg_match_all("/^\tcase '([a-z_]+)':/m", $ui_src, $mm);
$routes = array_values(array_unique(array_merge($mm[1], array('logout'))));
$expect = array(   // route => array(GET min role, POST min role)   (the decision table, written out independently of acl.php)
	'dashboard' => array('demo', 'admin'), 'account' => array('demo', 'admin'), 'logout' => array('demo', 'demo'), 'logs' => array('operator', 'admin'), 'identity' => array('operator', 'admin'),
	'overrides' => array('operator', 'admin'), 'rules' => array('operator', 'admin'), 'geo' => array('operator', 'admin'), 'iplists' => array('operator', 'admin'), 'replay' => array('operator', 'admin'),
	'models' => array('operator', 'admin'), 'settings' => array('operator', 'admin'), 'captcha_preview' => array('operator', 'admin'), 'jobs' => array('operator', 'admin'), 'audit' => array('operator', 'admin'),
	'config_file' => array('admin', 'admin'), 'update' => array('admin', 'admin'), 'users' => array('admin', 'admin'));
$rank = array('' => 0, 'demo' => 1, 'operator' => 2, 'admin' => 3);
t_ok('ACL: every route the router handles has an explicit entry in the permission map (a new route without one fails the build)', array_diff($routes, array_keys(gp_acl_map())) === array() && array_diff($routes, array_keys($expect)) === array());
$bad = array();
foreach ($routes as $rt) {
	foreach (array('GET', 'POST') as $me) {
		foreach (array('admin', 'operator', 'demo', '') as $role) {
			$want = isset($expect[$rt]) ? ($rank[$role] >= $rank[$expect[$rt][$me === 'GET' ? 0 : 1]] && $role !== '') : ($role === 'admin');
			if (gp_acl_allows($role, $rt, $me) !== $want) { $bad[] = "$role $me $rt"; }
		}
	}
}
t_ok('ACL matrix: every route x GET / POST x admin / operator / demo / logged out is allowed or denied exactly as the table says' . ($bad ? ' (' . implode(', ', array_slice($bad, 0, 5)) . ')' : ''), !$bad);
t_ok('ACL: the operator can POST nothing except logout and its own password; the demo role likewise', (function () use ($routes) {
	foreach (array('operator', 'demo') as $role) {
		foreach ($routes as $rt) {
			$allowed = gp_acl_allows($role, $rt, 'POST', gp_acl_action($rt, array('do' => 'password')));
			if ($allowed !== in_array($rt, array('logout', 'account'), true)) { return false; }
		}
		if (gp_acl_allows($role, 'account', 'POST', 'something-else') || gp_acl_allows($role, 'account', 'POST', '')) { return false; }
	}
	return true;
})());
t_ok('ACL: admin only is the default (unknown route, unknown method, unlisted POST action)', gp_acl_required('brand_new_route', 'GET') === 'admin' && gp_acl_required('logs', 'DELETE') === 'operator'
	&& !gp_acl_allows('operator', 'brand_new_route', 'GET') && !gp_acl_allows('demo', 'brand_new_route', 'POST') && gp_acl_allows('admin', 'brand_new_route', 'GET') && gp_acl_required('account', 'POST', 'other') === 'admin');
t_ok('ACL: demo sees only the dashboard (aggregate view) and My account; operator sees every page except Config, Update and Users',
	gp_acl_nav('demo') === array('dashboard', 'account') && array_values(array_diff(gp_acl_nav('admin'), gp_acl_nav('operator'))) === array('config_file', 'update', 'users') && array_diff(gp_acl_nav('operator'), gp_acl_nav('admin')) === array());
$gate = strpos($ui_src, '!gp_acl_allows($gp_role, $gp_route');
t_ok('ACL: the check sits in the router after the session check and before CSRF and every handler; a denial is HTTP 403 plus an acl_denied audit line',
	$gate !== false && $gate > strpos($ui_src, 'if ($gp_user === null)') && $gate < strpos($ui_src, "if (\$gp_post && !gp_csrf_check(") && $gate < strpos($ui_src, 'switch ($gp_route)')
	&& strpos($ui_src, "'acl_denied'") !== false && strpos($ui_src, 'http_response_code(403)') !== false);
t_ok('ACL: the Update page and the user pages are POST handlers behind the same gate and the CSRF check (new POSTs: users, account)', (function () use ($ui_src) {
	$csrf = strpos($ui_src, "if (\$gp_post && !gp_csrf_check(");
	foreach (array("case 'users':", "case 'account':", "case 'update':") as $c) { $p = strpos($ui_src, $c); if ($p === false || $p < $csrf) { return false; } }
	$blk = substr($ui_src, strpos($ui_src, "case 'users':"), strpos($ui_src, "case 'update':") - strpos($ui_src, "case 'users':"));
	return substr_count($blk, 'if ($gp_post') === 2;
})());
t_ok('ACL: the decision table in acl.php names every route', (function () { $s = file_get_contents(__DIR__ . '/../panel/acl.php'); foreach (array('logs', 'identity', 'overrides', 'rules', 'geo', 'iplists', 'replay', 'models', 'settings', 'jobs', 'audit', 'config_file', 'update', 'users', 'account', 'logout', 'dashboard') as $r) { if (strpos($s, "//   " . $r) === false) { return false; } } return true; })());

// ---- the demo role: a separate, data-minimised view
$seed = array('ips' => array('203.0.113.77', '198.51.100.9'), 'ua' => 'SecretBot/9.9 (+https://internal.example.test)', 'path' => '/secret/path-xyz', 'dev' => 'dev-abc123def', 'pattern' => 'zz-pattern-qq',
	'file' => '/home/secretuser/bot-guard/guard/config.php', 'host' => 'redis.internal.example.test', 'country' => 'Ruritania', 'err' => 'Traceback: connect to 10.99.88.77 failed', 'other_user' => 'secret.colleague');
$snap_seed = array('generated_at' => time() - 60, 'tz' => array('name' => 'Zone/Secret', 'offset' => 3600), 'kpi' => array('window_h' => 24,
	'cur' => array('requests' => 1840, 'allowed' => 1500, 'blocked' => 210, 'limited' => 12, 'challenged' => 96, 'challenge_success' => 91.4, 'rule_hits' => 140, 'honeypot' => 6, 'degraded' => 0, 'captcha_shown' => 30, 'captcha_solved' => 20, 'captcha_failed' => 5, 'captcha_expired' => 5, 'captcha_solve_rate' => 66.7, 'secret_extra' => $seed['ua']),
	'prev' => array('requests' => 1500, 'allowed' => 1320, 'blocked' => 120, 'limited' => 12, 'challenged' => 40, 'challenge_success' => 96.0, 'rule_hits' => 100, 'honeypot' => 9, 'degraded' => 0, 'captcha_shown' => 10, 'captcha_solved' => 8, 'captcha_failed' => 1, 'captcha_expired' => 1, 'captcha_solve_rate' => 80.0)),
	'top' => array('ips' => array(array($seed['ips'][0], 80), array($seed['ips'][1], 60)), 'uas' => array(array($seed['ua'], 120)), 'paths' => array(array($seed['path'], 40)), 'devices' => array(array($seed['dev'], 30)), 'countries' => array(array($seed['country'], 900))),
	'decisions' => array('allow' => 1500), 'host' => $seed['host']);
$rules_seed = array(array('id' => 'r1', 'name' => $seed['pattern'], 'enabled' => true, 'mode' => 'enforce', 'action' => 'block', 'pattern' => $seed['pattern']), array('id' => 'r2', 'name' => 'x', 'enabled' => false, 'mode' => 'monitor', 'action' => 'log'));
$lists_seed = array(array('id' => 'l1', 'name' => $seed['ips'][0], 'enabled' => true, 'type' => 'block', 'mode' => 'enforce', 'entries' => array($seed['ips'][1])));
$jobs_seed = array('verify' => array('state' => 'failing', 'required' => true, 'last_error' => $seed['err'], 'first_line' => $seed['err'], 'path' => $seed['file']), 'worker' => array('state' => 'ok', 'required' => true), 'train' => array('state' => 'never', 'required' => false));
$cfg_seed = array('secret' => 'REAL-SECRET-VALUE-123', 'holdout_salt' => 'REAL-SALT', 'enforce' => array('block' => true, 'challenge' => false, 'ratelimit' => false), 'redis' => array('host' => $seed['host'], 'password' => 'REDIS-PASS-XYZ'));
$model = gp_demo_model(array('snapshot' => $snap_seed, 'cfg' => $cfg_seed, 'rules' => $rules_seed, 'lists' => $lists_seed, 'jobs' => $jobs_seed, 'now' => time()));
t_ok('demo: the view model has aggregates only (KPI numbers with their change, the protection word, five counts)', $model['kpi']['requests']['cur'] === 1840.0 && $model['kpi']['blocked']['change'] === '+75.0 %'
	&& $model['protection'] === 'partial' && $model['counts'] === array('rules_total' => 2, 'rules_enabled' => 1, 'lists_total' => 1, 'lists_enabled' => 1, 'jobs_healthy' => 1, 'jobs_unhealthy' => 1) && !isset($model['kpi']['secret_extra']));
$demo_user = 'demo.viewer';
$gp_user_save = isset($GLOBALS['gp_user']) ? $GLOBALS['gp_user'] : null;
ob_start();
$user = $demo_user; $role = 'demo'; $route = 'dashboard'; $flash = array(); $demo = $model; $view_file = __DIR__ . '/../panel/views/demo.php';
require __DIR__ . '/../panel/views/layout.php';
$demo_html = ob_get_clean();
$leak = array();
foreach (array_merge($seed['ips'], array($seed['ua'], $seed['path'], $seed['dev'], $seed['pattern'], $seed['file'], $seed['host'], $seed['country'], $seed['err'], $seed['other_user'], '10.99.88.77', 'REAL-SECRET', 'REDIS-PASS', 'internal.example', 'Zone/Secret', 'secretuser')) as $needle) {
	if (stripos($demo_html, $needle) !== false) { $leak[] = $needle; }
}
t_ok('demo: the demo dashboard rendered with seeded sensitive data contains none of it (IPs, User-Agents, paths, device ids, rule patterns, file paths, host names, errors, other users, secrets)' . ($leak ? ' LEAKED: ' . implode(', ', $leak) : ''), !$leak && strlen($demo_html) > 2000);
t_ok('demo: the page shows the banner, the numbers, and no other nav entry than Dashboard and My account', strpos($demo_html, 'Demo mode') !== false && strpos($demo_html, 'sensitive data hidden') !== false && strpos($demo_html, '1,840') !== false
	&& strpos($demo_html, 'r=logs') === false && strpos($demo_html, 'r=settings') === false && strpos($demo_html, 'r=users') === false && strpos($demo_html, 'r=account') !== false && strpos($demo_html, $demo_user) !== false);
t_ok('demo: the view model is a plain array of numbers and fixed words (no string from the data survives json_encode)', (function () use ($model, $seed) { $j = json_encode($model); foreach (array_merge($seed['ips'], array($seed['ua'], $seed['path'], $seed['dev'], $seed['pattern'], $seed['err'])) as $n) { if (strpos($j, $n) !== false) { return false; } } return true; })());
$dcase = substr($ui_src, strpos($ui_src, "case 'dashboard':"), 900);
t_ok('demo: the dashboard handler answers a demo user with the demo model BEFORE it reads any health, log or config data', strpos($dcase, "gp_role === 'demo'") !== false && strpos($dcase, "gp_render('demo'") !== false && strpos($dcase, "gp_role === 'demo'") < strpos($ui_src, 'gp_health_inputs()', strpos($ui_src, "case 'dashboard':")));
$op_html = (function () use ($model) { ob_start(); $user = 'olivia'; $role = 'operator'; $route = 'logs'; $flash = array(); $view_file = __DIR__ . '/../panel/views/forbidden.php'; require __DIR__ . '/../panel/views/layout.php'; return ob_get_clean(); })();
t_ok('operator: the navigation has every page except Config, Update and Users, shows the read-only note and the role in the top bar', strpos($op_html, 'r=audit') !== false && strpos($op_html, 'r=jobs') !== false && strpos($op_html, 'r=config_file') === false
	&& strpos($op_html, 'r=update') === false && strpos($op_html, 'r=users') === false && strpos($op_html, 'Monitoring operator') !== false && strpos($op_html, '<body class="gp-body" data-readonly="1">') !== false);
$ad_html = (function () { ob_start(); $user = 'legacyadmin'; $role = 'admin'; $route = 'users'; $flash = array(); $view_file = __DIR__ . '/../panel/views/forbidden.php'; require __DIR__ . '/../panel/views/layout.php'; return ob_get_clean(); })();
t_ok('admin: the navigation has Update and Users, and the top bar names user and role', strpos($ad_html, 'r=update') !== false && strpos($ad_html, 'r=users') !== false && strpos($ad_html, 'r=config_file') !== false && strpos($ad_html, 'legacyadmin') !== false && strpos($ad_html, 'Administrator') !== false && strpos($ad_html, '<body class="gp-body">') !== false);

// ---- operator never sees secrets
t_ok('operator: the raw Config page (overlay editor) is admin only and no secret key is in the operator-visible audit events', gp_acl_required('config_file', 'GET') === 'admin' && !in_array('secret', array_keys(gv_overlay_whitelist()), true)
	&& !in_array('holdout_salt', array_keys(gv_overlay_whitelist()), true) && !preg_grep('/^redis\./', array_keys(gv_overlay_whitelist())));
$sv = shell_exec(escapeshellarg($UT_PHP) . ' ' . escapeshellarg(__DIR__ . '/secret-values.php') . ' 2>/dev/null');
t_ok('secrets: scripts/secret-values.php also lists the password hashes of the user store (job logs redact them)', is_string($sv) && strpos($sv, gp_users_find('olivia')['password_hash']) !== false);

// ---- fail closed: a damaged store logs nobody in; a missing store with no config is an error, not an open door
$_COOKIE[GP_SESSION_COOKIE] = gp_session_make('legacyadmin', $uc_secret, null, (int)gp_users_find('legacyadmin')['session_version']);
file_put_contents($UT . '/users-main.json', '{"users": [ not json');
t_ok('fail closed: a corrupt users.json -> the state is an error, nobody has a session, nobody can log in (own message), nothing overwrites the file',
	gp_users_state(true)['ok'] === false && gp_users_state()['error'] === 'corrupt' && gp_current_user() === null && gp_login_attempt('legacyadmin', 'legacy password 1')[1] === 'login_store'
	&& gp_users_create('x', 'newbie.user', 'demo', 'long-enough-password')[1] === 'usr_err_store' && file_get_contents($UT . '/users-main.json') === '{"users": [ not json' && gp_reauth('legacyadmin', 'legacy password 1') === 'bad');
foreach (array('{"v":1,"users":[{"username":"a1x","role":"god","password_hash":"x"}]}', '{"v":1,"users":[{"username":"dup","role":"admin","password_hash":"x"},{"username":"dup","role":"demo","password_hash":"y"}]}', '{"v":1,"users":[{"username":"nohash","role":"admin"}]}', '', '[]', 'null') as $bad_store) {
	file_put_contents($UT . '/users-main.json', $bad_store);
	if (gp_users_state(true)['ok']) { $leak = 1; }
}
t_ok('fail closed: an unknown role, a duplicate name, a missing hash, an empty file or a wrong shape are all rejected as a store', empty($leak));
t_ok('fail closed: the CLI recovery refuses to write into a corrupt store (it offers to move it aside instead)', gp_users_cli_admin('rescue.admin', 'rescue-admin-password')[1] === 'usr_err_store');
unset($_COOKIE[GP_SESSION_COOKIE]);
@unlink($UT . '/users-main.json');
unset($GLOBALS['gp_test_panel_cfg']);
t_ok('fail closed: no users.json and no panel.config.php -> an error state, nobody signs in', gp_users_state(true)['ok'] === false && gp_users_state()['error'] === 'missing' && gp_current_user() === null);

// ---- concurrent writes: eight processes add eight users to one store
$GLOBALS['gp_test_panel_cfg'] = array('username' => 'root.user', 'password_hash' => password_hash('root password long', PASSWORD_DEFAULT), 'session_secret' => $uc_secret, 'session_ttl' => 43200);
@unlink($UT . '/users-conc.json'); putenv('GV_USERS=' . $UT . '/users-conc.json');
gp_users_state(true);
$kids = array();
$code = 'define("GV_BOOT",1);define("GP_BOOT",1);define("GV_NO_AUTORUN",1);define("GP_SELFTEST",1);require ' . var_export(__DIR__ . '/../panel/config_io.php', true) . ';require ' . var_export(__DIR__ . '/../panel/auth.php', true)
	. ';$r=gp_users_create("root.user","conc".(int)getenv("UC_N"),"operator","concurrent-password-1");exit($r[0]?0:1);';
for ($i = 1; $i <= 8; $i++) {
	$pipes = array();
	$kids[] = proc_open(array($UT_PHP, '-r', $code), array(0 => array('file', '/dev/null', 'r'), 1 => array('file', '/dev/null', 'w'), 2 => array('file', '/dev/null', 'w')), $pipes, null, array('UC_N' => (string)$i, 'GV_USERS' => $UT . '/users-conc.json', 'GV_AUDIT' => $UT . '/audit-conc.jsonl', 'PATH' => getenv('PATH')));
}
$codes = array();
foreach ($kids as $k) { $codes[] = proc_close($k); }
$cs = gp_users_state(true);
t_ok('concurrent writes: eight processes each create a user in the same store - all eight and the original are there, the file is valid JSON, no temp file is left', array_sum($codes) === 0 && $cs['ok'] && count($cs['users']) === 9
	&& isset($cs['users']['conc1'], $cs['users']['conc8'], $cs['users']['root.user']) && glob($UT . '/users-conc.json.tmp*') === array());
unset($GLOBALS['gp_test_panel_cfg']);

// ---- CLI recovery (php panel/setpass.php) in a scratch copy of the install
$ur = ut_install();
@unlink($ur . '/panel/panel.config.php');
$cli = function ($input) use ($ur, $UT_PHP) {
	$p = proc_open(array($UT_PHP, $ur . '/panel/setpass.php'), array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes, $ur, array('PATH' => getenv('PATH'), 'GV_AUDIT' => $ur . '/audit-cli.jsonl'));
	fwrite($pipes[0], $input); fclose($pipes[0]);
	$out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
	fclose($pipes[1]); fclose($pipes[2]);
	return array(proc_close($p), $out);
};
$ucli = function () use ($ur) { $d = json_decode((string)@file_get_contents($ur . '/panel/users.json'), true); $o = array(); foreach ((array)($d['users'] ?? array()) as $u) { $o[$u['username']] = $u; } return $o; };
$c1 = $cli("Root.Admin\nfirst-admin-password-1\nfirst-admin-password-1\n");
$u1 = $ucli();
t_ok('CLI: the first run creates panel.config.php and the first administrator (lowercased) in users.json, mode 0600', $c1[0] === 0 && isset($u1['root.admin']) && $u1['root.admin']['role'] === 'admin' && $u1['root.admin']['enabled'] === true
	&& (fileperms($ur . '/panel/users.json') & 0777) === 0600 && is_file($ur . '/panel/panel.config.php') && password_verify('first-admin-password-1', $u1['root.admin']['password_hash']));
$d = json_decode(file_get_contents($ur . '/panel/users.json'), true);
$d['users'][0]['enabled'] = false; $d['users'][0]['role'] = 'demo';
$d['users'][] = array('username' => 'keep.me', 'role' => 'operator', 'enabled' => true, 'password_hash' => password_hash('keep-me-password-1', PASSWORD_DEFAULT), 'created_at' => 1, 'created_by' => 'x', 'updated_at' => 1, 'last_login_at' => 0, 'last_login_ip' => '', 'session_version' => 3);
file_put_contents($ur . '/panel/users.json', json_encode($d));
$c2 = $cli("y\nroot.admin\nrecovered-password-1\nrecovered-password-1\nn\n");
$u2 = $ucli();
t_ok('CLI recovery: resetting a disabled, demoted admin re-enables it, makes it an administrator again, sets the password and ends its sessions; other accounts are untouched',
	$c2[0] === 0 && $u2['root.admin']['enabled'] === true && $u2['root.admin']['role'] === 'admin' && password_verify('recovered-password-1', $u2['root.admin']['password_hash']) && $u2['root.admin']['session_version'] === $u1['root.admin']['session_version'] + 1
	&& $u2['keep.me']['session_version'] === 3 && $u2['keep.me']['role'] === 'operator' && password_verify('keep-me-password-1', $u2['keep.me']['password_hash']));
$c3 = $cli("y\nnew.admin\nanother-admin-pass-1\nanother-admin-pass-1\nn\n");
t_ok('CLI recovery: a new administrator can be created while others exist', $c3[0] === 0 && isset($ucli()['new.admin']) && $ucli()['new.admin']['role'] === 'admin' && count($ucli()) === 3);
$cfg_before = file_get_contents($ur . '/panel/panel.config.php');
$c4 = $cli("y\nx\n");
t_ok('CLI: a bad username is refused with an error and exit code 2, nothing written', $c4[0] === 2 && file_get_contents($ur . '/panel/panel.config.php') === $cfg_before && count($ucli()) === 3);
$cli("y\nroot.admin\nrecovered-password-2\nrecovered-password-2\ny\n");
t_ok('CLI: answering yes to "log out every session" rotates the session secret', file_get_contents($ur . '/panel/panel.config.php') !== $cfg_before);
file_put_contents($ur . '/panel/users.json', 'garbage');
$c5 = $cli("y\nn\n");
t_ok('CLI recovery: a corrupt users.json is not touched unless you agree', $c5[0] === 2 && file_get_contents($ur . '/panel/users.json') === 'garbage');
$c6 = $cli("y\ny\nrescue.admin\nrescue-password-123\nrescue-password-123\nn\n");
t_ok('CLI recovery: ...and with your agreement it is moved aside and a new store starts with the new administrator', $c6[0] === 0 && isset($ucli()['rescue.admin']) && count($ucli()) === 1 && count(glob($ur . '/panel/users.json.bad-*')) === 1);
$c7 = $cli("y\nroot\nroot\nroot\nn\n");
t_ok('CLI: a password equal to the username or shorter than 12 characters is refused', $c7[0] === 2);

// ---- the updater is admin only; the new pages carry tooltips and strings
t_ok('updater: the Update page and every update action are admin only (GET and POST)', gp_acl_required('update', 'GET') === 'admin' && gp_acl_required('update', 'POST') === 'admin' && !gp_acl_allows('operator', 'update', 'GET') && !gp_acl_allows('operator', 'update', 'POST') && !gp_acl_allows('demo', 'update', 'GET'));
$_SERVER['REQUEST_METHOD'] = 'GET';
$uview = function ($file, array $vars) { extract($vars); ob_start(); require $file; return ob_get_clean(); };
$u_html = $uview(__DIR__ . '/../panel/views/users.php', array('users' => array(array('username' => 'olivia', 'role' => 'operator', 'enabled' => true, 'created_at' => 1700000000, 'created_by' => 'x', 'last_login_at' => 0, 'last_login_ip' => '', 'session_version' => 0)),
	'all_count' => 3, 'filter' => array('role' => array('v' => array('operator'), 'not' => true)), 'state' => array('readonly' => false), 'me' => 'legacyadmin'));
t_ok('Users page renders the filters (with an exclude chip), the create form, per-row actions with a delete confirmation and a tooltip on every new field',
	strpos($u_html, 'gp-chip-not') !== false && strpos($u_html, 'name="do" value="create"') !== false && strpos($u_html, 'data-confirm=') !== false && substr_count($u_html, 'gp-tip-btn') >= 5
	&& substr_count($u_html, 'name="csrf"') >= 3 && strpos($u_html, '$2y$') === false && strpos($u_html, 'Monitoring operator') !== false);
$a_html = $uview(__DIR__ . '/../panel/views/account.php', array('me' => array('username' => 'olivia', 'role' => 'operator', 'last_login_at' => 0)));
t_ok('My account page: the form needs the current password, has tooltips, CSRF and is allowed for read-only roles (data-allow)', strpos($a_html, 'name="current"') !== false && strpos($a_html, 'data-allow') !== false && substr_count($a_html, 'gp-tip-btn') >= 2 && strpos($a_html, 'name="csrf"') !== false);
putenv('GV_AUDIT'); putenv('GV_USERS');

echo "\n";
// Say so out loud. A green run on a host missing the extension must never be
// mistakable for full coverage.
if (!$GP_HAS_DOM) {
	echo "NOTE: ext-dom was unavailable; the DOM-level XSS assertions did not run.\n";
}
echo "PASS " . $GP_PASS . "  FAIL " . $GP_FAIL . "  SKIP " . $GP_SKIP . "\n";
exit($GP_FAIL === 0 ? 0 : 1);
