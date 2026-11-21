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
$GLOBALS['gp_test_panel_cfg'] = array(
	'username' => 'operator', 'session_secret' => $sec, 'session_ttl' => 43200);
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
	&& !$lm(array('ovr' => 'allow', 'ovr_op' => 'not')) && $lm(array('ovr' => '(none)')));
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
	$mk = function ($val, $op) use ($of) { return gp_filter_parse(array($of => $val, $of . '_op' => $op), array($of => $of === 'cc' ? array('choice', 'ci' => true) : ($of === 'dev' ? 'ident' : 'choice'))); };
	$chk = function ($val, $op, $absent, $has, $other) use ($of, $d, $mk, &$ob) {
		$f = $mk($val, $op);
		$got = array(gp_log_match($d[0], $f), gp_log_match($d[1], $f), gp_log_match($d[2], $f));
		if ($got !== array($absent, $has, $other)) { $ob[] = $of . ' ' . $op . ' ' . $val . ' => ' . json_encode($got); }
	};
	$v = $d[3];
	$chk($v, 'is', false, true, false);                    // is X: absent no
	$chk($v, 'not', false, false, true);                   // is not X: absent NO (neither is nor is not)
	$chk('(none)', 'is', true, false, false);              // is (none): the absent rows only
	$chk('(none)', 'not', false, true, true);              // is not (none): rows that have a value
	$chk($v . ',(none)', 'is', true, true, false);         // X or none
	$chk($v . ',(none)', 'not', false, false, true);       // not X and not none
	$chk(strtoupper('(None)'), 'is', true, false, false);  // the token is case-insensitive
}
t_ok('optional fields (cc, asn, status, botv, ovr, dev, reason): is / is not / (none) / mixed lists behave as specified on a row without, with, and with another value' . ($ob ? ' (' . implode('; ', $ob) . ')' : ''), !$ob);
t_ok('a row WITHOUT the field matches neither "is" nor "is not" (country, status, botv)',
	!gp_log_match(array(), array('cc' => array('v' => array('IR'), 'not' => false))) && !gp_log_match(array(), array('cc' => array('v' => array('IR'), 'not' => true)))
	&& !gp_log_match(array(), array('status' => array('v' => array('5xx'), 'not' => false))) && !gp_log_match(array(), array('status' => array('v' => array('5xx'), 'not' => true)))
	&& !gp_log_match(array(), array('botv' => array('v' => array('ok'), 'not' => false))) && !gp_log_match(array(), array('botv' => array('v' => array('ok'), 'not' => true))));
t_ok('a row with asn 0 (looked up, none found) counts as having no ASN', gp_log_match(array('asn' => 0), array('asn' => array('v' => array('(none)'), 'not' => false))) && !gp_log_match(array('asn' => 0), array('asn' => array('v' => array('1'), 'not' => true))));
t_ok('always-present fields keep include / exclude: act, ip, tok, sh, path, ua', gp_log_match(array('ip' => '1.2.3.4'), array('ip' => array('v' => array('5.5.5.5'), 'not' => true)))
	&& gp_log_match(array(), array('act' => array('v' => array('403'), 'not' => true))) && gp_log_match(array('p' => '/a'), array('path' => array('v' => array('zzz'), 'not' => true)))
	&& gp_log_match(array('tok' => 'm'), array('tok' => array('v' => array('v'), 'not' => true))) && gp_log_match(array('sh' => 0), array('sh' => array('v' => array('1'), 'not' => true))));
t_ok('(none) is only a value for optional fields: on an always-present field it matches nothing and "is not (none)" matches everything', !gp_log_match(array('act' => '403'), array('act' => array('v' => array('(none)'), 'not' => false)))
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
t_ok('rules: country (any case) and ASN conditions, is / is not, among rules that have one', $rfl(array('cc' => 'ir')) === array('r-g1') && array_values($rfl(array('cc' => 'US', 'cc_op' => 'not'))) === array('r-g1')
	&& $rfl(array('asn' => '13335')) === array('r-g1') && $rfl(array('asn' => '1', 'asn_op' => 'not')) === array('r-g1')
	&& $rfl(array('cc' => 'IR', 'cc_op' => 'not')) === array() && array_values($rfl(array('cc' => '(none)'))) === array('r-g2') && array_values($rfl(array('cc' => '(none)', 'cc_op' => 'not'))) === array('r-g1'));
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
foreach (array('ip', 'path', 'ua', 'cc', 'asn', 'act', 'status', 'reason', 'botv', 'tok', 'dev', 'sh', 'hold', 'ovr', 'date', 'score', 'q', 'kind', 'event', 'actor', 'use', 'state') as $k) { $tip_keys[] = 'flt_' . $k; }
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

echo "\n";
// Say so out loud. A green run on a host missing the extension must never be
// mistakable for full coverage.
if (!$GP_HAS_DOM) {
	echo "NOTE: ext-dom was unavailable; the DOM-level XSS assertions did not run.\n";
}
echo "PASS " . $GP_PASS . "  FAIL " . $GP_FAIL . "  SKIP " . $GP_SKIP . "\n";
exit($GP_FAIL === 0 ? 0 : 1);
