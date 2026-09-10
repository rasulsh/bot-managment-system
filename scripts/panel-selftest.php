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
$GLOBALS['gp_test_panel_cfg'] = array('session_secret' => $sec);
// gp_csrf_token reads the real panel config; without one installed it returns
// an empty string, which must never validate.
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
// Say so out loud. A green run on a host missing the extension must never be
// mistakable for full coverage.
if (!$GP_HAS_DOM) {
	echo "NOTE: ext-dom was unavailable; the DOM-level XSS assertions did not run.\n";
}
echo "PASS " . $GP_PASS . "  FAIL " . $GP_FAIL . "  SKIP " . $GP_SKIP . "\n";
exit($GP_FAIL === 0 ? 0 : 1);
