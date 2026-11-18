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
	array('challenge.bind_ip', false, false),
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
