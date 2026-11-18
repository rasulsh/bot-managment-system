<?php
// Bot Guard admin panel - front controller.
//
// Session check, routing and dispatch. Every route is listed here explicitly;
// there is no dynamic include of a path derived from the request.
declare(strict_types=0);

if (PHP_VERSION_ID < 80000) {
	http_response_code(500);
	header('Content-Type: text/plain; charset=utf-8');
	echo 'Bot Guard panel requires PHP 8.0 or newer (found ' . PHP_VERSION . ").\n";
	exit;
}

define('GP_BOOT', 1);

require_once __DIR__ . '/config_io.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/data.php';
require_once __DIR__ . '/jobs.php';
require_once __DIR__ . '/replay.php';

$GP_LANG = require __DIR__ . '/lang.php';

// Translate one key. Missing keys render as the key itself rather than blank,
// so a typo is visible instead of silently producing an empty label.
function gp_t($key) {
	global $GP_LANG;
	return isset($GP_LANG[$key]) ? $GP_LANG[$key] : $key;
}

// --------------------------------------------------------------------------
// Headers
// --------------------------------------------------------------------------

// The hardening headers shared by every panel response, minus Content-Type so
// each caller sets its own (text/html for pages, text/csv for the log export).
function gp_hardening_headers() {
	if (headers_sent()) { return; }
	header('X-Content-Type-Options: nosniff');
	header('Referrer-Policy: no-referrer');
	header('X-Frame-Options: DENY');
	// Keep every panel response out of search results. Together with the robots
	// meta tag in layout.php; robots.txt is deliberately NOT used (see
	// docs/09-ADMIN-PANEL.md): it would announce the panel's URL and stop crawlers
	// from ever reading this header.
	header('X-Robots-Tag: noindex, nofollow, noarchive, nosnippet');
	header('Cache-Control: no-store, no-cache, must-revalidate');
	// 'unsafe-inline' for scripts is required because every enhancement in this
	// panel is a small inline block - there is no bundler and no external JS.
	header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; "
		. "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; "
		. "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
}

function gp_send_headers() {
	if (headers_sent()) { return; }
	header('Content-Type: text/html; charset=utf-8');
	gp_hardening_headers();
}

// A bare 404 with no body. Used when the panel is not installed, so nothing
// hints that a panel exists at this path at all.
function gp_bare_404() {
	if (!headers_sent()) {
		http_response_code(404);
		header('Content-Type: text/plain; charset=utf-8');
		header('X-Robots-Tag: noindex, nofollow');
	}
	exit;
}

// --------------------------------------------------------------------------
// Boot
// --------------------------------------------------------------------------

$gp_cfg = gp_panel_config();
if ($gp_cfg === null) {
	// No credentials installed: the panel does not exist as far as the web is
	// concerned. Run php panel/setpass.php to install it.
	gp_bare_404();
}

if (!gp_ip_allowed($gp_cfg)) {
	gp_send_headers();
	http_response_code(403);
	echo '<!doctype html><html lang="en" dir="ltr"><meta charset="utf-8"><body>'
		. gp_e(gp_t('login_ip_blocked')) . '</body></html>';
	exit;
}

$gp_route = (isset($_GET['r']) && is_string($_GET['r'])) ? $_GET['r'] : 'dashboard';
$gp_user = gp_current_user();
$gp_flash = array();          // array of array(kind, message)
gp_flash_load_from_cookie();  // pick up any flash left by the previous redirect
$gp_post = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';

function gp_flash($kind, $message) {
	global $gp_flash;
	$gp_flash[] = array('kind' => $kind, 'message' => $message);
}

// Persist any pending flashes into a short-lived signed cookie (gp_flash_encode
// lives in auth.php). SameSite=Strict like the session and csrf cookies, so it
// rides the same-site 303 and is never sent cross-site.
function gp_flash_save_to_cookie() {
	global $gp_flash, $gp_cfg;
	if (headers_sent() || empty($gp_flash)) { return; }
	$secret = isset($gp_cfg['session_secret']) ? (string)$gp_cfg['session_secret'] : '';
	$value = gp_flash_encode($gp_flash, $secret);
	if ($value === '') { return; }
	setcookie(GP_FLASH_COOKIE, $value, array(
		'expires'  => time() + 30,
		'path'     => gp_cookie_path(),
		'secure'   => gp_is_https(),
		'httponly' => true,
		'samesite' => 'Strict',
	));
}

// Merge flashes left by the previous request, then expire the cookie at once so
// a message is shown exactly once. Any verification failure is ignored silently.
function gp_flash_load_from_cookie() {
	global $gp_flash, $gp_cfg;
	$raw = isset($_COOKIE[GP_FLASH_COOKIE]) ? (string)$_COOKIE[GP_FLASH_COOKIE] : '';
	if ($raw === '') { return; }
	gp_flash_clear_cookie();
	$secret = isset($gp_cfg['session_secret']) ? (string)$gp_cfg['session_secret'] : '';
	foreach (gp_flash_decode($raw, $secret) as $entry) {
		$gp_flash[] = $entry;
	}
}

function gp_flash_clear_cookie() {
	if (headers_sent()) { return; }
	setcookie(GP_FLASH_COOKIE, '', array(
		'expires'  => time() - 3600,
		'path'     => gp_cookie_path(),
		'secure'   => gp_is_https(),
		'httponly' => true,
		'samesite' => 'Strict',
	));
}

function gp_redirect($route, $extra = array()) {
	$query = array_merge(array('r' => $route), $extra);
	$url = 'index.php?' . http_build_query($query);
	gp_flash_save_to_cookie();                 // carry any pending flash across the 303
	if (!headers_sent()) { header('Location: ' . $url, true, 303); }
	exit;
}

// Render a view inside the layout. $view is a fixed name from the route table,
// never anything derived from the request.
function gp_render($view, array $vars = array()) {
	global $gp_user, $gp_flash, $gp_route;
	$vars['user'] = $gp_user;
	$vars['flash'] = $gp_flash;
	$vars['route'] = $gp_route;
	$vars['view_file'] = __DIR__ . '/views/' . $view . '.php';
	gp_send_headers();
	extract($vars, EXTR_SKIP);
	require __DIR__ . '/views/layout.php';
	exit;
}

// --------------------------------------------------------------------------
// Login and logout
// --------------------------------------------------------------------------

if ($gp_route === 'login') {
	if ($gp_user !== null) { gp_redirect('dashboard'); }
	if ($gp_post) {
		$result = gp_login_attempt($_POST['username'] ?? '', $_POST['password'] ?? '');
		if ($result[0]) { gp_redirect('dashboard'); }
		gp_flash('error', gp_t($result[1]));
	}
	gp_render('login');
}

if ($gp_route === 'logout') {
	if ($gp_user !== null && gp_csrf_check($_POST['csrf'] ?? '')) {
		gp_logout($gp_user);
	}
	gp_redirect('login');
}

// --------------------------------------------------------------------------
// Everything below requires a session
// --------------------------------------------------------------------------

if ($gp_user === null) {
	gp_redirect('login');
}

// State-changing routes are POST only and must carry the CSRF token. A GET
// never changes state anywhere in this panel.
if ($gp_post && !gp_csrf_check($_POST['csrf'] ?? '')) {
	gp_flash('error', gp_t('err_csrf'));
	$gp_post = false;
	$_POST = array();
}

$gp_ip = gp_client_ip();

switch ($gp_route) {

	case 'dashboard':
		if ($gp_post && isset($_POST['killswitch'])) {
			$stop = $_POST['killswitch'] === 'stop';
			if (gp_killswitch_set($stop)) {
				gp_audit_append(array('event' => 'killswitch', 'actor' => $gp_user,
					'ip' => $gp_ip, 'key' => 'guard.off',
					'old' => $stop ? false : true, 'new' => $stop ? true : false));
			} else {
				// The emergency button did nothing (the project directory is not
				// writable by PHP). Saying so is the whole point of the button.
				gp_flash('error', gp_t('write_failed'));
			}
			gp_redirect('dashboard');
		}
		gp_render('dashboard', array(
			'snapshot' => gp_snapshot(),
			'cfg'      => gv_cfg_load(),
			'kill'     => gp_killswitch_on(),
			'redis_up' => gp_redis_up(),
			'health'   => gp_guard_health(),
			'rinfo'    => gp_redis_info(),
			'exposed'  => gp_exposure_warning(),
			'pipeline' => gp_pipeline_status(),
			'ip_open'  => empty($gp_cfg['ip_allowlist']),
		));

	case 'logs':
		$filter = gp_logs_filter_from_request();
		$page = gp_log_query($filter, (int)($_GET['cursor'] ?? 0),
			(int)($_GET['limit'] ?? 50));
		if (($_GET['export'] ?? '') === 'csv') {
			gp_logs_export_csv($page[0]);
		}
		gp_render('logs', array(
			'filter' => $filter, 'rows' => $page[0], 'meta' => $page[1],
			'dates' => gp_log_dates(),
			'pipeline' => $page[0] ? null : gp_pipeline_status(),
		));

	case 'identity':
		$identity = (string)($_GET['id'] ?? '');
		if ($gp_post && isset($_POST['override'])) {
			gp_handle_override_post($gp_user, $gp_ip);
			gp_redirect('identity', array('id' => $identity));
		}
		gp_render('identity', array(
			'identity' => $identity,
			'verdicts' => $identity !== '' ? gp_identity_verdicts($identity) : array(),
			'rows'     => $identity !== '' ? gp_identity_rows($identity) : array(),
			'redis_up' => gp_redis_up(),
		));

	case 'overrides':
		if ($gp_post) {
			gp_handle_override_post($gp_user, $gp_ip);
			gp_redirect('overrides');
		}
		gp_render('overrides', array(
			'items'    => gp_overrides_list(),
			'redis_up' => gp_redis_up(),
		));

	case 'replay':
		$params = gp_replay_params_from_request();
		$result = null;
		if (($_GET['run'] ?? '') === '1' || $gp_post) {
			$result = gp_replay_run($params);
		}
		if ($gp_post && ($_POST['action'] ?? '') === 'apply') {
			$save = gp_config_save(gp_replay_overlay_from_params($params), $gp_user, $gp_ip);
			gp_flash($save['ok'] ? 'ok' : 'error',
				$save['ok'] ? gp_t('rep_applied') : gp_t('set_invalid'));
		}
		if ($gp_post && ($_POST['action'] ?? '') === 'full') {
			$job = gp_job_enqueue('replay_full',
				array('days' => $params['days'], 'set' => gp_replay_overlay_from_params($params)),
				$gp_user);
			gp_flash($job['ok'] ? 'ok' : 'error',
				$job['ok'] ? gp_t('job_enqueued') : gp_t('job_needs_redis'));
		}
		gp_render('replay', array('params' => $params, 'result' => $result,
			'cfg' => gv_cfg_load(), 'dates' => gp_log_dates()));

	case 'models':
		if ($gp_post) {
			$type = (string)($_POST['job'] ?? '');
			$job = gp_job_enqueue($type, array('days' => 7), $gp_user);
			gp_flash($job['ok'] ? 'ok' : 'error',
				$job['ok'] ? gp_t('job_enqueued') : ($job['error'] ?? gp_t('err_generic')));
			gp_redirect('models');
		}
		gp_render('models', array('models' => gp_model_status()));

	case 'settings':
		$pending = gp_settings_from_request();
		if ($gp_post && ($_POST['action'] ?? '') === 'save') {
			$save = gp_config_save($pending, $gp_user, $gp_ip);
			if ($save['ok']) {
				gp_flash('ok', $save['applied'] ? gp_t('set_saved') : gp_t('set_nochange'));
				gp_redirect('settings');
			}
			gp_flash('error', gp_t(isset($save['errors']['_write']) ? 'write_failed' : 'set_invalid'));
		}
		if ($gp_post && ($_POST['action'] ?? '') === 'reset' && isset($_POST['key'])) {
			$reset_key = is_string($_POST['key']) ? $_POST['key'] : '';
			if (!gp_config_reset($reset_key, $gp_user, $gp_ip)) { gp_flash('error', gp_t('write_failed')); }
			gp_redirect('settings');
		}
		gp_render('settings', array(
			'cfg'     => gv_cfg_load(),
			'overlay' => gp_overlay_current(),
			'errors'  => isset($save) ? $save['errors'] : array(),
			'pending' => $gp_post ? $pending : array(),
			'diff'    => $gp_post ? gp_overlay_diff($pending) : array(),
		));

	case 'audit':
		gp_render('audit', array(
			'entries' => gp_audit_read(200, (string)($_GET['q'] ?? '')),
			'query'   => (string)($_GET['q'] ?? ''),
		));

	case 'jobs':
		if ($gp_post) {
			$job = gp_job_enqueue((string)($_POST['job'] ?? ''), array('days' => 7), $gp_user);
			gp_flash($job['ok'] ? 'ok' : 'error',
				$job['ok'] ? gp_t('job_enqueued') : ($job['error'] ?? gp_t('err_generic')));
			gp_redirect('jobs');
		}
		gp_render('jobs', array('jobs' => gp_job_list(), 'redis_up' => gp_redis_up()));
}

// Unknown route: a small, honest 404. Rendering the dashboard under a 404
// status both masked the status and did work the request never asked for.
gp_send_headers();
http_response_code(404);
echo '<!doctype html><html lang="en" dir="ltr"><meta charset="utf-8">'
	. '<title>404</title><body style="font-family:sans-serif;padding:2rem">'
	. gp_e(gp_t('err_notfound')) . ' '
	. '<a href="index.php?r=dashboard">' . gp_e(gp_t('nav_dashboard')) . '</a>'
	. '</body></html>';
exit;

// --------------------------------------------------------------------------
// Request helpers
// --------------------------------------------------------------------------

// Read the log filter set out of the query string, typed and bounded.
function gp_logs_filter_from_request() {
	$get = $_GET;
	$out = array();
	foreach (array('date', 'act', 'ovr', 'tok', 'dev', 'ip', 'path', 'reason', 'status') as $key) {
		$value = isset($get[$key]) ? trim((string)$get[$key]) : '';
		if ($value !== '') { $out[$key] = substr($value, 0, 200); }
	}
	foreach (array('sh', 'hold') as $key) {
		if (isset($get[$key]) && $get[$key] !== '') { $out[$key] = (int)$get[$key]; }
	}
	foreach (array('sc_min', 'sc_max', 'esc_min', 'esc_max') as $key) {
		if (isset($get[$key]) && $get[$key] !== '') { $out[$key] = (int)$get[$key]; }
	}
	return $out;
}

// Stream the current page as CSV - only the rows the log view is showing, not
// the whole filter. The export link label and its title say so (logs_export /
// logs_export_hint); a full-filter streaming export is out of scope under the
// existing scan-byte caps. Values are quoted and CSV-escaped by fputcsv;
// nothing here is interpolated into HTML.
function gp_logs_export_csv(array $rows) {
	if (!headers_sent()) {
		header('Content-Type: text/csv; charset=utf-8');
		header('Content-Disposition: attachment; filename="guard-logs.csv"');
		// The same hardening headers as every other panel response (nosniff,
		// X-Frame-Options, Referrer-Policy, Cache-Control, CSP); the CSV
		// Content-Type set above is preserved because the helper never sets one.
		gp_hardening_headers();
	}
	$out = fopen('php://output', 'w');
	fwrite($out, "\xEF\xBB\xBF");     // BOM so spreadsheets read UTF-8
	$cols = array('ts', 'rid', 'ip', 'dev', 'm', 'p', 'q', 'act', 'sh', 'hold', 'ovr',
		'tok', 'sc', 'esc', 'rs', 'rep', 'ml', 'clf', 'botv', 'st', 'by', 'dur');
	fputcsv($out, $cols);
	foreach ($rows as $row) {
		$line = array();
		foreach ($cols as $col) {
			if (in_array($col, array('st', 'by', 'dur'), true)) {
				$line[] = isset($row['_out'][$col]) ? $row['_out'][$col] : '';
			} elseif ($col === 'rs') {
				$line[] = implode(' ', isset($row['rs']) && is_array($row['rs']) ? $row['rs'] : array());
			} else {
				$line[] = isset($row[$col]) ? (is_array($row[$col]) ? json_encode($row[$col]) : $row[$col]) : '';
			}
		}
		// A cell that starts with = + - @ is a formula to a spreadsheet, and the
		// path and query columns are whatever a visitor typed. Neutralise it.
		foreach ($line as $i => $cell) {
			if (is_string($cell) && $cell !== '' && strpos("=+-@\t\r", $cell[0]) !== false) {
				$line[$i] = "'" . $cell;
			}
		}
		fputcsv($out, $line);
	}
	fclose($out);
	exit;
}

// Add, extend or clear an override from either the overrides page or the
// identity page. Every write is audited.
function gp_handle_override_post($user, $ip) {
	$action = (string)($_POST['override'] ?? '');
	$identity = trim((string)($_POST['identity'] ?? ''));
	$ttl = (int)($_POST['ttl'] ?? 3600);
	if ($identity === '') { return; }

	if ($action === 'clear') {
		if (gp_override_clear($identity)) {
			gp_audit_append(array('event' => 'override_clear', 'actor' => $user,
				'ip' => $ip, 'key' => $identity, 'old' => null, 'new' => null));
			gp_flash('ok', gp_t('ovr_cleared'));
		}
		return;
	}
	if ($action === 'allow' || $action === 'deny') {
		if (gp_override_set($action, $identity, $ttl)) {
			gp_audit_append(array('event' => 'override_' . $action, 'actor' => $user,
				'ip' => $ip, 'key' => $identity, 'old' => null,
				'new' => array('ttl' => $ttl)));
			gp_flash('ok', gp_t('ovr_added'));
		} else {
			gp_flash('error', gp_t('err_generic'));
		}
	}
}

// Read the settings form into a proposed overlay. Types are coerced here so
// gv_overlay_validate() sees the right shapes; anything invalid is refused
// there, never clamped.
function gp_settings_from_request() {
	$post = $_POST;
	$out = array();
	$bools = array('enforce.block', 'enforce.challenge', 'enforce.ratelimit',
		'signals.reputation', 'signals.ml', 'signals.clf', 'capture_outcomes', 'challenge.gate_post');
	foreach ($bools as $key) {
		if (!isset($post['present'][$key])) { continue; }
		$out[$key] = !empty($post['f'][$key]);
	}
	$ints = array('hard_block_score', 'limits.window', 'limits.device', 'limits.ip_ua',
		'limits.ip', 'limits.bot', 'limits.mint', 'limits.device_hour', 'limits.device_day',
		'limits.preview', 'limits.bot_unverified', 'challenge.pow_bits', 'holdout_pct');
	foreach ($ints as $key) {
		if (!isset($post['f'][$key]) || $post['f'][$key] === '') { continue; }
		$raw = trim((string)$post['f'][$key]);
		// A non-numeric string must reach the validator as a string so it is
		// refused by name, not silently cast to 0.
		$out[$key] = preg_match('/^-?\d+$/', $raw) ? (int)$raw : $raw;
	}
	foreach (array('ml_weight', 'clf_weight') as $key) {
		if (!isset($post['f'][$key]) || $post['f'][$key] === '') { continue; }
		$raw = trim((string)$post['f'][$key]);
		$out[$key] = is_numeric($raw) ? (float)$raw : $raw;
	}
	if (isset($post['f']['honeypot_path'])) {
		$out['honeypot_path'] = trim((string)$post['f']['honeypot_path']);
	}
	foreach (array('exempt_paths', 'known_bots', 'preview_bots') as $key) {
		if (!isset($post['f'][$key])) { continue; }
		$out[$key] = gp_lines_to_list((string)$post['f'][$key]);
	}
	if (isset($post['f']['exempt_params'])) {
		$out['exempt_params'] = gp_parse_params((string)$post['f']['exempt_params']);
	}
	return $out;
}

function gp_lines_to_list($text) {
	$out = array();
	foreach (preg_split('/[\r\n]+/', $text) as $line) {
		$line = trim($line);
		if ($line !== '') { $out[] = $line; }
	}
	return $out;
}

// One "name: value, value" pair per line.
function gp_parse_params($text) {
	$out = array();
	foreach (preg_split('/[\r\n]+/', $text) as $line) {
		$line = trim($line);
		if ($line === '' || strpos($line, ':') === false) { continue; }
		list($name, $values) = explode(':', $line, 2);
		$name = trim($name);
		if ($name === '') { continue; }
		$list = array();
		foreach (explode(',', $values) as $value) {
			$value = trim($value);
			if ($value !== '') { $list[] = $value; }
		}
		$out[$name] = $list;
	}
	return $out;
}
