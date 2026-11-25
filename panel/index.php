<?php
// Bot Guard admin panel - front controller.
//
// Session check, routing and dispatch. Every route is listed here explicitly;
// there is no dynamic include of a path derived from the request.
declare(strict_types=0);

if (PHP_VERSION_ID < 80000) {
	http_response_code(500);
	header('Content-Type: text/plain; charset=utf-8');
	header('X-LiteSpeed-Cache-Control: no-cache');
	echo 'Bot Guard panel requires PHP 8.0 or newer (found ' . PHP_VERSION . ").\n";
	exit;
}

define('GP_BOOT', 1);

require_once __DIR__ . '/config_io.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/acl.php';
require_once __DIR__ . '/demo.php';
require_once __DIR__ . '/data.php';
require_once __DIR__ . '/jobs.php';
require_once __DIR__ . '/update.php';
require_once __DIR__ . '/replay.php';
require_once __DIR__ . '/filters.php';
require_once __DIR__ . '/ui.php';
require_once __DIR__ . '/reasons.php';
require_once __DIR__ . '/overrides.php';
require_once __DIR__ . '/live.php';
require_once __DIR__ . '/dash.php';
require_once __DIR__ . '/health.php';
require_once __DIR__ . '/geo.php';
require_once __DIR__ . '/rules.php';
require_once __DIR__ . '/iplists.php';
require_once __DIR__ . '/feeds.php';

$GP_LANG = require __DIR__ . '/lang.php';

// Translate one key. Missing keys render as the key itself rather than blank,
// so a typo is visible instead of silently producing an empty label.
function gp_t($key) {
	global $GP_LANG;
	return isset($GP_LANG[$key]) ? $GP_LANG[$key] : $key;
}

gp_note_panel_prefix();       // see panel/data.php

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
	// LiteSpeed's page cache (LSCache) must never keep a panel page: it caches on its own header, not on Cache-Control. Every panel
	// response carries this (the versioned static assets are the only cacheable thing, and they are served by the web server itself).
	header('X-LiteSpeed-Cache-Control: no-cache');
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
		header('Cache-Control: no-store');
		header('X-LiteSpeed-Cache-Control: no-cache');
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
$gp_role = gp_current_role();      // '' when nobody is signed in
$gp_flash = array();          // array of array(kind, message)
gp_flash_load_from_cookie();  // pick up any flash left by the previous redirect
$gp_post = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';
$gp_section = ($gp_post && gp_section_valid(gp_post_section($gp_route, $_POST))) ? gp_post_section($gp_route, $_POST) : '';   // where this POST's messages go

// $section: the page section the message belongs to (default: the section of the POST action being handled, see gp_post_section).
function gp_flash($kind, $message, $section = null) {
	global $gp_flash, $gp_section;
	$e = array('kind' => $kind, 'message' => $message);
	$sec = $section === null ? (string)$gp_section : (string)$section;
	if ($sec !== '') { $e['section'] = $sec; }
	$gp_flash[] = $e;
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
	// Back to the section that was acted on, so the message is on screen (same page only).
	global $gp_flash, $gp_route;
	if ($route === $gp_route && !empty($gp_flash)) {
		foreach (array_reverse($gp_flash) as $m) { if (!empty($m['section'])) { $url .= '#msg-' . $m['section']; break; } }
	}
	gp_flash_save_to_cookie();                 // carry any pending flash across the 303
	if (!headers_sent()) { header('Cache-Control: no-store'); header('X-LiteSpeed-Cache-Control: no-cache'); header('Location: ' . $url, true, 303); }
	exit;
}

// Render a view inside the layout. $view is a fixed name from the route table,
// never anything derived from the request.
function gp_render($view, array $vars = array()) {
	global $gp_user, $gp_role, $gp_flash, $gp_route;
	$vars['user'] = $gp_user;
	$vars['role'] = $gp_role;
	$vars['flash'] = ($view === 'login') ? array() : $gp_flash;   // login draws its own message in the card
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
	$gp_login_msg = '';
	if ($gp_post && gp_panel_config() !== null && !gp_login_csrf_check($_POST['csrf'] ?? '')) {
		// A POST without the cookie and its matching field (a cross-site form, an expired page): not an attempt, nothing is counted.
		$gp_login_msg = gp_t('login_csrf');
		$gp_post = false;
	}
	if ($gp_post) {
		$result = gp_login_attempt($_POST['username'] ?? '', $_POST['password'] ?? '');
		if ($result[0]) { gp_redirect('dashboard'); }
		// The message is drawn inside the login card, not by the layout.
		$gp_login_msg = $result[1] === 'login_locked'
			? sprintf(gp_t('login_locked'), max(1, (int)ceil(((int)($result[2] ?? 0)) / 60)))
			: gp_t($result[1]);
		$gp_login_user = is_string($_POST['username'] ?? null) ? substr($_POST['username'], 0, 200) : '';
	}
	gp_render('login', array('login_msg' => $gp_login_msg ?? '', 'login_user' => $gp_login_user ?? '', 'login_csrf' => gp_login_csrf_issue()));
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

// Access control: ONE permission map (panel/acl.php), checked here for GET and POST BEFORE any handler runs. Deny by default:
// a route or POST action that is not in the map needs the admin role. A denied request gets HTTP 403 and an audit line.
$gp_method = (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') ? 'POST' : 'GET';
$gp_action = gp_acl_action($gp_route, $_POST);
if (!gp_acl_allows($gp_role, $gp_route, $gp_method, $gp_action)) {
	gp_audit_append(array('event' => 'acl_denied', 'actor' => $gp_user, 'ip' => gp_client_ip(), 'key' => substr($gp_route, 0, 60),
		'old' => null, 'new' => array('method' => $gp_method, 'action' => substr($gp_action, 0, 40), 'role' => $gp_role)));
	http_response_code(403);
	gp_render('forbidden');
}

// State-changing routes are POST only and must carry the CSRF token. A GET
// never changes state anywhere in this panel.
// A body larger than post_max_size arrives with NO post data at all. Decided here, before the CSRF gate empties $_POST itself: a request
// the CSRF check rejected is not also "an upload that was too big" (the page used to report both for the same request).
$gp_body_overflow = ($gp_post && empty($_POST) && empty($_FILES) && (int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 0);
if ($gp_post && !gp_csrf_check($_POST['csrf'] ?? '')) {
	if (!$gp_body_overflow) { gp_flash('error', gp_t('err_csrf')); }       // an over-size body has its own message (no token could arrive with it)
	$gp_post = false;
	$_POST = array();
}

$gp_ip = gp_client_ip();

switch ($gp_route) {

	case 'dashboard':
		// The Demo role gets a separate, data-minimised view model and nothing else (panel/demo.php).
		if ($gp_role === 'demo') { gp_render('demo', array('demo' => gp_demo_model())); }
		if ($gp_post && isset($_POST['killswitch'])) {
			$stop = $_POST['killswitch'] === 'stop';
			// Stopping all protection takes a confirmation step: the form that carries confirm=1 is only drawn by the confirmation state.
			if ($stop && (($_POST['confirm'] ?? '') !== '1')) { gp_redirect('dashboard', array('kill_confirm' => 1)); }
			if (gp_killswitch_set($stop)) {
				gp_audit_append(array('event' => 'killswitch', 'actor' => $gp_user,
					'ip' => $gp_ip, 'key' => 'guard.off',
					'old' => $stop ? false : true, 'new' => $stop ? true : false));
				gp_flash($stop ? 'warn' : 'ok', gp_t($stop ? 'dash_kill_stopped' : 'dash_kill_started'));
			} else {
				// The emergency button did nothing (the project directory is not
				// writable by PHP). Saying so is the whole point of the button.
				gp_flash('error', gp_t('write_failed'));
			}
			gp_redirect('dashboard');
		}
		$hin = gp_health_inputs();
		$hjobs = $hin['jobs'];
		$hcfg = gv_cfg_load();
		$hrules = gp_rules_state();
		$hlists = gp_iplists_state()['lists'];
		gp_render('dashboard', array(
			'snapshot' => $hin['snapshot'], 'clf_labels' => gp_clf_labels(),
			'cfg'      => $hcfg,
			'kill'     => gp_killswitch_on(),
			'kill_confirm' => (($_GET['kill_confirm'] ?? '') === '1'),
			'redis_up' => $hin['redis_up'],
			'health'   => gp_guard_health(),
			'rinfo'    => gp_redis_info(),
			'exposed'  => $hin['exposed'],
			'pipeline' => gp_pipeline_status(),
			'storage'  => $hin['storage'],
			'ip_open'  => empty($gp_cfg['ip_allowlist']),
			'geo_warn' => $hin['geo_warn'],
			'alerts'   => gp_health_alerts($hin),
			'jobs'     => $hjobs,
			'queue'    => $hin['queue'],
			'cron'     => $hin['cron'],
			'cron_card' => gp_cron_card_needed($hjobs, $hin['cron']),
			'cron_lines' => gp_cron_setup_lines($hjobs, $hin['cron']),
			'protection' => gp_protection_mode($hcfg, $hrules['rules']),
			'rsum'     => gp_rules_summary($hrules['rules']),
			'isum'     => gp_iplists_summary($hlists),
			'rules'    => $hrules['rules'],
			'iplists'  => $hlists,
			'geo'      => gp_geo_status(),
			'feeds'    => $hin['feeds'],
			'perms'    => $hin['perms'],
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

	case 'live':
		// The Live requests page. Read only: the log is tailed from a byte-offset cursor, no Redis, no writes. ?poll=1 answers JSON
		// (a GET, never cached); anything else is the page. Operators and admins only (the ACL map): demo never gets here.
		if (($_GET['poll'] ?? '') === '1') {
			gp_hardening_headers();
			header('Content-Type: application/json; charset=utf-8');
			header('Cache-Control: no-store, no-cache, must-revalidate');
			$ans = gp_live_answer(gp_live_request_from_get($_GET));
			echo json_encode($ans, JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
			exit;
		}
		gp_render('live', array('req' => gp_live_request_from_get($_GET), 'dates' => gp_log_dates(), 'pipeline' => gp_pipeline_status()));

	case 'identity':
		$identity = (string)($_GET['id'] ?? '');
		if ($gp_post && isset($_POST['override'])) {
			gp_handle_override_post($gp_user, $gp_ip);
			gp_redirect('identity', array('id' => $identity));
		}
		$idfilter = gp_filter_parse($_GET, array('act' => 'choice', 'path' => 'text'));
		gp_render('identity', array(
			'filter'   => $idfilter,
			'identity' => $identity,
			'verdicts' => $identity !== '' ? gp_identity_verdicts($identity) : array(),
			'rows'     => $identity !== '' ? gp_identity_rows($identity, 60, $idfilter) : array(),
			// The allow-list overlap of a deny override reads the logs (the addresses a device was seen on): only when asked for (?shadow=1).
			'shadow'   => ($identity !== '' && ($_GET['shadow'] ?? '') === '1') ? gp_iplists_deny_shadow(array($identity)) : array(),
			'shadow_ran' => (($_GET['shadow'] ?? '') === '1'),
			'redis_up' => gp_redis_up(),
		));

	case 'overrides':
		if ($gp_post) {
			gp_handle_override_post($gp_user, $gp_ip);
			// A quick action returns to the page it was pressed on (Logs, Identity, Live).
			$qb = (($_POST['from'] ?? '') === 'quick') ? gp_quick_back($_POST['back'] ?? '') : null;
			if ($qb !== null) { gp_redirect($qb[0], $qb[1]); }
			gp_redirect('overrides');
		}
		$ofilter = gp_filter_parse($_GET, array('kind' => 'choice', 'identity' => 'ident'));
		$onew = is_string($_GET['new'] ?? null) ? substr(trim($_GET['new']), 0, 128) : '';
		gp_render('overrides', array(
			'new_identity' => preg_match('/^[A-Za-z0-9._:-]*$/', $onew) ? $onew : '',
			'filter'   => $ofilter,
			'items_all' => $oall = gp_overrides_list(),
			'items'    => gp_overrides_filter($oall, $ofilter),
			'shadow'   => gp_iplists_deny_shadow(array_values(array_map(function ($i) { return $i['identity']; }, array_filter($oall, function ($i) { return $i['kind'] === 'deny'; })))),
			'redis_up' => gp_redis_up(),
		));

	case 'rules':
		$rcfg = gv_cfg_load();
		$draft = null;
		$errors = array();
		$details = array();
		$warnings = array();
		$impact = null;
		if ($gp_post && isset($_POST['do']) && is_string($_POST['do'])) {
			$res = gp_rules_action($_POST['do'], $_POST, $gp_user, $gp_ip, $rcfg);
			if ($res['ok']) {
				gp_flash('ok', gp_t($res['msg']), $res['msg'] === 'rule_saved' || $_POST['do'] === 'save' ? 'rules-list' : null);
				gp_redirect('rules');
			}
			gp_flash(in_array($res['msg'], array('rule_warnings', 'rule_preview'), true) ? 'warn' : 'error', gp_t($res['msg']));
			$draft = $res['draft'];
			$errors = $res['errors'];
			$details = $res['details'];
			$warnings = $res['warnings'];
			$impact = $res['impact'];
		}
		$rstate = gp_rules_state();
		if ($draft === null && isset($_GET['edit']) && is_string($_GET['edit'])) {
			foreach ($rstate['rules'] as $r) { if ($r['id'] === $_GET['edit']) { $draft = $r; } }
		}
		if ($draft === null && isset($_GET['new'])) {
			// "Quick block" from a log row passes the UA: a monitor-mode rule pre-filled from it.
			$draft = isset($_GET['qua']) && is_string($_GET['qua']) ? gp_rule_from_ua(substr($_GET['qua'], 0, 300)) : gp_rule_blank();
		}
		// Opening the form does NOT scan the logs any more (a 4 MiB read on a plain GET): the form has a button that adds ?impact=1.
		if ($impact === null && $draft !== null && !$gp_post && ($_GET['impact'] ?? '') === '1') {
			$pv = gv_rule_validate(array_merge($draft, array('id' => $draft['id'] === '' ? 'r-preview' : $draft['id'], 'name' => $draft['name'] === '' ? 'preview' : $draft['name'])), false);
			if ($pv[0]) { $impact = gp_rules_impact($pv[1]); }
		}
		$rfilter = gp_rules_filter_from_request($_GET);
		$rnow = time();
		$rvisible = array();
		foreach ($rstate['rules'] as $r) { if (gp_rules_filter_match($r, $rfilter, $rnow)) { $rvisible[] = $r; } }
		$test_in = array('ua' => is_string($_GET['test_ua'] ?? null) ? substr($_GET['test_ua'], 0, 500) : '',
			'path' => is_string($_GET['test_path'] ?? null) ? substr($_GET['test_path'], 0, 300) : '',
			'verified' => !empty($_GET['test_verified']),
			'ip' => is_string($_GET['test_ip'] ?? null) ? substr($_GET['test_ip'], 0, 45) : '');
		$rtest = (($_GET['test'] ?? '') === '1')
			? gp_rules_test($rstate['rules'], $test_in['ua'], $test_in['path'], $test_in['verified'], $rcfg, $rnow, $test_in['ip']) : null;
		gp_render('rules', array(
			'state' => $rstate, 'all' => $rstate['rules'], 'visible' => $rvisible, 'filter' => $rfilter,
			'draft' => $draft, 'errors' => $errors, 'details' => $details, 'warnings' => $warnings, 'impact' => $impact,
			'test' => $rtest, 'test_in' => $test_in, 'snapshot' => gp_snapshot(),
		));

	case 'geo':
		$gcfg = gv_cfg_load();
		if ($gp_post && isset($_POST['do']) && is_string($_POST['do'])) {
			$do = $_POST['do'];
			$r = array(false, 'err_generic', '');
			if ($do === 'upload') { $r = gp_geo_upload(isset($_FILES['source']) && is_array($_FILES['source']) ? $_FILES['source'] : array(), $gp_user, $gp_ip); }
			elseif ($do === 'compile') { $r = gp_geo_compile($gp_user); }
			elseif ($do === 'delete') { $r = gp_geo_delete_source(is_string($_POST['name'] ?? null) ? $_POST['name'] : '', $gp_user, $gp_ip); }
			elseif ($do === 'rollback') { $r = gp_geo_rollback(($_POST['kind'] ?? '') === 'asn' ? 'asn' : 'country', $gp_user, $gp_ip); }
			gp_flash($r[0] ? 'ok' : 'error', gp_t($r[1]) . ($r[2] !== '' ? ': ' . $r[2] : '') . ($do === 'upload' && $r[0] ? '. ' . gp_t('geo_up_next') : ''));
			gp_redirect('geo');
		}
		// A body larger than post_max_size arrives with no POST data at all (so no CSRF
		// token): tell the operator why instead of showing a bare "invalid token".
		if ($gp_body_overflow) {
			gp_flash('error', gp_t('geo_up_toobig'));
		}
		$gstate = gp_rules_state();
		$gtest_in = array('ip' => is_string($_GET['ip'] ?? null) ? substr($_GET['ip'], 0, 45) : '',
			'ua' => is_string($_GET['ua'] ?? null) ? substr($_GET['ua'], 0, 500) : '',
			'path' => is_string($_GET['path'] ?? null) ? substr($_GET['path'], 0, 300) : '',
			'verified' => !empty($_GET['verified']));
		$gstatus = gp_geo_status();
		$gfilter = gp_filter_parse($_GET, array('name' => 'text', 'use' => 'choice'));
		$gstatus['sources_all'] = count($gstatus['sources']);
		$gstatus['sources'] = gp_geo_filter_sources($gstatus['sources'], $gfilter);
		gp_render('geo', array(
			'filter' => $gfilter,
			'status' => $gstatus, 'cfg' => $gcfg, 'geo_rules' => gp_geo_rules_need($gstate['rules']),
			'test_in' => $gtest_in,
			'test' => (($_GET['test'] ?? '') === '1')
				? gp_geo_test($gtest_in['ip'], $gtest_in['ua'], $gtest_in['path'], $gtest_in['verified'], $gstate['rules'], $gcfg, time()) : null,
			'test_ran' => (($_GET['test'] ?? '') === '1'),
			'jobs' => array_slice(array_values(array_filter(gp_job_list(30), function ($j) { return ($j['type'] ?? '') === 'geo_compile'; })), 0, 5),
		));

	case 'iplists':
		if ($gp_post && isset($_POST['do']) && is_string($_POST['do'])) {
			$do = $_POST['do'];
			$r = array(false, 'err_generic', '');
			if (strncmp($do, 'feed_', 5) === 0) {
				// IP range feeds (panel/feeds.php). Fetching is a network call: allow it a minute.
				@set_time_limit(90);
				$fid = is_string($_POST['id'] ?? null) ? $_POST['id'] : '';
				if ($do === 'feed_save') {
					$fsv = gp_feed_save($_POST, $gp_user, $gp_ip);
					if ($fsv['ok']) { gp_flash('ok', gp_t($fsv['msg']) . ($fsv['detail'] !== '' ? ': ' . $fsv['detail'] : ''), 'feeds-list'); gp_redirect('iplists'); }
					gp_flash('error', gp_t($fsv['msg']));
					$feed_save = $fsv;
				} else {
					if ($do === 'feed_delete') { $r = gp_feed_delete($fid, $gp_user, $gp_ip); $r[0] && ($sec_override = 'feeds-list'); }
					elseif ($do === 'feed_accept_cap') { $r = gp_feed_accept_cap($fid, $gp_user, $gp_ip); }
					elseif ($do === 'feed_discard_hold') { $r = gp_feed_discard_hold($fid, $gp_user, $gp_ip); }
					elseif ($do === 'feed_update' || $do === 'feed_accept_hold') {
						$sr = gp_feed_sync($fid, $gp_user, $gp_ip, $do === 'feed_accept_hold' ? array('accept_hold' => true) : array());
						if ($sr['ok']) {
							$r = array(true, $sr['status'] === 'held' ? 'feed_upd_held' : ($sr['status'] === 'nochange' ? 'feed_upd_nochange' : 'feed_upd_applied'),
								sprintf(gp_t('feed_diff_line'), gp_num($sr['added']), gp_num($sr['removed']), gp_num($sr['unchanged'])));
						} else { $r = array(false, 'feed_upd_failed', gp_feed_error_text($sr['error'] . ($sr['detail'] !== '' ? ': ' . $sr['detail'] : ''))); }
					}
					gp_flash($r[0] ? ($r[1] === 'feed_upd_held' ? 'warn' : 'ok') : 'error', gp_t($r[1]) . ($r[2] !== '' ? ': ' . $r[2] : ''), isset($sec_override) ? $sec_override : null);
					gp_redirect('iplists');
				}
			} elseif ($do === 'save') {
				$sv = gp_iplists_save($_POST, isset($_FILES['file']) && is_array($_FILES['file']) ? $_FILES['file'] : null, $gp_user, $gp_ip);
				if ($sv['ok']) { gp_flash('ok', gp_t($sv['msg']) . ($sv['detail'] !== '' ? ': ' . $sv['detail'] : ''), 'ipl-lists'); gp_redirect('iplists'); }
				gp_flash($sv['msg'] === 'ipl_confirm' ? 'warn' : 'error', gp_t($sv['msg']) . ($sv['detail'] !== '' ? ': ' . $sv['detail'] : ''));
				$ipl_save = $sv;
			} else {
				if ($do === 'delete') { $r = gp_iplists_delete(is_string($_POST['id'] ?? null) ? $_POST['id'] : '', $gp_user, $gp_ip); }
				elseif ($do === 'set') { $r = gp_iplists_set($_POST, $gp_user, $gp_ip); }
				elseif ($do === 'compile') {
					$r = gp_iplists_compile_auto($gp_user, !empty($_POST['job']));
					gp_ipl_audit($gp_user, $gp_ip, 'compile', null, array('ok' => $r[0], 'result' => $r[1], 'job' => !empty($_POST['job'])));
				}
				elseif ($do === 'rollback') { $r = gp_iplists_rollback(($_POST['type'] ?? '') === 'block' ? 'block' : 'allow', $gp_user, $gp_ip); }
				gp_flash($r[0] ? 'ok' : 'error', gp_t($r[1]) . ($r[2] !== '' ? ': ' . $r[2] : ''));
				gp_redirect('iplists');
			}
		}
		if (($_GET['export'] ?? '') !== '' && is_string($_GET['export'])) {
			$ex = gp_iplists_export($_GET['export']);
			if ($ex[0] === null) { gp_flash('error', gp_t('ipl_not_found')); gp_redirect('iplists'); }
			gp_hardening_headers();
			header('Content-Type: text/plain; charset=utf-8');
			header('Content-Disposition: attachment; filename="' . $ex[0]['id'] . '.txt"');
			echo $ex[1];
			exit;
		}
		// A body larger than post_max_size arrives with no POST data at all (so no CSRF token).
		if ($gp_body_overflow) {
			gp_flash('error', gp_t('ipl_up_toobig'));
		}
		$istate = gp_iplists_state();
		$istatus = gp_iplists_status();
		$ifilter = gp_filter_parse($_GET, gp_iplists_filter_spec());
		$irows = gp_iplists_rows($istate['lists'], $istatus, gp_snapshot());
		$iedit = null;
		if (isset($ipl_save)) { $iedit = $ipl_save['draft']; }
		elseif (isset($_GET['edit']) && is_string($_GET['edit'])) { $iedit = gp_ipl_find($istate['lists'], $_GET['edit']); if ($iedit) { $iedit['text'] = ''; } }
		elseif (isset($_GET['new'])) { $iedit = array('id' => '', 'name' => '', 'type' => (($_GET['type'] ?? '') === 'allow' ? 'allow' : 'block'), 'mode' => 'monitor', 'enabled' => true, 'force' => false, 'note' => '', 'text' => ''); }
		$eid = isset($_GET['list']) && is_string($_GET['list']) ? $_GET['list'] : '';
		$efilter = gp_filter_parse($_GET, array('entry' => 'text', 'family' => 'choice'));
		$itest_ip = is_string($_GET['ip'] ?? null) ? substr($_GET['ip'], 0, 45) : '';
		$feed_draft = null;
		if (isset($feed_save)) { $feed_draft = $feed_save['draft']; }
		elseif (isset($_GET['edit_feed']) && is_string($_GET['edit_feed'])) { $feed_draft = gp_feed_find(gp_feeds_state()['feeds'], $_GET['edit_feed']); }
		elseif (isset($_GET['new_feed'])) {
			$feed_draft = gp_feed_blank();
			$pre = gp_feed_presets();
			if (is_string($_GET['preset'] ?? null) && isset($pre[$_GET['preset']])) { $feed_draft = array_merge($feed_draft, $pre[$_GET['preset']]); }
		}
		gp_render('iplists', array(
			'feeds_state' => gp_feeds_state(), 'feed_edit' => $feed_draft, 'feed_save' => isset($feed_save) ? $feed_save : null,
			'state' => $istate, 'status' => $istatus, 'all' => $irows, 'visible' => gp_iplists_filter_rows($irows, $ifilter), 'filter' => $ifilter,
			'edit' => $iedit, 'save' => isset($ipl_save) ? $ipl_save : null,
			'warnings' => gp_iplists_warnings_cached($istate['lists']),
			'pending' => gp_iplists_pending($istate, $istatus), 'health' => gp_iplists_health(),
			'eid' => $eid, 'efilter' => $efilter, 'entries' => $eid !== '' ? gp_iplists_entries($eid, $efilter) : array(array(), 0, 0, 0),
			'test_ip' => $itest_ip, 'test' => (($_GET['test'] ?? '') === '1') ? gp_iplists_test($itest_ip) : null, 'test_ran' => (($_GET['test'] ?? '') === '1'),
			'limit' => gp_geo_upload_limit(), 'jobs' => array_slice(array_values(array_filter(gp_job_list(30), function ($j) { return ($j['type'] ?? '') === 'iplist_compile'; })), 0, 5),
			'prev' => array('allow' => is_file(gv_iplist_file('allow') . '.prev'), 'block' => is_file(gv_iplist_file('block') . '.prev')),
		));

	case 'captcha_preview':
		// A sample CAPTCHA image for the Settings page, drawn with the values typed in the form (query string) over the
		// saved ones. Logged-in operators only (the session check above); nothing is saved and no answer is shown.
		$cv = gv_cfg_load();
		$pq = array();
		if (isset($_GET['level']) && is_string($_GET['level']) && ctype_digit($_GET['level'])) { $pq['level'] = (int)$_GET['level']; }
		if (isset($_GET['length']) && is_string($_GET['length']) && ctype_digit($_GET['length'])) { $pq['length'] = (int)$_GET['length']; }
		foreach (array('charset', 'warp', 'noise', 'overlap') as $pk) { if (isset($_GET[$pk]) && is_string($_GET[$pk])) { $pq[$pk] = $_GET[$pk]; } }
		$pp = gv_captcha_params(array('captcha' => array_merge($cv['captcha'], $pq)));
		$png = gv_captcha_available() ? gv_captcha_image(gv_captcha_answer($pp['length'], $pp['charset']), $pp) : '';
		gp_hardening_headers();
		if ($png === '') { http_response_code(204); exit; }
		header('Content-Type: image/png');
		header('Content-Length: ' . strlen($png));
		echo $png;
		exit;

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
		gp_render('models', array('models' => gp_model_status(), 'clf_labels' => gp_clf_labels()));

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
			'cfg'     => gp_effective_config(),
			'overlay' => gp_overlay_current(),
			'errors'  => isset($save) ? $save['errors'] : array(),
			'pending' => $gp_post ? $pending : array(),
			'diff'    => $gp_post ? gp_overlay_diff($pending) : array(),
		));

	case 'config_file':
		$cf_text = null;
		$cf_check = null;
		if ($gp_post && ($_POST['action'] ?? '') === 'save_file') {
			$cf_text = is_string($_POST['content'] ?? null) ? $_POST['content'] : '';
			$cf_check = gp_overlay_file_save($cf_text, (string)($_POST['base_hash'] ?? ''), $gp_user, $gp_ip);
			if ($cf_check['ok']) {
				gp_flash('ok', $cf_check['changed'] ? gp_t('cf_saved') : gp_t('set_nochange'));
				gp_redirect('config_file');
			}
			gp_flash('error', gp_t('cf_not_saved'));
		}
		$cf_backup = is_string($_GET['backup'] ?? null) ? $_GET['backup'] : '';
		$cf_from_backup = false;
		if ($cf_text === null && $cf_backup !== '') {
			$cf_text = gp_overlay_backup_read($cf_backup);
			$cf_from_backup = $cf_text !== null;
		}
		$cf_current = gp_overlay_file_raw();
		gp_render('config_file', array(
			'text'        => $cf_text === null ? $cf_current : $cf_text,
			'base_hash'   => $cf_check !== null && isset($_POST['base_hash']) && is_string($_POST['base_hash'])
				? $_POST['base_hash'] : hash('sha256', $cf_current),
			'check'       => $cf_check,
			'from_backup' => $cf_from_backup ? $cf_backup : '',
			'backups'     => gp_overlay_backups(),
			'path'        => gv_overlay_path(),
		));

	case 'users':
		// Admin only (the ACL above). Every action audits actor, target, before / after; never a password hash.
		if ($gp_post) {
			$do = is_string($_POST['do'] ?? null) ? $_POST['do'] : '';
			$target = is_string($_POST['username'] ?? null) ? $_POST['username'] : '';
			$pw = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
			$r = array(false, 'err_generic');
			if ($do === 'create') { $r = gp_users_create($gp_user, $target, is_string($_POST['role'] ?? null) ? $_POST['role'] : '', $pw); }
			elseif ($do === 'role') { $r = gp_users_set_role($gp_user, $target, is_string($_POST['role'] ?? null) ? $_POST['role'] : ''); }
			elseif ($do === 'enable') { $r = gp_users_set_enabled($gp_user, $target, true); }
			elseif ($do === 'disable') { $r = gp_users_set_enabled($gp_user, $target, false); }
			elseif ($do === 'reset') { $r = gp_users_reset_password($gp_user, $target, $pw); }
			elseif ($do === 'delete') { $r = gp_users_delete($gp_user, $target); }
			elseif ($do === 'unlock') {
				// Clear a sign-in lockout (admin only, like everything on this page): a name, an address, or every counter.
				$ul_user = is_string($_POST['unlock_user'] ?? null) ? gp_users_norm(substr($_POST['unlock_user'], 0, 64)) : '';
				$ul_ip = is_string($_POST['unlock_ip'] ?? null) ? trim(substr($_POST['unlock_ip'], 0, 64)) : '';
				$ul_all = !empty($_POST['unlock_all']);
				if ($ul_ip !== '' && filter_var($ul_ip, FILTER_VALIDATE_IP) === false) { $r = array(false, 'usr_err_unlock_ip'); }
				elseif (!$ul_all && $ul_user === '' && $ul_ip === '') { $r = array(false, 'usr_err_unlock_none'); }
				else {
					$cleared = gp_login_unlock($ul_user, $ul_ip !== '' ? gv_ip_canon($ul_ip) : '', $ul_all);
					gp_audit_append(array('event' => 'login_unlock', 'actor' => $gp_user, 'ip' => $gp_ip, 'key' => $ul_all ? 'all' : trim($ul_user . ' ' . $ul_ip),
						'old' => null, 'new' => array('cleared' => $cleared)));
					$r = array(true, '');
				}
			}
			gp_flash($r[0] ? 'ok' : 'error', $r[0] ? gp_t('usr_done_' . $do) : gp_t($r[1]));
			gp_redirect('users');
		}
		$ust = gp_users_state();
		$ufilter = gp_filter_parse($_GET, array('role' => 'choice', 'enabled' => 'choice', 'q' => 'text'));
		$urows = array();
		foreach ($ust['users'] as $u) {
			if (isset($ufilter['role']) && !gp_filter_test('choice', $ufilter['role'], $u['role'])) { continue; }
			if (isset($ufilter['enabled']) && !gp_filter_test('choice', $ufilter['enabled'], $u['enabled'] ? 'yes' : 'no')) { continue; }
			if (isset($ufilter['q']) && !gp_filter_test('text', $ufilter['q'], $u['username'])) { continue; }
			unset($u['password_hash']);
			$urows[] = $u;
		}
		usort($urows, function ($a, $b) { return strcmp($a['username'], $b['username']); });
		gp_render('users', array('locks' => gp_login_lock_state(), 'users' => $urows, 'all_count' => count($ust['users']), 'filter' => $ufilter, 'state' => $ust, 'me' => $gp_user));

	case 'account':
		// Any role: change your OWN password (the current one is required). Other sessions of the user end; this one is reissued.
		if ($gp_post && ($_POST['do'] ?? '') === 'password') {
			$cur = is_string($_POST['current'] ?? null) ? $_POST['current'] : '';
			$new = is_string($_POST['new'] ?? null) ? $_POST['new'] : '';
			$rep = is_string($_POST['repeat'] ?? null) ? $_POST['repeat'] : '';
			if (!hash_equals($new, $rep)) { gp_flash('error', gp_t('acc_err_repeat')); gp_redirect('account'); }
			$auth = gp_reauth($gp_user, $cur);
			if ($auth !== 'ok') { gp_flash('error', gp_t($auth === 'locked' ? 'login_locked_short' : 'usr_err_current')); gp_redirect('account'); }
			$r = gp_users_change_own_password($gp_user, $cur, $new);
			if ($r[0]) { gp_session_set_cookie(gp_session_make($gp_user, $gp_cfg['session_secret'], null, $r[2]), $gp_cfg['session_ttl']); }
			gp_flash($r[0] ? 'ok' : 'error', gp_t($r[0] ? 'acc_changed' : $r[1]));
			gp_redirect('account');
		}
		gp_render('account', array('me' => gp_session_record()));

	case 'update':
		// Admin page: upload a GitHub ZIP, review, apply with the password, roll back. Every POST needs the CSRF token (checked above).
		if ($gp_post) {
			$do = (string)($_POST['do'] ?? '');
			if ($do === 'upload') {
				$r = gp_upd_upload(isset($_FILES['zip']) && is_array($_FILES['zip']) ? $_FILES['zip'] : array(), $gp_user);
				if ($r[0]) { gp_redirect('update', array('plan' => $r[1])); }
				gp_flash('error', gp_t($r[2]) . ($r[3] !== '' ? ': ' . $r[3] : ''));
				gp_redirect('update');
			}
			if ($do === 'discard') {
				gp_upd_plan_discard((string)($_POST['plan'] ?? ''));
				gp_flash('ok', gp_t('upd_discarded'));
				gp_redirect('update');
			}
			if ($do === 'apply') {
				$pid = (string)($_POST['plan'] ?? '');
				$auth = gp_reauth($gp_user, $_POST['password'] ?? '');
				if ($auth !== 'ok') {
					gp_flash('error', gp_t($auth === 'locked' ? 'login_locked_short' : 'upd_err_password'));
					gp_redirect('update', array('plan' => $pid));
				}
				$confirm = isset($_POST['confirm']) && is_array($_POST['confirm']) ? array_map('strval', array_keys(array_filter($_POST['confirm']))) : array();
				$r = gp_upd_apply($pid, $gp_user, array('confirm' => $confirm));
				if (!$r['ok']) {
					gp_upd_audit('update_failed', $gp_user, $r['error'], null, array('detail' => substr((string)$r['detail'], 0, 200)));
					gp_flash('error', gp_t($r['error']) . ($r['detail'] !== '' ? ': ' . $r['detail'] : ''));
					gp_redirect('update', array('plan' => $pid));
				}
				gp_upd_audit('update_apply', $gp_user, $r['stamp'], null, array('stamp' => $r['stamp']));
				// The health check is a fresh request served by the NEW code, judged by the OLD updates/verify.php.
				if (!headers_sent()) { header('Location: recover.php?a=verify&ts=' . rawurlencode($r['stamp']) . '&k=' . rawurlencode($r['verify_key']), true, 303); }
				exit;
			}
			if ($do === 'verify') {
				// "Run the check now": the same verify code, inside this authenticated request (no extra URL needed). It ends the
				// request with a redirect to the result page; it only returns when it could not start.
				$vr = gp_upd_verify_inprocess(is_string($_POST['stamp'] ?? null) ? $_POST['stamp'] : '', $gp_user);
				gp_flash('error', gp_t($vr[1]));
				gp_redirect('update');
			}
			if ($do === 'pip') {
				$pr = gp_upd_pip_queue(is_string($_POST['stamp'] ?? null) ? $_POST['stamp'] : '', $gp_user);
				gp_flash($pr[0] ? 'ok' : 'error', gp_t($pr[1]));
				gp_redirect('update', array('res' => 'ok', 'ts' => is_string($_POST['stamp'] ?? null) ? $_POST['stamp'] : ''));
			}
			if ($do === 'rollback') {
				$stamp = (string)($_POST['stamp'] ?? '');
				$rb = gp_upd_rollback($stamp);
				gp_upd_audit('update_rollback', $gp_user, $stamp, null, array('ok' => $rb[0], 'log' => array_slice($rb[1], 0, 5)));
				gp_flash($rb[0] ? 'ok' : 'error', gp_t($rb[0] ? 'upd_rolled_back' : 'upd_err_rollback') . ($rb[0] ? '' : ': ' . implode('; ', array_slice($rb[1], 0, 3))));
				gp_redirect('update');
			}
			gp_redirect('update');
		}
		// A body larger than post_max_size arrives with no POST data at all: say why.
		if ($gp_body_overflow) {
			gp_flash('error', gp_t('upd_err_phplimit') . ': ' . gp_bytes(gp_upd_upload_limit()));
		}
		$upd_ts = (isset($_GET['ts']) && is_string($_GET['ts']) && preg_match('/^\d{8}-\d{6}(-\d+)?$/', $_GET['ts'])) ? $_GET['ts'] : '';
		$upd_res = (isset($_GET['res']) && is_string($_GET['res']) && in_array($_GET['res'], array('ok', 'rolled', 'rollback_failed'), true)) ? $_GET['res'] : '';
		$upd_m = null; $upd_token = ''; $upd_lines = array(); $upd_perms = null;
		if ($upd_ts !== '' && $upd_res === 'ok') {
			$upd_m = gp_upd_post_verify($upd_ts, $gp_user);
			$upd_token = gp_upd_token_take($upd_ts);
			$uj = gp_job_health(); $uc = gp_cron_check(null, true, true);
			$upd_lines = gp_cron_setup_lines($uj, $uc);
			$upd_perms = gp_perm_scan(true);          // the post-update check: modes, cron scripts, readable secrets
		} elseif ($upd_ts !== '') {
			foreach (gp_upd_history(10) as $hh) { if ($hh['stamp'] === $upd_ts) { $upd_m = $hh; } }
		}
		$upd_plan = isset($_GET['plan']) ? gp_upd_plan_load((string)$_GET['plan']) : null;
		gp_render('update', array('env' => gp_upd_environment(), 'version' => gp_upd_version(), 'plan' => $upd_plan, 'history' => gp_upd_history(10),
			'res' => $upd_res, 'ts' => $upd_ts, 'm' => $upd_m, 'token' => $upd_token, 'cron_lines' => $upd_lines, 'perms' => $upd_perms,
			'web_url' => 'recover.php'));

	case 'audit':
		gp_render('audit', array(
			'filter' => $afilter = gp_filter_parse($_GET, array('event' => 'choice', 'actor' => 'ident', 'q' => 'text')),
			'entries' => gp_audit_read(200, $afilter),
			'query'   => (string)($_GET['q'] ?? ''),
		));

	case 'jobs':
		if ($gp_post) {
			if (isset($_POST['cron_refresh'])) {
				$r = gp_cron_check_refresh($gp_user, $gp_ip);
				gp_flash($r[0] ? 'ok' : 'warn', gp_t($r[1]));
				gp_redirect('jobs');
			}
			if (isset($_POST['perm_refresh'])) {
				gp_perm_scan(true);
				gp_audit_append(array('event' => 'perm_check_refresh', 'actor' => $gp_user, 'ip' => $gp_ip, 'key' => 'perm-check', 'old' => null, 'new' => null));
				gp_flash('ok', gp_t('perm_rescanned'));
				gp_redirect('jobs');
			}
			if (isset($_POST['seen'])) {
				$r = gp_jobs_mark_seen((string)$_POST['seen'], $gp_user, $gp_ip);
				gp_flash($r[0] ? 'ok' : 'error', gp_t($r[1]));
				gp_redirect('jobs', array('job' => (string)$_POST['seen']));
			}
			$job = gp_job_enqueue((string)($_POST['job'] ?? ''), array('days' => 7), $gp_user);
			gp_flash($job['ok'] ? 'ok' : 'error',
				$job['ok'] ? gp_t('job_enqueued') : ($job['error'] ?? gp_t('err_generic')));
			gp_redirect('jobs');
		}
		$jdetail = (isset($_GET['job']) && is_string($_GET['job']) && isset(gp_job_defs()[$_GET['job']])) ? $_GET['job'] : '';
		$jhealth = gp_job_health();
		$jcron = gp_cron_check();
		gp_render('jobs', array('jobs' => gp_job_list(), 'redis_up' => gp_redis_up(), 'health' => $jhealth, 'detail' => $jdetail,
			'queue' => gp_queue_health(), 'cron' => $jcron, 'cron_lines' => gp_cron_setup_lines($jhealth, $jcron), 'perms' => gp_perm_scan(), 'php_env' => gp_php_env(),
			'runs' => $jdetail !== '' ? gp_job_runs($jdetail) : array(), 'errors' => $jdetail !== '' ? gp_job_error_blocks($jdetail) : array()));
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
		'tok', 'sc', 'esc', 'rs', 'rep', 'ml', 'clf', 'botv', 'cc', 'asn', 'st', 'by', 'dur');
	// The short codes stay the columns (scripts and old exports depend on them); the last column spells the reasons out
	// (docs/14-REASON-CODES.md lists every code).
	fputcsv($out, array_merge($cols, array('rs_names')));
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
		$line[] = implode(' | ', array_map('gp_reason_label', isset($row['rs']) && is_array($row['rs']) ? array_values(array_filter($row['rs'], 'is_string')) : array()));
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
	$ttl = gp_override_ttl_from_post($_POST);
	if ($identity === '') { return; }
	// A quick action (a log row, the identity page): one button = one kind and one time.
	$quick = isset($_POST['quick']) && is_string($_POST['quick']) ? $_POST['quick'] : '';
	if ($quick !== '') {
		$specs = gp_quick_specs();
		if (!isset($specs[$quick])) { gp_flash('error', gp_t('err_generic')); return; }
		$action = $specs[$quick][0];
		$ttl = $specs[$quick][1];
	}
	$via = $quick !== '' ? 'quick' : (string)($_POST['from'] ?? '');

	if ($action === 'clear') {
		if (gp_override_clear($identity)) {
			gp_audit_append(array('event' => 'override_clear', 'actor' => $user,
				'ip' => $ip, 'key' => $identity, 'old' => null, 'new' => null));
			gp_flash('ok', gp_t('ovr_cleared'));
		}
		return;
	}
	// Change the time left of one that exists (extend or shorten).
	if ($action === 'retime') {
		$kind = (string)($_POST['kind'] ?? '');
		if ($ttl > 0 && gp_override_retime($kind, $identity, $ttl)) {
			gp_audit_append(array('event' => 'override_retime', 'actor' => $user, 'ip' => $ip, 'key' => $identity,
				'old' => array('kind' => $kind), 'new' => array('ttl' => $ttl)));
			gp_flash('ok', gp_t('ovr_retimed'));
		} else {
			gp_flash('error', gp_t($ttl > 0 ? 'ovr_gone' : 'ovr_bad_ttl'));
		}
		return;
	}
	if (in_array($action, gp_override_kinds(), true)) {
		if ($ttl <= 0) { gp_flash('error', gp_t('ovr_bad_ttl')); return; }
		if (gp_override_set($action, $identity, $ttl)) {
			gp_audit_append(array('event' => 'override_' . $action, 'actor' => $user,
				'ip' => $ip, 'key' => $identity, 'old' => null,
				'new' => array('ttl' => $ttl, 'via' => $via)));
			gp_flash('ok', gp_t('ovr_added'));
			// A deny under an ENFORCED allow list does nothing: the allow list is checked first.
			if ($action === 'deny' || $action === 'challenge' || $action === 'captcha') {
				$sh = gp_iplists_deny_shadow(array(gp_identity_canon($identity)));
				if ($sh) { gp_flash('warn', str_replace('%s', (string)reset($sh), gp_t('ovr_deny_shadowed'))); }
			}
			// An address many people share (a mobile network, carrier-grade NAT): say so while the operator can still change it.
			$shared = $action === 'allow' ? null : gp_override_shared_ip(gp_identity_canon($identity));
			if ($shared !== null) { gp_flash('warn', str_replace('%s', $shared[1], gp_t('ovr_shared_' . $shared[0])) . ' ' . gp_t('ovr_shared_advice')); }
		} else {
			gp_flash('error', gp_t('err_generic'));
		}
	}
}

// Read the settings form into a proposed overlay. Types are coerced here so
// gv_overlay_validate() sees the right shapes; anything invalid is refused
// there, never clamped.
// Read the settings form into a flat array of overlay keys, driven by the
// whitelist so a new key needs no parsing code here. Values are typed only as
// far as the form can tell; gv_overlay_validate() decides what is valid.
// A field that was not on the form is not in the result, so it stays unchanged.
function gp_settings_from_request() {
	$post = $_POST;
	$fields = isset($post['f']) && is_array($post['f']) ? $post['f'] : array();
	$present = isset($post['present']) && is_array($post['present']) ? $post['present'] : array();
	$out = array();
	foreach (gv_overlay_whitelist() as $key => $spec) {
		$type = $spec[0];
		if ($type === 'bool') {
			if (isset($present[$key])) { $out[$key] = !empty($fields[$key]); }
			continue;
		}
		if (!isset($fields[$key]) || is_array($fields[$key])) { continue; }
		$raw = (string)$fields[$key];
		switch ($type) {
			case 'int':
				$raw = trim($raw);
				if ($raw === '') { break; }
				// A non-numeric string must reach the validator as a string so it is
				// refused by name, not silently cast to 0.
				$out[$key] = preg_match('/^-?\d+$/', $raw) ? (int)$raw : $raw;
				break;
			case 'float':
				$raw = trim($raw);
				if ($raw === '') { break; }
				$out[$key] = is_numeric($raw) ? (float)$raw : $raw;
				break;
			case 'paths': case 'exactpaths': case 'bots': case 'cidrs4': case 'regexes': case 'ips': case 'names':
				$out[$key] = gp_lines_to_list($raw);
				break;
			case 'params': case 'suffixes':
				$out[$key] = gp_parse_params($raw);
				break;
			case 'text':
				// Keep inner spaces; only line breaks are not allowed in one line.
				$out[$key] = trim($raw);
				break;
			default:   // hppath, lang, enum, host
				$out[$key] = trim($raw);
		}
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
