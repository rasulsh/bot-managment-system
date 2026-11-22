<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// Small markup helpers shared by the views: help tooltips and tabs. Plain
// functions that return or echo escaped HTML; the behaviour (open on hover, focus
// and tap, arrow keys, the URL hash) is one inline script in views/layout.php,
// and without it everything stays readable (tooltips show on focus, tabs stack).

// A "?" help button for a field. The text is lang.php key tip_<key>: what the
// field does, a safe value, the risk of a wrong one. Returns '' for a key with no
// text, so a missing tip never breaks a page (panel-selftest fails the build instead).
// IP list colours, one place: allow = blue, block = red. The word is always printed too (never colour alone).
function gp_ipl_badge_class($type) { return $type === 'block' ? 'gp-badge-ipl-block' : 'gp-badge-ipl-allow'; }

// The list type a log reason names (IPL_ALLOW:<id>, SH_IPL_BLOCK:<id>, ...): 'allow', 'block' or ''.
function gp_reason_ipl_type($reason) {
	return preg_match('/^(?:SH_)?IPL_(ALLOW|BLOCK):/', (string)$reason, $m) ? strtolower($m[1]) : '';
}

// Class of a reason badge in a log row: list reasons get the list colours, everything else stays neutral.
function gp_reason_badge_class($reason) {
	$t = gp_reason_ipl_type($reason);
	return $t === '' ? 'gp-badge-off' : gp_ipl_badge_class($t);
}

// --------------------------------------------------------------------------
// Messages in context. Every POST action belongs to ONE section of ONE page; its result message is drawn in that section
// (gp_msg), the redirect after it ends in #msg-<section>, and a small script scrolls to and focuses the message. A message
// whose section is not on the page falls back to the top of the page, so nothing is ever lost.
//
// The table: route / posted field => section id. Keep it in sync with the views (the self-test walks every POST form).
// --------------------------------------------------------------------------
function gp_post_section($route, array $post) {
	$s = function ($k) use ($post) { return isset($post[$k]) && is_string($post[$k]) ? $post[$k] : ''; };
	switch ((string)$route) {
		case 'dashboard': return 'killswitch';
		case 'identity': return 'identity-override';
		case 'overrides': return $s('override') === 'clear' ? 'override-list' : ($s('from') === 'list' ? 'ovr-' . gp_row_key($s('identity')) : 'override-add');
		case 'rules': return in_array($s('do'), array('save', 'preview'), true) ? 'rule-editor' : ($s('do') === 'discard_invalid' ? 'rules-file' : 'rules-list');
		case 'geo': return $s('do') === 'upload' || $s('do') === 'compile' ? 'geo-upload' : ($s('do') === 'rollback' ? 'geo-status' : 'geo-sources');
		case 'iplists': $d = $s('do'); return $d === 'save' ? 'ipl-editor' : ($d === 'compile' ? 'ipl-compile' : ($d === 'rollback' ? 'ipl-status' : 'ipl-lists'));
		case 'replay': return in_array($s('action'), array('apply', 'full'), true) ? 'replay-actions' : 'replay-run';
		case 'models': return substr($s('job'), -3) === 'clf' ? 'models-clf' : 'models-ml';
		case 'settings': return $s('action') === 'reset' ? 'settings-reset' : 'settings-save';
		case 'config_file': return 'config-file';
		case 'users': $d = $s('do'); return $d === 'create' ? 'users-create' : ($d === 'unlock' ? 'users-unlock' : ($d === 'delete' || $s('username') === '' ? 'users-list' : 'usr-' . gp_row_key($s('username'))));
		case 'account': return 'account-password';
		case 'update': $d = $s('do'); return in_array($d, array('upload', 'discard'), true) ? 'update-upload' : ($d === 'apply' ? 'update-apply' : ($d === 'verify' ? 'update-verify' : 'update-history'));
		case 'jobs': return isset($post['cron_refresh']) ? 'jobs-cron' : (isset($post['perm_refresh']) ? 'jobs-perms' : (isset($post['seen']) ? 'jobs-detail' : 'jobs-start'));
	}
	return '';
}

// A short stable key of one row (an identity, a user, a list id), for sections that exist once per row: msg-<prefix>-<key>.
function gp_row_key($value) { return substr(md5((string)$value), 0, 8); }

function gp_section_valid($id) { return is_string($id) && preg_match('/^[a-z0-9-]{1,40}$/', $id) === 1; }

// The messages of one section, drawn where the action's button is. Ok / warning = role=status, error = role=alert. The wrapper
// is the scroll and focus target (#msg-<id>). Marks the section as drawn so the layout does not repeat it at the top.
function gp_msg($id) {
	global $gp_flash;
	if (empty($gp_flash) || !gp_section_valid($id) || !empty($GLOBALS['gp_msg_drawn'][$id])) { return ''; }
	$h = '';
	foreach ($gp_flash as $m) {
		if (($m['section'] ?? '') !== $id) { continue; }
		$h .= '<div class="gp-flash gp-flash-' . gp_e($m['kind']) . '" role="' . ($m['kind'] === 'error' ? 'alert' : 'status') . '">' . gp_e($m['message']) . '</div>';
	}
	if ($h === '') { return ''; }
	$GLOBALS['gp_msg_drawn'][$id] = true;
	return '<div class="gp-msg" id="msg-' . gp_e($id) . '" tabindex="-1" data-gp-msg>' . $h . '</div>';
}

function gp_tip($key) {
	static $n = 0;
	$text = gp_t('tip_' . $key);
	if ($text === 'tip_' . $key) { return ''; }
	$id = 'tip-' . (++$n);
	return '<span class="gp-tip"><button type="button" class="gp-tip-btn" aria-describedby="' . $id . '" aria-label="' . gp_e(gp_t('tip_label')) . '">?</button>'
		. '<span role="tooltip" id="' . $id . '" class="gp-tip-box">' . gp_e($text) . '</span></span>';
}

// Open a tab group. $tabs: id => label. $errors: id => number of errors in that tab.
// The tab with the first error opens on load (and every tab with errors gets a badge);
// otherwise the URL hash (#<group>-<tab>) or the first tab.
function gp_tabs_begin($group, array $tabs, array $errors = array()) {
	$open = '';
	foreach ($tabs as $id => $label) { if (!empty($errors[$id])) { $open = $id; break; } }
	echo '<div class="gp-tabs" data-tabs="' . gp_e($group) . '"' . ($open !== '' ? ' data-open="' . gp_e($open) . '"' : '') . '>';
	echo '<div class="gp-tablist" role="tablist" aria-label="' . gp_e(gp_t('tabs_label')) . '">';
	foreach ($tabs as $id => $label) {
		$n = isset($errors[$id]) ? (int)$errors[$id] : 0;
		echo '<button type="button" class="gp-tab" role="tab" id="tab-' . gp_e($group . '-' . $id) . '" data-tab="' . gp_e($id)
			. '" aria-controls="panel-' . gp_e($group . '-' . $id) . '" aria-selected="false" tabindex="-1">' . gp_e($label);
		if ($n > 0) { echo ' <span class="gp-tab-badge" title="' . gp_e(gp_t('tabs_errors')) . '">' . gp_e((string)$n) . '</span>'; }
		echo '</button>';
	}
	echo '</div>';
}

function gp_tab_begin($group, $id, $label) {
	echo '<section class="gp-tabpanel" role="tabpanel" id="panel-' . gp_e($group . '-' . $id) . '" aria-labelledby="tab-' . gp_e($group . '-' . $id)
		. '" data-panel="' . gp_e($id) . '"><h3 class="gp-tabpanel-title">' . gp_e($label) . '</h3>';
}

function gp_tab_end() { echo '</section>'; }
function gp_tabs_end() { echo '</div>'; }
