<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// Temporary blocks and allows (the Overrides page): the kinds, the time presets, the form pieces shared by the Temporary blocks page,
// the identity view and the quick actions on a log row, and the warning for an address many people share.
//
// Everything is a per-IP or per-device Redis key with a TTL (allow:<id>, deny:<id>, chal:<id>), read by the guard in its existing
// pipeline. Plain functions that return HTML or data; every word lives in lang.php.

// The kinds an operator can set. 'challenge' and 'captcha' are stored in ONE key family (chal:<id>), value '1' / 'c'.
function gp_override_kinds() { return array('allow', 'deny', 'challenge', 'captcha'); }

// Time presets in seconds, shortest first, and the custom limit in minutes (30 days).
function gp_override_presets() { return array(300, 900, 1800, 3600, 21600, 86400, 604800, 2592000); }
define('GP_OVERRIDE_MIN_TTL', 60);
define('GP_OVERRIDE_CUSTOM_MAX_MIN', 43200);

// "5 minutes", "1 hour", "7 days" for a number of seconds that is a whole unit.
function gp_override_ttl_label($seconds) {
	$s = (int)$seconds;
	if ($s % 86400 === 0) { return gp_plural(intdiv($s, 86400), 'day'); }
	if ($s % 3600 === 0) { return gp_plural(intdiv($s, 3600), 'hour'); }
	return gp_plural(max(1, intdiv($s, 60)), 'minute');
}

// The time a POST asks for, in seconds: a custom value in minutes when given (1 to 43200), otherwise the chosen preset (or any
// whole number of seconds between 60 and 30 days, which is what older forms and scripts send). 0 = invalid.
function gp_override_ttl_from_post(array $post) {
	$custom = isset($post['ttl_minutes']) && is_string($post['ttl_minutes']) ? trim($post['ttl_minutes']) : '';
	if ($custom !== '') {
		if (!ctype_digit($custom) || strlen($custom) > 6) { return 0; }
		$m = (int)$custom;
		return ($m >= 1 && $m <= GP_OVERRIDE_CUSTOM_MAX_MIN) ? $m * 60 : 0;
	}
	$ttl = isset($post['ttl']) && is_scalar($post['ttl']) ? (string)$post['ttl'] : '3600';
	if (!ctype_digit($ttl) || strlen($ttl) > 9) { return 0; }
	$ttl = (int)$ttl;
	return ($ttl >= GP_OVERRIDE_MIN_TTL && $ttl <= GP_OVERRIDE_MAX_TTL) ? $ttl : 0;
}

// The time chooser: the presets plus a custom value in minutes. $selected is the preset shown first.
function gp_override_ttl_fields($selected = 3600, $select_name = 'ttl', $compact = false) {
	$h = ($compact ? '' : '<span class="gp-label">' . gp_e(gp_t('id_ttl')) . gp_tip('ovr_ttl') . '</span>')
		. '<div class="gp-fgroup"><select class="gp-input" name="' . gp_e($select_name) . '">';
	foreach (gp_override_presets() as $p) {
		$h .= '<option value="' . (int)$p . '"' . ((int)$p === (int)$selected ? ' selected' : '') . '>' . gp_e(gp_override_ttl_label($p)) . '</option>';
	}
	return $h . '</select><label class="gp-field"><span class="sr-only">' . gp_e(gp_t('ovr_custom')) . '</span>'
		. '<input class="gp-input gp-ltr" type="number" name="ttl_minutes" min="1" max="' . GP_OVERRIDE_CUSTOM_MAX_MIN . '" inputmode="numeric" placeholder="' . gp_e(gp_t('ovr_custom_ph')) . '" aria-label="' . gp_e(gp_t('ovr_custom')) . '"></label></div>'
		. ($compact ? '' : '<span class="gp-help">' . gp_e(gp_t('ovr_custom_help')) . gp_tip('ovr_custom') . '</span>');
}

// The four action buttons of the form (the value of name="override" is the kind).
function gp_override_buttons($small = false) {
	$sz = $small ? ' gp-btn-sm' : '';
	return '<button class="gp-btn gp-btn-primary' . $sz . '" type="submit" name="override" value="allow">' . gp_e(gp_t('id_allow')) . '</button>'
		. '<button class="gp-btn gp-btn-danger' . $sz . '" type="submit" name="override" value="deny">' . gp_e(gp_t('id_deny')) . '</button>'
		. '<button class="gp-btn gp-btn-info' . $sz . '" type="submit" name="override" value="challenge">' . gp_e(gp_t('id_challenge')) . '</button>'
		. '<button class="gp-btn gp-btn-info' . $sz . '" type="submit" name="override" value="captcha">' . gp_e(gp_t('id_captcha')) . '</button>';
}

// Colour class and label of a kind (the word is always printed, never colour alone).
function gp_override_badge($kind) {
	$cls = array('allow' => 'gp-badge-on', 'deny' => 'gp-badge-bad', 'challenge' => 'gp-badge-warn', 'captcha' => 'gp-badge-info');
	$k = isset($cls[$kind]) ? $kind : 'deny';
	return '<span class="gp-badge ' . $cls[$k] . '">' . gp_e(gp_t('ovr_k_' . $k)) . '</span>';
}

// "in 14 minutes (2026-11-23 08:12 UTC)" for a time left in seconds; unknown when null.
function gp_override_expires_text($ttl, $now = null) {
	if ($ttl === null) { return gp_t('unknown'); }
	$now = $now === null ? time() : (int)$now;
	$s = max(0, (int)$ttl);
	$left = $s < 60 ? gp_plural($s, 'second') : ($s < 3600 ? gp_plural(intdiv($s, 60), 'minute') : ($s < 86400 ? gp_plural(intdiv($s, 3600), 'hour') : gp_plural(intdiv($s, 86400), 'day')));
	return gp_t('ovr_in') . ' ' . $left . ' (' . gmdate('Y-m-d H:i', $now + $s) . ' UTC)';
}

// Quick actions: key => array(kind, seconds, lang key of the button).
function gp_quick_specs() {
	return array(
		'deny:900'       => array('deny', 900, 'ovr_q_block15'),
		'challenge:3600' => array('challenge', 3600, 'ovr_q_chal1h'),
		'captcha:3600'   => array('captcha', 3600, 'ovr_q_cap1h'),
		'allow:3600'     => array('allow', 3600, 'ovr_q_allow1h'),
	);
}

// A same-site place to return to after a quick action: only the Logs, Identity and Live pages, a short query of plain characters.
// Returns array(route, params) or null.
function gp_quick_back($back) {
	if (!is_string($back) || strlen($back) > 600 || !preg_match('/^index\.php\?r=(logs|identity|live)(?:&[A-Za-z0-9_\[\]=%.,:+~-]*)*$/', $back, $m)) { return null; }
	$q = array();
	parse_str((string)substr($back, strlen('index.php?')), $q);
	unset($q['r']);
	foreach ($q as $k => $v) { if (!is_string($v)) { unset($q[$k]); } }
	return array($m[1], $q);
}

// The quick actions of one identity (an address or a device id) as a small form. $back is the page to return to. Admin only: the
// buttons are not drawn for anyone else (the POST is admin-only in the ACL map as well).
function gp_quick_actions_html($identity, $back, $role) {
	if (!gp_acl_allows($role, 'overrides', 'POST') || (string)$identity === '') { return ''; }
	$is_ip = filter_var($identity, FILTER_VALIDATE_IP) !== false;
	$h = '<form method="post" action="index.php?r=overrides" class="gp-quick"><input type="hidden" name="csrf" value="' . gp_e(gp_csrf_token()) . '">'
		. '<input type="hidden" name="identity" value="' . gp_e($identity) . '"><input type="hidden" name="from" value="quick">'
		. '<input type="hidden" name="back" value="' . gp_e($back) . '">'
		. '<span class="gp-quick-who gp-ltr"><b>' . gp_e(gp_t($is_ip ? 'ovr_q_ip' : 'ovr_q_dev')) . '</b> <span class="gp-mono">' . gp_e($identity) . '</span></span>';
	foreach (gp_quick_specs() as $key => $spec) {
		$h .= '<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit" name="quick" value="' . gp_e($key) . '">' . gp_e(gp_t($spec[2])) . '</button>';
	}
	return $h . '<a class="gp-btn gp-btn-ghost gp-btn-sm" href="index.php?r=overrides&amp;new=' . gp_u($identity) . '#override-add' . '">' . gp_e(gp_t('ovr_q_custom')) . '</a>'
		. gp_tip('ovr_quick') . '</form>';
}

// Mobile networks whose addresses are shared by very many people at once (carrier-grade NAT). Not exhaustive: a hint, not a verdict.
function gp_mobile_asns() { return gp_ipl_mobile_asns(); }

// The warning for an address many users may share: array(reason, label) or null. 100.64.0.0/10 is the carrier-grade NAT range; the
// AS number comes from the compiled ASN database when there is one (the guard's lookup), otherwise only the range is known.
function gp_override_shared_ip($identity) {
	$ip = (string)$identity;
	if (filter_var($ip, FILTER_VALIDATE_IP) === false) { return null; }
	$bin = @inet_pton($ip);
	if ($bin !== false && strlen($bin) === 4 && (ord($bin[0]) === 100 && (ord($bin[1]) & 0xC0) === 64)) { return array('cgnat', '100.64.0.0/10'); }
	if (function_exists('gv_geo_asn') && function_exists('gv_geo_file') && defined('GV_GEO_ASN') && is_file(gv_geo_file(GV_GEO_ASN))) {      // no database: no lookup (and no error line in the guard's log)
		$asn = (int)@gv_geo_asn($ip);
		$list = gp_mobile_asns();
		if ($asn > 0 && isset($list[$asn])) { return array('mobile', 'AS' . $asn . ' ' . $list[$asn]); }
	}
	return null;
}

// The warning as markup (empty when the address is not known to be shared).
function gp_override_shared_note($identity) {
	$s = gp_override_shared_ip($identity);
	if ($s === null) { return ''; }
	return '<div class="gp-note gp-note-strong" role="alert" data-shared-ip="' . gp_e($s[0]) . '">'
		. gp_e(str_replace('%s', $s[1], gp_t('ovr_shared_' . $s[0]))) . ' ' . gp_e(gp_t('ovr_shared_advice')) . '</div>';
}
