<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// Reason codes and the other short log fields, in words.
//
// The log rows keep their SHORT codes (SH_RULE:<id>, IPL_BLOCK:<id>, UA_SCRIPT, ...): they are written on every request, and the
// analyzer, the filters, saved links and old logs depend on them, so they are never renamed. This file is the one place that says
// what each code MEANS. It is data plus a few small renderers; every word shown lives in lang.php:
//
//     rsn_<code>      the full name        rsn_<code>_x     one-sentence explanation        rsn_cat_<category>   the category
//
// The same registry feeds the badges (Logs, Identity, dashboard, Live), the Reason filter's pick list and docs/14-REASON-CODES.md
// (scripts/gen-reason-docs.php). panel-selftest scans the guard, analyzer and panel source for emitted codes and fails when one is
// missing here, so a new code cannot ship without a name.

// Categories, in the order the docs list them. The colour class of a code follows from its category (list codes use the list colours).
function gp_reason_categories() {
	return array(
		'rule'      => 'gp-badge-info',
		'iplist'    => 'gp-badge-info',
		'bot'       => 'gp-badge-warn',
		'ratelimit' => 'gp-badge-warn',
		'token'     => 'gp-badge-off',
		'challenge' => 'gp-badge-info',
		'captcha'   => 'gp-badge-info',
		'signal'    => 'gp-badge-off',
		'degraded'  => 'gp-badge-bad',
		'override'  => 'gp-badge-warn',
		'other'     => 'gp-badge-off',
	);
}

// The registry: base code => category. A code with an id (RULE:<id>) is registered WITHOUT the id; the SH_ prefix is also left out and
// handled once, below ("monitor only"). '403', 'challenge' and '429' are the actions an SH_<action> reason names.
function gp_reason_registry() {
	return array(
		'RULE'               => 'rule',        // RULE:<id>        SH_RULE:<id>
		'IPL_BLOCK'          => 'iplist',      // IPL_BLOCK:<id>   SH_IPL_BLOCK:<id>
		'IPL_ALLOW'          => 'iplist',      // IPL_ALLOW:<id>   SH_IPL_ALLOW:<id>
		'RULE_SKIP_DEGRADED' => 'degraded',
		'BOT_FAKE'           => 'bot',
		'BOT_UNVERIFIED'     => 'bot',
		'DEV_HOUR'           => 'ratelimit',
		'DEV_DAY'            => 'ratelimit',
		'CAPT_ESC'           => 'captcha',
		'CAPT_BUDGET'        => 'captcha',
		'CAPT_DEGRADED'      => 'degraded',
		'UA_EMPTY'           => 'signal',
		'UA_SCRIPT'          => 'signal',
		'NO_AL'              => 'signal',
		'NO_SF'              => 'signal',
		'FEW_HDR'            => 'signal',
		'HP_HIST'            => 'signal',
		'OVR_CHALLENGE'      => 'override',
		'OVR_CAPTCHA'        => 'override',
		'TEST'               => 'other',
		'403'                => 'rule',        // SH_403: a monitor-only rule would have blocked
		'429'                => 'rule',        // SH_429
		'challenge'          => 'rule',        // SH_challenge
	);
}

// The actions an SH_<action> reason names; they are reasons only with the SH_ prefix.
function gp_reason_is_action($base) { return in_array((string)$base, array('403', '429', 'challenge'), true); }

// Codes that carry an id after a colon.
function gp_reason_has_id($base) { return in_array((string)$base, array('RULE', 'IPL_BLOCK', 'IPL_ALLOW'), true); }

// A code taken apart: array(base, id, monitor, known). 'SH_RULE:7' => ('RULE', '7', true, true).
function gp_reason_parse($code) {
	$code = (string)$code;
	$monitor = false;
	$rest = $code;
	if (strncmp($rest, 'SH_', 3) === 0) { $monitor = true; $rest = substr($rest, 3); }
	$id = '';
	$p = strpos($rest, ':');
	if ($p !== false) { $id = substr($rest, $p + 1); $rest = substr($rest, 0, $p); }
	$reg = gp_reason_registry();
	$known = isset($reg[$rest]) && (gp_reason_has_id($rest) ? $p !== false : $p === false) && (!gp_reason_is_action($rest) || $monitor);
	// A reason that merely starts with SH_ but is a code of its own would have been registered whole; none is.
	return array($rest, $id, $monitor, $known);
}

// Everything the panel knows about one code. Names and explanations come from lang.php; a code that is not registered still gets a
// readable entry (its own text, category "other") so a log from a newer guard never breaks a page.
function gp_reason_info($code) {
	list($base, $id, $monitor, $known) = gp_reason_parse($code);
	$cats = gp_reason_categories();
	$cat = $known ? gp_reason_registry()[$base] : 'other';
	$name = $known ? gp_t('rsn_' . $base) : (string)$code;
	$class = $cats[$cat];
	if ($known && $cat === 'iplist') { $class = gp_ipl_badge_class($base === 'IPL_BLOCK' ? 'block' : 'allow'); }
	$ref = array('', '');
	if ($known && $id !== '') {
		$ref = array($base === 'RULE' ? 'rule' : 'list', $id);
	}
	return array(
		'code' => (string)$code, 'base' => $base, 'id' => $id, 'monitor' => $monitor, 'known' => $known,
		'name' => $name, 'explain' => $known ? gp_t('rsn_' . $base . '_x') : gp_t('rsn_unknown_x'),
		'category' => $cat, 'class' => $class, 'ref' => $ref,
	);
}

// The names of the rules and IP lists on this install: array('rule' => id => name, 'list' => id => name). Read once per request.
function gp_reason_names($set = null) {
	static $names = null;
	if ($set === false) { $names = null; return array(); }          // test hook: forget what was read
	if (is_array($set)) { $names = $set; return $names; }           // test hook: use this instead of the files
	if ($names !== null) { return $names; }
	$names = array('rule' => array(), 'list' => array());
	if (function_exists('gp_rules_state')) {
		$st = gp_rules_state();
		foreach ($st['rules'] as $r) { if (isset($r['id'])) { $names['rule'][(string)$r['id']] = isset($r['name']) ? (string)$r['name'] : ''; } }
	}
	if (function_exists('gp_iplists_state')) {
		$st = gp_iplists_state();
		foreach ((isset($st['lists']) && is_array($st['lists'])) ? $st['lists'] : array() as $l) {
			if (isset($l['id'])) { $names['list'][(string)$l['id']] = isset($l['name']) ? (string)$l['name'] : ''; }
		}
	}
	return $names;
}

// Where a rule / list id leads, and what it is called ('' when it no longer exists).
function gp_reason_target($type, $id) {
	$names = gp_reason_names();
	$name = isset($names[$type][$id]) ? $names[$type][$id] : null;
	$href = $type === 'rule' ? 'index.php?r=rules&edit=' . rawurlencode($id) : 'index.php?r=iplists&list=' . rawurlencode($id) . '#ipl-entries';
	return array($name, $href);
}

// Plain text for one code: "Rule matched: Block scrapers (monitor only)". Used in pick lists and the CSV header comment.
function gp_reason_label($code) {
	$i = gp_reason_info($code);
	$s = $i['name'];
	if ($i['ref'][0] !== '') {
		$t = gp_reason_target($i['ref'][0], $i['ref'][1]);
		$s .= ': ' . ($t[0] !== null && $t[0] !== '' ? $t[0] : '#' . $i['ref'][1]);
	}
	return $s . ($i['monitor'] ? ' (' . gp_t('rsn_monitor_word') . ')' : '');
}

// The badge: the full name, the code small and monospace beside it, the explanation as a tooltip, a "monitor" marker for SH_ codes,
// and a link to the rule / list a code with an id names ($links = false inside another link). Everything dynamic goes through gp_e().
function gp_reason_badge($code, $links = true) {
	$i = gp_reason_info($code);
	$tip = $i['explain'];
	if ($i['monitor']) { $tip .= ' ' . gp_t('rsn_monitor_x'); }
	$name = gp_e($i['name']);
	if ($i['ref'][0] !== '') {
		$t = gp_reason_target($i['ref'][0], $i['ref'][1]);
		$label = ($t[0] !== null && $t[0] !== '') ? $t[0] : '#' . $i['ref'][1];
		$name .= ': ' . ($t[0] === null ? '<span class="gp-reason-gone" title="' . gp_e(gp_t('rsn_gone')) . '">' . gp_e($label) . '</span>'
			: ($links ? '<a class="gp-reason-link" href="' . gp_e($t[1]) . '">' . gp_e($label) . '</a>' : gp_e($label)));
	}
	$h = '<span class="gp-badge gp-reason ' . gp_e($i['class']) . '" title="' . gp_e($tip) . '">' . $name;
	if ($i['monitor']) { $h .= ' <span class="gp-reason-mon">' . gp_e(gp_t('rsn_monitor_word')) . '</span>'; }
	return $h . ' <code class="gp-reason-code gp-ltr">' . gp_e($code) . '</code></span>';
}

// Pick list for the Logs "Reason" filter: code => label (the value stays the code). Every registered code, the SH_ twin of those
// that can be monitor-only, and one entry per rule and IP list on this install.
function gp_reason_options() {
	$o = array();
	$reg = gp_reason_registry();
	foreach ($reg as $base => $cat) {
		if (gp_reason_has_id($base) || gp_reason_is_action($base)) { continue; }
		$o[$base] = gp_reason_label($base);
	}
	foreach (array('403', '429', 'challenge', 'CAPT_ESC') as $b) { $o['SH_' . $b] = gp_reason_label('SH_' . $b); }
	$names = gp_reason_names();
	foreach ($names['rule'] as $id => $n) { $o['RULE:' . $id] = gp_reason_label('RULE:' . $id); $o['SH_RULE:' . $id] = gp_reason_label('SH_RULE:' . $id); }
	foreach ($names['list'] as $id => $n) {
		foreach (array('IPL_BLOCK', 'IPL_ALLOW') as $b) { $o[$b . ':' . $id] = gp_reason_label($b . ':' . $id); $o['SH_' . $b . ':' . $id] = gp_reason_label('SH_' . $b . ':' . $id); }
	}
	return $o;
}

// --------------------------------------------------------------------------
// The other short fields of a log row: full column header and a label for each value.
//
//     field => array(lang key of the header, values) ; values: value => lang key of its label ('' value = "none")
// --------------------------------------------------------------------------
function gp_field_registry() {
	return array(
		'act'  => array('fld_act', array('allow' => 'fv_act_allow', 'challenge' => 'fv_act_challenge', '403' => 'fv_act_403', '429' => 'fv_act_429',
			'exempt' => 'fv_act_exempt', 'allow_bot' => 'fv_act_allow_bot', 'allow_preview' => 'fv_act_allow_preview',
			'allow_override' => 'fv_act_allow_override', '404_hp' => 'fv_act_404_hp', 'token_issued' => 'fv_act_token_issued',
			'nonce_bad' => 'fv_act_nonce_bad', 'nonce_replay' => 'fv_act_nonce_replay', 'pow_bad' => 'fv_act_pow_bad',
			'mint_limited' => 'fv_act_mint_limited')),
		'tok'  => array('fld_tok', array('v' => 'fv_tok_v', 'm' => 'fv_tok_m', 'b' => 'fv_tok_b')),
		'ovr'  => array('fld_ovr', array('' => 'fv_ovr_none', 'allow' => 'fv_ovr_allow', 'deny' => 'fv_ovr_deny', 'challenge' => 'fv_ovr_challenge', 'captcha' => 'fv_ovr_captcha')),
		'botv' => array('fld_botv', array('' => 'fv_botv_none', 'ok' => 'fv_botv_ok', 'bad' => 'fv_botv_bad')),
		'sh'   => array('fld_sh', array('0' => 'fv_sh_0', '1' => 'fv_sh_1')),
		'hold' => array('fld_hold', array('0' => 'fv_hold_0', '1' => 'fv_hold_1')),
		'cap'  => array('fld_cap', array('show' => 'fv_cap_show', 'ok' => 'fv_cap_ok', 'wrong' => 'fv_cap_wrong', 'fail' => 'fv_cap_fail',
			'exp' => 'fv_cap_exp', 'inv' => 'fv_cap_inv', 'esc' => 'fv_cap_esc')),
		'tl'   => array('fld_tl', array('c' => 'fv_tl_c')),
	);
}

// The full header of a short field ('tok' => "Token state"), or the key itself for a field that is not registered.
function gp_field_name($field) {
	$r = gp_field_registry();
	return isset($r[$field]) ? gp_t($r[$field][0]) : (string)$field;
}

// The label of one value ('v' => "valid token"); an unknown value is shown as it is.
function gp_field_value($field, $value) {
	$r = gp_field_registry();
	$value = (string)$value;
	if (isset($r[$field][1][$value])) { return gp_t($r[$field][1][$value]); }
	return $value;
}

// "valid token (v)" - the label with the stored value in brackets, for lists and detail views.
function gp_field_value_full($field, $value) {
	$label = gp_field_value($field, $value);
	return $label === (string)$value ? (string)$value : $label . ' (' . $value . ')';
}

// field => value => label, for a filter pick list (the value stays what the log stores).
function gp_field_options($field) {
	$r = gp_field_registry();
	$o = array();
	if (isset($r[$field])) { foreach ($r[$field][1] as $v => $k) { if ((string)$v !== '') { $o[(string)$v] = gp_t($k); } } }
	return $o;
}
