<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// Small markup helpers shared by the views: help tooltips and tabs. Plain
// functions that return or echo escaped HTML; the behaviour (open on hover, focus
// and tap, arrow keys, the URL hash) is one inline script in views/layout.php,
// and without it everything stays readable (tooltips show on focus, tabs stack).

// A "?" help button for a field. The text is lang.php key tip_<key>: what the
// field does, a safe value, the risk of a wrong one. Returns '' for a key with no
// text, so a missing tip never breaks a page (panel-selftest fails the build instead).
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
