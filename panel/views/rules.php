<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Access rules: table, test box and the create / edit form.
//
// Every UA, path and rule name here is operator or client data: all of it goes
// through gp_e(). The one-line summary of a condition is built in rules.php.
$errors  = is_array($errors ?? null) ? $errors : array();
$details = is_array($details ?? null) ? $details : array();
$form    = is_array($draft ?? null) ? $draft : null;     // a rule being created or edited
$now     = time();
$rule_hits = (is_array($snapshot) && isset($snapshot['rules']) && is_array($snapshot['rules'])) ? $snapshot['rules'] : array();
$err_text = function ($field) use ($errors, $details) {
	if (!isset($errors[$field])) { return ''; }
	$k = 'rerr_' . $errors[$field];
	$t = gp_t($k);
	return ($t === $k ? $errors[$field] : $t) . (isset($details[$field]) ? ' (' . $details[$field] . ')' : '');
};
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('rules_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('rules_sub')) ?></p>
</div>

<?php if ($state['state'] === 'invalid'): ?>
<div class="gp-note gp-note-strong">
	<?= gp_e(gp_t('rules_file_invalid')) ?>
	<?php if ($state['rules'] || $state['dropped']): ?>
	<form method="post" action="index.php?r=rules" data-confirm="<?= gp_e(gp_t('rules_discard_confirm')) ?>" style="display:inline">
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<button class="gp-btn gp-btn-danger gp-btn-sm" type="submit" name="do" value="discard_invalid">
			<?= gp_e(gp_t('rules_discard')) ?></button>
	</form>
	<?php endif; ?>
</div>
<?php endif; ?>
<div class="gp-note"><?= gp_e(gp_t('rules_precedence')) ?></div>

<?php /* ------------------------------------------------------------ form */ ?>
<?php if ($form !== null): $is_new = ($form['id'] === '');
	$ua = is_array($form['ua']) ? $form['ua'] : array('op' => 'include', 'type' => 'contains', 'values' => array());
	$pa = is_array($form['path']) ? $form['path'] : array('op' => 'include', 'type' => 'prefix', 'values' => array());
	$co = is_array($form['country'] ?? null) ? $form['country'] : array('op' => 'include', 'type' => 'code', 'values' => array());
	$as = is_array($form['asn'] ?? null) ? $form['asn'] : array('op' => 'include', 'type' => 'number', 'values' => array());
	$exp_date = ((int)$form['expires_at'] > 0) ? gmdate('Y-m-d', (int)$form['expires_at']) : '';
	$sel = function ($a, $b) { return $a === $b ? ' selected' : ''; };
?>
<form method="post" action="index.php?r=rules<?= $is_new ? '' : '&amp;edit=' . gp_u($form['id']) ?>" class="gp-card gp-form" novalidate>
	<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
	<input type="hidden" name="do" value="save">
	<input type="hidden" name="id" value="<?= gp_e($form['id']) ?>">
	<div class="gp-card-title"><?= gp_e(gp_t($is_new ? 'rules_new' : 'rules_edit')) ?></div>

	<?php if (isset($errors['_rule'])): ?><div class="gp-flash gp-flash-error"><?= gp_e($err_text('_rule')) ?></div><?php endif; ?>
	<?php if (!empty($warnings)): ?>
	<div class="gp-note gp-note-strong" role="alert">
		<strong><?= gp_e(gp_t('rules_warn_title')) ?></strong>
		<ul>
		<?php foreach ($warnings as $w): ?>
			<li><?= gp_e(gp_t('rwarn_' . $w[0])) ?><?= $w[1] !== '' ? ': ' . gp_e($w[1]) : '' ?></li>
		<?php endforeach; ?>
		</ul>
		<label class="gp-check"><input type="checkbox" name="ack" value="1">
			<span><?= gp_e(gp_t('rules_warn_ack')) ?></span></label>
	</div>
	<?php endif; ?>

	<div class="gp-grid-2">
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_f_name')) ?><?= gp_tip('rule_name') ?></span>
			<input class="gp-input" type="text" name="name" maxlength="80" value="<?= gp_e($form['name']) ?>">
			<span class="gp-help"><?= gp_e(gp_t('rules_h_name')) ?></span>
			<?php if ($err_text('name') !== ''): ?><span class="gp-error" role="alert"><?= gp_e($err_text('name')) ?></span><?php endif; ?>
		</label>
	</div>

	<?php
	// Tabs: conditions / action / advanced. A rejected save opens the tab with the
	// first error and badges every tab that has one. One form, one Save button.
	$rt_map = array('ua' => 'conditions', 'path' => 'conditions', 'country' => 'conditions', 'asn' => 'conditions',
		'action' => 'action', 'mode' => 'action', 'skip_verified_bots' => 'action', 'pow_bits' => 'action',
		'priority' => 'advanced', 'expires_at' => 'advanced', 'note' => 'advanced', 'enabled' => 'advanced');
	$rt_err = array('conditions' => 0, 'action' => 0, 'advanced' => 0);
	foreach ($errors as $ef => $ec) { if (isset($rt_map[$ef])) { $rt_err[$rt_map[$ef]]++; } }
	$rt_tabs = array('conditions' => gp_t('rules_tab_conditions'), 'action' => gp_t('rules_tab_action'), 'advanced' => gp_t('rules_tab_advanced'));
	gp_tabs_begin('rule', $rt_tabs, $rt_err);
	gp_tab_begin('rule', 'conditions', $rt_tabs['conditions']); ?>
	<p class="gp-help"><?= gp_e(gp_t('rules_tab_conditions_help')) ?></p>
	<fieldset class="gp-section">
		<legend class="gp-label"><?= gp_e(gp_t('rules_f_ua')) ?><?= gp_tip('rule_ua') ?></legend>
		<div class="gp-grid-2">
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('rules_f_op')) ?></span>
				<select class="gp-input" name="ua_op">
					<option value="include"<?= $sel($ua['op'], 'include') ?>><?= gp_e(gp_t('rules_op_include')) ?></option>
					<option value="exclude"<?= $sel($ua['op'], 'exclude') ?>><?= gp_e(gp_t('rules_op_exclude')) ?></option>
				</select>
			</label>
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('rules_f_type')) ?></span>
				<select class="gp-input" name="ua_type">
					<?php foreach (gv_rule_ua_types() as $t): ?>
					<option value="<?= gp_e($t) ?>"<?= $sel($ua['type'], $t) ?>><?= gp_e(gp_t('rules_type_' . $t)) ?></option>
					<?php endforeach; ?>
				</select>
			</label>
		</div>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_f_values')) ?></span>
			<textarea class="gp-textarea gp-ltr" name="ua_values" rows="4" spellcheck="false"><?= gp_e(implode("\n", $ua['values'])) ?></textarea>
			<span class="gp-help"><?= gp_e(gp_t('rules_h_ua_values')) ?></span>
			<?php if ($err_text('ua') !== ''): ?><span class="gp-error" role="alert"><?= gp_e($err_text('ua')) ?></span><?php endif; ?>
		</label>
	</fieldset>

	<fieldset class="gp-section">
		<legend class="gp-label"><?= gp_e(gp_t('rules_f_path')) ?><?= gp_tip('rule_path') ?></legend>
		<div class="gp-grid-2">
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('rules_f_op')) ?></span>
				<select class="gp-input" name="path_op">
					<option value="include"<?= $sel($pa['op'], 'include') ?>><?= gp_e(gp_t('rules_op_include')) ?></option>
					<option value="exclude"<?= $sel($pa['op'], 'exclude') ?>><?= gp_e(gp_t('rules_op_exclude')) ?></option>
				</select>
			</label>
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('rules_f_values')) ?></span>
				<textarea class="gp-textarea gp-ltr" name="path_values" rows="2" spellcheck="false"><?= gp_e(implode("\n", $pa['values'])) ?></textarea>
				<span class="gp-help"><?= gp_e(gp_t('rules_h_path_values')) ?></span>
				<?php if ($err_text('path') !== ''): ?><span class="gp-error" role="alert"><?= gp_e($err_text('path')) ?></span><?php endif; ?>
			</label>
		</div>
	</fieldset>
	<?php foreach (array('country' => array($co, 'rules_f_country', 'rules_h_country', 'IR, US', 'country_values'),
		'asn' => array($as, 'rules_f_asn', 'rules_h_asn', '13335, 15169', 'asn_values')) as $gk => $gdef): ?>
	<fieldset class="gp-section">
		<legend class="gp-label"><?= gp_e(gp_t($gdef[1])) ?><?= gp_tip('rule_' . $gk) ?></legend>
		<div class="gp-grid-2">
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('rules_f_op')) ?></span>
				<select class="gp-input" name="<?= gp_e($gk) ?>_op">
					<option value="include"<?= $sel($gdef[0]['op'], 'include') ?>><?= gp_e(gp_t('rules_op_include')) ?></option>
					<option value="exclude"<?= $sel($gdef[0]['op'], 'exclude') ?>><?= gp_e(gp_t('rules_op_exclude')) ?></option>
				</select>
			</label>
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('rules_f_values')) ?></span>
				<textarea class="gp-textarea gp-ltr" name="<?= gp_e($gdef[4]) ?>" rows="2" spellcheck="false" placeholder="<?= gp_e($gdef[3]) ?>"><?= gp_e(implode("\n", $gdef[0]['values'])) ?></textarea>
				<span class="gp-help"><?= gp_e(gp_t($gdef[2])) ?></span>
				<span class="gp-help"><strong><?= gp_e(gp_t('rules_h_geo_unknown')) ?></strong></span>
				<?php if ($err_text($gk) !== ''): ?><span class="gp-error" role="alert"><?= gp_e($err_text($gk)) ?></span><?php endif; ?>
			</label>
		</div>
	</fieldset>
	<?php endforeach; ?>
	<?php gp_tab_end(); gp_tab_begin('rule', 'action', $rt_tabs['action']); ?>
	<div class="gp-grid-2">
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_f_action')) ?><?= gp_tip('rule_action') ?></span>
			<select class="gp-input" name="action">
				<?php foreach (gv_rule_actions() as $a): ?>
				<option value="<?= gp_e($a) ?>"<?= $sel($form['action'], $a) ?>><?= gp_e(gp_t('rules_act_' . $a)) ?></option>
				<?php endforeach; ?>
			</select>
			<span class="gp-help"><?= gp_e(gp_t('rules_h_action')) ?></span>
			<?php if ($err_text('action') !== ''): ?><span class="gp-error" role="alert"><?= gp_e($err_text('action')) ?></span><?php endif; ?>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_f_mode')) ?><?= gp_tip('rule_mode') ?></span>
			<select class="gp-input" name="mode">
				<option value="monitor"<?= $sel($form['mode'], 'monitor') ?>><?= gp_e(gp_t('rules_mode_monitor')) ?></option>
				<option value="enforce"<?= $sel($form['mode'], 'enforce') ?>><?= gp_e(gp_t('rules_mode_enforce')) ?></option>
			</select>
			<span class="gp-help"><?= gp_e(gp_t('rules_h_mode')) ?></span>
			<?php if ($err_text('mode') !== ''): ?><span class="gp-error" role="alert"><?= gp_e($err_text('mode')) ?></span><?php endif; ?>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_f_pow')) ?><?= gp_tip('rule_pow') ?></span>
			<input class="gp-input gp-ltr" type="number" name="pow_bits" min="0" max="22" value="<?= gp_e((string)$form['pow_bits']) ?>">
			<span class="gp-help"><?= gp_e(gp_t('rules_h_pow')) ?></span>
			<?php if ($err_text('pow_bits') !== ''): ?><span class="gp-error" role="alert"><?= gp_e($err_text('pow_bits')) ?></span><?php endif; ?>
		</label>

		<div class="gp-field">
			<label class="gp-check"><input type="checkbox" name="skip_verified_bots" value="1"<?= $form['skip_verified_bots'] ? ' checked' : '' ?>>
				<span><?= gp_e(gp_t('rules_f_skip')) ?></span><?= gp_tip('rule_skip') ?></label>
			<span class="gp-help"><?= gp_e(gp_t('rules_h_skip')) ?></span>
		</div>
	</div>
	<?php gp_tab_end(); gp_tab_begin('rule', 'advanced', $rt_tabs['advanced']); ?>
	<div class="gp-grid-2">
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_f_priority')) ?><?= gp_tip('rule_priority') ?></span>
			<input class="gp-input gp-ltr" type="number" name="priority" min="1" max="100000" value="<?= gp_e((string)$form['priority']) ?>">
			<span class="gp-help"><?= gp_e(gp_t('rules_h_priority')) ?></span>
			<?php if ($err_text('priority') !== ''): ?><span class="gp-error" role="alert"><?= gp_e($err_text('priority')) ?></span><?php endif; ?>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_f_expires')) ?><?= gp_tip('rule_expires') ?></span>
			<input class="gp-input gp-ltr" type="date" name="expires_date" value="<?= gp_e($exp_date) ?>">
			<span class="gp-help"><?= gp_e(gp_t('rules_h_expires')) ?></span>
			<?php if ($err_text('expires_at') !== ''): ?><span class="gp-error" role="alert"><?= gp_e($err_text('expires_at')) ?></span><?php endif; ?>
		</label>

		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_f_note')) ?><?= gp_tip('rule_note') ?></span>
			<input class="gp-input" type="text" name="note" maxlength="300" value="<?= gp_e($form['note']) ?>">
		</label>

		<div class="gp-field">
		<label class="gp-check"><input type="checkbox" name="enabled" value="1"<?= $form['enabled'] ? ' checked' : '' ?>>
			<span><?= gp_e(gp_t('rules_f_enabled')) ?></span><?= gp_tip('rule_enabled') ?></label>
		</div>
	</div>
	<?php gp_tab_end(); gp_tabs_end(); ?>

	<?php if (is_array($impact ?? null)): $im = $impact; $mt = $im['meta']; ?>
	<div class="gp-note<?= $im['danger'] ? ' gp-note-strong' : '' ?>" role="status"<?= $im['danger'] ? ' style="border-color:#c0392b"' : '' ?>>
		<strong><?= gp_e(gp_t('rules_impact')) ?></strong>
		<?php if ($im['danger']): ?>
		<div class="gp-text-bad" role="alert"><?= gp_e(gp_t('rules_impact_danger')) ?></div>
		<?php endif; ?>
		<div class="gp-help"><?= gp_e(gp_t('rules_impact_range')) ?>:
			<?= $mt['oldest'] > 0 ? gp_e(gp_num_raw(date('Y-m-d H:i', (int)$mt['oldest'])) . ' - ' . gp_num_raw(date('Y-m-d H:i', (int)$mt['newest']))) : '—' ?>
			(<?= gp_e(gp_num($im['scanned'])) ?> <?= gp_e(gp_t('rules_impact_rows')) ?>, <?= gp_e(gp_num($mt['files'])) ?> <?= gp_e(gp_t('rules_impact_files')) ?><?= $mt['capped'] ? ', ' . gp_e(gp_t('rules_impact_capped')) : '' ?>)</div>
		<?php if (!empty($im['geo'])): $gl = (int)$im['geo_logged']; $gk2 = (int)$im['geo_lookup']; $gn = (int)$im['geo_none']; ?>
		<div class="gp-help" role="status"><strong><?= gp_e(gp_t('rules_impact_geo')) ?>:</strong>
			<?php if ($im['scanned'] > 0 && $gl === 0 && $gk2 === 0): ?><?= gp_e(gp_t('rules_impact_geo_blind')) ?>
			<?php elseif ($gl === 0): ?><?= gp_e(gp_t('rules_impact_geo_nolog')) ?>
			<?php else: ?><?= gp_e(gp_t('rules_impact_geo_mixed')) ?><?php endif; ?>
			(<?= gp_e(gp_num($gl)) ?> <?= gp_e(gp_t('rules_impact_geo_logged')) ?>, <?= gp_e(gp_num($gk2)) ?> <?= gp_e(gp_t('rules_impact_geo_lookup')) ?>, <?= gp_e(gp_num($gn)) ?> <?= gp_e(gp_t('rules_impact_geo_none')) ?>)</div>
		<?php endif; ?>
		<dl class="gp-dl">
			<dt><?= gp_e(gp_t('rules_impact_requests')) ?></dt><dd class="gp-mono"><?= gp_e(gp_num($im['requests'])) ?></dd>
			<dt><?= gp_e(gp_t('rules_impact_ips')) ?></dt><dd class="gp-mono"><?= gp_e(gp_num($im['ips'])) ?></dd>
			<dt><?= gp_e(gp_t('rules_impact_devices')) ?></dt><dd class="gp-mono"><?= gp_e(gp_num($im['devices'])) ?></dd>
			<dt><?= gp_e(gp_t('rules_impact_tokened')) ?></dt><dd class="gp-mono"><?= gp_e(gp_num($im['tokened'])) ?></dd>
		</dl>
		<?php if ($im['paths']): ?>
		<div class="gp-help"><?= gp_e(gp_t('rules_impact_paths')) ?>:</div>
		<ul class="gp-mono gp-ltr">
			<?php foreach ($im['paths'] as $ip_path => $ip_n): ?><li><?= gp_e($ip_path) ?> &times; <?= gp_e(gp_num($ip_n)) ?></li><?php endforeach; ?>
		</ul>
		<?php elseif ($im['requests'] === 0 && !(!empty($im['geo']) && (int)$im['geo_logged'] === 0 && (int)$im['geo_lookup'] === 0)): ?><div class="gp-help"><?= gp_e(gp_t('rules_impact_none')) ?></div><?php endif; ?>
		<div class="gp-help"><?= gp_e(gp_t('rules_impact_note')) ?></div>
	</div>
	<?php endif; ?>

	<div class="gp-row-head">
		<button class="gp-btn gp-btn-primary" type="submit"><?= gp_e(gp_t(!empty($warnings) ? 'rules_save_anyway' : 'save')) ?></button>
		<button class="gp-btn gp-btn-ghost" type="submit" name="do" value="preview"><?= gp_e(gp_t('rules_preview')) ?></button>
		<a class="gp-btn gp-btn-ghost" href="index.php?r=rules"><?= gp_e(gp_t('cancel')) ?></a>
	</div>
</form>
<?php endif; ?>

<?php /* ------------------------------------------------------------ test box */ ?>
<form method="get" action="index.php" class="gp-card gp-form">
	<input type="hidden" name="r" value="rules">
	<div class="gp-card-title"><?= gp_e(gp_t('rules_test')) ?></div>
	<p class="gp-help"><?= gp_e(gp_t('rules_test_help')) ?></p>
	<div class="gp-grid-2">
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_test_ua')) ?></span>
			<input class="gp-input gp-ltr" type="text" name="test_ua" value="<?= gp_e($test_in['ua']) ?>" spellcheck="false">
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_test_path')) ?></span>
			<input class="gp-input gp-ltr" type="text" name="test_path" value="<?= gp_e($test_in['path']) ?>" placeholder="/">
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_test_ip')) ?></span>
			<input class="gp-input gp-ltr" type="text" name="test_ip" value="<?= gp_e($test_in['ip']) ?>" placeholder="203.0.113.7">
		</label>
	</div>
	<label class="gp-check"><input type="checkbox" name="test_verified" value="1"<?= $test_in['verified'] ? ' checked' : '' ?>>
		<span><?= gp_e(gp_t('rules_test_verified')) ?></span></label>
	<div class="gp-row-head"><button class="gp-btn gp-btn-primary" type="submit" name="test" value="1"><?= gp_e(gp_t('rules_test_run')) ?></button></div>
	<?php if ($test !== null): ?>
	<div class="gp-note<?= $test['winner'] ? ' gp-note-strong' : '' ?>" role="status">
		<?php if ($test['ip'] !== ''): ?><div><?= gp_e(gp_t('rules_test_geo')) ?>: <code class="gp-mono"><?= gp_e($test['cc'] !== '' ? $test['cc'] : gp_t('geo_unknown')) ?></code>
			/ <code class="gp-mono"><?= gp_e($test['asn'] > 0 ? 'AS' . $test['asn'] : gp_t('geo_unknown')) ?></code></div><?php endif; ?>
		<?php if ($test['bot'] !== ''): ?><div><?= gp_e(gp_t('rules_test_bot')) ?>: <code class="gp-mono"><?= gp_e($test['bot']) ?></code></div><?php endif; ?>
		<?php if ($test['winner']): $w = $test['winner']; ?>
		<div><strong><?= gp_e(gp_t('rules_test_winner')) ?>:</strong> <?= gp_e($w['name']) ?> (<code class="gp-mono"><?= gp_e($w['id']) ?></code>)
			&rarr; <?= gp_e(gp_t('rules_act_' . $w['action'])) ?>,
			<?= gp_e(gp_t('rules_mode_' . $w['mode'])) ?></div>
		<div class="gp-help"><?= gp_e(gp_t($w['mode'] === 'monitor' ? 'rules_test_monitor' : 'rules_test_enforce')) ?></div>
		<?php else: ?>
		<div><?= gp_e(gp_t('rules_test_none')) ?></div>
		<?php endif; ?>
		<?php if (count($test['matches']) > 1 || $test['skipped']): ?>
		<div class="gp-help"><?= gp_e(gp_t('rules_test_also')) ?>:
			<?php foreach ($test['matches'] as $m): ?>
			<code class="gp-mono"><?= gp_e($m['id']) ?></code><?= in_array($m['id'], $test['skipped'], true) ? ' (' . gp_e(gp_t('rules_test_skipped')) . ')' : '' ?>
			<?php endforeach; ?>
		</div>
		<?php endif; ?>
	</div>
	<?php endif; ?>
</form>

<?php /* ------------------------------------------------------------ table */ ?>
<div class="gp-card">
	<div class="gp-card-title">
		<?= gp_e(gp_t('rules_list')) ?> <span class="gp-card-sub"><?= gp_num(count($visible)) ?> / <?= gp_num(count($all)) ?></span>
	</div>

	<?php
	$rflt = array('action' => array('rules_flt_action', 'is', array('block', 'challenge', 'log')), 'mode' => array('rules_flt_mode', 'is', array('enforce', 'monitor')),
		'state' => array('rules_flt_state', 'is', array('active', 'disabled', 'expired')), 'cc' => array('geo_cc', 'is', array(GP_FILTER_NONE)),
		'asn' => array('geo_asn', 'is', array(GP_FILTER_NONE)), 'ua' => array('logs_ua', 'has', array()), 'q' => array('rules_flt_q', 'has', array()));
	$rchips = gp_filter_chips($filter, array_map(function ($d) { return gp_t($d[0]); }, $rflt),
		array_map(function ($d) { return $d[1] === 'has' ? 'text' : 'choice'; }, $rflt),
		function ($q) { return 'index.php?' . http_build_query(array_merge(array('r' => 'rules'), $q)); });
	?>
	<form method="get" action="index.php" class="gp-form">
		<input type="hidden" name="r" value="rules">
		<div class="gp-filters gp-filters-3">
			<?php foreach ($rflt as $fk => $fd): $fv = isset($filter[$fk]) ? $filter[$fk] : null; ?>
			<div class="gp-field">
				<label class="gp-label" for="rf-<?= gp_e($fk) ?>"><?= gp_e(gp_t($fd[0])) ?><?= gp_tip($fk === 'q' ? 'flt_q' : ($fk === 'action' || $fk === 'mode' ? 'rule_' . $fk : 'flt_' . $fk)) ?></label>
				<div class="gp-fgroup">
					<?= gp_filter_op_select($fk, $fv, $fd[1]) ?>
					<input class="gp-input gp-ltr" type="text" id="rf-<?= gp_e($fk) ?>" name="<?= gp_e($fk) ?>" value="<?= gp_e(gp_filter_text($fv)) ?>"
						<?= $fd[2] ? 'list="rdl-' . gp_e($fk) . '"' : '' ?> spellcheck="false" autocomplete="off">
					<?php if ($fd[2]): ?><datalist id="rdl-<?= gp_e($fk) ?>"><?php foreach ($fd[2] as $o): ?><option value="<?= gp_e($o) ?>"><?php endforeach; ?></datalist><?php endif; ?>
				</div>
			</div>
			<?php endforeach; ?>
		</div>
		<div class="gp-row-head">
			<button class="gp-btn gp-btn-ghost" type="submit"><?= gp_e(gp_t('filter')) ?></button>
			<a class="gp-btn gp-btn-ghost" href="index.php?r=rules"><?= gp_e(gp_t('reset')) ?></a>
			<a class="gp-btn gp-btn-primary" href="index.php?r=rules&amp;new=1"><?= gp_e(gp_t('rules_new')) ?></a>
		</div>
		<?= gp_filter_chips_html($rchips) ?>
	</form>
	<form method="post" action="index.php?r=rules" style="margin-top:.5rem">
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit" name="do" value="starter"><?= gp_e(gp_t('rules_starter')) ?></button>
		<span class="gp-help"><?= gp_e(gp_t('rules_starter_help')) ?></span>
	</form>

	<?php if (!$visible): ?>
		<p class="gp-help"><?= gp_e(gp_t($all ? 'no_results' : 'rules_empty')) ?></p>
	<?php else: ?>
	<div class="gp-table-wrap">
	<table class="gp-table">
		<thead><tr>
			<th><?= gp_e(gp_t('rules_c_pri')) ?></th><th><?= gp_e(gp_t('rules_f_name')) ?></th>
			<th><?= gp_e(gp_t('rules_c_cond')) ?></th><th><?= gp_e(gp_t('rules_f_action')) ?></th>
			<th><?= gp_e(gp_t('rules_f_mode')) ?></th><th><?= gp_e(gp_t('rules_c_state')) ?></th>
			<th><?= gp_e(gp_t('rules_f_expires')) ?></th><th><?= gp_e(gp_t('rules_c_hits')) ?></th>
			<th><?= gp_e(gp_t('rules_c_last')) ?></th><th></th>
		</tr></thead>
		<tbody>
		<?php foreach ($visible as $r):
			$h = isset($rule_hits[$r['id']]) && is_array($rule_hits[$r['id']]) ? $rule_hits[$r['id']] : array();
			$expired = ((int)$r['expires_at'] !== 0 && (int)$r['expires_at'] <= $now);
			$post = function ($do, $label, $extra = '', $confirm = '') use ($r) {
				return '<form method="post" action="index.php?r=rules" style="display:inline"' . ($confirm !== '' ? ' data-confirm="' . gp_e($confirm) . '"' : '') . '>'
					. '<input type="hidden" name="csrf" value="' . gp_e(gp_csrf_token()) . '">'
					. '<input type="hidden" name="id" value="' . gp_e($r['id']) . '">' . $extra
					. '<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit" name="do" value="' . gp_e($do) . '">' . gp_e($label) . '</button></form>';
			};
		?>
		<tr>
			<td class="gp-mono">
				<?= gp_e((string)$r['priority']) ?>
				<?= $post('move', "\u{2191}", '<input type="hidden" name="dir" value="up">') ?>
				<?= $post('move', "\u{2193}", '<input type="hidden" name="dir" value="down">') ?>
			</td>
			<td><strong><?= gp_e($r['name']) ?></strong><br><code class="gp-mono"><?= gp_e($r['id']) ?></code></td>
			<td class="gp-mono gp-ltr"><?= gp_e(gp_rule_cond_text('UA', $r['ua'])) ?><?= ($r['ua'] && $r['path']) ? '<br>' : '' ?><?= gp_e(gp_rule_cond_text('path', $r['path'])) ?>
				<?php foreach (array('country' => 'country', 'asn' => 'ASN') as $gk => $gl): if (!empty($r[$gk])): ?><br><?= gp_e(gp_rule_cond_text($gl, $r[$gk])) ?><?php endif; endforeach; ?></td>
			<td><span class="gp-badge <?= $r['action'] === 'block' ? 'gp-badge-bad' : ($r['action'] === 'challenge' ? 'gp-badge-warn' : 'gp-badge-info') ?>"><?= gp_e(gp_t('rules_act_' . $r['action'])) ?></span></td>
			<td><span class="gp-badge <?= $r['mode'] === 'enforce' ? 'gp-badge-on' : 'gp-badge-off' ?>"><?= gp_e(gp_t('rules_mode_' . $r['mode'])) ?></span></td>
			<td><span class="gp-badge <?= (!$r['enabled'] || $expired) ? 'gp-badge-off' : 'gp-badge-on' ?>"><?= gp_e(gp_t(!$r['enabled'] ? 'off' : ($expired ? 'rules_expired' : 'on'))) ?></span></td>
			<td class="gp-mono"><?= $r['expires_at'] ? gp_e(gmdate('Y-m-d', (int)$r['expires_at'])) : gp_e(gp_t('never')) ?></td>
			<td class="gp-mono"><?= isset($snapshot['rules']) ? gp_e(gp_num((int)($h['h24'] ?? 0)) . ' / ' . gp_num((int)($h['d7'] ?? 0))) : '—' ?></td>
			<td class="gp-mono"><?= !empty($h['last']) ? gp_e(gp_age((int)$h['last'])) . ' ' . gp_e(gp_t('ago')) : '—' ?></td>
			<td>
				<a class="gp-btn gp-btn-ghost gp-btn-sm" href="index.php?r=rules&amp;edit=<?= gp_u($r['id']) ?>"><?= gp_e(gp_t('rules_edit')) ?></a>
				<?= $post('duplicate', gp_t('rules_duplicate')) ?>
				<?= $post('toggle', gp_t($r['enabled'] ? 'rules_disable' : 'rules_enable')) ?>
				<?= $post('delete', gp_t('rules_delete'), '', gp_t('rules_delete_confirm')) ?>
			</td>
		</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	</div>
	<?php endif; ?>
</div>
