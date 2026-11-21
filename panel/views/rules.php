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
			<span class="gp-label"><?= gp_e(gp_t('rules_f_name')) ?></span>
			<input class="gp-input" type="text" name="name" maxlength="80" value="<?= gp_e($form['name']) ?>">
			<span class="gp-help"><?= gp_e(gp_t('rules_h_name')) ?></span>
			<?php if ($err_text('name') !== ''): ?><span class="gp-error" role="alert"><?= gp_e($err_text('name')) ?></span><?php endif; ?>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_f_priority')) ?></span>
			<input class="gp-input gp-ltr" type="number" name="priority" min="1" max="100000" value="<?= gp_e((string)$form['priority']) ?>">
			<span class="gp-help"><?= gp_e(gp_t('rules_h_priority')) ?></span>
			<?php if ($err_text('priority') !== ''): ?><span class="gp-error" role="alert"><?= gp_e($err_text('priority')) ?></span><?php endif; ?>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_f_action')) ?></span>
			<select class="gp-input" name="action">
				<?php foreach (gv_rule_actions() as $a): ?>
				<option value="<?= gp_e($a) ?>"<?= $sel($form['action'], $a) ?>><?= gp_e(gp_t('rules_act_' . $a)) ?></option>
				<?php endforeach; ?>
			</select>
			<span class="gp-help"><?= gp_e(gp_t('rules_h_action')) ?></span>
			<?php if ($err_text('action') !== ''): ?><span class="gp-error" role="alert"><?= gp_e($err_text('action')) ?></span><?php endif; ?>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_f_mode')) ?></span>
			<select class="gp-input" name="mode">
				<option value="monitor"<?= $sel($form['mode'], 'monitor') ?>><?= gp_e(gp_t('rules_mode_monitor')) ?></option>
				<option value="enforce"<?= $sel($form['mode'], 'enforce') ?>><?= gp_e(gp_t('rules_mode_enforce')) ?></option>
			</select>
			<span class="gp-help"><?= gp_e(gp_t('rules_h_mode')) ?></span>
			<?php if ($err_text('mode') !== ''): ?><span class="gp-error" role="alert"><?= gp_e($err_text('mode')) ?></span><?php endif; ?>
		</label>
	</div>

	<fieldset class="gp-section">
		<legend class="gp-label"><?= gp_e(gp_t('rules_f_ua')) ?></legend>
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
		<legend class="gp-label"><?= gp_e(gp_t('rules_f_path')) ?></legend>
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

	<div class="gp-grid-2">
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_f_expires')) ?></span>
			<input class="gp-input gp-ltr" type="date" name="expires_date" value="<?= gp_e($exp_date) ?>">
			<span class="gp-help"><?= gp_e(gp_t('rules_h_expires')) ?></span>
			<?php if ($err_text('expires_at') !== ''): ?><span class="gp-error" role="alert"><?= gp_e($err_text('expires_at')) ?></span><?php endif; ?>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_f_pow')) ?></span>
			<input class="gp-input gp-ltr" type="number" name="pow_bits" min="0" max="22" value="<?= gp_e((string)$form['pow_bits']) ?>">
			<span class="gp-help"><?= gp_e(gp_t('rules_h_pow')) ?></span>
			<?php if ($err_text('pow_bits') !== ''): ?><span class="gp-error" role="alert"><?= gp_e($err_text('pow_bits')) ?></span><?php endif; ?>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_f_note')) ?></span>
			<input class="gp-input" type="text" name="note" maxlength="300" value="<?= gp_e($form['note']) ?>">
		</label>
		<div class="gp-field">
			<label class="gp-check"><input type="checkbox" name="enabled" value="1"<?= $form['enabled'] ? ' checked' : '' ?>>
				<span><?= gp_e(gp_t('rules_f_enabled')) ?></span></label>
			<label class="gp-check"><input type="checkbox" name="skip_verified_bots" value="1"<?= $form['skip_verified_bots'] ? ' checked' : '' ?>>
				<span><?= gp_e(gp_t('rules_f_skip')) ?></span></label>
			<span class="gp-help"><?= gp_e(gp_t('rules_h_skip')) ?></span>
		</div>
	</div>

	<div class="gp-row-head">
		<button class="gp-btn gp-btn-primary" type="submit"><?= gp_e(gp_t(!empty($warnings) ? 'rules_save_anyway' : 'save')) ?></button>
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
	</div>
	<label class="gp-check"><input type="checkbox" name="test_verified" value="1"<?= $test_in['verified'] ? ' checked' : '' ?>>
		<span><?= gp_e(gp_t('rules_test_verified')) ?></span></label>
	<div class="gp-row-head"><button class="gp-btn gp-btn-primary" type="submit" name="test" value="1"><?= gp_e(gp_t('rules_test_run')) ?></button></div>
	<?php if ($test !== null): ?>
	<div class="gp-note<?= $test['winner'] ? ' gp-note-strong' : '' ?>" role="status">
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

	<form method="get" action="index.php" class="gp-form">
		<input type="hidden" name="r" value="rules">
		<div class="gp-filters">
			<?php foreach (array('action' => array('block', 'challenge', 'log'), 'mode' => array('enforce', 'monitor'),
				'state' => array('active', 'disabled', 'expired')) as $fk => $opts): ?>
			<div class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('rules_flt_' . $fk)) ?></span>
				<select class="gp-input" name="<?= gp_e($fk) ?>_op" aria-label="<?= gp_e(gp_t('rules_flt_op')) ?>">
					<option value="is"><?= gp_e(gp_t('rules_flt_is')) ?></option>
					<option value="not"<?= (($filter[$fk . '_op'] ?? '') === 'not') ? ' selected' : '' ?>><?= gp_e(gp_t('rules_flt_not')) ?></option>
				</select>
				<select class="gp-input" name="<?= gp_e($fk) ?>">
					<option value=""><?= gp_e(gp_t('any')) ?></option>
					<?php foreach ($opts as $o): ?>
					<option value="<?= gp_e($o) ?>"<?= (isset($filter[$fk]) && $filter[$fk] === array($o)) ? ' selected' : '' ?>><?= gp_e($o) ?></option>
					<?php endforeach; ?>
				</select>
			</div>
			<?php endforeach; ?>
			<div class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('rules_flt_q')) ?></span>
				<select class="gp-input" name="q_op" aria-label="<?= gp_e(gp_t('rules_flt_op')) ?>">
					<option value="is"><?= gp_e(gp_t('rules_flt_has')) ?></option>
					<option value="not"<?= (($filter['q_op'] ?? '') === 'not') ? ' selected' : '' ?>><?= gp_e(gp_t('rules_flt_hasnot')) ?></option>
				</select>
				<input class="gp-input" type="text" name="q" value="<?= gp_e($filter['q'] ?? '') ?>">
			</div>
		</div>
		<div class="gp-row-head">
			<button class="gp-btn gp-btn-ghost" type="submit"><?= gp_e(gp_t('filter')) ?></button>
			<a class="gp-btn gp-btn-ghost" href="index.php?r=rules"><?= gp_e(gp_t('reset')) ?></a>
			<a class="gp-btn gp-btn-primary" href="index.php?r=rules&amp;new=1"><?= gp_e(gp_t('rules_new')) ?></a>
			<span style="margin-inline-start:auto"></span>
		</div>
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
			<td class="gp-mono gp-ltr"><?= gp_e(gp_rule_cond_text('UA', $r['ua'])) ?><?= ($r['ua'] && $r['path']) ? '<br>' : '' ?><?= gp_e(gp_rule_cond_text('path', $r['path'])) ?></td>
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
