<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// IP lists: the lists table, the editor (paste or upload), the entries of one list,
// the lookup tester and the compile status.
//
// List names, notes, entries and error text come from the operator or from uploaded
// files: all of it goes through gp_e().
$now = time();
$form = is_array($edit ?? null) ? $edit : null;
$sv = is_array($save ?? null) ? $save : null;
$errors = $sv ? $sv['errors'] : array();
$report = $sv ? $sv['report'] : null;
$mb = function ($b) { return $b >= 1048576 ? sprintf('%.1f MiB', $b / 1048576) : sprintf('%.0f KiB', $b / 1024); };
$sel = function ($a, $b) { return $a === $b ? ' selected' : ''; };
$wcodes = array();
foreach ($health as $h) { $wcodes[] = $h; }
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('ipl_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('ipl_sub')) ?></p>
</div>

<?php if ($state['state'] === 'invalid'): ?><div class="gp-note gp-note-strong" role="alert"><?= gp_e(gp_t('ipl_file_invalid')) ?></div><?php endif; ?>
<?php foreach ($wcodes as $h): ?>
<div class="gp-note gp-note-strong" role="alert"><?= gp_e(gp_t('al_iplist_' . $h[0])) ?><?= $h[1] !== '' ? ': ' . gp_e((string)$h[1]) : '' ?></div>
<?php endforeach; ?>
<?php foreach ($warnings as $w): ?>
<div class="gp-note gp-note-strong" role="alert"><strong><?= gp_e(gp_t('ipl_w_' . $w[0])) ?></strong><?= $w[1] !== '' ? ' <span class="gp-mono gp-ltr">' . gp_e($w[1]) . '</span>' : '' ?></div>
<?php endforeach; ?>
<div class="gp-note"><?= gp_e(gp_t('ipl_precedence')) ?></div>

<?php
$it = array('lists' => gp_t('ipl_tab_lists'), 'editor' => gp_t('ipl_tab_editor'), 'entries' => gp_t('ipl_tab_entries'), 'tester' => gp_t('ipl_tab_tester'), 'compile' => gp_t('ipl_tab_compile'));
gp_tabs_begin('ipl', $it, $sv ? array('editor' => max(1, count($errors))) : array());
gp_tab_begin('ipl', 'lists', $it['lists']);
?>
<div class="gp-card">
	<div class="gp-card-title"><?= gp_e(gp_t('ipl_list')) ?> <span class="gp-card-sub"><?= gp_num(count($visible)) ?> / <?= gp_num(count($all)) ?></span></div>
	<?php
	$lflt = array('name' => array('ipl_f_name', 'has', array(), 'ipl_filter_name'), 'type' => array('ipl_f_type', 'is', array('allow', 'block'), 'ipl_type'),
		'mode' => array('ipl_f_mode', 'is', array('enforce', 'monitor'), 'ipl_mode'), 'status' => array('ipl_f_status', 'is', array('enabled', 'disabled'), 'ipl_enabled'));
	$lchips = gp_filter_chips($filter, array_map(function ($d) { return gp_t($d[0]); }, $lflt),
		array_map(function ($d) { return $d[1] === 'has' ? 'text' : 'choice'; }, $lflt),
		function ($q) { return 'index.php?' . http_build_query(array_merge(array('r' => 'iplists'), $q)); });
	?>
	<form method="get" action="index.php" class="gp-form">
		<input type="hidden" name="r" value="iplists">
		<div class="gp-filters gp-filters-3">
			<?php foreach ($lflt as $fk => $fd): $fv = isset($filter[$fk]) ? $filter[$fk] : null; ?>
			<div class="gp-field">
				<label class="gp-label" for="lf-<?= gp_e($fk) ?>"><?= gp_e(gp_t($fd[0])) ?><?= gp_tip($fd[3]) ?></label>
				<div class="gp-fgroup">
					<?= gp_filter_op_select($fk, $fv, $fd[1]) ?>
					<input class="gp-input gp-ltr" type="text" id="lf-<?= gp_e($fk) ?>" name="<?= gp_e($fk) ?>" value="<?= gp_e(gp_filter_text($fv)) ?>"
						<?= $fd[2] ? 'list="ldl-' . gp_e($fk) . '"' : '' ?> spellcheck="false" autocomplete="off">
					<?php if ($fd[2]): ?><datalist id="ldl-<?= gp_e($fk) ?>"><?php foreach ($fd[2] as $o): ?><option value="<?= gp_e($o) ?>"><?php endforeach; ?></datalist><?php endif; ?>
				</div>
			</div>
			<?php endforeach; ?>
		</div>
		<div class="gp-row-head">
			<button class="gp-btn gp-btn-ghost" type="submit"><?= gp_e(gp_t('filter')) ?></button>
			<a class="gp-btn gp-btn-ghost" href="index.php?r=iplists"><?= gp_e(gp_t('reset')) ?></a>
			<a class="gp-btn gp-btn-primary" href="index.php?r=iplists&amp;new=1&amp;type=block#ipl-editor"><?= gp_e(gp_t('ipl_new_block')) ?></a>
			<a class="gp-btn gp-btn-primary" href="index.php?r=iplists&amp;new=1&amp;type=allow#ipl-editor"><?= gp_e(gp_t('ipl_new_allow')) ?></a>
		</div>
		<?= gp_filter_chips_html($lchips) ?>
	</form>
	<?php if ($pending): ?><div class="gp-note"><?= gp_e(gp_t('ipl_pending')) ?></div><?php endif; ?>
	<?php if (!$visible): ?>
		<p class="gp-help"><?= gp_e(gp_t($all ? 'no_results' : 'ipl_empty')) ?></p>
	<?php else: ?>
	<div class="gp-table-wrap">
	<table class="gp-table">
		<thead><tr>
			<th><?= gp_e(gp_t('ipl_f_name')) ?></th><th><?= gp_e(gp_t('ipl_f_type')) ?></th><th><?= gp_e(gp_t('ipl_f_mode')) ?></th>
			<th><?= gp_e(gp_t('ipl_f_status')) ?></th><th><?= gp_e(gp_t('ipl_c_entries')) ?></th><th><?= gp_e(gp_t('ipl_c_addr')) ?></th>
			<th><?= gp_e(gp_t('rules_c_hits')) ?></th><th><?= gp_e(gp_t('rules_c_last')) ?></th><th></th>
		</tr></thead>
		<tbody>
		<?php foreach ($visible as $r):
			$c = $r['stat']; $h = $r['hit'];
			$post = function ($do, $label, $extra = '', $confirm = '') use ($r) {
				return '<form method="post" action="index.php?r=iplists" style="display:inline"' . ($confirm !== '' ? ' data-confirm="' . gp_e($confirm) . '"' : '') . '>'
					. '<input type="hidden" name="csrf" value="' . gp_e(gp_csrf_token()) . '"><input type="hidden" name="id" value="' . gp_e($r['id']) . '">' . $extra
					. '<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit" name="do" value="' . gp_e($do) . '">' . gp_e($label) . '</button></form>';
			};
		?>
		<tr>
			<td><strong><?= gp_e($r['name']) ?></strong><br><code class="gp-mono"><?= gp_e($r['id']) ?></code><?= $r['note'] !== '' ? '<br><span class="gp-help">' . gp_e($r['note']) . '</span>' : '' ?></td>
			<td><span class="gp-badge <?= $r['type'] === 'block' ? 'gp-badge-bad' : 'gp-badge-on' ?>"><?= gp_e(gp_t('ipl_type_' . $r['type'])) ?></span></td>
			<td><span class="gp-badge <?= $r['mode'] === 'enforce' ? 'gp-badge-on' : 'gp-badge-off' ?>"><?= gp_e(gp_t('rules_mode_' . $r['mode'])) ?></span></td>
			<td><span class="gp-badge <?= $r['enabled'] ? 'gp-badge-on' : 'gp-badge-off' ?>"><?= gp_e(gp_t($r['enabled'] ? 'on' : 'off')) ?></span></td>
			<td class="gp-mono"><?= $c ? gp_e(gp_num((int)$c['entries'])) . ($c['invalid'] ? ' <span class="gp-badge gp-badge-warn">' . gp_e(gp_num((int)$c['invalid'])) . ' ' . gp_e(gp_t('ipl_invalid_short')) . '</span>' : '') : '—' ?></td>
			<td class="gp-mono"><?= $c ? gp_e(gp_num((int)$c['addresses'])) . ($c['v6'] ? ' + ' . gp_e(gp_num((int)$c['v6'])) . ' IPv6' : '') : '—' ?></td>
			<td class="gp-mono"><?= $h ? gp_e(gp_num((int)($h['h24'] ?? 0)) . ' / ' . gp_num((int)($h['d7'] ?? 0))) : '—' ?></td>
			<td class="gp-mono"><?= !empty($h['last']) ? gp_e(gp_age((int)$h['last'])) . ' ' . gp_e(gp_t('ago')) : '—' ?></td>
			<td>
				<a class="gp-btn gp-btn-ghost gp-btn-sm" href="index.php?r=iplists&amp;edit=<?= gp_u($r['id']) ?>#ipl-editor"><?= gp_e(gp_t('rules_edit')) ?></a>
				<a class="gp-btn gp-btn-ghost gp-btn-sm" href="index.php?r=iplists&amp;list=<?= gp_u($r['id']) ?>#ipl-entries"><?= gp_e(gp_t('ipl_entries')) ?></a>
				<a class="gp-btn gp-btn-ghost gp-btn-sm" href="index.php?r=iplists&amp;export=<?= gp_u($r['id']) ?>"><?= gp_e(gp_t('ipl_export')) ?></a>
				<?= $post('set', gp_t($r['enabled'] ? 'rules_disable' : 'rules_enable'), '<input type="hidden" name="enabled" value="' . ($r['enabled'] ? '0' : '1') . '">') ?>
				<?= $post('set', gp_t($r['mode'] === 'enforce' ? 'ipl_to_monitor' : 'ipl_to_enforce'), '<input type="hidden" name="mode" value="' . ($r['mode'] === 'enforce' ? 'monitor' : 'enforce') . '">') ?>
				<?= $post('delete', gp_t('rules_delete'), '', gp_t('ipl_delete_confirm')) ?>
			</td>
		</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	</div>
	<?php endif; ?>
</div>

<?php gp_tab_end(); gp_tab_begin('ipl', 'editor', $it['editor']); ?>
<?php if ($form === null): ?>
<div class="gp-card"><p class="gp-help"><?= gp_e(gp_t('ipl_editor_none')) ?></p>
	<a class="gp-btn gp-btn-primary" href="index.php?r=iplists&amp;new=1&amp;type=block#ipl-editor"><?= gp_e(gp_t('ipl_new_block')) ?></a>
	<a class="gp-btn gp-btn-primary" href="index.php?r=iplists&amp;new=1&amp;type=allow#ipl-editor"><?= gp_e(gp_t('ipl_new_allow')) ?></a></div>
<?php else: ?>
<form method="post" action="index.php?r=iplists" enctype="multipart/form-data" class="gp-card gp-form">
	<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
	<input type="hidden" name="id" value="<?= gp_e((string)$form['id']) ?>">
	<?php if ($sv && $sv['pending'] !== ''): ?><input type="hidden" name="pending" value="<?= gp_e($sv['pending']) ?>"><?php endif; ?>
	<div class="gp-card-title"><?= gp_e(gp_t($form['id'] === '' ? 'ipl_new' : 'ipl_edit')) ?></div>
	<?php if ($report): ?>
	<div class="gp-note gp-note-strong" role="alert">
		<strong><?= gp_e(gp_t('ipl_confirm_title')) ?></strong>
		<?php if ($report['invalid_n']): ?>
		<p><?= gp_e(gp_t('ipl_bad_lines')) ?> (<?= gp_num($report['invalid_n']) ?>):</p>
		<div class="gp-table-wrap"><table class="gp-table"><thead><tr><th><?= gp_e(gp_t('ipl_c_line')) ?></th><th><?= gp_e(gp_t('ipl_c_text')) ?></th></tr></thead><tbody>
			<?php foreach ($report['invalid'] as $b): ?><tr><td class="gp-mono"><?= gp_e((string)$b[0]) ?></td><td class="gp-mono gp-ltr"><?= gp_e($b[1]) ?></td></tr><?php endforeach; ?>
		</tbody></table></div>
		<?php endif; ?>
		<?php if ($report['refused_n']): ?>
		<p><?= gp_e(gp_t('ipl_refused_lines')) ?> (<?= gp_num($report['refused_n']) ?>):</p>
		<div class="gp-table-wrap"><table class="gp-table"><thead><tr><th><?= gp_e(gp_t('ipl_c_line')) ?></th><th><?= gp_e(gp_t('ipl_c_text')) ?></th><th><?= gp_e(gp_t('ipl_c_why')) ?></th></tr></thead><tbody>
			<?php foreach ($report['refused'] as $b): ?><tr><td class="gp-mono"><?= gp_e((string)$b[0]) ?></td><td class="gp-mono gp-ltr"><?= gp_e($b[1]) ?></td><td><?= gp_e(gp_t('ipl_why_' . $b[2])) ?></td></tr><?php endforeach; ?>
		</tbody></table></div>
		<?php endif; ?>
		<label class="gp-check"><input type="checkbox" name="accept" value="1"><span><?= gp_e(gp_t('ipl_accept')) ?></span><?= gp_tip('ipl_accept') ?></label>
	</div>
	<?php endif; ?>
	<fieldset class="gp-section">
		<legend class="gp-label"><?= gp_e(gp_t('ipl_sec_details')) ?></legend>
		<div class="gp-grid-2">
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('ipl_f_name')) ?><?= gp_tip('ipl_name') ?></span>
				<input class="gp-input" type="text" name="name" maxlength="80" value="<?= gp_e($form['name']) ?>">
				<?php if (isset($errors['name'])): ?><span class="gp-error" role="alert"><?= gp_e(gp_t('ipl_err_name')) ?></span><?php endif; ?>
			</label>
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('ipl_f_type')) ?><?= gp_tip('ipl_type') ?></span>
				<?php if ($form['id'] !== ''): ?>
				<input class="gp-input" type="text" value="<?= gp_e(gp_t('ipl_type_' . $form['type'])) ?>" disabled>
				<?php else: ?>
				<select class="gp-input" name="type">
					<option value="block"<?= $sel($form['type'], 'block') ?>><?= gp_e(gp_t('ipl_type_block')) ?></option>
					<option value="allow"<?= $sel($form['type'], 'allow') ?>><?= gp_e(gp_t('ipl_type_allow')) ?></option>
				</select>
				<?php endif; ?>
				<span class="gp-help"><?= gp_e(gp_t('ipl_h_type_' . $form['type'])) ?></span>
			</label>
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('ipl_f_mode')) ?><?= gp_tip('ipl_mode') ?></span>
				<select class="gp-input" name="mode">
					<option value="monitor"<?= $sel($form['mode'], 'monitor') ?>><?= gp_e(gp_t('rules_mode_monitor')) ?></option>
					<option value="enforce"<?= $sel($form['mode'], 'enforce') ?>><?= gp_e(gp_t('rules_mode_enforce')) ?></option>
				</select>
				<span class="gp-help"><?= gp_e(gp_t('ipl_h_mode')) ?></span>
			</label>
			<div class="gp-field">
				<label class="gp-check"><input type="checkbox" name="enabled" value="1"<?= !empty($form['enabled']) ? ' checked' : '' ?>><span><?= gp_e(gp_t('ipl_f_enabled')) ?></span><?= gp_tip('ipl_enabled') ?></label>
			</div>
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('ipl_f_note')) ?><?= gp_tip('ipl_note') ?></span>
				<input class="gp-input" type="text" name="note" maxlength="200" value="<?= gp_e($form['note']) ?>">
			</label>
		</div>
	</fieldset>
	<fieldset class="gp-section">
		<legend class="gp-label"><?= gp_e(gp_t('ipl_sec_content')) ?></legend>
		<p class="gp-help"><?= gp_e(gp_t('ipl_format_help')) ?></p>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('ipl_f_text')) ?><?= gp_tip('ipl_text') ?></span>
			<textarea class="gp-textarea gp-ltr" name="text" rows="8" spellcheck="false" placeholder="203.0.113.0/24&#10;2001:db8::/32&#10;198.51.100.7"></textarea>
			<?php if ($form['id'] !== ''): ?><span class="gp-help"><?= gp_e(gp_t('ipl_h_text_edit')) ?></span><?php endif; ?>
			<?php if (isset($errors['text'])): ?><span class="gp-error" role="alert"><?= gp_e(gp_t('ipl_err_' . $errors['text'])) ?></span><?php endif; ?>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('ipl_f_file')) ?><?= gp_tip('ipl_file') ?></span>
			<input class="gp-input" type="file" name="file" accept=".txt,.csv,.lst,.list">
			<span class="gp-help"><?= $limit > 0 ? gp_e(gp_t('geo_upload_limit')) . ': ' . gp_e($mb($limit)) . '. ' : '' ?><?= gp_e(gp_t('ipl_upload_sftp')) ?></span>
			<?php if (isset($errors['file'])): ?><span class="gp-error" role="alert"><?= gp_e(gp_t('ipl_up_toobig')) ?></span><?php endif; ?>
		</label>
		<div class="gp-field">
			<label class="gp-check"><input type="checkbox" name="force" value="1"<?= !empty($form['force']) ? ' checked' : '' ?>><span><?= gp_e(gp_t('ipl_f_force')) ?></span><?= gp_tip('ipl_force') ?></label>
			<span class="gp-help"><?= gp_e(gp_t('ipl_h_force')) ?></span>
		</div>
	</fieldset>
	<div class="gp-row-head">
		<button class="gp-btn gp-btn-primary" type="submit" name="do" value="save"><?= gp_e(gp_t('save')) ?></button>
		<a class="gp-btn gp-btn-ghost" href="index.php?r=iplists"><?= gp_e(gp_t('cancel')) ?></a>
	</div>
</form>
<?php endif; ?>

<?php gp_tab_end(); gp_tab_begin('ipl', 'entries', $it['entries']); ?>
<div class="gp-card gp-form">
	<div class="gp-card-title"><?= gp_e(gp_t('ipl_entries')) ?></div>
	<?php
	$eflt = array('entry' => array('ipl_c_text', 'has', array(), 'ipl_f_entry'), 'family' => array('ipl_c_family', 'is', array('v4', 'v6'), 'ipl_f_family'));
	$echips = gp_filter_chips($efilter, array_map(function ($d) { return gp_t($d[0]); }, $eflt), array('entry' => 'text', 'family' => 'choice'),
		function ($q) use ($eid) { return 'index.php?' . http_build_query(array_merge(array('r' => 'iplists', 'list' => $eid), $q)) . '#ipl-entries'; });
	?>
	<form method="get" action="index.php#ipl-entries" class="gp-form">
		<input type="hidden" name="r" value="iplists">
		<div class="gp-filters">
			<div class="gp-field">
				<label class="gp-label" for="ent-list"><?= gp_e(gp_t('ipl_f_list')) ?><?= gp_tip('ipl_f_list') ?></label>
				<select class="gp-input" id="ent-list" name="list">
					<option value="">—</option>
					<?php foreach ($all as $r): ?><option value="<?= gp_e($r['id']) ?>"<?= $sel($eid, $r['id']) ?>><?= gp_e($r['name']) ?> (<?= gp_e($r['id']) ?>)</option><?php endforeach; ?>
				</select>
			</div>
			<?php foreach ($eflt as $fk => $fd): $fv = isset($efilter[$fk]) ? $efilter[$fk] : null; ?>
			<div class="gp-field">
				<label class="gp-label" for="ef-<?= gp_e($fk) ?>"><?= gp_e(gp_t($fd[0])) ?><?= gp_tip($fd[3]) ?></label>
				<div class="gp-fgroup">
					<?= gp_filter_op_select($fk, $fv, $fd[1]) ?>
					<input class="gp-input gp-ltr" type="text" id="ef-<?= gp_e($fk) ?>" name="<?= gp_e($fk) ?>" value="<?= gp_e(gp_filter_text($fv)) ?>" spellcheck="false" autocomplete="off">
				</div>
			</div>
			<?php endforeach; ?>
		</div>
		<div class="gp-row-head"><button class="gp-btn gp-btn-ghost" type="submit"><?= gp_e(gp_t('filter')) ?></button>
			<a class="gp-btn gp-btn-ghost" href="index.php?r=iplists#ipl-entries"><?= gp_e(gp_t('reset')) ?></a></div>
		<?= gp_filter_chips_html($echips) ?>
	</form>
	<?php if ($eid === ''): ?><p class="gp-help"><?= gp_e(gp_t('ipl_entries_pick')) ?></p>
	<?php else: ?>
	<p class="gp-help"><?= gp_num($entries[1]) ?> / <?= gp_num($entries[2]) ?> <?= gp_e(gp_t('ipl_c_entries')) ?><?= $entries[3] ? ', ' . gp_num($entries[3]) . ' ' . gp_e(gp_t('ipl_invalid_short')) : '' ?>
		<?= $entries[1] > GP_IPL_SHOW_MAX ? '— ' . gp_e(gp_t('ipl_first')) . ' ' . gp_num(GP_IPL_SHOW_MAX) : '' ?></p>
	<?php $ec = ($status && isset($status['lists'][$eid]) && is_array($status['lists'][$eid])) ? $status['lists'][$eid] : array(); ?>
	<?php if ($ec && ((int)($ec['dropped_n'] ?? 0) > 0 || (int)($ec['invalid'] ?? 0) > 0)): ?>
	<div class="gp-note gp-note-strong" role="status"><strong><?= gp_e(gp_t('ipl_dropped_title')) ?>:</strong>
		<?php foreach ((array)($ec['dropped'] ?? array()) as $why => $n): if ((int)$n > 0): ?><span class="gp-badge gp-badge-warn"><?= gp_e(gp_t('ipl_why_' . $why)) ?>: <?= gp_e(gp_num((int)$n)) ?></span> <?php endif; endforeach; ?>
		<span class="gp-mono gp-ltr"><?php foreach ((array)($ec['dropped_samples'] ?? array()) as $sm): ?><br><?= gp_e((string)$sm[0]) ?> (<?= gp_e((string)$sm[1]) ?>)<?php endforeach; ?>
		<?php foreach ((array)($ec['invalid_samples'] ?? array()) as $sm): ?><br><?= gp_e(gp_t('ipl_c_line') . ' ' . (string)$sm[0] . ': ' . (string)$sm[1]) ?><?php endforeach; ?></span></div>
	<?php endif; ?>
	<?php if ($entries[0]): ?>
	<div class="gp-table-wrap"><table class="gp-table"><thead><tr><th><?= gp_e(gp_t('ipl_c_line')) ?></th><th><?= gp_e(gp_t('ipl_c_text')) ?></th><th><?= gp_e(gp_t('ipl_c_family')) ?></th></tr></thead><tbody>
		<?php foreach ($entries[0] as $en): ?><tr><td class="gp-mono"><?= gp_e((string)$en['line']) ?></td><td class="gp-mono gp-ltr"><?= gp_e($en['text']) ?></td><td class="gp-mono">IPv<?= gp_e((string)$en['v']) ?></td></tr><?php endforeach; ?>
	</tbody></table></div>
	<?php endif; endif; ?>
</div>

<?php gp_tab_end(); gp_tab_begin('ipl', 'tester', $it['tester']); ?>
<form method="get" action="index.php#ipl-tester" class="gp-card gp-form">
	<input type="hidden" name="r" value="iplists">
	<div class="gp-card-title"><?= gp_e(gp_t('ipl_tester')) ?></div>
	<p class="gp-help"><?= gp_e(gp_t('ipl_tester_help')) ?></p>
	<label class="gp-field">
		<span class="gp-label"><?= gp_e(gp_t('rules_test_ip')) ?><?= gp_tip('ipl_ip') ?></span>
		<input class="gp-input gp-ltr" type="text" name="ip" value="<?= gp_e($test_ip) ?>" placeholder="203.0.113.7" spellcheck="false">
	</label>
	<div class="gp-row-head"><button class="gp-btn gp-btn-primary" type="submit" name="test" value="1"><?= gp_e(gp_t('rules_test_run')) ?></button></div>
	<?php if ($test_ran && $test === null): ?>
	<div class="gp-note gp-note-strong" role="alert"><?= gp_e(gp_t('geo_bad_ip')) ?></div>
	<?php elseif ($test !== null): ?>
	<div class="gp-note" role="status">
		<div><strong><?= gp_e(gp_t('ipl_effective')) ?>:</strong> <?= gp_e(gp_t('ipl_eff_' . ($test['effective'] === '' ? 'none' : $test['effective']))) ?></div>
		<?php foreach ($test['live'] as $t => $l): ?>
		<div><?= gp_e(gp_t('ipl_live')) ?>: <?= gp_e(gp_t('ipl_type_' . $t)) ?> &rarr; <code class="gp-mono"><?= gp_e($l['id']) ?></code> (<?= gp_e(gp_t($l['monitor'] ? 'rules_mode_monitor' : 'rules_mode_enforce')) ?>)</div>
		<?php endforeach; ?>
		<?php if ($test['matches']): ?>
		<div class="gp-table-wrap"><table class="gp-table"><thead><tr><th><?= gp_e(gp_t('ipl_f_name')) ?></th><th><?= gp_e(gp_t('ipl_f_type')) ?></th><th><?= gp_e(gp_t('ipl_f_status')) ?></th><th><?= gp_e(gp_t('ipl_c_entry')) ?></th></tr></thead><tbody>
			<?php foreach ($test['matches'] as $m): ?><tr><td><?= gp_e($m['name']) ?> (<code class="gp-mono"><?= gp_e($m['id']) ?></code>)</td><td><?= gp_e(gp_t('ipl_type_' . $m['type'])) ?></td>
				<td><?= gp_e(gp_t($m['enabled'] ? 'on' : 'off')) ?> · <?= gp_e(gp_t('rules_mode_' . $m['mode'])) ?></td><td class="gp-mono gp-ltr"><?= gp_e($m['entry']) ?> (<?= gp_e(gp_t('ipl_c_line')) ?> <?= gp_e((string)$m['line']) ?>)</td></tr><?php endforeach; ?>
		</tbody></table></div>
		<?php else: ?><div><?= gp_e(gp_t('ipl_no_match')) ?></div><?php endif; ?>
	</div>
	<?php endif; ?>
</form>

<?php gp_tab_end(); gp_tab_begin('ipl', 'compile', $it['compile']); ?>
<div class="gp-card gp-form">
	<div class="gp-card-title"><?= gp_e(gp_t('ipl_compile_title')) ?></div>
	<div class="gp-table-wrap"><table class="gp-table"><thead><tr><th><?= gp_e(gp_t('ipl_f_type')) ?></th><th><?= gp_e(gp_t('geo_c_built')) ?></th><th><?= gp_e(gp_t('geo_c_v4')) ?></th><th><?= gp_e(gp_t('geo_c_v6')) ?></th><th><?= gp_e(gp_t('ipl_c_lists')) ?></th><th></th></tr></thead><tbody>
		<?php foreach (array('allow', 'block') as $t): $ti = ($status && is_array($status['types'][$t] ?? null)) ? $status['types'][$t] : null; ?>
		<tr><td><strong><?= gp_e(gp_t('ipl_type_' . $t)) ?></strong><br><code class="gp-mono"><?= gp_e($t) ?>.bin</code></td>
			<?php if ($ti): ?><td class="gp-mono"><?= gp_e(gmdate('Y-m-d H:i', (int)$ti['built'])) ?> UTC</td><td class="gp-mono"><?= gp_e(gp_num((int)$ti['v4'])) ?></td><td class="gp-mono"><?= gp_e(gp_num((int)$ti['v6'])) ?></td>
			<td class="gp-mono gp-ltr"><?= gp_e(implode(', ', array_map('strval', (array)$ti['lists']))) ?></td>
			<?php else: ?><td colspan="4"><?= gp_e(gp_t('ipl_no_file')) ?></td><?php endif; ?>
			<td><?php if ($prev[$t]): ?>
				<form method="post" action="index.php?r=iplists" data-confirm="<?= gp_e(gp_t('geo_rb_confirm')) ?>" style="display:inline">
					<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>"><input type="hidden" name="type" value="<?= gp_e($t) ?>">
					<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit" name="do" value="rollback"><?= gp_e(gp_t('geo_rollback')) ?></button><?= gp_tip('geo_rollback') ?></form>
			<?php endif; ?></td></tr>
		<?php endforeach; ?>
	</tbody></table></div>
	<?php if ($status): ?>
	<p class="gp-help"><?= gp_e(gp_t('geo_last_compile')) ?>: <?= gp_e(gp_age((int)$status['time'])) ?> <?= gp_e(gp_t('ago')) ?> (<?= gp_e((string)($status['by'] ?? '?')) ?>)
		<span class="gp-badge <?= !empty($status['ok']) ? 'gp-badge-on' : 'gp-badge-bad' ?>"><?= gp_e(gp_t(!empty($status['ok']) ? 'geo_ok' : 'geo_failed')) ?></span></p>
	<?php foreach ((array)($status['errors'] ?? array()) as $e): ?><p class="gp-text-bad gp-ltr gp-mono"><?= gp_e((string)$e) ?></p><?php endforeach; ?>
	<?php endif; ?>
	<div class="gp-card-title"><?= gp_e(gp_t('ipl_dropped_title')) ?></div>
	<p class="gp-help"><?= gp_e(gp_t('ipl_dropped_help')) ?></p>
	<?php
	$ipl_drop_rows = array();
	foreach ($all as $r) { $c = $r['stat']; if ($c && ((int)($c['dropped_n'] ?? 0) > 0 || (int)($c['invalid'] ?? 0) > 0)) { $ipl_drop_rows[] = array($r, $c); } }
	?>
	<?php if (!$ipl_drop_rows): ?><p class="gp-help"><?= gp_e(gp_t('ipl_none_dropped')) ?></p>
	<?php else: ?>
	<div class="gp-table-wrap"><table class="gp-table"><thead><tr><th><?= gp_e(gp_t('ipl_f_name')) ?></th><th><?= gp_e(gp_t('ipl_c_dropped')) ?></th><th><?= gp_e(gp_t('ipl_invalid_short')) ?></th><th><?= gp_e(gp_t('ipl_c_text')) ?></th></tr></thead><tbody>
		<?php foreach ($ipl_drop_rows as $dr): $r = $dr[0]; $c = $dr[1]; ?>
		<tr><td><strong><?= gp_e($r['name']) ?></strong> <code class="gp-mono"><?= gp_e($r['id']) ?></code></td>
			<td class="gp-mono"><?php foreach ((array)($c['dropped'] ?? array()) as $why => $n): if ((int)$n > 0): ?><span class="gp-badge gp-badge-warn"><?= gp_e(gp_t('ipl_why_' . $why)) ?>: <?= gp_e(gp_num((int)$n)) ?></span> <?php endif; endforeach; ?></td>
			<td class="gp-mono"><?= gp_e(gp_num((int)($c['invalid'] ?? 0))) ?></td>
			<td class="gp-mono gp-ltr"><?php foreach ((array)($c['dropped_samples'] ?? array()) as $sm): ?><?= gp_e((string)$sm[0]) ?> (<?= gp_e((string)$sm[1]) ?>)<br><?php endforeach; ?>
				<?php foreach ((array)($c['invalid_samples'] ?? array()) as $sm): ?><?= gp_e(gp_t('ipl_c_line') . ' ' . (string)$sm[0] . ': ' . (string)$sm[1]) ?><br><?php endforeach; ?></td></tr>
		<?php endforeach; ?>
	</tbody></table></div>
	<?php endif; ?>
	<form method="post" action="index.php?r=iplists">
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<div class="gp-row-head">
			<button class="gp-btn gp-btn-primary" type="submit" name="do" value="compile"><?= gp_e(gp_t('ipl_compile_now')) ?></button><?= gp_tip('ipl_compile') ?>
			<label class="gp-check"><input type="checkbox" name="job" value="1"><span><?= gp_e(gp_t('ipl_compile_job')) ?></span><?= gp_tip('ipl_compile_job') ?></label>
		</div>
	</form>
	<p class="gp-help"><?= gp_e(gp_t('ipl_compile_help')) ?></p>
	<?php if ($jobs): ?>
	<div class="gp-help"><?= gp_e(gp_t('geo_jobs')) ?>:
		<?php foreach ($jobs as $j): ?><span class="gp-badge gp-badge-off gp-ltr"><?= gp_e((string)($j['status'] ?? '?')) ?></span> <span class="gp-mono"><?= gp_e(gp_age((float)($j['requested_at'] ?? 0))) ?> <?= gp_e(gp_t('ago')) ?></span> <?php endforeach; ?>
		<a href="index.php?r=jobs"><?= gp_e(gp_t('nav_jobs')) ?></a></div>
	<?php endif; ?>
</div>
<?php gp_tab_end(); gp_tabs_end(); ?>
