<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// The Feeds tab of the IP lists page (included from iplists.php, same variables): provider IP ranges fetched from an HTTPS URL.
// Feed names, URLs, notes and error text come from the operator or from a remote server: all of it goes through gp_e().
$fe_state = is_array($feeds_state ?? null) ? $feeds_state : array('state' => 'missing', 'feeds' => array());
$fe_form = is_array($feed_edit ?? null) ? $feed_edit : null;
$fe_sv = is_array($feed_save ?? null) ? $feed_save : null;
$fe_err = $fe_sv ? $fe_sv['errors'] : array();
$fe_age = function ($t) { return $t > 0 ? gp_e(gp_age(max(0, time() - (int)$t))) . ' ' . gp_e(gp_t('ago')) : gp_e(gp_t('never')); };
?>
<div class="gp-card gp-form">
	<div class="gp-card-title"><?= gp_e(gp_t('feed_title')) ?><?= gp_tip('feed_about') ?></div>
	<p class="gp-help"><?= gp_e(gp_t('feed_help')) ?></p>
	<div class="gp-note gp-note-strong" role="alert"><strong><?= gp_e(gp_t('feed_cdn_warn_title')) ?></strong> <?= gp_e(gp_t('feed_cdn_warn')) ?></div>
	<?php if ($fe_state['state'] === 'invalid'): ?><div class="gp-note gp-note-strong" role="alert"><?= gp_e(gp_t('feed_file_invalid')) ?></div><?php endif; ?>
	<div class="gp-row-head">
		<?php foreach (gp_feed_presets() as $pk => $pr): ?>
		<a class="gp-btn gp-btn-ghost gp-btn-sm" href="index.php?r=iplists&amp;new_feed=1&amp;preset=<?= gp_u($pk) ?>#ipl-feeds"><?= gp_e(gp_t('feed_add_preset')) ?>: <?= gp_e($pr['name']) ?> <span class="gp-help">(<?= gp_e(gp_t('feed_dest_' . $pr['dest'] . '_short')) ?>)</span></a>
		<?php endforeach; ?>
		<a class="gp-btn gp-btn-ghost gp-btn-sm" href="index.php?r=iplists&amp;new_feed=1#ipl-feeds"><?= gp_e(gp_t('feed_add_custom')) ?></a>
	</div>
	<?= gp_msg('feeds-list') ?>
	<?php if (!$fe_state['feeds']): ?>
	<p class="gp-help"><?= gp_e(gp_t('feed_none')) ?></p>
	<?php else: ?>
	<div class="gp-table-wrap"><table class="gp-table">
		<thead><tr><th><?= gp_e(gp_t('feed_f_name')) ?></th><th><?= gp_e(gp_t('feed_f_dest')) ?></th><th><?= gp_e(gp_t('feed_f_schedule')) ?></th><th><?= gp_e(gp_t('feed_c_last')) ?></th><th><?= gp_e(gp_t('feed_c_result')) ?></th><th></th></tr></thead>
		<tbody>
		<?php foreach ($fe_state['feeds'] as $f): $s = $f['st']; $rk = gp_row_key($f['id']);
			$post = function ($do, $label, $extra = '', $confirm = '', $cls = 'gp-btn-ghost') use ($f) {
				return '<form method="post" action="index.php?r=iplists" style="display:inline"' . ($confirm !== '' ? ' data-confirm="' . gp_e($confirm) . '"' : '') . '>'
					. '<input type="hidden" name="csrf" value="' . gp_e(gp_csrf_token()) . '"><input type="hidden" name="id" value="' . gp_e($f['id']) . '">' . $extra
					. '<button class="gp-btn ' . $cls . ' gp-btn-sm" type="submit" name="do" value="' . gp_e($do) . '">' . gp_e($label) . '</button></form>';
			}; ?>
		<tr>
			<td><strong><?= gp_e($f['name']) ?></strong><br><span class="gp-mono gp-ltr gp-truncate" style="max-width:22rem;display:inline-block"><?= gp_e($f['url']) ?></span>
				<?php if ($f['note'] !== ''): ?><br><span class="gp-help"><?= gp_e($f['note']) ?></span><?php endif; ?></td>
			<td><span class="gp-badge <?= $f['dest'] === 'allow' ? gp_e(gp_ipl_badge_class('allow')) : 'gp-badge-warn' ?>"><?= gp_e(gp_t('feed_dest_' . $f['dest'] . '_short')) ?></span>
				<?php if ($f['dest'] === 'allow'): ?><br><a class="gp-help" href="index.php?r=iplists&amp;list=<?= gp_u(gp_feed_list_id($f['id'])) ?>#ipl-entries"><code class="gp-mono"><?= gp_e(gp_feed_list_id($f['id'])) ?></code></a>
				<span class="gp-badge <?= $f['mode'] === 'enforce' ? 'gp-badge-on' : 'gp-badge-off' ?>"><?= gp_e(gp_t('rules_mode_' . $f['mode'])) ?></span><?php endif; ?>
				<?php if ($f['dest'] === 'allow' && gp_feed_cdn_host($f['url'])): ?><br><span class="gp-badge gp-badge-bad" role="alert"><?= gp_e(gp_t('feed_row_cdn_allow')) ?></span><?php endif; ?>
				<br><span class="gp-badge <?= $f['enabled'] ? 'gp-badge-on' : 'gp-badge-off' ?>"><?= gp_e(gp_t($f['enabled'] ? 'on' : 'off')) ?></span></td>
			<td><?= gp_e(gp_t('feed_sched_' . $f['schedule'])) ?></td>
			<td class="gp-mono"><?= $fe_age($s['last_run']) ?><?= $s['last_ok'] > 0 && $s['last_ok'] !== $s['last_run'] ? '<br><span class="gp-help">' . gp_e(gp_t('feed_last_good')) . ': ' . $fe_age($s['last_ok']) . '</span>' : '' ?></td>
			<td>
				<?php if ($s['error'] !== ''): ?><span class="gp-badge gp-badge-bad" role="alert"><?= gp_e(gp_t('feed_failed')) ?> &times;<?= gp_e((string)$s['fail_streak']) ?>: <?= gp_e(gp_feed_error_text($s['error'])) ?></span><br><span class="gp-help"><?= gp_e(gp_t('feed_kept_good')) ?></span>
				<?php elseif ($s['last_run'] > 0): ?><span class="gp-badge gp-badge-on"><?= gp_e(gp_t('feed_ok')) ?></span><?php endif; ?>
				<?php if ($s['last_run'] > 0): ?>
				<div class="gp-help gp-mono"><?= gp_e(gp_t('feed_diff')) ?>: +<?= gp_e(gp_num($s['added'])) ?> / &minus;<?= gp_e(gp_num($s['removed'])) ?> / =<?= gp_e(gp_num($s['unchanged'])) ?>
					· <?= gp_e(gp_t('feed_entries')) ?>: <?= gp_e(gp_num($s['applied'])) ?> · IPv6 <?= gp_e(gp_t('feed_dropped')) ?>: <?= gp_e(gp_num($s['v6'])) ?> · <?= gp_e(gp_t('feed_invalid')) ?>: <?= gp_e(gp_num($s['invalid'])) ?>
					· HTTP <?= gp_e((string)$s['http']) ?> · <?= gp_e(gp_bytes($s['bytes'])) ?> · <?= gp_e(gp_num($s['ms'])) ?> ms · <?= gp_e($s['format']) ?></div>
				<?php endif; ?>
				<?php if ($s['held'] !== ''): ?>
				<div class="gp-note gp-note-strong" role="alert"><?= gp_e(sprintf(gp_t('feed_held_shrink'), gp_num($s['held_removed']), gp_num($s['held_n']))) ?>
					<?= $post('feed_accept_hold', gp_t('feed_accept_hold'), '', gp_t('feed_accept_hold_confirm'), 'gp-btn-primary') ?>
					<?= $post('feed_discard_hold', gp_t('feed_discard_hold')) ?></div>
				<?php endif; ?>
				<?php if ($s['cap_held'] > 0): ?>
				<div class="gp-note" role="status"><strong><?= gp_e(gp_num($s['cap_held'])) ?></strong> <?= gp_e(gp_t($f['dest'] === 'allow' ? 'feed_cap_held_allow' : 'feed_cap_held_cdn')) ?>
					<span class="gp-mono gp-ltr"><?= gp_e(implode(', ', array_slice($s['cap_samples'], 0, 5))) ?></span>
					<?php if ($f['dest'] === 'allow'): ?><?= $post('feed_accept_cap', gp_t('feed_accept_cap'), '', gp_t('feed_accept_cap_confirm')) ?><?php endif; ?></div>
				<?php endif; ?>
				<?= gp_msg('fd-' . $rk) ?>
			</td>
			<td>
				<?= $post('feed_update', gp_t('feed_update'), '', '', 'gp-btn-primary') ?>
				<a class="gp-btn gp-btn-ghost gp-btn-sm" href="index.php?r=iplists&amp;edit_feed=<?= gp_u($f['id']) ?>#ipl-feeds"><?= gp_e(gp_t('rules_edit')) ?></a>
				<?= $post('feed_delete', gp_t('rules_delete'), '', gp_t('feed_delete_confirm'), 'gp-btn-danger') ?>
			</td>
		</tr>
		<?php endforeach; ?>
		</tbody>
	</table></div>
	<?php endif; ?>
</div>

<?php if ($fe_form !== null): $new_f = ($fe_form['id'] === '' || empty($fe_form['created_at'])); ?>
<form method="post" action="index.php?r=iplists" class="gp-card gp-form" id="ipl-feed-editor">
	<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
	<input type="hidden" name="id" value="<?= gp_e($new_f ? '' : $fe_form['id']) ?>">
	<div class="gp-card-title"><?= gp_e(gp_t($new_f ? 'feed_new' : 'feed_edit')) ?></div>
	<?php foreach (array('name', 'url', 'format', 'dest', 'mode', 'schedule', 'note') as $fk): if (isset($fe_err[$fk])): ?>
	<div class="gp-flash gp-flash-error" role="alert"><?= gp_e(gp_t('feed_f_' . $fk)) ?>: <?= gp_e(gp_t('feed_err_' . $fe_err[$fk]) !== 'feed_err_' . $fe_err[$fk] ? gp_t('feed_err_' . $fe_err[$fk]) : $fe_err[$fk]) ?></div>
	<?php endif; endforeach; ?>
	<div class="gp-grid-2">
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('feed_f_name')) ?><?= gp_tip('feed_name') ?></span>
			<input class="gp-input" type="text" name="name" maxlength="60" required value="<?= gp_e($fe_form['name']) ?>">
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('feed_f_url')) ?><?= gp_tip('feed_url') ?></span>
			<input class="gp-input gp-ltr" type="url" name="url" maxlength="500" required spellcheck="false" placeholder="https://" value="<?= gp_e($fe_form['url']) ?>">
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('feed_f_format')) ?><?= gp_tip('feed_format') ?></span>
			<select class="gp-input" name="format">
				<?php foreach (explode(',', GP_FEED_FORMATS) as $fm): ?><option value="<?= gp_e($fm) ?>"<?= $fe_form['format'] === $fm ? ' selected' : '' ?>><?= gp_e(gp_t('feed_format_' . $fm)) ?></option><?php endforeach; ?>
			</select>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('feed_f_dest')) ?><?= gp_tip('feed_dest') ?></span>
			<?php if (!$new_f): ?>
			<input class="gp-input" type="text" value="<?= gp_e(gp_t('feed_dest_' . $fe_form['dest'])) ?>" disabled>
			<span class="gp-help"><?= gp_e(gp_t('feed_dest_fixed')) ?></span>
			<?php else: ?>
			<select class="gp-input" name="dest">
				<option value="allow"<?= $fe_form['dest'] === 'allow' ? ' selected' : '' ?>><?= gp_e(gp_t('feed_dest_allow')) ?></option>
				<option value="cdn"<?= $fe_form['dest'] === 'cdn' ? ' selected' : '' ?>><?= gp_e(gp_t('feed_dest_cdn')) ?></option>
			</select>
			<?php endif; ?>
			<span class="gp-help"><?= gp_e(gp_t('feed_dest_help')) ?></span>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('feed_f_mode')) ?><?= gp_tip('feed_mode') ?></span>
			<select class="gp-input" name="mode">
				<option value="monitor"<?= $fe_form['mode'] === 'monitor' ? ' selected' : '' ?>><?= gp_e(gp_t('rules_mode_monitor')) ?></option>
				<option value="enforce"<?= $fe_form['mode'] === 'enforce' ? ' selected' : '' ?>><?= gp_e(gp_t('rules_mode_enforce')) ?></option>
			</select>
			<span class="gp-help"><?= gp_e(gp_t('feed_mode_help')) ?></span>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('feed_f_schedule')) ?><?= gp_tip('feed_schedule') ?></span>
			<select class="gp-input" name="schedule">
				<?php foreach (array('manual', 'daily', 'weekly') as $sk): ?><option value="<?= gp_e($sk) ?>"<?= $fe_form['schedule'] === $sk ? ' selected' : '' ?>><?= gp_e(gp_t('feed_sched_' . $sk)) ?></option><?php endforeach; ?>
			</select>
			<span class="gp-help"><?= gp_e(gp_t('feed_schedule_help')) ?></span>
		</label>
		<div class="gp-field">
			<label class="gp-check"><input type="checkbox" name="enabled" value="1"<?= !empty($fe_form['enabled']) ? ' checked' : '' ?>><span><?= gp_e(gp_t('ipl_f_enabled')) ?></span><?= gp_tip('feed_enabled') ?></label>
			<label class="gp-check"><input type="checkbox" name="force" value="1"<?= !empty($fe_form['force']) ? ' checked' : '' ?>><span><?= gp_e(gp_t('feed_f_force')) ?></span><?= gp_tip('feed_force') ?></label>
		</div>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('ipl_f_note')) ?><?= gp_tip('feed_note') ?></span>
			<input class="gp-input" type="text" name="note" maxlength="200" value="<?= gp_e($fe_form['note']) ?>">
		</label>
	</div>
	<div class="gp-row-head">
		<button class="gp-btn gp-btn-primary" type="submit" name="do" value="feed_save"><?= gp_e(gp_t('save')) ?></button>
		<a class="gp-btn gp-btn-ghost" href="index.php?r=iplists#ipl-feeds"><?= gp_e(gp_t('cancel')) ?></a>
	</div>
	<?= gp_msg('feed-editor') ?>
</form>
<?php endif; ?>
