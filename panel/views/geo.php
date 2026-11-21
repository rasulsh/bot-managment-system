<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// GeoIP: active databases, source upload, compile, rollback and the lookup tester.
//
// Source file names, tag names and error text come from files an operator
// uploaded or from the compile step: all of it goes through gp_e().
$st = $status;
$now = time();
$warn = gp_geo_warnings($st, (int)$geo_rules, $cfg);
$limit = (int)$st['limit'];
$mb = function ($b) { return $b >= 1048576 ? sprintf('%.1f MiB', $b / 1048576) : sprintf('%.0f KiB', $b / 1024); };
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('geo_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('geo_sub')) ?></p>
</div>

<?php foreach ($warn as $w): ?>
<div class="gp-note gp-note-strong" role="alert"><?= gp_e(gp_t('geo_w_' . $w)) ?></div>
<?php endforeach; ?>
<div class="gp-note"><?= gp_e(gp_t('geo_unknown_rule')) ?></div>

<?php /* ------------------------------------------------------- active databases */ ?>
<div class="gp-card">
	<div class="gp-card-title"><?= gp_e(gp_t('geo_active')) ?></div>
	<div class="gp-table-wrap">
	<table class="gp-table">
		<thead><tr>
			<th><?= gp_e(gp_t('geo_c_db')) ?></th><th><?= gp_e(gp_t('geo_c_source')) ?></th><th><?= gp_e(gp_t('geo_c_built')) ?></th>
			<th><?= gp_e(gp_t('geo_c_age')) ?></th><th><?= gp_e(gp_t('geo_c_v4')) ?></th><th><?= gp_e(gp_t('geo_c_v6')) ?></th><th></th>
		</tr></thead>
		<tbody>
		<?php foreach (array('country' => 'geo_country', 'asn' => 'geo_asn_db') as $k => $label): $d = $st[$k]; ?>
		<tr>
			<td><strong><?= gp_e(gp_t($label)) ?></strong><br><code class="gp-mono"><?= gp_e($k) ?>.bin</code></td>
			<?php if ($d === null): ?>
			<td colspan="5"><?= gp_e(gp_t('geo_none')) ?></td>
			<?php elseif (!$d['valid']): ?>
			<td colspan="5"><span class="gp-badge gp-badge-bad"><?= gp_e(gp_t('geo_w_corrupt')) ?></span></td>
			<?php else: ?>
			<td class="gp-mono gp-ltr"><?= gp_e($d['source']) ?></td>
			<td class="gp-mono"><?= gp_e(gmdate('Y-m-d H:i', $d['built'])) ?> UTC</td>
			<td class="gp-mono"><span class="gp-badge <?= $d['age_days'] > GP_GEO_STALE_DAYS ? 'gp-badge-warn' : 'gp-badge-on' ?>"><?= gp_e(gp_num($d['age_days'])) ?> <?= gp_e(gp_t('geo_days')) ?></span></td>
			<td class="gp-mono"><?= gp_e(gp_num($d['v4'])) ?></td>
			<td class="gp-mono"><?= gp_e(gp_num($d['v6'])) ?></td>
			<?php endif; ?>
			<td>
				<?php if ($d !== null && $d['prev']): ?>
				<form method="post" action="index.php?r=geo" data-confirm="<?= gp_e(gp_t('geo_rb_confirm')) ?>" style="display:inline">
					<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
					<input type="hidden" name="kind" value="<?= gp_e($k) ?>">
					<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit" name="do" value="rollback"><?= gp_e(gp_t('geo_rollback')) ?></button>
				</form>
				<?php endif; ?>
			</td>
		</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	</div>
	<?php if ($st['compile']): ?>
	<p class="gp-help"><?= gp_e(gp_t('geo_last_compile')) ?>: <?= gp_e(gp_age($st['compile']['time'])) ?> <?= gp_e(gp_t('ago')) ?>
		<span class="gp-badge <?= $st['compile']['ok'] ? 'gp-badge-on' : 'gp-badge-bad' ?>"><?= gp_e(gp_t($st['compile']['ok'] ? 'geo_ok' : 'geo_failed')) ?></span></p>
	<?php endif; ?>
	<?php foreach ($st['errors'] as $e): ?><p class="gp-text-bad gp-ltr gp-mono"><?= gp_e((string)$e) ?></p><?php endforeach; ?>
	<?php if ($st['ignored_tags']): ?>
	<p class="gp-help"><?= gp_e(gp_t('geo_ignored')) ?>: <span class="gp-mono gp-ltr"><?= gp_e(implode(', ', array_slice(array_keys($st['ignored_tags']), 0, 60))) ?></span></p>
	<?php endif; ?>
</div>

<?php /* ------------------------------------------------------- sources, upload, compile */ ?>
<div class="gp-card gp-form">
	<div class="gp-card-title"><?= gp_e(gp_t('geo_sources')) ?></div>
	<p class="gp-help"><?= gp_e(gp_t('geo_sources_help')) ?> <code class="gp-mono gp-ltr"><?= gp_e($st['dir']) ?></code></p>
	<?php if (!$st['dir_writable']): ?><div class="gp-note gp-note-strong" role="alert"><?= gp_e(gp_t('geo_up_nowrite')) ?>: <?= gp_e($st['dir']) ?></div><?php endif; ?>
	<?php if ($st['sources']): ?>
	<div class="gp-table-wrap">
	<table class="gp-table">
		<thead><tr><th><?= gp_e(gp_t('geo_c_file')) ?></th><th><?= gp_e(gp_t('geo_c_size')) ?></th><th><?= gp_e(gp_t('geo_c_mtime')) ?></th><th><?= gp_e(gp_t('geo_c_use')) ?></th><th></th></tr></thead>
		<tbody>
		<?php foreach ($st['sources'] as $s): ?>
		<tr>
			<td class="gp-mono gp-ltr"><?= gp_e((string)($s['name'] ?? '')) ?></td>
			<td class="gp-mono"><?= gp_e($mb((int)($s['size'] ?? 0))) ?></td>
			<td class="gp-mono"><?= gp_e(gmdate('Y-m-d H:i', (int)($s['mtime'] ?? 0))) ?> UTC</td>
			<td>
				<?php if (!empty($s['error'])): ?><span class="gp-badge gp-badge-bad"><?= gp_e((string)$s['error']) ?></span>
				<?php elseif (!empty($s['new'])): ?><span class="gp-badge gp-badge-info"><?= gp_e(gp_t('geo_not_compiled')) ?></span>
				<?php elseif (!empty($s['used'])): ?><span class="gp-badge gp-badge-on"><?= gp_e(implode(' + ', array_map('strval', $s['used']))) ?></span>
				<?php else: ?><span class="gp-badge gp-badge-off"><?= gp_e(gp_t('geo_unused')) ?></span><?php endif; ?>
			</td>
			<td>
				<form method="post" action="index.php?r=geo" data-confirm="<?= gp_e(gp_t('geo_del_confirm')) ?>" style="display:inline">
					<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
					<input type="hidden" name="name" value="<?= gp_e((string)($s['name'] ?? '')) ?>">
					<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit" name="do" value="delete"><?= gp_e(gp_t('geo_delete')) ?></button>
				</form>
			</td>
		</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	</div>
	<?php endif; ?>

	<form method="post" action="index.php?r=geo" enctype="multipart/form-data">
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('geo_upload')) ?></span>
			<input class="gp-input" type="file" name="source" accept=".mmdb,.dat">
			<span class="gp-help"><?= gp_e(gp_t('geo_upload_help')) ?>
				<?= $limit > 0 ? gp_e(gp_t('geo_upload_limit')) . ': ' . gp_e($mb($limit)) . '.' : '' ?>
				<?= gp_e(gp_t('geo_upload_sftp')) ?></span>
		</label>
		<div class="gp-row-head">
			<button class="gp-btn gp-btn-primary" type="submit" name="do" value="upload"><?= gp_e(gp_t('geo_upload_btn')) ?></button>
			<button class="gp-btn gp-btn-ghost" type="submit" name="do" value="compile"><?= gp_e(gp_t('geo_compile')) ?></button>
		</div>
	</form>
	<p class="gp-help"><?= gp_e(gp_t('geo_compile_help')) ?></p>
	<?php if ($jobs): ?>
	<div class="gp-help"><?= gp_e(gp_t('geo_jobs')) ?>:
		<?php foreach ($jobs as $j): ?>
		<span class="gp-badge gp-badge-off gp-ltr"><?= gp_e((string)($j['status'] ?? '?')) ?></span>
		<span class="gp-mono"><?= gp_e(gp_age((float)($j['requested_at'] ?? 0))) ?> <?= gp_e(gp_t('ago')) ?></span>
		<?php endforeach; ?>
		<a href="index.php?r=jobs"><?= gp_e(gp_t('nav_jobs')) ?></a>
	</div>
	<?php endif; ?>
</div>

<?php /* ------------------------------------------------------- lookup tester */ ?>
<form method="get" action="index.php" class="gp-card gp-form">
	<input type="hidden" name="r" value="geo">
	<div class="gp-card-title"><?= gp_e(gp_t('geo_tester')) ?></div>
	<p class="gp-help"><?= gp_e(gp_t('geo_tester_help')) ?></p>
	<div class="gp-grid-2">
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_test_ip')) ?></span>
			<input class="gp-input gp-ltr" type="text" name="ip" value="<?= gp_e($test_in['ip']) ?>" placeholder="203.0.113.7" spellcheck="false">
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_test_ua')) ?></span>
			<input class="gp-input gp-ltr" type="text" name="ua" value="<?= gp_e($test_in['ua']) ?>" spellcheck="false">
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rules_test_path')) ?></span>
			<input class="gp-input gp-ltr" type="text" name="path" value="<?= gp_e($test_in['path']) ?>" placeholder="/">
		</label>
	</div>
	<label class="gp-check"><input type="checkbox" name="verified" value="1"<?= $test_in['verified'] ? ' checked' : '' ?>>
		<span><?= gp_e(gp_t('rules_test_verified')) ?></span></label>
	<div class="gp-row-head"><button class="gp-btn gp-btn-primary" type="submit" name="test" value="1"><?= gp_e(gp_t('rules_test_run')) ?></button></div>
	<?php if ($test_ran && $test === null): ?>
	<div class="gp-note gp-note-strong" role="alert"><?= gp_e(gp_t('geo_bad_ip')) ?></div>
	<?php elseif ($test !== null): ?>
	<div class="gp-note" role="status">
		<dl class="gp-dl">
			<dt><?= gp_e(gp_t('geo_cc')) ?></dt><dd class="gp-mono"><?= gp_e($test['cc'] !== '' ? $test['cc'] : gp_t('geo_unknown')) ?></dd>
			<dt><?= gp_e(gp_t('geo_asn')) ?></dt><dd class="gp-mono"><?= gp_e($test['asn'] > 0 ? 'AS' . $test['asn'] : gp_t('geo_unknown')) ?></dd>
		</dl>
		<?php if ($test['winner']): $w = $test['winner']; ?>
		<div><strong><?= gp_e(gp_t('rules_test_winner')) ?>:</strong> <?= gp_e($w['name']) ?> (<code class="gp-mono"><?= gp_e($w['id']) ?></code>)
			&rarr; <?= gp_e(gp_t('rules_act_' . $w['action'])) ?>, <?= gp_e(gp_t('rules_mode_' . $w['mode'])) ?></div>
		<?php else: ?><div><?= gp_e(gp_t('rules_test_none')) ?></div><?php endif; ?>
		<?php if (count($test['matches']) > 1 || $test['skipped']): ?>
		<div class="gp-help"><?= gp_e(gp_t('rules_test_also')) ?>:
			<?php foreach ($test['matches'] as $m): ?><code class="gp-mono"><?= gp_e($m['id']) ?></code><?= in_array($m['id'], $test['skipped'], true) ? ' (' . gp_e(gp_t('rules_test_skipped')) . ')' : '' ?> <?php endforeach; ?>
		</div>
		<?php endif; ?>
	</div>
	<?php endif; ?>
</form>
