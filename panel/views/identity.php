<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Identity drill-down: everything `ctl.py show` prints, plus the context.
// This is the first page to open when a customer reports being blocked.
$v = is_array($verdicts) ? $verdicts : array();
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('id_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('id_first_step')) ?></p>
</div>

<form method="get" action="index.php" class="gp-card gp-form">
	<input type="hidden" name="r" value="identity">
	<label class="gp-field">
		<span class="gp-label"><?= gp_e(gp_t('ovr_identity')) ?></span>
		<input class="gp-input gp-ltr" type="text" name="id" value="<?= gp_e($identity) ?>"
			placeholder="device id / ip" required>
	</label>
	<button class="gp-btn gp-btn-primary" type="submit"><?= gp_e(gp_t('search')) ?></button>
</form>

<?php if ($identity === ''): ?>
	<?php return; ?>
<?php endif; ?>

<?php if (!$redis_up): ?>
<div class="gp-note gp-note-strong"><?= gp_e(gp_t('err_redis')) ?></div>
<?php endif; ?>

<div class="gp-grid-3">
	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('id_reputation')) ?></div>
		<div class="gp-kpi-value">
			<?= $v['rep'] === null ? gp_e(gp_t('none')) : gp_num((int)$v['rep']) ?>
		</div>
		<p class="gp-kpi-hint"><?= gp_e(gp_t('help_signals_reputation')) ?></p>
	</div>
	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('id_ml')) ?></div>
		<div class="gp-kpi-value">
			<?= $v['ml'] === null ? gp_e(gp_t('none')) : gp_num((int)$v['ml']) ?>
		</div>
		<p class="gp-kpi-hint"><?= gp_e(gp_t('help_signals_ml')) ?></p>
	</div>
	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('id_clf')) ?></div>
		<div class="gp-kpi-value">
			<?= $v['clf'] === null ? gp_e(gp_t('none')) : gp_num((int)$v['clf']) ?>
		</div>
		<p class="gp-kpi-hint"><?= gp_e(gp_t('help_signals_clf')) ?></p>
	</div>
</div>

<div class="gp-grid-2">
	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('id_botv')) ?></div>
		<div class="gp-stat-row">
			<span class="gp-stat-key">botok</span>
			<span class="gp-badge <?= !empty($v['botok']) ? 'gp-badge-on' : 'gp-badge-off' ?>">
				<?= gp_e(!empty($v['botok']) ? gp_t('yes') : gp_t('no')) ?></span>
		</div>
		<div class="gp-stat-row">
			<span class="gp-stat-key">botbad</span>
			<span class="gp-badge <?= !empty($v['botbad']) ? 'gp-badge-bad' : 'gp-badge-off' ?>">
				<?= gp_e(!empty($v['botbad']) ? gp_t('yes') : gp_t('no')) ?></span>
		</div>
		<div class="gp-stat-row">
			<span class="gp-stat-key"><?= gp_e(gp_t('id_honeypot')) ?></span>
			<span class="gp-badge <?= !empty($v['honeypot']) ? 'gp-badge-bad' : 'gp-badge-off' ?>">
				<?= gp_e(!empty($v['honeypot']) ? gp_t('yes') : gp_t('no')) ?></span>
		</div>
	</div>

	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('id_overrides')) ?></div>
		<div class="gp-stat-row">
			<span class="gp-stat-key"><?= gp_e(gp_t('ovr_allow')) ?></span>
			<span class="gp-stat-val">
				<?= $v['allow_ttl'] === null ? gp_e(gp_t('none')) : gp_e(gp_age(time() - (int)$v['allow_ttl'])) ?>
			</span>
		</div>
		<div class="gp-stat-row">
			<span class="gp-stat-key"><?= gp_e(gp_t('ovr_deny')) ?></span>
			<span class="gp-stat-val">
				<?= $v['deny_ttl'] === null ? gp_e(gp_t('none')) : gp_e(gp_age(time() - (int)$v['deny_ttl'])) ?>
			</span>
		</div>

		<?php foreach ((isset($shadow) && is_array($shadow) ? $shadow : array()) as $slist): ?>
		<div class="gp-note gp-note-strong" role="alert" data-shadow="1"><?= gp_e(str_replace('%s', $slist, gp_t('ovr_deny_shadowed'))) ?>
			<a href="index.php?r=iplists&amp;list=<?= gp_u($slist) ?>#ipl-entries"><?= gp_e(gp_t('ovr_shadow_link')) ?></a></div>
		<?php endforeach; ?>
		<form method="post" action="index.php?r=identity&amp;id=<?= gp_u($identity) ?>"
			class="gp-form" style="margin-top:.75rem">
			<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
			<input type="hidden" name="identity" value="<?= gp_e($identity) ?>">
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('id_ttl')) ?></span>
				<select class="gp-input" name="ttl">
					<option value="3600"><?= gp_e(gp_plural(1, 'hour')) ?></option>
					<option value="21600"><?= gp_e(gp_plural(6, 'hour')) ?></option>
					<option value="86400" selected><?= gp_e(gp_plural(1, 'day')) ?></option>
					<option value="604800"><?= gp_e(gp_plural(7, 'day')) ?></option>
					<option value="2592000"><?= gp_e(gp_plural(30, 'day')) ?></option>
				</select>
			</label>
			<div class="gp-row-head">
				<button class="gp-btn gp-btn-primary gp-btn-sm" type="submit"
					name="override" value="allow"><?= gp_e(gp_t('id_allow')) ?></button>
				<button class="gp-btn gp-btn-danger gp-btn-sm" type="submit"
					name="override" value="deny"><?= gp_e(gp_t('id_deny')) ?></button>
				<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit"
					name="override" value="clear"><?= gp_e(gp_t('ovr_clear')) ?></button>
			</div>
		</form>
		<?= gp_msg('identity-override') ?>
		<p class="gp-note" style="margin-top:.5rem"><?= gp_e(gp_t('ovr_rule_allow')) ?></p>
	</div>
</div>

<?= gp_filter_form_html('identity', array(
	'act' => array('logs_act', 'is', array('allow', 'challenge', '403', '429', 'allow_bot', 'allow_override', '404_hp'), 'flt_act'),
	'path' => array('logs_path', 'has', array(), 'flt_path')), $filter, array('id' => $identity)) ?>

<div class="gp-card">
	<div class="gp-card-title">
		<?= gp_e(gp_t('id_recent')) ?>
		<span class="gp-card-sub"><?= gp_num(count($rows)) ?></span>
	</div>
	<?php if (!$rows): ?>
		<p class="gp-help"><?= gp_e(gp_t('id_not_found')) ?></p>
	<?php else: ?>
	<div class="gp-rows">
		<?php foreach ($rows as $row):
			$out = isset($row['_out']) && is_array($row['_out']) ? $row['_out'] : null; ?>
		<div class="gp-row">
			<div class="gp-row-head">
				<span class="gp-badge gp-badge-off"><?= gp_e($row['act'] ?? '') ?></span>
				<?php if ($out !== null): ?>
					<span class="gp-badge gp-badge-info"><?= gp_e((string)($out['st'] ?? '')) ?></span>
				<?php endif; ?>
				<span class="gp-mono" style="margin-inline-start:auto">
					<?= gp_e(gp_num_raw(date('m-d H:i:s', (int)($row['ts'] ?? 0)))) ?></span>
			</div>
			<div class="gp-row-main gp-mono gp-ltr gp-truncate"><?= gp_e($row['p'] ?? '') ?></div>
			<div class="gp-row-meta">
				<span><?= gp_e(gp_t('logs_sc')) ?>: <?= gp_num((int)($row['sc'] ?? 0)) ?></span>
				<span><?= gp_e(gp_t('logs_esc')) ?>: <?= gp_num((int)($row['esc'] ?? 0)) ?></span>
				<?php foreach ((array)($row['rs'] ?? array()) as $reason): ?>
					<?= gp_reason_badge($reason) ?>
				<?php endforeach; ?>
				<?php if (isset($row['ua'])): ?>
				<a class="gp-btn gp-btn-ghost gp-btn-sm"
					href="index.php?r=rules&amp;new=1&amp;qua=<?= gp_u($row['ua']) ?>">
					<?= gp_e(gp_t('rules_quick_block')) ?></a>
				<?php endif; ?>
			</div>
		</div>
		<?php endforeach; ?>
	</div>
	<?php endif; ?>
</div>
