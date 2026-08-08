<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Operator overrides. The allow-is-ungated / deny-is-gated rule is stated
// directly in the UI, because that distinction is the thing an operator most
// needs to understand while a customer is on the phone.
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('ovr_title')) ?></h1>
</div>

<div class="gp-grid-2">
	<div class="gp-note">
		<strong><?= gp_e(gp_t('ovr_allow')) ?>:</strong> <?= gp_e(gp_t('ovr_rule_allow')) ?>
	</div>
	<div class="gp-note gp-note-strong">
		<strong><?= gp_e(gp_t('ovr_deny')) ?>:</strong> <?= gp_e(gp_t('ovr_rule_deny')) ?>
	</div>
</div>

<?php if (!$redis_up): ?>
<div class="gp-note gp-note-strong"><?= gp_e(gp_t('err_redis')) ?></div>
<?php endif; ?>

<div class="gp-card">
	<div class="gp-card-title"><?= gp_e(gp_t('ovr_add')) ?></div>
	<form method="post" action="index.php?r=overrides" class="gp-form">
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<div class="gp-grid-2">
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('ovr_identity')) ?></span>
				<input class="gp-input gp-ltr" type="text" name="identity" required
					placeholder="device id / ip">
				<span class="gp-help"><?= gp_e(gp_t('id_first_step')) ?></span>
			</label>
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('id_ttl')) ?></span>
				<select class="gp-input" name="ttl">
					<option value="3600"><?= gp_e(gp_num(1)) ?> ساعت</option>
					<option value="21600"><?= gp_e(gp_num(6)) ?> ساعت</option>
					<option value="86400" selected><?= gp_e(gp_num(1)) ?> روز</option>
					<option value="604800"><?= gp_e(gp_num(7)) ?> روز</option>
					<option value="2592000"><?= gp_e(gp_num(30)) ?> روز</option>
				</select>
				<span class="gp-help"><?= gp_e(gp_t('ovr_max_ttl')) ?></span>
			</label>
		</div>
		<div class="gp-row-head">
			<button class="gp-btn gp-btn-primary" type="submit" name="override" value="allow">
				<?= gp_e(gp_t('id_allow')) ?></button>
			<button class="gp-btn gp-btn-danger" type="submit" name="override" value="deny">
				<?= gp_e(gp_t('id_deny')) ?></button>
		</div>
	</form>
</div>

<div class="gp-card">
	<div class="gp-card-title">
		<?= gp_e(gp_t('ovr_title')) ?>
		<span class="gp-card-sub"><?= gp_num(count($items)) ?></span>
	</div>
	<?php if (!$items): ?>
		<p class="gp-help"><?= gp_e(gp_t('no_results')) ?></p>
	<?php else: ?>
	<div class="gp-rows">
		<?php foreach ($items as $item): ?>
		<div class="gp-row">
			<div class="gp-row-head">
				<span class="gp-badge <?= $item['kind'] === 'allow' ? 'gp-badge-on' : 'gp-badge-bad' ?>">
					<?= gp_e($item['kind'] === 'allow' ? gp_t('ovr_allow') : gp_t('ovr_deny')) ?>
				</span>
				<span class="gp-mono gp-ltr gp-truncate"><?= gp_e($item['identity']) ?></span>
				<span style="margin-inline-start:auto" class="gp-mono">
					<?= gp_e(gp_t('ovr_remaining')) ?>:
					<?= $item['ttl'] === null ? gp_e(gp_t('unknown'))
						: gp_e(gp_age(time() - (int)$item['ttl'])) ?>
				</span>
			</div>
			<div class="gp-row-meta">
				<a class="gp-btn gp-btn-ghost gp-btn-sm"
					href="index.php?r=identity&amp;id=<?= gp_u($item['identity']) ?>">
					<?= gp_e(gp_t('id_title')) ?></a>
				<form method="post" action="index.php?r=overrides" style="display:inline">
					<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
					<input type="hidden" name="identity" value="<?= gp_e($item['identity']) ?>">
					<input type="hidden" name="ttl" value="86400">
					<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit"
						name="override" value="<?= gp_e($item['kind']) ?>">
						<?= gp_e(gp_t('ovr_extend')) ?></button>
				</form>
				<form method="post" action="index.php?r=overrides" style="display:inline"
					data-confirm="<?= gp_e(gp_t('ovr_clear')) ?>؟">
					<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
					<input type="hidden" name="identity" value="<?= gp_e($item['identity']) ?>">
					<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit"
						name="override" value="clear"><?= gp_e(gp_t('ovr_clear')) ?></button>
				</form>
			</div>
		</div>
		<?php endforeach; ?>
	</div>
	<?php endif; ?>
</div>
