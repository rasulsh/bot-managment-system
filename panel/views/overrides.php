<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Operator overrides. The allow-is-ungated / deny-is-gated rule is stated
// directly in the UI, because that distinction is the thing an operator most
// needs to understand while a customer is on the phone.
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('ovr_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('ovr_intro')) ?></p>
	<p class="gp-page-sub"><strong data-ovr-immediate><?= gp_e(gp_t('ovr_immediate')) ?></strong></p>
</div>

<div class="gp-grid-2">
	<div class="gp-note">
		<strong><?= gp_e(gp_t('ovr_allow')) ?>:</strong> <?= gp_e(gp_t('ovr_rule_allow')) ?>
	</div>
	<div class="gp-note gp-note-strong">
		<strong><?= gp_e(gp_t('ovr_deny')) ?>:</strong> <?= gp_e(gp_t('ovr_rule_deny')) ?>
	</div>
	<div class="gp-note gp-note-strong">
		<strong><?= gp_e(gp_t('ovr_k_challenge')) ?> / <?= gp_e(gp_t('ovr_k_captcha')) ?>:</strong> <?= gp_e(gp_t('ovr_rule_chal')) ?>
	</div>
	<div class="gp-note">
		<strong><?= gp_e(gp_t('ovr_precedence_title')) ?>:</strong> <?= gp_e(gp_t('ovr_precedence')) ?>
	</div>
</div>

<?php if (!$redis_up): ?>
<div class="gp-note gp-note-strong"><?= gp_e(gp_t('err_redis')) ?></div>
<?php endif; ?>

<?php $shadow = isset($shadow) && is_array($shadow) ? $shadow : array(); foreach ($shadow as $sid => $slist): ?>
<div class="gp-note gp-note-strong" role="alert" data-shadow="<?= gp_e($sid) ?>"><span class="gp-mono gp-ltr"><?= gp_e($sid) ?></span>: <?= gp_e(str_replace('%s', $slist, gp_t('ovr_deny_shadowed'))) ?>
	<a href="index.php?r=iplists&amp;list=<?= gp_u($slist) ?>#ipl-entries"><?= gp_e(gp_t('ovr_shadow_link')) ?></a></div>
<?php endforeach; ?>

<div class="gp-card" id="override-add">
	<div class="gp-card-title"><?= gp_e(gp_t('ovr_add')) ?></div>
	<?php $new_identity = isset($new_identity) ? (string)$new_identity : ''; ?>
	<?= $new_identity !== '' ? gp_override_shared_note($new_identity) : '' ?>
	<form method="post" action="index.php?r=overrides" class="gp-form">
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<div class="gp-grid-2">
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('ovr_identity')) ?><?= gp_tip('ovr_identity') ?></span>
				<input class="gp-input gp-ltr" type="text" name="identity" required value="<?= gp_e($new_identity) ?>"
					placeholder="device id / ip">
				<span class="gp-help"><?= gp_e(gp_t('id_first_step')) ?></span>
			</label>
			<div class="gp-field">
				<?= gp_override_ttl_fields(3600) ?>
				<span class="gp-help"><?= gp_e(gp_t('ovr_max_ttl')) ?></span>
			</div>
		</div>
		<div class="gp-row-head"><?= gp_override_buttons() ?></div>
	</form>
	<?= gp_msg('override-add') ?>
</div>

<?= gp_filter_form_html('overrides', array(
	'kind' => array('ovr_kind', 'is', gp_override_kinds(), 'flt_kind'),
	'identity' => array('ovr_identity', 'is', array(), 'flt_ip')), $filter) ?>

<div class="gp-card">
	<div class="gp-card-title">
		<?= gp_e(gp_t('ovr_title')) ?>
		<span class="gp-card-sub"><?= gp_num(count($items)) ?> / <?= gp_num(count($items_all)) ?></span>
	</div>
	<?= gp_msg('override-list') ?>
	<?php if (!$items): ?>
		<p class="gp-help"><?= gp_e(gp_t('no_results')) ?></p>
	<?php else: ?>
	<div class="gp-rows">
		<?php foreach ($items as $item): ?>
		<div class="gp-row">
			<div class="gp-row-head">
				<?= gp_override_badge($item['kind']) ?>
				<span class="gp-mono gp-ltr gp-truncate"><?= gp_e($item['identity']) ?></span>
				<span style="margin-inline-start:auto" class="gp-mono">
					<?= gp_e(gp_t('ovr_remaining')) ?>: <?= gp_e(gp_override_expires_text($item['ttl'])) ?>
				</span>
			</div>
			<?php $shared = gp_override_shared_note($item['identity']); echo $shared; ?>
			<div class="gp-row-meta">
				<a class="gp-btn gp-btn-ghost gp-btn-sm"
					href="index.php?r=identity&amp;id=<?= gp_u($item['identity']) ?>">
					<?= gp_e(gp_t('id_title')) ?></a>
				<form method="post" action="index.php?r=overrides" class="gp-retime">
					<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
					<input type="hidden" name="identity" value="<?= gp_e($item['identity']) ?>">
					<input type="hidden" name="kind" value="<?= gp_e($item['kind']) ?>">
					<input type="hidden" name="from" value="list">
					<?= gp_override_ttl_fields(3600, 'ttl', true) ?>
					<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit" name="override" value="retime"><?= gp_e(gp_t('ovr_retime')) ?></button><?= gp_tip('ovr_retime') ?>
				</form>
				<form method="post" action="index.php?r=overrides" style="display:inline"
					data-confirm="<?= gp_e(gp_t('ovr_clear')) ?>?">
					<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
					<input type="hidden" name="identity" value="<?= gp_e($item['identity']) ?>">
					<input type="hidden" name="from" value="list">
					<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit"
						name="override" value="clear"><?= gp_e(gp_t('ovr_clear')) ?></button>
				</form>
				<?= gp_msg('ovr-' . gp_row_key($item['identity'])) ?>
			</div>
		</div>
		<?php endforeach; ?>
	</div>
	<?php endif; ?>
</div>
