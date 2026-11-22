<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Models. Everything shown comes from the analyzer snapshot: the panel never
// opens a joblib bundle itself, because that means unpickling in the web tier.
$kinds = array('ml' => gp_t('mdl_train'), 'clf' => gp_t('mdl_train_clf'));
$jobs = array('ml' => 'train', 'clf' => 'train_clf');
$promote = array('ml' => 'promote_ml', 'clf' => 'promote_clf');
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('mdl_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('job_needs_worker')) ?></p>
</div>

<?php foreach ($kinds as $kind => $train_label):
	$info = isset($models[$kind]) && is_array($models[$kind]) ? $models[$kind] : array();
	$live = isset($info['live']) && is_array($info['live']) ? $info['live'] : null;
	$cand = isset($info['candidate']) && is_array($info['candidate']) ? $info['candidate'] : null;
?>
<div class="gp-card">
	<div class="gp-card-title">
		<span class="gp-mono"><?= gp_e($kind) ?></span>
		<span class="gp-card-sub"><?= gp_e($train_label) ?></span>
	</div>

	<?php if ($live !== null && !empty($live['stale'])): ?>
	<div class="gp-note gp-note-strong" style="margin-bottom:.75rem">
		<?= gp_e(gp_t('mdl_stale_warn')) ?>
	</div>
	<?php endif; ?>

	<div class="gp-grid-2">
		<?php foreach (array('live' => gp_t('mdl_live'), 'candidate' => gp_t('mdl_candidate'))
			as $slot => $slot_label):
			$m = $slot === 'live' ? $live : $cand; ?>
		<div>
			<div class="gp-card-title" style="font-size:.75rem"><?= gp_e($slot_label) ?></div>
			<?php if ($m === null || empty($m['exists'])): ?>
				<p class="gp-help"><?= gp_e(gp_t('mdl_absent')) ?></p>
			<?php else: ?>
				<div class="gp-stat-row">
					<span class="gp-stat-key"><?= gp_e(gp_t('mdl_loads')) ?></span>
					<span class="gp-badge <?= !empty($m['loadable']) ? 'gp-badge-on' : 'gp-badge-bad' ?>">
						<?= gp_e(!empty($m['loadable']) ? gp_t('yes') : gp_t('mdl_stale')) ?></span>
				</div>
				<div class="gp-stat-row">
					<span class="gp-stat-key"><?= gp_e(gp_t('mdl_features')) ?></span>
					<span class="gp-stat-val"><?= gp_num((int)($m['feature_count'] ?? 0)) ?></span>
				</div>
				<div class="gp-stat-row">
					<span class="gp-stat-key"><?= gp_e(gp_t('mdl_trained_at')) ?></span>
					<span class="gp-stat-val">
						<?= !empty($m['mtime']) ? gp_e(gp_age((float)$m['mtime'])) . ' ' . gp_e(gp_t('ago'))
							: gp_e(gp_t('unknown')) ?></span>
				</div>
				<?php $metrics = isset($m['metrics']) && is_array($m['metrics']) ? $m['metrics'] : null;
				if ($metrics): ?>
				<div class="gp-stat-row">
					<span class="gp-stat-key"><?= gp_e(gp_t('mdl_precision')) ?></span>
					<span class="gp-stat-val"><?= gp_num((float)($metrics['precision'] ?? 0), 3) ?></span>
				</div>
				<div class="gp-stat-row">
					<span class="gp-stat-key"><?= gp_e(gp_t('mdl_recall')) ?></span>
					<span class="gp-stat-val"><?= gp_num((float)($metrics['recall'] ?? 0), 3) ?></span>
				</div>
				<?php endif; ?>
				<?php if (!empty($m['error'])): ?>
				<p class="gp-help gp-ltr gp-mono"><?= gp_e($m['error']) ?></p>
				<?php endif; ?>
			<?php endif; ?>
		</div>
		<?php endforeach; ?>
	</div>

	<form method="post" action="index.php?r=models" style="margin-top:.75rem">
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<div class="gp-row-head">
			<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit"
				name="job" value="<?= gp_e($jobs[$kind]) ?>"><?= gp_e($train_label) ?></button>
			<button class="gp-btn gp-btn-primary gp-btn-sm" type="submit"
				name="job" value="<?= gp_e($promote[$kind]) ?>"><?= gp_e(gp_t('mdl_promote')) ?></button>
		</div>
	</form>
	<?= gp_msg('models-' . $kind) ?>
</div>
<?php endforeach; ?>
